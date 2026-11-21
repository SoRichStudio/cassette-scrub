from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Final

from cassette_scrub import __version__
from cassette_scrub.cli import _discover_files
from cassette_scrub.config import load_config
from cassette_scrub.installer import (
    install_mcp,
    install_pre_commit_config,
    install_skill,
)
from cassette_scrub.parser import dump_cassette, load_cassette
from cassette_scrub.scrubber import format_cassette_diff, scrub_cassette
from cassette_scrub.types import InstallResult

__all__ = ["handle_mcp_request", "run_mcp_server"]

PROTOCOL_VERSION: Final[str] = "2024-11-05"

_SCAN_FIX_DIFF_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "paths": {"type": "array", "items": {"type": "string"}, "description": "Files or folders to process (default: ['.'])."},
        "scrub_pii": {"type": "boolean", "default": True, "description": "Whether to scrub email addresses."},
    },
    "additionalProperties": False,
}

_TOOLS: Final[tuple[dict[str, Any], ...]] = (
    {"name": "cassette_scrub_scan", "description": "Scan VCR.py cassettes without editing files.", "inputSchema": _SCAN_FIX_DIFF_SCHEMA},
    {"name": "cassette_scrub_fix", "description": "Scrub detected secrets and emails from VCR.py cassettes in place.", "inputSchema": _SCAN_FIX_DIFF_SCHEMA},
    {"name": "cassette_scrub_diff", "description": "Preview unified diffs for pending VCR.py redactions.", "inputSchema": _SCAN_FIX_DIFF_SCHEMA},
    {
        "name": "cassette_scrub_install",
        "description": "Install the /cassette-scrub skill, MCP config, or pre-commit hook.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["skill", "mcp", "hook", "all"], "default": "all"},
                "targets": {"type": "array", "items": {"type": "string"}},
                "project_dir": {"type": "string"},
                "home_dir": {"type": "string"},
                "hook_id": {"type": "string", "default": "cassette-scrub-check"},
                "command": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
)


def _rpc_ok(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_err(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _parse_paths(args: dict[str, Any]) -> list[str]:
    raw = args.get("paths", args.get("path"))
    if raw is None:
        return ["."]
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else ["."]
    if isinstance(raw, (list, tuple)) and all(isinstance(x, str) for x in raw):
        return [x.strip() for x in raw if x.strip()] or ["."]
    raise ValueError("'paths' must be a string or array of strings.")


def _parse_str_list(raw: Any, name: str) -> list[str] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return [p.strip() for p in raw.split(",") if p.strip()] or None
    if isinstance(raw, (list, tuple)) and all(isinstance(x, str) for x in raw):
        return [x.strip() for x in raw if x.strip()] or None
    raise ValueError(f"'{name}' must contain only strings.")


def _opt_path(raw: Any, name: str) -> Path | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError(f"'{name}' must be a string path.")
    return Path(raw.strip()) if raw.strip() else None


def _run_cassettes(args: dict[str, Any], *, fix: bool = False, diff: bool = False) -> tuple[str, bool]:
    paths = _parse_paths(args)
    scrub_pii = args.get("scrub_pii", True)
    if not isinstance(scrub_pii, bool):
        raise ValueError("'scrub_pii' must be a boolean.")

    scanned = 0
    dirty = 0
    modified_files: list[str] = []
    findings: list[dict[str, Any]] = []
    diffs: list[str] = []

    for path in _discover_files(paths):
        data, fmt = load_cassette(path)
        if data is None or not fmt:
            continue
        scanned += 1
        result = scrub_cassette(data, str(path), load_config(path.parent, scrub_pii=scrub_pii))
        if result.findings:
            dirty += 1
            findings.extend(asdict(f) for f in result.findings)
        if result.modified and result.updated_data is not None:
            if diff:
                text = format_cassette_diff(data, result.updated_data, fmt, file_path=str(path))
                if text.strip():
                    diffs.append(text)
            if fix:
                dump_cassette(path, result.updated_data, fmt)
                modified_files.append(str(path))

    if diff:
        return ("\n".join(diffs) if diffs else "No changes needed."), False

    payload: dict[str, Any] = {
        "version": __version__,
        "modified": bool(modified_files) if fix else False,
        "files_scanned": scanned,
        "files_with_findings": dirty,
        "finding_count": len(findings),
        "findings": findings,
    }
    if fix:
        payload["modified_files"] = modified_files
    else:
        payload["has_findings"] = bool(findings)
    return json.dumps(payload, indent=2), False


def _run_install(args: dict[str, Any]) -> tuple[str, bool]:
    raw_action = args.get("action", args.get("kind", "all"))
    if not isinstance(raw_action, str) or raw_action.strip().lower() not in ("skill", "mcp", "hook", "all"):
        raise ValueError("'action' must be 'skill', 'mcp', 'hook', or 'all'.")
    action = raw_action.strip().lower()

    targets = _parse_str_list(args.get("targets"), "targets")
    home_dir = _opt_path(args.get("home_dir"), "home_dir")
    project_dir = _opt_path(args.get("project_dir"), "project_dir")
    raw_hook = args.get("hook_id", "cassette-scrub-check")
    if not isinstance(raw_hook, str):
        raise ValueError("'hook_id' must be a string.")
    hook_id = raw_hook.strip() or "cassette-scrub-check"
    raw_cmd = args.get("command")
    if raw_cmd is not None and not isinstance(raw_cmd, str):
        raise ValueError("'command' must be a string.")

    results: list[InstallResult] = []
    if action in ("skill", "all"):
        results.extend(install_skill(targets=targets, home_dir=home_dir, project_dir=project_dir))
    if action in ("mcp", "all"):
        results.extend(install_mcp(targets=targets, command=raw_cmd, home_dir=home_dir, project_dir=project_dir))
    if action == "hook" or (action == "all" and (project_dir is not None or (targets and "project" in {t.lower() for t in targets}))):
        results.append(install_pre_commit_config(project_dir or Path.cwd(), hook_id=hook_id))

    ok = all(r.success for r in results)
    payload = {"action": action, "success": ok, "results": [asdict(r) for r in results]}
    return json.dumps(payload, indent=2), not ok


def handle_mcp_request(request: dict[str, Any]) -> dict[str, Any] | None:
    """Process one parsed JSON-RPC 2.0 MCP request dict."""
    if not isinstance(request, dict):
        return _rpc_err(None, -32600, "Invalid Request")
    method = request.get("method")
    if "id" not in request or (isinstance(method, str) and method.startswith("notifications/")):
        return None

    req_id = request["id"]
    if not isinstance(method, str) or not method:
        return _rpc_err(req_id, -32600, "Invalid Request: missing method")
    if method == "initialize":
        return _rpc_ok(req_id, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}}, "serverInfo": {"name": "cassette-scrub", "version": __version__}})
    if method == "ping":
        return _rpc_ok(req_id, {})
    if method == "tools/list":
        return _rpc_ok(req_id, {"tools": list(_TOOLS)})
    if method == "tools/call":
        params = request.get("params")
        if not isinstance(params, dict):
            return _rpc_err(req_id, -32602, "Invalid params")
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return _rpc_err(req_id, -32602, "Missing tool name")
        args = params.get("arguments")
        if args is None:
            args = {}
        elif not isinstance(args, dict):
            return _rpc_err(req_id, -32602, "Arguments must be an object")

        dispatch = {
            "cassette_scrub_scan": lambda a: _run_cassettes(a),
            "cassette_scrub_fix": lambda a: _run_cassettes(a, fix=True),
            "cassette_scrub_diff": lambda a: _run_cassettes(a, diff=True),
            "cassette_scrub_install": _run_install,
        }
        handler = dispatch.get(name)
        if handler is None:
            return _rpc_err(req_id, -32602, f"Unknown tool: {name}")
        try:
            text, is_err = handler(args)
        except Exception as exc:
            return _rpc_ok(req_id, {"content": [{"type": "text", "text": json.dumps({"error": str(exc)}, indent=2)}], "isError": True})
        return _rpc_ok(req_id, {"content": [{"type": "text", "text": text}], "isError": is_err})

    return _rpc_err(req_id, -32601, f"Method not found: {method}")


def run_mcp_server() -> int:
    """Run line-delimited JSON-RPC 2.0 MCP server on stdio."""
    for stream in (sys.stdin, sys.stdout):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            try:
                reconf(encoding="utf-8")
            except (AttributeError, OSError, ValueError):
                pass

    try:
        while raw := sys.stdin.readline():
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                sys.stdout.write(json.dumps(_rpc_err(None, -32700, "Parse error")) + "\n")
                sys.stdout.flush()
                continue

            if isinstance(payload, list):
                if not payload:
                    sys.stdout.write(json.dumps(_rpc_err(None, -32600, "Invalid Request")) + "\n")
                else:
                    resps = [r for item in payload if (r := handle_mcp_request(item) if isinstance(item, dict) else _rpc_err(None, -32600, "Invalid Request")) is not None]
                    if resps:
                        sys.stdout.write(json.dumps(resps) + "\n")
                sys.stdout.flush()
                continue

            resp = handle_mcp_request(payload) if isinstance(payload, dict) else _rpc_err(None, -32600, "Invalid Request")
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
    except (KeyboardInterrupt, BrokenPipeError):
        return 0
    return 0
