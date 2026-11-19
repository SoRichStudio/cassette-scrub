from __future__ import annotations

import difflib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Final

import yaml

from cassette_scrub import __version__
from cassette_scrub.config import load_config
from cassette_scrub.installer import (
    install_mcp,
    install_pre_commit_config,
    install_skill,
)
from cassette_scrub.parser import dump_cassette, load_cassette
from cassette_scrub.scrubber import scrub_cassette
from cassette_scrub.types import Finding, InstallResult

__all__ = ["handle_mcp_request", "run_mcp_server"]

PROTOCOL_VERSION: Final[str] = "2024-11-05"
_CASSETTE_EXTENSIONS: Final[frozenset[str]] = frozenset({".yaml", ".yml", ".json"})
_IGNORED_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        "node_modules",
    }
)

_TOOLS: Final[tuple[dict[str, Any], ...]] = (
    {
        "name": "cassette_scrub_scan",
        "description": (
            "Scan VCR.py YAML and JSON cassettes for secrets, sensitive headers, "
            "query parameters, and email PII without modifying files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Cassette file or directory paths to scan (defaults to ['.']).",
                },
                "scrub_pii": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to detect email PII in addition to secrets.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cassette_scrub_fix",
        "description": (
            "Scrub detected secrets, sensitive headers, query parameters, and email PII "
            "from VCR.py cassettes in place."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Cassette file or directory paths to scrub in place (defaults to ['.']).",
                },
                "scrub_pii": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to scrub email PII in addition to secrets.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cassette_scrub_diff",
        "description": (
            "Return unified diffs showing the exact redactions scrubbing would apply "
            "to VCR.py cassettes without modifying files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Cassette file or directory paths to preview (defaults to ['.']).",
                },
                "scrub_pii": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to include email PII redactions in the diff.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cassette_scrub_install",
        "description": (
            "Install the /cassette-scrub AI skill, MCP server configuration, and/or "
            ".pre-commit-config.yaml hook."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["skill", "mcp", "hook", "all"],
                    "default": "all",
                    "description": "Install target type: 'skill', 'mcp', 'hook', or 'all'.",
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Target assistants or scopes (antigravity, claude, codex, "
                        "cursor, windsurf, vscode, project, or all)."
                    ),
                },
                "project_dir": {
                    "type": "string",
                    "description": "Project directory for project-level skills, .mcp.json, or pre-commit hook.",
                },
                "home_dir": {
                    "type": "string",
                    "description": "Optional user home directory override.",
                },
                "hook_id": {
                    "type": "string",
                    "default": "cassette-scrub-check",
                    "description": "Pre-commit hook ID ('cassette-scrub-check' or 'cassette-scrub-fix').",
                },
                "command": {
                    "type": "string",
                    "description": "Optional command override for MCP server registration.",
                },
            },
            "additionalProperties": False,
        },
    },
)


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success response object."""
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response object."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


def _discover_cassette_files(raw_paths: list[str]) -> list[Path]:
    """Discover candidate YAML and JSON files from directories and explicit file paths."""
    discovered: list[Path] = []
    seen: set[Path] = set()

    for raw_path in raw_paths:
        target = Path(raw_path)
        if target.is_dir():
            for root, dirnames, filenames in os.walk(target):
                dirnames[:] = sorted(d for d in dirnames if d not in _IGNORED_DIRS)
                root_path = Path(root)
                for filename in sorted(filenames):
                    candidate = root_path / filename
                    if candidate.suffix.lower() not in _CASSETTE_EXTENSIONS:
                        continue
                    resolved = candidate.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        discovered.append(candidate)
        elif target.is_file():
            if target.suffix.lower() not in _CASSETTE_EXTENSIONS:
                continue
            resolved = target.resolve()
            if resolved not in seen:
                seen.add(resolved)
                discovered.append(target)

    return discovered


def _normalize_paths_arg(arguments: dict[str, Any]) -> list[str]:
    """Extract and validate a list of path strings from tool arguments."""
    raw_paths = arguments.get("paths")
    if raw_paths is None and "path" in arguments:
        raw_paths = arguments.get("path")
    if raw_paths is None:
        return ["."]
    if isinstance(raw_paths, str):
        cleaned = raw_paths.strip()
        return [cleaned] if cleaned else ["."]
    if isinstance(raw_paths, (list, tuple)):
        if not all(isinstance(item, str) for item in raw_paths):
            raise ValueError("'paths' must contain only strings.")
        cleaned_list = [item.strip() for item in raw_paths if item.strip()]
        return cleaned_list or ["."]
    raise ValueError("'paths' must be a string or an array of strings.")


def _normalize_scrub_pii_arg(arguments: dict[str, Any]) -> bool:
    """Extract and validate the boolean scrub_pii argument."""
    value = arguments.get("scrub_pii", True)
    if not isinstance(value, bool):
        raise ValueError("'scrub_pii' must be a boolean.")
    return value


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    """Convert a Finding dataclass to a JSON-serializable dict."""
    return {
        "file_path": finding.file_path,
        "interaction_index": finding.interaction_index,
        "location": finding.location,
        "preview": finding.preview,
    }


def _fallback_format_diff(
    original_data: dict[str, Any],
    updated_data: dict[str, Any],
    fmt: str,
    file_path: str = "cassette",
) -> str:
    """Render a unified diff between original and updated cassette dicts."""
    if fmt == "yaml":
        before = yaml.safe_dump(original_data, sort_keys=False, allow_unicode=True)
        after = yaml.safe_dump(updated_data, sort_keys=False, allow_unicode=True)
    else:
        before = json.dumps(original_data, indent=2, default=str) + "\n"
        after = json.dumps(updated_data, indent=2, default=str) + "\n"

    diff_lines = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )
    return "".join(diff_lines)


def _format_diff(
    original_data: dict[str, Any],
    updated_data: dict[str, Any],
    fmt: str,
    file_path: str,
) -> str:
    """Render unified diff using scrubber.format_cassette_diff when available."""
    try:
        from cassette_scrub.scrubber import format_cassette_diff
    except ImportError:
        return _fallback_format_diff(original_data, updated_data, fmt, file_path=file_path)
    return format_cassette_diff(original_data, updated_data, fmt, file_path=file_path)


def _tool_scan(arguments: dict[str, Any]) -> tuple[str, bool]:
    """Execute cassette_scrub_scan and return JSON summary + findings."""
    paths = _normalize_paths_arg(arguments)
    scrub_pii = _normalize_scrub_pii_arg(arguments)
    files = _discover_cassette_files(paths)

    files_scanned = 0
    files_with_findings = 0
    findings: list[dict[str, Any]] = []

    for path in files:
        data, fmt = load_cassette(path)
        if data is None or not fmt:
            continue
        files_scanned += 1
        config = load_config(start_dir=path.parent, scrub_pii=scrub_pii)
        result = scrub_cassette(data, str(path), config)
        if result.findings:
            files_with_findings += 1
            findings.extend(_serialize_finding(item) for item in result.findings)

    payload = {
        "version": __version__,
        "modified": False,
        "files_scanned": files_scanned,
        "files_with_findings": files_with_findings,
        "finding_count": len(findings),
        "has_findings": bool(findings),
        "findings": findings,
    }
    return json.dumps(payload, indent=2), False


def _tool_fix(arguments: dict[str, Any]) -> tuple[str, bool]:
    """Execute cassette_scrub_fix in place and return modified files + findings."""
    paths = _normalize_paths_arg(arguments)
    scrub_pii = _normalize_scrub_pii_arg(arguments)
    files = _discover_cassette_files(paths)

    files_scanned = 0
    files_with_findings = 0
    modified_files: list[str] = []
    findings: list[dict[str, Any]] = []

    for path in files:
        data, fmt = load_cassette(path)
        if data is None or not fmt:
            continue
        files_scanned += 1
        config = load_config(start_dir=path.parent, scrub_pii=scrub_pii)
        result = scrub_cassette(data, str(path), config)
        if result.findings:
            files_with_findings += 1
            findings.extend(_serialize_finding(item) for item in result.findings)
        if result.modified and result.updated_data is not None:
            dump_cassette(path, result.updated_data, fmt)
            modified_files.append(str(path))

    payload = {
        "version": __version__,
        "modified": bool(modified_files),
        "files_scanned": files_scanned,
        "files_with_findings": files_with_findings,
        "modified_files": modified_files,
        "finding_count": len(findings),
        "findings": findings,
    }
    return json.dumps(payload, indent=2), False


def _tool_diff(arguments: dict[str, Any]) -> tuple[str, bool]:
    """Execute cassette_scrub_diff and return unified diff output."""
    paths = _normalize_paths_arg(arguments)
    scrub_pii = _normalize_scrub_pii_arg(arguments)
    files = _discover_cassette_files(paths)

    diffs: list[str] = []
    for path in files:
        data, fmt = load_cassette(path)
        if data is None or not fmt:
            continue
        config = load_config(start_dir=path.parent, scrub_pii=scrub_pii)
        result = scrub_cassette(data, str(path), config)
        if result.modified and result.updated_data is not None:
            diff_text = _format_diff(data, result.updated_data, fmt, file_path=str(path))
            if diff_text.strip():
                diffs.append(diff_text)

    if not diffs:
        return "No secrets or PII detected; no changes required.", False
    return "\n".join(diffs), False


def _normalize_optional_targets(raw: Any) -> list[str] | None:
    """Normalize optional targets argument into a list of strings or None."""
    if raw is None:
        return None
    if isinstance(raw, str):
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        return parts or None
    if isinstance(raw, (list, tuple)):
        if not all(isinstance(item, str) for item in raw):
            raise ValueError("'targets' must contain only strings.")
        parts = [item.strip() for item in raw if item.strip()]
        return parts or None
    raise ValueError("'targets' must be a list of target strings.")


def _normalize_optional_path(raw: Any, field_name: str) -> Path | None:
    """Normalize an optional string path argument into a Path or None."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError(f"'{field_name}' must be a string path.")
    cleaned = raw.strip()
    return Path(cleaned) if cleaned else None


def _tool_install(arguments: dict[str, Any]) -> tuple[str, bool]:
    """Execute cassette_scrub_install for skills, MCP configs, and/or pre-commit."""
    raw_action = arguments.get("action")
    if raw_action is None:
        raw_action = arguments.get("kind", "all")
    if not isinstance(raw_action, str):
        raise ValueError("'action' must be a string ('skill', 'mcp', 'hook', or 'all').")
    action = raw_action.strip().lower()
    if action not in ("skill", "mcp", "hook", "all"):
        raise ValueError(
            f"Unsupported install action {raw_action!r}; expected 'skill', 'mcp', 'hook', or 'all'."
        )

    targets = _normalize_optional_targets(arguments.get("targets"))
    home_dir = _normalize_optional_path(arguments.get("home_dir"), "home_dir")
    project_dir = _normalize_optional_path(arguments.get("project_dir"), "project_dir")

    raw_hook_id = arguments.get("hook_id", "cassette-scrub-check")
    if not isinstance(raw_hook_id, str):
        raise ValueError("'hook_id' must be a string.")
    hook_id = raw_hook_id.strip() or "cassette-scrub-check"

    raw_command = arguments.get("command")
    if raw_command is not None and not isinstance(raw_command, str):
        raise ValueError("'command' must be a string.")

    results: list[InstallResult] = []
    if action in ("skill", "all"):
        results.extend(
            install_skill(targets=targets, home_dir=home_dir, project_dir=project_dir)
        )
    if action in ("mcp", "all"):
        results.extend(
            install_mcp(
                targets=targets,
                command=raw_command,
                home_dir=home_dir,
                project_dir=project_dir,
            )
        )
    if action == "hook":
        results.append(
            install_pre_commit_config(
                project_dir=project_dir if project_dir is not None else Path.cwd(),
                hook_id=hook_id,
            )
        )
    elif action == "all" and (
        project_dir is not None
        or (targets is not None and "project" in {t.lower() for t in targets})
    ):
        results.append(
            install_pre_commit_config(
                project_dir=project_dir if project_dir is not None else Path.cwd(),
                hook_id=hook_id,
            )
        )

    all_succeeded = all(item.success for item in results)
    payload = {
        "action": action,
        "success": all_succeeded,
        "results": [asdict(item) for item in results],
    }
    return json.dumps(payload, indent=2), not all_succeeded


def _execute_tool(
    tool_name: str, arguments: dict[str, Any]
) -> tuple[str, bool] | None:
    """Dispatch a known MCP tool call or return None if unknown."""
    if tool_name == "cassette_scrub_scan":
        return _tool_scan(arguments)
    if tool_name == "cassette_scrub_fix":
        return _tool_fix(arguments)
    if tool_name == "cassette_scrub_diff":
        return _tool_diff(arguments)
    if tool_name == "cassette_scrub_install":
        return _tool_install(arguments)
    return None


def handle_mcp_request(request: dict[str, Any]) -> dict[str, Any] | None:
    """Process one parsed JSON-RPC 2.0 MCP request dict and return response or None."""
    if not isinstance(request, dict):
        return _jsonrpc_error(None, -32600, "Invalid Request")

    method = request.get("method")
    if (
        method == "notifications/initialized"
        or (isinstance(method, str) and method.startswith("notifications/"))
        or "id" not in request
    ):
        return None

    req_id = request["id"]
    if not isinstance(method, str) or not method:
        return _jsonrpc_error(req_id, -32600, "Invalid Request: missing method")

    if method == "initialize":
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "cassette-scrub",
                    "version": __version__,
                },
            },
        )

    if method == "ping":
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": list(_TOOLS)})

    if method == "tools/call":
        params = request.get("params")
        if not isinstance(params, dict):
            return _jsonrpc_error(req_id, -32602, "Invalid params: expected object")

        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return _jsonrpc_error(req_id, -32602, "Invalid params: missing tool name")

        raw_arguments = params.get("arguments")
        if raw_arguments is None:
            arguments: dict[str, Any] = {}
        elif isinstance(raw_arguments, dict):
            arguments = raw_arguments
        else:
            return _jsonrpc_error(
                req_id, -32602, "Invalid params: arguments must be an object"
            )

        try:
            outcome = _execute_tool(tool_name, arguments)
        except Exception as exc:
            return _jsonrpc_result(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"error": str(exc)}, indent=2),
                        }
                    ],
                    "isError": True,
                },
            )

        if outcome is None:
            return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name}")

        text_output, is_error = outcome
        return _jsonrpc_result(
            req_id,
            {
                "content": [{"type": "text", "text": text_output}],
                "isError": is_error,
            },
        )

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def _configure_stdio_utf8() -> None:
    """Best-effort UTF-8 stream setup on stdio without breaking test StringIO doubles."""
    for stream in (sys.stdin, sys.stdout):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (AttributeError, OSError, ValueError):
                pass


def run_mcp_server() -> int:
    """Run the line-delimited JSON-RPC 2.0 MCP server over stdin/stdout."""
    _configure_stdio_utf8()

    try:
        while True:
            raw_line = sys.stdin.readline()
            if not raw_line:
                break
            stripped = raw_line.strip()
            if not stripped:
                continue

            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                err_resp = _jsonrpc_error(None, -32700, "Parse error")
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            if isinstance(payload, list):
                if not payload:
                    batch_err = _jsonrpc_error(None, -32600, "Invalid Request")
                    sys.stdout.write(json.dumps(batch_err) + "\n")
                    sys.stdout.flush()
                    continue
                batch_responses: list[dict[str, Any]] = []
                for item in payload:
                    if isinstance(item, dict):
                        resp = handle_mcp_request(item)
                    else:
                        resp = _jsonrpc_error(None, -32600, "Invalid Request")
                    if resp is not None:
                        batch_responses.append(resp)
                if batch_responses:
                    sys.stdout.write(json.dumps(batch_responses) + "\n")
                    sys.stdout.flush()
                continue

            if isinstance(payload, dict):
                response = handle_mcp_request(payload)
            else:
                response = _jsonrpc_error(None, -32600, "Invalid Request")

            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
    except (KeyboardInterrupt, BrokenPipeError):
        return 0

    return 0
