from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Any, Final

import yaml

from cassette_scrub.types import InstallResult

__all__ = [
    "SUPPORTED_TARGETS",
    "get_skill_markdown",
    "install_skill",
    "install_mcp",
    "install_pre_commit_config",
]

SUPPORTED_TARGETS: Final[tuple[str, ...]] = (
    "antigravity",
    "claude",
    "codex",
    "cursor",
    "windsurf",
    "vscode",
    "project",
)
_DEFAULT_SKILL_TARGETS: Final[tuple[str, ...]] = (
    "antigravity",
    "claude",
    "codex",
    "cursor",
    "windsurf",
)
_DEFAULT_MCP_TARGETS: Final[tuple[str, ...]] = (*_DEFAULT_SKILL_TARGETS, "vscode")
PRE_COMMIT_REPO_URL: Final[str] = "https://github.com/SoRichStudio/cassette-scrub"
PRE_COMMIT_REV: Final[str] = "v0.2.0"

_EMBEDDED_SKILL_MARKDOWN: Final[str] = """---
name: cassette-scrub
description: Scrub secrets, auth headers, and emails from VCR.py cassettes.
---

# /cassette-scrub

Check and redact credentials, cookies, and email addresses in VCR.py `.yaml`, `.yml`, and `.json` cassettes without touching unrelated files.

## CLI

```bash
cassette-scrub --check tests/
cassette-scrub --diff tests/
cassette-scrub --check --json tests/
cassette-scrub --fix tests/
cassette-scrub --fix --no-pii tests/
```

## MCP tools

With `cassette-scrub --mcp` (or `cassette-scrub-mcp`) configured:

- `cassette_scrub_scan` (`paths`, `scrub_pii`) - check files and return JSON findings
- `cassette_scrub_diff` (`paths`, `scrub_pii`) - preview unified diffs without writing
- `cassette_scrub_fix` (`paths`, `scrub_pii`) - redact matches in place
- `cassette_scrub_install` (`action`, `targets`, `project_dir`) - install skill, MCP config, or pre-commit hook

## Config

Reads `[tool.cassette-scrub]` from the nearest `pyproject.toml` (`extra_headers`, `extra_query_keys`, `extra_body_keys`, `scrub_pii`, `custom_patterns`, `allowlist`). Check files with `--check` or `--diff` before running `--fix`, and avoid echoing unredacted secrets in output.
"""


def get_skill_markdown() -> str:
    """Load SKILL.md from disk or bundled zipapp, falling back to embedded text."""
    candidate = Path(__file__).resolve().parent.parent / "skills" / "cassette-scrub" / "SKILL.md"
    try:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        pass
    for parent in Path(__file__).resolve().parents:
        if parent.is_file() and zipfile.is_zipfile(parent):
            try:
                with zipfile.ZipFile(parent, "r") as zf:
                    return zf.read("skills/cassette-scrub/SKILL.md").decode("utf-8")
            except (KeyError, OSError, UnicodeDecodeError):
                break
    return _EMBEDDED_SKILL_MARKDOWN


def _normalize_targets(
    targets: list[str] | None,
    defaults: tuple[str, ...],
    project_dir: Path | None,
) -> list[str]:
    cleaned = [t.strip().lower() for t in (targets or []) if isinstance(t, str) and t.strip()]
    if not cleaned or "all" in cleaned:
        out = list(defaults)
        if project_dir is not None or "project" in cleaned:
            out.append("project")
        extras = [t for t in cleaned if t != "all"]
        return list(dict.fromkeys([*out, *extras]))
    return list(dict.fromkeys(cleaned))


def _skill_paths(target: str, home: Path, project: Path) -> list[Path]:
    mapping = {
        "antigravity": [home / ".gemini" / "config" / "skills" / "cassette-scrub" / "SKILL.md"],
        "claude": [
            home / ".claude" / "skills" / "cassette-scrub" / "SKILL.md",
            home / ".claude" / "commands" / "cassette-scrub.md",
        ],
        "codex": [home / ".codex" / "skills" / "cassette-scrub" / "SKILL.md"],
        "cursor": [home / ".cursor" / "skills" / "cassette-scrub" / "SKILL.md"],
        "windsurf": [home / ".codeium" / "windsurf" / "skills" / "cassette-scrub" / "SKILL.md"],
        "project": [
            project / ".agent" / "skills" / "cassette-scrub" / "SKILL.md",
            project / ".claude" / "skills" / "cassette-scrub" / "SKILL.md",
        ],
    }
    return mapping.get(target, [])


def _mcp_specs(target: str, home: Path, project: Path) -> list[tuple[Path, str]]:
    mapping = {
        "antigravity": [(home / ".gemini" / "config" / "mcp_config.json", "mcpServers")],
        "claude": [
            (home / ".claude.json", "mcpServers"),
            (home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json", "mcpServers"),
        ],
        "codex": [(home / ".codex" / "mcp.json", "mcpServers")],
        "cursor": [(home / ".cursor" / "mcp.json", "mcpServers")],
        "windsurf": [(home / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers")],
        "vscode": [(home / "AppData" / "Roaming" / "Code" / "User" / "mcp.json", "servers")],
        "project": [(project / ".mcp.json", "mcpServers")],
    }
    return mapping.get(target, [])


def install_skill(
    targets: list[str] | None = None,
    home_dir: Path | None = None,
    project_dir: Path | None = None,
) -> list[InstallResult]:
    """Install the /cassette-scrub skill file for each requested target."""
    home = home_dir or Path.home()
    project = project_dir or Path.cwd()
    content = get_skill_markdown()
    results: list[InstallResult] = []

    for target in _normalize_targets(targets, _DEFAULT_SKILL_TARGETS, project_dir):
        if target not in SUPPORTED_TARGETS:
            results.append(InstallResult(target, "skill", "", False, f"Unknown target: {target}"))
            continue
        if target == "vscode":
            continue
        for dest in _skill_paths(target, home, project):
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open("w", encoding="utf-8", newline="\n") as handle:
                    handle.write(content)
                results.append(InstallResult(target, "skill", str(dest), True, "Installed skill."))
            except OSError as exc:
                results.append(InstallResult(target, "skill", str(dest), False, f"Write failed: {exc}"))
    return results


def _resolve_mcp_entry(command: str | None = None) -> dict[str, Any]:
    if command and command.strip():
        return {"command": command.strip(), "args": ["--mcp"]}
    which_exe = shutil.which("cassette-scrub")
    if which_exe:
        return {"command": str(which_exe), "args": ["--mcp"]}
    for candidate in (
        Path(sys.executable).with_name("Scripts") / "cassette-scrub.exe",
        Path(sys.executable).with_name("cassette-scrub.exe"),
    ):
        if candidate.is_file():
            return {"command": str(candidate), "args": ["--mcp"]}
    return {"command": sys.executable, "args": ["-m", "cassette_scrub.cli", "--mcp"]}


def _merge_mcp_file(
    target: str, config_path: Path, root_key: str, entry: dict[str, Any]
) -> InstallResult:
    if config_path.exists():
        if not config_path.is_file():
            return InstallResult(target, "mcp", str(config_path), False, "Path is not a file.")
        try:
            data = json.loads(config_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return InstallResult(target, "mcp", str(config_path), False, f"Invalid JSON: {exc}")
        if not isinstance(data, dict):
            return InstallResult(target, "mcp", str(config_path), False, "Config root must be an object.")
        section = data.setdefault(root_key, {})
        if not isinstance(section, dict):
            return InstallResult(target, "mcp", str(config_path), False, f"'{root_key}' must be an object.")
    else:
        data = {root_key: {}}

    data[root_key]["cassette-scrub"] = dict(entry)
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with config_path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(data, indent=2) + "\n")
    except OSError as exc:
        return InstallResult(target, "mcp", str(config_path), False, f"Write failed: {exc}")
    return InstallResult(target, "mcp", str(config_path), True, f"Updated '{root_key}'.")


def install_mcp(
    targets: list[str] | None = None,
    command: str | None = None,
    home_dir: Path | None = None,
    project_dir: Path | None = None,
) -> list[InstallResult]:
    """Register cassette-scrub as a stdio MCP server in each target config."""
    home = home_dir or Path.home()
    project = project_dir or Path.cwd()
    entry = _resolve_mcp_entry(command)
    results: list[InstallResult] = []

    for target in _normalize_targets(targets, _DEFAULT_MCP_TARGETS, project_dir):
        if target not in SUPPORTED_TARGETS:
            results.append(InstallResult(target, "mcp", "", False, f"Unknown target: {target}"))
            continue
        for cfg_path, root_key in _mcp_specs(target, home, project):
            results.append(_merge_mcp_file(target, cfg_path, root_key, entry))
    return results


def install_pre_commit_config(
    project_dir: Path, hook_id: str = "cassette-scrub-check"
) -> InstallResult:
    """Create or update .pre-commit-config.yaml in project_dir with cassette-scrub."""
    clean_id = hook_id.strip()
    cfg_path = project_dir / ".pre-commit-config.yaml"
    if not clean_id:
        return InstallResult("project", "hook", str(cfg_path), False, "Empty hook ID.")
    if project_dir.exists() and not project_dir.is_dir():
        return InstallResult("project", "hook", str(cfg_path), False, "Project path is not a directory.")

    if cfg_path.exists():
        if not cfg_path.is_file():
            return InstallResult("project", "hook", str(cfg_path), False, "Config path is not a file.")
        try:
            parsed = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            return InstallResult("project", "hook", str(cfg_path), False, f"Invalid YAML: {exc}")
        data: dict[str, Any] = {"repos": []} if parsed is None else parsed
        if not isinstance(data, dict) or not isinstance(data.setdefault("repos", []), list):
            return InstallResult("project", "hook", str(cfg_path), False, "Invalid .pre-commit-config.yaml schema.")
    else:
        data = {"repos": []}

    repos: list[Any] = data["repos"]
    existing = next(
        (
            entry
            for entry in repos
            if isinstance(entry, dict)
            and str(entry.get("repo", "")).strip().rstrip("/") == PRE_COMMIT_REPO_URL
        ),
        None,
    )
    if existing is not None:
        existing["rev"] = PRE_COMMIT_REV
        hooks = existing.setdefault("hooks", [])
        if not isinstance(hooks, list):
            return InstallResult("project", "hook", str(cfg_path), False, "'hooks' must be a list.")
        if not any(isinstance(h, dict) and h.get("id") == clean_id for h in hooks):
            hooks.append({"id": clean_id})
    else:
        repos.append({"repo": PRE_COMMIT_REPO_URL, "rev": PRE_COMMIT_REV, "hooks": [{"id": clean_id}]})

    try:
        project_dir.mkdir(parents=True, exist_ok=True)
        with cfg_path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    except OSError as exc:
        return InstallResult("project", "hook", str(cfg_path), False, f"Write failed: {exc}")
    return InstallResult("project", "hook", str(cfg_path), True, f"Configured '{clean_id}' ({PRE_COMMIT_REV}).")
