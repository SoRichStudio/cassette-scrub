from __future__ import annotations

import json
import shutil
import sys
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

_DEFAULT_MCP_TARGETS: Final[tuple[str, ...]] = (
    "antigravity",
    "claude",
    "codex",
    "cursor",
    "windsurf",
    "vscode",
)

PRE_COMMIT_REPO_URL: Final[str] = "https://github.com/SoRichStudio/cassette-scrub"
PRE_COMMIT_REV: Final[str] = "v0.2.0"

_EMBEDDED_SKILL_MARKDOWN: Final[str] = """---
name: cassette-scrub
description: Scan, diff, and scrub secrets, sensitive headers, query parameters, and email PII from VCR.py YAML and JSON cassettes via CLI or MCP tools.
---

# cassette-scrub (`/cassette-scrub`)

Check, preview diffs for, and scrub secrets, credentials, cookies, and email PII from [VCR.py](https://vcrpy.readthedocs.io/) YAML (`.yaml`, `.yml`) and JSON (`.json`) cassettes. Non-cassette YAML and JSON files are left untouched.

## When to Use

- Before committing recorded HTTP fixtures or test cassettes to source control
- When auditing existing VCR cassettes for leaked credentials, tokens, or email addresses
- When configuring project-specific redaction rules in `pyproject.toml` or pre-commit hooks

## CLI Commands

Run with `cassette-scrub` (or `python -m cassette_scrub.cli`):

```bash
# Check cassettes without modifying files (exits 1 if findings exist, 0 if clean)
cassette-scrub --check tests/

# Print unified diffs for dirty cassettes without writing changes
cassette-scrub --diff tests/

# Output machine-readable JSON findings and summary
cassette-scrub --check --json tests/

# Scrub detected secrets and email PII in place
cassette-scrub --fix tests/

# Scrub in place while keeping exit code 0 in scripts/hooks
cassette-scrub --fix --exit-zero-on-fix tests/

# Scrub secrets and headers while preserving email addresses
cassette-scrub --fix --no-pii tests/

# Launch desktop GUI or start stdio MCP server
cassette-scrub --gui
cassette-scrub --mcp
```

## MCP Tools

When registered as an MCP server (`cassette-scrub --mcp` or `cassette-scrub-mcp`), the following tools are exposed:

- `cassette_scrub_scan`: Scan cassette files or directories (`paths`, `scrub_pii`) and return a JSON summary and findings list without modifying files.
- `cassette_scrub_diff`: Return unified diffs (`paths`, `scrub_pii`) showing exact redactions that scrubbing would apply.
- `cassette_scrub_fix`: Scrub detected secrets and PII in place (`paths`, `scrub_pii`) and return modified file paths and findings.
- `cassette_scrub_install`: Install the `/cassette-scrub` skill, MCP server configuration, and/or `.pre-commit-config.yaml` hook (`action`: `skill` | `mcp` | `hook` | `all`, `targets`, `project_dir`).

## Configuration (`[tool.cassette-scrub]`)

`cassette-scrub` walks upward from each cassette's directory to load `[tool.cassette-scrub]` from the nearest `pyproject.toml`:

```toml
[tool.cassette-scrub]
extra_headers = ["x-internal-secret", "x-session-id"]
extra_query_keys = ["tenant_secret"]
extra_body_keys = ["private_note", "internal_token"]
scrub_pii = true
custom_patterns = ["INTERNAL_KEY_[A-Z0-9]{12}"]
allowlist = ["public-demo-token", "fixture-placeholder"]
```

- `extra_headers`: Additional HTTP header names (case-insensitive) to replace with `<REDACTED>`.
- `extra_query_keys`: Additional URI query parameter names (case-insensitive) to replace with `<REDACTED>`.
- `extra_body_keys`: Additional JSON or form-encoded body keys (case-insensitive) to replace with `<REDACTED>`.
- `scrub_pii`: Enable or disable email PII redaction (`<REDACTED_EMAIL>`). `--no-pii` always overrides this to `false`.
- `custom_patterns`: Additional regex patterns whose matches are scrubbed with `<REDACTED>`.
- `allowlist`: Exact string values that remain unredacted and do not emit findings.

## Pre-commit & Multi-Agent Setup

Install a `.pre-commit-config.yaml` hook into a repository:

```bash
cassette-scrub --install-hook
```

Or configure `.pre-commit-config.yaml` manually (`cassette-scrub-check` to fail on findings, or `cassette-scrub-fix` to scrub in place):

```yaml
repos:
  - repo: https://github.com/SoRichStudio/cassette-scrub
    rev: v0.2.0
    hooks:
      - id: cassette-scrub-check
```

Install the `/cassette-scrub` skill or MCP server configuration across supported AI tools (`antigravity`, `claude`, `codex`, `cursor`, `windsurf`, `vscode`, `project`, or `all`):

```bash
cassette-scrub --install-skill all
cassette-scrub --install-mcp all
```

## Safe Usage Rules

1. Run `--check` or `--diff` (or `cassette_scrub_scan` / `cassette_scrub_diff`) before `--fix` when inspecting changes.
2. Never echo raw secrets in summaries; reference `<REDACTED>` / `<REDACTED_EMAIL>` previews and `file_path:interaction[index] location`.
3. Re-run `--check` after `--fix` to confirm zero remaining findings and idempotency.
"""


def get_skill_markdown() -> str:
    """Return the /cassette-scrub SKILL.md markdown, falling back to embedded text."""
    candidate = (
        Path(__file__).resolve().parent.parent / "skills" / "cassette-scrub" / "SKILL.md"
    )
    try:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        pass
    return _EMBEDDED_SKILL_MARKDOWN


def _normalize_targets(
    targets: list[str] | None,
    default_targets: tuple[str, ...],
    project_dir: Path | None,
) -> list[str]:
    """Normalize target names, expanding empty lists or 'all' safely."""
    cleaned = [t.strip().lower() for t in (targets or []) if isinstance(t, str) and t.strip()]
    if not cleaned or "all" in cleaned:
        resolved = list(default_targets)
        if (project_dir is not None or "project" in cleaned) and "project" not in resolved:
            resolved.append("project")
        for item in cleaned:
            if item != "all" and item not in resolved:
                resolved.append(item)
        return resolved

    deduped: list[str] = []
    seen: set[str] = set()
    for item in cleaned:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _skill_paths_for_target(target: str, home: Path, project: Path) -> list[Path]:
    """Return destination skill file path(s) for a normalized skill target."""
    if target == "antigravity":
        return [home / ".gemini" / "config" / "skills" / "cassette-scrub" / "SKILL.md"]
    if target == "claude":
        return [
            home / ".claude" / "skills" / "cassette-scrub" / "SKILL.md",
            home / ".claude" / "commands" / "cassette-scrub.md",
        ]
    if target == "codex":
        return [home / ".codex" / "skills" / "cassette-scrub" / "SKILL.md"]
    if target == "cursor":
        return [home / ".cursor" / "skills" / "cassette-scrub" / "SKILL.md"]
    if target == "windsurf":
        return [home / ".codeium" / "windsurf" / "skills" / "cassette-scrub" / "SKILL.md"]
    if target == "project":
        return [
            project / ".agent" / "skills" / "cassette-scrub" / "SKILL.md",
            project / ".claude" / "skills" / "cassette-scrub" / "SKILL.md",
        ]
    return []


def install_skill(
    targets: list[str] | None = None,
    home_dir: Path | None = None,
    project_dir: Path | None = None,
) -> list[InstallResult]:
    """Install /cassette-scrub skill files for the requested AI coding assistants."""
    home = home_dir if home_dir is not None else Path.home()
    project = project_dir if project_dir is not None else Path.cwd()
    normalized = _normalize_targets(targets, _DEFAULT_SKILL_TARGETS, project_dir)
    content = get_skill_markdown()
    results: list[InstallResult] = []

    for target in normalized:
        if target not in SUPPORTED_TARGETS:
            results.append(
                InstallResult(
                    target=target,
                    kind="skill",
                    path="",
                    success=False,
                    message=f"Unsupported skill target: {target}",
                )
            )
            continue

        if target == "vscode":
            continue

        for dest in _skill_paths_for_target(target, home, project):
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open("w", encoding="utf-8", newline="\n") as handle:
                    handle.write(content)
                results.append(
                    InstallResult(
                        target=target,
                        kind="skill",
                        path=str(dest),
                        success=True,
                        message="Installed cassette-scrub skill.",
                    )
                )
            except OSError as exc:
                results.append(
                    InstallResult(
                        target=target,
                        kind="skill",
                        path=str(dest),
                        success=False,
                        message=f"Failed to write skill file: {exc}",
                    )
                )

    return results


def _resolve_mcp_server_entry(command: str | None = None) -> dict[str, Any]:
    """Determine the MCP server command and arguments entry."""
    if command is not None and command.strip():
        return {"command": command.strip(), "args": ["--mcp"]}

    which_exe = shutil.which("cassette-scrub")
    if which_exe:
        return {"command": str(which_exe), "args": ["--mcp"]}

    scripts_exe = Path(sys.executable).with_name("Scripts") / "cassette-scrub.exe"
    if scripts_exe.is_file():
        return {"command": str(scripts_exe), "args": ["--mcp"]}

    sibling_exe = Path(sys.executable).with_name("cassette-scrub.exe")
    if sibling_exe.is_file():
        return {"command": str(sibling_exe), "args": ["--mcp"]}

    return {"command": sys.executable, "args": ["-m", "cassette_scrub.cli", "--mcp"]}


def _mcp_specs_for_target(
    target: str, home: Path, project: Path
) -> list[tuple[Path, str]]:
    """Return ``(config_path, root_key)`` pairs for an MCP target."""
    if target == "antigravity":
        return [(home / ".gemini" / "config" / "mcp_config.json", "mcpServers")]
    if target == "claude":
        return [
            (home / ".claude.json", "mcpServers"),
            (
                home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
                "mcpServers",
            ),
        ]
    if target == "codex":
        return [(home / ".codex" / "mcp.json", "mcpServers")]
    if target == "cursor":
        return [(home / ".cursor" / "mcp.json", "mcpServers")]
    if target == "windsurf":
        return [(home / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers")]
    if target == "vscode":
        return [(home / "AppData" / "Roaming" / "Code" / "User" / "mcp.json", "servers")]
    if target == "project":
        return [(project / ".mcp.json", "mcpServers")]
    return []


def _merge_mcp_config_file(
    target: str,
    config_path: Path,
    root_key: str,
    server_entry: dict[str, Any],
) -> InstallResult:
    """Merge the cassette-scrub MCP server entry into a JSON config file safely."""
    data: dict[str, Any]

    if config_path.exists():
        if not config_path.is_file():
            return InstallResult(
                target=target,
                kind="mcp",
                path=str(config_path),
                success=False,
                message=f"Target path exists and is not a file: {config_path}",
            )
        try:
            raw_text = config_path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            return InstallResult(
                target=target,
                kind="mcp",
                path=str(config_path),
                success=False,
                message=f"Failed to read MCP config: {exc}",
            )

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            return InstallResult(
                target=target,
                kind="mcp",
                path=str(config_path),
                success=False,
                message=f"Malformed JSON in existing MCP config (left untouched): {exc}",
            )

        if not isinstance(parsed, dict):
            return InstallResult(
                target=target,
                kind="mcp",
                path=str(config_path),
                success=False,
                message="Existing MCP config root must be a JSON object (left untouched).",
            )

        data = parsed
        existing_section = data.get(root_key)
        if existing_section is None:
            data[root_key] = {}
        elif not isinstance(existing_section, dict):
            return InstallResult(
                target=target,
                kind="mcp",
                path=str(config_path),
                success=False,
                message=(
                    f"Existing '{root_key}' entry is not a JSON object (left untouched)."
                ),
            )
    else:
        data = {root_key: {}}

    data[root_key]["cassette-scrub"] = dict(server_entry)

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(data, indent=2) + "\n"
        with config_path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(serialized)
    except OSError as exc:
        return InstallResult(
            target=target,
            kind="mcp",
            path=str(config_path),
            success=False,
            message=f"Failed to write MCP config: {exc}",
        )

    return InstallResult(
        target=target,
        kind="mcp",
        path=str(config_path),
        success=True,
        message=f"Configured cassette-scrub MCP server in '{root_key}'.",
    )


def install_mcp(
    targets: list[str] | None = None,
    command: str | None = None,
    home_dir: Path | None = None,
    project_dir: Path | None = None,
) -> list[InstallResult]:
    """Install cassette-scrub MCP server entries for the requested AI tools."""
    home = home_dir if home_dir is not None else Path.home()
    project = project_dir if project_dir is not None else Path.cwd()
    normalized = _normalize_targets(targets, _DEFAULT_MCP_TARGETS, project_dir)
    server_entry = _resolve_mcp_server_entry(command=command)
    results: list[InstallResult] = []

    for target in normalized:
        if target not in SUPPORTED_TARGETS:
            results.append(
                InstallResult(
                    target=target,
                    kind="mcp",
                    path="",
                    success=False,
                    message=f"Unsupported MCP target: {target}",
                )
            )
            continue

        for config_path, root_key in _mcp_specs_for_target(target, home, project):
            results.append(
                _merge_mcp_config_file(
                    target=target,
                    config_path=config_path,
                    root_key=root_key,
                    server_entry=server_entry,
                )
            )

    return results


def install_pre_commit_config(
    project_dir: Path, hook_id: str = "cassette-scrub-check"
) -> InstallResult:
    """Safely create or update .pre-commit-config.yaml inside project_dir."""
    clean_hook_id = hook_id.strip()
    config_path = project_dir / ".pre-commit-config.yaml"

    if not clean_hook_id:
        return InstallResult(
            target="project",
            kind="hook",
            path=str(config_path),
            success=False,
            message="Pre-commit hook ID must not be empty.",
        )

    if project_dir.exists() and not project_dir.is_dir():
        return InstallResult(
            target="project",
            kind="hook",
            path=str(config_path),
            success=False,
            message=f"Project path exists and is not a directory: {project_dir}",
        )

    data: dict[str, Any]
    if config_path.exists():
        if not config_path.is_file():
            return InstallResult(
                target="project",
                kind="hook",
                path=str(config_path),
                success=False,
                message=f"Pre-commit config path exists and is not a file: {config_path}",
            )
        try:
            raw_text = config_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(raw_text)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            return InstallResult(
                target="project",
                kind="hook",
                path=str(config_path),
                success=False,
                message=f"Failed to parse existing .pre-commit-config.yaml (left untouched): {exc}",
            )

        if parsed is None:
            data = {"repos": []}
        elif not isinstance(parsed, dict):
            return InstallResult(
                target="project",
                kind="hook",
                path=str(config_path),
                success=False,
                message="Existing .pre-commit-config.yaml root must be a mapping (left untouched).",
            )
        else:
            data = parsed
            repos_section = data.get("repos")
            if repos_section is None:
                data["repos"] = []
            elif not isinstance(repos_section, list):
                return InstallResult(
                    target="project",
                    kind="hook",
                    path=str(config_path),
                    success=False,
                    message="Existing 'repos' key in .pre-commit-config.yaml must be a list (left untouched).",
                )
    else:
        data = {"repos": []}

    repos: list[Any] = data["repos"]
    existing_repo: dict[str, Any] | None = None
    for entry in repos:
        if (
            isinstance(entry, dict)
            and str(entry.get("repo", "")).strip().rstrip("/") == PRE_COMMIT_REPO_URL
        ):
            existing_repo = entry
            break

    if existing_repo is not None:
        existing_repo["rev"] = PRE_COMMIT_REV
        hooks = existing_repo.get("hooks")
        if hooks is None:
            existing_repo["hooks"] = [{"id": clean_hook_id}]
        elif not isinstance(hooks, list):
            return InstallResult(
                target="project",
                kind="hook",
                path=str(config_path),
                success=False,
                message="Existing 'hooks' entry for cassette-scrub must be a list (left untouched).",
            )
        else:
            if not any(
                isinstance(item, dict) and item.get("id") == clean_hook_id
                for item in hooks
            ):
                hooks.append({"id": clean_hook_id})
    else:
        repos.append(
            {
                "repo": PRE_COMMIT_REPO_URL,
                "rev": PRE_COMMIT_REV,
                "hooks": [{"id": clean_hook_id}],
            }
        )

    try:
        project_dir.mkdir(parents=True, exist_ok=True)
        serialized = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
        with config_path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(serialized)
    except OSError as exc:
        return InstallResult(
            target="project",
            kind="hook",
            path=str(config_path),
            success=False,
            message=f"Failed to write .pre-commit-config.yaml: {exc}",
        )

    return InstallResult(
        target="project",
        kind="hook",
        path=str(config_path),
        success=True,
        message=f"Configured pre-commit hook '{clean_hook_id}' ({PRE_COMMIT_REV}).",
    )
