# cassette-scrub

Check and scrub sensitive headers, query parameters, API tokens, and email PII from [VCR.py](https://vcrpy.readthedocs.io/) YAML and JSON cassettes — via CLI, dark utilitarian Desktop GUI, `pre-commit`, MCP server, or AI coding assistant skills.

## Features

- Automatically identifies valid VCR cassettes (`interactions` with `request` and `response` entries) and leaves non-cassette YAML/JSON files untouched.
- Redacts sensitive request and response headers (such as `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `Api-Key`, `X-Auth-Token`, `Cookie`, `Set-Cookie`, `X-Csrf-Token`, and `X-Amz-Security-Token`) while preserving `Bearer`/`Basic` prefixes and cookie names/attributes.
- Redacts sensitive URI query parameters, form-encoded fields, and nested JSON body keys.
- Expanded built-in secret detectors for **Anthropic**, **OpenAI**, **GitHub**, **AWS**, **JWT**, **Stripe**, **Slack** (tokens & incoming webhooks), **Google / GCP** (API keys & OAuth tokens), **SendGrid**, **Twilio**, **Discord** webhooks, and **PEM private keys**, plus email PII (`<REDACTED_EMAIL>`).
- Supports `custom_patterns` (regex detectors) and `allowlist` (exact value exemptions) in `pyproject.toml`.
- Updates `Content-Length` headers accurately when body lengths change, safely skips non-UTF-8 binary payloads, and is idempotent on already-scrubbed cassettes.
- Machine-readable `--json` reports and unified `--diff` previews.
- Dark utilitarian Desktop GUI (`--gui`) and standalone Windows `.exe` builds (`--build-exe`).
- Built-in `/cassette-scrub` AI Skill, stdio MCP server (`--mcp`), and one-click installer (`--install-skill`, `--install-mcp`, `--install-hook`) for Antigravity, Claude, Codex, Cursor, Windsurf, VS Code, and project repositories.

## Installation

### Download Standalone Windows Executables (No Python Required)

Download the pre-built Windows binaries from [GitHub Releases](https://github.com/SoRichStudio/cassette-scrub/releases):

- **`cassette-scrub.exe`**: Launches the Desktop GUI when opened with no arguments, or runs as the full CLI when invoked with flags or paths (set `CASSETTE_SCRUB_NO_GUI=1` to force CLI mode with no arguments).
- **`cassette-scrub-gui.exe`**: Launches the Desktop GUI directly with no console window.

### Install via pip

```bash
pip install cassette-scrub
```

### Build Standalone `.exe` Locally

```bash
cassette-scrub --build-exe
```

Outputs `dist/cassette-scrub.exe` and `dist/cassette-scrub-gui.exe`. Pass a directory path before `--build-exe` to write executables to a custom output folder.

## Desktop GUI

Launch the dark utilitarian Desktop GUI via:

```bash
cassette-scrub --gui
# or:
cassette-scrub-gui
```

The GUI provides:

- Directory/file target picker and PII scrubbing toggle
- **SCAN**, **DIFF PREVIEW**, **SCRUB IN-PLACE**, **COPY JSON REPORT**, and **BUILD .EXE** actions
- Split findings list and color-coded unified diff inspector
- Built-in **AI Skill (`/cassette-scrub`) & MCP Installer** panel for Antigravity, Claude, Codex, Cursor, Windsurf, VS Code, and project `pre-commit` hooks

## AI Skill (`/cassette-scrub`) & MCP Server

### One-Click Multi-Agent Installer

Install the `/cassette-scrub` skill, MCP server configuration, and `pre-commit` hook across supported AI coding assistants and repositories:

```bash
# Install the /cassette-scrub skill for all global assistants (or specify targets)
cassette-scrub --install-skill
cassette-scrub --install-skill antigravity claude codex cursor windsurf

# Install the cassette-scrub MCP server config (merges safely into existing JSON configs)
cassette-scrub --install-mcp
cassette-scrub --install-mcp antigravity claude codex cursor windsurf vscode

# Install skill and MCP config into a specific project repository
cassette-scrub /path/to/repo --install-skill project --install-mcp project

# Install .pre-commit-config.yaml hook into the current or specified repository
cassette-scrub --install-hook
cassette-scrub /path/to/repo --install-hook
```

Supported targets: `antigravity`, `claude`, `codex`, `cursor`, `windsurf`, `vscode` (MCP), `project`, and `all`.

### Stdio MCP Server

Start the JSON-RPC 2.0 stdio MCP server manually or via your assistant's MCP config:

```bash
cassette-scrub --mcp
# or:
cassette-scrub-mcp
```

Exposed MCP tools:

- `cassette_scrub_scan`: Scan files or directories without modifying them and return structured findings.
- `cassette_scrub_fix`: Scrub detected secrets and PII from cassettes in place.
- `cassette_scrub_diff`: Generate unified diffs showing pending redactions without modifying files.
- `cassette_scrub_install`: Install `/cassette-scrub` skills, MCP configs, or `.pre-commit-config.yaml` hooks.

## Quickstart with `pre-commit`

Install automatically with `cassette-scrub --install-hook`, or add `cassette-scrub` to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/SoRichStudio/cassette-scrub
    rev: v0.2.0
    hooks:
      - id: cassette-scrub-check
```

### Available Hooks

| Hook ID | Entry | Behavior |
| --- | --- | --- |
| `cassette-scrub-check` | `cassette-scrub --check` | Fails commit if secrets or PII are detected; does not modify files. |
| `cassette-scrub-fix` | `cassette-scrub --fix` | Scrubs cassettes in place and exits non-zero when files are updated so changes can be staged. |

Both hooks target files matching `(cassette|cassettes|vcr).*\.(yaml|yml|json)$`.

To scrub automatically and allow commits to proceed without re-failing on modification:

```yaml
repos:
  - repo: https://github.com/SoRichStudio/cassette-scrub
    rev: v0.2.0
    hooks:
      - id: cassette-scrub-fix
        args: [--exit-zero-on-fix]
```

## CLI Usage

```bash
cassette-scrub [OPTIONS] [PATHS...]
```

When given directories (or omitted, which defaults to `.`), `cassette-scrub` recursively scans `*.yaml`, `*.yml`, and `*.json` files while skipping `.git`, `.venv`, `venv`, `__pycache__`, `.tox`, `.pytest_cache`, `.mypy_cache`, and `node_modules`.

### Options

- `--check`: Scan cassettes and report findings without modifying files (default mode when `--fix` is omitted). Exits `1` if findings are found, `0` otherwise.
- `--fix`: Scrub detected secrets and PII in place. Exits `1` if any files were modified, or `0` if no files changed.
- `--exit-zero-on-fix`: Return exit code `0` even when `--fix` modifies files.
- `--no-pii`: Disable email PII scrubbing (`<REDACTED_EMAIL>`) while still redacting secrets and headers.
- `--json`: Emit machine-readable JSON output instead of plain lines, preserving `--check`, `--fix`, `--exit-zero-on-fix`, and installer exit codes.
- `--diff`: Print unified diffs for dirty or modified cassettes.
- `--gui`: Launch the desktop GUI (optionally seeded with the first provided path).
- `--mcp`: Start the stdio MCP server.
- `--install-skill [TARGET ...]`: Install the `/cassette-scrub` skill for specified targets (or `all` when omitted).
- `--install-mcp [TARGET ...]`: Install MCP server config for specified targets (or `all` when omitted).
- `--install-hook`: Install the `cassette-scrub-check` hook into `.pre-commit-config.yaml`.
- `--build-exe`: Build standalone `cassette-scrub.exe` and `cassette-scrub-gui.exe` into `dist/` (or the provided path).
- `--version`: Show the installed `cassette-scrub` version and exit.

### Examples

Check all cassettes under `tests/`:

```bash
cassette-scrub --check tests/
```

Preview unified diffs without modifying files:

```bash
cassette-scrub --check --diff tests/cassettes/
```

Emit machine-readable JSON output for CI pipelines:

```bash
cassette-scrub --check --json tests/cassettes/
```

Sample `--json` output:

```json
{
  "version": "0.2.0",
  "modified": false,
  "files_scanned": 1,
  "files_with_findings": 1,
  "findings": [
    {
      "file_path": "tests/cassettes/login.yaml",
      "interaction_index": 0,
      "location": "request.headers.Authorization",
      "preview": "sec... -> Bearer <REDACTED>"
    }
  ]
}
```

Scrub a specific cassette file in place:

```bash
cassette-scrub --fix tests/cassettes/login.yaml
```

Scrub in place in CI/scripts without failing on edits, while preserving emails:

```bash
cassette-scrub --fix --exit-zero-on-fix --no-pii tests/cassettes/
```

Sample terminal output when a finding is detected:

```text
tests/cassettes/login.yaml:interaction[0] request.headers.Authorization: sec... -> Bearer <REDACTED>
```

## Configuration

`cassette-scrub` loads `[tool.cassette-scrub]` from the nearest `pyproject.toml` found by walking upward from each cassette's directory:

```toml
[tool.cassette-scrub]
extra_headers = ["x-internal-secret", "x-session-id"]
extra_query_keys = ["tenant_secret"]
extra_body_keys = ["private_note", "internal_token"]
scrub_pii = true
custom_patterns = ['INTERNAL_KEY_[A-Z0-9]{12,}']
allowlist = ["example-safe-placeholder", "public-demo-token"]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `extra_headers` | `list[str]` | `[]` | Additional HTTP header names (case-insensitive) to redact. |
| `extra_query_keys` | `list[str]` | `[]` | Additional URI query parameter names (case-insensitive) to redact. |
| `extra_body_keys` | `list[str]` | `[]` | Additional JSON/form body keys (case-insensitive) to redact. |
| `scrub_pii` | `bool` | `true` | Enable or disable email PII redaction (`--no-pii` always disables it). |
| `custom_patterns` | `list[str]` | `[]` | Additional regular expressions whose matches are replaced with `<REDACTED>`. |
| `allowlist` | `list[str]` | `[]` | Exact values exempted from redaction and findings. |
