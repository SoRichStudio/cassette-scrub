---
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
