# cassette-scrub

Find and redact API keys, auth headers, cookies, query tokens, and email addresses in [VCR.py](https://vcrpy.readthedocs.io/) YAML and JSON cassettes. Other YAML and JSON files are ignored.

## Install

```bash
pip install cassette-scrub
```

Standalone Windows builds (`cassette-scrub.exe` and `cassette-scrub-gui.exe`) are on the [Releases page](https://github.com/SoRichStudio/cassette-scrub/releases). Opening `cassette-scrub.exe` with no arguments starts the desktop window; passing flags or paths runs it in the terminal (or set `CASSETTE_SCRUB_NO_GUI=1`).

To build the `.exe` files from source on Windows:

```bash
cassette-scrub --build-exe
```

## Usage

```bash
# Check files (exits 1 if secrets or emails are found)
cassette-scrub tests/

# Show unified diffs without editing files
cassette-scrub --diff tests/

# Redact matches in place
cassette-scrub --fix tests/

# Redact in place, keep emails, and exit 0
cassette-scrub --fix --exit-zero-on-fix --no-pii tests/

# Output JSON for scripts or CI
cassette-scrub --check --json tests/

# Open the desktop window
cassette-scrub --gui
```

## Pre-commit

Add the hook manually or run `cassette-scrub --install-hook`:

```yaml
repos:
  - repo: https://github.com/SoRichStudio/cassette-scrub
    rev: v0.2.0
    hooks:
      - id: cassette-scrub-check
```

Use `cassette-scrub-fix` (with `args: [--exit-zero-on-fix]` if desired) to rewrite files automatically instead of failing the commit.

## Configuration

Settings are read from `[tool.cassette-scrub]` in the nearest `pyproject.toml`:

```toml
[tool.cassette-scrub]
extra_headers = ["x-internal-secret"]
extra_query_keys = ["tenant_secret"]
extra_body_keys = ["private_note"]
scrub_pii = true
custom_patterns = ["INTERNAL_KEY_[A-Z0-9]{12,}"]
allowlist = ["public-demo-token"]
```

## Editor and AI tool setup

```bash
cassette-scrub --install-skill
cassette-scrub --install-mcp
cassette-scrub /path/to/repo --install-skill project --install-mcp project
```

Supported targets: `antigravity`, `claude`, `codex`, `cursor`, `windsurf`, `vscode` (MCP), `project`, and `all`. You can also start the stdio MCP server directly with `cassette-scrub --mcp` (or `cassette-scrub-mcp`).
