---
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
