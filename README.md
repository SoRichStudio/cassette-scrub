# cassette-scrub

Check and scrub sensitive headers, query parameters, API tokens, and email PII from [VCR.py](https://vcrpy.readthedocs.io/) YAML and JSON cassettes.

## Features

- Automatically identifies valid VCR cassettes (`interactions` with `request` and `response` entries) and leaves non-cassette YAML/JSON files untouched.
- Redacts sensitive request and response headers (such as `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `Cookie`, and `Set-Cookie`) while preserving `Bearer`/`Basic` prefixes and cookie names/attributes.
- Redacts sensitive URI query parameters, form-encoded fields, and nested JSON keys.
- Scrubs common API key formats (Anthropic, OpenAI, GitHub, AWS access keys, and JWTs) and email PII (`<REDACTED_EMAIL>`).
- Updates `Content-Length` headers accurately when body lengths change and preserves binary payloads.
- Idempotent on already-scrubbed cassettes.

## Installation

```bash
pip install cassette-scrub
```

## Quickstart with `pre-commit`

Add `cassette-scrub` to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/SoRichStudio/cassette-scrub
    rev: v0.1.0
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
    rev: v0.1.0
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
- `--no-pii`: Disable email PII scrubbing (`<REDACTED_EMAIL>`) while still redacting headers, query parameters, body keys, and API tokens.

### Examples

Check all cassettes under `tests/`:

```bash
cassette-scrub --check tests/
```

Scrub a specific cassette file in place:

```bash
cassette-scrub --fix tests/cassettes/login.yaml
```

Scrub in place in CI/scripts without failing on edits, while preserving emails:

```bash
cassette-scrub --fix --exit-zero-on-fix --no-pii tests/cassettes/
```

Sample output when a finding is detected:

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
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `extra_headers` | `list[str]` | `[]` | Additional HTTP header names (case-insensitive) to redact. |
| `extra_query_keys` | `list[str]` | `[]` | Additional URI query parameter names (case-insensitive) to redact. |
| `extra_body_keys` | `list[str]` | `[]` | Additional JSON/form body keys (case-insensitive) to redact. |
| `scrub_pii` | `bool` | `true` | Enable or disable email PII redaction (`--no-pii` always disables it). |
