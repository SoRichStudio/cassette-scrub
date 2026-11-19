from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, cast

import yaml

__all__ = ["is_vcr_cassette", "load_cassette", "dump_cassette"]

_YAML_EXTENSIONS = frozenset({".yaml", ".yml"})


def is_vcr_cassette(data: Any) -> bool:
    """Return True if data matches the VCR cassette schema."""
    if not isinstance(data, dict):
        return False
    interactions = data.get("interactions")
    if not isinstance(interactions, list):
        return False
    return all(
        isinstance(item, dict)
        and isinstance(item.get("request"), dict)
        and isinstance(item.get("response"), dict)
        for item in interactions
    )


def load_cassette(path: Path) -> tuple[dict[str, Any] | None, str]:
    """Load and validate a YAML or JSON VCR cassette from disk.

    Returns ``(data, fmt)`` where ``fmt`` is ``"yaml"`` or ``"json"``,
    or ``(None, "")`` if the file is missing, unsupported, malformed,
    or not a VCR cassette.
    """
    suffix = path.suffix.lower()
    if suffix == ".json":
        fmt = "json"
    elif suffix in _YAML_EXTENSIONS:
        fmt = "yaml"
    else:
        return None, ""

    try:
        if not path.is_file():
            return None, ""
        raw_text = path.read_text(encoding="utf-8")
        if fmt == "json":
            data = json.loads(raw_text)
        else:
            data = yaml.safe_load(raw_text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError):
        return None, ""

    if not is_vcr_cassette(data):
        return None, ""
    return cast("dict[str, Any]", data), fmt


def _json_default(value: Any) -> str:
    """Safely encode bytes values when dumping to JSON."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(value).decode("ascii")
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def dump_cassette(path: Path, data: dict[str, Any], fmt: str) -> None:
    """Write a VCR cassette dict to path in UTF-8 YAML or JSON format."""
    if fmt == "yaml":
        serialized = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    elif fmt == "json":
        serialized = json.dumps(data, indent=2, default=_json_default) + "\n"
    else:
        raise ValueError(f"Unsupported cassette format: {fmt!r}")

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(serialized)
