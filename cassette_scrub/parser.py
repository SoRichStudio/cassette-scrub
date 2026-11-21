from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, cast

import yaml

__all__ = ["_json_default", "dump_cassette", "is_vcr_cassette", "load_cassette"]

_YAML_EXTS = frozenset({".yaml", ".yml"})


def is_vcr_cassette(data: Any) -> bool:
    """Return True if data looks like a VCR.py cassette mapping."""
    if not isinstance(data, dict):
        return False
    interactions = data.get("interactions")
    return isinstance(interactions, list) and all(
        isinstance(item, dict)
        and isinstance(item.get("request"), dict)
        and isinstance(item.get("response"), dict)
        for item in interactions
    )


def load_cassette(path: Path) -> tuple[dict[str, Any] | None, str]:
    """Load a YAML or JSON VCR cassette, or return ``(None, "")`` if skipped/invalid."""
    suffix = path.suffix.lower()
    fmt = "json" if suffix == ".json" else ("yaml" if suffix in _YAML_EXTS else "")
    if not fmt or not path.is_file():
        return None, ""
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text) if fmt == "json" else yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError):
        return None, ""
    if not is_vcr_cassette(data):
        return None, ""
    return cast("dict[str, Any]", data), fmt


def _json_default(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(value).decode("ascii")
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def dump_cassette(path: Path, data: dict[str, Any], fmt: str) -> None:
    """Write cassette data back to disk in YAML or JSON format."""
    if fmt == "yaml":
        out = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    elif fmt == "json":
        out = json.dumps(data, indent=2, default=_json_default) + "\n"
    else:
        raise ValueError(f"Unsupported cassette format: {fmt!r}")
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(out)
