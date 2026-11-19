from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from cassette_scrub.types import ScrubConfig


def _normalize_string_set(raw: Any) -> set[str]:
    """Normalize a TOML sequence of strings into a lowercased non-empty set."""
    if not isinstance(raw, (list, tuple, set)):
        return set()
    return {
        str(item).strip().lower()
        for item in raw
        if isinstance(item, str) and item.strip()
    }


def _find_pyproject(start_dir: Path) -> Path | None:
    """Locate the nearest pyproject.toml starting from start_dir and walking upward."""
    base = start_dir.resolve()
    if base.is_file():
        base = base.parent
    for directory in (base, *base.parents):
        candidate = directory / "pyproject.toml"
        if candidate.is_file():
            return candidate
    return None


def load_config(start_dir: Path | None = None, scrub_pii: bool = True) -> ScrubConfig:
    """Load [tool.cassette-scrub] configuration from the nearest pyproject.toml."""
    base = start_dir if start_dir is not None else Path.cwd()
    pyproject = _find_pyproject(base)
    if pyproject is None:
        return ScrubConfig(
            extra_headers=set(),
            extra_query_keys=set(),
            extra_body_keys=set(),
            scrub_pii=scrub_pii,
        )

    try:
        with pyproject.open("rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return ScrubConfig(
            extra_headers=set(),
            extra_query_keys=set(),
            extra_body_keys=set(),
            scrub_pii=scrub_pii,
        )

    tool_section = parsed.get("tool")
    if not isinstance(tool_section, dict):
        tool_cfg: dict[str, Any] = {}
    else:
        raw_cfg = tool_section.get("cassette-scrub")
        tool_cfg = raw_cfg if isinstance(raw_cfg, dict) else {}

    config_scrub_pii = tool_cfg.get("scrub_pii", True)
    effective_scrub_pii = (
        bool(config_scrub_pii) if isinstance(config_scrub_pii, bool) else True
    ) and bool(scrub_pii)

    return ScrubConfig(
        extra_headers=_normalize_string_set(tool_cfg.get("extra_headers")),
        extra_query_keys=_normalize_string_set(tool_cfg.get("extra_query_keys")),
        extra_body_keys=_normalize_string_set(tool_cfg.get("extra_body_keys")),
        scrub_pii=effective_scrub_pii,
    )
