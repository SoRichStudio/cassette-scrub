from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from cassette_scrub.types import ScrubConfig


def _str_list(raw: Any, *, lower: bool = False) -> list[str]:
    if not isinstance(raw, (list, tuple, set)):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            s = item.strip()
            out.append(s.lower() if lower else s)
    return out


def _find_pyproject(start_dir: Path) -> Path | None:
    base = start_dir.resolve()
    if base.is_file():
        base = base.parent
    for d in (base, *base.parents):
        candidate = d / "pyproject.toml"
        if candidate.is_file():
            return candidate
    return None


def load_config(start_dir: Path | None = None, scrub_pii: bool = True) -> ScrubConfig:
    """Load ``[tool.cassette-scrub]`` from the nearest ``pyproject.toml``."""
    pyproject = _find_pyproject(start_dir or Path.cwd())
    if pyproject is None:
        return ScrubConfig(scrub_pii=scrub_pii)
    try:
        with pyproject.open("rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return ScrubConfig(scrub_pii=scrub_pii)

    tool = parsed.get("tool")
    cfg = tool.get("cassette-scrub") if isinstance(tool, dict) else None
    if not isinstance(cfg, dict):
        cfg = {}

    cfg_pii = cfg.get("scrub_pii", True)
    effective_pii = (cfg_pii if isinstance(cfg_pii, bool) else True) and bool(scrub_pii)

    return ScrubConfig(
        extra_headers=set(_str_list(cfg.get("extra_headers"), lower=True)),
        extra_query_keys=set(_str_list(cfg.get("extra_query_keys"), lower=True)),
        extra_body_keys=set(_str_list(cfg.get("extra_body_keys"), lower=True)),
        scrub_pii=effective_pii,
        custom_patterns=tuple(_str_list(cfg.get("custom_patterns"))),
        allowlist=set(_str_list(cfg.get("allowlist"))),
    )
