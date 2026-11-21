from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScrubConfig:
    extra_headers: set[str] = field(default_factory=set)
    extra_query_keys: set[str] = field(default_factory=set)
    extra_body_keys: set[str] = field(default_factory=set)
    scrub_pii: bool = True
    custom_patterns: tuple[str, ...] = ()
    allowlist: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Finding:
    file_path: str
    interaction_index: int
    location: str
    preview: str


@dataclass(frozen=True)
class ScrubResult:
    modified: bool
    findings: list[Finding]
    updated_data: dict[str, Any] | None = None


@dataclass(frozen=True)
class InstallResult:
    target: str
    kind: str
    path: str
    success: bool
    message: str
