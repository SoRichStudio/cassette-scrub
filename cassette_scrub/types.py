from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScrubConfig:
    """Configuration controlling cassette scrubbing behavior."""

    extra_headers: set[str] = field(default_factory=set)
    extra_query_keys: set[str] = field(default_factory=set)
    extra_body_keys: set[str] = field(default_factory=set)
    scrub_pii: bool = True


@dataclass(frozen=True)
class Finding:
    """Single sensitive value detected or scrubbed inside a cassette."""

    file_path: str
    interaction_index: int
    location: str
    preview: str


@dataclass(frozen=True)
class ScrubResult:
    """Outcome of scrubbing a parsed VCR cassette."""

    modified: bool
    findings: list[Finding]
    updated_data: dict[str, Any] | None = None
