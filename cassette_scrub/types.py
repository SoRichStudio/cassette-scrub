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
    custom_patterns: tuple[str, ...] = ()
    allowlist: set[str] = field(default_factory=set)


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


@dataclass(frozen=True)
class InstallResult:
    """Result of installing a skill, MCP server config, or hook into a target."""

    target: str
    kind: str
    path: str
    success: bool
    message: str
