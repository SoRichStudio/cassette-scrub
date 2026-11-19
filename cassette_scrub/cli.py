from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Final

from cassette_scrub import __version__
from cassette_scrub.config import load_config
from cassette_scrub.parser import dump_cassette, load_cassette
from cassette_scrub.scrubber import scrub_cassette
from cassette_scrub.types import Finding, InstallResult

CASSETTE_EXTENSIONS: Final[frozenset[str]] = frozenset({".yaml", ".yml", ".json"})
IGNORED_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        "node_modules",
    }
)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for cassette-scrub."""
    parser = argparse.ArgumentParser(
        prog="cassette-scrub",
        description="Check and scrub sensitive headers, query parameters, tokens, and PII from VCR cassettes.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Cassette files or directories to scan (default: .).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check cassettes for secrets and PII without modifying files (default).",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Scrub detected secrets and PII from cassette files in place.",
    )
    parser.add_argument(
        "--exit-zero-on-fix",
        action="store_true",
        help="Return exit code 0 even when --fix modifies files.",
     )
    parser.add_argument(
        "--no-pii",
        action="store_true",
        help="Disable email PII scrubbing while still redacting secrets and headers.",
     )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Print unified diff for dirty or modified cassettes.",
     )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the dark desktop GUI.",
     )
    parser.add_argument(
        "--mcp",
        action="store_true",
        help="Start the stdio MCP server.",
    )
    parser.add_argument(
        "--install-skill",
        nargs="*",
        default=None,
        metavar="TARGET",
        help="Install the /cassette-scrub skill for target AI assistants (default: all).",
    )
    parser.add_argument(
        "--install-mcp",
        nargs="*",
        default=None,
        metavar="TARGET",
        help="Install cassette-scrub MCP server config for target AI assistants (default: all).",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install the cassette-scrub pre-commit hook into .pre-commit-config.yaml.",
    )
    parser.add_argument(
        "--build-exe",
        action="store_true",
        help="Build standalone CLI and GUI executables into dist/.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _discover_files(raw_paths: list[str]) -> list[Path]:
    """Discover candidate YAML and JSON files from directories and explicit file paths."""
    discovered: list[Path] = []
    seen: set[Path] = set()

    for raw_path in raw_paths:
        target = Path(raw_path)
        if target.is_dir():
            for root, dirnames, filenames in os.walk(target):
                dirnames[:' = sorted(d for d in dirnames if d not in IGNORED_DIRS)
                root_path = Path(root)
                for filename in sorted(filenames):
                    candidate = root_path / filename
                    if candidate.suffix.lower() not in CASSETTE_EXTENSIONS:
                        continue
                    resolved = candidate.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        discovered.append(candidate)
        elif target.is_file():
            if target.suffix.lower() not in CASSETTE_EXTENSIONS:
                continue
            resolved = target.resolve()
            if resolved not in seen:
                seen.add(resolved)
                discovered.append(target)

    return discovered


def _format_finding(finding: Finding) -> str:
    """Format a single ScrubResult finding for terminal output."""
    return (
        f"{finding.file_path}:interaction[{finding.interaction_index}] "
        f"{finding.location}: {finding.location }"
    )