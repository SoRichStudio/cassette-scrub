from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Final

from cassette_scrub.config import load_config
from cassette_scrub.parser import dump_cassette, load_cassette
from cassette_scrub.scrubber import scrub_cassette
from cassette_scrub.types import Finding

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
        description="Check and scrub sensitive headers, query params, tokens, and PII in VCR cassettes.",
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
    return parser


def _discover_files(raw_paths: list[str]) -> list[Path]:
    """Discover candidate YAML and JSON files from directories and explicit file paths."""
    discovered: list[Path] = []
    seen: set[Path] = set()

    for raw_path in raw_paths:
        target = Path(raw_path)
        if target.is_dir():
            for root, dirnames, filenames in os.walk(target):
                dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
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
        f"{finding.location}: {finding.preview}"
    )


def main(argv: list[str] | None = None) -> int:
    """Run cassette-scrub CLI and return an exit status code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    files = _discover_files(list(args.paths))
    has_findings = False
    modified_files = 0
    scrub_pii = not bool(args.no_pii)

    for path in files:
        data, fmt = load_cassette(path)
        if data is None or not fmt:
            continue

        config = load_config(start_dir=path.parent, scrub_pii=scrub_pii)
        result = scrub_cassette(data, str(path), config)

        for finding in result.findings:
            print(_format_finding(finding))

        if result.findings:
            has_findings = True

        if args.fix and result.modified and result.updated_data is not None:
            dump_cassette(path, result.updated_data, fmt)
            modified_files += 1

    if args.fix:
        if modified_files > 0 and not args.exit_zero_on_fix:
            return 1
        return 0

    return 1 if has_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
