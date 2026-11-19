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


def _resolve_project_dir(raw_paths: list[str], *, fallback_cwd: bool) -> Path | None:
    """Resolve explicit project directory argument or optional CWD fallback."""
    if raw_paths and raw_paths != ["."]:
        return Path(raw_paths[0])
    return Path.cwd() if fallback_cwd else None


def _emit_install_results(results: list[InstallResult], *, as_json: bool) -> int:
    """Print installer results in text or JSON format and return exit status."""
    all_ok = all(item.success for item in results)
    if as_json:
        import json

        payload = {
            "version": __version__,
            "success": all_ok,
            "results": [
                {
                    "target": item.target,
                    "kind": item.kind,
                    "path": item.path,
                    "success": item.success,
                    "message": item.message,
                }
                for item in results
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        for item in results:
            status = "OK" if item.success else "ERROR"
            path_part = f"{item.path} - " if item.path else ""
            print(f"[{status}] {item.kind} ({item.target}): {path_part}{item.message}")

    return 0 if all_ok else 1


def main(argv: list[str] | None = None) -> int:
    """Run cassette-scrub CLI and return an exit status code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    raw_paths = list(args.paths)

    if args.gui:
        from cassette_scrub.gui import launch_gui

        initial_path = raw_paths[0] if raw_paths and raw_paths != ["."] else None
        return int(launch_gui(initial_path=initial_path))

    if args.mcp:
        from cassette_scrub.mcp_server import run_mcp_server

        return int(run_mcp_server())

    if args.build_exe:
        from cassette_scrub.builder import build_standalone_exe

        output_dir = _resolve_project_dir(raw_paths, fallback_cwd=False)
        built = build_standalone_exe(output_dir=output_dir)
        if args.json:
            import json

            print(
                json.dumps(
                    {
                        "version": __version__,
                        "artifacts": {name: str(path) for name, path in built.items()},
                    },
                    indent=2,
                )
            )
        else:
            for name, path in built.items():
                print(f"{name}: {path}")
        return 0

    if (
        args.install_skill is not None
        or args.install_mcp is not None
        or args.install_hook
    ):
        results: list[InstallResult] = []
        if args.install_skill is not None:
            from cassette_scrub.installer import install_skill

            targets = list(args.install_skill) if args.install_skill else ["all"]
            skill_project_dir = _resolve_project_dir(raw_paths, fallback_cwd=False)
            results.extend(
                install_skill(targets=targets, project_dir=skill_project_dir)
            )
        if args.install_mcp is not None:
            from cassette_scrub.installer import install_mcp

            targets = list(args.install_mcp) if args.install_mcp else ["all"]
            mcp_project_dir = _resolve_project_dir(raw_paths, fallback_cwd=False)
            results.extend(install_mcp(targets=targets, project_dir=mcp_project_dir))
        if args.install_hook:
            from cassette_scrub.installer import install_pre_commit_config

            hook_project_dir = _resolve_project_dir(raw_paths, fallback_cwd=True)
            assert hook_project_dir is not None
            results.append(install_pre_commit_config(project_dir=hook_project_dir))

        return _emit_install_results(results, as_json=bool(args.json))

    files = _discover_files(raw_paths)
    has_findings = False
    modified_files = 0
    files_scanned = 0
    files_with_findings = 0
    all_findings: list[Finding] = []
    scrub_pii = not bool(args.no_pii)

    format_diff = None
    if args.diff and not args.json:
        from cassette_scrub.scrubber import format_cassette_diff

        format_diff = format_cassette_diff

    for path in files:
        data, fmt = load_cassette(path)
        if data is None or not fmt:
            continue

        files_scanned += 1
        config = load_config(start_dir=path.parent, scrub_pii=scrub_pii)
        result = scrub_cassette(data, str(path), config)

        if result.findings:
            has_findings = True
            files_with_findings += 1
            all_findings.extend(result.findings)

        if not args.json:
            for finding in result.findings:
                print(_format_finding(finding))

            if (
                format_diff is not None
                and result.modified
                and result.updated_data is not None
            ):
                diff_text = format_diff(
                    data,
                    result.updated_data,
                    fmt,
                    file_path=str(path),
                )
                if diff_text:
                    print(diff_text, end="" if diff_text.endswith("\n") else "\n")

        if args.fix and result.modified and result.updated_data is not None:
            dump_cassette(path, result.updated_data, fmt)
            modified_files += 1

    if args.json:
        import json

        payload = {
            "version": __version__,
            "modified": modified_files > 0,
            "files_scanned": files_scanned,
            "files_with_findings": files_with_findings,
            "findings": [
                {
                    "file_path": finding.file_path,
                    "interaction_index": finding.interaction_index,
                    "location": finding.location,
                    "preview": finding.preview,
                }
                for finding in all_findings
            ],
        }
        print(json.dumps(payload, indent=2))

    if args.fix:
        if modified_files > 0 and not args.exit_zero_on_fix:
            return 1
        return 0

    return 1 if has_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
