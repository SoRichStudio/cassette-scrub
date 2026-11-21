from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Final

from cassette_scrub import __version__
from cassette_scrub.config import load_config
from cassette_scrub.parser import dump_cassette, load_cassette
from cassette_scrub.scrubber import format_cassette_diff, scrub_cassette
from cassette_scrub.types import Finding, InstallResult

CASSETTE_EXTENSIONS: Final[frozenset[str]] = frozenset({".yaml", ".yml", ".json"})
IGNORED_DIRS: Final[frozenset[str]] = frozenset(
    {".git", ".venv", "venv", "__pycache__", ".tox", ".pytest_cache", ".mypy_cache", "node_modules"}
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cassette-scrub",
        description="Check and redact secrets and emails in VCR.py cassettes.",
    )
    p.add_argument("paths", nargs="*", default=["."], help="Cassette files or directories (default: .).")
    p.add_argument("--check", action="store_true", help="Check files without editing (default).")
    p.add_argument("--fix", action="store_true", help="Redact matches in place.")
    p.add_argument("--exit-zero-on-fix", action="store_true", help="Exit 0 even when --fix edits files.")
    p.add_argument("--no-pii", action="store_true", help="Keep email addresses while redacting secrets.")
    p.add_argument("--json", action="store_true", help="Print JSON output.")
    p.add_argument("--diff", action="store_true", help="Print unified diff for dirty cassettes.")
    p.add_argument("--gui", action="store_true", help="Open the desktop window.")
    p.add_argument("--mcp", action="store_true", help="Run the stdio MCP server.")
    p.add_argument("--install-skill", nargs="*", default=None, metavar="TARGET", help="Install /cassette-scrub skill (default: all).")
    p.add_argument("--install-mcp", nargs="*", default=None, metavar="TARGET", help="Install MCP server config (default: all).")
    p.add_argument("--install-hook", action="store_true", help="Add cassette-scrub hook to .pre-commit-config.yaml.")
    p.add_argument("--build-exe", action="store_true", help="Build standalone Windows .exe files into dist/.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _discover_files(raw_paths: list[str]) -> list[Path]:
    discovered: list[Path] = []
    seen: set[Path] = set()
    for raw in raw_paths:
        target = Path(raw)
        if target.is_dir():
            for root, dirs, files in os.walk(target):
                dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
                root_p = Path(root)
                for name in sorted(files):
                    cand = root_p / name
                    if cand.suffix.lower() in CASSETTE_EXTENSIONS and (res := cand.resolve()) not in seen:
                        seen.add(res)
                        discovered.append(cand)
        elif target.is_file() and target.suffix.lower() in CASSETTE_EXTENSIONS:
            if (res := target.resolve()) not in seen:
                seen.add(res)
                discovered.append(target)
    return discovered


def _project_arg(raw_paths: list[str], *, fallback_cwd: bool) -> Path | None:
    if raw_paths and raw_paths != ["."]:
        return Path(raw_paths[0])
    return Path.cwd() if fallback_cwd else None


def main(argv: list[str] | None = None) -> int:
    """Run the cassette-scrub CLI and return a process exit code."""
    args = _build_parser().parse_args(argv)
    raw_paths = list(args.paths)

    if args.gui:
        from cassette_scrub.gui import launch_gui

        return int(launch_gui(raw_paths[0] if raw_paths and raw_paths != ["."] else None))
    if args.mcp:
        from cassette_scrub.mcp_server import run_mcp_server

        return int(run_mcp_server())
    if args.build_exe:
        from cassette_scrub.builder import build_standalone_exe

        built = build_standalone_exe(_project_arg(raw_paths, fallback_cwd=False))
        if args.json:
            print(json.dumps({"version": __version__, "artifacts": {k: str(v) for k, v in built.items()}}, indent=2))
        else:
            for k, v in built.items():
                print(f"{k}: {v}")
        return 0

    if args.install_skill is not None or args.install_mcp is not None or args.install_hook:
        from cassette_scrub.installer import (
            install_mcp,
            install_pre_commit_config,
            install_skill,
        )

        results: list[InstallResult] = []
        proj = _project_arg(raw_paths, fallback_cwd=False)
        if args.install_skill is not None:
            results.extend(install_skill(list(args.install_skill) or ["all"], project_dir=proj))
        if args.install_mcp is not None:
            results.extend(install_mcp(list(args.install_mcp) or ["all"], project_dir=proj))
        if args.install_hook:
            results.append(install_pre_commit_config(_project_arg(raw_paths, fallback_cwd=True) or Path.cwd()))

        ok = all(r.success for r in results)
        if args.json:
            print(json.dumps({"version": __version__, "success": ok, "results": [asdict(r) for r in results]}, indent=2))
        else:
            for r in results:
                status = "OK" if r.success else "ERR"
                loc = f"{r.path} - " if r.path else ""
                print(f"[{status}] {r.kind} ({r.target}): {loc}{r.message}")
        return 0 if ok else 1

    scanned = 0
    dirty = 0
    modified = 0
    findings: list[Finding] = []
    scrub_pii = not args.no_pii

    for path in _discover_files(raw_paths):
        data, fmt = load_cassette(path)
        if data is None or not fmt:
            continue
        scanned += 1
        result = scrub_cassette(data, str(path), load_config(path.parent, scrub_pii=scrub_pii))
        if result.findings:
            dirty += 1
            findings.extend(result.findings)
        if not args.json:
            for f in result.findings:
                print(f"{f.file_path}:interaction[{f.interaction_index}] {f.location}: {f.preview}")
            if args.diff and result.modified and result.updated_data is not None:
                diff = format_cassette_diff(data, result.updated_data, fmt, file_path=str(path))
                if diff:
                    print(diff, end="" if diff.endswith("\n") else "\n")
        if args.fix and result.modified and result.updated_data is not None:
            dump_cassette(path, result.updated_data, fmt)
            modified += 1

    if args.json:
        print(
            json.dumps(
                {
                    "version": __version__,
                    "modified": modified > 0,
                    "files_scanned": scanned,
                    "files_with_findings": dirty,
                    "findings": [asdict(f) for f in findings],
                },
                indent=2,
            )
        )

    if args.fix:
        return 1 if (modified > 0 and not args.exit_zero_on_fix) else 0
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
