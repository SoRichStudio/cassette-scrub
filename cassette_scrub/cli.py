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
        description="Check and scrub sensitive headers, query parameters, tokens, and PII  in VCR cassettes.".replace("  in", " in"),
    )
