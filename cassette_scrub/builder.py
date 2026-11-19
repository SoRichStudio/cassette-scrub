from __future__ import annotations

import io
import zipfile
from pathlib import Path

import yaml

try:
    import distlib.scripts as _distlib_scripts
except ImportError:  # pragma: no cover - fallback for Python envs without standalone distlib
    from pip._vendor.distlib import scripts as _distlib_scripts  # type: ignore[no-redef]

__all__ = ["build_standalone_exe"]

_CLI_SHEBANG = b"#!" + b"python.exe\r\n"
_GUI_SHEBANG = b"#!" + b"pythonw.exe\r\n"

_CLI_MAIN_PY = """\
from __future__ import annotations

import os
import sys


def _main() -> int:
    if len(sys.argv) > 1:
        from cassette_scrub import cli

        return cli.main(sys.argv[1:])
    if os.environ.get("CASSETTE_SCRUB_NO_GUI") == "1":
        from cassette_scrub import cli

        return cli.main([])
    from cassette_scrub import gui

    return gui.launch_gui()


if __name__ == "__main__":
    sys.exit(_main())
"""

_GUI_MAIN_PY = """\
from __future__ import annotations

import sys

from cassette_scrub import gui

if __name__ == "__main__":
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(gui.launch_gui(initial))
"""


def _find_enclosing_zip(file_path: Path) -> Path | None:
    """Locate an enclosing zip/exe archive if running from a zipapp bundle."""
    for candidate in file_path.resolve().parents:
        if candidate.is_file() and zipfile.is_zipfile(candidate):
            return candidate
    return None


def _collect_disk_py_files(root_dir: Path, archive_prefix: str) -> list[tuple[str, bytes]]:
    """Collect *.py files recursively from a package directory on disk."""
    entries: list[tuple[str, bytes]] = []
    for py_file in sorted(root_dir.rglob("*.py")):
        if "__pycache__" in py_file.parts:
            continue
        rel = py_file.relative_to(root_dir).as_posix()
        entries.append((f"{archive_prefix}/{rel}", py_file.read_bytes()))
    return entries


def _collect_zip_entries(archive_path: Path, prefix: str) -> list[tuple[str, bytes]]:
    """Collect entries matching prefix from an existing zipapp archive."""
    entries: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(archive_path, "r") as zf:
        for name in sorted(zf.namelist()):
            if name == prefix or name.startswith(prefix):
                if name.endswith("/"):
                    continue
                entries.append((name, zf.read(name)))
    return entries


def _collect_payload_files() -> list[tuple[str, bytes]]:
    """Collect cassette_scrub, PyYAML, and optional SKILL.md payload entries."""
    entries: list[tuple[str, bytes]] = []
    seen_arcnames: set[str] = set()

    def _add(arcname: str, data: bytes) -> None:
        if arcname not in seen_arcnames:
            seen_arcnames.add(arcname)
            entries.append((arcname, data))

    pkg_dir = Path(__file__).resolve().parent
    if pkg_dir.is_dir():
        for arcname, data in _collect_disk_py_files(pkg_dir, "cassette_scrub"):
            _add(arcname, data)
    else:
        bundle = _find_enclosing_zip(Path(__file__))
        if bundle is None:
            raise FileNotFoundError(f"Cannot locate cassette_scrub package files at {pkg_dir}")
        for arcname, data in _collect_zip_entries(bundle, "cassette_scrub/"):
            if arcname.endswith(".py"):
                _add(arcname, data)

    yaml_file = getattr(yaml, "__file__", None)
    if yaml_file is None:
        raise FileNotFoundError("Cannot locate PyYAML package files")
    yaml_dir = Path(yaml_file).resolve().parent
    if yaml_dir.is_dir():
        for arcname, data in _collect_disk_py_files(yaml_dir, "yaml"):
            _add(arcname, data)
    else:
        yaml_bundle = _find_enclosing_zip(Path(yaml_file))
        if yaml_bundle is None:
            raise FileNotFoundError(f"Cannot locate PyYAML package files at {yaml_dir}")
        for arcname, data in _collect_zip_entries(yaml_bundle, "yaml/"):
            if arcname.endswith(".py"):
                _add(arcname, data)

    skill_candidates = [
        pkg_dir.parent / "skills" / "cassette-scrub" / "SKILL.md",
        Path.cwd() / "skills" / "cassette-scrub" / "SKILL.md",
    ]
    skill_loaded = False
    for skill_path in skill_candidates:
        if skill_path.is_file():
            _add("skills/cassette-scrub/SKILL.md", skill_path.read_bytes())
            skill_loaded = True
            break

    if not skill_loaded and not pkg_dir.is_dir():
        bundle = _find_enclosing_zip(Path(__file__))
        if bundle is not None:
            for arcname, data in _collect_zip_entries(bundle, "skills/cassette-scrub/SKILL.md"):
                _add(arcname, data)

    return entries


def _build_zip_payload(base_entries: list[tuple[str, bytes]], main_source: str) -> bytes:
    """Create a compressed zipapp payload in memory containing base_entries and __main__.py."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in base_entries:
            zf.writestr(arcname, data)
        zf.writestr("__main__.py", main_source.encode("utf-8"))
    return buffer.getvalue()


def _load_launcher_stub(stub_dir: Path, filename: str) -> bytes:
    """Load an Authenticode-signed distlib Windows launcher stub."""
    stub_path = stub_dir / filename
    if not stub_path.is_file():
        raise FileNotFoundError(f"Launcher stub not found: {stub_path}")
    return stub_path.read_bytes()


def build_standalone_exe(output_dir: Path | None = None) -> dict[str, Path]:
    """Build standalone Windows CLI and GUI .exe binaries using distlib launcher stubs."""
    target_dir = output_dir if output_dir is not None else Path.cwd() / "dist"
    target_dir.mkdir(parents=True, exist_ok=True)

    stub_dir = Path(_distlib_scripts.__file__).resolve().parent
    t64_stub = _load_launcher_stub(stub_dir, "t64.exe")
    w64_stub = _load_launcher_stub(stub_dir, "w64.exe")

    base_entries = _collect_payload_files()
    cli_zip = _build_zip_payload(base_entries, _CLI_MAIN_PY)
    gui_zip = _build_zip_payload(base_entries, _GUI_MAIN_PY)

    cli_exe = target_dir / "cassette-scrub.exe"
    gui_exe = target_dir / "cassette-scrub-gui.exe"

    cli_exe.write_bytes(t64_stub + _CLI_SHEBANG + cli_zip)
    gui_exe.write_bytes(w64_stub + _GUI_SHEBANG + gui_zip)

    return {"cli_exe": cli_exe, "gui_exe": gui_exe}
