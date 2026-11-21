from __future__ import annotations

import io
import zipfile
from pathlib import Path

import yaml

try:
    import distlib.scripts as _distlib_scripts
except ImportError:  # pragma: no cover
    from pip._vendor.distlib import scripts as _distlib_scripts  # type: ignore[no-redef]

__all__ = ["build_standalone_exe"]

_CLI_SHEBANG = b"#!" + b"python.exe\r\n"
_GUI_SHEBANG = b"#!" + b"pythonw.exe\r\n"

_CLI_MAIN_PY = """\
from __future__ import annotations
import os, sys

def _main() -> int:
    if len(sys.argv) > 1 or os.environ.get("CASSETTE_SCRUB_NO_GUI") == "1":
        from cassette_scrub import cli
        return cli.main(sys.argv[1:])
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
    sys.exit(gui.launch_gui(sys.argv[1] if len(sys.argv) > 1 else None))
"""


def _collect_py(path_str: str, prefix: str) -> list[tuple[str, bytes]]:
    p = Path(path_str).resolve()
    parent = p.parent
    if parent.is_dir():
        return [
            (f"{prefix}/{f.relative_to(parent).as_posix()}", f.read_bytes())
            for f in sorted(parent.rglob("*.py"))
            if "__pycache__" not in f.parts
        ]
    for candidate in p.parents:
        if candidate.is_file() and zipfile.is_zipfile(candidate):
            with zipfile.ZipFile(candidate, "r") as zf:
                return [
                    (n, zf.read(n))
                    for n in sorted(zf.namelist())
                    if n.startswith(f"{prefix}/") and n.endswith(".py")
                ]
    raise FileNotFoundError(f"Cannot locate {prefix} files at {parent}")


def _collect_payload() -> list[tuple[str, bytes]]:
    entries: dict[str, bytes] = {}
    for arcname, data in _collect_py(__file__, "cassette_scrub"):
        entries.setdefault(arcname, data)
    yaml_file = getattr(yaml, "__file__", None)
    if not yaml_file:
        raise FileNotFoundError("Cannot locate PyYAML files")
    for arcname, data in _collect_py(yaml_file, "yaml"):
        entries.setdefault(arcname, data)

    for cand in (
        Path(__file__).resolve().parent.parent / "skills" / "cassette-scrub" / "SKILL.md",
        Path.cwd() / "skills" / "cassette-scrub" / "SKILL.md",
    ):
        if cand.is_file():
            entries.setdefault("skills/cassette-scrub/SKILL.md", cand.read_bytes())
            break
    return list(entries.items())


def _zip_payload(base: list[tuple[str, bytes]], main_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in base:
            zf.writestr(arcname, data)
        zf.writestr("__main__.py", main_src.encode("utf-8"))
    return buf.getvalue()


def build_standalone_exe(output_dir: Path | None = None) -> dict[str, Path]:
    """Build standalone Windows CLI and GUI .exe binaries using distlib launcher stubs."""
    out = output_dir if output_dir is not None else Path.cwd() / "dist"
    out.mkdir(parents=True, exist_ok=True)
    stub_dir = Path(_distlib_scripts.__file__).resolve().parent
    base = _collect_payload()

    cli_exe = out / "cassette-scrub.exe"
    gui_exe = out / "cassette-scrub-gui.exe"
    cli_exe.write_bytes((stub_dir / "t64.exe").read_bytes() + _CLI_SHEBANG + _zip_payload(base, _CLI_MAIN_PY))
    gui_exe.write_bytes((stub_dir / "w64.exe").read_bytes() + _GUI_SHEBANG + _zip_payload(base, _GUI_MAIN_PY))
    return {"cli_exe": cli_exe, "gui_exe": gui_exe}
