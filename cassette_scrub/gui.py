from __future__ import annotations

import json
import tkinter as tk
from dataclasses import asdict
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any, Callable, Final

from cassette_scrub import __version__
from cassette_scrub.builder import build_standalone_exe
from cassette_scrub.cli import _discover_files
from cassette_scrub.config import load_config
from cassette_scrub.installer import install_mcp, install_pre_commit_config, install_skill
from cassette_scrub.parser import dump_cassette, load_cassette
from cassette_scrub.scrubber import format_cassette_diff, scrub_cassette
from cassette_scrub.types import Finding, InstallResult, ScrubResult

__all__ = ["CassetteScrubApp", "launch_gui"]

BG_ROOT: Final[str] = "#0d1117"
BG_PANEL: Final[str] = "#161b22"
BG_BUTTON: Final[str] = "#21262d"
BG_ACTIVE: Final[str] = "#30363d"
BORDER: Final[str] = "#21262d"
FG_PRIMARY: Final[str] = "#c9d1d9"
FG_MUTED: Final[str] = "#8b949e"
FG_ACCENT: Final[str] = "#58a6ff"
FG_OK: Final[str] = "#3fb950"
FG_ERR: Final[str] = "#f85149"

FONT: Final[tuple[str, int]] = ("Consolas", 10)
FONT_BOLD: Final[tuple[str, int, str]] = ("Consolas", 10, "bold")

_TARGETS: Final[tuple[tuple[str, str], ...]] = (
    ("antigravity", "Antigravity"),
    ("claude", "Claude"),
    ("codex", "Codex"),
    ("cursor", "Cursor"),
    ("windsurf", "Windsurf"),
    ("vscode", "VS Code"),
    ("project", "Project"),
)


class CassetteScrubApp:
    """Tkinter desktop window for inspecting and scrubbing VCR.py cassettes."""

    def __init__(self, root: tk.Tk, initial_path: str | None = None) -> None:
        self.root = root
        self.root.title(f"cassette-scrub {__version__}")
        self.root.configure(bg=BG_ROOT)
        self.root.minsize(960, 680)
        self.root.geometry("1160x800")

        default_path = initial_path or str(Path.cwd())
        self.target_var = tk.StringVar(value=default_path)
        self.scrub_pii_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Ready")
        self.findings_header_var = tk.StringVar(value="Findings (0)")
        self.diff_header_var = tk.StringVar(value="Diff")
        self.installer_status_var = tk.StringVar(value="")
        self.target_vars = {k: tk.BooleanVar(value=True) for k, _ in _TARGETS}

        self._files_scanned = 0
        self._files_with_findings = 0
        self._last_modified = False
        self._findings: list[Finding] = []
        self._finding_paths: list[str] = []
        self._file_diffs: dict[str, str] = {}
        self._dirty: list[tuple[Path, str, ScrubResult]] = []

        self._build_ui()
        if initial_path and Path(initial_path).is_file():
            self.root.after(50, self.scan)

    def _btn(self, parent: tk.Misc, text: str, cmd: Callable[[], None], *, accent: bool = False) -> tk.Button:
        b = tk.Button(
            parent, text=text, command=cmd, font=FONT_BOLD, bg=BG_BUTTON,
            fg=FG_ACCENT if accent else FG_PRIMARY, activebackground=BG_ACTIVE,
            activeforeground=FG_PRIMARY, relief="flat", bd=1, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=FG_ACCENT, padx=10, pady=4, cursor="hand2",
        )
        b.bind("<Enter>", lambda _e: b.configure(bg=BG_ACTIVE))
        b.bind("<Leave>", lambda _e: b.configure(bg=BG_BUTTON))
        return b

    def _chk(self, parent: tk.Misc, text: str, var: tk.BooleanVar) -> tk.Checkbutton:
        return tk.Checkbutton(
            parent, text=text, variable=var, font=FONT, bg=BG_PANEL, fg=FG_PRIMARY,
            activebackground=BG_PANEL, activeforeground=FG_PRIMARY, selectcolor=BG_ROOT,
            relief="flat", bd=1, highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=FG_ACCENT, anchor="w", padx=6, pady=2, cursor="hand2",
        )

    def _panel(self, parent: tk.Misc) -> tk.Frame:
        return tk.Frame(parent, bg=BG_PANEL, relief="flat", bd=1, highlightthickness=1, highlightbackground=BORDER, padx=8, pady=8)

    def _build_ui(self) -> None:
        wrap = tk.Frame(self.root, bg=BG_ROOT, padx=10, pady=10)
        wrap.pack(fill=tk.BOTH, expand=True)

        # Target bar
        top = self._panel(wrap)
        top.pack(fill=tk.X, pady=(0, 8))
        tk.Label(top, text="Path:", font=FONT_BOLD, bg=BG_PANEL, fg=FG_MUTED).pack(side=tk.LEFT, padx=(0, 6))
        tk.Entry(
            top, textvariable=self.target_var, font=FONT, bg=BG_ROOT, fg=FG_PRIMARY,
            insertbackground=FG_ACCENT, relief="flat", bd=1, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=FG_ACCENT,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)
        self._btn(top, "Folder...", self._browse_dir).pack(side=tk.LEFT, padx=(0, 6))
        self._btn(top, "File...", self._browse_file).pack(side=tk.LEFT, padx=(0, 8))
        self._chk(top, "Scrub emails", self.scrub_pii_var).pack(side=tk.LEFT)

        # Action toolbar
        bar = tk.Frame(wrap, bg=BG_ROOT)
        bar.pack(fill=tk.X, pady=(0, 8))
        self._btn(bar, "Scan", self.scan, accent=True).pack(side=tk.LEFT, padx=(0, 6))
        self._btn(bar, "Diff", self.diff_preview).pack(side=tk.LEFT, padx=(0, 6))
        self._btn(bar, "Scrub", self.scrub_in_place).pack(side=tk.LEFT, padx=(0, 6))
        self._btn(bar, "Copy JSON", self.copy_json_report).pack(side=tk.LEFT)
        self.status_label = tk.Label(bar, textvariable=self.status_var, font=FONT, bg=BG_ROOT, fg=FG_MUTED, anchor="e")
        self.status_label.pack(side=tk.RIGHT)

        # Findings / Diff split
        paned = tk.PanedWindow(wrap, orient=tk.HORIZONTAL, bg=BORDER, sashwidth=4, sashrelief="flat", bd=0, opaqueresize=True)
        paned.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        left = self._panel(paned)
        self.findings_header_label = tk.Label(left, textvariable=self.findings_header_var, font=FONT_BOLD, bg=BG_PANEL, fg=FG_MUTED, anchor="w")
        self.findings_header_label.pack(fill=tk.X, pady=(0, 4))
        lf = tk.Frame(left, bg=BG_PANEL)
        lf.pack(fill=tk.BOTH, expand=True)
        ly = tk.Scrollbar(lf, orient=tk.VERTICAL, relief="flat", bd=0)
        lx = tk.Scrollbar(lf, orient=tk.HORIZONTAL, relief="flat", bd=0)
        self.findings_listbox = tk.Listbox(
            lf, font=FONT, bg=BG_PANEL, fg=FG_PRIMARY, selectbackground=BG_ACTIVE,
            selectforeground=FG_ACCENT, activestyle="none", exportselection=False,
            relief="flat", bd=1, highlightthickness=1, highlightbackground=BORDER,
            yscrollcommand=ly.set, xscrollcommand=lx.set,
        )
        ly.config(command=self.findings_listbox.yview)
        lx.config(command=self.findings_listbox.xview)
        ly.pack(side=tk.RIGHT, fill=tk.Y)
        lx.pack(side=tk.BOTTOM, fill=tk.X)
        self.findings_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.findings_listbox.bind("<<ListboxSelect>>", self._on_select)

        right = self._panel(paned)
        tk.Label(right, textvariable=self.diff_header_var, font=FONT_BOLD, bg=BG_PANEL, fg=FG_MUTED, anchor="w").pack(fill=tk.X, pady=(0, 4))
        rf = tk.Frame(right, bg=BG_PANEL)
        rf.pack(fill=tk.BOTH, expand=True)
        ry = tk.Scrollbar(rf, orient=tk.VERTICAL, relief="flat", bd=0)
        rx = tk.Scrollbar(rf, orient=tk.HORIZONTAL, relief="flat", bd=0)
        self.diff_text = tk.Text(
            rf, font=FONT, bg=BG_PANEL, fg=FG_PRIMARY, insertbackground=FG_ACCENT,
            wrap="none", state="disabled", relief="flat", bd=1, highlightthickness=1,
            highlightbackground=BORDER, yscrollcommand=ry.set, xscrollcommand=rx.set,
        )
        ry.config(command=self.diff_text.yview)
        rx.config(command=self.diff_text.xview)
        ry.pack(side=tk.RIGHT, fill=tk.Y)
        rx.pack(side=tk.BOTTOM, fill=tk.X)
        self.diff_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        for tag, cfg in (
            ("del", {"foreground": FG_ERR}),
            ("add", {"foreground": FG_OK}),
            ("hunk", {"foreground": FG_ACCENT, "font": FONT_BOLD}),
            ("hdr", {"foreground": FG_PRIMARY, "font": FONT_BOLD}),
            ("clean", {"foreground": FG_OK}),
            ("err", {"foreground": FG_ERR}),
            ("muted", {"foreground": FG_MUTED}),
        ):
            self.diff_text.tag_configure(tag, **cfg)
        paned.add(left, minsize=360, width=480)
        paned.add(right, minsize=440)

        # Integrations footer
        bot = self._panel(wrap)
        bot.pack(fill=tk.X)
        hdr = tk.Frame(bot, bg=BG_PANEL)
        hdr.pack(fill=tk.X, pady=(0, 6))
        tk.Label(hdr, text="Integrations", font=FONT_BOLD, bg=BG_PANEL, fg=FG_MUTED, anchor="w").pack(side=tk.LEFT)
        self.installer_status_label = tk.Label(hdr, textvariable=self.installer_status_var, font=FONT, bg=BG_PANEL, fg=FG_MUTED, anchor="e")
        self.installer_status_label.pack(side=tk.RIGHT)

        chk_row = tk.Frame(bot, bg=BG_PANEL)
        chk_row.pack(fill=tk.X, pady=(0, 6))
        for key, label in _TARGETS:
            self._chk(chk_row, label, self.target_vars[key]).pack(side=tk.LEFT, padx=(0, 8))

        btn_row = tk.Frame(bot, bg=BG_PANEL)
        btn_row.pack(fill=tk.X, pady=(0, 6))
        self._btn(btn_row, "Install skill", self.install_selected_skills).pack(side=tk.LEFT, padx=(0, 6))
        self._btn(btn_row, "Install MCP", self.install_selected_mcp).pack(side=tk.LEFT, padx=(0, 6))
        self._btn(btn_row, "Install all", self.install_all_selected, accent=True).pack(side=tk.LEFT)

        lf2 = tk.Frame(bot, bg=BG_PANEL)
        lf2.pack(fill=tk.X)
        ly2 = tk.Scrollbar(lf2, orient=tk.VERTICAL, relief="flat", bd=0)
        self.log_text = tk.Text(
            lf2, height=5, font=FONT, bg=BG_ROOT, fg=FG_PRIMARY, wrap="none",
            state="disabled", relief="flat", bd=1, highlightthickness=1, highlightbackground=BORDER,
            yscrollcommand=ly2.set,
        )
        ly2.config(command=self.log_text.yview)
        ly2.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        for tag, color in (("ok", FG_OK), ("err", FG_ERR), ("info", FG_MUTED), ("accent", FG_ACCENT)):
            self.log_text.tag_configure(tag, foreground=color)

    def _set_status(self, msg: str, color: str = FG_MUTED) -> None:
        self.status_var.set(msg)
        self.status_label.configure(fg=color)

    def _log(self, line: str, tag: str = "info") -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, line + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _show_diff(self, text: str, default_tag: str | None = None) -> None:
        self.diff_text.configure(state="normal")
        self.diff_text.delete("1.0", tk.END)
        for line in text.splitlines(keepends=True):
            tag = (
                "hunk" if line.startswith("@@")
                else "del" if line.startswith("-")
                else "add" if line.startswith("+")
                else "hdr" if line.startswith("=== ")
                else default_tag
            )
            self.diff_text.insert(tk.END, line, tag) if tag else self.diff_text.insert(tk.END, line)
        self.diff_text.configure(state="disabled")

    def _browse_dir(self) -> None:
        cur = self.target_var.get().strip()
        picked = filedialog.askdirectory(initialdir=cur if cur and Path(cur).is_dir() else str(Path.cwd()), title="Select folder")
        if picked:
            self.target_var.set(picked)

    def _browse_file(self) -> None:
        cur = Path(self.target_var.get().strip() or ".")
        start = cur if cur.is_dir() else cur.parent
        picked = filedialog.askopenfilename(
            initialdir=str(start if start.is_dir() else Path.cwd()),
            title="Select cassette file",
            filetypes=[("VCR Cassettes", "*.yaml *.yml *.json"), ("All Files", "*.*")],
        )
        if picked:
            self.target_var.set(picked)

    def _target(self) -> Path:
        return Path(self.target_var.get().strip() or ".")

    def _project_dir(self) -> Path:
        t = self._target()
        return t if t.is_dir() else (t.parent if t.is_file() else Path.cwd())

    def _run_scan(self, *, modified: bool = False) -> bool:
        target = self._target()
        self.findings_listbox.delete(0, tk.END)
        self._findings.clear()
        self._finding_paths.clear()
        self._file_diffs.clear()
        self._dirty.clear()
        self._files_scanned = 0
        self._files_with_findings = 0
        self._last_modified = modified

        if not target.exists():
            self.findings_header_var.set("Findings (0)")
            self.findings_header_label.configure(fg=FG_ERR)
            self.diff_header_var.set("Diff")
            msg = f"Missing path: {target}"
            self._show_diff(msg + "\n", "err")
            self._set_status(msg, FG_ERR)
            self._log(msg, "err")
            return False

        scrub_pii = bool(self.scrub_pii_var.get())
        for path in _discover_files([str(target)]):
            data, fmt = load_cassette(path)
            if data is None or not fmt:
                continue
            self._files_scanned += 1
            res = scrub_cassette(data, str(path), load_config(path.parent, scrub_pii=scrub_pii))
            if not res.findings:
                continue
            self._files_with_findings += 1
            self._dirty.append((path, fmt, res))
            if res.modified and res.updated_data is not None:
                self._file_diffs[str(path)] = format_cassette_diff(data, res.updated_data, fmt, file_path=str(path))
            try:
                label = path.relative_to(target).as_posix() if target.is_dir() else path.name
            except ValueError:
                label = path.name
            for f in res.findings:
                self._findings.append(f)
                self._finding_paths.append(f.file_path)
                self.findings_listbox.insert(tk.END, f"{label} [{f.interaction_index}] {f.location}: {f.preview}")

        count = len(self._findings)
        self.findings_header_var.set(f"Findings ({count})")
        if count:
            self.findings_header_label.configure(fg=FG_ERR)
            self.findings_listbox.selection_set(0)
            self._show_index_diff(0)
            self._set_status(f"{count} findings in {self._files_with_findings}/{self._files_scanned} files", FG_ERR)
        elif self._files_scanned == 0:
            self.findings_header_label.configure(fg=FG_MUTED)
            self.diff_header_var.set("Diff")
            self._show_diff("No VCR cassettes found.\n", "muted")
            self._set_status("0 cassettes scanned", FG_MUTED)
        else:
            self.findings_header_label.configure(fg=FG_OK)
            self.diff_header_var.set("Diff")
            self._show_diff(f"Clean ({self._files_scanned} files).\n", "clean")
            self._set_status(f"Clean ({self._files_scanned} files)", FG_OK)
        return True

    def _show_index_diff(self, idx: int) -> None:
        if 0 <= idx < len(self._finding_paths):
            fp = self._finding_paths[idx]
            self.diff_header_var.set(f"Diff - {fp}")
            self._show_diff(self._file_diffs.get(fp) or f"No diff for {fp}.\n", None if fp in self._file_diffs else "muted")

    def _on_select(self, _event: tk.Event[tk.Listbox]) -> None:
        if sel := self.findings_listbox.curselection():
            self._show_index_diff(int(sel[0]))

    def scan(self) -> None:
        """Scan the selected file or directory without modifying files."""
        if self._run_scan():
            self._log(f"Scanned {self._files_scanned} files: {len(self._findings)} findings.", "err" if self._findings else "ok")

    def diff_preview(self) -> None:
        """Show unified diffs for all dirty cassettes."""
        if not self._run_scan():
            return
        blocks = [f"=== {fp} ===\n{txt}" for fp, txt in self._file_diffs.items() if txt]
        if not blocks:
            self._log("No changes needed.", "ok")
            return
        self.diff_header_var.set(f"Diff ({len(blocks)} files)")
        self._show_diff("\n".join(blocks))

    def scrub_in_place(self) -> None:
        """Scrub detected secrets and emails from dirty files on disk."""
        if not self._run_scan() or not self._dirty:
            return
        if not messagebox.askyesno("Scrub files", f"Scrub {len(self._findings)} findings across {len(self._dirty)} files?"):
            self._log("Scrub cancelled.", "info")
            return

        written: list[Path] = []
        diffs: list[str] = []
        for path, fmt, res in self._dirty:
            if res.modified and res.updated_data is not None:
                dump_cassette(path, res.updated_data, fmt)
                written.append(path)
                if d := self._file_diffs.get(str(path), ""):
                    diffs.append(f"=== {path} ===\n{d}")
                self._log(f"Scrubbed {path}", "ok")
        self._run_scan(modified=bool(written))
        if diffs and not self._findings:
            self.diff_header_var.set(f"Scrubbed {len(written)} files")
            self._show_diff("\n".join(diffs))
            self._set_status(f"Scrubbed {len(written)} files", FG_OK)

    def _build_json_report(self) -> dict[str, Any]:
        return {
            "version": __version__,
            "modified": self._last_modified,
            "files_scanned": self._files_scanned,
            "files_with_findings": self._files_with_findings,
            "findings": [asdict(f) for f in self._findings],
        }

    def copy_json_report(self) -> None:
        """Copy the JSON report to the clipboard."""
        payload = json.dumps(self._build_json_report(), indent=2)
        self.root.clipboard_clear()
        self.root.clipboard_append(payload)
        self.root.update()
        self.diff_header_var.set("JSON")
        self._show_diff(payload + "\n")
        self._set_status(f"Copied JSON ({len(self._findings)} findings)", FG_ACCENT)

    def build_exe(self) -> None:
        """Build standalone CLI and GUI .exe binaries in dist/."""
        try:
            built = build_standalone_exe()
        except Exception as exc:
            self._set_status(f"Build failed: {exc}", FG_ERR)
            self._log(f"Build failed: {exc}", "err")
            messagebox.showerror("Build failed", str(exc))
            return
        for path in built.values():
            self._log(f"Built {path}", "ok")
        self._set_status(f"Built executables in {built['cli_exe'].parent}", FG_OK)

    def _selected_targets(self) -> list[str]:
        return [k for k, _ in _TARGETS if self.target_vars[k].get()]

    def _log_install(self, results: list[InstallResult]) -> None:
        ok = sum(1 for r in results if r.success)
        err = len(results) - ok
        for r in results:
            self._log(f"{r.target} ({r.kind}): {r.path or '-'} - {r.message}", "ok" if r.success else "err")
        msg = f"{ok} ok, {err} failed"
        color = FG_ERR if err else FG_OK
        self.installer_status_var.set(msg)
        self.installer_status_label.configure(fg=color)
        self._set_status(msg, color)

    def install_selected_skills(self) -> None:
        """Install /cassette-scrub skill for checked targets."""
        targets = [t for t in self._selected_targets() if t != "vscode"]
        if targets:
            self._log_install(install_skill(targets=targets, project_dir=self._project_dir()))

    def install_selected_mcp(self) -> None:
        """Install MCP server config for checked targets."""
        targets = self._selected_targets()
        if targets:
            self._log_install(install_mcp(targets=targets, project_dir=self._project_dir()))

    def install_all_selected(self) -> None:
        """Install skill, MCP config, and project pre-commit hook for checked targets."""
        targets = self._selected_targets()
        if not targets:
            return
        proj = self._project_dir()
        results: list[InstallResult] = []
        skill_targets = [t for t in targets if t != "vscode"]
        if skill_targets:
            results.extend(install_skill(targets=skill_targets, project_dir=proj))
        results.extend(install_mcp(targets=targets, project_dir=proj))
        if "project" in targets:
            results.append(install_pre_commit_config(proj))
        self._log_install(results)


def launch_gui(initial_path: str | None = None) -> int:
    """Start the Tkinter window and return its exit code."""
    root = tk.Tk()
    CassetteScrubApp(root, initial_path=initial_path)
    root.mainloop()
    return 0
