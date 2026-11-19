from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any, Callable, Final

from cassette_scrub import __version__
from cassette_scrub.builder import build_standalone_exe
from cassette_scrub.cli import _discover_files
from cassette_scrub.config import load_config
from cassette_scrub.installer import (
    install_mcp,
    install_pre_commit_config,
    install_skill,
)
from cassette_scrub.parser import dump_cassette, load_cassette
from cassette_scrub.scrubber import format_cassette_diff, scrub_cassette
from cassette_scrub.types import Finding, InstallResult, ScrubResult

__all__ = ["CassetteScrubApp", "launch_gui"]

BG_ROOT: Final[str] = "#0d1117"
BG_PANEL: Final[str] = "#161b22"
BG_BUTTON: Final[str] = "#21262d"
BG_ACTIVE: Final[str] = "#30363d"
BORDER_COLOR: Final[str] = "#21262d"
FG_PRIMARY: Final[str] = "#c9d1d9"
FG_MUTED: Final[str] = "#8b949e"
FG_ACCENT: Final[str] = "#58a6ff"
FG_SUCCESS: Final[str] = "#3fb950"
FG_ERROR: Final[str] = "#f85149"

FONT_MONO: Final[tuple[str, int]] = ("Consolas", 10)
FONT_MONO_BOLD: Final[tuple[str, int, str]] = ("Consolas", 10, "bold")

_INSTALLER_TARGET_OPTIONS: Final[tuple[tuple[str, str], ...]] = (
    ("antigravity", "Antigravity"),
    ("claude", "Claude"),
    ("codex", "Codex"),
    ("cursor", "Cursor"),
    ("windsurf", "Windsurf"),
    ("vscode", "VS Code"),
    ("project", "Project Hook"),
)


class CassetteScrubApp:
    """Utilitarian dark developer GUI for inspecting and scrubbing VCR cassettes."""

    def __init__(self, root: tk.Tk, initial_path: str | None = None) -> None:
        self.root = root
        self.root.title(f"CASSETTE-SCRUB v{__version__}")
        self.root.configure(bg=BG_ROOT)
        self.root.minsize(1020, 720)
        self.root.geometry("1220x840")

        default_target = initial_path if initial_path else str(Path.cwd())
        self.target_var = tk.StringVar(value=default_target)
        self.scrub_pii_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="READY")
        self.findings_header_var = tk.StringVar(value="FINDINGS (0)")
        self.diff_header_var = tk.StringVar(value="DIFF / INSPECTOR")
        self.installer_status_var = tk.StringVar(value="INSTALLER READY")

        self.target_vars: dict[str, tk.BooleanVar] = {
            key: tk.BooleanVar(value=True) for key, _label in _INSTALLER_TARGET_OPTIONS
        }

        self._files_scanned: int = 0
        self._files_with_findings: int = 0
        self._last_modified: bool = False
        self._findings: list[Finding] = []
        self._finding_file_paths: list[str] = []
        self._file_diffs: dict[str, str] = {}
        self._dirty_records: list[tuple[Path, str, dict[str, Any], ScrubResult]] = []

        self._build_ui()
        self._append_log(f"READY | TARGET: {default_target}", tag="info")

        if initial_path:
            candidate = Path(initial_path)
            if candidate.is_file():
                self.root.after(50, self.scan)

    def _make_button(
        self,
        parent: tk.Misc,
        text: str,
        command: Callable[[], None],
        *,
        accent: bool = False,
    ) -> tk.Button:
        """Create a square flat dark button with hover state."""
        fg_color = FG_ACCENT if accent else FG_PRIMARY
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            font=FONT_MONO_BOLD,
            bg=BG_BUTTON,
            fg=fg_color,
            activebackground=BG_ACTIVE,
            activeforeground=FG_PRIMARY,
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            highlightcolor=FG_ACCENT,
            padx=10,
            pady=4,
            cursor="hand2",
        )
        btn.bind("<Enter>", lambda _event: btn.configure(bg=BG_ACTIVE))
        btn.bind("<Leave>", lambda _event: btn.configure(bg=BG_BUTTON))
        return btn

    def _make_checkbox(
        self,
        parent: tk.Misc,
        text: str,
        variable: tk.BooleanVar,
        *,
        bg: str = BG_PANEL,
    ) -> tk.Checkbutton:
        """Create a square flat dark checkbutton."""
        return tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            font=FONT_MONO,
            bg=bg,
            fg=FG_PRIMARY,
            activebackground=bg,
            activeforeground=FG_PRIMARY,
            selectcolor=BG_ROOT,
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            highlightcolor=FG_ACCENT,
            anchor="w",
            padx=6,
            pady=2,
            cursor="hand2",
        )

    def _build_ui(self) -> None:
        """Construct the complete single-window developer UI."""
        container = tk.Frame(self.root, bg=BG_ROOT, padx=10, pady=10)
        container.pack(fill=tk.BOTH, expand=True)

        # Header strip
        header_bar = tk.Frame(container, bg=BG_ROOT)
        header_bar.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            header_bar,
            text=f"CASSETTE-SCRUB v{__version__} // VCR SECRET & PII INSPECTOR",
            font=FONT_MONO_BOLD,
            bg=BG_ROOT,
            fg=FG_ACCENT,
            anchor="w",
        ).pack(side=tk.LEFT)

        self.status_label = tk.Label(
            header_bar,
            textvariable=self.status_var,
            font=FONT_MONO_BOLD,
            bg=BG_ROOT,
            fg=FG_MUTED,
            anchor="e",
        )
        self.status_label.pack(side=tk.RIGHT)

        # Top target bar
        target_bar = tk.Frame(
            container,
            bg=BG_PANEL,
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            padx=8,
            pady=8,
        )
        target_bar.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            target_bar,
            text="TARGET",
            font=FONT_MONO_BOLD,
            bg=BG_PANEL,
            fg=FG_MUTED,
        ).pack(side=tk.LEFT, padx=(0, 8))

        self.target_entry = tk.Entry(
            target_bar,
            textvariable=self.target_var,
            font=FONT_MONO,
            bg=BG_ROOT,
            fg=FG_PRIMARY,
            insertbackground=FG_ACCENT,
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            highlightcolor=FG_ACCENT,
        )
        self.target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)

        self._make_button(target_bar, "[BROWSE DIR]", self._browse_dir).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        self._make_button(target_bar, "[BROWSE FILE]", self._browse_file).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        self._make_checkbox(
            target_bar,
            "SCRUB PII (EMAILS)",
            self.scrub_pii_var,
            bg=BG_PANEL,
        ).pack(side=tk.LEFT)

        # Action toolbar
        toolbar = tk.Frame(container, bg=BG_ROOT)
        toolbar.pack(fill=tk.X, pady=(0, 8))

        self._make_button(toolbar, "[SCAN]", self.scan, accent=True).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        self._make_button(toolbar, "[DIFF PREVIEW]", self.diff_preview).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        self._make_button(toolbar, "[SCRUB IN-PLACE]", self.scrub_in_place).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        self._make_button(toolbar, "[COPY JSON REPORT]", self.copy_json_report).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        self._make_button(toolbar, "[BUILD .EXE]", self.build_exe).pack(side=tk.LEFT)

        # Split inspector
        paned = tk.PanedWindow(
            container,
            orient=tk.HORIZONTAL,
            bg=BORDER_COLOR,
            sashwidth=4,
            sashrelief="flat",
            bd=0,
            opaqueresize=True,
        )
        paned.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        # Left pane: Findings Listbox
        left_pane = tk.Frame(
            paned,
            bg=BG_PANEL,
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            padx=6,
            pady=6,
        )
        self.findings_header_label = tk.Label(
            left_pane,
            textvariable=self.findings_header_var,
            font=FONT_MONO_BOLD,
            bg=BG_PANEL,
            fg=FG_MUTED,
            anchor="w",
        )
        self.findings_header_label.pack(fill=tk.X, pady=(0, 4))

        left_scroll_frame = tk.Frame(left_pane, bg=BG_PANEL)
        left_scroll_frame.pack(fill=tk.BOTH, expand=True)

        left_yscroll = tk.Scrollbar(
            left_scroll_frame, orient=tk.VERTICAL, relief="flat", bd=0
        )
        left_xscroll = tk.Scrollbar(
            left_scroll_frame, orient=tk.HORIZONTAL, relief="flat", bd=0
        )
        self.findings_listbox = tk.Listbox(
            left_scroll_frame,
            font=FONT_MONO,
            bg=BG_PANEL,
            fg=FG_PRIMARY,
            selectbackground=BG_ACTIVE,
            selectforeground=FG_ACCENT,
            activestyle="none",
            exportselection=False,
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            highlightcolor=FG_ACCENT,
            yscrollcommand=left_yscroll.set,
            xscrollcommand=left_xscroll.set,
        )
        left_yscroll.config(command=self.findings_listbox.yview)
        left_xscroll.config(command=self.findings_listbox.xview)

        left_yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        left_xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.findings_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.findings_listbox.bind("<<ListboxSelect>>", self._on_finding_selected)

        # Right pane: Unified Diff / Inspector Text
        right_pane = tk.Frame(
            paned,
            bg=BG_PANEL,
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            padx=6,
            pady=6,
        )
        tk.Label(
            right_pane,
            textvariable=self.diff_header_var,
            font=FONT_MONO_BOLD,
            bg=BG_PANEL,
            fg=FG_MUTED,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 4))

        right_scroll_frame = tk.Frame(right_pane, bg=BG_PANEL)
        right_scroll_frame.pack(fill=tk.BOTH, expand=True)

        right_yscroll = tk.Scrollbar(
            right_scroll_frame, orient=tk.VERTICAL, relief="flat", bd=0
        )
        right_xscroll = tk.Scrollbar(
            right_scroll_frame, orient=tk.HORIZONTAL, relief="flat", bd=0
        )
        self.diff_text = tk.Text(
            right_scroll_frame,
            font=FONT_MONO,
            bg=BG_PANEL,
            fg=FG_PRIMARY,
            insertbackground=FG_ACCENT,
            wrap="none",
            state="disabled",
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            highlightcolor=FG_ACCENT,
            yscrollcommand=right_yscroll.set,
            xscrollcommand=right_xscroll.set,
        )
        right_yscroll.config(command=self.diff_text.yview)
        right_xscroll.config(command=self.diff_text.xview)

        right_yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        right_xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.diff_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.diff_text.tag_configure("diff_del", foreground=FG_ERROR)
        self.diff_text.tag_configure("diff_add", foreground=FG_SUCCESS)
        self.diff_text.tag_configure(
            "diff_hunk", foreground=FG_ACCENT, font=FONT_MONO_BOLD
        )
        self.diff_text.tag_configure(
            "diff_header", foreground=FG_PRIMARY, font=FONT_MONO_BOLD
        )
        self.diff_text.tag_configure("info_clean", foreground=FG_SUCCESS)
        self.diff_text.tag_configure("info_error", foreground=FG_ERROR)
        self.diff_text.tag_configure("info_muted", foreground=FG_MUTED)

        paned.add(left_pane, minsize=380, width=500)
        paned.add(right_pane, minsize=460)

        # Bottom AI Skill & MCP Installer panel
        installer_panel = tk.Frame(
            container,
            bg=BG_PANEL,
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            padx=8,
            pady=8,
        )
        installer_panel.pack(fill=tk.X)

        installer_title_row = tk.Frame(installer_panel, bg=BG_PANEL)
        installer_title_row.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            installer_title_row,
            text="AI SKILL (/cassette-scrub) & MCP INSTALLER",
            font=FONT_MONO_BOLD,
            bg=BG_PANEL,
            fg=FG_ACCENT,
            anchor="w",
        ).pack(side=tk.LEFT)

        self.installer_status_label = tk.Label(
            installer_title_row,
            textvariable=self.installer_status_var,
            font=FONT_MONO_BOLD,
            bg=BG_PANEL,
            fg=FG_MUTED,
            anchor="e",
        )
        self.installer_status_label.pack(side=tk.RIGHT)

        checkboxes_row = tk.Frame(installer_panel, bg=BG_PANEL)
        checkboxes_row.pack(fill=tk.X, pady=(0, 6))

        for target_key, label_text in _INSTALLER_TARGET_OPTIONS:
            self._make_checkbox(
                checkboxes_row,
                label_text,
                self.target_vars[target_key],
                bg=BG_PANEL,
            ).pack(side=tk.LEFT, padx=(0, 8))

        installer_btn_row = tk.Frame(installer_panel, bg=BG_PANEL)
        installer_btn_row.pack(fill=tk.X, pady=(0, 6))

        self._make_button(
            installer_btn_row, "[INSTALL SKILL]", self.install_selected_skills
        ).pack(side=tk.LEFT, padx=(0, 6))
        self._make_button(
            installer_btn_row, "[INSTALL MCP]", self.install_selected_mcp
        ).pack(side=tk.LEFT, padx=(0, 6))
        self._make_button(
            installer_btn_row,
            "[INSTALL ALL SELECTED]",
            self.install_all_selected,
            accent=True,
        ).pack(side=tk.LEFT)

        log_frame = tk.Frame(installer_panel, bg=BG_PANEL)
        log_frame.pack(fill=tk.X)

        log_yscroll = tk.Scrollbar(log_frame, orient=tk.VERTICAL, relief="flat", bd=0)
        self.log_text = tk.Text(
            log_frame,
            height=6,
            font=FONT_MONO,
            bg=BG_ROOT,
            fg=FG_PRIMARY,
            insertbackground=FG_ACCENT,
            wrap="none",
            state="disabled",
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            highlightcolor=FG_ACCENT,
            yscrollcommand=log_yscroll.set,
        )
        log_yscroll.config(command=self.log_text.yview)
        log_yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.log_text.tag_configure("ok", foreground=FG_SUCCESS)
        self.log_text.tag_configure("err", foreground=FG_ERROR)
        self.log_text.tag_configure("info", foreground=FG_MUTED)
        self.log_text.tag_configure("accent", foreground=FG_ACCENT)

    def _set_status(self, message: str, color: str = FG_MUTED) -> None:
        """Update top-right status line and foreground color."""
        self.status_var.set(message)
        self.status_label.configure(fg=color)

    def _set_installer_status(self, message: str, color: str = FG_MUTED) -> None:
        """Update installer status line and foreground color."""
        self.installer_status_var.set(message)
        self.installer_status_label.configure(fg=color)

    def _append_log(self, line: str, *, tag: str = "info") -> None:
        """Append a single line to the multi-line installer/output log."""
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, line + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _set_diff_content(self, text: str, *, default_tag: str | None = None) -> None:
        """Render text into the right diff/inspector panel with unified diff color tags."""
        self.diff_text.configure(state="normal")
        self.diff_text.delete("1.0", tk.END)
        for line in text.splitlines(keepends=True):
            tag = default_tag
            if line.startswith("@@"):
                tag = "diff_hunk"
            elif line.startswith("-"):
                tag = "diff_del"
            elif line.startswith("+"):
                tag = "diff_add"
            elif line.startswith("=== "):
                tag = "diff_header"
            if tag:
                self.diff_text.insert(tk.END, line, tag)
            else:
                self.diff_text.insert(tk.END, line)
        self.diff_text.configure(state="disabled")

    def _browse_dir(self) -> None:
        """Open directory picker and update target path."""
        current = self.target_var.get().strip()
        initial_dir = current if current and Path(current).is_dir() else str(Path.cwd())
        selected = filedialog.askdirectory(initialdir=initial_dir, title="SELECT TARGET DIRECTORY")
        if selected:
            self.target_var.set(selected)
            self._append_log(f"TARGET SET -> {selected}", tag="info")

    def _browse_file(self) -> None:
        """Open file picker and update target path."""
        current = self.target_var.get().strip()
        candidate = Path(current) if current else Path.cwd()
        initial_dir = str(candidate if candidate.is_dir() else candidate.parent)
        if not Path(initial_dir).is_dir():
            initial_dir = str(Path.cwd())
        selected = filedialog.askopenfilename(
            initialdir=initial_dir,
            title="SELECT VCR CASSETTE FILE",
            filetypes=[
                ("VCR Cassettes", "*.yaml *.yml *.json"),
                ("YAML Files", "*.yaml *.yml"),
                ("JSON Files", "*.json"),
                ("All Files", "*.*"),
            ],
        )
        if selected:
            self.target_var.set(selected)
            self._append_log(f"TARGET SET -> {selected}", tag="info")

    def _resolve_target_path(self) -> Path:
        """Return Path for current target entry (defaulting to CWD if blank)."""
        raw = self.target_var.get().strip()
        return Path(raw) if raw else Path.cwd()

    def _resolve_project_dir(self) -> Path:
        """Resolve project directory from target path for project-local installs."""
        target = self._resolve_target_path()
        if target.is_file():
            return target.parent
        if target.is_dir():
            return target
        return Path.cwd()

    def _display_file_label(self, file_path: str, base_target: Path) -> str:
        """Format a concise file label relative to base_target when possible."""
        p = Path(file_path)
        if base_target.is_dir():
            try:
                return p.relative_to(base_target).as_posix()
            except ValueError:
                return p.name
        return p.name

    def _execute_scan(self, *, modified_flag: bool = False) -> bool:
        """Scan target cassettes, populate findings and per-file unified diffs."""
        target = self._resolve_target_path()
        self.findings_listbox.delete(0, tk.END)
        self._findings.clear()
        self._finding_file_paths.clear()
        self._file_diffs.clear()
        self._dirty_records.clear()
        self._files_scanned = 0
        self._files_with_findings = 0
        self._last_modified = modified_flag

        if not target.exists():
            self.findings_header_var.set("FINDINGS (0)")
            self.findings_header_label.configure(fg=FG_ERROR)
            self.diff_header_var.set("DIFF / INSPECTOR")
            msg = f"ERROR: TARGET PATH DOES NOT EXIST: {target}"
            self._set_diff_content(msg + "\n", default_tag="info_error")
            self._set_status(f"ERR | MISSING PATH: {target}", FG_ERROR)
            self._append_log(f"[ERR] {msg}", tag="err")
            return False

        files = _discover_files([str(target)])
        scrub_pii = bool(self.scrub_pii_var.get())

        for path in files:
            data, fmt = load_cassette(path)
            if data is None or not fmt:
                continue

            self._files_scanned += 1
            config = load_config(start_dir=path.parent, scrub_pii=scrub_pii)
            result = scrub_cassette(data, str(path), config)

            if result.findings:
                self._files_with_findings += 1
                self._dirty_records.append((path, fmt, data, result))
                if result.modified and result.updated_data is not None:
                    diff_text = format_cassette_diff(
                        data,
                        result.updated_data,
                        fmt,
                        file_path=str(path),
                    )
                    self._file_diffs[str(path)] = diff_text

                display_name = self._display_file_label(str(path), target)
                for finding in result.findings:
                    self._findings.append(finding)
                    self._finding_file_paths.append(finding.file_path)
                    row = (
                        f"{display_name} | interaction[{finding.interaction_index}] "
                        f"| {finding.location} | {finding.preview}"
                    )
                    self.findings_listbox.insert(tk.END, row)

        count = len(self._findings)
        self.findings_header_var.set(f"FINDINGS ({count})")

        if count > 0:
            self.findings_header_label.configure(fg=FG_ERROR)
            self.findings_listbox.selection_clear(0, tk.END)
            self.findings_listbox.selection_set(0)
            self._render_diff_for_index(0)
            self._set_status(
                f"FINDINGS: {count} IN {self._files_with_findings}/{self._files_scanned} CASSETTE(S)",
                FG_ERROR,
            )
        else:
            self.findings_header_label.configure(fg=FG_SUCCESS if self._files_scanned else FG_MUTED)
            self.diff_header_var.set("DIFF / INSPECTOR")
            if self._files_scanned == 0:
                self._set_diff_content(
                    "NO VCR CASSETTES FOUND AT TARGET.\n",
                    default_tag="info_muted",
                )
                self._set_status("0 CASSETTES SCANNED", FG_MUTED)
            else:
                self._set_diff_content(
                    f"CLEAN: 0 FINDINGS ACROSS {self._files_scanned} CASSETTE(S).\n",
                    default_tag="info_clean",
                )
                self._set_status(
                    f"CLEAN | {self._files_scanned} CASSETTE(S) | 0 FINDINGS",
                    FG_SUCCESS,
                )
        return True

    def _render_diff_for_index(self, index: int) -> None:
        """Render the unified diff for the finding at Listbox index."""
        if index < 0 or index >= len(self._finding_file_paths):
            return
        file_path = self._finding_file_paths[index]
        diff_text = self._file_diffs.get(file_path, "")
        self.diff_header_var.set(f"DIFF / INSPECTOR | {file_path}")
        if diff_text:
            self._set_diff_content(diff_text)
        else:
            self._set_diff_content(
                f"NO UNIFIED DIFF AVAILABLE FOR {file_path}.\n",
                default_tag="info_muted",
            )

    def _on_finding_selected(self, _event: tk.Event[tk.Listbox]) -> None:
        """Handle clicking a finding row by rendering that file's unified diff."""
        selection = self.findings_listbox.curselection()
        if not selection:
            return
        self._render_diff_for_index(int(selection[0]))

    def scan(self) -> None:
        """Run a non-destructive --check scan on the target path."""
        ok = self._execute_scan(modified_flag=False)
        if ok:
            self._append_log(
                f"SCAN | SCANNED={self._files_scanned} DIRTY={self._files_with_findings} FINDINGS={len(self._findings)}",
                tag="err" if self._findings else "ok",
            )

    def diff_preview(self) -> None:
        """Scan target cassettes and render combined unified diffs for all dirty files."""
        ok = self._execute_scan(modified_flag=False)
        if not ok:
            return
        if not self._file_diffs:
            self._append_log("DIFF PREVIEW | ALL SCANNED CASSETTES ARE CLEAN.", tag="ok")
            return

        blocks = [
            f"=== FILE: {file_path} ===\n{diff_text}"
            for file_path, diff_text in self._file_diffs.items()
            if diff_text
        ]
        self.diff_header_var.set(
            f"DIFF PREVIEW | {len(blocks)} MODIFIED CASSETTE(S)"
        )
        self._set_diff_content("\n".join(blocks))
        self._append_log(
            f"DIFF PREVIEW | DISPLAYED {len(blocks)} CASSETTE DIFF(S).",
            tag="accent",
        )

    def scrub_in_place(self) -> None:
        """Scrub detected secrets and PII from dirty cassettes on disk (--fix)."""
        ok = self._execute_scan(modified_flag=False)
        if not ok:
            return

        if not self._dirty_records:
            self._append_log("SCRUB IN-PLACE | NO DIRTY CASSETTES FOUND.", tag="ok")
            return

        file_count = len(self._dirty_records)
        finding_count = len(self._findings)
        confirmed = messagebox.askyesno(
            "CONFIRM SCRUB IN-PLACE",
            f"Scrub {finding_count} finding(s) across {file_count} cassette file(s) in-place?",
        )
        if not confirmed:
            self._append_log("SCRUB IN-PLACE | CANCELLED BY USER.", tag="info")
            return

        written_paths: list[Path] = []
        applied_diffs: list[str] = []
        for path, fmt, _original_data, result in self._dirty_records:
            if result.modified and result.updated_data is not None:
                dump_cassette(path, result.updated_data, fmt)
                written_paths.append(path)
                diff_text = self._file_diffs.get(str(path), "")
                if diff_text:
                    applied_diffs.append(f"=== SCRUBBED: {path} ===\n{diff_text}")
                self._append_log(f"[OK] SCRUBBED -> {path}", tag="ok")

        self._execute_scan(modified_flag=bool(written_paths))
        if applied_diffs and not self._findings:
            self.diff_header_var.set(
                f"SCRUBBED IN-PLACE | {len(written_paths)} FILE(S) MODIFIED"
            )
            self._set_diff_content("\n".join(applied_diffs))
            self._set_status(
                f"SCRUBBED | {len(written_paths)} FILE(S) MODIFIED | 0 REMAINING",
                FG_SUCCESS,
            )

    def _build_json_report(self) -> dict[str, Any]:
        """Construct the machine-readable JSON scan report payload."""
        return {
            "version": __version__,
            "modified": self._last_modified,
            "files_scanned": self._files_scanned,
            "files_with_findings": self._files_with_findings,
            "findings": [
                {
                    "file_path": finding.file_path,
                    "interaction_index": finding.interaction_index,
                    "location": finding.location,
                    "preview": finding.preview,
                }
                for finding in self._findings
            ],
        }

    def copy_json_report(self) -> None:
        """Copy the JSON findings report to the system clipboard."""
        payload = json.dumps(self._build_json_report(), indent=2)
        self.root.clipboard_clear()
        self.root.clipboard_append(payload)
        self.root.update()
        self.diff_header_var.set("JSON REPORT (COPIED TO CLIPBOARD)")
        self._set_diff_content(payload + "\n")
        self._set_status(
            f"COPIED JSON REPORT | {len(self._findings)} FINDING(S)",
            FG_ACCENT,
        )
        self._append_log(
            f"[OK] COPIED JSON REPORT TO CLIPBOARD ({len(self._findings)} FINDINGS)",
            tag="accent",
        )

    def build_exe(self) -> None:
        """Build standalone CLI and GUI .exe binaries in dist/."""
        try:
            built = build_standalone_exe()
        except Exception as exc:
            self._set_status(f"ERR | BUILD .EXE FAILED: {exc}", FG_ERROR)
            self._append_log(f"[ERR] BUILD .EXE FAILED -> {exc}", tag="err")
            messagebox.showerror("BUILD .EXE FAILED", str(exc))
            return

        cli_exe = built["cli_exe"]
        gui_exe = built["gui_exe"]
        self._append_log(f"[OK] BUILT CLI EXE -> {cli_exe}", tag="ok")
        self._append_log(f"[OK] BUILT GUI EXE -> {gui_exe}", tag="ok")
        self._set_status(f"BUILT .EXE ARTIFACTS -> {cli_exe.parent}", FG_SUCCESS)

    def _selected_installer_targets(self) -> list[str]:
        """Return ordered target keys currently checked in the installer panel."""
        return [
            key
            for key, _label in _INSTALLER_TARGET_OPTIONS
            if self.target_vars[key].get()
        ]

    def _record_install_results(self, results: list[InstallResult]) -> None:
        """Write InstallResult entries to the multi-line log and status line."""
        if not results:
            self._set_installer_status("NO INSTALL OPERATIONS EXECUTED", FG_MUTED)
            self._append_log("INSTALLER | NO MATCHING TARGET OPERATIONS.", tag="info")
            return

        ok_count = 0
        fail_count = 0
        for res in results:
            if res.success:
                ok_count += 1
                tag = "ok"
                prefix = "[OK]"
            else:
                fail_count += 1
                tag = "err"
                prefix = "[ERR]"
            path_part = res.path if res.path else "<none>"
            self._append_log(
                f"{prefix} {res.target} ({res.kind}) | {path_part} | {res.message}",
                tag=tag,
            )

        summary = f"INSTALL COMPLETE | {ok_count} OK, {fail_count} FAILED"
        self._set_installer_status(summary, FG_ERROR if fail_count else FG_SUCCESS)
        self._set_status(summary, FG_ERROR if fail_count else FG_SUCCESS)

    def install_selected_skills(self) -> None:
        """Install /cassette-scrub skill files for checked targets."""
        selected = self._selected_installer_targets()
        skill_targets = [t for t in selected if t != "vscode"]
        if not skill_targets:
            msg = "NO SKILL-COMPATIBLE TARGETS SELECTED."
            self._set_installer_status(msg, FG_ERROR)
            self._append_log(f"[ERR] {msg}", tag="err")
            return

        project_dir = self._resolve_project_dir()
        results = install_skill(targets=skill_targets, project_dir=project_dir)
        self._record_install_results(results)

    def install_selected_mcp(self) -> None:
        """Install cassette-scrub MCP server config for checked targets."""
        selected = self._selected_installer_targets()
        if not selected:
            msg = "NO INSTALLER TARGETS SELECTED."
            self._set_installer_status(msg, FG_ERROR)
            self._append_log(f"[ERR] {msg}", tag="err")
            return

        project_dir = self._resolve_project_dir()
        results = install_mcp(targets=selected, project_dir=project_dir)
        self._record_install_results(results)

    def install_all_selected(self) -> None:
        """Install skill, MCP configs, and project pre-commit hook for checked targets."""
        selected = self._selected_installer_targets()
        if not selected:
            msg = "NO INSTALLER TARGETS SELECTED."
            self._set_installer_status(msg, FG_ERROR)
            self._append_log(f"[ERR] {msg}", tag="err")
            return

        project_dir = self._resolve_project_dir()
        results: list[InstallResult] = []

        skill_targets = [t for t in selected if t != "vscode"]
        if skill_targets:
            results.extend(install_skill(targets=skill_targets, project_dir=project_dir))

        results.extend(install_mcp(targets=selected, project_dir=project_dir))

        if "project" in selected:
            results.append(install_pre_commit_config(project_dir=project_dir))

        self._record_install_results(results)


def launch_gui(initial_path: str | None = None) -> int:
    """Launch the cassette-scrub Tkinter desktop GUI and return process exit code."""
    root = tk.Tk()
    CassetteScrubApp(root, initial_path=initial_path)
    root.mainloop()
    return 0
