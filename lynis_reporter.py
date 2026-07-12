#!/usr/bin/env python3
"""Lynis Report Viewer — parses a lynis-report.dat and displays a findings dashboard."""

import tkinter as tk
import webbrowser
from dataclasses import dataclass, field
from tkinter import filedialog, messagebox, ttk

CISOFY_URL = "https://cisofy.com/lynis/controls/{test_id}/"

BG = "#FAFAFA"
BG_PANEL = "#FFFFFF"
BORDER = "#E2E5EA"
TEXT_PRIMARY = "#22262B"
TEXT_MUTED = "#6B7280"
ACCENT = "#3B5BDB"
RED = "#D9364A"
ORANGE = "#E08A1E"
GREEN = "#2F9E5B"
ROW_WARNING_BG = "#FDEEEF"
ROW_SUGGESTION_BG = "#FFF8E6"


@dataclass
class Finding:
    severity: str  # "warning" | "suggestion"
    test_id: str
    description: str
    detail: str
    doc_url: str


@dataclass
class ParsedReport:
    hardening_index: int
    os_fullname: str
    hostname: str
    lynis_version: str
    report_datetime: str
    findings: list = field(default_factory=list)


def parse_lynis_report(text: str) -> ParsedReport:
    findings = []
    meta = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        if key in ("warning[]", "suggestion[]"):
            severity = "warning" if key == "warning[]" else "suggestion"
            parts = value.split("|")
            test_id = parts[0] if len(parts) > 0 else ""
            description = parts[1] if len(parts) > 1 else ""
            detail = parts[2] if len(parts) > 2 else ""
            if not test_id and not description:
                continue
            findings.append(
                Finding(
                    severity=severity,
                    test_id=test_id,
                    description=description,
                    detail=detail,
                    doc_url=CISOFY_URL.format(test_id=test_id) if test_id else "",
                )
            )
        else:
            meta.setdefault(key, value)

    try:
        hardening_index = int(meta.get("hardening_index", "0"))
    except ValueError:
        hardening_index = 0

    if "hardening_index" not in meta and not findings:
        raise ValueError(
            "No Lynis data recognized in this content.\n"
            "Check that this is really a lynis-report.dat file."
        )

    return ParsedReport(
        hardening_index=hardening_index,
        os_fullname=meta.get("os_fullname", "—"),
        hostname=meta.get("hostname", "—"),
        lynis_version=meta.get("lynis_version", "—"),
        report_datetime=meta.get("report_datetime_start", "—"),
        findings=findings,
    )


class LynisReporterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Lynis Report Viewer")
        self.geometry("1080x720")
        self.minsize(860, 560)
        self.configure(bg=BG)

        self.report: ParsedReport | None = None
        self.all_findings: list[Finding] = []

        self._setup_style()
        self._build_input_section()
        self._build_score_banner()
        self._build_table_section()

        self._show_input_only()

    # ---------- style ----------

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=BG, foreground=TEXT_PRIMARY, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=BG_PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT_PRIMARY)
        style.configure("Panel.TLabel", background=BG_PANEL, foreground=TEXT_PRIMARY)
        style.configure("Muted.TLabel", background=BG_PANEL, foreground=TEXT_MUTED, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=BG, foreground=TEXT_PRIMARY, font=("Segoe UI", 16, "bold"))
        style.configure("Score.TLabel", background=BG_PANEL, font=("Segoe UI", 34, "bold"))
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="white",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 8),
            borderwidth=0,
        )
        style.map("Accent.TButton", background=[("active", "#2F49B8")])
        style.configure(
            "Secondary.TButton",
            background="#EEF1F6",
            foreground=TEXT_PRIMARY,
            font=("Segoe UI", 10),
            padding=(12, 7),
            borderwidth=0,
        )
        style.map("Secondary.TButton", background=[("active", "#E2E6EE")])

        style.configure(
            "Treeview",
            background=BG_PANEL,
            fieldbackground=BG_PANEL,
            foreground=TEXT_PRIMARY,
            rowheight=28,
            font=("Segoe UI", 9),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#EEF1F6",
            foreground=TEXT_PRIMARY,
            font=("Segoe UI", 9, "bold"),
            padding=(6, 6),
            borderwidth=0,
        )
        style.map("Treeview", background=[("selected", "#D8E0FA")], foreground=[("selected", TEXT_PRIMARY)])

        style.configure("TCombobox", padding=4)
        style.configure("TEntry", padding=4)

    # ---------- input section ----------

    def _build_input_section(self):
        self.input_frame = ttk.Frame(self, padding=(20, 18, 20, 10))

        ttk.Label(self.input_frame, text="Lynis Report Viewer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            self.input_frame,
            text="Load a lynis-report.dat file or paste its content below.",
            style="Muted.TLabel",
            background=BG,
        ).pack(anchor="w", pady=(2, 12))

        btn_row = ttk.Frame(self.input_frame)
        btn_row.pack(fill="x", pady=(0, 8))
        ttk.Button(btn_row, text="Load a file…", style="Secondary.TButton", command=self._load_file).pack(
            side="left"
        )
        self.file_label = ttk.Label(btn_row, text="", style="Muted.TLabel", background=BG)
        self.file_label.pack(side="left", padx=10)

        text_frame = tk.Frame(self.input_frame, bg=BORDER, bd=0, highlightthickness=1, highlightbackground=BORDER)
        text_frame.pack(fill="both", expand=True)
        self.text_input = tk.Text(
            text_frame,
            height=12,
            wrap="none",
            bg=BG_PANEL,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            font=("Consolas", 9),
            padx=10,
            pady=8,
        )
        yscroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.text_input.yview)
        self.text_input.configure(yscrollcommand=yscroll.set)
        self.text_input.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        action_row = ttk.Frame(self.input_frame)
        action_row.pack(fill="x", pady=(10, 0))
        ttk.Button(action_row, text="Analyze", style="Accent.TButton", command=self._analyze).pack(side="left")
        ttk.Button(action_row, text="Clear", style="Secondary.TButton", command=self._clear_input).pack(
            side="left", padx=(8, 0)
        )

    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Choose a lynis-report.dat",
            filetypes=[("Lynis report", "*.dat *.log *.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as exc:
            messagebox.showerror("Read error", f"Could not read the file:\n{exc}")
            return
        self.text_input.delete("1.0", "end")
        self.text_input.insert("1.0", content)
        self.file_label.config(text=path.split("/")[-1])

    def _clear_input(self):
        self.text_input.delete("1.0", "end")
        self.file_label.config(text="")

    def _analyze(self):
        content = self.text_input.get("1.0", "end")
        if not content.strip():
            messagebox.showwarning("Empty content", "Load a file or paste the content of a Lynis report.")
            return
        try:
            report = parse_lynis_report(content)
        except ValueError as exc:
            messagebox.showerror("Parse error", str(exc))
            return

        self.report = report
        self.all_findings = report.findings
        self._populate_score_banner(report)
        self._populate_table(self.all_findings)
        self._show_results()

    # ---------- score banner ----------

    def _build_score_banner(self):
        self.score_frame = tk.Frame(self, bg=BG_PANEL, highlightthickness=1, highlightbackground=BORDER)

        inner = tk.Frame(self.score_frame, bg=BG_PANEL, padx=20, pady=14)
        inner.pack(fill="x")

        self.score_value_label = ttk.Label(inner, text="—", style="Score.TLabel")
        self.score_value_label.grid(row=0, column=0, rowspan=2, padx=(0, 24), sticky="w")

        self.score_caption_label = ttk.Label(inner, text="Hardening index", style="Muted.TLabel")
        self.score_caption_label.grid(row=2, column=0, sticky="w", padx=(0, 24))

        self.meta_label = ttk.Label(inner, text="", style="Panel.TLabel", font=("Segoe UI", 10, "bold"))
        self.meta_label.grid(row=0, column=1, sticky="w")

        self.meta_sub_label = ttk.Label(inner, text="", style="Muted.TLabel")
        self.meta_sub_label.grid(row=1, column=1, sticky="w")

        self.counts_label = ttk.Label(inner, text="", style="Panel.TLabel", font=("Segoe UI", 10))
        self.counts_label.grid(row=2, column=1, sticky="w")

        inner.grid_columnconfigure(1, weight=1)

    def _populate_score_banner(self, report: ParsedReport):
        score = report.hardening_index
        color = RED if score < 50 else ORANGE if score < 80 else GREEN
        self.score_value_label.config(text=str(score), foreground=color)

        self.meta_label.config(text=f"{report.os_fullname}  ·  {report.hostname}")
        self.meta_sub_label.config(text=f"Lynis {report.lynis_version}   —   Scan: {report.report_datetime}")

        n_warn = sum(1 for f in report.findings if f.severity == "warning")
        n_sugg = sum(1 for f in report.findings if f.severity == "suggestion")
        self.counts_label.config(text=f"⚠ {n_warn} warning(s)      ℹ {n_sugg} suggestion(s)")

    # ---------- table section ----------

    def _build_table_section(self):
        self.table_frame = ttk.Frame(self, padding=(20, 10, 20, 20))

        filter_row = ttk.Frame(self.table_frame)
        filter_row.pack(fill="x", pady=(0, 10))

        ttk.Label(filter_row, text="Severity:").pack(side="left")
        self.severity_filter = tk.StringVar(value="All")
        severity_combo = ttk.Combobox(
            filter_row,
            textvariable=self.severity_filter,
            values=["All", "warning", "suggestion"],
            state="readonly",
            width=12,
        )
        severity_combo.pack(side="left", padx=(6, 18))
        severity_combo.bind("<<ComboboxSelected>>", lambda _event: self._apply_filters())

        ttk.Label(filter_row, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_args: self._apply_filters())
        ttk.Entry(filter_row, textvariable=self.search_var, width=40).pack(side="left", padx=(6, 18))

        ttk.Button(
            filter_row, text="Open doc", style="Secondary.TButton", command=self._open_selected_doc
        ).pack(side="right")
        ttk.Button(
            filter_row, text="New analysis", style="Secondary.TButton", command=self._show_input_only
        ).pack(side="right", padx=(0, 8))

        columns = ("severity", "test_id", "description", "doc")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("severity", text="Severity", command=lambda: self._sort_by("severity"))
        self.tree.heading("test_id", text="Test-ID", command=lambda: self._sort_by("test_id"))
        self.tree.heading("description", text="Description", command=lambda: self._sort_by("description"))
        self.tree.heading("doc", text="Documentation")
        self.tree.column("severity", width=100, anchor="w")
        self.tree.column("test_id", width=110, anchor="w")
        self.tree.column("description", width=560, anchor="w")
        self.tree.column("doc", width=220, anchor="w")

        self.tree.tag_configure("warning", background=ROW_WARNING_BG)
        self.tree.tag_configure("suggestion", background=ROW_SUGGESTION_BG)

        vscroll = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", lambda _event: self._open_selected_doc())
        self.tree.bind("<Button-3>", self._show_context_menu)

        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self._copy_selected_finding)

        self._sort_state = {"column": None, "reverse": False}
        self._visible_findings: dict[str, Finding] = {}

    def _populate_table(self, findings: list[Finding]):
        self.tree.delete(*self.tree.get_children())
        self._visible_findings = {}
        for index, f in enumerate(findings):
            iid = str(index)
            label = "Warning" if f.severity == "warning" else "Suggestion"
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(label, f.test_id, f.description, f.doc_url),
                tags=(f.severity,),
            )
            self._visible_findings[iid] = f

    def _apply_filters(self):
        if not self.report:
            return
        severity = self.severity_filter.get()
        query = self.search_var.get().strip().lower()

        filtered = self.all_findings
        if severity != "All":
            filtered = [f for f in filtered if f.severity == severity]
        if query:
            filtered = [
                f for f in filtered if query in f.test_id.lower() or query in f.description.lower()
            ]
        self._populate_table(filtered)

    def _sort_by(self, column):
        reverse = self._sort_state["column"] == column and not self._sort_state["reverse"]
        self._sort_state = {"column": column, "reverse": reverse}

        items = [(self.tree.set(iid, column), iid) for iid in self.tree.get_children("")]
        items.sort(key=lambda t: t[0].lower(), reverse=reverse)
        for index, (_, iid) in enumerate(items):
            self.tree.move(iid, "", index)

    def _show_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def _copy_selected_finding(self):
        selection = self.tree.selection()
        if not selection:
            return
        finding = self._visible_findings.get(selection[0])
        if not finding:
            return
        label = "Warning" if finding.severity == "warning" else "Suggestion"
        lines = [f"[{label}] {finding.test_id}: {finding.description}"]
        if finding.detail:
            lines.append(finding.detail)
        if finding.doc_url:
            lines.append(finding.doc_url)
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))

    def _open_selected_doc(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select a row in the table first.")
            return
        doc_url = self.tree.set(selection[0], "doc")
        if doc_url:
            webbrowser.open(doc_url)
        else:
            messagebox.showinfo("No link", "No documentation available for this entry.")

    # ---------- view state ----------

    def _show_input_only(self):
        self.score_frame.pack_forget()
        self.table_frame.pack_forget()
        self.input_frame.pack(fill="both", expand=True)

    def _show_results(self):
        self.input_frame.pack_forget()
        self.score_frame.pack(fill="x", padx=20, pady=(18, 10))
        self.table_frame.pack(fill="both", expand=True)


if __name__ == "__main__":
    app = LynisReporterApp()
    app.mainloop()
