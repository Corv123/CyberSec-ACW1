"""
gui_app.py -- Person6's module (FR11 case demonstration, FR12 evidence/reproducibility)

Tkinter GUI (ALIGNMENT.md Section 3). Run from the repo root:

    python src/gui_app.py

Tabs:
  Protect     FR1/FR2 input, FR3 payload, FR4 sign, FR5/FR6 embed, FR7 start, FR9 hash
  Verify      FR8 extract, FR4 signature, FR9 hash, FR10 verdict
  Test Cases  FR11 positive + negative cases in one click (expected vs actual)

Every run is also saved to tests/evidence/ (report.json + summary.md) for FR12 --
use the "Open evidence folder" button on each tab.

Logic lives in gui_pipeline.py and widgets in gui_components.py -- teammates can
reuse either without touching this file. Unimplemented teammate functions show up
as PENDING instead of crashing the GUI.
"""

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import gui_pipeline as pipeline
from gui_components import (
    BeforeAfterPreview, CaseTable, FileField, JsonView,
    MediaPreview, ParamsFrame, StepList, VerdictBanner, open_path, run_async,
)

KEY_FILETYPES = [("PEM key", "*.pem"), ("All files", "*.*")]


def _controls_column(parent, width=330):
    frame = ttk.Frame(parent, width=width, padding=(8, 8, 4, 8))
    frame.grid(row=0, column=0, sticky="nsw")
    frame.grid_propagate(False)
    frame.columnconfigure(0, weight=1)
    return frame


def _results_column(parent):
    frame = ttk.Frame(parent, padding=(4, 8, 8, 8))
    frame.grid(row=0, column=1, sticky="nsew")
    parent.columnconfigure(1, weight=1)
    parent.rowconfigure(0, weight=1)
    return frame


class ProtectTab(ttk.Frame):
    """Cover + message + parameters -> signed stego file."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app, self.result = app, None
        left, right = _controls_column(self), _results_column(self)

        self.cover = FileField(left, "Cover file (PNG image or WAV audio)", on_change=self._on_cover)
        self.cover.pack(fill="x")
        self.info = ttk.Label(left, text="", wraplength=310, foreground="#555")
        self.info.pack(fill="x", pady=(2, 6))

        msg = ttk.LabelFrame(left, text="Secret message (FR3)", padding=6)
        msg.pack(fill="x")
        self.preset = tk.StringVar(value="short")
        row = ttk.Frame(msg)
        row.pack(fill="x")
        for name in ("short", "large", "custom"):
            ttk.Radiobutton(row, text=name.title(), value=name, variable=self.preset,
                            command=self._load_preset).pack(side="left")
        self.message = tk.Text(msg, height=5, wrap="word")
        self.message.pack(fill="x", pady=(4, 0))
        self.msg_count = ttk.Label(msg, text="")
        self.msg_count.pack(anchor="e")
        self.message.bind("<KeyRelease>", lambda _e: self._count())
        self._load_preset()

        self.params = ParamsFrame(left)
        self.params.pack(fill="x", pady=6)
        self.key = FileField(left, "Private key (signing, FR4)", KEY_FILETYPES,
                             pipeline.DEFAULT_PRIVATE_KEY)
        self.key.pack(fill="x")

        self.run_btn = ttk.Button(left, text="Protect (embed)", command=self.run)
        self.run_btn.pack(fill="x", pady=(10, 2))
        self.progress = ttk.Progressbar(left, mode="indeterminate")
        self.progress.pack(fill="x")
        self.to_verify = ttk.Button(left, text="Verify this output →", command=self._send_to_verify,
                                    state="disabled")
        self.to_verify.pack(fill="x", pady=(8, 2))
        self.save_btn = ttk.Button(left, text="Save stego as…", command=self._save_as, state="disabled")
        self.save_btn.pack(fill="x", pady=2)
        self.ev_btn = ttk.Button(left, text="Open evidence folder", state="disabled",
                                 command=lambda: open_path(self.result.evidence_dir))
        self.ev_btn.pack(fill="x", pady=2)

        self.banner = VerdictBanner(right)
        self.banner.pack(fill="x")
        self.preview = BeforeAfterPreview(right)
        self.preview.pack(fill="x", pady=6)
        self.steps = StepList(right, height=8)
        self.steps.pack(fill="both", expand=True)

    def _load_preset(self):
        self.message.delete("1.0", "end")
        self.message.insert("1.0", pipeline.MESSAGE_PRESETS[self.preset.get()])
        self._count()

    def _count(self):
        n = len(self.message.get("1.0", "end-1c").encode("utf-8"))
        self.msg_count.configure(text=f"{n:,} bytes")

    def _on_cover(self, path):
        try:
            kind, info, warnings = pipeline.inspect_media(path)
            self.params.set_kind(kind)
            self.info.configure(text=pipeline.describe_media(kind, info)
                                + "".join("\n⚠ " + w for w in warnings), foreground="#555")
            self.preview.show(cover=path)
        except Exception as exc:
            self.info.configure(text=f"✘ {exc}", foreground="#c62828")
            self.preview.show()

    def run(self):
        cover = self.cover.get()
        if not cover:
            messagebox.showwarning("Protect", "Choose a cover file first.")
            return
        try:
            params = self.params.get()
        except ValueError as exc:
            messagebox.showwarning("Protect", str(exc))
            return
        message = self.message.get("1.0", "end-1c")
        key = self.key.get()
        self._busy(True)
        self.banner.show_text("Protecting…", "Large images can take several seconds.", "idle")
        run_async(self, lambda _p: pipeline.protect(cover, message, params, key),
                  self._done, self._error)

    def _done(self, result):
        self._busy(False)
        self.result = result
        self.banner.show_result(result)
        self.steps.set_steps(result.steps)
        self.preview.show(self.cover.get(), result.outputs.get("stego"),
                          result.outputs.get("difference"), result.stats.get("summary", ""))
        ok = result.outcome == "Protected"
        self.to_verify.configure(state="normal" if ok else "disabled")
        self.save_btn.configure(state="normal" if ok else "disabled")
        self.ev_btn.configure(state="normal")
        self.app.after_run()

    def _error(self, exc, tb):
        self._busy(False)
        self.banner.show_text("✘  ERROR", f"{type(exc).__name__}: {exc}", "warning")

    def _busy(self, busy):
        self.run_btn.configure(state="disabled" if busy else "normal")
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _send_to_verify(self):
        params = dict(self.result.params)
        self.app.verify_tab.prefill(self.result.outputs["stego"], params)
        self.app.notebook.select(self.app.verify_tab)

    def _save_as(self):
        src = Path(self.result.outputs["stego"])
        dst = filedialog.asksaveasfilename(initialdir=str(pipeline.ROOT / "samples"),
                                           initialfile=src.name, defaultextension=src.suffix)
        if dst:
            pipeline.copy_file(src, dst)
            messagebox.showinfo("Saved", f"Saved to {dst}")


class VerifyTab(ttk.Frame):
    """Stego file -> extract -> signature -> hash -> verdict."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app, self.result = app, None
        left, right = _controls_column(self), _results_column(self)

        self.file = FileField(left, "File to verify (PNG / WAV)", on_change=self._on_file)
        self.file.pack(fill="x")
        self.info = ttk.Label(left, text="", wraplength=310, foreground="#555")
        self.info.pack(fill="x", pady=(2, 6))
        ttk.Label(left, text="Use the same start location and LSB depth as when protecting.",
                  wraplength=310, foreground="#1565c0").pack(fill="x")
        self.params = ParamsFrame(left)
        self.params.pack(fill="x", pady=6)
        self.key = FileField(left, "Public key (verification, FR4)", KEY_FILETYPES,
                             pipeline.DEFAULT_PUBLIC_KEY)
        self.key.pack(fill="x")
        self.run_btn = ttk.Button(left, text="Verify (extract)", command=self.run)
        self.run_btn.pack(fill="x", pady=(10, 2))
        self.progress = ttk.Progressbar(left, mode="indeterminate")
        self.progress.pack(fill="x")
        self.ev_btn = ttk.Button(left, text="Open evidence folder", state="disabled",
                                 command=lambda: open_path(self.result.evidence_dir))
        self.ev_btn.pack(fill="x", pady=(8, 2))

        self.banner = VerdictBanner(right)
        self.banner.pack(fill="x")
        mid = ttk.Frame(right)
        mid.pack(fill="x", pady=6)
        self.preview = MediaPreview(mid, "File under test", 300, 220)
        self.preview.pack(side="left", anchor="n")
        pay = ttk.LabelFrame(mid, text="Extracted payload (FR8)", padding=4)
        pay.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.payload = JsonView(pay, height=14)
        self.payload.pack(fill="both", expand=True)
        self.steps = StepList(right, height=8)
        self.steps.pack(fill="both", expand=True)

    def _on_file(self, path):
        try:
            kind, info, warnings = pipeline.inspect_media(path)
            self.params.set_kind(kind)
            self.info.configure(text=pipeline.describe_media(kind, info), foreground="#555")
        except Exception as exc:
            self.info.configure(text=f"✘ {exc}", foreground="#c62828")
        self.preview.show(path)

    def prefill(self, path, params):
        self.params.set(params)
        self.file.set(path)
        self.banner.clear("Ready to verify")
        self.steps.clear()
        self.payload.set_data(None)

    def run(self):
        path = self.file.get()
        if not path:
            messagebox.showwarning("Verify", "Choose a file to verify first.")
            return
        try:
            params = self.params.get()
        except ValueError as exc:
            messagebox.showwarning("Verify", str(exc))
            return
        key = self.key.get()
        self.run_btn.configure(state="disabled")
        self.progress.start(12)
        self.banner.show_text("Verifying…", "", "idle")
        run_async(self, lambda _p: pipeline.verify(path, params, key), self._done, self._error)

    def _done(self, result):
        self.run_btn.configure(state="normal")
        self.progress.stop()
        self.result = result
        self.banner.show_result(result)
        self.steps.set_steps(result.steps)
        failed = next((s for s in result.steps if s.fr == "FR8" and s.status == "fail"), None)
        self.payload.set_data(result.payload if result.payload is not None else
                              "EXTRACTION FAILED\n\n" + (failed.detail if failed else
                                                         "No payload could be decoded."))
        self.ev_btn.configure(state="normal")
        self.app.after_run()

    def _error(self, exc, tb):
        self.run_btn.configure(state="normal")
        self.progress.stop()
        self.banner.show_text("✘  ERROR", f"{type(exc).__name__}: {exc}", "warning")


class CasesTab(ttk.Frame):
    """FR11: every positive and negative case against one cover, in one click."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app, self.last = app, None
        left, right = _controls_column(self), _results_column(self)

        self.cover = FileField(left, "Cover file (PNG image or WAV audio)",
                               initial=pipeline.ROOT / "samples" / "file_example_WAV_1MG.wav",
                               on_change=self._on_cover)
        self.cover.pack(fill="x")
        self.params = ParamsFrame(left)
        self.params.pack(fill="x", pady=6)
        self.params.set_kind("audio")
        msg = ttk.LabelFrame(left, text="Custom message (short/large use the presets)", padding=6)
        msg.pack(fill="x")
        self.custom = tk.Text(msg, height=4, wrap="word")
        self.custom.insert("1.0", pipeline.MESSAGE_PRESETS["custom"])
        self.custom.pack(fill="x")
        ttk.Label(left, text="Runs: 3 positive (short / large / custom) + 7 negative cases. "
                             "A 4000x4000 image takes about a minute; audio a few seconds.",
                  wraplength=310, foreground="#555").pack(fill="x", pady=6)
        self.run_btn = ttk.Button(left, text="▶  Run all test cases", command=self.run)
        self.run_btn.pack(fill="x", pady=(4, 2))
        self.progress = ttk.Progressbar(left, mode="determinate")
        self.progress.pack(fill="x")
        self.progress_text = ttk.Label(left, text="")
        self.progress_text.pack(anchor="w")
        self.ev_btn = ttk.Button(left, text="Open evidence folder", state="disabled",
                                 command=lambda: open_path(self.last["evidence_dir"]))
        self.ev_btn.pack(fill="x", pady=(8, 2))
        ttk.Label(left, text="* = provisional GUI verdict (FR10 pending)\nBLOCKED = needs a "
                             "pending FR before it can pass", foreground="#555").pack(anchor="w")

        self.banner = VerdictBanner(right)
        self.banner.pack(fill="x")
        self.table = CaseTable(right, on_select=self._on_row, height=10)
        self.table.pack(fill="x", pady=6)
        bottom = ttk.Frame(right)
        bottom.pack(fill="both", expand=True)
        self.preview = MediaPreview(bottom, "File used by selected case", 280, 190)
        self.preview.pack(side="left", anchor="n")
        detail = ttk.Frame(bottom)
        detail.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.case_banner = VerdictBanner(detail)
        self.case_banner.pack(fill="x")
        self.steps = StepList(detail, height=5)
        self.steps.pack(fill="both", expand=True)

    def _on_cover(self, path):
        try:
            self.params.set_kind(pipeline.detect_kind(path))
        except ValueError:
            pass

    def run(self):
        cover = self.cover.get()
        if not cover:
            messagebox.showwarning("Test cases", "Choose a cover file first.")
            return
        try:
            params = self.params.get()
        except ValueError as exc:
            messagebox.showwarning("Test cases", str(exc))
            return
        custom = self.custom.get("1.0", "end-1c")
        self.run_btn.configure(state="disabled")
        self.progress.configure(value=0, maximum=len(pipeline.CASES))
        self.banner.show_text("Running test cases…", "", "idle")
        run_async(self, lambda progress: pipeline.run_case_suite(
            cover, params, {"custom": custom}, progress=progress),
            self._done, self._error, self._progress)

    def _progress(self, i, total, text):
        self.progress.configure(value=i, maximum=total)
        self.progress_text.configure(text=f"{i}/{total}  {text}")

    def _done(self, out):
        self.run_btn.configure(state="normal")
        self.last = out
        s = out["summary"]
        pol = "negative" if s["FAIL"] else "positive"
        self.banner.show_text(
            f"{'✘' if s['FAIL'] else '✔'}  {s['PASS']} PASS · {s['FAIL']} FAIL "
            f"· {s['BLOCKED']} BLOCKED  (of {s['total']})",
            f"{out['kind'].title()} cover. Positive = must be Authentic; negative = must be "
            f"detected. Click a row for its file and steps.", pol)
        self.table.set_rows(out["rows"])
        self.ev_btn.configure(state="normal")
        self.app.after_run()

    def _error(self, exc, tb):
        self.run_btn.configure(state="normal")
        self.banner.show_text("✘  ERROR", f"{type(exc).__name__}: {exc}", "warning")

    def _on_row(self, row):
        if row.get("file"):
            self.preview.show(row["file"])
        else:
            self.preview.clear()
        if row["expected"] == "Rejected":
            self.case_banner.show_text(
                f"{'✔' if row['result'] == 'PASS' else '✘'}  {row['actual'].upper()}  "
                "—  NEGATIVE CASE", "Capacity check refused the oversized payload.",
                "negative")
        elif row["result"] != "PASS":
            blocked = row["result"] == "BLOCKED"
            icon = "…" if blocked else "✘"
            reason = row["note"] or "Actual verdict differs from the expected one."
            self.case_banner.show_text(
                f"{icon}  {row['result']}: got {row['actual']}, expected {row['expected']}",
                reason, "warning" if blocked else "negative")
        else:
            self.case_banner.show(row["actual"], row["provisional"],
                                  f"Expected {row['expected']} → PASS")
        self.steps.set_steps(row["steps"])


class ACW1App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Steganographic Verification Tool - ACW1")
        self.geometry("1320x900")
        self.minsize(1100, 760)

        header = ttk.Frame(self, padding=(10, 6))
        header.pack(fill="x")
        ttk.Label(header, text="Steganographic Image & Audio Verification",
                  font=("Helvetica", 16, "bold")).pack(side="left")
        self.status_summary = ttk.Label(header, text="")
        self.status_summary.pack(side="right")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)
        self.protect_tab = ProtectTab(self.notebook, self)
        self.verify_tab = VerifyTab(self.notebook, self)
        self.cases_tab = CasesTab(self.notebook, self)
        for tab, text in ((self.protect_tab, "1. Protect"), (self.verify_tab, "2. Verify"),
                          (self.cases_tab, "3. Test Cases (FR11)")):
            self.notebook.add(tab, text=text)
        self._update_summary()

    def after_run(self):
        self._update_summary()

    def _update_summary(self):
        s = pipeline.fr_status()
        done = sum(1 for x in s if x["status"] == "done")
        pending = [x["fr"] for x in s if x["status"] != "done"]
        self.status_summary.configure(
            text=f"{done}/{len(s)} FRs implemented · pending/partial: {', '.join(pending)}")


if __name__ == "__main__":
    ACW1App().mainloop()
