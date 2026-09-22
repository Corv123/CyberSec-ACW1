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
from tkinter.scrolledtext import ScrolledText

import gui_pipeline as pipeline
from gui_components import (
    BeforeAfterPreview, CaseTable, DataTable, FileField, JsonView,
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


def _scrollable_results_column(parent):
    """Same slot as _results_column, but scrollable -- for tabs (like Innovation)
    whose stacked result panels can run taller than the window. The mouse-wheel
    handler is bound globally (not just while hovering the bare canvas
    background) and guarded by winfo_ismapped(), since this column is fully
    tiled with child widgets (tables, text boxes, buttons) that would otherwise
    swallow the wheel event before an Enter/Leave-based binding ever fires."""
    container = ttk.Frame(parent, padding=(4, 8, 8, 8))
    container.grid(row=0, column=1, sticky="nsew")
    parent.columnconfigure(1, weight=1)
    parent.rowconfigure(0, weight=1)
    container.columnconfigure(0, weight=1)
    container.rowconfigure(0, weight=1)

    canvas = tk.Canvas(container, highlightthickness=0)
    vsb = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    canvas.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")

    inner = ttk.Frame(canvas)
    window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

    def _resize_scrollregion(_event=None):
        canvas.configure(scrollregion=canvas.bbox("all"))

    def _resize_inner_width(event):
        canvas.itemconfig(window_id, width=event.width)

    inner.bind("<Configure>", _resize_scrollregion)
    canvas.bind("<Configure>", _resize_inner_width)

    def _wheel(event):
        if canvas.winfo_ismapped():
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    canvas.bind_all("<MouseWheel>", _wheel)
    canvas.bind_all("<Button-4>", lambda _e: canvas.winfo_ismapped() and canvas.yview_scroll(-3, "units"))
    canvas.bind_all("<Button-5>", lambda _e: canvas.winfo_ismapped() and canvas.yview_scroll(3, "units"))

    return inner


class ProtectTab(ttk.Frame):
    """Cover + message + parameters -> signed stego file."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app, self.result = app, None
        left, right = _controls_column(self), _results_column(self)

        self.cover = FileField(left, "Cover file (PNG image / WAV audio / AVI video)", on_change=self._on_cover)
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

        self.file = FileField(left, "File to verify (PNG / WAV / AVI)", on_change=self._on_file)
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

        self.cover = FileField(left, "Cover file (PNG image / WAV audio / AVI video)",
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


def _zoomed_attack_comparison(cover_path, stego_path, tmp_dir, pad=6, target=360, max_zoom=24):
    """Crop cover/stego to the region that actually changed (or the whole
    image, if nothing did), upscale with NEAREST so individual pixels stay
    crisp blocks instead of blurring away, and draw a red box around every
    changed pixel on the diff. Built specifically for the attack-sim's tiny
    (48x48) throwaway covers, where a single flipped bit is otherwise
    invisible: MediaPreview's thumbnail() only ever shrinks an image to fit
    its canvas, never enlarges one, so a 48x48 image renders as a small
    postage stamp with mostly empty canvas around it. Returns
    (before_path, after_path, diff_path, changed_count) or None if the two
    images aren't directly comparable (different sizes, unreadable, ...).
    """
    from PIL import Image, ImageDraw

    try:
        a = Image.open(cover_path).convert("RGB")
        b = Image.open(stego_path).convert("RGB")
    except Exception:
        return None
    if a.size != b.size:
        return None
    w, h = a.size
    pa, pb = a.load(), b.load()
    changed = [(x, y) for y in range(h) for x in range(w) if pa[x, y] != pb[x, y]]

    if changed:
        xs, ys = [p[0] for p in changed], [p[1] for p in changed]
        x0, x1 = max(0, min(xs) - pad), min(w, max(xs) + pad + 1)
        y0, y1 = max(0, min(ys) - pad), min(h, max(ys) + pad + 1)
    else:
        x0, y0, x1, y1 = 0, 0, w, h

    crop_a, crop_b = a.crop((x0, y0, x1, y1)), b.crop((x0, y0, x1, y1))
    cw, ch = crop_b.size
    zoom = max(4, min(max_zoom, target // max(cw, ch, 1)))

    def upscale(im):
        return im.resize((cw * zoom, ch * zoom), Image.NEAREST)

    before_zoom, after_zoom, diff_zoom = upscale(crop_a), upscale(crop_b), upscale(crop_b)
    draw = ImageDraw.Draw(diff_zoom)
    box_w = max(1, zoom // 4)
    for (x, y) in changed:
        rx, ry = (x - x0) * zoom, (y - y0) * zoom
        draw.rectangle([rx, ry, rx + zoom - 1, ry + zoom - 1], outline=(255, 0, 0), width=box_w)

    stem = Path(stego_path).stem
    before_path = Path(tmp_dir) / f"{stem}_zoom_before.png"
    after_path = Path(tmp_dir) / f"{stem}_zoom_after.png"
    diff_path = Path(tmp_dir) / f"{stem}_zoom_diff.png"
    before_zoom.save(before_path, format="PNG")
    after_zoom.save(after_path, format="PNG")
    diff_zoom.save(diff_path, format="PNG")
    return str(before_path), str(after_path), str(diff_path), len(changed)


class InnovationTab(ttk.Frame):
    """FR13 -- Person3's start-location innovation write-up + live bias evidence."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        left, right = _controls_column(self), _scrollable_results_column(self)

        ttk.Label(left, text="Start location innovation (FR7 / FR13)",
                 font=("Helvetica", 11, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(left, text="derive_start_location() stretches the shared seed with "
                             "PBKDF2-HMAC-SHA256, then reduces it to a start index by "
                             "rejection sampling instead of naive modulo, to avoid "
                             "structural bias. The demo below proves that empirically "
                             "with a chi-square goodness-of-fit test.",
                 wraplength=310, foreground="#555").pack(fill="x", pady=(0, 8))

        demo = ttk.LabelFrame(left, text="Bias demo: rejection sampling vs naive modulo",
                              padding=6)
        demo.pack(fill="x")
        row = ttk.Frame(demo)
        row.pack(fill="x")
        ttk.Label(row, text="Upper bound:").grid(row=0, column=0, sticky="w")
        self.upper = tk.IntVar(value=7)
        tk.Spinbox(row, from_=3, to=97, textvariable=self.upper, width=6
                  ).grid(row=0, column=1, sticky="w", padx=(4, 0))
        ttk.Label(row, text="Trials:").grid(row=1, column=0, sticky="w")
        self.trials = tk.IntVar(value=20000)
        tk.Spinbox(row, from_=1000, to=200000, increment=1000, textvariable=self.trials,
                  width=8).grid(row=1, column=1, sticky="w", padx=(4, 0))
        ttk.Label(demo, text="Upper is deliberately awkward (not a power of two, e.g. 7) "
                             "so naive modulo's bias shows up clearly.",
                 wraplength=290, foreground="#555").pack(fill="x", pady=(4, 0))

        self.run_btn = ttk.Button(left, text="▶  Run chi-square bias demo", command=self.run)
        self.run_btn.pack(fill="x", pady=(8, 2))
        self.progress = ttk.Progressbar(left, mode="indeterminate")
        self.progress.pack(fill="x")

        ttk.Separator(left, orient="horizontal").pack(fill="x", pady=14)

        ttk.Label(left, text="Attack simulation innovation (FR10 / FR13)",
                 font=("Helvetica", 11, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(left, text="generate_verdict() drives the six required verdicts from "
                             "extraction/signature/hash results. This runs REAL attacks "
                             "(tampering, wrong-key signing, wrong-start-location "
                             "extraction, replay, substitution) against throwaway cover "
                             "images generated on the fly -- plus a couple of fast "
                             "logic-only checks -- and verifies each produces the "
                             "expected verdict. Files are written to your OS temp "
                             "directory, never into this project.",
                 wraplength=310, foreground="#555").pack(fill="x", pady=(0, 8))

        self.verdict_run_btn = ttk.Button(left, text="▶  Run attack simulation",
                                          command=self.run_verdict_check)
        self.verdict_run_btn.pack(fill="x", pady=(0, 2))
        self.verdict_progress = ttk.Progressbar(left, mode="indeterminate")
        self.verdict_progress.pack(fill="x")

        write_frame = ttk.LabelFrame(right, text="explain_security() -- FR13 write-up",
                                     padding=4)
        write_frame.pack(fill="both")
        self.writeup = JsonView(write_frame, height=9)
        self.writeup.pack(fill="both", expand=True)
        self._load_writeup()

        result_frame = ttk.LabelFrame(right, text="Bias demo result", padding=4)
        result_frame.pack(fill="both", expand=True, pady=(6, 0))
        self.banner = VerdictBanner(result_frame)
        self.banner.pack(fill="x")
        self.table = DataTable(result_frame, height=8)
        self.table.pack(fill="both", pady=(6, 0))
        self.breakdown = ScrolledText(result_frame, height=8, wrap="word", font=("Menlo", 11))
        self.breakdown.pack(fill="both", expand=True, pady=(6, 0))
        self.breakdown.configure(state="disabled")

        verdict_result_frame = ttk.LabelFrame(right, text="Attack simulation result",
                                              padding=4)
        verdict_result_frame.pack(fill="both", expand=True, pady=(6, 0))
        self.verdict_banner = VerdictBanner(verdict_result_frame)
        self.verdict_banner.pack(fill="x")
        self.verdict_table = CaseTable(verdict_result_frame, on_select=self._on_verdict_row,
                                       height=6)
        self.verdict_table.pack(fill="x", pady=(6, 4))
        ttk.Label(verdict_result_frame,
                 text="Click a scenario above to play back exactly what the attacker did and how "
                      "the pipeline caught it -- the changed region is cropped and zoomed so a "
                      "single flipped bit is actually visible.",
                 foreground="#555").pack(anchor="w", pady=(0, 4))
        verdict_detail = ttk.Frame(verdict_result_frame)
        verdict_detail.pack(fill="both", expand=True)
        self.verdict_preview = BeforeAfterPreview(verdict_detail, width=190, height=170)
        self.verdict_preview.pack(side="left", anchor="n")
        verdict_steps_frame = ttk.Frame(verdict_detail)
        verdict_steps_frame.pack(side="left", fill="both", expand=True, padx=(8, 0))
        ttk.Label(verdict_steps_frame, text="Attack playback",
                 font=("Helvetica", 10, "bold")).pack(anchor="w")
        self.verdict_steps = StepList(verdict_steps_frame, height=7)
        self.verdict_steps.pack(fill="both", expand=True)

    def _load_writeup(self):
        status, value = pipeline.explain_start_location()
        self.writeup.set_data(value if status == "ok" else f"({status.upper()}) {value}")

    def run(self):
        try:
            upper = int(self.upper.get())
            trials = int(self.trials.get())
        except (tk.TclError, ValueError):
            messagebox.showwarning("Innovation", "Upper bound and trials must be whole numbers.")
            return
        self.run_btn.configure(state="disabled")
        self.progress.start(12)
        self.banner.show_text("Running…", "", "idle")
        run_async(self, lambda _p: pipeline.run_start_location_bias_demo(upper, trials),
                 self._done, self._error)

    def _done(self, result):
        self.run_btn.configure(state="normal")
        self.progress.stop()
        status, value = result
        if status != "ok":
            self._error(RuntimeError(value), "")
            return
        rs, nv = value["rejection_sampling"], value["naive_modulo"]
        as_expected = rs["uniform"] and not nv["uniform"]
        self.banner.show_text(
            "✔  Rejection sampling uniform, naive modulo biased -- as expected" if as_expected
            else "!  See breakdown below",
            f"chi-square: rejection sampling = {rs['chi_square']}, naive modulo = "
            f"{nv['chi_square']}  (critical value at 5%: {value['critical_value_5pct']})",
            "positive" if as_expected else "warning")
        rows = [{"bucket": i, "rejection sampling": rs["counts"][i],
                "naive modulo": nv["counts"][i], "expected": value["expected_per_slot"]}
               for i in range(value["upper"])]
        self.table.set_rows(rows)
        self._set_breakdown(pipeline.describe_start_location_bias_demo(value))

    def _error(self, exc, _tb):
        self.run_btn.configure(state="normal")
        self.progress.stop()
        self.banner.show_text("✘  ERROR", f"{type(exc).__name__}: {exc}", "warning")
        self._set_breakdown("")

    def _set_breakdown(self, text):
        self.breakdown.configure(state="normal")
        self.breakdown.delete("1.0", "end")
        self.breakdown.insert("1.0", text)
        self.breakdown.configure(state="disabled")

    def run_verdict_check(self):
        self.verdict_run_btn.configure(state="disabled")
        self.verdict_progress.start(12)
        self.verdict_banner.show_text("Running…", "", "idle")
        run_async(self, lambda _p: pipeline.run_attack_simulation(),
                 self._verdict_done, self._verdict_error)

    def _verdict_done(self, result):
        self.verdict_run_btn.configure(state="normal")
        self.verdict_progress.stop()
        status, rows = result
        if status != "ok":
            self._verdict_error(RuntimeError(rows), "")
            return
        passed = sum(1 for r in rows if r["result"] == "PASS")
        all_pass = passed == len(rows)
        self.verdict_banner.show_text(
            f"✔  {passed}/{len(rows)} scenarios PASS" if all_pass
            else f"!  {passed}/{len(rows)} scenarios PASS -- see table below",
            "Real tampering, wrong-key, wrong-start-location, replay and substitution "
            "attacks run against throwaway files, plus a couple of fast logic-only checks.",
            "positive" if all_pass else "warning")
        self.verdict_table.set_rows(rows)
        self.verdict_preview.show(summary="Click a scenario above to see its files.")
        self.verdict_steps.set_steps([])

    def _verdict_error(self, exc, _tb):
        self.verdict_run_btn.configure(state="normal")
        self.verdict_progress.stop()
        self.verdict_banner.show_text("✘  ERROR", f"{type(exc).__name__}: {exc}", "warning")

    def _on_verdict_row(self, row):
        self.verdict_steps.set_steps(row.get("steps", []))
        cover, stego = row.get("cover"), row.get("file")
        if not (cover and stego and Path(cover).is_file() and Path(stego).is_file()):
            self.verdict_preview.show(summary=row.get("note", "") or
                                      "No image for this scenario -- decision-logic check only.")
            return
        note = row.get("note", "")
        try:
            result = _zoomed_attack_comparison(cover, stego, Path(stego).parent)
            if result is None:
                raise ValueError("images not directly comparable")
            before_zoom, after_zoom, diff_zoom, changed = result
            headline = (f"{changed:,} pixel(s) changed in the full image -- cropped and "
                        f"zoomed to the affected region." if changed
                        else "0 pixels changed -- same file both times, cropped view shown "
                             "at native size for reference.")
            self.verdict_preview.show(before_zoom, after_zoom, diff_zoom,
                                      f"{headline}\n{note}" if note else headline)
        except Exception as exc:
            self.verdict_preview.show(cover, stego, None,
                                      f"{note}\n(zoomed comparison unavailable: {exc})")


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
        self.innovation_tab = InnovationTab(self.notebook, self)
        for tab, text in ((self.protect_tab, "1. Protect"), (self.verify_tab, "2. Verify"),
                          (self.cases_tab, "3. Test Cases (FR11)"),
                          (self.innovation_tab, "4. Innovation (FR13)")):
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