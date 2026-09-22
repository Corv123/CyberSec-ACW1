"""
gui_components.py -- Person6's reusable Tkinter widgets (FR11 / FR12)

Every widget takes plain data (dicts, or Step / RunResult from gui_pipeline) so any
teammate can drop one into a window for their own FR, e.g.:

    import tkinter as tk
    from gui_components import VerdictBanner, StepList, CaseTable, MediaPreview

    root = tk.Tk()
    banner = VerdictBanner(root); banner.pack(fill="x")
    banner.show("Tampered")                         # red NEGATIVE banner
    steps = StepList(root); steps.pack(fill="both", expand=True)
    steps.set_steps([{"fr": "FR9", "title": "Check cover hash", "status": "fail",
                      "detail": "hash mismatch"}])
    root.mainloop()

Widgets:
  VerdictBanner      big green / red / amber verdict (positive vs negative case)
  StepList           per-FR step results; selecting a row shows the full detail/error
  MediaPreview       image thumbnail, or audio waveform with Play/Stop
  BeforeAfterPreview cover vs stego vs difference map + stats
  CaseTable          positive/negative test-case table (expected vs actual)
  DataTable          generic table for a list of dicts (e.g. attack-simulation output)
  JsonView           read-only pretty JSON / text
  ParamsFrame        start mode (manual / FR7 seed), LSB depth, audio low-byte option
  FileField          label + entry + Browse
  run_async()        run slow work off the Tk thread, deliver the result back on it
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import traceback
import tkinter as tk
from dataclasses import asdict, is_dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from PIL import Image, ImageTk

import gui_pipeline as pipeline

GREEN, RED, AMBER, BLUE, GREY = "#1e7e34", "#c62828", "#b26a00", "#1565c0", "#6b6b6b"
POLARITY_COLOURS = {"positive": GREEN, "negative": RED, "warning": AMBER, "idle": GREY}
STATUS_LABELS = {
    "ok": ("✔ PASS", GREEN), "fail": ("✘ FAIL", RED), "pending": ("… PENDING", AMBER),
    "info": ("i INFO", BLUE), "skip": ("- SKIP", GREY),
}
RESULT_COLOURS = {"PASS": GREEN, "FAIL": RED, "BLOCKED": AMBER}
MEDIA_FILETYPES = [
    ("Media", "*.png *.wav *.avi *.mp4"),
    ("Images", "*.png *.bmp *.jpg *.jpeg"),
    ("WAV audio", "*.wav"),
    ("Video", "*.avi *.mp4 *.mov *.mkv"),
    ("All files", "*.*"),
]


def _as_dict(obj):
    return asdict(obj) if is_dataclass(obj) else dict(obj)


# ---------- threading ----------

def run_async(widget, work, on_done, on_error=None, on_progress=None):
    """Run work(progress) in a thread. on_done(result) / on_error(exc, tb) /
    on_progress(*args) are called back on the Tk thread (Tk is not thread-safe)."""
    q = queue.Queue()

    def target():
        try:
            q.put(("done", work(lambda *a: q.put(("progress", a)))))
        except Exception as exc:
            q.put(("error", exc, traceback.format_exc()))

    def poll():
        try:
            while True:
                item = q.get_nowait()
                if item[0] == "progress":
                    if on_progress:
                        on_progress(*item[1])
                elif item[0] == "done":
                    on_done(item[1])
                    return
                else:
                    (on_error or _show_error)(item[1], item[2])
                    return
        except queue.Empty:
            widget.after(100, poll)

    threading.Thread(target=target, daemon=True).start()
    widget.after(100, poll)


def _show_error(exc, tb):
    messagebox.showerror("Error", f"{type(exc).__name__}: {exc}\n\n{tb[-1500:]}")


def open_path(path):
    """Open a file or folder with the OS default app (Finder / Explorer)."""
    path = str(path)
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606 -- local file only
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


class AudioPlayer:
    """Minimal WAV playback without extra dependencies."""
    _proc = None

    @classmethod
    def play(cls, path):
        cls.stop()
        if sys.platform == "win32":
            import winsound
            winsound.PlaySound(str(path), winsound.SND_FILENAME | winsound.SND_ASYNC)
        elif sys.platform == "darwin":
            cls._proc = subprocess.Popen(["afplay", str(path)])
        else:
            cls._proc = subprocess.Popen(["aplay", "-q", str(path)])

    @classmethod
    def stop(cls):
        if sys.platform == "win32":
            import winsound
            winsound.PlaySound(None, 0)
        elif cls._proc and cls._proc.poll() is None:
            cls._proc.terminate()
        cls._proc = None


# ---------- verdict banner ----------

class VerdictBanner(tk.Frame):
    """Large coloured banner. show(verdict) picks colour + POSITIVE/NEGATIVE label."""

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=GREY, **kw)
        self.title = tk.Label(self, font=("Helvetica", 20, "bold"), fg="white", bg=GREY,
                              anchor="w", padx=14, pady=6)
        self.subtitle = tk.Label(self, font=("Helvetica", 12), fg="white", bg=GREY,
                                 anchor="w", justify="left", padx=14, wraplength=760)
        self.title.pack(fill="x")
        self.subtitle.pack(fill="x", pady=(0, 8))
        self.clear()

    def show_text(self, title, subtitle="", polarity="idle"):
        colour = POLARITY_COLOURS.get(polarity, GREY)
        for w in (self, self.title, self.subtitle):
            w.configure(bg=colour)
        self.title.configure(text=title)
        self.subtitle.configure(text=subtitle)

    def show(self, verdict, provisional=False, detail=""):
        pol = pipeline.polarity(verdict)
        icon = {"positive": "✔", "negative": "✘"}.get(pol, "!")
        case = {"positive": "POSITIVE CASE", "negative": "NEGATIVE CASE"}.get(pol, "CHECK INPUT")
        sub = detail
        if provisional:
            sub = (sub + "\n" if sub else "") + ("Provisional verdict from the GUI -- "
                                                 "verdict.generate_verdict() (FR10) is not implemented yet.")
        self.show_text(f"{icon}  {verdict.upper()}  —  {case}", sub, pol)

    def show_result(self, result):
        """Convenience for gui_pipeline.RunResult."""
        if result.action == "protect":
            if result.outcome == "Protected":
                self.show_text("✔  PROTECTED", "Signed payload embedded. Verify it on the "
                               "Verify tab with the same start location and LSB depth.", "positive")
            else:
                failed = next((s for s in result.steps if s.status == "fail"), None)
                self.show_text(f"✘  {result.outcome.upper()}",
                               failed.detail if failed else "", "negative")
        else:
            failed = next((s for s in result.steps if s.status == "fail"), None)
            self.show(result.outcome, result.provisional,
                      f"First failing step: {failed.fr} {failed.title}" if failed else "All checks passed.")

    def clear(self, text="No result yet"):
        self.show_text(text, "", "idle")


# ---------- step list ----------

class StepList(ttk.Frame):
    """Treeview of steps; the detail box shows the full message / error of the selected step."""

    def __init__(self, parent, height=8, **kw):
        super().__init__(parent, **kw)
        cols = ("fr", "step", "status")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=height)
        for c, text, width in zip(cols, ("FR", "Step", "Status"), (70, 330, 110)):
            self.tree.heading(c, text=text)
            self.tree.column(c, width=width, stretch=(c == "step"))
        for status, (_, colour) in STATUS_LABELS.items():
            self.tree.tag_configure(status, foreground=colour)
        self.detail = ScrolledText(self, height=5, wrap="word", font=("Menlo", 11))
        self.tree.pack(fill="both", expand=True)
        self.detail.pack(fill="x", pady=(4, 0))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self._steps = []

    def set_steps(self, steps):
        self._steps = [_as_dict(s) for s in steps]
        self.tree.delete(*self.tree.get_children())
        for i, s in enumerate(self._steps):
            label = STATUS_LABELS.get(s["status"], (s["status"], GREY))[0]
            self.tree.insert("", "end", iid=str(i), values=(s["fr"], s["title"], label),
                             tags=(s["status"],))
        # Surface the first failure automatically, else the last step.
        focus = next((i for i, s in enumerate(self._steps) if s["status"] == "fail"),
                     len(self._steps) - 1)
        if focus >= 0:
            self.tree.selection_set(str(focus))
            self.tree.see(str(focus))
        else:
            self._set_detail("")

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if sel:
            s = self._steps[int(sel[0])]
            self._set_detail(f"[{s['fr']}] {s['title']}\n{s['detail']}")

    def _set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def clear(self):
        self.set_steps([])


# ---------- media previews ----------

class MediaPreview(ttk.LabelFrame):
    """show(path) renders an image thumbnail or an audio waveform (+ Play/Stop)."""

    def __init__(self, parent, text="Preview", width=300, height=220, **kw):
        super().__init__(parent, text=text, **kw)
        self.w, self.h = width, height
        self.canvas = tk.Canvas(self, width=width, height=height, bg="#1b1b1b",
                                highlightthickness=0)
        self.canvas.pack()
        self.caption = ttk.Label(self, text="", wraplength=width, justify="left")
        self.caption.pack(fill="x")
        self.controls = ttk.Frame(self)
        ttk.Button(self.controls, text="▶ Play", command=self._play).pack(side="left")
        ttk.Button(self.controls, text="■ Stop", command=AudioPlayer.stop).pack(side="left")
        ttk.Button(self.controls, text="Open", command=lambda: self.path and open_path(self.path)
                   ).pack(side="left")
        self.path, self._photo = None, None
        self.clear()

    def clear(self, message="No file"):
        self.path = None
        self.canvas.delete("all")
        self.canvas.create_text(self.w // 2, self.h // 2, text=message, fill="#9e9e9e")
        self.caption.configure(text="")
        self.controls.pack_forget()

    def show(self, path, caption=None):
        self.canvas.delete("all")
        self.path = str(path)
        try:
            kind = pipeline.detect_kind(path)
            if kind == "image":
                self._show_image(path)
            elif kind == "video":
                self._show_video_frame(path)
            else:
                self._show_waveform(path)
            if caption is None:
                k, info, warnings = pipeline.inspect_media(path)
                caption = pipeline.describe_media(k, info) + "".join("\n⚠ " + w for w in warnings)
        except Exception as exc:
            self.canvas.create_text(self.w // 2, self.h // 2, width=self.w - 20, fill="#ff8a80",
                                    text=f"Cannot preview:\n{type(exc).__name__}: {exc}")
            caption = caption or ""
        self.caption.configure(text=f"{Path(path).name}\n{caption}")
        self.controls.pack(anchor="w")

    def _show_image(self, path):
        with Image.open(path) as im:
            im.draft("RGB", (self.w, self.h))
            im = im.convert("RGB")
            im.thumbnail((self.w, self.h))
        self._photo = ImageTk.PhotoImage(im)
        self.canvas.create_image(self.w // 2, self.h // 2, image=self._photo)

    def _show_video_frame(self, path):
        import video_stego
        im = video_stego.first_frame_rgb(path)
        im.thumbnail((self.w, self.h))
        self._photo = ImageTk.PhotoImage(im)
        self.canvas.create_image(self.w // 2, self.h // 2, image=self._photo)
        self.canvas.create_text(6, 6, anchor="nw", fill="#bdbdbd", text="frame 0")

    def _show_waveform(self, path):
        env, meta = pipeline.waveform_envelope(path, buckets=self.w)
        mid = self.h / 2
        self.canvas.create_line(0, mid, self.w, mid, fill="#424242")
        for x, (lo, hi) in enumerate(env[: self.w]):
            self.canvas.create_line(x, mid - hi * (mid - 4), x, mid - lo * (mid - 4) + 1,
                                    fill="#4fc3f7")
        self.canvas.create_text(6, 6, anchor="nw", fill="#bdbdbd",
                                text=f"{meta['duration_s']:.2f} s")

    def _play(self):
        if self.path and self.path.lower().endswith((".wav", ".wave")):
            try:
                AudioPlayer.play(self.path)
            except Exception as exc:
                messagebox.showerror("Playback", str(exc))


class BeforeAfterPreview(ttk.Frame):
    """Cover | Stego | Difference map (image) -- plus a one-line stats summary."""

    def __init__(self, parent, width=260, height=200, **kw):
        super().__init__(parent, **kw)
        self.before = MediaPreview(self, "Before (cover)", width, height)
        self.after = MediaPreview(self, "After (stego)", width, height)
        self.diff = MediaPreview(self, "Difference (changed = red)", width, height)
        for i, w in enumerate((self.before, self.after, self.diff)):
            w.grid(row=0, column=i, padx=3, sticky="n")
        self.stats = ttk.Label(self, text="", foreground=BLUE, wraplength=3 * width)
        self.stats.grid(row=1, column=0, columnspan=3, sticky="w", pady=2)

    def show(self, cover=None, stego=None, diff_image=None, summary=""):
        self.before.show(cover) if cover else self.before.clear()
        self.after.show(stego) if stego else self.after.clear("Not protected yet")
        if diff_image:
            self.diff.show(diff_image, caption="Changed pixels, enlarged so they stay visible")
        else:
            msg = "No comparison"
            if stego:
                low = str(stego).lower()
                if low.endswith((".wav", ".wave")):
                    msg = "Audio: see stats below"
                elif low.endswith((".avi", ".mp4", ".mov", ".mkv")):
                    msg = "Video: first-frame diff when available"
            self.diff.clear(msg)
        self.stats.configure(text=summary)


# ---------- tables ----------

class CaseTable(ttk.Frame):
    """Positive/negative test cases. on_select(row_dict) fires when a row is clicked."""

    COLS = (("case", "Case", 270), ("type", "Type", 80), ("expected", "Expected", 150),
            ("actual", "Actual", 170), ("result", "Result", 80), ("note", "Note", 220))

    def __init__(self, parent, on_select=None, height=11, **kw):
        super().__init__(parent, **kw)
        self.tree = ttk.Treeview(self, columns=[c for c, _, _ in self.COLS], show="headings",
                                 height=height)
        for c, text, width in self.COLS:
            self.tree.heading(c, text=text)
            self.tree.column(c, width=width, stretch=(c in ("case", "note")))
        for result, colour in RESULT_COLOURS.items():
            self.tree.tag_configure(result, foreground=colour)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.on_select, self.rows = on_select, []

    def set_rows(self, rows):
        self.rows = [dict(r) for r in rows]
        self.tree.delete(*self.tree.get_children())
        for i, r in enumerate(self.rows):
            pol = r.get("expected_polarity", pipeline.polarity(r.get("expected", "")))
            actual = r.get("actual", "") + (" *" if r.get("provisional") else "")
            icon = {"PASS": "✔ ", "FAIL": "✘ ", "BLOCKED": "… "}.get(r.get("result"), "")
            self.tree.insert("", "end", iid=str(i), tags=(r.get("result", ""),), values=(
                r.get("case", ""), "positive" if pol == "positive" else "negative",
                r.get("expected", ""), actual, icon + r.get("result", ""), r.get("note", "")))

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if sel and self.on_select:
            self.on_select(self.rows[int(sel[0])])


class DataTable(ttk.Frame):
    """Generic table for a list of dicts -- e.g. run_attack_simulation() results.
    A 'result'/'status' column with PASS/FAIL values is coloured automatically."""

    def __init__(self, parent, height=8, **kw):
        super().__init__(parent, **kw)
        self.tree = ttk.Treeview(self, show="headings", height=height)
        self.tree.pack(fill="both", expand=True)
        for result, colour in RESULT_COLOURS.items():
            self.tree.tag_configure(result, foreground=colour)

    def set_rows(self, rows):
        rows = [_as_dict(r) for r in rows]
        cols = list(dict.fromkeys(k for r in rows for k in r))
        self.tree.delete(*self.tree.get_children())
        self.tree.configure(columns=cols)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=140)
        for r in rows:
            tag = str(r.get("result", r.get("status", ""))).upper()
            self.tree.insert("", "end", values=[r.get(c, "") for c in cols], tags=(tag,))


class FRStatusBoard(DataTable):
    """FR1-FR13 status board. refresh() re-reads gui_pipeline.fr_status()."""

    def __init__(self, parent, **kw):
        super().__init__(parent, height=14, **kw)
        for status, colour in (("DONE", GREEN), ("PARTIAL", AMBER), ("PENDING", RED)):
            self.tree.tag_configure(status, foreground=colour)

    def refresh(self):
        self.set_rows([{"FR": s["fr"], "Requirement": s["title"], "Owner": s["owner"],
                        "status": s["status"].upper(), "Where": s["where"]}
                       for s in pipeline.fr_status()])
        self.tree.column("Where", width=380)


class JsonView(ScrolledText):
    def __init__(self, parent, height=8, **kw):
        super().__init__(parent, height=height, wrap="word", font=("Menlo", 11), **kw)
        self.configure(state="disabled")

    def set_data(self, data):
        text = data if isinstance(data, str) else json.dumps(data, indent=2, default=str)
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.insert("1.0", "" if data is None else text)
        self.configure(state="disabled")


# ---------- inputs ----------

class FileField(ttk.Frame):
    def __init__(self, parent, label, filetypes=MEDIA_FILETYPES, initial="", on_change=None, **kw):
        super().__init__(parent, **kw)
        ttk.Label(self, text=label).pack(anchor="w")
        row = ttk.Frame(self)
        row.pack(fill="x")
        self.var = tk.StringVar(value=str(initial))
        entry = ttk.Entry(row, textvariable=self.var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self._changed())
        ttk.Button(row, text="Browse…", command=self._browse).pack(side="left", padx=(4, 0))
        self.filetypes, self.on_change = filetypes, on_change

    def _browse(self):
        start = Path(self.var.get()).parent if self.var.get() else pipeline.ROOT / "samples"
        path = filedialog.askopenfilename(initialdir=str(start), filetypes=self.filetypes)
        if path:
            self.set(path)

    def _changed(self):
        if self.on_change and self.get():
            self.on_change(self.get())

    def get(self):
        return self.var.get().strip()

    def set(self, path):
        self.var.set(str(path))
        self._changed()


class ParamsFrame(ttk.LabelFrame):
    """Embedding parameters shared by protect, verify and the case suite.
    get() returns the dict gui_pipeline expects; set(params) pre-fills it."""

    def __init__(self, parent, text="Embedding parameters", **kw):
        super().__init__(parent, text=text, padding=6, **kw)
        self.mode = tk.StringVar(value="manual")
        self.start = tk.IntVar(value=100)
        self.seed = tk.StringVar(value="")
        self.lsb = tk.IntVar(value=2)
        self.low = tk.BooleanVar(value=False)
        self.frame_step = tk.IntVar(value=1)
        self.use_dct = tk.BooleanVar(value=False)

        ttk.Radiobutton(self, text="Manual start location", variable=self.mode, value="manual",
                        command=self._sync).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(self, text="Start index:").grid(row=1, column=0, sticky="w", padx=(18, 0))
        self.start_box = tk.Spinbox(self, from_=0, to=10 ** 9, textvariable=self.start, width=12)
        self.start_box.grid(row=1, column=1, sticky="w")
        ttk.Radiobutton(self, text="Derive from seed (FR7)", variable=self.mode, value="derive",
                        command=self._sync).grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Label(self, text="Seed / passphrase:").grid(row=3, column=0, sticky="w", padx=(18, 0))
        self.seed_entry = ttk.Entry(self, textvariable=self.seed, width=18)
        self.seed_entry.grid(row=3, column=1, sticky="w")
        self.fr7_note = ttk.Label(self, text="", foreground=AMBER, wraplength=280)
        self.fr7_note.grid(row=4, column=0, columnspan=2, sticky="w")

        self.depth_label = ttk.Label(self, text="LSB depth (1-8):")
        self.depth_label.grid(row=5, column=0, sticky="w", pady=(6, 0))
        lsb_row = ttk.Frame(self)
        lsb_row.grid(row=5, column=1, sticky="w", pady=(6, 0))
        tk.Scale(lsb_row, from_=1, to=8, orient="horizontal", variable=self.lsb, length=120,
                 showvalue=True).pack(side="left")
        self.low_check = ttk.Checkbutton(self, text="Audio: low byte only (less distortion)",
                                         variable=self.low)
        self.low_check.grid(row=6, column=0, columnspan=2, sticky="w")

        self.dct_check = ttk.Checkbutton(
            self,
            text="Image: use DCT embedding (mid-band 8×8 coeffs)",
            variable=self.use_dct,
            command=self._on_dct_toggle,
        )
        self.dct_check.grid(row=7, column=0, columnspan=2, sticky="w", pady=(4, 0))
        self.dct_note = ttk.Label(
            self,
            text="Off = classic LSB. On = Discrete Cosine Transform (optional).",
            foreground="#555", wraplength=280)
        self.dct_note.grid(row=8, column=0, columnspan=2, sticky="w")

        self.frame_step_label = ttk.Label(self, text="Video frame step:")
        self.frame_step_label.grid(row=9, column=0, sticky="w", pady=(6, 0))
        self.frame_step_box = tk.Spinbox(
            self, from_=1, to=60, textvariable=self.frame_step, width=8)
        self.frame_step_box.grid(row=9, column=1, sticky="w", pady=(6, 0))
        self.frame_step_note = ttk.Label(
            self,
            text="1 = every frame; 2 = every 2nd frame (selected-frame embedding).",
            foreground="#555", wraplength=280)
        self.frame_step_note.grid(row=10, column=0, columnspan=2, sticky="w")

        self._sync()
        self.set_kind(None)

    def _on_dct_toggle(self):
        if self.use_dct.get():
            self.depth_label.configure(text="DCT coeff depth (1-8):")
        else:
            self.depth_label.configure(text="LSB depth (1-8):")

    def _sync(self):
        derive = self.mode.get() == "derive"
        self.seed_entry.configure(state="normal" if derive else "disabled")
        pending = pipeline.is_stub(pipeline.start_location.derive_start_location)
        self.fr7_note.configure(text="FR7 pending (Person3): the manual start index is used "
                                     "as a fallback." if derive and pending else "")

    def set_kind(self, kind):
        self.low_check.configure(state="normal" if kind == "audio" else "disabled")
        if kind != "audio":
            self.low.set(False)

        image = kind == "image"
        self.dct_check.configure(state="normal" if image else "disabled")
        if not image:
            self.use_dct.set(False)
        self._on_dct_toggle()

        video = kind == "video"
        state = "normal" if video else "disabled"
        self.frame_step_label.configure(state=state)
        self.frame_step_box.configure(state=state)
        self.frame_step_note.configure(
            text=("1 = every frame; 2 = every 2nd frame (selected-frame embedding)."
                  if video else "Frame step applies only when the cover is video."))
        if not video:
            self.frame_step.set(1)

    def get(self) -> dict:
        try:
            start = int(self.start.get())
        except (tk.TclError, ValueError):
            raise ValueError("Start index must be a whole number.")
        try:
            frame_step = int(self.frame_step.get())
        except (tk.TclError, ValueError):
            raise ValueError("Frame step must be a whole number >= 1.")
        if frame_step < 1:
            raise ValueError("Frame step must be >= 1.")
        return pipeline.default_params(
            start_mode=self.mode.get(),
            start=start,
            seed=self.seed.get(),
            lsb_depth=int(self.lsb.get()),
            low_byte_only=bool(self.low.get()),
            frame_step=frame_step,
            use_dct=bool(self.use_dct.get()),
        )

    def set(self, params: dict):
        self.mode.set(params.get("start_mode", "manual"))
        self.start.set(int(params.get("start", 0)))
        self.seed.set(params.get("seed", ""))
        self.lsb.set(int(params.get("lsb_depth", 2)))
        self.low.set(bool(params.get("low_byte_only")))
        self.frame_step.set(int(params.get("frame_step", 1)))
        self.use_dct.set(bool(params.get("use_dct")))
        self._on_dct_toggle()
        self._sync()
