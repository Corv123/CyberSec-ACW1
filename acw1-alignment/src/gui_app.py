"""
gui_app.py -- Person6's module (FR11 case demonstration, FR12 evidence/reproducibility)

Skeleton only -- this runs as-is (try `python src/gui_app.py`) but doesn't do
anything real yet. Wire in the other five modules as they become ready, and replace
the placeholder buttons with real file pickers, an LSB-depth selector, and
before/after previews (required by the mandatory scope in the spec).
"""

import tkinter as tk

# TODO: once the other modules have real implementations, import them:
# from crypto_utils import build_payload, sign_payload, load_private_key, load_public_key, ...
# from image_stego import embed_image, extract_image, check_capacity
# from audio_stego import embed_audio, extract_audio
# from start_location import derive_start_location
# from verdict import generate_verdict


class ACW1App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Steganographic Verification Tool - ACW1")
        self.geometry("600x420")

        tk.Label(self, text="Cover file:").pack(pady=10)
        tk.Button(self, text="Choose file...", command=self.choose_cover).pack()

        tk.Label(self, text="LSB depth (1-8):").pack(pady=10)
        self.lsb_slider = tk.Scale(self, from_=1, to=8, orient="horizontal")
        self.lsb_slider.pack()

        tk.Button(self, text="Protect (embed)", command=self.on_protect).pack(pady=10)
        tk.Button(self, text="Verify (extract)", command=self.on_verify).pack(pady=10)

        self.status_label = tk.Label(self, text="Ready.")
        self.status_label.pack(pady=20)

    def choose_cover(self):
        # TODO: tkinter.filedialog.askopenfilename(), then show a cover preview
        pass

    def on_protect(self):
        # TODO: crypto_utils.build_payload -> sign_payload -> pack, then
        # image_stego.embed_image or audio_stego.embed_audio depending on file type;
        # show a before/after comparison per the mandatory scope
        pass

    def on_verify(self):
        # TODO: extract -> unpack -> verify_signature / verify_hash -> generate_verdict;
        # display the verdict clearly
        pass


if __name__ == "__main__":
    ACW1App().mainloop()
