"""
Aplikasi Desktop Caesar Cipher & Cryptanalysis Toolkit
Perspektif: Cyber Security & Cryptography Evaluation

Versi GUI (CustomTkinter) dari aplikasi CLI yang sudah ada.
  - TIDAK mengubah engine kriptografi (caesar_cipher.py, cryptanalysis.py) -> di-reuse.
  - TIDAK mengubah CLI (app.py) -> tetap berjalan apa adanya.
  - Mengimpor ADVISORY_TEXT dari app.py agar laporan advisory tidak diduplikasi.

Menjalankan:
    pip install customtkinter
    python desktop_app.py
"""

import time
import tkinter.filedialog as filedialog

import customtkinter as ctk

from caesar_cipher import CaesarCipher
from cryptanalysis import CaesarBreaker
from app import ADVISORY_TEXT, _transpose_text, TRANSPOSITION_CLASSES
from transposition import RouteCipher


# ---------------------------------------------------------------------------
# Tema & Konstanta Tampilan
# ---------------------------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Palet sinyal keamanan (warna teks status)
COLOR_DANGER = "#FF5757"     # merah - identitas / kritis
COLOR_WARN = "#FF9F40"       # oranye - ROT13
COLOR_WEAK = "#FFD24D"        # kuning - lemah
COLOR_OK = "#4ADE80"         # hijau - info sukses
COLOR_MUTED = "#8A8F98"      # abu-abu - netral

FONT_MONO = ("Consolas", 14)
FONT_MONO_SMALL = ("Consolas", 12)
FONT_TITLE = ("Segoe UI", 22, "bold")
FONT_SUBTITLE = ("Segoe UI", 12)
FONT_BODY = ("Segoe UI", 12)
FONT_BODY_BOLD = ("Segoe UI", 12, "bold")


def key_strength(norm_k: int):
    """
    Indikator kekuatan kunci Caesar (menegaskan pesan advisory keamanan).
    Mengembalikan (label, warna).
    """
    if norm_k == 0:
        return ("IDENTITAS - tidak ada pergeseran, teks tidak berubah", COLOR_DANGER)
    if norm_k == 13:
        return ("ROT13 - kunci paling lemah (huruf dipetakan bolak-balik)", COLOR_WARN)
    return ("Lemah - keyspace Caesar hanya 25, dapat dibobol <0.0001 dtk via brute-force", COLOR_WEAK)


# ---------------------------------------------------------------------------
# Field parameter transposisi (dipakai bersama: tab "Transposisi" & "Operasi File")
# ---------------------------------------------------------------------------

def _rebuild_key_fields(container, store):
    """
    Bangun ulang field parameter algoritma transposisi di dalam `container`.
    `store` harus memuat:
      algo_var       -> ctk.StringVar berisi nama algoritma
      on_change      -> callback (dipanggil tiap entri/kontrol berubah & setelah rebuild)
      widgets        -> dict; diisi pasangan nama -> widget (entry / OptionMenu route).
    Setiap CTkEntry memakai StringVar yang dibaca lewat key "<nama>_var",
    sehingga tidak ada getter widget yang rusak saat rebuild.
    """
    for child in container.winfo_children():
        child.destroy()
    widgets = {}
    algo = store["algo_var"].get()
    on_change = store["on_change"]

    def add(label_text, name, width=120, default=""):
        ctk.CTkLabel(container, text=label_text, font=FONT_BODY).pack(side="left", padx=(0, 6))
        var = ctk.StringVar(value=default)
        entry = ctk.CTkEntry(container, width=width, font=FONT_MONO, textvariable=var)
        entry.bind("<KeyRelease>", lambda _e: on_change())
        entry.pack(side="left", padx=(0, 12))
        widgets[name] = entry
        widgets[name + "_var"] = var

    if algo == "railfence":
        add("Jumlah Rel (Rails):", "rails", default="3")
    elif algo == "route":
        add("Lebar Grid:", "width", default="5")
        ctk.CTkLabel(container, text="Rute:", font=FONT_BODY).pack(side="left", padx=(0, 6))
        route_menu = ctk.CTkOptionMenu(container, values=list(RouteCipher.ROUTE_CHOICES),
                                       width=150, command=lambda _r: on_change())
        route_menu.set("spiral_tl")
        route_menu.pack(side="left", padx=(0, 12))
        widgets["route_menu"] = route_menu
    elif algo in ("columnar", "myszkowski"):
        default = "ZEBRA" if algo == "columnar" else "TOMATO"
        add("Keyword:", "keyword", default=default)
    else:  # double
        add("Keyword 1:", "key1", default="ZEBRA")
        add("Keyword 2:", "key2", default="KRIPTO")

    store["widgets"] = widgets
    on_change()


def _collect_trans_params(store):
    """Kumpulkan parameter (dict kwargs cipher) dari store field transposisi."""
    algo = store["algo_var"].get()
    w = store["widgets"]

    def _int(var, default):
        raw = var.get().strip()
        return int(raw) if raw else default

    if algo == "railfence":
        return {"rails": _int(w["rails_var"], 3)}
    if algo == "route":
        return {"width": _int(w["width_var"], 5), "route": w["route_menu"].get()}
    if algo in ("columnar", "myszkowski"):
        return {"keyword": w["keyword_var"].get()}
    return {"key1": w["key1_var"].get(), "key2": w["key2_var"].get()}


# ---------------------------------------------------------------------------
# Aplikasi Utama
# ---------------------------------------------------------------------------
class CaesarCipherApp(ctk.CTk):
    """Jendela utama aplikasi desktop."""

    def __init__(self):
        super().__init__()

        self.title("Cyber Security - Caesar Cipher & Cryptanalysis Toolkit")
        self.geometry("1120x760")
        self.minsize(960, 680)

        # Layout utama: header (atas) | tabview (tengah, ekspansi) | history (bawah)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_tabview()
        self._build_history_panel()

        # Sinkronisasi slider<->entry & live preview awal untuk tab enkripsi/dekripsi
        self._sync_encrypt()
        self._sync_decrypt()

    # ----------------------- Komponen umum -----------------------
    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=20, pady=(18, 6), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header,
            text="CYBER SECURITY  ·  CAESAR CIPHER & CRYPTANALYSIS TOOLKIT",
            font=FONT_TITLE, text_color=COLOR_OK,
        )
        title.grid(row=0, column=0, sticky="w")
        sub = ctk.CTkLabel(
            header,
            text="Desktop Edition (CustomTkinter)  ·  Enkripsi · Dekripsi · Kriptanalisis · Advisory",
            font=FONT_SUBTITLE, text_color=COLOR_MUTED,
        )
        sub.grid(row=1, column=0, sticky="w", padx=2)

    def _build_tabview(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, padx=20, pady=6, sticky="nsew")

        self.tabs.add("Enkripsi")
        self.tabs.add("Dekripsi")
        self.tabs.add("Operasi File")
        self.tabs.add("Brute Force")
        self.tabs.add("Frequency Analysis")
        self.tabs.add("Transposisi")
        self.tabs.add("Advisory")

        self._build_encrypt_tab(self.tabs.tab("Enkripsi"))
        self._build_decrypt_tab(self.tabs.tab("Dekripsi"))
        self._build_file_tab(self.tabs.tab("Operasi File"))
        self._build_bruteforce_tab(self.tabs.tab("Brute Force"))
        self._build_freq_tab(self.tabs.tab("Frequency Analysis"))
        self._build_transposition_tab(self.tabs.tab("Transposisi"))
        self._build_advisory_tab(self.tabs.tab("Advisory"))

    def _build_history_panel(self):
        frame = ctk.CTkFrame(self)
        frame.grid(row=2, column=0, padx=20, pady=(6, 18), sticky="ew")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Riwayat Operasi Sesi", font=FONT_BODY_BOLD).grid(
            row=0, column=0, sticky="w", padx=12, pady=(8, 2)
        )
        self.history_box = ctk.CTkTextbox(frame, height=90, font=FONT_MONO_SMALL,
                                          state="disabled", wrap="word")
        self.history_box.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))

    def _log(self, tag: str, message: str):
        """Catat operasi ke panel history (terbaru di puncak, hanya sesi, tidak persisten)."""
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {tag}: {message}"
        lines = getattr(self, "_history_lines", [])
        lines.insert(0, line)
        self._history_lines = lines
        self._write_box(self.history_box, "\n".join(lines))

    def _copy(self, text: str, source_label: str = "Hasil"):
        """Salin teks ke clipboard sistem lalu catat di history."""
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._log("CLIPBOARD", f"{source_label} disalin ({len(text)} karakter)")
        except Exception as exc:
            self._log("ERROR", f"Gagal menyalin: {exc}")

    # ----------------------- Tab 1: Enkripsi Teks -----------------------
    def _build_encrypt_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(parent, text="Plaintext", font=FONT_BODY_BOLD).grid(
            row=0, column=0, sticky="w", padx=4, pady=(4, 0))
        self.enc_input = ctk.CTkTextbox(parent, height=120, font=FONT_MONO, wrap="word")
        self.enc_input.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        self.enc_input.insert("0.0", "PESAN SANGAT RAHASIA")
        self.enc_input.bind("<KeyRelease>", lambda _e: self._sync_encrypt())

        # Baris kontrol kunci
        keyrow = ctk.CTkFrame(parent, fg_color="transparent")
        keyrow.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        keyrow.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(keyrow, text="Kunci (k):", font=FONT_BODY).grid(row=0, column=0, padx=(0, 8))
        self.enc_key_var = ctk.StringVar(value="3")
        self.enc_key_entry = ctk.CTkEntry(keyrow, textvariable=self.enc_key_var,
                                          width=70, font=FONT_MONO)
        self.enc_key_entry.grid(row=0, column=1, sticky="w")
        self.enc_key_entry.bind("<KeyRelease>", lambda _e: self._sync_encrypt())

        ctk.CTkLabel(keyrow, text="Slider 0-25:", font=FONT_BODY).grid(row=0, column=2, padx=(16, 8))
        self.enc_slider = ctk.CTkSlider(keyrow, from_=0, to=25, number_of_steps=25,
                                        width=240, command=self._on_enc_slider)
        self.enc_slider.set(3)
        self.enc_slider.grid(row=0, column=3, sticky="w")

        self.enc_norm = ctk.CTkLabel(keyrow, text="k = 3  (normalized: 3 % 26 = 3)",
                                     font=FONT_MONO_SMALL, text_color=COLOR_MUTED)
        self.enc_norm.grid(row=0, column=4, padx=(16, 0))

        self.enc_strength = ctk.CTkLabel(keyrow, text="", font=FONT_BODY_BOLD)
        self.enc_strength.grid(row=1, column=0, columnspan=5, sticky="w", padx=0, pady=(4, 0))

        # Output
        ctk.CTkLabel(parent, text="Ciphertext (live preview)", font=FONT_BODY_BOLD).grid(
            row=3, column=0, sticky="sw", padx=4, pady=(8, 0))
        outframe = ctk.CTkFrame(parent)
        outframe.grid(row=4, column=0, sticky="nsew", padx=4, pady=(4, 4))
        outframe.grid_columnconfigure(0, weight=1)
        outframe.grid_rowconfigure(0, weight=1)
        self.enc_output = ctk.CTkTextbox(outframe, height=140, font=FONT_MONO,
                                        wrap="word", state="disabled")
        self.enc_output.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        btns = ctk.CTkFrame(parent, fg_color="transparent")
        btns.grid(row=5, column=0, sticky="w", padx=4)
        ctk.CTkButton(btns, text="Salin Ciphertext",
                      command=lambda: self._copy(self._read_box(self.enc_output), "Ciphertext")).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="Salin & Catat Log", fg_color="#2B6E2F", hover_color="#1F5A22",
                      command=self._enc_log).pack(side="left")

    def _on_enc_slider(self, value):
        k = int(round(value))
        if self.enc_key_var.get() != str(k):
            self.enc_key_var.set(str(k))
        self._sync_encrypt()

    def _sync_encrypt(self):
        try:
            raw_k = self.enc_key_var.get().strip()
            k = int(raw_k) if raw_k else 3
        except ValueError:
            self._set_strength(self.enc_strength, 3, True)
            self._write_box(self.enc_output, "[Kunci tidak valid - masukkan bilangan bulat]")
            return
        # sinkronkan slider agar mencerminkan normalized key (0..25)
        try:
            self.enc_slider.set(k % 26)
        except Exception:
            pass

        text = self.enc_input.get("0.0", "end").rstrip("\n")
        result = CaesarCipher.encrypt(text, k)
        self._write_box(self.enc_output, result)
        norm = k % 26
        self.enc_norm.configure(text=f"k = {k}  (normalized: {k} % 26 = {norm})")
        self._set_strength(self.enc_strength, norm)
        self._last_enc = (text, k, result)

    def _enc_log(self):
        text, k, result = getattr(self, "_last_enc", ("", 3, ""))
        self._log("ENKRIPSI", f'k={k} "{text[:40]}{"..." if len(text) > 40 else ""}" -> "{result[:40]}{"..." if len(result) > 40 else ""}"')
        self._copy(result, "Ciphertext")

    # ----------------------- Tab 2: Dekripsi Teks -----------------------
    def _build_decrypt_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(parent, text="Ciphertext", font=FONT_BODY_BOLD).grid(
            row=0, column=0, sticky="w", padx=4, pady=(4, 0))
        self.dec_input = ctk.CTkTextbox(parent, height=120, font=FONT_MONO, wrap="word")
        self.dec_input.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        self.dec_input.insert("0.0", "SHVDQ VDQJDW UDKHVLD")
        self.dec_input.bind("<KeyRelease>", lambda _e: self._sync_decrypt())

        keyrow = ctk.CTkFrame(parent, fg_color="transparent")
        keyrow.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        keyrow.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(keyrow, text="Kunci (k):", font=FONT_BODY).grid(row=0, column=0, padx=(0, 8))
        self.dec_key_var = ctk.StringVar(value="3")
        self.dec_key_entry = ctk.CTkEntry(keyrow, textvariable=self.dec_key_var,
                                          width=70, font=FONT_MONO)
        self.dec_key_entry.grid(row=0, column=1, sticky="w")
        self.dec_key_entry.bind("<KeyRelease>", lambda _e: self._sync_decrypt())

        ctk.CTkLabel(keyrow, text="Slider 0-25:", font=FONT_BODY).grid(row=0, column=2, padx=(16, 8))
        self.dec_slider = ctk.CTkSlider(keyrow, from_=0, to=25, number_of_steps=25,
                                        width=240, command=self._on_dec_slider)
        self.dec_slider.set(3)
        self.dec_slider.grid(row=0, column=3, sticky="w")

        self.dec_norm = ctk.CTkLabel(keyrow, text="k = 3  (normalized: 3 % 26 = 3)",
                                     font=FONT_MONO_SMALL, text_color=COLOR_MUTED)
        self.dec_norm.grid(row=0, column=4, padx=(16, 0))

        self.dec_strength = ctk.CTkLabel(keyrow, text="", font=FONT_BODY_BOLD)
        self.dec_strength.grid(row=1, column=0, columnspan=5, sticky="w", padx=0, pady=(4, 0))

        ctk.CTkLabel(parent, text="Plaintext (live preview)", font=FONT_BODY_BOLD).grid(
            row=3, column=0, sticky="sw", padx=4, pady=(8, 0))
        outframe = ctk.CTkFrame(parent)
        outframe.grid(row=4, column=0, sticky="nsew", padx=4, pady=(4, 4))
        outframe.grid_columnconfigure(0, weight=1)
        outframe.grid_rowconfigure(0, weight=1)
        self.dec_output = ctk.CTkTextbox(outframe, height=140, font=FONT_MONO,
                                        wrap="word", state="disabled")
        self.dec_output.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        btns = ctk.CTkFrame(parent, fg_color="transparent")
        btns.grid(row=5, column=0, sticky="w", padx=4)
        ctk.CTkButton(btns, text="Salin Plaintext",
                      command=lambda: self._copy(self._read_box(self.dec_output), "Plaintext")).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="Salin & Catat Log", fg_color="#2B6E2F", hover_color="#1F5A22",
                      command=self._dec_log).pack(side="left")

    def _on_dec_slider(self, value):
        k = int(round(value))
        if self.dec_key_var.get() != str(k):
            self.dec_key_var.set(str(k))
        self._sync_decrypt()

    def _sync_decrypt(self):
        try:
            raw_k = self.dec_key_var.get().strip()
            k = int(raw_k) if raw_k else 3
        except ValueError:
            self._set_strength(self.dec_strength, 3, True)
            self._write_box(self.dec_output, "[Kunci tidak valid - masukkan bilangan bulat]")
            return
        try:
            self.dec_slider.set(k % 26)
        except Exception:
            pass
        text = self.dec_input.get("0.0", "end").rstrip("\n")
        result = CaesarCipher.decrypt(text, k)
        self._write_box(self.dec_output, result)
        norm = k % 26
        self.dec_norm.configure(text=f"k = {k}  (normalized: {k} % 26 = {norm})")
        self._set_strength(self.dec_strength, norm)
        self._last_dec = (text, k, result)

    def _dec_log(self):
        text, k, result = getattr(self, "_last_dec", ("", 3, ""))
        self._log("DEKRIPSI", f'k={k} "{text[:40]}{"..." if len(text) > 40 else ""}" -> "{result[:40]}{"..." if len(result) > 40 else ""}"')
        self._copy(result, "Plaintext")

    # ----------------------- Tab 3: Operasi File -----------------------
    def _build_file_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        def browse(entry):
            path = filedialog.askopenfilename(filetypes=[("File Teks", "*.txt"), ("Semua File", "*.*")])
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)

        def browse_save(entry):
            path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("File Teks", "*.txt"), ("Semua File", "*.*")])
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)

        # Row 0: mode operasi
        self.file_mode = ctk.StringVar(value="encrypt")
        modes = ctk.CTkFrame(parent, fg_color="transparent")
        modes.grid(row=0, column=0, columnspan=3, sticky="w", padx=4, pady=(4, 4))
        ctk.CTkLabel(modes, text="Mode Operasi:", font=FONT_BODY_BOLD).pack(side="left", padx=(0, 12))
        ctk.CTkRadioButton(modes, text="Enkripsi File", variable=self.file_mode,
                           value="encrypt", font=FONT_BODY).pack(side="left", padx=8)
        ctk.CTkRadioButton(modes, text="Dekripsi File", variable=self.file_mode,
                           value="decrypt", font=FONT_BODY).pack(side="left", padx=8)

        # Row 1: pilihan sistem cipher
        ctk.CTkLabel(parent, text="Sistem Cipher:", font=FONT_BODY_BOLD).grid(
            row=1, column=0, sticky="w", padx=4, pady=(4, 0))
        self.file_sys = ctk.StringVar(value="caesar")
        sysrow = ctk.CTkFrame(parent, fg_color="transparent")
        sysrow.grid(row=1, column=0, columnspan=3, sticky="w", padx=4, pady=4)
        ctk.CTkRadioButton(sysrow, text="Caesar Shift", variable=self.file_sys, value="caesar",
                           font=FONT_BODY, command=self._on_file_sys_change).pack(side="left", padx=8)
        ctk.CTkRadioButton(sysrow, text="Transposisi", variable=self.file_sys, value="transposisi",
                           font=FONT_BODY, command=self._on_file_sys_change).pack(side="left", padx=8)

        # Row 2-3: path input/output
        ctk.CTkLabel(parent, text="File Input:", font=FONT_BODY).grid(row=2, column=0, sticky="w", padx=4, pady=6)
        self.file_in = ctk.CTkEntry(parent, width=520, font=FONT_MONO_SMALL)
        self.file_in.grid(row=2, column=1, sticky="ew", padx=4, pady=6)
        ctk.CTkButton(parent, text="Browse...", width=90,
                      command=lambda: browse(self.file_in)).grid(row=2, column=2, padx=4, pady=6)

        ctk.CTkLabel(parent, text="File Output:", font=FONT_BODY).grid(row=3, column=0, sticky="w", padx=4, pady=6)
        self.file_out = ctk.CTkEntry(parent, width=520, font=FONT_MONO_SMALL)
        self.file_out.grid(row=3, column=1, sticky="ew", padx=4, pady=6)
        ctk.CTkButton(parent, text="Browse...", width=90,
                      command=lambda: browse_save(self.file_out)).grid(row=3, column=2, padx=4, pady=6)

        # Row 4: kontrol spesifik sistem (Caesar key ATAU parameter transposisi)
        self.file_ctrl = ctk.CTkFrame(parent, fg_color="transparent")
        self.file_ctrl.grid(row=4, column=0, columnspan=3, sticky="w", padx=4, pady=6)
        self.file_ctrl.grid_columnconfigure(1, weight=1)

        # Sub-frame Caesar: label + entry kunci
        self.file_caesar_ctrl = ctk.CTkFrame(self.file_ctrl, fg_color="transparent")
        ctk.CTkLabel(self.file_caesar_ctrl, text="Kunci (k):", font=FONT_BODY).pack(side="left", padx=(0, 8))
        self.file_key = ctk.CTkEntry(self.file_caesar_ctrl, width=120, font=FONT_MONO)
        self.file_key.insert(0, "3")
        self.file_key.pack(side="left")

        # Sub-frame Transposisi: algoritma + parameter + opsi clean
        self.file_trans_ctrl = ctk.CTkFrame(self.file_ctrl, fg_color="transparent")
        ctk.CTkLabel(self.file_trans_ctrl, text="Algoritma:", font=FONT_BODY).pack(side="left", padx=(0, 8))
        self.ft_algo_var = ctk.StringVar(value="columnar")
        self.ft_algo_menu = ctk.CTkOptionMenu(
            self.file_trans_ctrl,
            values=["columnar", "myszkowski", "railfence", "route", "double"],
            width=190, command=lambda _a: self._on_ft_algo_change(),
        )
        self.ft_algo_menu.set("columnar")
        self.ft_algo_menu.pack(side="left", padx=(0, 12))
        self.ft_key_container = ctk.CTkFrame(self.file_trans_ctrl, fg_color="transparent")
        self.ft_key_container.pack(side="left")
        self.ft_clean = ctk.CTkCheckBox(self.file_trans_ctrl, text="Mode klasik (clean)", font=FONT_BODY)
        self.ft_clean.pack(side="left", padx=(14, 0))

        # Persisten config transposisi operasi file
        self.ft_store = {"algo_var": self.ft_algo_var, "on_change": self._on_ft_key_change, "widgets": {}}
        _rebuild_key_fields(self.ft_key_container, self.ft_store)
        self._on_file_sys_change()  # tampilkan frame sesuai sistem default (caesar)

        # Row 5-6: tombol jalankan + status
        ctk.CTkButton(parent, text="Jalankan Operasi File", height=36,
                      command=self._run_file_op).grid(row=5, column=0, columnspan=3,
                                                      sticky="ew", padx=4, pady=(10, 6))
        self.file_status = ctk.CTkLabel(parent, text="Siap.", font=FONT_MONO_SMALL,
                                        text_color=COLOR_MUTED, anchor="w")
        self.file_status.grid(row=6, column=0, columnspan=3, sticky="ew", padx=4, pady=(2, 4))

    def _on_file_sys_change(self, *_args):
        """Tampilkan/sembunyikan kontrol sesuai sistem cipher terpilih (Caesar | Transposisi)."""
        is_trans = self.file_sys.get() == "transposisi"
        if is_trans:
            self.file_caesar_ctrl.pack_forget()
            self.file_trans_ctrl.pack(side="left", fill="x", expand=True)
        else:
            self.file_trans_ctrl.pack_forget()
            self.file_caesar_ctrl.pack(side="left", fill="x", expand=True)

    def _on_ft_algo_change(self, *_args):
        _rebuild_key_fields(self.ft_key_container, self.ft_store)

    def _on_ft_key_change(self, *_args):
        """No-op; penyimpanan otomatis saat entri berubah tidak diperlukan di sini."""

    def _collect_file_trans_params(self):
        """Baca parameter transposisi dari kontrol tab Operasi File (store dict)."""
        return _collect_trans_params(self.ft_store)

    def _run_file_op(self):
        in_path = self.file_in.get().strip()
        out_path = self.file_out.get().strip()
        if not in_path or not out_path:
            self.file_status.configure(text="[!] Path input dan output wajib diisi.", text_color=COLOR_DANGER)
            return

        mode = self.file_mode.get()
        try:
            if self.file_sys.get() == "transposisi":
                algo = self.ft_algo_var.get()
                params = self._collect_file_trans_params()
                clean = bool(self.ft_clean.get())
                trans_cls = TRANSPOSITION_CLASSES[algo]
                method = trans_cls.encrypt_file if mode == "encrypt" else trans_cls.decrypt_file
                method(in_path, out_path, **params, clean=clean)
                sys_label = f"TRANS-{algo.upper()}"
                msg = f"Berhasil {mode} file -> {out_path}"
                self._log(sys_label, f"{in_path} -> {out_path} ({params})")
            else:
                key_str = self.file_key.get().strip()
                try:
                    k = int(key_str) if key_str else 3
                except ValueError:
                    self.file_status.configure(text="[!] Kunci harus bilangan bulat.", text_color=COLOR_DANGER)
                    return
                if mode == "encrypt":
                    CaesarCipher.encrypt_file(in_path, out_path, k)
                    msg = f"Berhasil mengenkripsi file -> {out_path}"
                    self._log("FILE-ENC", f"k={k} {in_path} -> {out_path}")
                else:
                    CaesarCipher.decrypt_file(in_path, out_path, k)
                    msg = f"Berhasil mendekripsi file -> {out_path}"
                    self._log("FILE-DEC", f"k={k} {in_path} -> {out_path}")
            self.file_status.configure(text=f"[+] {msg}", text_color=COLOR_OK)
        except Exception as exc:
            self.file_status.configure(text=f"[-] Error operasi file: {exc}", text_color=COLOR_DANGER)

    # ----------------------- Tab 4: Brute Force -----------------------
    def _build_bruteforce_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(parent, text="Ciphertext", font=FONT_BODY_BOLD).grid(
            row=0, column=0, sticky="w", padx=4, pady=(4, 0))
        self.bf_input = ctk.CTkTextbox(parent, height=80, font=FONT_MONO, wrap="word")
        self.bf_input.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        self.bf_input.insert("0.0", "LQIRUPDWLND XSJULV")

        btns = ctk.CTkFrame(parent, fg_color="transparent")
        btns.grid(row=2, column=0, sticky="w", padx=4, pady=4)
        ctk.CTkButton(btns, text="Serang (Exhaustive Key Search)", height=34,
                      command=self._run_bruteforce).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="Salin Hasil", fg_color="#2B6E2F", hover_color="#1F5A22",
                      command=lambda: self._copy(self._read_box(self.bf_output), "Brute-force results")).pack(side="left")

        self.bf_output = ctk.CTkTextbox(parent, font=FONT_MONO_SMALL, wrap="none",
                                        state="disabled")
        self.bf_output.grid(row=3, column=0, sticky="nsew", padx=4, pady=(4, 4))

    def _run_bruteforce(self):
        cipher = self.bf_input.get("0.0", "end").rstrip("\n")
        if not cipher.strip():
            self._write_box(self.bf_output, "[-] Ciphertext tidak boleh kosong.")
            return
        results = CaesarBreaker.brute_force(cipher)
        lines = [f"[*] Exhaustive search |K| = 25 pergeseran (k = 1..25):\n"]
        for res in results:
            lines.append(f"  Shift {res['key']:2d} : {res['plaintext']}")
        text = "\n".join(lines)
        self._write_box(self.bf_output, text)
        self._log("BRUTE-FORCE", f'{len(results)} kandidat diuji untuk ciphertext "{cipher[:40]}..."')

    # ----------------------- Tab 5: Frequency Analysis -----------------------
    def _build_freq_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(parent, text="Ciphertext", font=FONT_BODY_BOLD).grid(
            row=0, column=0, sticky="w", padx=4, pady=(4, 0))
        self.fa_input = ctk.CTkTextbox(parent, height=80, font=FONT_MONO, wrap="word")
        self.fa_input.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        self.fa_input.insert(
            "0.0",
            "SHVDQ VDQJDW UDKDVLD GHUPD LQIRUPDWLND VLEHU GDQ NULSWRJUDIL "
            "GDODP PHOLQGXQJDQ SHJDPLQDQ UDKDVLD",
        )

        ctrl = ctk.CTkFrame(parent, fg_color="transparent")
        ctrl.grid(row=2, column=0, sticky="w", padx=4, pady=4)
        ctk.CTkLabel(ctrl, text="Bahasa kamus frekuensi:", font=FONT_BODY).pack(side="left", padx=(0, 8))
        self.fa_lang = ctk.CTkOptionMenu(ctrl, values=["id", "en"], width=90)
        self.fa_lang.set("id")
        self.fa_lang.pack(side="left", padx=(0, 12))
        ctk.CTkButton(ctrl, text="Crack (Chi-Squared)", height=34,
                      command=self._run_freq).pack(side="left", padx=(0, 8))
        ctk.CTkButton(ctrl, text="Salin Plaintext", fg_color="#2B6E2F", hover_color="#1F5A22",
                      command=lambda: self._copy(getattr(self, "_fa_plain", ""), "Cracked plaintext")).pack(side="left")

        self.fa_output = ctk.CTkTextbox(parent, font=FONT_MONO_SMALL, wrap="word",
                                        state="disabled")
        self.fa_output.grid(row=3, column=0, sticky="nsew", padx=4, pady=(4, 4))

    def _run_freq(self):
        cipher = self.fa_input.get("0.0", "end").rstrip("\n")
        if not cipher.strip():
            self._write_box(self.fa_output, "[-] Ciphertext tidak boleh kosong.")
            return
        lang = self.fa_lang.get()
        try:
            res = CaesarBreaker.frequency_analysis_crack(cipher, lang=lang)
        except Exception as exc:
            self._write_box(self.fa_output, f"[-] Error analisis frekuensi: {exc}")
            return
        lines = [
            "[+] HASIL ANALISIS FREKUENSI (Chi-Squared Test):",
            f"  Kunci Terbaik Ditemukan : {res['best_key']}",
            f"  Skor Chi-Squared (chi^2): {res['best_score']}  (semakin rendah = semakin akurat)",
            f"  Hasil Plaintext         : {res['cracked_plaintext']}",
            "",
            "  Top 3 Kandidat Probabilitas Tertinggi:",
        ]
        for rank, item in enumerate(res["all_ranked"][:3], 1):
            lines.append(f"    {rank}. Key {item['key']:2d} (Chi^2: {item['score']:7.2f}) -> {item['plaintext']}")
        self._write_box(self.fa_output, "\n".join(lines))
        self._fa_plain = res["cracked_plaintext"]
        self._log("FREQ-CRACK", f'lang={lang} best_key={res["best_key"]} chi2={res["best_score"]}')

    # ----------------------- Tab 6: Transposisi -----------------------
    def _build_transposition_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(4, weight=1)

        # Row 0: pemilih algoritma
        band = ctk.CTkFrame(parent, fg_color="transparent")
        band.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 0))
        ctk.CTkLabel(band, text="Algoritma:", font=FONT_BODY_BOLD).pack(side="left", padx=(0, 8))
        self.trans_algo_var = ctk.StringVar(value="columnar")
        self.trans_algo_menu = ctk.CTkOptionMenu(
            band,
            values=["columnar", "myszkowski", "railfence", "route", "double"],
            width=190, command=lambda _a: self._trans_algo_changed(),
        )
        self.trans_algo_menu.set("columnar")
        self.trans_algo_menu.pack(side="left", padx=(0, 16))

        # Row 0b: mode enkripsi/dekripsi
        self.trans_mode_var = ctk.StringVar(value="encrypt")
        ctk.CTkRadioButton(band, text="Enkripsi", variable=self.trans_mode_var,
                           value="encrypt", font=FONT_BODY, command=self._sync_transposition).pack(side="left", padx=(0, 8))
        ctk.CTkRadioButton(band, text="Dekripsi", variable=self.trans_mode_var,
                           value="decrypt", font=FONT_BODY, command=self._sync_transposition).pack(side="left", padx=(0, 8))

        # Row 0c: opsi klasik
        self.trans_clean = ctk.CTkCheckBox(band, text="Mode klasik (clean)", font=FONT_BODY,
                                           command=self._sync_transposition)
        self.trans_clean.pack(side="left", padx=(16, 0))
        self.trans_group5 = ctk.CTkCheckBox(band, text="Grup 5 huruf", font=FONT_BODY,
                                            command=self._sync_transposition)
        self.trans_group5.pack(side="left", padx=(0, 0))

        # Row 1: text input
        ctk.CTkLabel(parent, text="Input teks", font=FONT_BODY_BOLD).grid(
            row=1, column=0, sticky="w", padx=4, pady=(8, 0))
        self.trans_input = ctk.CTkTextbox(parent, height=110, font=FONT_MONO, wrap="word")
        self.trans_input.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        self.trans_input.insert(
            "0.0",
            "WEAREDISCOVEREDFLEEATONCE",
        )
        self.trans_input.bind("<KeyRelease>", lambda _e: self._sync_transposition())

        # Row 3: field parameter dinamis (rails/keyword/width+rute)
        self.trans_key_container = ctk.CTkFrame(parent, fg_color="transparent")
        self.trans_key_container.grid(row=3, column=0, sticky="ew", padx=4, pady=(4, 0))
        self.trans_store = {"algo_var": self.trans_algo_var, "on_change": self._on_trans_key_change, "widgets": {}}
        _rebuild_key_fields(self.trans_key_container, self.trans_store)

        # Row 4: output (ekspansi)
        ctk.CTkLabel(parent, text="Hasil (live preview)", font=FONT_BODY_BOLD).grid(
            row=4, column=0, sticky="sw", padx=4, pady=(8, 0))
        outframe = ctk.CTkFrame(parent)
        outframe.grid(row=5, column=0, sticky="nsew", padx=4, pady=(4, 4))
        outframe.grid_columnconfigure(0, weight=1)
        outframe.grid_rowconfigure(0, weight=1)
        self.trans_output = ctk.CTkTextbox(outframe, height=130, font=FONT_MONO,
                                           wrap="word", state="disabled")
        self.trans_output.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        btns = ctk.CTkFrame(parent, fg_color="transparent")
        btns.grid(row=6, column=0, sticky="w", padx=4)
        ctk.CTkButton(btns, text="Salin Hasil",
                      command=lambda: self._copy(self._read_box(self.trans_output), "Transposisi")).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="Salin & Catat Log", fg_color="#2B6E2F", hover_color="#1F5A22",
                      command=self._trans_log).pack(side="left")

        self._sync_transposition()

    def _on_trans_key_change(self, *_args):
        self._sync_transposition()

    def _trans_algo_changed(self):
        _rebuild_key_fields(self.trans_key_container, self.trans_store)
        self._sync_transposition()

    def _collect_trans_text_params(self):
        """Parameter transposisi untuk operasi teks (store tab Transposisi)."""
        return _collect_trans_params(self.trans_store)

    def _trans_info(self) -> str:
        algo = self.trans_algo_var.get()
        params = self._collect_trans_text_params()
        mode = self.trans_mode_var.get()
        clean = bool(self.trans_clean.get())
        group5 = bool(self.trans_group5.get())
        flags = ""
        if clean:
            flags += " · clean"
        if group5:
            flags += " · grup5"
        return f"{algo.upper()} · {mode} · {params}{flags}"

    def _sync_transposition(self):
        # Field parameter dibangun sebelum widget output; tahan aksi sampai output siap.
        if not hasattr(self, "trans_output"):
            return
        raw = self.trans_input.get("0.0", "end").rstrip("\n")
        algo = self.trans_algo_var.get()
        mode = self.trans_mode_var.get()
        try:
            params = self._collect_trans_text_params()
            result = _transpose_text(algo, mode, params, raw,
                                     bool(self.trans_clean.get()),
                                     bool(self.trans_group5.get()))
            self._write_box(self.trans_output, result)
            self._last_trans = (algo, mode, params, raw)
        except (TypeError, ValueError) as exc:
            self._write_box(self.trans_output, f"[Parameter tidak valid] {exc}")

    def _trans_log(self):
        algo, mode, params, raw = getattr(self, "_last_trans", ("columnar", "encrypt", {}, ""))
        preview = raw[:40] + ("..." if len(raw) > 40 else "")
        self._log("TRANSPOSISI", f"{algo} ({mode}) {params} \"{preview}\"")

    # ----------------------- Tab 7: Advisory -----------------------
    def _build_advisory_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(parent,
                     text="Cyber Security Threat Model & Advisory Report (reuse dari app.py)",
                     font=FONT_BODY_BOLD, text_color=COLOR_MUTED).grid(
            row=0, column=0, sticky="w", padx=4, pady=(4, 2))
        box = ctk.CTkTextbox(parent, font=FONT_MONO_SMALL, wrap="word", state="disabled")
        box.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
        self._write_box(box, ADVISORY_TEXT)

    # ----------------------- Helper render -----------------------
    @staticmethod
    def _write_box(box, text):
        box.configure(state="normal")
        box.delete("0.0", "end")
        box.insert("0.0", text)
        box.configure(state="disabled")

    @staticmethod
    def _read_box(box):
        return box.get("0.0", "end").rstrip("\n")

    @staticmethod
    def _set_strength(label, norm_k, invalid=False):
        if invalid:
            label.configure(text="! Kunci tidak valid", text_color=COLOR_DANGER)
            return
        text, color = key_strength(norm_k)
        label.configure(text=text, text_color=color)


if __name__ == "__main__":
    app = CaesarCipherApp()
    app.mainloop()
