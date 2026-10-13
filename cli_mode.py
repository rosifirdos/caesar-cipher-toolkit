"""
Mode CLI ter-embed untuk aplikasi desktop (CustomTkinter).

Apa yang dilakukan modul ini
----------------------------
Memberi aplikasi desktop "menu pilihan untuk memilih mode CLI": empat operasi
favorit dijalankan langsung (fast-path tanpa subprocess), atau terminal CLI
asli (`app.py`) dijalankan dalam window terminal terpisah (subprocess).

Fast-path
---------
`_cli_fast` di `desktop_app.py` memanggil engine yang SAMA dengan CLI
(`app.py`): CaesarCipher, CaesarBreaker, dan _transpose_text -- tidak ada
duplikasi logika, dan hasil di-render dengan palet warna Kali di kotak output.

Terminal CLI (penuh)
--------------------
`python -m cli_mode shell` (dipanggil dari aplikasi desktop) menjalankan
`app.py` (CLI asli, mendukung mode interaktif maupun --flag) sebagai
subprocess di window console baru, tanpa memblokir UI desktop -- sehingga
"mode CLI" berfungsi penuh persis seperti menjalankan `python app.py` dari
terminal.
"""

import os
import sys
import subprocess

# Nama simbol yang diimpor aplikasi desktop.
__all__ = ["CLI_COLOR_CODES", "COLOR_NAME_TO_HEX", "colorize_cli", "CLI_LABEL_HINT"]


# ---------------------------------------------------------------------------
# Palet CLI -- palet bawaan `xterm-256color` (menarik elemen Kali Linux)
# ---------------------------------------------------------------------------
CLI_COLOR_CODES = {
    "blue": "\033[38;5;111m",        # Kali blue
    "green": "\033[38;5;077m",       # hijau terminal
    "red": "\033[38;5;203m",         # merah error
    "cyan": "\033[38;5;080m",        # cyan info
    "yellow": "\033[38;5;228m",      # kuning warn
    "reset": "\033[0m",
}
COLOR_NAME_TO_HEX = {
    "blue": "#7AA2F7",
    "green": "#00CC66",
    "red": "#FF6B6B",
    "cyan": "#4FD6C8",
    "yellow": "#FFD24D",
}
CLI_LABEL_HINT = "Legenda: [#] biru=CMD · [+] hijau=OK · [-] merah=ERR · [*] cyan=INFO"


def colorize_cli(name: str, text: str) -> str:
    """Bungkus teks dengan ansi palet CLI (xterm-256color)."""
    code = CLI_COLOR_CODES.get(name, "")
    reset = CLI_COLOR_CODES["reset"]
    return f"{code}{text}{reset}"


def _run_shell():
    """
    Jalankan CLI `app.py` sebagai subprocess di window console terpisah.

    `app.py` membaca dari stdin -> masuk mode interaktif penuh. Window di
    Windows dibuka via CREATE_NEW_CONSOLE (jalur paling andal tanpa shell).
    """
    app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
    python_exe = sys.executable

    creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)  # hanya di Windows
    subprocess.Popen(
        [python_exe, app_path],
        cwd=os.path.dirname(app_path),
        creationflags=creationflags,
    )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "shell":
        _run_shell()