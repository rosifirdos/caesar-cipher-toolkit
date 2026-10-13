"""
Aplikasi Caesar Cipher & Cryptanalysis Toolkit
Perspektif: Cyber Security & Cryptography Evaluation
Mendukung Mode Interaktif (CLI Menu) dan Mode Otomasi (Command Line Arguments).

Keluarga cipher yang ditangani:
  1. Substitusi: Caesar Shift (enkripsi/dekripsi/brute-force/frequency-analysis).
  2. Transposisi: Rail Fence, Route, Columnar, Double, Myszkowski
     (submenu interaktif 7 dan flag --transposition).
"""

import argparse
import sys
from pathlib import Path

from caesar_cipher import CaesarCipher
from cryptanalysis import CaesarBreaker
from transposition import (
    ColumnarTransposition,
    DoubleTransposition,
    MyszkowskiTransposition,
    RailFence,
    RouteCipher,
)


CYBER_BANNER = r"""
========================================================================
   ____                              ____ _       _
  / ___|__ _  ___  ___  __ _ _ __   / ___(_)_ __ | |__   ___ _ __
 | |   / _` |/ _ \/ __|/ _` | '__| | |   | | '_ \| '_ \ / _ \ '__|
 | |__| (_| |  __/\__ \ (_| | |    | |___| | |_) | | | |  __/ |
  \____\__,_|\___||___/\__,_|_|     \____|_| .__/|_| |_|\___|_|
                                           |_|
  [ CYBER SECURITY & CRYPTANALYSIS TOOLKIT - PYTHON EDITION ]
========================================================================
"""

ADVISORY_TEXT = """
[!] CYBER SECURITY ADVISORY & THREAT MODEL REPORT: CAESAR CIPHER
------------------------------------------------------------------------
1. Tingkat Keamanan: CRITICAL VULNERABILITY (BROKEN)
   - Caesar Cipher adalah Monoalphabetic Substitution Cipher klasik.
   - Ukuran Ruang Kunci (Keyspace): |K| = 26 (hanya 25 pergeseran efektif).
   - Entropi kunci hanya ~4.7 bits (jauh di bawah standar aman 128-256 bits).

2. Vektor Serangan Utama:
   a. Brute Force (Exhaustive Key Search):
      Kompleksitas O(26). Komputer modern dapat menguji seluruh keyspace
      dalam hitungan mikrodetik.
   b. Frequency Analysis Attack (Ciphertext-Only Attack / COA):
      Pola pergeseran tidak mengubah distribusi frekuensi relatif huruf.
      Statistik Chi-Squared dapat menebak kunci secara instan tanpa bantuan manusia.
   c. Known-Plaintext Attack (KPA):
      Cukup mengetahui 1 huruf plaintext dan pasangannya di ciphertext,
      kunci k langsung terbongkar: k = (C - P) mod 26.

3. Ketiadaan Integritas (Malleability):
   - Tidak memiliki Message Authentication Code (MAC) / cryptographic tag.
   - Penyerang dapat memanipulasi ciphertext dalam transit (bit/character flipping)
     tanpa terdeteksi.

4. Rekomendasi Industri Kriptografi Modern:
   - Gunakan Authenticated Encryption with Associated Data (AEAD):
     Contoh: AES-256-GCM atau ChaCha20-Poly1305.
   - Manajemen Kunci: Gunakan Key Derivation Function (KDF) seperti Argon2id/PBKDF2.
------------------------------------------------------------------------

[!] CATATAN TRANSPOSISI (lihat SECURITY_ANALYSIS.md)
------------------------------------------------------------------------
   Keluarga transposisi murni (Rail Fence, Route, Columnar, Double, Myszkowski)
   hanya mengubah URUTAN huruf, bukan identitasnya. Distribusi frekuensi huruf
   tetap utuh -> rentan terhadap analisis frekuensi & keduanya tidak cocok untuk
   proteksi data produksi (nilai pedagogis & historis saja).
------------------------------------------------------------------------
"""


# ---------------------------------------------------------------------------
# Kriptografi Transposisi — registry + helper bersama (CLI & interaktif)
# ---------------------------------------------------------------------------

TRANSPOSITION_CLASSES = {
    "railfence": RailFence,
    "route": RouteCipher,
    "columnar": ColumnarTransposition,
    "double": DoubleTransposition,
    "myszkowski": MyszkowskiTransposition,
}

TRANSPOSITION_ALGOS = {
    "1": ("railfence", "TRANSPOSISI RAIL FENCE"),
    "2": ("route", "TRANSPOSISI ROUTE"),
    "3": ("columnar", "TRANSPOSISI KOLOM"),
    "4": ("double", "TRANSPOSISI GANDA"),
    "5": ("myszkowski", "TRANSPOSISI MYSZKOWSKI"),
}


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    value = input(prompt).strip().lower()
    if not value:
        return default
    return value in ("y", "yes", "1", "true", "ya")


def _ask_algo() -> tuple:
    """Menu interaktif pemilihan algoritma; mengembalikan (algo, label) atau (None, None)."""
    print("\n  Pilih algoritma transposisi:")
    for num, (_, label) in TRANSPOSITION_ALGOS.items():
        print(f"    {num}. {label}")
    choice = input("  Pilih [1-5]: ").strip()
    return TRANSPOSITION_ALGOS.get(choice, (None, None))


def _prompt_route() -> str:
    """Pilih rute Route Cipher dari daftar terkurasi."""
    print("  Rute tersedia:")
    for i, route in enumerate(RouteCipher.ROUTE_CHOICES, 1):
        print(f"    {i}. {route}")
    raw = input(f"  Pilih rute [1-{len(RouteCipher.ROUTE_CHOICES)}, default 1]: ").strip()
    if not raw:
        return "spiral_tl"
    try:
        return RouteCipher.ROUTE_CHOICES[int(raw) - 1]
    except (ValueError, IndexError):
        return "spiral_tl"


def _ask_params(algo: str, for_file: bool = False) -> tuple:
    """
    Bertanya parameter (kunci/keyword) sesuai algoritma.

    Returns:
        (params, clean, group5) — params = dict kwargs cipher; group5 hanya
        relevan untuk operasi teks (operasi file tidak mendukung format grup 5).
    """
    clean = _ask_yes_no("  Mode klasik (clean) [y/N]: ")
    group5 = False
    if clean and not for_file:
        group5 = _ask_yes_no("  Format kelompok 5 huruf [y/N]: ")

    if algo == "railfence":
        raw = input("  Jumlah rel (rails) [default 3]: ").strip()
        params = {"rails": int(raw) if raw else 3}
    elif algo == "route":
        raw = input("  Lebar grid (width) [default 5]: ").strip()
        params = {"width": int(raw) if raw else 5, "route": _prompt_route()}
    elif algo in ("columnar", "myszkowski"):
        keyword = input("  Keyword: ").strip()
        params = {"keyword": keyword}
    else:  # double
        key1 = input("  Keyword 1: ").strip()
        key2 = input("  Keyword 2: ").strip()
        params = {"key1": key1, "key2": key2}
    return params, clean, group5


def _transpose_text(algo: str, mode: str, params: dict, raw: str,
                    clean: bool, group5: bool = False) -> str:
    """Terapkan cipher transposisi pada teks (encrypt/decrypt)."""
    cls = TRANSPOSITION_CLASSES[algo]
    if mode == "decrypt":
        if algo == "double":
            return cls.decrypt(raw, params["key1"], params["key2"], clean=clean)
        if algo == "railfence":
            return cls.decrypt(raw, params["rails"], clean=clean)
        if algo == "route":
            return cls.decrypt(raw, params["width"], params["route"], clean=clean)
        return cls.decrypt(raw, params["keyword"], clean=clean)

    # encrypt
    if algo == "double":
        return cls.encrypt(raw, params["key1"], params["key2"], clean=clean, group5=group5)
    if algo == "railfence":
        return cls.encrypt(raw, params["rails"], clean=clean, group5=group5)
    if algo == "route":
        return cls.encrypt(raw, params["width"], params["route"], clean=clean, group5=group5)
    return cls.encrypt(raw, params["keyword"], clean=clean, group5=group5)


def _transpose_file(algo: str, mode: str, params: dict, in_path: str,
                    out_path: str, clean: bool) -> None:
    """Terapkan cipher transposisi pada file .txt (reuse engine encrypt_file/decrypt_file)."""
    cls = TRANSPOSITION_CLASSES[algo]
    method = cls.encrypt_file if mode == "encrypt" else cls.decrypt_file
    method(in_path, out_path, **params, clean=clean)


# ---------------------------------------------------------------------------
# Alur interaktif
# ---------------------------------------------------------------------------

def run_transposition_algo_flow(algo: str, label: str) -> None:
    """Alur interaktif: pilih mode, masukkan parameter, proses teks."""
    print(f"\n--- {label} ---")
    mode_str = input("  Mode (1: Enkripsi, 2: Dekripsi) [1]: ").strip() or "1"
    mode = "decrypt" if mode_str == "2" else "encrypt"
    try:
        params, clean, group5 = _ask_params(algo)
    except ValueError as e:
        print(f"[-] Input tidak valid: {e}")
        return

    raw = input("  Masukkan teks: ").strip()
    if not raw:
        print("[-] Teks tidak boleh kosong.")
        return
    try:
        result = _transpose_text(algo, mode, params, raw, clean, group5)
    except (TypeError, ValueError) as e:
        print(f"[-] Error: {e}")
        return

    print(f"\n[+] Algoritma : {label}")
    print(f"[+] Mode      : {mode.upper()}"
          + (" (clean)" if clean else "") + (" (grup 5)" if group5 else ""))
    print(f"[+] Hasil     : {result}")


def run_transposition_menu() -> None:
    """Submenu interaktif: Kriptografi Transposisi (5 algoritma)."""
    while True:
        print("\n[ SUBMENU: KRIPTOGRAFI TRANSPOSISI ]")
        for num, (_, label) in TRANSPOSITION_ALGOS.items():
            print(f"  {num}. {label}")
        print("  0. Kembali ke Menu Utama")
        choice = input("\n  Pilih algoritma [1-5] atau 0: ").strip()
        if choice == "0":
            return
        if choice not in TRANSPOSITION_ALGOS:
            print("[-] Pilihan tidak valid.")
            continue
        algo, label = TRANSPOSITION_ALGOS[choice]
        run_transposition_algo_flow(algo, label)


def run_transposition_file_flow() -> None:
    """Operasi file transposisi (digunakan dari menu 3 sub-opsi transposisi)."""
    print("\n--- OPERASI FILE TRANSPOSISI ---")
    mode_str = input("  Mode (1: Enkripsi File, 2: Dekripsi File): ").strip()
    if mode_str not in ("1", "2"):
        print("[-] Pilihan tidak valid.")
        return
    mode = "decrypt" if mode_str == "2" else "encrypt"

    algo, label = _ask_algo()
    if algo is None:
        print("[-] Pilihan tidak valid.")
        return
    try:
        params, clean, _ = _ask_params(algo, for_file=True)
    except ValueError as e:
        print(f"[-] Input tidak valid: {e}")
        return

    in_path = input("  Path file input : ").strip()
    out_path = input("  Path file output: ").strip()
    if not in_path or not out_path:
        print("[-] Path input/output tidak boleh kosong.")
        return
    try:
        _transpose_file(algo, mode, params, in_path, out_path, clean)
    except (TypeError, ValueError, FileNotFoundError) as e:
        print(f"[-] Error operasi file transposisi: {e}")
        return
    print(f"\n[+] Algoritma : {label}")
    print(f"[+] Mode      : {mode.upper()}" + (" (clean)" if clean else ""))
    print(f"[+] Berhasil  : output ditulis ke {out_path}")


def run_interactive():
    print(CYBER_BANNER)
    while True:
        print("\n[ MENU UTAMA ]")
        print("  1. Enkripsi Teks (Shift Cipher)")
        print("  2. Dekripsi Teks (Shift Cipher)")
        print("  3. Enkripsi / Dekripsi File (.txt)")
        print("  4. Kriptanalisis: Serangan Brute Force (Tampilkan 25 Variasi)")
        print("  5. Kriptanalisis: Serangan Frekuensi Otomatis (Chi-Squared)")
        print("  6. Cyber Security Threat Model & Advisory")
        print("  7. Kriptografi Transposisi (5 Algoritma)")
        print("  0. Keluar")

        choice = input("\nPilih opsi [0-7]: ").strip()

        if choice == "1":
            print("\n--- ENKRIPSI TEKS ---")
            text = input("Masukkan plaintext : ")
            key_str = input("Masukkan kunci (default 3): ").strip()
            key = int(key_str) if key_str else 3
            result = CaesarCipher.encrypt(text, key)
            print(f"\n[+] Plaintext  : {text}")
            print(f"[+] Kunci (k)  : {key} (Normalized: {key % 26})")
            print(f"[+] Ciphertext : {result}")

        elif choice == "2":
            print("\n--- DEKRIPSI TEKS ---")
            text = input("Masukkan ciphertext: ")
            key_str = input("Masukkan kunci (default 3): ").strip()
            key = int(key_str) if key_str else 3
            result = CaesarCipher.decrypt(text, key)
            print(f"\n[+] Ciphertext : {text}")
            print(f"[+] Kunci (k)  : {key} (Normalized: {key % 26})")
            print(f"[+] Plaintext  : {result}")

        elif choice == "3":
            print("\n--- OPERASI FILE ENKRIPSI / DEKRIPSI ---")
            sys_choice = input("Sistem cipher (1: Caesar Shift, 2: Transposisi): ").strip()
            if sys_choice == "2":
                run_transposition_file_flow()
                continue
            if sys_choice not in ("", "1"):
                print("[-] Pilihan tidak valid.")
                continue
            sub_choice = input("Pilih mode (1: Enkripsi File, 2: Dekripsi File): ").strip()
            in_path = input("Path file input : ").strip()
            out_path = input("Path file output: ").strip()
            key_str = input("Kunci pergeseran: ").strip()
            try:
                key = int(key_str)
                if sub_choice == "1":
                    CaesarCipher.encrypt_file(in_path, out_path, key)
                    print(f"\n[+] Berhasil mengenkripsi file ke: {out_path}")
                elif sub_choice == "2":
                    CaesarCipher.decrypt_file(in_path, out_path, key)
                    print(f"\n[+] Berhasil mendekripsi file ke: {out_path}")
                else:
                    print("[-] Pilihan tidak valid.")
            except Exception as e:
                print(f"[-] Error operasi file: {e}")

        elif choice == "4":
            print("\n--- SERANGAN KRIPTANALISIS: BRUTE FORCE (EXHAUSTIVE SEARCH) ---")
            cipher = input("Masukkan ciphertext: ").strip()
            if not cipher:
                print("[-] Ciphertext tidak boleh kosong.")
                continue
            print(f"\n[*] Melakukan uji coba pada seluruh ruang kunci (k = 1 s.d 25)...\n")
            results = CaesarBreaker.brute_force(cipher)
            for res in results:
                print(f"  Shift {res['key']:2d} : {res['plaintext']}")

        elif choice == "5":
            print("\n--- SERANGAN KRIPTANALISIS: ANALISIS FREKUENSI OTOMATIS ---")
            cipher = input("Masukkan ciphertext: ").strip()
            lang = input("Bahasa kamus frekuensi [id = Indonesia, en = Inggris] (default: id): ").strip() or "id"
            if not cipher:
                print("[-] Ciphertext tidak boleh kosong.")
                continue

            crack_res = CaesarBreaker.frequency_analysis_crack(cipher, lang=lang)
            print(f"\n[+] HASIL ANALISIS FREKUENSI (Chi-Squared Test):")
            print(f"  Kunci Terbaik Ditemukan : {crack_res['best_key']}")
            print(f"  Skor Chi-Squared (chi^2): {crack_res['best_score']} (Semakin rendah = semakin akurat)")
            print(f"  Hasil Plaintext         : {crack_res['cracked_plaintext']}")
            print("\n  Top 3 Kandidat Probabilitas Tertinggi:")
            for rank, item in enumerate(crack_res['all_ranked'][:3], 1):
                print(f"    {rank}. Key {item['key']:2d} (Chi^2: {item['score']:7.2f}) -> {item['plaintext']}")

        elif choice == "6":
            print(ADVISORY_TEXT)

        elif choice == "7":
            run_transposition_menu()

        elif choice == "0":
            print("\n[+] Menghentikan aplikasi. Salam Cyber Security!")
            break
        else:
            print("[-] Pilihan tidak valid. Silakan coba lagi.")


def run_cli_args():
    parser = argparse.ArgumentParser(
        description="Aplikasi Caesar Cipher & Offensive Cryptanalysis Toolkit (Cyber Security Perspective)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Contoh:\n"
               "  python app.py -e -k 3 -t \"PESAN SANGAT RAHASIA\"\n"
               "  python app.py -d -k 3 -t \"SHVDQ VDQJDW UDKDVLD\"\n"
               "  python app.py --brute-force -t \"LQIRUPDWLND XSJULV\"\n"
               "  python app.py --auto-crack -t \"LQIRUPDWLND XSJULV\" --lang id\n"
               "\n"
               "Transposisi:\n"
               "  python app.py --transposition --algo railfence  --key 3 --mode encrypt -t \"WEAREDISCOVEREDFLEEATONCE\"\n"
               "  python app.py --transposition --algo columnar   --keyword ZEBRA --mode encrypt -t \"WEAREDISCOVEREDFLEEATONCE\"\n"
               "  python app.py --transposition --algo myszkowski --keyword TOMATO --mode decrypt -t \"TINESAEOAHTFHMTALITIHAEIYTOASPTNNGHDML\"\n"
               "  python app.py --transposition --algo route      --key 5 --route spiral_tl --mode encrypt -t \"WEAREDISCOVEREDFLEEATONCE\"\n"
               "  python app.py --transposition --algo double     --keyword ZEBRA --keyword2 KRIPTO --mode encrypt -t \"WEAREDISCOVEREDFLEEATONCE\"\n"
    )

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("-e", "--encrypt", action="store_true", help="Lakukan enkripsi")
    action_group.add_argument("-d", "--decrypt", action="store_true", help="Lakukan dekripsi")
    action_group.add_argument("-b", "--brute-force", action="store_true", help="Jalankan serangan brute-force (25 shift)")
    action_group.add_argument("-c", "--auto-crack", action="store_true", help="Jalankan serangan analisis frekuensi otomatis")
    action_group.add_argument("--advisory", action="store_true", help="Tampilkan laporan analisis keamanan siber")
    action_group.add_argument("--transposition", action="store_true",
                              help="Jalankan kriptografi transposisi (5 algoritma). Tanpa --algo, buka submenu interaktif.")

    parser.add_argument("-k", "--key", type=int, default=3,
                        help="Kunci pergeseran (default: 3). Untuk transposisi dipakai sebagai rails (Rail Fence) / width (Route).")
    parser.add_argument("-t", "--text", type=str, help="Teks input untuk diproses")
    parser.add_argument("-i", "--input-file", type=str, help="Path file input (.txt)")
    parser.add_argument("-o", "--output-file", type=str, help="Path file output (.txt)")
    parser.add_argument("--lang", type=str, default="id", choices=["id", "en"],
                        help="Bahasa target untuk analisis frekuensi (id/en)")

    # Parameter transposisi (inert untuk aksi Caesar — hanya dibaca saat --transposition dipakai)
    parser.add_argument("--algo", type=str, choices=["railfence", "route", "columnar", "double", "myszkowski"],
                        help="Algoritma transposisi (dipakai bersama --transposition)")
    parser.add_argument("--mode", type=str, choices=["encrypt", "decrypt"], default="encrypt",
                        help="Mode transposisi (default: encrypt)")
    parser.add_argument("--keyword", type=str, help="Keyword transposisi kolom (columnar/myszkowski/double)")
    parser.add_argument("--keyword2", type=str, help="Keyword kedua transposisi ganda (double)")
    parser.add_argument("--route", type=str, default="spiral_tl",
                        help="Rute transposisi route (default: spiral_tl)")
    parser.add_argument("--clean", action="store_true",
                        help="Mode klasik transposisi: strip karakter non-huruf + semua kapital")
    parser.add_argument("--group5", action="store_true",
                        help="Format output kelompok 5 huruf (membutuhkan --clean)")

    args = parser.parse_args()

    # Jika dijalankan tanpa argumen apa pun, luncurkan mode interaktif
    if len(sys.argv) == 1:
        run_interactive()
        return

    if args.advisory:
        print(ADVISORY_TEXT)
        return

    # Transposisi: cek SEBELUM membaca teks karena penanganan kunci berbeda.
    if args.transposition:
        _run_transposition(args, parser)
        return

    # Ambil sumber teks (dari argumen -t atau file -i)
    raw_text = None
    if args.text is not None:
        raw_text = args.text
    elif args.input_file:
        raw_text = Path(args.input_file).read_text(encoding="utf-8")

    if args.encrypt:
        if raw_text is None:
            parser.error("Diperlukan teks (-t) atau file input (-i) untuk enkripsi.")
        result = CaesarCipher.encrypt(raw_text, args.key)
        if args.output_file:
            Path(args.output_file).write_text(result, encoding="utf-8")
            print(f"[+] Hasil enkripsi disimpan ke: {args.output_file}")
        else:
            print(result)

    elif args.decrypt:
        if raw_text is None:
            parser.error("Diperlukan teks (-t) atau file input (-i) untuk dekripsi.")
        result = CaesarCipher.decrypt(raw_text, args.key)
        if args.output_file:
            Path(args.output_file).write_text(result, encoding="utf-8")
            print(f"[+] Hasil dekripsi disimpan ke: {args.output_file}")
        else:
            print(result)

    elif args.brute_force:
        if raw_text is None:
            parser.error("Diperlukan teks (-t) atau file input (-i) untuk serangan brute-force.")
        results = CaesarBreaker.brute_force(raw_text)
        for res in results:
            print(f"Shift {res['key']:2d}: {res['plaintext']}")

    elif args.auto_crack:
        if raw_text is None:
            parser.error("Diperlukan teks (-t) atau file input (-i) untuk analisis frekuensi otomatis.")
        crack_res = CaesarBreaker.frequency_analysis_crack(raw_text, lang=args.lang)
        print(f"[+] Predicted Key: {crack_res['best_key']}")
        print(f"[+] Chi^2 Score  : {crack_res['best_score']}")
        print(f"[+] Plaintext    : {crack_res['cracked_plaintext']}")

    else:
        run_interactive()


def _run_transposition(args, parser):
    """Action handler CLI: --transposition (menggunakan subparameter --algo/--mode)."""
    if not args.algo:
        print("\n[*] --transposition tanpa --algo -> membuka Submenu Kriptografi Transposisi.\n")
        run_transposition_menu()
        return

    algo = args.algo
    mode = args.mode
    clean = args.clean
    group5 = args.group5

    # Sumber teks: dari -t atau file -i.
    if args.text is not None:
        raw = args.text
    elif args.input_file:
        raw = Path(args.input_file).read_text(encoding="utf-8")
    else:
        parser.error("Diperlukan teks (-t) atau file input (-i) untuk transposisi.")

    # Bangun parameter sesuai algoritma (validasi keyword dilakukan di sini).
    if algo in ("railfence", "route"):
        params = ({"rails": args.key} if algo == "railfence"
                  else {"width": args.key, "route": args.route})
    elif algo in ("columnar", "myszkowski"):
        if not args.keyword:
            parser.error(f"Algoritma '{algo}' memerlukan --keyword.")
        params = {"keyword": args.keyword}
    else:  # double
        if not args.keyword:
            parser.error("Transposisi Ganda memerlukan --keyword (kunci pertama).")
        if not args.keyword2:
            parser.error("Transposisi Ganda memerlukan --keyword2 (kunci kedua).")
        params = {"key1": args.keyword, "key2": args.keyword2}

    try:
        result = _transpose_text(algo, mode, params, raw, clean, group5)
    except (TypeError, ValueError) as e:
        parser.error(f"Parameter transposisi tidak valid: {e}")

    if args.output_file:
        Path(args.output_file).write_text(result, encoding="utf-8")
        print(f"[+] Hasil {mode} transposisi ({algo}) disimpan ke: {args.output_file}")
    else:
        print(result)


if __name__ == "__main__":
    run_cli_args()