"""
Aplikasi Caesar Cipher & Cryptanalysis Toolkit
Perspektif: Cyber Security & Cryptography Evaluation
Mendukung Mode Interaktif (CLI Menu) dan Mode Otomasi (Command Line Arguments).
"""

import argparse
import sys
from pathlib import Path
from caesar_cipher import CaesarCipher
from cryptanalysis import CaesarBreaker


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
"""


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
        print("  0. Keluar")

        choice = input("\nPilih opsi [0-6]: ").strip()

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
    )

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("-e", "--encrypt", action="store_true", help="Lakukan enkripsi")
    action_group.add_argument("-d", "--decrypt", action="store_true", help="Lakukan dekripsi")
    action_group.add_argument("-b", "--brute-force", action="store_true", help="Jalankan serangan brute-force (25 shift)")
    action_group.add_argument("-c", "--auto-crack", action="store_true", help="Jalankan serangan analisis frekuensi otomatis")
    action_group.add_argument("--advisory", action="store_true", help="Tampilkan laporan analisis keamanan siber")

    parser.add_argument("-k", "--key", type=int, default=3, help="Kunci pergeseran (shift value, default: 3)")
    parser.add_argument("-t", "--text", type=str, help="Teks input untuk diproses")
    parser.add_argument("-i", "--input-file", type=str, help="Path file input (.txt)")
    parser.add_argument("-o", "--output-file", type=str, help="Path file output (.txt)")
    parser.add_argument("--lang", type=str, default="id", choices=["id", "en"], help="Bahasa target untuk analisis frekuensi (id/en)")

    args = parser.parse_args()

    # Jika dijalankan tanpa argumen apa pun, luncurkan mode interaktif
    if len(sys.argv) == 1:
        run_interactive()
        return

    if args.advisory:
        print(ADVISORY_TEXT)
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


if __name__ == "__main__":
    run_cli_args()
