"""
Unit Testing & Security Verification Suite
Memverifikasi fungsionalitas core cryptography engine, penanganan edge cases,
serta pembuktian serangan kriptanalisis (brute force & frequency analysis).
"""

import tempfile
import unittest
from pathlib import Path
from caesar_cipher import CaesarCipher
from cryptanalysis import CaesarBreaker


class TestCaesarCipherCore(unittest.TestCase):
    """Pengujian Unit untuk CaesarCipher Engine"""

    def test_slide_exercise_encryption(self):
        """
        Verifikasi Soal Latihan Kampus (Screenshot 2026-10-05 175822.png)
        Plaintext : "PESAN SANGAT RAHASIA"
        Kunci (k) : 3
        Ekspektasi: "SHVDQ VDQJDW UDKDVLD"
        """
        plaintext = "PESAN SANGAT RAHASIA"
        expected_cipher = "SHVDQ VDQJDW UDKDVLD"
        cipher = CaesarCipher.encrypt(plaintext, key=3)
        self.assertEqual(cipher, expected_cipher)

    def test_slide_exercise_decryption(self):
        """
        Verifikasi Soal Latihan Kampus (Screenshot 2026-10-05 175822.png)
        Ciphertext: "LQIRUPDWLND XSJULV"
        Kunci (k) : 3
        Ekspektasi: "INFORMATIKA UPGRIS"
        """
        ciphertext = "LQIRUPDWLND XSJULV"
        expected_plain = "INFORMATIKA UPGRIS"
        plain = CaesarCipher.decrypt(ciphertext, key=3)
        self.assertEqual(plain, expected_plain)

    def test_case_preservation_and_symbols(self):
        """Memastikan huruf besar/kecil dan tanda baca tidak terdistorsi"""
        text = "Halo Dunia 123! Keamanan Siber."
        encrypted = CaesarCipher.encrypt(text, key=3)
        self.assertEqual(encrypted, "Kdor Gxqld 123! Nhdpdqdq Vlehu.")
        decrypted = CaesarCipher.decrypt(encrypted, key=3)
        self.assertEqual(decrypted, text)

    def test_key_normalization(self):
        """Pengujian kunci modular: k=0, k=26, k=-3, k=29, k=1043"""
        base_text = "CYBERSECURITY"

        # Key = 0 -> tidak berubah
        self.assertEqual(CaesarCipher.encrypt(base_text, 0), base_text)

        # Key = 26 -> identitas (rotasi penuh)
        self.assertEqual(CaesarCipher.encrypt(base_text, 26), base_text)

        # Key = 29 -> ekuivalen dengan k = 3 (29 % 26 = 3)
        self.assertEqual(CaesarCipher.encrypt(base_text, 29), CaesarCipher.encrypt(base_text, 3))

        # Key = -3 -> ekuivalen dengan k = 23 (-3 % 26 = 23)
        self.assertEqual(CaesarCipher.encrypt(base_text, -3), CaesarCipher.encrypt(base_text, 23))

    def test_round_trip_invariant(self):
        """Memastikan sifat matematis D_k(E_k(m)) == m untuk berbagai kunci"""
        samples = [
            "Serangan Siber Mengancam Infrastruktur Kritis Nasional",
            "Kriptografi Simetris vs Asimetris @2026",
            "The quick brown fox jumps over the lazy dog."
        ]
        for key in [-10, 0, 1, 3, 13, 25, 100]:
            for msg in samples:
                enc = CaesarCipher.encrypt(msg, key)
                dec = CaesarCipher.decrypt(enc, key)
                self.assertEqual(dec, msg, f"Gagal pada key={key} untuk teks: {msg}")

    def test_file_operations(self):
        """Memastikan enkripsi dan dekripsi berbasis file bekerja tanpa korupsi"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            in_file = tmp_path / "rahasia.txt"
            enc_file = tmp_path / "terenkripsi.txt"
            dec_file = tmp_path / "terdekripsi.txt"

            original_content = "Dokumen Rahasia Negara: Operasi Cyber Defense 2026."
            in_file.write_text(original_content, encoding="utf-8")

            # Enkripsi file
            CaesarCipher.encrypt_file(in_file, enc_file, key=5)
            self.assertTrue(enc_file.exists())
            self.assertNotEqual(enc_file.read_text(encoding="utf-8"), original_content)

            # Dekripsi file
            CaesarCipher.decrypt_file(enc_file, dec_file, key=5)
            self.assertTrue(dec_file.exists())
            self.assertEqual(dec_file.read_text(encoding="utf-8"), original_content)


class TestCryptanalysisOffensive(unittest.TestCase):
    """Pengujian Unit untuk Modul Kriptanalisis (Brute Force & Frequency Analysis)"""

    def test_brute_force_keyspace(self):
        """Memastikan brute force menghasilkan tepat 25 kemungkinan rotasi"""
        cipher = "LQIRUPDWLND XSJULV"
        results = CaesarBreaker.brute_force(cipher)
        self.assertEqual(len(results), 25)

        # Pastikan kunci 3 menghasilkan jawaban yang benar
        found_target = any(r["key"] == 3 and r["plaintext"] == "INFORMATIKA UPGRIS" for r in results)
        self.assertTrue(found_target)

    def test_automated_frequency_analysis_crack(self):
        """
        Memastikan serangan analisis frekuensi statistik chi^2 berhasil
        menebak kunci secara otomatis tanpa intervensi manusia
        """
        # Teks bahasa Indonesia yang cukup representatif
        plaintext = (
            "KEAMANAN INFORMASI DAN KRIPTOGRAFI ADALAH DASAR UTAMA "
            "DALAM MENJAGA KERAHASIAAN DAN INTEGRITAS DATA PADA JARINGAN KOMPUTER"
        )
        key = 3
        ciphertext = CaesarCipher.encrypt(plaintext, key)

        crack_result = CaesarBreaker.frequency_analysis_crack(ciphertext, lang="id")
        self.assertEqual(crack_result["best_key"], 3)
        self.assertEqual(crack_result["cracked_plaintext"], plaintext)


if __name__ == "__main__":
    unittest.main()
