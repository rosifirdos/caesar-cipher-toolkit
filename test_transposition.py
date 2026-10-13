"""
Unit Testing & Security Verification Suite: Transposition Ciphers
Memverifikasi 5 algoritma transposisi (Rail Fence, Route, Columnar, Double,
Myszkowski) terhadap vektor kanonik publik serta invariant bulat penuh:
  D( E(m) ) == m   (preserve mode, panjang LESTARI)
  D( E(clean m) ) == clean m   (clean/klasik mode)
"""

import unittest

from transposition import (
    ColumnarTransposition,
    DoubleTransposition,
    MyszkowskiTransposition,
    RailFence,
    RouteCipher,
)

# ---------------------------------------------------------------------------
# Vektor kanonik yang DIVERIFIKASI terhadap publikasi terpercaya:
#  - Rail Fence 3-rel "WEAREDISCOVEREDFLEEATONCE" -> canonical Challenge vector.
#  - Myszkowski TOMATO (pad X, 7x6) -> crypto.interactive-maths.com (byte-identical).
# ---------------------------------------------------------------------------


class TestRailFence(unittest.TestCase):
    """Transposisi Rail Fence"""

    def test_canonical_vector(self):
        """WEAREDISCOVEREDFLEEATONCE dengan 3 rel -> vektor kanonik publik."""
        plain = "WEAREDISCOVEREDFLEEATONCE"
        expected = "WECRLTEERDSOEEFEAOCAIVDEN"
        self.assertEqual(RailFence.encrypt(plain, rails=3), expected)
        self.assertEqual(RailFence.decrypt(expected, rails=3), plain)

    def test_preserve_symbols_and_mixed_case(self):
        """Spasi, angka, tanda baca, dan huruf kapital dipertahankan (mode default)."""
        plain = "HELLO WORLD 123!"
        expected = "HREOL!LWD3L  2O1"
        self.assertEqual(RailFence.encrypt(plain, rails=5), expected)
        self.assertEqual(RailFence.decrypt(expected, rails=5), plain)

    def test_ragged_last_rail(self):
        """Panjang bukan kelipatan perioda zig-zag -> dekripsi tetap eksak."""
        plain = "KRIPTOGRAFI KLASIK"
        expected = "KGKROR LKITAIAIPFS"
        self.assertEqual(RailFence.encrypt(plain, rails=4), expected)
        self.assertEqual(RailFence.decrypt(expected, rails=4), plain)

    def test_identity_for_single_rail(self):
        """rails <= 1 adalah transformasi identitas (bukan error)."""
        plain = "PESAN RAHASIA"
        self.assertEqual(RailFence.encrypt(plain, rails=1), plain)
        self.assertEqual(RailFence.decrypt(plain, rails=1), plain)

    def test_empty_and_tiny_texts(self):
        """Teks kosong / sangat pendek tidak merusak invariant."""
        samples = ["", "A", "AB", "ABC", "AB CD"]
        for text in samples:
            for rails in (1, 2, 3, 5, 8):
                self.assertEqual(RailFence.decrypt(RailFence.encrypt(text, rails), rails), text)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            RailFence.encrypt(12345, rails=3)
        with self.assertRaises(TypeError):
            RailFence.encrypt("teks", rails="tiga")


class TestColumnarTransposition(unittest.TestCase):
    """Transposisi Kolom (konvensi standar: huruf berulang diberi peringkat berbeda)"""

    def test_keyword_example(self):
        """ZEBRA pada plaintext canonical (tidak memuat huruf berulang)."""
        plain = "WEAREDISCOVEREDFLEEATONCE"
        expected = "EODAEASRENEIELORCEECWDVFT"
        self.assertEqual(ColumnarTransposition.encrypt(plain, "ZEBRA"), expected)
        self.assertEqual(ColumnarTransposition.decrypt(expected, "ZEBRA"), plain)

    def test_repeated_keyword_distinct_ranks(self):
        """TOMATO -> peringkat 5 3 2 1 6 4 (Columnar distinct-rank)."""
        ranks = ColumnarTransposition._keyword_ranks("TOMATO")
        self.assertEqual(ranks, [5, 3, 2, 1, 6, 4])

    def test_ragged_round_trip(self):
        """n tidak kelipatan ncols -> grid tergerigit tetap bulat sempurna."""
        texts = [
            "PESAN SANGAT RAHASIA DARI UPGRIS",
            "WEAREDISCOVEREDFLEEATONCE",
            "a", "ab", "abc", "abcde",
            "Keamanan Siber @2026",
        ]
        keywords = ["ZEBRA", "KRIPTO", "INDONESIA", "AB", "A", "TOMATO"]
        for text in texts:
            for keyword in keywords:
                enc = ColumnarTransposition.encrypt(text, keyword)
                self.assertEqual(len(enc), len(text), f"panjang berubah: {text!r}/{keyword}")
                self.assertEqual(ColumnarTransposition.decrypt(enc, keyword), text)

    def test_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            ColumnarTransposition.encrypt("teks", 123)
        with self.assertRaises(ValueError):
            ColumnarTransposition.encrypt("teks", "")
        with self.assertRaises(ValueError):
            ColumnarTransposition.encrypt("teks", "123 !@#")  # bersih -> kosong


class TestMyszkowskiTransposition(unittest.TestCase):
    """Transposisi Myszkowski (konvensi shared-rank untuk huruf berulang)"""

    def test_shared_rank(self):
        """TOMATO -> peringkat 4 3 2 1 4 3 (huruf sama, peringkat sama)."""
        ranks = MyszkowskiTransposition._keyword_ranks("TOMATO")
        self.assertEqual(ranks, [4, 3, 2, 1, 4, 3])

    def test_published_example(self):
        """Reproduksi persis contoh publik (kripto.interactive-maths.com), null-padded."""
        plain = "THETOMATOISAPLANTINTHENIGHTSHADEFAMILY"
        # Pad 42 huruf (7 baris x 6 kolom) ala tutorial: 38 huruf + 4 null 'X'.
        padded = plain + "XXXX"
        expected = "TINESAXEOAHTFXHMTALITIHAEIYXTOASPTNNGHDMLX"
        self.assertEqual(MyszkowskiTransposition.encrypt(padded, "TOMATO"), expected)
        self.assertEqual(MyszkowskiTransposition.decrypt(expected, "TOMATO"), padded)

    def test_no_padding_vector(self):
        """Tanpa null padding: plaintext di bawah contoh publik, baris akhir tergerigit."""
        plain = "THETOMATOISAPLANTINTHENIGHTSHADEFAMILY"
        expected = "TINESAEOAHTFHMTALITIHAEIYTOASPTNNGHDML"
        self.assertEqual(MyszkowskiTransposition.encrypt(plain, "TOMATO"), expected)
        self.assertEqual(MyszkowskiTransposition.decrypt(expected, "TOMATO"), plain)

    def test_differs_from_columnar_on_repeated_keyword(self):
        """Konvensi tie-breaking berbeda => ciphertext berbeda untuk keyword berulang."""
        plain = "THETOMATOISAPLANTINTHENIGHTSHADEFAMILY"
        columnar = ColumnarTransposition.encrypt(plain, "TOMATO")
        myszkowski = MyszkowskiTransposition.encrypt(plain, "TOMATO")
        self.assertNotEqual(columnar, myszkowski)

    def test_no_repeat_equals_columnar(self):
        """Keyword tanpa huruf berulang -> kedua konvensi menghasilkan ciphertext sama."""
        plain = "WEAREDISCOVEREDFLEEATONCE"
        self.assertEqual(
            ColumnarTransposition.encrypt(plain, "ZEBRA"),
            MyszkowskiTransposition.encrypt(plain, "ZEBRA"),
        )

    def test_round_trip_ragged(self):
        """Round-trip penuh berbagai keyword berulang & panjang ragged."""
        texts = [
            "PESAN SANGAT RAHASIA DARI UPGRIS",
            "KRIPTOGRAFI KLASIK 2026",
            "BERANGKAT PAGI PAGI",
            "a", "aa", "aba",
        ]
        keywords = ["TOMATO", "MAMMAL", "ABAB", "A", "BANANA", "INDONESIA"]
        for text in texts:
            for keyword in keywords:
                enc = MyszkowskiTransposition.encrypt(text, keyword)
                self.assertEqual(len(enc), len(text))
                self.assertEqual(MyszkowskiTransposition.decrypt(enc, keyword), text)


class TestDoubleTransposition(unittest.TestCase):
    """Transposisi Ganda (Columnar dua tahap)"""

    def test_round_trip(self):
        texts = [
            "WEAREDISCOVEREDFLEEATONCE",
            "PESAN SANGAT RAHASIA DARI UPGRIS",
            "KRIPTOGRAFI KLASIK 2026",
            "a", "abcd", "abcde",
        ]
        key_pairs = [
            ("ZEBRA", "KRIPTO"),
            ("TOMATO", "BANANA"),
            ("A", "ZEBRA"),
            ("INDONESIA", "MERDEKA"),
        ]
        for text in texts:
            for k1, k2 in key_pairs:
                enc = DoubleTransposition.encrypt(text, k1, k2)
                self.assertEqual(len(enc), len(text))
                self.assertEqual(DoubleTransposition.decrypt(enc, k1, k2), text)

    def test_differs_from_single(self):
        """Dua tahap Columnar mengubah ciphertext terhadap Columnar tunggal."""
        plain = "WEAREDISCOVEREDFLEEATONCE"
        single = ColumnarTransposition.encrypt(plain, "ZEBRA")
        double = DoubleTransposition.encrypt(plain, "ZEBRA", "KRIPTO")
        self.assertNotEqual(single, double)


class TestRouteCipher(unittest.TestCase):
    """Transposisi Route (rute + lebar grid)"""

    def test_all_routes_round_trip(self):
        """Semua rute terkurasi, berbagai lebar dan panjang tekstur round-trip eksak."""
        texts = [
            "WEAREDISCOVEREDFLEEATONCE",
            "HELLO WORLD 123!",
            "PESAN SANGAT RAHASIA DARI UPGRIS",
            "a", "ab", "abcde", "abcdefghijklm",  # panjang menyentuh beberapa baris
            "Keamanan Siber @2026",
            "",
        ]
        widths = [2, 3, 5, 7, 10]
        for route in RouteCipher.ROUTE_CHOICES:
            for width in widths:
                for text in texts:
                    enc = RouteCipher.encrypt(text, width, route)
                    self.assertEqual(len(enc), len(text),
                                     f"panjang berubah route={route} w={width}: {text!r}")
                    self.assertEqual(RouteCipher.decrypt(enc, width, route), text)

    def test_specific_vectors(self):
        """Vektor konkret untuk beberapa (lebar, rute)."""
        cases = [
            ("WEAREDISCOVEREDFLEEATONCE", 5, "spiral_tl", "WEAREODAECNOTFVDISCEEELER"),
            ("CRYPTOGRAPHY", 4, "serp_tl", "CRYPRGOTAPHY"),
            ("TRANSPOSITIONCIPHER", 6, "spiral_br", "RNOTRANSPOEHPICSITI"),
        ]
        for plain, width, route, expected in cases:
            with self.subTest(route=route, width=width):
                self.assertEqual(RouteCipher.encrypt(plain, width, route), expected)
                self.assertEqual(RouteCipher.decrypt(expected, width, route), plain)

    def test_route_preserves_length(self):
        """Tanpa padding, panjang ciphertext selalu sama dengan panjang plaintext."""
        for route in RouteCipher.ROUTE_CHOICES:
            for width in (2, 4, 7):
                self.assertEqual(len(RouteCipher.encrypt("PESAN SANGAT RAHASIA", width, route)),
                                 len("PESAN SANGAT RAHASIA"))

    def test_validate_errors(self):
        with self.assertRaises(ValueError):
            RouteCipher.encrypt("teks", width=0)
        with self.assertRaises(TypeError):
            RouteCipher.encrypt("teks", width="lima")
        with self.assertRaises(ValueError):
            RouteCipher.encrypt("teks", width=5, route="tidak-ada")
        with self.assertRaises(TypeError):
            RouteCipher.encrypt(42, width=5)


class TestCleanMode(unittest.TestCase):
    """Mode klasik (clean): strip non-huruf + kapital, opsi format kelompok 5"""

    @staticmethod
    def _clean(text: str) -> str:
        return "".join(ch for ch in text if ch.isalpha()).upper()

    def test_group5_is_output_formatting_only(self):
        """group5 menambah spasi berpola ke output; isi ciphertext normal tanpa spasi."""
        plain = "PESAN SANGAT RAHASIA DARI UPGRIS"
        clean_plain = self._clean(plain)
        enc_clean = ColumnarTransposition.encrypt(clean_plain, "ZEBRA")
        enc_group = ColumnarTransposition.encrypt(clean_plain, "ZEBRA", clean=True, group5=True)
        # group5 menstimkan spasi header; strip untuk membandingkan isi.
        self.assertEqual(enc_group.replace(" ", ""), enc_clean)

    def test_clean_round_trip(self):
        """D(E(clean m)) == clean m untuk semua cipher (nilai ekspektasi versi super)."""
        samples = [
            "PESAN SANGAT RAHASIA DARI UPGRIS",
            "The quick brown fox jumps 12345!",
            "Kriptografi Klasik.",
        ]
        rails, width = 4, 6
        for raw in samples:
            clean_plain = self._clean(raw)
            self.assertEqual(RailFence.decrypt(RailFence.encrypt(clean_plain, rails, clean=True), rails, clean=True),
                             clean_plain)
            self.assertEqual(RouteCipher.decrypt(RouteCipher.encrypt(clean_plain, width, "serp_tl", clean=True),
                                                 width, "serp_tl", clean=True), clean_plain)
            self.assertEqual(ColumnarTransposition.decrypt(ColumnarTransposition.encrypt(clean_plain, "ZEBRA", clean=True),
                                                           "ZEBRA", clean=True), clean_plain)
            self.assertEqual(MyszkowskiTransposition.decrypt(MyszkowskiTransposition.encrypt(clean_plain, "TOMATO", clean=True),
                                                             "TOMATO", clean=True), clean_plain)
            self.assertEqual(DoubleTransposition.decrypt(DoubleTransposition.encrypt(clean_plain, "ZEBRA", "KRIPTO", clean=True),
                                                         "ZEBRA", "KRIPTO", clean=True), clean_plain)


class TestFileOperations(unittest.TestCase):
    """Enkripsi/dekripsi berbasis file untuk semua cipher transposisi"""

    import tempfile
    from pathlib import Path

    def _round_trip_file(self, cipher, enc_kw, dec_kw, data):
        with self.tempfile.TemporaryDirectory() as tmpdir:
            tmp = self.Path(tmpdir)
            in_file = tmp / "plain.txt"
            enc_file = tmp / "enc.txt"
            dec_file = tmp / "dec.txt"
            in_file.write_text(data, encoding="utf-8")
            cipher.encrypt_file(in_file, enc_file, **enc_kw)
            cipher.decrypt_file(enc_file, dec_file, **dec_kw)
            self.assertEqual(dec_file.read_text(encoding="utf-8"), data)

    def test_rail_fence_file(self):
        self._round_trip_file(RailFence, {"rails": 4}, {"rails": 4}, "PESAN RAHASIA DARI UPGRIS")

    def test_columnar_file(self):
        self._round_trip_file(ColumnarTransposition, {"keyword": "ZEBRA"}, {"keyword": "ZEBRA"},
                              "Dokumen Kriptografi Klasik 2026.")

    def test_myszkowski_file(self):
        self._round_trip_file(MyszkowskiTransposition, {"keyword": "TOMATO"}, {"keyword": "TOMATO"},
                              "BERANGKAT PAGI MENUJU KAMPUS UPGRIS")

    def test_double_file(self):
        self._round_trip_file(DoubleTransposition,
                              {"key1": "ZEBRA", "key2": "KRIPTO"},
                              {"key1": "ZEBRA", "key2": "KRIPTO"},
                              "Serangan Siber Mengancam Infrastruktur Kritis Nasional.")

    def test_route_file(self):
        self._round_trip_file(RouteCipher,
                              {"width": 5, "route": "spiral_tl"},
                              {"width": 5, "route": "spiral_tl"},
                              "The quick brown fox jumps over the lazy dog.")


if __name__ == "__main__":
    unittest.main()