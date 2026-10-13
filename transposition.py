"""
Core Cryptographic Engine: Transposition Ciphers (Keluarga Transposisi)
Perspektif Cyber Security: Implementasi defensif untuk 5 algoritma
transposisi klasik — Rail Fence, Route, Columnar, Double, dan Myszkowski.

Perilaku teks (parameter `clean`):
  clean=False (default): karakter non-alfabetik (spasi, angka, tanda baca) dan
      huruf besar/kecil DI-PERTAHANKAN, sehingga D(E(m)) == m eksak.
  clean=True (mode klasik): strip karakter non-huruf + seluruhnya huruf kapital,
      mengikuti konvensi buku teks kriptografi klasik; output boleh diformat
      menjadi kelompok 5 huruf (hanya pemformatan output, tidak memengaruhi
      isi ciphertext).

Matematika Dasar:
  Semua cipher di sini adalah TRANSPOSISI murni (permutasi posisi huruf),
  bukan substitusi, sehingga distribusi frekuensi huruf tidak berubah —
  hal ini justru menjadi dasar serangan kriptanalisis mereka (lihat laporan).
"""

from pathlib import Path
from typing import Generator, List, Tuple, Union


class _TranspositionBase:
    """Fondasi bersama: validasi tipe, preparasi teks, grup 5, operasi file."""

    @classmethod
    def _prepare(cls, text: str, clean: bool) -> str:
        """
        Menyiapkan teks sebelum transposisi.
        clean=False -> teks apa adanya (preservasi).
        clean=True  -> hanya huruf, semuanya kapital (konvensi klasik).
        """
        if not isinstance(text, str):
            raise TypeError(f"Teks harus bertipe string, diterima: {type(text).__name__}")
        if clean:
            return "".join(ch for ch in text if ch.isalpha()).upper()
        return text

    @classmethod
    def _group5(cls, text: str) -> str:
        """Memformat teks menjadi kelompok 5 huruf (klasik), hanya untuk tampilan."""
        return " ".join(text[i:i + 5] for i in range(0, len(text), 5))

    @staticmethod
    def _resolve_paths(input_path: Union[str, Path], output_path: Union[str, Path]):
        """Memvalidasi path input dan mengembalikan objek Path input & output."""
        in_file = Path(input_path)
        out_file = Path(output_path)
        if not in_file.exists():
            raise FileNotFoundError(f"File input tidak ditemukan: {in_file}")
        return in_file, out_file


class RailFence(_TranspositionBase):
    """
    Transposisi Rail Fence (Zigzag Cipher).
    Teks ditulis mengikuti pola zig-zag menurun/menaik melewati sejumlah rel,
    lalu dibaca baris-per-baris dari atas ke bawah. Kunci = jumlah rel.

    Mathematical note:
      Posisi rel setiap karakter ke-i adalah r = min(i mod period, period - (i mod period)),
      dengan period = 2 * (rails - 1).
    """

    @staticmethod
    def _rail_pos(index: int, rails: int) -> int:
        """Menghitung nomor rel untuk karakter pada posisi `index` (zig-zag)."""
        period = 2 * (rails - 1)
        pos = index % period
        return pos if pos < rails else period - pos

    @classmethod
    def _validate_rails(cls, rails) -> int:
        if isinstance(rails, bool) or not isinstance(rails, int):
            raise TypeError(f"Jumlah rel (rails) harus bilangan bulat, diterima: {type(rails).__name__}")
        return rails

    @classmethod
    def encrypt(cls, text: str, rails: int = 3, clean: bool = False, group5: bool = False) -> str:
        """
        Enkripsi Rail Fence: tulis zig-zag, baca per baris.

        Args:
            text (str):  Plaintext yang akan dienkripsi.
            rails (int): Jumlah rel (baris zig-zag). Default klasik = 3.
            clean (bool): Mode klasik (strip non-huruf + huruf kapital).
            group5 (bool): Format output menjadi kelompok 5 huruf (butuh clean=True).

        Returns:
            str: Ciphertext.
        """
        prepared = cls._prepare(text, clean)
        rails = cls._validate_rails(rails)
        if rails <= 1:
            result = prepared
        else:
            buckets: List[List[str]] = [[] for _ in range(rails)]
            for i, ch in enumerate(prepared):
                buckets[cls._rail_pos(i, rails)].append(ch)
            result = "".join("".join(b) for b in buckets)
        if clean and group5:
            result = cls._group5(result)
        return result

    @classmethod
    def decrypt(cls, ciphertext: str, rails: int = 3, clean: bool = False) -> str:
        """
        Dekripsi Rail Fence: hitung panjang tiap rel, isi ulang, baca zig-zag.

        Kunci agar mantap: jumlah huruf per rel dihitung dengan menelusuri ulang
        pola zig-zag (bukan rumus cycle) sehingga rel terakhir yang pendek tetap
        akurat untuk sembarang panjang teks.
        """
        prepared = cls._prepare(ciphertext, clean)
        rails = cls._validate_rails(rails)
        if rails <= 1:
            return prepared

        n = len(prepared)
        counts = [0] * rails
        for i in range(n):
            counts[cls._rail_pos(i, rails)] += 1

        parts: List[str] = []
        cursor = 0
        for length in counts:
            parts.append(prepared[cursor:cursor + length])
            cursor += length

        out: List[str] = []
        rail_index = [0] * rails
        for i in range(n):
            r = cls._rail_pos(i, rails)
            out.append(parts[r][rail_index[r]])
            rail_index[r] += 1
        return "".join(out)

    @classmethod
    def encrypt_file(cls, input_path, output_path, rails: int = 3, clean: bool = False) -> None:
        in_file, out_file = cls._resolve_paths(input_path, output_path)
        result = cls.encrypt(in_file.read_text(encoding="utf-8"), rails, clean=clean)
        out_file.write_text(result, encoding="utf-8")

    @classmethod
    def decrypt_file(cls, input_path, output_path, rails: int = 3, clean: bool = False) -> None:
        in_file, out_file = cls._resolve_paths(input_path, output_path)
        result = cls.decrypt(in_file.read_text(encoding="utf-8"), rails, clean=clean)
        out_file.write_text(result, encoding="utf-8")


class _KeywordTransposition(_TranspositionBase):
    """
    Transposisi Kolom generik berbasis keyword.
    Teks ditulis ke grid berukuran nrows x ncols (ncols = panjang keyword),
    lalu kolom-kolom dibaca sesuai peringkat abjad huruf keyword.

    Dua konvensi penomoran kunci (dibedakan oleh atribut SHARED_RANK):
      - Columnar (SHARED_RANK=False): huruf identik di keyword diberi peringkat
        BERBEDA, diurutkan dari kiri ke kanan. Contoh TOMATO -> 5 3 2 1 6 4.
      - Myszkowski (SHARED_RANK=True): huruf identik diberi peringkat SAMA dan
        kolomnya dibaca serentak (row-by-row). Contoh TOMATO -> 4 3 2 1 4 3.
    Keyword tanpa huruf berulang membuat kedua konvensi menghasilkan ciphertext
    yang identik (mis. ZEBRA -> 5 3 2 4 1).
    """

    SHARED_RANK = False

    @classmethod
    def _keyword_ranks(cls, keyword: str) -> List[int]:
        """
        Mengonversi keyword menjadi daftar peringkat kolom (1-based).

        Raises:
            TypeError:  keyword bukan string.
            ValueError: keyword kosong (atau hanya berisi non-huruf) setelah dibersihkan.
        """
        if not isinstance(keyword, str):
            raise TypeError(f"Keyword harus bertipe string, diterima: {type(keyword).__name__}")
        cleaned = "".join(ch for ch in keyword if ch.isalpha()).upper()
        if not cleaned:
            raise ValueError("Keyword tidak boleh kosong.")

        n = len(cleaned)
        if cls.SHARED_RANK:
            # Myszkowski: urutkan abjad saja (stable), huruf sama -> peringkat sama.
            order = sorted(range(n), key=lambda i: cleaned[i])
        else:
            # Columnar: urutkan abjad lalu posisi; huruf sama -> peringkat berbeda.
            order = sorted(range(n), key=lambda i: (cleaned[i], i))

        ranks = [0] * n
        if cls.SHARED_RANK:
            rank = 0
            for pos, idx in enumerate(order):
                if pos == 0 or cleaned[idx] != cleaned[order[pos - 1]]:
                    rank += 1
                ranks[idx] = rank
        else:
            for rank, idx in enumerate(order, start=1):
                ranks[idx] = rank
        return ranks

    @classmethod
    def _grid_dims(cls, n: int, ncols: int) -> Tuple[int, int]:
        """Menghitung (nrows, jumlah kolom 'panjang') untuk grid n sel."""
        if n <= 0:
            return 0, 0
        nrows = (n + ncols - 1) // ncols
        long_cols = n % ncols or ncols
        return nrows, long_cols

    @classmethod
    def _columnar_encrypt(cls, text: str, ranks: List[int]) -> str:
        """
        Transposisi kolom - arah maju (enkripsi).
        Menulis baris-demi-baris, membaca per peringkat kolom (naik).
        Konvensi Myszkowski: peringkat ganda dibaca row-by-row melintasi kolom terkait.
        """
        n = len(text)
        ncols = len(ranks)
        if ncols == 1:
            return text
        nrows, _ = cls._grid_dims(n, ncols)

        grid: List[List[Union[str, None]]] = [[None] * ncols for _ in range(nrows)]
        k = 0
        for r in range(nrows):
            for c in range(ncols):
                if k < n:
                    grid[r][c] = text[k]
                    k += 1

        out: List[str] = []
        max_rank = max(ranks)
        for rank in range(1, max_rank + 1):
            cols = [c for c in range(ncols) if ranks[c] == rank]
            if len(cols) == 1:
                c = cols[0]
                for r in range(nrows):
                    if grid[r][c] is not None:
                        out.append(grid[r][c])
            else:
                # Konvensi Myszkowski: baca bersama per baris, kiri ke kanan.
                for r in range(nrows):
                    for c in cols:
                        if grid[r][c] is not None:
                            out.append(grid[r][c])
        return "".join(out)

    @classmethod
    def _columnar_decrypt(cls, ciphertext: str, ranks: List[int]) -> str:
        """
        Transposisi kolom - arah balik (dekripsi).
        Menghitung tinggi tiap kolom dari bentuk grid tergerigit (ragged last row),
        mengisi ciphertext per peringkat, lalu membaca baris-demi-baris.
        """
        n = len(ciphertext)
        ncols = len(ranks)
        if ncols == 1:
            return ciphertext
        nrows, long_cols = cls._grid_dims(n, ncols)

        grid: List[List[Union[str, None]]] = [[None] * ncols for _ in range(nrows)]
        k = 0
        max_rank = max(ranks)
        for rank in range(1, max_rank + 1):
            cols = [c for c in range(ncols) if ranks[c] == rank]
            if len(cols) == 1:
                c = cols[0]
                height = nrows if c < long_cols else nrows - 1
                for r in range(height):
                    grid[r][c] = ciphertext[k]
                    k += 1
            else:
                # Konvensi Myszkowski: isi bersama per baris, kiri ke kanan.
                for r in range(nrows):
                    for c in cols:
                        if c < long_cols or r < nrows - 1:
                            grid[r][c] = ciphertext[k]
                            k += 1
        return "".join(grid[r][c] for r in range(nrows) for c in range(ncols) if grid[r][c] is not None)

    @classmethod
    def encrypt(cls, text: str, keyword: str, clean: bool = False, group5: bool = False) -> str:
        prepared = cls._prepare(text, clean)
        ranks = cls._keyword_ranks(keyword)
        result = cls._columnar_encrypt(prepared, ranks)
        if clean and group5:
            result = cls._group5(result)
        return result

    @classmethod
    def decrypt(cls, ciphertext: str, keyword: str, clean: bool = False) -> str:
        prepared = cls._prepare(ciphertext, clean)
        ranks = cls._keyword_ranks(keyword)
        return cls._columnar_decrypt(prepared, ranks)

    @classmethod
    def encrypt_file(cls, input_path, output_path, keyword: str, clean: bool = False) -> None:
        in_file, out_file = cls._resolve_paths(input_path, output_path)
        result = cls.encrypt(in_file.read_text(encoding="utf-8"), keyword, clean=clean)
        out_file.write_text(result, encoding="utf-8")

    @classmethod
    def decrypt_file(cls, input_path, output_path, keyword: str, clean: bool = False) -> None:
        in_file, out_file = cls._resolve_paths(input_path, output_path)
        result = cls.decrypt(in_file.read_text(encoding="utf-8"), keyword, clean=clean)
        out_file.write_text(result, encoding="utf-8")


class ColumnarTransposition(_KeywordTransposition):
    """
    Transposisi Kolom (Columnar Transposition) — konvensi standar.
    Huruf berulang pada keyword diberi peringkat berbeda dari kiri ke kanan
    (mis. TOMATO -> 5 3 2 1 6 4).
    """

    SHARED_RANK = False


class MyszkowskiTransposition(_KeywordTransposition):
    """
    Transposisi Myszkowski (1902) — varian Columnar.
    Huruf berulang pada keyword diberi peringkat SAMA dan kolom terkait dibaca
    serentak per baris (mis. TOMATO -> 4 3 2 1 4 3).
    """

    SHARED_RANK = True


class DoubleTransposition(_TranspositionBase):
    """
    Transposisi Ganda (Double / Two-Columnar Transposition).
    Enkripsi = Columnar dengan keyword1, lalu hasilnya di-Columnar lagi dengan
    keyword2. Dekripsi = kebalikannya (keyword2 dulu, lalu keyword1).
    Penerapan ganda menggandakan diffusion sehingga jauh lebih kokoh terhadap
    serangan analisis frekuensi daripada Columnar tunggal.
    """

    @classmethod
    def encrypt(cls, text: str, key1: str, key2: str, clean: bool = False, group5: bool = False) -> str:
        prepared = cls._prepare(text, clean)
        ranks1 = ColumnarTransposition._keyword_ranks(key1)
        ranks2 = ColumnarTransposition._keyword_ranks(key2)
        middle = ColumnarTransposition._columnar_encrypt(prepared, ranks1)
        result = ColumnarTransposition._columnar_encrypt(middle, ranks2)
        if clean and group5:
            result = cls._group5(result)
        return result

    @classmethod
    def decrypt(cls, ciphertext: str, key1: str, key2: str, clean: bool = False) -> str:
        prepared = cls._prepare(ciphertext, clean)
        ranks1 = ColumnarTransposition._keyword_ranks(key1)
        ranks2 = ColumnarTransposition._keyword_ranks(key2)
        middle = ColumnarTransposition._columnar_decrypt(prepared, ranks2)
        return ColumnarTransposition._columnar_decrypt(middle, ranks1)

    @classmethod
    def encrypt_file(cls, input_path, output_path, key1: str, key2: str, clean: bool = False) -> None:
        in_file, out_file = cls._resolve_paths(input_path, output_path)
        result = cls.encrypt(in_file.read_text(encoding="utf-8"), key1, key2, clean=clean)
        out_file.write_text(result, encoding="utf-8")

    @classmethod
    def decrypt_file(cls, input_path, output_path, key1: str, key2: str, clean: bool = False) -> None:
        in_file, out_file = cls._resolve_paths(input_path, output_path)
        result = cls.decrypt(in_file.read_text(encoding="utf-8"), key1, key2, clean=clean)
        out_file.write_text(result, encoding="utf-8")


class RouteCipher(_TranspositionBase):
    """
    Transposisi Route (Route Cipher).
    Plaintext ditulis ke grid baris-demi-baris, lalu dibaca mengikuti sebuah
    jalur (route) berbelit — spiral, serpentine, dll. Kunci = lebar grid + rute.

    Round-trip presisi (tanpa padding): hanya sel yang terisi plaintext yang
    dipakai; rute dilewati pada sel kosong baris terakhir yang tergerigit.
    Karena itu panjang ciphertext LESTARI dan D(E(m)) == m eksak.

    Rute yang tersedia:
      spiral_tl/tr/bl/br : spiral searah jarum jam ke dalam dari tiap sudut.
      serp_tl            : baris menyilang (boustrophedon) dari kiri-atas.
      serp_br            : baris menyilang dimulai kanan-bawah.
      rows_lr / rows_rl  : baris kiri-kanan / kanan-kiri.
      cols_td            : kolom atas-bawah.
    """

    ROUTE_CHOICES = (
        "spiral_tl", "spiral_tr", "spiral_bl", "spiral_br",
        "serp_tl", "serp_br", "rows_lr", "rows_rl", "cols_td",
    )

    @staticmethod
    def _validate_width(width) -> int:
        if isinstance(width, bool) or not isinstance(width, int):
            raise TypeError(f"Lebar grid harus bilangan bulat, diterima: {type(width).__name__}")
        if width <= 0:
            raise ValueError("Lebar grid harus lebih besar dari 0.")
        return width

    @classmethod
    def _row_lengths(cls, nrows: int, ncols: int, n: int) -> List[int]:
        """Panjang baris pada grid tergerigit yang memuat tepat n sel."""
        if n <= 0:
            return [0] * nrows
        long_cols = n % ncols or ncols
        return [ncols if r < n // ncols else long_cols for r in range(nrows)]

    @classmethod
    def _spiral_cells(cls, nrows: int, ncols: int, corner: str) -> Generator[Tuple[int, int], None, None]:
        """
        Generator sel (r, c) spiral searah jarum jam ke dalam, dimulai dari satu
        sudut tertentu ('tl' / 'tr' / 'bl' / 'br'). Bijection pada box penuh.
        """
        if nrows <= 0 or ncols <= 0:
            return
        top, left = 0, 0
        bottom, right = nrows - 1, ncols - 1
        directions = ((0, 1), (1, 0), (0, -1), (-1, 0))  # kanan, bawah, kiri, atas
        start_dir = {"tl": 0, "tr": 1, "br": 2, "bl": 3}[corner]
        r = {"tl": top, "tr": top, "br": bottom, "bl": bottom}[corner]
        c = {"tl": left, "tr": right, "br": right, "bl": left}[corner]
        d = start_dir

        while True:
            yield (r, c)
            dr, dc = directions[d]
            nr, nc = r + dr, c + dc
            if top <= nr <= bottom and left <= nc <= right:
                r, c = nr, nc
                continue
            # Sisi habis: kecilkan box, lalu belok.
            if d == 0:
                top += 1
            elif d == 1:
                right -= 1
            elif d == 2:
                bottom -= 1
            else:
                left += 1
            if top > bottom or left > right:
                break
            d = (d + 1) % 4
            dr, dc = directions[d]
            nr, nc = r + dr, c + dc
            if not (top <= nr <= bottom and left <= nc <= right):
                break
            r, c = nr, nc

    @classmethod
    def _route_cells(cls, nrows: int, ncols: int, route: str) -> List[Tuple[int, int]]:
        """Daftar koordinat grid penuh yang dilintasi sebuah rute."""
        if route not in cls.ROUTE_CHOICES:
            raise ValueError(
                f"Rute tidak dikenal: {route!r}. Rute tersedia: {', '.join(cls.ROUTE_CHOICES)}"
            )
        if route.startswith("spiral_"):
            return list(cls._spiral_cells(nrows, ncols, route.split("_", 1)[1]))

        cells: List[Tuple[int, int]] = []
        if route == "serp_tl":
            for r in range(nrows):
                row = [(r, c) for c in range(ncols)]
                cells.extend(row if r % 2 == 0 else reversed(row))
        elif route == "serp_br":
            for offset in range(nrows):
                r = nrows - 1 - offset
                row = [(r, c) for c in range(ncols)]
                cells.extend(row if offset % 2 == 0 else reversed(row))
        elif route == "rows_lr":
            for r in range(nrows):
                cells.extend((r, c) for c in range(ncols))
        elif route == "rows_rl":
            for r in range(nrows):
                cells.extend((r, c) for c in range(ncols - 1, -1, -1))
        elif route == "cols_td":
            for c in range(ncols):
                cells.extend((r, c) for r in range(nrows))
        return cells

    @classmethod
    def encrypt(cls, text: str, width: int = 5, route: str = "spiral_tl",
                clean: bool = False, group5: bool = False) -> str:
        """
        Enkripsi Route: tulis grid baris-demi-baris, baca mengikuti rute
        (lewati sel kosong baris tergerigit) -> ciphertext panjang LESTARI.
        """
        width = cls._validate_width(width)
        if route not in cls.ROUTE_CHOICES:
            raise ValueError(f"Rute tidak dikenal: {route!r}. Rute tersedia: {', '.join(cls.ROUTE_CHOICES)}")
        prepared = cls._prepare(text, clean)

        n = len(prepared)
        if n <= 1 or width == 1:
            result = prepared
        else:
            nrows = (n + width - 1) // width
            rlens = cls._row_lengths(nrows, width, n)
            grid: List[List[Union[str, None]]] = [[None] * width for _ in range(nrows)]
            k = 0
            for r in range(nrows):
                for c in range(rlens[r]):
                    grid[r][c] = prepared[k]
                    k += 1
            chars = [grid[r][c] for (r, c) in cls._route_cells(nrows, width, route) if c < rlens[r]]
            result = "".join(chars)

        if clean and group5:
            result = cls._group5(result)
        return result

    @classmethod
    def decrypt(cls, ciphertext: str, width: int = 5, route: str = "spiral_tl",
                clean: bool = False) -> str:
        """
        Dekripsi Route: isi ulang grid mengikuti rute, lalu baca baris-demi-baris.
        Invers eksak dari encrypt untuk sembarang panjang teks (ragged aman).
        """
        width = cls._validate_width(width)
        if route not in cls.ROUTE_CHOICES:
            raise ValueError(f"Rute tidak dikenal: {route!r}. Rute tersedia: {', '.join(cls.ROUTE_CHOICES)}")
        prepared = cls._prepare(ciphertext, clean)

        n = len(prepared)
        if n <= 1 or width == 1:
            return prepared
        nrows = (n + width - 1) // width
        rlens = cls._row_lengths(nrows, width, n)
        grid: List[List[Union[str, None]]] = [[None] * width for _ in range(nrows)]
        k = 0
        for (r, c) in cls._route_cells(nrows, width, route):
            if c < rlens[r]:
                grid[r][c] = prepared[k]
                k += 1
        return "".join(grid[r][c] for r in range(nrows) for c in range(rlens[r]))

    @classmethod
    def encrypt_file(cls, input_path, output_path, width: int = 5, route: str = "spiral_tl",
                     clean: bool = False) -> None:
        in_file, out_file = cls._resolve_paths(input_path, output_path)
        result = cls.encrypt(in_file.read_text(encoding="utf-8"), width, route, clean=clean)
        out_file.write_text(result, encoding="utf-8")

    @classmethod
    def decrypt_file(cls, input_path, output_path, width: int = 5, route: str = "spiral_tl",
                     clean: bool = False) -> None:
        in_file, out_file = cls._resolve_paths(input_path, output_path)
        result = cls.decrypt(in_file.read_text(encoding="utf-8"), width, route, clean=clean)
        out_file.write_text(result, encoding="utf-8")