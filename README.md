# Caesar Cipher & Cryptanalysis Toolkit (Python)

Aplikasi kriptografi **Caesar Cipher & Transposisi Klasik** yang dikembangkan dengan pendekatan **Cyber Security (Defensive & Offensive Kriptanalisis)**. Toolkit mencakup dua keluarga besar cipher klasik:

- **Substitusi:** Caesar Shift (enkripsi/dekripsi + modul kriptanalisis).
- **Transposisi:** Rail Fence, Route, Columnar, Double, Myszkowski (enkripsi/dekripsi).

---

## 🎯 Pembahasan Jawaban Soal Latihan Kampus

Berdasarkan soal latihan pada slide kuliah:

### 1. Latihan Caesar Cipher 1 (`Screenshot 2026-10-05 175822.png`)
* **Plaintext:** `PESAN SANGAT RAHASIA`
* **Kunci (k):** `3` (Julius Caesar Standard Shift)
* **Ciphertext:** `SHVDQ VDQJDW UDKDVLD`

### 2. Latihan Caesar Cipher 2 (`Screenshot 2026-10-05 175822.png`)
* **Ciphertext:** `LQIRUPDWLND XSJULV`
* **Kunci (k):** `3`
* **Plaintext:** `INFORMATIKA UPGRIS`

---

## 📁 Struktur File Proyek

```text
D:\portofolio\caesar-cipher-toolkit\
│
├── caesar_cipher.py        # Core Cryptography Engine (Enkripsi, Dekripsi, File Ops) - Substitusi
├── cryptanalysis.py        # Offensive Module (Brute Force 25 shifts & Chi-Squared Auto Crack)
├── transposition.py        # Core Cryptography Engine - Keluarga Transposisi (5 Algoritma)
├── app.py                  # User Interface (CLI Interaktif & Terminal Flags Parser)
├── desktop_app.py          # Versi Desktop GUI (CustomTkinter) - 7 tab mirror CLI + fitur UX
├── requirements.txt        # Dependensi versi desktop (customtkinter)
├── test_caesar.py          # Unit Test Suite (Substitusi Caesar & Kriptanalisis)
├── test_transposition.py   # Unit Test Suite (Keluarga Transposisi - 29 tes, vektor terverifikasi)
├── SECURITY_ANALYSIS.md    # Laporan Analisis Keamanan Siber & Threat Modeling
└── README.md               # Dokumentasi panduan penggunaan
```

---

## 🚀 Cara Menjalankan Aplikasi

Aplikasi tidak membutuhkan dependensi eksternal (menggunakan *Python Standard Library*).

### 1. Mode Menu Interaktif
Jalankan aplikasi tanpa argumen untuk masuk ke menu interaktif:
```bash
python app.py
```

Menu yang tersedia:
1. Enkripsi Teks (Shift Cipher)
2. Dekripsi Teks (Shift Cipher)
3. Enkripsi / Dekripsi File (.txt)
4. Kriptanalisis: Serangan Brute Force (Tampilkan 25 Variasi)
5. Kriptanalisis: Serangan Frekuensi Otomatis (Chi-Squared Test)
6. Cyber Security Threat Model & Advisory
7. Kriptografi Transposisi (5 Algoritma)
0. Keluar

---

### 2. Mode Command Line Arguments (CLI / Automasi)


#### A. Enkripsi Teks
```bash
python app.py -e -k 3 -t "PESAN SANGAT RAHASIA"
# Output: SHVDQ VDQJDW UDKDVLD
```

#### B. Dekripsi Teks
```bash
python app.py -d -k 3 -t "LQIRUPDWLND XSJULV"
# Output: INFORMATIKA UPGRIS
```

#### C. Serangan Kriptanalisis: Brute-Force (Exhaustive Key Search)
Menguji ke-25 kemungkinan kunci secara bersamaan:
```bash
python app.py --brute-force -t "LQIRUPDWLND XSJULV"
```

#### D. Serangan Kriptanalisis: Automated Frequency Analysis (Chi-Squared Test)
Membobol ciphertext secara otomatis tanpa mengetahui kuncinya:
```bash
python app.py --auto-crack -t "SHVDQ VDQJDW UDKDVLD GDODP NHDPDQDQ VLEHU" --lang id
```

#### E. Enkripsi & Dekripsi File
```bash
# Enkripsi file
python app.py -e -k 7 -i dokumen_asli.txt -o dokumen_terenkripsi.txt

# Dekripsi file
python app.py -d -k 7 -i dokumen_terenkripsi.txt -o dokumen_pulih.txt
```

#### F. Menampilkan Laporan Analisis Keamanan Siber
```bash
python app.py --advisory
```

---

## 🔐 Mode Transposisi (Keluarga Cipher Transposisi — 5 Algoritma)

Seluruh cipher transposisi diakses via satu flag `--transposition` (mutual-exclusive dengan aksi Caesar). Tanpa `--algo`, flag ini membuka submenu interaktif.

### Algoritma & Parameter

| Algoritma | Flag `--algo` | Parameter | Konvensi Kunci |
|---|---|---|---|
| Rail Fence | `railfence` | `-k/--key = jumlah rel` | Pola zig-zag; `rails ≤ 1` = identitas |
| Route | `route` | `-k/--key = lebar grid`, `--route` | 9 rute terkurasi (spiral/serpentine/rows/cols) |
| Columnar | `columnar` | `--keyword` | Huruf berulang diberi peringkat **berbeda** (TOMATO → 5 3 2 1 6 4) |
| Double | `double` | `--keyword`, `--keyword2` | Columnar dua tahap (key1 → key2) |
| Myszkowski | `myszkowski` | `--keyword` | Huruf berulang diberi peringkat **sama** (TOMATO → 4 3 2 1 4 3) |

Opsi umum: `--mode {encrypt,decrypt}` (default `encrypt`), `--clean` (mode klasik: strip non-huruf + kapital), `--group5` (format output kelompok 5 huruf, butuh `--clean`). Mode default tanpa `--clean` **mempertahankan** spasi, angka, tanda baca, dan kapital — sejalan dengan filosofi `caesar_cipher.py`.

### Contoh CLI Transposisi

```bash
# Kolom (Columnar) — vektor terverifikasi
python app.py --transposition --algo columnar --keyword ZEBRA --mode encrypt -t "WEAREDISCOVEREDFLEEATONCE"
# -> EODAEASRENEIELORCEECWDVFT

# Rail Fence — vektor kanonik
python app.py --transposition --algo railfence --key 3 --mode encrypt -t "WEAREDISCOVEREDFLEEATONCE"
# -> WECRLTEERDSOEEFEAOCAIVDEN

# Route — spiral TL, lebar 5
python app.py --transposition --algo route --key 5 --route spiral_tl --mode encrypt -t "WEAREDISCOVEREDFLEEATONCE"
# -> WEAREODAECNOTFVDISCEEELER

# Myszkowski — dekripsi (contoh publik, tanpa null-pad)
python app.py --transposition --algo myszkowski --keyword TOMATO --mode decrypt -t "TINESAEOAHTFHMTALITIHAEIYTOASPTNNGHDML"
# -> THETOMATOISAPLANTINTHENIGHTSHADEFAMILY

# Double (Transposisi Ganda)
python app.py --transposition --algo double --keyword ZEBRA --keyword2 KRIPTO --mode encrypt -t "WEAREDISCOVEREDFLEEATONCE"
# -> DEOWESEETAIEFANRDORLCEECV

# Mode klasik + grup 5 huruf
python app.py --transposition --algo columnar --keyword ZEBRA --clean --group5 -t "Pes an sangat rahasia"
```

### Operasi File Transposisi (CLI)

```bash
# Enkripsi file lalu dekripsi balik
python app.py --transposition --algo columnar --keyword ZEBRA -i in.txt -o enc.txt
python app.py --transposition --algo columnar --keyword ZEBRA --mode decrypt -i enc.txt -o dec.txt
```

### Submenu Interaktif (menu 7)

Jalankan `python app.py`, pilih **7. Kriptografi Transposisi**, lalu pilih algoritma 1–5. Setiap alur: pilih mode enkripsi/dekripsi, masukkan parameter (rails / lebar grid + rute / keyword / dua keyword), pilih mode classic `clean` opsional, dan masukkan teks. Menu **3** juga menerima sistem cipher (1: Caesar, 2: Transposisi) untuk operasi file.

---

## 🖥️ Mode Desktop (GUI)

Selain CLI, tersedia versi **aplikasi desktop** berbasis CustomTkinter. Versi desktop mempertahankan **seluruh** fitur CLI dalam bentuk 7 tab, plus fitur UX tambahan:

- **Live preview** real-time saat mengetik / menggeser kunci
- **Slider kunci visual 0–25** sinkron dua-arah dengan input numerik
- **Indikator kekuatan kunci** berwarna (IDENTITAS / ROT13 / Lemah) — menegaskan pesan *cyber security advisory*
- **Live preview transposisi** — hasil berubah real-time saat mengganti algoritma, keyword, rute, atau mode
- **Salin ke clipboard** untuk setiap hasil
- **Riwayat operasi sesi** di panel bawah

> Catatan: CLI (`app.py`) tetap **zero-dependency** (Python Standard Library). Hanya versi desktop yang membutuhkan satu paket eksternal (`customtkinter`). Engine kriptografi (`caesar_cipher.py`, `cryptanalysis.py`, `transposition.py`) **dipakai bersama** oleh CLI dan desktop — tidak ada duplikasi logika.

### 1. Instalasi Dependensi Desktop
```bash
pip install -r requirements.txt
# atau: pip install customtkinter
```

### 2. Menjalankan Aplikasi Desktop
```bash
python desktop_app.py
```

### 3. Tab yang Tersedia (mirror menu CLI)

| Tab | Setara menu CLI | Fungsi |
|---|---|---|
| **Enkripsi** | menu 1 | Enkripsi teks + live preview + slider kunci + indikator kekuatan |
| **Dekripsi** | menu 2 | Dekripsi teks + live preview + slider kunci |
| **Operasi File** | menu 3 | Browse file input/output, Caesar **atau Transposisi**, enkripsi/dekripsi file `.txt` |
| **Brute Force** | menu 4 | Exhaustive key search — tampilkan 25 variasi pergeseran |
| **Frequency Analysis** | menu 5 | Serangan Chi-Squared otomatis + top-3 kandidat |
| **Transposisi** | menu 7 | 5 algoritma transposisi + live preview + parameter dinamis per algoritma |
| **Advisory** | menu 6 | Laporan Threat Model & Advisory (reuse dari `app.py`) |

---

## 🧪 Menjalankan Pengujian Otomatis (Unit Tests)

Jalankan test suite untuk memvalidasi algoritma, penanganan karakter spesial, normalisasi kunci modular, modul serangan, serta seluruh keluarga transposisi:

```bash
# Substitusi Caesar + Kriptanalisis (8 tes)
python test_caesar.py

# Keluarga Transposisi (29 tes — vektor kanonik + round-trip sempurna)
python test_transposition.py
```

Hasil:
```text
python test_caesar.py
Ran 8 tests in 0.05s
OK

python test_transposition.py
Ran 29 tests in 0.35s
OK
```

Suite transposisi memverifikasi, antara lain, vektor kanonik publik (Rail Fence `WECRLTEERDSOEEFEAOCAIVDEN`, Columnar ZEBRA, contoh publik Myszkowski `TINESAXE...`, dll.), invariant bulat penuh `D(E(m)) == m` untuk sembarang panjang ragged, mode `clean`, grup 5, operasi file, dan penanganan kesalahan tipe/nilai.
