# Caesar Cipher & Cryptanalysis Toolkit (Python)

Aplikasi kriptografi Caesar Cipher tingkat lanjut yang dikembangkan dengan pendekatan **Cyber Security (Defensive & Offensive Kriptanalisis)**.

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
D:\portofolio\proyek-cyber\
│
├── caesar_cipher.py        # Core Cryptography Engine (Enkripsi, Dekripsi, File Ops)
├── cryptanalysis.py        # Offensive Module (Brute Force 25 shifts & Chi-Squared Auto Crack)
├── app.py                  # User Interface (CLI Interaktif & Terminal Flags Parser)
├── desktop_app.py          # Versi Desktop GUI (CustomTkinter) - 6 tab mirror CLI + fitur UX
├── requirements.txt        # Dependensi versi desktop (customtkinter)
├── test_caesar.py          # Unit Test Suite (Pengujian fungsi & pembuktian matematis)
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

## 🖥️ Mode Desktop (GUI)

Selain CLI, tersedia versi **aplikasi desktop** berbasis CustomTkinter. Versi desktop mempertahankan **seluruh** fitur CLI dalam bentuk 6 tab, plus fitur UX tambahan:

- **Live preview** real-time saat mengetik / menggeser kunci
- **Slider kunci visual 0–25** sinkron dua-arah dengan input numerik
- **Indikator kekuatan kunci** berwarna (IDENTITAS / ROT13 / Lemah) — menegaskan pesan *cyber security advisory*
- **Salin ke clipboard** untuk setiap hasil
- **Riwayat operasi sesi** di panel bawah

> Catatan: CLI (`app.py`) tetap **zero-dependency** (Python Standard Library). Hanya versi desktop yang membutuhkan satu paket eksternal (`customtkinter`). Engine kriptografi (`caesar_cipher.py`, `cryptanalysis.py`) **dipakai bersama** oleh CLI dan desktop — tidak ada duplikasi logika.

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
| **Operasi File** | menu 3 | Browse file input/output, enkripsi/dekripsi file `.txt` |
| **Brute Force** | menu 4 | Exhaustive key search — tampilkan 25 variasi pergeseran |
| **Frequency Analysis** | menu 5 | Serangan Chi-Squared otomatis + top-3 kandidat |
| **Advisory** | menu 6 | Laporan Threat Model & Advisory (reuse dari `app.py`) |

---

## 🧪 Menjalankan Pengujian Otomatis (Unit Tests)

Jalankan test suite untuk memvalidasi algoritma, penanganan karakter spesial, normalisasi kunci modular, dan modul serangan:
```bash
python test_caesar.py
```
Hasil:
```text
Ran 8 tests in 0.033s

OK
```
