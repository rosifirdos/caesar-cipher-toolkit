# Laporan Analisis Keamanan Siber: Evaluasi Kriptografis Caesar Cipher

**Author:** Cyber Security Specialist  
**Klasifikasi:** Analisis Kriptografi & Threat Modeling  
**Target Algoritma:** Caesar Cipher (Monoalphabetic Substitution / Shift Cipher)

---

## 1. Executive Summary

Caesar Cipher adalah algoritma kriptografi simetris klasik berbasis substitusi monoalfabetik dengan melakukan pergeseran siklis (shift) pada alfabet sebesar nilai kunci $k$. Berdasarkan standar keamanan informasi modern (NIST, OWASP, ISO/IEC 27001), Caesar Cipher diklasifikasikan sebagai **CRITICALLY VULNERABLE & BROKEN**, dan dilarang keras untuk digunakan dalam proteksi kerahasiaan (*confidentiality*) pada sistem produksi.

Namun, dari kacamata pedagogis keamanan siber, Caesar Cipher merupakan fondasi krusial untuk memahami konsep **Kerckhoffs's Principle**, **Confusion & Diffusion (Claude Shannon)**, dan **Cryptanalysis Vectors**.

---

## 2. Analisis Matematis & Entropi Kunci

### 2.1 Formulasi Matematis
Diberikan alfabet $\Sigma = \{A, B, C, \dots, Z\}$ berukuran $m = 26$:
- **Fungsi Enkripsi:**  
  $$E_k(p) = (p + k) \pmod{26}, \quad p \in \mathbb{Z}_{26}, k \in \mathbb{Z}$$
- **Fungsi Dekripsi:**  
  $$D_k(c) = (c - k) \pmod{26}, \quad c \in \mathbb{Z}_{26}, k \in \mathbb{Z}$$

### 2.2 Ukuran Ruang Kunci (*Keyspace*)
Ukuran keyspace efektif hanyalah:
$$|K| = 26 - 1 = 25 \text{ kemungkinan pergeseran non-trivial}$$
Entropi kunci dapat dihitung menggunakan Shannon Entropy:
$$H(K) = \log_2(|K|) = \log_2(26) \approx 4.7004 \text{ bits}$$

Sebagai perbandingan:
| Algoritma | Ukuran Kunci | Entropi (Bits) | Waktu Bobol (Exhaustive Search) |
|---|---|---|---|
| **Caesar Cipher** | $k \in [1..25]$ | $\approx 4.7\text{ bits}$ | $< 0.0001\text{ detik}$ |
| **DES (Legacy)** | 56 bits | $56\text{ bits}$ | Beberapa menit s.d. jam |
| **AES-128 (Modern)** | 128 bits | $128\text{ bits}$ | Miliaran tahun (secara komputasi mustahil) |
| **AES-256 (Modern)** | 256 bits | $256\text{ bits}$ | Tahan terhadap komputasi kuantum (Grover's) |

---

## 3. Vektor Serangan Kriptanalisis (Threat Vectors)

### 3.1 Exhaustive Key Search (Brute Force Attack)
- **Model Penyerang:** *Ciphertext-Only Attack (COA)*.
- **Mekanisme:** Penyerang mencoba seluruh $k \in \{1, 2, \dots, 25\}$.
- **Kompleksitas Waktu:** $\mathcal{O}(|K| \cdot N) = \mathcal{O}(25 \cdot N)$, di mana $N$ adalah panjang pesan.
- **Dampak:** Seluruh kunci dapat diuji dan dibaca manusia dalam waktu instan.

### 3.2 Statistical Frequency Analysis Attack
- **Kelemahan Fundamental:** Tidak adanya sifat **Diffusion** (penyebaran statistik).
- Huruf dengan frekuensi tertinggi dalam bahasa alami (misal huruf `'A'` pada Bahasa Indonesia sekitar $19.3\%$, atau huruf `'E'` pada Bahasa Inggris sekitar $12.7\%$) akan selalu dipetakan ke karakter ciphertext yang sama secara konsisten.
- Penyerang dapat menggunakan pengujian statistik **Chi-Squared ($\chi^2$)**:
  $$\chi^2 = \sum_{c='A'}^{'Z'} \frac{(O_c - E_c)^2}{E_c}$$
  Algoritma otomasi dapat memecahkan teks terenkripsi secara otomatis tanpa bantuan manusia.

### 3.3 Known-Plaintext Attack (KPA)
- Cukup dengan mengetahui **1 pasang karakter** $(p_i, c_i)$, penyerang langsung dapat merekonstruksi kunci:
  $$k = (c_i - p_i) \pmod{26}$$
- Seluruh sisa pesan rahasia terbongkar secara instan.

### 3.4 Ketiadaan Otentikasi & Integritas (*Malleability*)
- Caesar Cipher tidak memiliki *Integrity Check* (MAC / Hash / Signature).
- Ciphertext bersifat *malleable*: Jika penyerang mengubah karakter $c_i$ menjadi $c_i' = (c_i + \delta) \pmod{26}$, maka saat didekripsi oleh penerima yang sah, karakter tersebut akan berubah menjadi $p_i' = (p_i + \delta) \pmod{26}$ tanpa menimbulkan error atau kecurigaan sistem.

---

## 4. Evaluasi Prinsip Keamanan Kriptografi

1. **Prinsip Kerckhoffs (*Kerckhoffs's Principle*)**:
   > *"Sistem kriptografi harus tetap aman meskipun seluruh mekanisme dan algoritma enkripsi diketahui publik, asalkan kuncinya tetap rahasia."*
   - Caesar Cipher gagal memenuhi prinsip ini karena meskipun algoritmanya diketahui, ruang kuncinya terlalu kecil sehingga kerahasiaan kunci tidak dapat dipertahankan.

2. **Security through Obscurity**:
   - Jika keamanan bergantung pada musuh yang "tidak tahu bahwa kita menggunakan Caesar Cipher", maka begitu tipe cipher teridentifikasi (misal via *Index of Coincidence*), sistem langsung runtuh seketika.

---

## 5. Rekomendasi Industri Modern

Untuk mengamankan data sensitif pada arsitektur sistem informasi modern:
1. **Gunakan Authenticated Encryption with Associated Data (AEAD)**:
   - **AES-256-GCM** (Galois/Counter Mode) atau **ChaCha20-Poly1305**.
   - Menyediakan kerahasiaan (*confidentiality*), integritas (*integrity*), dan otentikasi asal pesan (*authenticity*).
2. **Manajemen Kunci & KDF**:
   - Gunakan Key Derivation Function standar seperti **Argon2id** atau **PBKDF2-HMAC-SHA256** untuk mengubah passphrase pengguna menjadi kunci kriptografi yang kuat dengan ketahanan terhadap serangan GPU/ASIC.
3. **Transport Layer Security (TLS 1.3)**:
   - Gunakan protokol TLS 1.3 untuk komunikasi data in-transit, mengimplementasikan *Ephemeral Diffie-Hellman* (ECDHE) demi menjamin *Perfect Forward Secrecy (PFS)*.

---

## 6. Cryptography Classic: Transposition Family (Evaluasi Kriptografis)

Dengan penambahan modul transposisi, toolkit kini mencakup dua **keluarga besar cipher klasik** — *substitution* (Caesar) dan *transposition*. Tinjauan keamanan berikut melengkapi evaluasi Caesar di atas.

### 6.1 Prinsip Kerja

Berbeda dengan substitusi (huruf **diganti**), transposisi murni hanya **mengubah urutan** huruf dengan permutasi $\pi$ pada posisi:
$$c_i = p_{\pi(i)}$$

Akibat fundamental: **distribusi frekuensi huruf tidak berubah**. Statistik huruf plaintext (mis. `A` ≈ 19% bahasa Indonesia) langsung terlihat di ciphertext — basis serangan *frequency analysis* yang sama dengan Caesar, tetapi kini bukan karena usia kunci, melainkan karena **tidak ada diffusion tunggal ke karakter** (hanya *transposition*, bukan *substitution* simultan).

### 6.2 Ukuran Ruang Kunci (*Keyspace*)

| Algoritma | Kunci | Ukuran Keyspace ($|K|$) | Entropi (Bits) | Catatan |
|---|---|---|---|---|
| **Rail Fence** | jumlah rel $r$ | $r - 1$ (≥ 2 rel non-trivial) | $\approx \log_2(r-1)$ | Ruang kunci sangat kecil; mudah dibobol |
| **Columnar** | keyword $n$ huruf | maksimum $n!$ (susunan abjad) | $\approx \log_2(n!)$ (n=10 → 21.8 bits) | Lebih besar dari Caesar, masih rapuh |
| **Double (columnar 2×)** | dua keyword $n_1, n_2$ | $n_1! \times n_2!$ (komposisi) | $\approx \log_2(n_1! \cdot n_2!)$ | Diffusion lebih baik, standarnya > 3 tahap (krusial dalam PNG 1944) |
| **Myszkowski** | keyword $n$ huruf | $<\frac{n!}{m!}$ (kelompok berulang menyusut) | kurang dari Columnar untuk keyword berulang | Konvensi *shared-rank* mereduksi variasi |
| **Route** | lebar grid $w$ × rute | $w_{max}\cdot$ (jumlah rute = 9) | bervariasi dengan $w$ | Rute terbatas; serangan *depth* (anagramming) sangat efektif |

Sebagai pembanding: **AES-128** memiliki 128 bit entropi. Bahkan Columnar dengan keyword 10 huruf hanya mencapai $\approx 21.8$ bit — jauh di bawah ambang praktis keamanan modern.

### 6.3 Vektor Serangan Khusus Transposisi

1. **Frequency Analysis (COA)**: Karena frekuensi huruf utuh, *letter distribution* langsung mencurigakan (tidak ada puncak/trough yang "datar"-kan). *Index of Coincidence* (IC) tinggi menandakan kemungkinan besar cipher transposisi murni.
2. **Anagramming / Depth (diployed)**: Kriptanalis mengujicoba lebar grid $w$ dan membaca kolom-kolom untuk menemukan fragmen kata yang masuk akal; teknik **Kasiski**-style pada plaintext *crib* mempercepat pemecahan.
3. **Known-Plaintext (KPA)**: Pola posisi permutasi $\pi$ dapat di-rekonstruksi dari pasangan (plaintext, ciphertext) yang diketahui.
4. **Ruang Kunci Small**: Rail Fence & Route dengan $w$ kecil dapat dibrute-force secara instan; keyword pendek (≤ 6 huruf) Columnar/Myszkowski juga.

### 6.4 Verdict

Sesuai wajah **NIST / OWASP stance** yang konsisten dengan evaluasi Caesar: seluruh cipher transposisi di atas **bersifat "breakable" dan tidak boleh digunakan** untuk melindungi data produksi (confidentiality). Nilai mereka murni **pedagogis & historis** — memahami permutasi, kombinasi transposition+substitution (dasar dari cipher modern benar-benar merupakan penggabungan keduanya), dan budaya cryptography. Untuk sistem produksi gunakan **AEAD modern (AES-256-GCM / ChaCha20-Poly1305)** sebagaimana disarankan di Bagian 5.
