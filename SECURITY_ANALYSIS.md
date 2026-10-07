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
