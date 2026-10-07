"""
Core Cryptographic Engine: Caesar Cipher (Shift Cipher)
Perspektif Cyber Security: Implementasi defensif dengan normalisasi kunci,
preservasi karakter non-alfabetik, dan dukungan enkripsi file.
"""

from pathlib import Path
from typing import Union


class CaesarCipher:
    """
    Implementasi algoritma kriptografi klasik Caesar Cipher.
    Matematika Dasar:
      Enkripsi : C_i = (P_i + k) mod 26
      Dekripsi : P_i = (C_i - k) mod 26
    """

    ALPHABET_SIZE = 26

    @classmethod
    def _normalize_key(cls, key: int) -> int:
        """
        Normalisasi nilai kunci shift ke dalam rentang [0, 25].
        Mendukung kunci negatif (misal -3 -> 23) maupun nilai besar (> 26).
        """
        if not isinstance(key, int):
            raise TypeError(f"Kunci harus berupa bilangan bulat (integer), diterima: {type(key).__name__}")
        return key % cls.ALPHABET_SIZE

    @classmethod
    def encrypt(cls, plaintext: str, key: int = 3) -> str:
        """
        Melakukan enkripsi pada plaintext menggunakan Caesar Cipher.

        Args:
            plaintext (str): Teks asli yang akan dienkripsi.
            key (int): Jumlah pergeseran (shift value). Default klasik Julius Caesar = 3.

        Returns:
            str: Teks hasil enkripsi (ciphertext).
        """
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext harus bertipe string.")

        k = cls._normalize_key(key)
        if k == 0:
            return plaintext

        encrypted_chars = []
        for char in plaintext:
            if 'A' <= char <= 'Z':
                # Shift untuk huruf besar (ASCII 65 - 90)
                shifted = chr((ord(char) - ord('A') + k) % cls.ALPHABET_SIZE + ord('A'))
                encrypted_chars.append(shifted)
            elif 'a' <= char <= 'z':
                # Shift untuk huruf kecil (ASCII 97 - 122)
                shifted = chr((ord(char) - ord('a') + k) % cls.ALPHABET_SIZE + ord('a'))
                encrypted_chars.append(shifted)
            else:
                # Karakter non-alfabetik (spasi, angka, tanda baca) dipertahankan
                encrypted_chars.append(char)

        return "".join(encrypted_chars)

    @classmethod
    def decrypt(cls, ciphertext: str, key: int = 3) -> str:
        """
        Melakukan dekripsi pada ciphertext menggunakan Caesar Cipher.

        Args:
            ciphertext (str): Teks terenkripsi.
            key (int): Jumlah pergeseran (shift value) yang digunakan saat enkripsi.

        Returns:
            str: Teks asli hasil dekripsi (plaintext).
        """
        if not isinstance(ciphertext, str):
            raise TypeError("Ciphertext harus bertipe string.")

        # Dekripsi dengan kunci k ekuivalen dengan enkripsi dengan kunci (26 - (k % 26))
        k = cls._normalize_key(key)
        return cls.encrypt(ciphertext, cls.ALPHABET_SIZE - k)

    @classmethod
    def encrypt_file(cls, input_path: Union[str, Path], output_path: Union[str, Path], key: int = 3) -> None:
        """
        Membaca file teks, mengenkripsi isinya, dan menyimpannya ke file baru.
        """
        in_file = Path(input_path)
        out_file = Path(output_path)

        if not in_file.exists():
            raise FileNotFoundError(f"File input tidak ditemukan: {in_file}")

        content = in_file.read_text(encoding="utf-8")
        encrypted = cls.encrypt(content, key)
        out_file.write_text(encrypted, encoding="utf-8")

    @classmethod
    def decrypt_file(cls, input_path: Union[str, Path], output_path: Union[str, Path], key: int = 3) -> None:
        """
        Membaca file ciphertext, mendekripsi isinya, dan menyimpannya ke file baru.
        """
        in_file = Path(input_path)
        out_file = Path(output_path)

        if not in_file.exists():
            raise FileNotFoundError(f"File input tidak ditemukan: {in_file}")

        content = in_file.read_text(encoding="utf-8")
        decrypted = cls.decrypt(content, key)
        out_file.write_text(decrypted, encoding="utf-8")
