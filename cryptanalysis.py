"""
Offensive Cryptanalysis Module: Caesar Cipher Breaker
Perspektif Cyber Security: Demonstrasi kerentanan matematis monoalphabetic cipher
melalui Brute-Force Key Exhaustion dan Statistical Frequency Analysis.
"""

from collections import Counter
from typing import Dict, List, Tuple
from caesar_cipher import CaesarCipher


class CaesarBreaker:
    """
    Modul serangan kriptanalisis untuk membobol pesan Caesar Cipher
    tanpa mengetahui kunci awal (Ciphertext-Only Attack / COA).
    """

    # Distribusi frekuensi huruf standar Bahasa Indonesia (dalam persentase %)
    # Karakter paling sering: A (~19.3%), N (~9.1%), E (~8.6%), I (~7.8%), T (~6.5%), dll.
    FREQ_INDONESIAN: Dict[str, float] = {
        'A': 19.3, 'B': 2.6,  'C': 0.7,  'D': 3.1,  'E': 8.6,
        'F': 0.3,  'G': 3.8,  'H': 2.8,  'I': 7.8,  'J': 0.8,
        'K': 5.2,  'L': 3.3,  'M': 3.6,  'N': 9.1,  'O': 2.3,
        'P': 2.6,  'Q': 0.01, 'R': 5.3,  'S': 4.1,  'T': 6.5,
        'U': 5.0,  'V': 0.2,  'W': 0.5,  'X': 0.03, 'Y': 1.6,
        'Z': 0.04
    }

    # Distribusi frekuensi huruf standar Bahasa Inggris (dalam persentase %)
    # Karakter ETAOIN SHRDLU
    FREQ_ENGLISH: Dict[str, float] = {
        'A': 8.2,  'B': 1.5,  'C': 2.8,  'D': 4.3,  'E': 12.7,
        'F': 2.2,  'G': 2.0,  'H': 6.1,  'I': 7.0,  'J': 0.15,
        'K': 0.77, 'L': 4.0,  'M': 2.4,  'N': 6.7,  'O': 7.5,
        'P': 1.9,  'Q': 0.09, 'R': 6.0,  'S': 6.3,  'T': 9.1,
        'U': 2.8,  'V': 0.98, 'W': 2.4,  'X': 0.15, 'Y': 2.0,
        'Z': 0.07
    }

    @classmethod
    def brute_force(cls, ciphertext: str) -> List[Dict[str, any]]:
        """
        Menjalankan Exhaustive Search Attack (Brute Force) ke seluruh keyspace (25 pergeseran).
        Kompleksitas: O(|K| * N) = O(25 * N) -> sangat trivial dan instan untuk dipecahkan.

        Returns:
            List[Dict]: Daftar hasil dekripsi untuk tiap kemungkinan kunci (1..25).
        """
        results = []
        for key in range(1, 26):
            decrypted = CaesarCipher.decrypt(ciphertext, key)
            results.append({
                "key": key,
                "plaintext": decrypted
            })
        return results

    @classmethod
    def _calculate_chi_squared(cls, text: str, expected_freqs: Dict[str, float]) -> float:
        """
        Menghitung Chi-Squared Statistic (chi^2) antara frekuensi huruf pada teks
        terhadap distribusi frekuensi alami bahasa target.
        Semakin KECIL nilai chi^2, semakin mirip teks dengan bahasa alami tersebut.
        """
        letters_only = [c.upper() for c in text if c.isalpha()]
        total_letters = len(letters_only)
        if total_letters == 0:
            return float('inf')

        counts = Counter(letters_only)
        chi_squared = 0.0

        for char, prob in expected_freqs.items():
            expected_count = (prob / 100.0) * total_letters
            observed_count = counts.get(char, 0)
            diff = observed_count - expected_count
            chi_squared += (diff * diff) / (expected_count + 1e-6)

        return chi_squared

    @classmethod
    def frequency_analysis_crack(cls, ciphertext: str, lang: str = "id") -> Dict[str, any]:
        """
        Melakukan penyerangan statistik otomatis (Frequency Analysis Attack).
        Mencoba seluruh 25 pergeseran dan mengevaluasi hasil dengan Chi-Squared test.
        Kandidat dengan skor chi^2 terendah adalah plaintext yang paling mungkin.

        Args:
            ciphertext (str): Teks rahasia yang akan dipecahkan.
            lang (str): Bahasa teks ("id" untuk Indonesia, "en" untuk Inggris).

        Returns:
            Dict: Kunci terpilih, plaintext terbaik, skor chi^2, dan top kandidat.
        """
        freq_table = cls.FREQ_INDONESIAN if lang.lower() == "id" else cls.FREQ_ENGLISH

        ranked_candidates = []
        for key in range(1, 26):
            candidate_text = CaesarCipher.decrypt(ciphertext, key)
            score = cls._calculate_chi_squared(candidate_text, freq_table)
            ranked_candidates.append({
                "key": key,
                "score": score,
                "plaintext": candidate_text
            })

        # Urutkan berdasarkan score chi^2 terendah (paling mendekati distribusi alami)
        ranked_candidates.sort(key=lambda x: x["score"])

        best_match = ranked_candidates[0]
        return {
            "status": "success",
            "best_key": best_match["key"],
            "best_score": round(best_match["score"], 4),
            "cracked_plaintext": best_match["plaintext"],
            "all_ranked": ranked_candidates
        }
