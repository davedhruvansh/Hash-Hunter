"""
modules/hash_detector.py
========================
Hash identification engine using length, pattern, charset, and entropy analysis.
Supports: MD5, SHA-1/224/256/384/512, SHA3, bcrypt, Argon2, NTLM, LM, MySQL,
          WPA/PBKDF2, Cisco, WordPress, Drupal, Django, RIPEMD, Whirlpool, CRC32,
          Base64-encoded variants, and more.
"""

import re
import math
import base64
import binascii
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Hash signature database
# Each entry: (name, length_in_hex_chars, regex_pattern, notes)
# ---------------------------------------------------------------------------
HASH_SIGNATURES = [
    # --- CRC / Fast Hashes ---
    ("CRC32",           8,   r"^[a-fA-F0-9]{8}$",          "CRC32 checksum"),
    ("Adler32",         8,   r"^[a-fA-F0-9]{8}$",          "Adler-32 (same length as CRC32)"),
    ("FNV32",           8,   r"^[a-fA-F0-9]{8}$",          "FNV-1a 32-bit"),

    # --- MD family ---
    ("MD4",             32,  r"^[a-fA-F0-9]{32}$",         "MD4"),
    ("MD5",             32,  r"^[a-fA-F0-9]{32}$",         "MD5 — most common 32-char hash"),
    ("MD5(Unix)",       None, r"^[$]1[$].{1,16}[$].{22,24}$",  "MD5crypt (Linux shadow)"),
    ("MD5(APR)",        None, r"^[$]apr1[$].{1,8}[$].{22}$",   "Apache MD5"),
    ("NTLM",            32,  r"^[a-fA-F0-9]{32}$",         "Windows NTLM (same as MD5 length)"),
    ("LM",              32,  r"^[a-fA-F0-9]{32}$",         "Windows LM Hash"),
    ("MySQL3.x",        16,  r"^[a-fA-F0-9]{16}$",         "Old MySQL password hash"),
    ("MySQL4.1+",       41,  r"^\*[A-F0-9]{40}$",          "MySQL 4.1+ sha1(sha1(pass))"),

    # --- SHA family ---
    ("SHA1",            40,  r"^[a-fA-F0-9]{40}$",         "SHA-1"),
    ("SHA224",          56,  r"^[a-fA-F0-9]{56}$",         "SHA-224"),
    ("SHA256",          64,  r"^[a-fA-F0-9]{64}$",         "SHA-256"),
    ("SHA384",          96,  r"^[a-fA-F0-9]{96}$",         "SHA-384"),
    ("SHA512",          128, r"^[a-fA-F0-9]{128}$",        "SHA-512"),
    ("SHA3-224",        56,  r"^[a-fA-F0-9]{56}$",         "SHA3-224"),
    ("SHA3-256",        64,  r"^[a-fA-F0-9]{64}$",         "SHA3-256"),
    ("SHA3-384",        96,  r"^[a-fA-F0-9]{96}$",         "SHA3-384"),
    ("SHA3-512",        128, r"^[a-fA-F0-9]{128}$",        "SHA3-512"),
    ("RIPEMD128",       32,  r"^[a-fA-F0-9]{32}$",         "RIPEMD-128"),
    ("RIPEMD160",       40,  r"^[a-fA-F0-9]{40}$",         "RIPEMD-160"),
    ("RIPEMD256",       64,  r"^[a-fA-F0-9]{64}$",         "RIPEMD-256"),
    ("RIPEMD320",       80,  r"^[a-fA-F0-9]{80}$",         "RIPEMD-320"),
    ("Whirlpool",       128, r"^[a-fA-F0-9]{128}$",        "Whirlpool"),
    ("BLAKE2b-256",     64,  r"^[a-fA-F0-9]{64}$",         "BLAKE2b-256"),
    ("BLAKE2b-512",     128, r"^[a-fA-F0-9]{128}$",        "BLAKE2b-512"),

    # --- KDF / Slow Hashes ---
    ("bcrypt",          60,  r"^[$]2[ayb][$].{56}$",         "bcrypt (cost factor embedded)"),
    ("bcrypt-sha256",   None,r"^[$]bcrypt-sha256[$]",        "bcrypt-SHA256 (Django variant)"),
    ("Argon2i",         None,r"^[$]argon2i[$]",              "Argon2i KDF"),
    ("Argon2id",        None,r"^[$]argon2id[$]",             "Argon2id KDF"),
    ("scrypt",          None,r"^[$]scrypt[$]",               "scrypt KDF"),
    ("PBKDF2-SHA1",     None,r"^pbkdf2_sha1[$]",             "Django PBKDF2-SHA1"),
    ("PBKDF2-SHA256",   None,r"^pbkdf2_sha256[$]",           "Django PBKDF2-SHA256"),
    ("PBKDF2-SHA512",   None,r"^pbkdf2_sha512[$]",           "Django PBKDF2-SHA512"),

    # --- CMS / Application Specific ---
    ("WordPress",       None,r"^[$]P[$][a-zA-Z0-9./]{29,32}$", "WordPress / phpass"),
    ("Drupal7",         None,r"^[$]S[$][a-zA-Z0-9./]{52,53}$", "Drupal 7"),
    ("Joomla",          32,  r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{32}$", "Joomla MD5:salt"),
    ("vBulletin",       32,  r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{3}$",  "vBulletin MD5:salt"),
    ("phpBB3",          None,r"^[$]H[$][a-zA-Z0-9./]{29,32}$", "phpBB3 / phpass"),

    # --- Network / OS ---
    ("Cisco IOS (MD5)", None,r"^[$]1[$][a-zA-Z0-9./]{4}[$][a-zA-Z0-9./]{22}$", "Cisco IOS MD5"),
    ("Cisco IOS Type 5",None,r"^[$]1[$]",                   "Cisco Type-5"),
    ("Cisco Type 7",    None,r"^[0-9a-fA-F]{2}[0-9a-fA-F]+$", "Cisco Type-7 (weak XOR)"),
    ("WPA-PBKDF2",      64,  r"^[a-fA-F0-9]{64}$",        "WPA/WPA2 PSK (PBKDF2-SHA1)"),
    ("Domain Cached",   32,  r"^[a-fA-F0-9]{32}$",        "Windows Domain Cached Credentials"),

    # --- Misc ---
    ("Base64",          None,r"^[A-Za-z0-9+/]+=*$",        "Base64-encoded data"),
    ("SHA512crypt",     None,r"^[$]6[$][a-zA-Z0-9./]{1,16}[$][a-zA-Z0-9./]{86}$", "SHA512crypt (Linux)"),
    ("SHA256crypt",     None,r"^[$]5[$][a-zA-Z0-9./]{1,16}[$][a-zA-Z0-9./]{43}$", "SHA256crypt (Linux)"),
]

# Mapping hash type names → hashlib algorithm names (for cracking)
HASHLIB_MAP = {
    "MD5":       "md5",
    "MD4":       "md4",
    "NTLM":      "md4",      # NTLM = MD4(UTF-16LE)
    "SHA1":      "sha1",
    "SHA224":    "sha224",
    "SHA256":    "sha256",
    "SHA384":    "sha384",
    "SHA512":    "sha512",
    "SHA3-224":  "sha3_224",
    "SHA3-256":  "sha3_256",
    "SHA3-384":  "sha3_384",
    "SHA3-512":  "sha3_512",
    "RIPEMD160": "ripemd160",
    "BLAKE2b-256":"blake2b",
    "BLAKE2b-512":"blake2b",
    "Whirlpool": "whirlpool",
}


class HashDetector:
    """
    Identifies the type(s) of a hash using:
      1. Special prefix/pattern matching (bcrypt, argon2, crypt formats)
      2. Hex-length matching
      3. Shannon entropy analysis
      4. Confidence scoring
    """

    def __init__(self):
        self._compiled = [
            (name, length, re.compile(pattern, re.IGNORECASE), notes)
            for name, length, pattern, notes in HASH_SIGNATURES
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def identify(self, hash_value: str) -> Dict:
        """
        Analyze a hash string and return identification metadata.

        Returns a dict with keys:
          - possible_types : list[str]  — all matching type names
          - best_guess     : str        — single best guess
          - length         : int
          - entropy        : float      — Shannon entropy (bits/char)
          - encoding       : str|None   — 'hex', 'base64', or None
          - is_salted      : bool
          - hashlib_name   : str|None   — name for hashlib if crackable
        """
        h = hash_value.strip()
        detected_encoding = self._detect_encoding(h)
        matches = []

        for name, length, pattern, notes in self._compiled:
            if pattern.match(h):
                # Extra length check for fixed-length hex types
                if length and len(h) != length:
                    continue
                matches.append(name)

        entropy = self._shannon_entropy(h)
        best = self._pick_best(h, matches, entropy)
        is_salted = self._is_salted(h)
        hashlib_name = HASHLIB_MAP.get(best)

        return {
            "hash": h,
            "possible_types": matches,
            "best_guess": best,
            "length": len(h),
            "entropy": entropy,
            "encoding": detected_encoding,
            "is_salted": is_salted,
            "hashlib_name": hashlib_name,
        }

    def get_hashlib_name(self, hash_type: str) -> Optional[str]:
        """Return the hashlib algorithm string for a given hash type name."""
        return HASHLIB_MAP.get(hash_type)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy in bits per character."""
        if not data:
            return 0.0
        freq = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def _detect_encoding(h: str) -> Optional[str]:
        """Detect if the hash is hex or base64 encoded."""
        if re.fullmatch(r"[0-9a-fA-F]+", h):
            return "hex"
        try:
            decoded = base64.b64decode(h + "==", validate=True)
            if len(decoded) in (16, 20, 28, 32, 48, 64):
                return "base64"
        except Exception:
            pass
        return None

    @staticmethod
    def _is_salted(h: str) -> bool:
        """Simple heuristic: salted hashes usually contain ':' or '$' separators."""
        return ":" in h or (h.startswith("$") and h.count("$") >= 3)

    @staticmethod
    def _pick_best(h: str, candidates: List[str], entropy: float) -> str:
        """
        Rank candidates and return the most likely hash type.
        Priority rules:
          1. Special-format types (bcrypt, argon2, crypt) win immediately.
          2. Among hex types, prefer higher-entropy → stronger algorithm.
          3. Known length → name mappings break remaining ties.
        """
        if not candidates:
            return "Unknown"

        # Exact-format wins
        priority_prefixes = {
            "$2": "bcrypt",
            "$argon2i": "Argon2i",
            "$argon2id": "Argon2id",
            "$P$": "WordPress",
            "$S$": "Drupal7",
            "$H$": "phpBB3",
            "$1$": "MD5(Unix)",
            "$5$": "SHA256crypt",
            "$6$": "SHA512crypt",
            "pbkdf2_sha256$": "PBKDF2-SHA256",
            "pbkdf2_sha512$": "PBKDF2-SHA512",
            "*": "MySQL4.1+",
        }
        for prefix, name in priority_prefixes.items():
            if h.startswith(prefix) and name in candidates:
                return name

        # Length-based tiebreaker for hex hashes
        length_preferred = {
            16:  "MySQL3.x",
            32:  "MD5",
            40:  "SHA1",
            56:  "SHA224",
            64:  "SHA256",
            80:  "RIPEMD320",
            96:  "SHA384",
            128: "SHA512",
        }
        if h and re.fullmatch(r"[0-9a-fA-F]+", h):
            preferred = length_preferred.get(len(h))
            if preferred and preferred in candidates:
                return preferred

        return candidates[0]
