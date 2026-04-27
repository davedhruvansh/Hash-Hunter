"""
modules/utilities.py
====================
Shared utilities: file I/O, hash encoding detection, logging setup,
result serialisation, and input validation.
"""

import os
import re
import json
import base64
import logging
import hashlib
from typing import List, Optional
from datetime import datetime


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(log_file: Optional[str] = None, verbose: bool = False) -> logging.Logger:
    """
    Configure and return the root logger.
      - Console handler always present (INFO or DEBUG depending on verbose flag).
      - Optional file handler for full DEBUG logs.
    """
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s  %(levelname)-8s  %(message)s"
    datefmt = "%H:%M:%S"

    logger = logging.getLogger("hashhunter")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(fmt, datefmt))
    logger.addHandler(ch)

    # File handler (always DEBUG)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
            "%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(fh)
        logger.info("Logging to file: %s", log_file)

    return logger


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def validate_file(path: str) -> bool:
    """Return True if path is an existing readable file."""
    return os.path.isfile(path) and os.access(path, os.R_OK)


def load_hashes_from_file(path: str, encoding_hint: str = "auto") -> List[str]:
    """
    Read a file and return a de-duplicated list of non-empty lines,
    with each line decoded according to encoding_hint.
    """
    seen = set()
    hashes = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            decoded = decode_hash_input(line, encoding_hint)
            if decoded and decoded not in seen:
                seen.add(decoded)
                hashes.append(decoded)
    return hashes


# ---------------------------------------------------------------------------
# Hash encoding detection & normalisation
# ---------------------------------------------------------------------------

def decode_hash_input(raw: str, hint: str = "auto") -> Optional[str]:
    """
    Normalise a hash string to its canonical form.
    - 'hex'    → pass through (lowercase)
    - 'base64' → decode bytes, return hex
    - 'auto'   → detect automatically
    Returns None if the input cannot be decoded.
    """
    raw = raw.strip()

    if hint == "hex" or (hint == "auto" and _looks_like_hex(raw)):
        return raw.lower()

    if hint == "base64" or (hint == "auto" and _looks_like_base64(raw)):
        try:
            decoded_bytes = base64.b64decode(raw + "==")
            return decoded_bytes.hex()
        except Exception:
            pass

    # Fall back: return as-is (for formats like $2y$..., $P$...)
    return raw


def _looks_like_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s)) and len(s) in (8, 16, 32, 40, 56, 64, 80, 96, 128)


def _looks_like_base64(s: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return False
    # Ensure proper padding before decoding
    padded = s + "=" * (-len(s) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
        return len(decoded) in (16, 20, 28, 32, 48, 64)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Result serialisation
# ---------------------------------------------------------------------------

def save_results(results: List[dict], output_path: str):
    """
    Save cracking results to a file.
    Format is auto-detected from extension:
      .json → JSON
      .csv  → CSV
      everything else → plain text
    """
    ext = os.path.splitext(output_path)[1].lower()
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    if ext == ".json":
        _save_json(results, output_path)
    elif ext == ".csv":
        _save_csv(results, output_path)
    else:
        _save_txt(results, output_path)


def _save_txt(results: List[dict], path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# HashHunter Results — {datetime.utcnow().isoformat()}Z\n")
        f.write(f"# Total: {len(results)}  Cracked: {sum(1 for r in results if r['cracked'])}\n\n")
        for r in results:
            status = "CRACKED" if r["cracked"] else "FAILED"
            f.write(f"[{status}]\n")
            f.write(f"  hash      : {r['hash']}\n")
            f.write(f"  type      : {r['hash_type']}\n")
            if r["cracked"]:
                f.write(f"  plaintext : {r['plaintext']}\n")
                f.write(f"  method    : {r['method']}\n")
            f.write(f"  elapsed   : {r['elapsed']:.2f}s\n")
            f.write(f"  timestamp : {r['timestamp']}\n\n")


def _save_json(results: List[dict], path: str):
    payload = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "tool": "HashHunter",
        "total": len(results),
        "cracked": sum(1 for r in results if r["cracked"]),
        "results": results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _save_csv(results: List[dict], path: str):
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["hash", "hash_type", "cracked", "plaintext", "method", "elapsed", "timestamp"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(results)


# ---------------------------------------------------------------------------
# Hash verification helper (used in tests / verification)
# ---------------------------------------------------------------------------

def verify_hash(plaintext: str, expected_hash: str, algo: str) -> bool:
    """Return True if hash(plaintext) == expected_hash for the given algorithm."""
    try:
        h = hashlib.new(algo)
        h.update(plaintext.encode("utf-8"))
        return h.hexdigest().lower() == expected_hash.lower()
    except Exception:
        return False
