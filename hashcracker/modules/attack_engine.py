"""
modules/attack_engine.py
========================
HashHunter v3 — Maximum Speed Engine
Made by Dhruvansh Dave

Speed optimizations:
  1. ZERO-LOCK inner loop  — no mutex contention during hashing
  2. Pre-encoded bytes     — encode words once, not per-attempt
  3. Direct hashlib fn     — hashlib.md5() not hashlib.new('md5')
  4. Large chunk buffering — 20K words per thread slice
  5. Local variable refs   — target/fn as locals for faster Python lookup
  6. Easy→Hard ordering    — short common words first = finds fast passwords faster
  7. 6-pass hybrid         — plain, case, leet, partial-leet, suffix, full mutations
  8. Batch mode            — one wordlist pass cracks ALL hashes simultaneously
  9. frozenset lookup      — O(1) check against all pending hashes per candidate
"""

import hashlib
import itertools
import os
import time
import threading
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from modules.hash_detector import HashDetector
from modules.mutations import (
    apply_mutations,
    generate_case_variants,
    generate_leet_variants,
    generate_suffix_variants,
    _leet, _partial_leet_variants, _multi_partial_leet,
    NUM_SUFFIXES, YEAR_SUFFIXES, SYM_SUFFIXES, SYM_NUM_SUFFIXES,
)
from modules.hash_file_parser import ParsedHashFile

# ---------------------------------------------------------------------------
# Direct hashlib dispatch — fastest possible, no hashlib.new() overhead
# ---------------------------------------------------------------------------
ALGO_FN = {
    "md5":      hashlib.md5,
    "sha1":     hashlib.sha1,
    "sha224":   hashlib.sha224,
    "sha256":   hashlib.sha256,
    "sha384":   hashlib.sha384,
    "sha512":   hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
    "blake2b":  hashlib.blake2b,
    "blake2s":  hashlib.blake2s,
}

CHARSETS = {
    "lowercase": "abcdefghijklmnopqrstuvwxyz",
    "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits":    "0123456789",
    "mixed":     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "full":      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?",
}

# Optimal chunk size — large enough to minimize lock grabs, small enough for responsiveness
CHUNK_SIZE = 20000

# ANSI
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; X = "\033[0m"


# ---------------------------------------------------------------------------
# Candidate generators
# ---------------------------------------------------------------------------

def _stream(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w:
                yield w


def _easy_to_hard(path: str):
    """
    Short words first — most real passwords are 6-8 chars.
    For large files uses smart buffering to avoid loading everything into RAM.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0

    if size > 150 * 1024 * 1024:   # > 150MB (rockyou etc.)
        yield from _smart_stream(path)
        return

    # Two-pass: short words first
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w and len(w) <= 10:
                yield w
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w and len(w) > 10:
                yield w


def _smart_stream(path: str):
    """Stream large wordlists: short words immediately, buffer long ones."""
    long_buf = []
    LIMIT = 500_000
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if not w:
                continue
            if len(w) <= 8:
                yield w
            elif len(long_buf) < LIMIT:
                long_buf.append(w)
            else:
                yield w
    yield from long_buf


def _hybrid_passes(path: str):
    """
    6-pass hybrid — ordered easy to hard:
    Pass 1  Plain words (easy→hard)
    Pass 2  Case variants   (Password, PASSWORD, PaSsWoRd)
    Pass 3  Full leet       (p@$$w0rd)
    Pass 4  Partial leet    (p@ssword, passw0rd)
    Pass 5  Suffix combos   (password@1, Password123)
    Pass 6  Full mutations  (all remaining)
    """
    yield from _easy_to_hard(path)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w:
                yield from generate_case_variants(w)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w and len(w) <= 20:
                yield from generate_leet_variants(w)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w and len(w) <= 20:
                wl = w.lower()
                for pl in _partial_leet_variants(wl):
                    yield pl
                    yield pl.capitalize()
                    yield pl.upper()
                for mpl in _multi_partial_leet(wl):
                    yield mpl
                    yield mpl.capitalize()
                    yield mpl.upper()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w:
                yield from generate_suffix_variants(w)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w:
                yield from apply_mutations(w)


def _combinator(path: str, max_len: int = 16):
    """word1+word2 combinations — catches davedhruv, adminpass etc."""
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w and 2 <= len(w) <= 8:
                words.append(w)
                if len(words) >= 50_000:
                    break
    for w1 in words:
        for w2 in words:
            combo = w1 + w2
            if len(combo) <= max_len:
                yield combo
                yield combo.capitalize()
                yield w1.capitalize() + w2
                yield w1 + w2.capitalize()


def _brute_gen(charset: str, min_len: int, max_len: int):
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


# ---------------------------------------------------------------------------
# Progress tracker
# ---------------------------------------------------------------------------

class ProgressTracker:
    def __init__(self, total: int = 0):
        self.total   = total
        self.checked = 0
        self.start   = time.time()
        self._lock   = threading.Lock()
        self._last_t = 0.0
        self._last_c = 0

    def increment(self, n: int = 1):
        # Atomic increment — no lock needed for int on CPython
        self.checked += n

    def report(self, extra: str = "") -> str:
        now = time.time()
        if now - self._last_t < 0.4:
            return ""
        with self._lock:
            interval  = now - self._last_t
            speed     = (self.checked - self._last_c) / max(interval, 1e-9)
            self._last_c = self.checked
            self._last_t = now
        pct = (self.checked / self.total * 100) if self.total else 0
        eta = ""
        if speed > 0 and self.total and self.checked < self.total:
            s   = int((self.total - self.checked) / speed)
            h, m, sec = s // 3600, (s % 3600) // 60, s % 60
            eta = f"  ETA {h:02d}:{m:02d}:{sec:02d}"
        spd = (f"{speed/1e6:.2f}MH/s" if speed >= 1e6 else
               f"{speed/1e3:.1f}KH/s" if speed >= 1e3 else
               f"{speed:.0f}H/s")
        bar  = "█" * int(22 * pct / 100) + "░" * (22 - int(22 * pct / 100))
        return f"\r  [{bar}] {pct:5.1f}%  {self.checked:,}  {C}{spd}{X}{eta}  {extra}   "


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class AttackEngine:
    """
    HashHunter cracking engine — Maximum Speed Edition.
    Made by Dhruvansh Dave.
    """

    def __init__(self, detector: HashDetector, config: Dict, logger: logging.Logger):
        self.detector = detector
        self.config   = config
        self.logger   = logger
        self.results: List[Dict] = []
        self._stop    = threading.Event()

    # ── Public API ──────────────────────────────────────────────────────────

    def run(self, hashes: List[str]) -> List[Dict]:
        self.results = []
        for i, h in enumerate(hashes, 1):
            print(f"\n{'═'*62}")
            print(f"  Target {i}/{len(hashes)}: {C}{h[:60]}{'…' if len(h)>60 else ''}{X}")
            info      = self.detector.identify(h)
            hash_type = self.config.get("hash_type") or info["best_guess"]
            algo      = self.detector.get_hashlib_name(hash_type)
            print(f"  Type   : {Y}{hash_type}{X}    Mode: {self.config['attack_mode']}")

            if not algo and self.config["attack_mode"] != "rainbow":
                print(f"  {R}[!] No hashlib support for '{hash_type}'. Skipping.{X}")
                self.results.append(self._make_result(h, hash_type))
                continue

            self._stop.clear()
            start     = time.time()
            plaintext, method = self._dispatch(h.lower(), algo, hash_type)

            # Fallback: try other possible algorithms (SHA3 vs SHA256 ambiguity)
            if plaintext is None and not self.config.get("hash_type"):
                from modules.hash_detector import HASHLIB_MAP
                others = [(t, HASHLIB_MAP[t]) for t in info["possible_types"]
                          if t in HASHLIB_MAP and HASHLIB_MAP[t] != algo]
                for alt_type, alt_algo in others:
                    print(f"  {Y}[retry]{X} Trying as {alt_type}...")
                    self._stop.clear()
                    plaintext, method = self._dispatch(h.lower(), alt_algo, alt_type)
                    if plaintext:
                        hash_type = alt_type
                        break

            elapsed = time.time() - start
            self.results.append(self._make_result(
                h, hash_type,
                cracked=plaintext is not None,
                plaintext=plaintext,
                method=method,
                elapsed=elapsed,
            ))
        return self.results

    def run_batch_file(self, parsed_file) -> List[Dict]:
        entries = parsed_file.crackable_entries
        pre_cracked = [
            self._make_result(e.hash_value, "potfile", cracked=True,
                              plaintext=e.known_plaintext, method="potfile",
                              username=e.username)
            for e in parsed_file.entries if e.already_cracked
        ]
        all_results: List[Dict] = list(pre_cracked)

        if not entries:
            msg = f"All {len(pre_cracked)} entries already cracked." if pre_cracked else "No crackable entries."
            print(f"  [*] {msg}")
            self.results = all_results
            return all_results

        groups: Dict[str, List] = {}
        for entry in entries:
            info      = self.detector.identify(entry.hash_value)
            hash_type = self.config.get("hash_type") or info["best_guess"]
            algo      = self.detector.get_hashlib_name(hash_type)
            key       = f"{hash_type}||{algo or '__unsupported__'}"
            groups.setdefault(key, []).append((entry, hash_type, algo))

        for key, group_entries in groups.items():
            hash_type, algo = key.split("||", 1)
            if algo == "__unsupported__":
                print(f"\n  {R}[!]{X} Skipping {len(group_entries)} '{hash_type}' — no hashlib support")
                for e, ht, _ in group_entries:
                    all_results.append(self._make_result(e.hash_value, ht))
                continue

            print(f"\n  {'═'*60}")
            print(f"  Group  : {Y}{hash_type}{X}  ({len(group_entries)} hashes)")
            print(f"  Mode   : {self.config['attack_mode']}")

            pending:   Dict[str, tuple] = {e.hash_value.lower(): (e, hash_type) for e, ht, _ in group_entries}
            found_map: Dict[str, str]   = {}

            self._stop.clear()
            start = time.time()
            self._batch_crack(pending, found_map, algo)
            elapsed = time.time() - start

            for h_lower, (entry, ht) in pending.items():
                pt = found_map.get(h_lower)
                all_results.append(self._make_result(
                    entry.hash_value, ht,
                    cracked=pt is not None, plaintext=pt,
                    method=self.config["attack_mode"],
                    elapsed=elapsed, username=entry.username,
                ))

        self.results = all_results
        return all_results

    def pause(self):  self._stop.set()
    def resume(self): self._stop.clear()

    # ── Dispatch ────────────────────────────────────────────────────────────

    def _dispatch(self, target: str, algo: str, hash_type: str) -> Tuple[Optional[str], str]:
        mode    = self.config["attack_mode"]
        threads = self.config.get("threads", 4)
        wl      = self.config.get("wordlist")

        if mode == "dictionary":
            print(f"  Wordlist : {wl}")
            print(f"  Strategy : easy→hard (short words first)\n")
            return self._fast_crack(target, algo, _easy_to_hard(wl), threads), "dictionary"

        elif mode == "hybrid":
            print(f"  Wordlist : {wl}")
            print(f"  Strategy : 6-pass (plain→case→leet→partial-leet→suffix→full)\n")
            return self._fast_crack(target, algo, _hybrid_passes(wl), threads), "hybrid"

        elif mode == "combinator":
            print(f"  Wordlist : {wl}")
            print(f"  Strategy : word+word combinations\n")
            def _cb():
                yield from _easy_to_hard(wl)
                yield from _combinator(wl)
            return self._fast_crack(target, algo, _cb(), threads), "combinator"

        elif mode == "brute":
            cs      = self.config.get("charset", "lowercase")
            charset = (self.config.get("custom_charset") if cs == "custom"
                       else CHARSETS.get(cs, CHARSETS["lowercase"]))
            min_l   = self.config.get("min_length", 1)
            max_l   = self.config.get("max_length", 6)
            total   = sum(len(charset) ** l for l in range(min_l, max_l + 1))
            print(f"  Charset  : {cs} ({len(charset)} chars)  len: {min_l}–{max_l}  total: {total:,}\n")
            return self._fast_crack(target, algo, _brute_gen(charset, min_l, max_l), threads, total), "brute-force"

        elif mode == "rainbow":
            return self._rainbow_lookup(target), "rainbow"

        elif mode == "auto":
            return self._auto_crack(target, algo, wl, threads)

        return None, mode

    def _auto_crack(self, target, algo, wl, threads):
        print(f"  {C}AUTO MODE{X} — dictionary → hybrid → combinator → brute\n")
        for label, gen in [
            ("dictionary",  _easy_to_hard(wl)),
            ("hybrid",      _hybrid_passes(wl)),
            ("combinator",  _combinator(wl)),
            ("brute-digits",_brute_gen("0123456789", 1, 8)),
        ]:
            print(f"  {Y}►{X} Trying {label}...")
            self._stop.clear()
            pt = self._fast_crack(target, algo, gen, threads)
            if pt:
                return pt, f"{label} (auto)"
        return None, "auto (exhausted)"

    # ── MAXIMUM SPEED: Zero-lock slice cracking ─────────────────────────────

    def _fast_crack(
        self,
        target:      str,
        algo:        str,
        candidates,
        num_workers: int,
        total:       int = 0,
    ) -> Optional[str]:
        """
        Maximum speed single-target cracker.

        Key design — ZERO lock in the inner hash loop:
          1. Buffer candidates into a large in-memory list
          2. Split list into N equal slices (one per thread)
          3. Each thread works on its own slice — NO shared state
          4. Only one atomic write when password is found

        This eliminates all lock contention from the hot path,
        giving full CPU throughput for hashing operations.
        """
        found   = [None]
        stop    = threading.Event()
        prog    = ProgressTracker(total)

        # Get fastest direct function — local ref for speed
        algo_fn = ALGO_FN.get(algo)
        if algo_fn is None:
            def algo_fn(d): return hashlib.new(algo, d)

        # ── Phase 1: Buffer candidates in chunks, dispatch slices ──────────
        BUFFER = CHUNK_SIZE * num_workers   # how many words to buffer before slicing
        lock   = threading.Lock()
        citer  = iter(candidates)
        active = [True]

        def get_buffer() -> List[bytes]:
            """Grab a large buffer from the shared iterator (one lock per BUFFER words)."""
            with lock:
                buf = []
                try:
                    for _ in range(BUFFER):
                        w = next(citer)
                        buf.append(w.encode("utf-8", errors="replace")
                                   if isinstance(w, str) else w)
                except StopIteration:
                    active[0] = False
                return buf

        def worker_slice(my_words: List[bytes]):
            """
            Zero-lock inner loop — pure hashing with no synchronisation.
            Only writes to found[] when a match is detected.
            """
            fn  = algo_fn          # local ref = faster attribute lookup
            tgt = target           # local ref
            for wb in my_words:
                if stop.is_set():
                    return
                if fn(wb).hexdigest() == tgt:
                    found[0] = wb.decode("utf-8", errors="replace")
                    stop.set()
                    return

        # ── Phase 2: Main loop — buffer → slice → dispatch ─────────────────
        print_lock = threading.Lock()
        checked    = [0]

        def run_buffers():
            while not stop.is_set():
                buf = get_buffer()
                if not buf:
                    return
                # Split buffer evenly across workers
                slices  = [buf[i::num_workers] for i in range(num_workers)]
                threads = [threading.Thread(target=worker_slice, args=(s,), daemon=True)
                           for s in slices]
                for t in threads: t.start()
                for t in threads: t.join()
                checked[0] += len(buf)
                prog.checked = checked[0]

        runner = threading.Thread(target=run_buffers, daemon=True)
        runner.start()

        # ── Phase 3: Progress display ───────────────────────────────────────
        try:
            while runner.is_alive():
                rpt = prog.report()
                if rpt:
                    print(rpt, end="", flush=True)
                time.sleep(0.25)
        except KeyboardInterrupt:
            stop.set()

        runner.join(timeout=3)
        print("\r" + " " * 85 + "\r", end="", flush=True)

        if found[0]:
            print(f"  {G}✓ CRACKED{X}  →  {G}{found[0]}{X}")
        else:
            print(f"  {R}✗ Not found in this pass{X}")

        return found[0]

    # ── Batch cracking (multiple hashes, single wordlist pass) ─────────────

    def _batch_crack(self, pending: Dict, found_map: Dict, algo: str):
        mode    = self.config["attack_mode"]
        wl      = self.config.get("wordlist")
        threads = self.config.get("threads", 4)

        cands = {
            "dictionary": lambda: _easy_to_hard(wl),
            "hybrid":     lambda: _hybrid_passes(wl),
            "combinator": lambda: (x for gen in [_easy_to_hard(wl), _combinator(wl)] for x in gen),
            "brute":      lambda: _brute_gen(
                              self.config.get("custom_charset") if self.config.get("charset") == "custom"
                              else CHARSETS.get(self.config.get("charset","lowercase"), CHARSETS["lowercase"]),
                              self.config.get("min_length",1), self.config.get("max_length",6)),
            "auto":       lambda: (x for gen in [_easy_to_hard(wl), _hybrid_passes(wl), _combinator(wl)] for x in gen),
            "rainbow":    None,
        }.get(mode)

        if mode == "rainbow":
            for h in list(pending.keys()):
                pt = self._rainbow_lookup(h)
                if pt: found_map[h] = pt; del pending[h]
            return

        if cands is None:
            return

        self._batch_threaded(pending, found_map, algo, cands(), threads)

    def _batch_threaded(self, pending, found_map, algo, candidates, num_workers):
        """
        Batch mode: one candidate hashed → checked against ALL hashes at once.
        Uses frozenset for O(1) multi-hash lookup.
        Same zero-lock buffer-slice design as _fast_crack.
        """
        remaining  = set(pending.keys())
        rlock      = threading.Lock()
        stop       = threading.Event()
        prog       = ProgressTracker(0)
        citer      = iter(candidates)
        iter_lock  = threading.Lock()
        active     = [True]

        algo_fn = ALGO_FN.get(algo)
        if algo_fn is None:
            def algo_fn(d): return hashlib.new(algo, d)

        def get_buffer():
            with iter_lock:
                buf = []
                try:
                    for _ in range(CHUNK_SIZE * num_workers):
                        w = next(citer)
                        buf.append(w.encode("utf-8", errors="replace")
                                   if isinstance(w, str) else w)
                except StopIteration:
                    active[0] = False
                return buf

        def worker_slice(my_words, targets_snap):
            fn = algo_fn
            for wb in my_words:
                if stop.is_set(): return
                digest = fn(wb).hexdigest()
                if digest in targets_snap:
                    pt = wb.decode("utf-8", errors="replace")
                    with rlock:
                        if digest in remaining:
                            remaining.discard(digest)
                            found_map[digest] = pt
                            print(f"\r  {G}✓{X}  {digest[:50]}  →  {G}{pt}{X}")
                            if not remaining:
                                stop.set(); return

        checked = [0]

        def run_buffers():
            while not stop.is_set():
                buf = get_buffer()
                if not buf: return
                with rlock:
                    if not remaining: stop.set(); return
                    snap = frozenset(remaining)
                slices  = [buf[i::num_workers] for i in range(num_workers)]
                threads = [threading.Thread(target=worker_slice, args=(s, snap), daemon=True)
                           for s in slices]
                for t in threads: t.start()
                for t in threads: t.join()
                checked[0] += len(buf)
                prog.checked = checked[0]

        runner = threading.Thread(target=run_buffers, daemon=True)
        runner.start()

        try:
            while runner.is_alive():
                cn  = len(pending) - len(remaining)
                rpt = prog.report(f"cracked: {G}{cn}{X}/{len(pending)}")
                if rpt: print(rpt, end="", flush=True)
                time.sleep(0.25)
        except KeyboardInterrupt:
            stop.set()

        runner.join(timeout=3)
        print("\r" + " " * 90 + "\r", end="", flush=True)
        if remaining:
            print(f"  {R}✗ {len(remaining)} hash(es) not cracked{X}")

    # ── Rainbow table ───────────────────────────────────────────────────────

    def _rainbow_lookup(self, target: str) -> Optional[str]:
        rd = self.config.get("rainbow_dir")
        if not rd or not os.path.isdir(rd):
            print(f"  {R}[!] Rainbow directory not available.{X}")
            return None
        tl = target.lower()
        for fname in [f for f in os.listdir(rd) if f.endswith((".txt",".rt",".rtc",".csv"))]:
            try:
                with open(os.path.join(rd, fname), "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if ":" in line:
                            h, pt = line.split(":", 1)
                            if h.strip().lower() == tl:
                                return pt.strip()
            except IOError:
                pass
        return None

    # ── Result builder ──────────────────────────────────────────────────────

    @staticmethod
    def _make_result(h, hash_type, cracked=False, plaintext=None,
                     method=None, elapsed=0.0, username="") -> Dict:
        return {
            "hash": h, "hash_type": hash_type, "cracked": cracked,
            "plaintext": plaintext, "method": method, "elapsed": elapsed,
            "username": username, "timestamp": datetime.utcnow().isoformat() + "Z",
        }
