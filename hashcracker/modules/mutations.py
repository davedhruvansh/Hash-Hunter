"""
modules/mutations.py
====================
Advanced password mutation engine.

Covers ALL common real-world password patterns:
  - Plain / capitalize / upper / lower
  - Toggle case (PaSsWoRd, pAsSwOrD)
  - Full leet + partial leet (single substitution per char)
  - Suffix: numbers, symbols, years, common endings
  - Prefix: numbers, symbols
  - Combined: capitalize+suffix, leet+suffix, upper+suffix
  - Mixed case + symbol + number  (Password@1, Pass@123)
  - Word reversal variants
  - Repeat / double word
  - Name patterns (dave123, Dave@123, DAVE_123)
  - Common separators (_, -, ., @, !)
  - Keyboard walks (excluded — covered by brute force)
"""

import itertools
from typing import Generator, Set, List

# ---------------------------------------------------------------------------
# Substitution maps
# ---------------------------------------------------------------------------

# Full leet — every substitutable char replaced
LEET_FULL = {
    'a': '@', 'e': '3', 'i': '1', 'o': '0',
    's': '$', 't': '7', 'b': '8', 'g': '9',
    'l': '1', 'z': '2', 'h': '#', 'q': '9',
}

# Partial leet — only the MOST common single substitutions
LEET_PARTIAL = [
    {'a': '@'},
    {'a': '4'},
    {'e': '3'},
    {'i': '1'},
    {'o': '0'},
    {'s': '$'},
    {'s': '5'},
    {'t': '7'},
    {'l': '1'},
    {'g': '9'},
    {'b': '8'},
    {'h': '#'},
]

# Common numeric suffixes (most frequent first)
NUM_SUFFIXES = [
    "1", "2", "12", "21", "123", "321",
    "1234", "12345", "123456",
    "01", "001", "007", "00", "0",
    "11", "22", "33", "99", "69",
    "100", "111", "222", "333", "999",
]

# Year suffixes
YEAR_SUFFIXES = [
    "2020", "2021", "2022", "2023", "2024", "2025",
    "19", "20", "99", "00", "01", "98", "95",
    "1990", "1991", "1992", "1993", "1994", "1995",
    "1996", "1997", "1998", "1999", "2000",
]

# Symbol suffixes
SYM_SUFFIXES = ["!", "@", "#", "$", "%", "^", "&", "*", ".", "_", "-", "?"]

# Combined symbol+number (very common pattern: password@1, pass!123)
SYM_NUM_SUFFIXES = [
    "@1", "@12", "@123", "@1234",
    "!1", "!12", "!123", "!1234",
    "#1", "#12", "#123",
    "$1", "$12", "$123",
    "_1", "_12", "_123",
    "@2023", "@2024", "@2024!", "!@#",
    "#123", "$123", "@!", "!@",
]

# Common prefixes
NUM_PREFIXES = ["1", "12", "123", "0", "00", "007"]
SYM_PREFIXES = ["@", "!", "#", "$"]

# Common word separators used between word+number
SEPARATORS = ["", "@", "!", "#", "_", "-", "."]


def apply_mutations(word: str) -> Generator[str, None, None]:
    """
    Yield ALL mutation variants of a base word.
    Ordered from most-likely (common patterns) to least-likely (complex).
    
    Skips empty words and very long words (>32 chars) to stay efficient.
    """
    if not word or len(word) > 32:
        return

    w = word.lower()
    w_cap = w.capitalize()
    w_up  = w.upper()
    w_rev = w[::-1]

    seen: Set[str] = set()

    def emit(s: str):
        if s and s != word and s not in seen:
            seen.add(s)
            return s
        return None

    def ey(s):
        """emit + yield"""
        v = emit(s)
        if v:
            yield v

    # ── 1. Basic case variants ────────────────────────────────────────────
    yield from ey(w_cap)
    yield from ey(w_up)
    yield from ey(w)
    yield from ey(word)         # original casing preserved
    yield from ey(word.swapcase())
    yield from ey(_title(w))

    # ── 2. Toggle case patterns ───────────────────────────────────────────
    for tp in _toggle_patterns(w):
        yield from ey(tp)

    # ── 3. Reversal variants ──────────────────────────────────────────────
    yield from ey(w_rev)
    yield from ey(w_rev.capitalize())
    yield from ey(w_rev.upper())

    # ── 4. Full leet variants ─────────────────────────────────────────────
    fl = _leet(w)
    fl_cap = _leet(w_cap)
    yield from ey(fl)
    yield from ey(fl_cap)
    yield from ey(fl.upper())

    # ── 5. Partial leet (single substitution) ────────────────────────────
    for pl in _partial_leet_variants(w):
        yield from ey(pl)
        yield from ey(pl.capitalize())
        yield from ey(pl.upper())

    # ── 5b. Multi-partial leet (2 subs: dr@g0n, L3tme1n, p@ssw0rd) ──────
    for mpl in _multi_partial_leet(w):
        yield from ey(mpl)
        yield from ey(mpl.capitalize())
        yield from ey(mpl.upper())

    # ── 6. Number suffixes ────────────────────────────────────────────────
    for n in NUM_SUFFIXES:
        yield from ey(w + n)
        yield from ey(w_cap + n)
        yield from ey(w_up + n)

    # ── 7. Year suffixes ──────────────────────────────────────────────────
    for y in YEAR_SUFFIXES:
        yield from ey(w + y)
        yield from ey(w_cap + y)
        yield from ey(w_up + y)

    # ── 8. Symbol suffixes ────────────────────────────────────────────────
    for s in SYM_SUFFIXES:
        yield from ey(w + s)
        yield from ey(w_cap + s)
        yield from ey(w_up + s)

    # ── 9. Symbol + number suffixes (Password@1, pass!123) ────────────────
    for sn in SYM_NUM_SUFFIXES:
        yield from ey(w + sn)
        yield from ey(w_cap + sn)
        yield from ey(w_up + sn)
        yield from ey(word + sn)    # preserve original case too

    # ── 10. Number prefixes ───────────────────────────────────────────────
    for n in NUM_PREFIXES:
        yield from ey(n + w)
        yield from ey(n + w_cap)

    # ── 11. Symbol prefixes ───────────────────────────────────────────────
    for s in SYM_PREFIXES:
        yield from ey(s + w)
        yield from ey(s + w_cap)

    # ── 12. Leet + number suffix combinations ────────────────────────────
    for n in NUM_SUFFIXES[:10]:    # top 10 only to keep manageable
        yield from ey(fl + n)
        yield from ey(fl_cap + n)
    for y in YEAR_SUFFIXES[:6]:
        yield from ey(fl + y)
        yield from ey(fl_cap + y)
    for sn in SYM_NUM_SUFFIXES[:8]:
        yield from ey(fl + sn)
        yield from ey(fl_cap + sn)

    # ── 13. Partial leet + number/symbol combos ───────────────────────────
    for pl in _partial_leet_variants(w):
        for n in NUM_SUFFIXES[:6]:
            yield from ey(pl + n)
            yield from ey(pl.capitalize() + n)
        for sn in SYM_NUM_SUFFIXES[:6]:
            yield from ey(pl + sn)
            yield from ey(pl.capitalize() + sn)
        for s in SYM_SUFFIXES[:4]:
            yield from ey(pl + s)

    # ── 14. Toggle case + number/symbol suffixes ──────────────────────────
    for tp in _toggle_patterns(w):
        for n in NUM_SUFFIXES[:5]:
            yield from ey(tp + n)
        for sn in SYM_NUM_SUFFIXES[:5]:
            yield from ey(tp + sn)
        for s in SYM_SUFFIXES[:3]:
            yield from ey(tp + s)

    # ── 15. Separator patterns (word_123, word-2024) ──────────────────────
    for sep in SEPARATORS[1:]:    # skip empty, already covered
        for n in NUM_SUFFIXES[:8]:
            yield from ey(w + sep + n)
            yield from ey(w_cap + sep + n)
        for y in YEAR_SUFFIXES[:4]:
            yield from ey(w + sep + y)
            yield from ey(w_cap + sep + y)

    # ── 16. Word doubling ─────────────────────────────────────────────────
    yield from ey(w + w)
    yield from ey(w_cap + w)
    yield from ey(w + w_cap)

    # ── 17. Strip trailing digits, re-append different numbers ────────────
    base = w.rstrip("0123456789")
    if base != w and len(base) >= 2:
        for n in NUM_SUFFIXES[:8]:
            yield from ey(base + n)
            yield from ey(base.capitalize() + n)
        for sn in SYM_NUM_SUFFIXES[:4]:
            yield from ey(base + sn)
            yield from ey(base.capitalize() + sn)


# ---------------------------------------------------------------------------
# Public helpers (used by attack_engine hybrid passes)
# ---------------------------------------------------------------------------

def generate_case_variants(word: str) -> Generator[str, None, None]:
    """Yield all case variants only — used in hybrid pass 2."""
    if not word:
        return
    w = word.lower()
    yield w.capitalize()
    yield w.upper()
    yield word.swapcase()
    yield _title(w)
    for tp in _toggle_patterns(w):
        if tp != word:
            yield tp


def generate_leet_variants(word: str) -> Generator[str, None, None]:
    """Yield leet variants — used in hybrid pass 3."""
    if not word:
        return
    w = word.lower()
    fl = _leet(w)
    if fl != w:
        yield fl
        yield fl.capitalize()
        yield fl.upper()
    for pl in _partial_leet_variants(w):
        if pl != w:
            yield pl
            yield pl.capitalize()
            yield pl.upper()
    # Multi-partial leet (dr@g0n, L3tme1n)
    for mpl in _multi_partial_leet(w):
        if mpl != w:
            yield mpl
            yield mpl.capitalize()
            yield mpl.upper()


def generate_suffix_variants(word: str) -> Generator[str, None, None]:
    """Yield suffix variants only — used in hybrid pass 4."""
    if not word:
        return
    w = word.lower()
    wc = w.capitalize()
    wu = w.upper()
    for n in NUM_SUFFIXES:
        yield w + n
        yield wc + n
        yield wu + n
    for y in YEAR_SUFFIXES:
        yield w + y
        yield wc + y
    for s in SYM_SUFFIXES:
        yield w + s
        yield wc + s
    for sn in SYM_NUM_SUFFIXES:
        yield w + sn
        yield wc + sn
        yield wu + sn


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _leet(word: str) -> str:
    """Full leet substitution — every applicable char replaced."""
    return "".join(LEET_FULL.get(c.lower(), c) for c in word)


def _partial_leet_variants(word: str) -> List[str]:
    """
    Single-substitution leet variants.
    e.g. 'dave' → ['d@ve', 'd4ve', 'dav3', 'dave'] (one sub at a time)
    """
    variants = []
    w = word.lower()
    for sub_map in LEET_PARTIAL:
        result = list(w)
        changed = False
        for i, c in enumerate(w):
            if c in sub_map:
                result[i] = sub_map[c]
                changed = True
                break   # only first occurrence per map
        if changed:
            v = "".join(result)
            if v not in variants:
                variants.append(v)
    # Also try replacing ALL occurrences of one char
    for char, sub in [('a','@'), ('e','3'), ('i','1'), ('o','0'), ('s','$')]:
        if char in w:
            v = w.replace(char, sub)
            if v not in variants and v != w:
                variants.append(v)
    return variants


def _multi_partial_leet(word: str) -> List[str]:
    """
    Generate variants with 1-2 simultaneous leet substitutions.
    Covers: dr@g0n (dragon), L3tme1n (letmein), p@55w0rd (password)
    """
    SUBS = {'a':'@','e':'3','i':'1','o':'0','s':'$','t':'7','g':'9','b':'8'}
    word = word.lower()
    positions = [(i, SUBS[c]) for i, c in enumerate(word) if c in SUBS]
    variants = []

    # Single substitutions
    for i, sub in positions:
        v = word[:i] + sub + word[i+1:]
        if v not in variants:
            variants.append(v)

    # Double substitutions (two chars replaced simultaneously)
    for (i, s1), (j, s2) in itertools.combinations(positions, 2):
        v = list(word); v[i] = s1; v[j] = s2
        vstr = "".join(v)
        if vstr not in variants:
            variants.append(vstr)

    return variants


def _toggle_patterns(word: str) -> List[str]:
    """
    Common toggle-case patterns:
      PaSsWoRd  — alternating from index 0
      pAsSwOrD  — alternating from index 1
      PASSword  — first half upper
      passWORD  — second half upper
      PaSs      — first half alternating
    """
    w = word.lower()
    n = len(w)
    patterns = []

    # Alternating from index 0: PaSsWoRd
    p1 = "".join(c.upper() if i % 2 == 0 else c for i, c in enumerate(w))
    # Alternating from index 1: pAsSwOrD
    p2 = "".join(c.upper() if i % 2 == 1 else c for i, c in enumerate(w))
    # First half upper: PASSword
    mid = max(1, n // 2)
    p3 = w[:mid].upper() + w[mid:]
    # Second half upper: passWORD
    p4 = w[:mid] + w[mid:].upper()
    # First char + last char upper
    if n >= 2:
        p5 = w[0].upper() + w[1:-1] + w[-1].upper()
    else:
        p5 = w.upper()

    for p in [p1, p2, p3, p4, p5]:
        if p != w and p != w.upper() and p != w.capitalize():
            patterns.append(p)

    return patterns


def _title(word: str) -> str:
    """Title-case: capitalize after spaces, underscores, hyphens."""
    result = []
    cap_next = True
    for ch in word:
        if ch in (" ", "_", "-"):
            result.append(ch)
            cap_next = True
        elif cap_next:
            result.append(ch.upper())
            cap_next = False
        else:
            result.append(ch)
    return "".join(result)
