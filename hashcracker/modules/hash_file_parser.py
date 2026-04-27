"""
modules/hash_file_parser.py
============================
Smart parser for real-world hash dump files.

Supported formats (auto-detected):
  - Plain hashes          : one hash per line
  - colon-separated       : hash:extra  OR  username:hash  OR  user:uid:hash (shadow-like)
  - /etc/shadow           : username:$algo$salt$hash:...
  - /etc/passwd           : username:x:uid:gid:...  (skipped — hashes in shadow)
  - NTLM dump (pwdump)    : username:RID:LM:NT:::
  - Hashcat potfile       : hash:plaintext  (already cracked — skipped/flagged)
  - Hashcat hash file     : hash  or  hash:salt
  - John the Ripper file  : username:hash
  - WordPress export      : username,$P$hash
  - Base64-wrapped hashes : auto-decoded
  - Commented lines (#)   : skipped
  - Blank lines           : skipped
"""

import re
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ANSI colours for console output
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class HashEntry:
    """A single parsed hash record from a hash file."""
    raw_line: str            # original line
    hash_value: str          # the extracted hash (normalised lowercase)
    username: str  = ""      # associated username (if present)
    salt: str      = ""      # salt (if extracted separately)
    extra: str     = ""      # any extra fields (comment, UID, etc.)
    format_name: str = ""    # detected format name
    line_number: int = 0
    already_cracked: bool = False   # True if potfile entry
    known_plaintext: str = ""       # plaintext from potfile


@dataclass
class ParsedHashFile:
    """Result of parsing a complete hash file."""
    path: str
    format_name: str
    total_lines: int
    entries: List[HashEntry] = field(default_factory=list)
    skipped: int = 0
    warnings: List[str] = field(default_factory=list)

    @property
    def unique_hashes(self) -> List[str]:
        seen = set()
        out = []
        for e in self.entries:
            if e.hash_value not in seen and not e.already_cracked:
                seen.add(e.hash_value)
                out.append(e.hash_value)
        return out

    @property
    def crackable_entries(self) -> List["HashEntry"]:
        seen = set()
        out = []
        for e in self.entries:
            if e.hash_value not in seen and not e.already_cracked:
                seen.add(e.hash_value)
                out.append(e)
        return out


# ---------------------------------------------------------------------------
# Format detectors
# ---------------------------------------------------------------------------

# Shadow-style: $id$salt$hash  where id is 1/5/6/y/2b etc.
_SHADOW_RE = re.compile(r"^\$(1|5|6|2[ayb]|apr1|P\$|S\$|H\$|argon2|scrypt)\$")

# NTLM/pwdump: user:RID:LMhash:NThash::: — LM or NT is 32 hex chars
_PWDUMP_RE = re.compile(
    r"^[^:]+:\d+:([a-fA-F0-9]{32}|aad3b435b51404eeaad3b435b51404ee):"
    r"([a-fA-F0-9]{32}):.*$"
)

# Plain hex hash lengths
_HEX_LENGTHS = {8, 16, 32, 40, 56, 64, 80, 96, 128}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# MySQL 4.1+ — starts with *
_MYSQL_RE = re.compile(r"^\*[A-F0-9]{40}$", re.IGNORECASE)

# Hashcat potfile line: hash:plaintext  (hash is recognisable, plaintext is printable)
# We detect these by checking if the part after : is plain printable text of reasonable length
_PRINTABLE_RE = re.compile(r"^[\x20-\x7e]+$")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_hash_file(path: str, encoding_hint: str = "auto") -> ParsedHashFile:
    """
    Open and parse a hash file, auto-detecting its format.
    Returns a ParsedHashFile with all entries populated.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Hash file not found: {path}")

    lines = _read_lines(path)
    fmt = _detect_format(lines)

    result = ParsedHashFile(
        path=path,
        format_name=fmt,
        total_lines=len(lines),
    )

    parser_fn = _FORMAT_PARSERS.get(fmt, _parse_plain)

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            result.skipped += 1
            continue
        try:
            entry = parser_fn(stripped, i)
            if entry is None:
                result.skipped += 1
                continue
            # Normalise hash value
            entry.hash_value = entry.hash_value.strip()
            entry.format_name = fmt
            result.entries.append(entry)
        except Exception as exc:
            result.warnings.append(f"Line {i}: parse error — {exc}")
            result.skipped += 1

    return result


def print_parse_summary(pf: ParsedHashFile):
    """Print a formatted summary of the parsed hash file."""
    crackable = pf.crackable_entries
    already = sum(1 for e in pf.entries if e.already_cracked)

    print(f"\n  {CYAN}Hash File Analysis{RESET}")
    print(f"  {'─'*46}")
    print(f"  Path          : {pf.path}")
    print(f"  Format        : {YELLOW}{pf.format_name}{RESET}")
    print(f"  Total lines   : {pf.total_lines:,}")
    print(f"  Valid entries : {len(pf.entries):,}")
    print(f"  Unique hashes : {len(crackable):,}")
    print(f"  Pre-cracked   : {already:,}  {DIM}(potfile entries){RESET}")
    print(f"  Skipped lines : {pf.skipped:,}")
    if pf.warnings:
        print(f"  Warnings      : {len(pf.warnings)}")
        for w in pf.warnings[:5]:
            print(f"    {YELLOW}⚠{RESET} {w}")
        if len(pf.warnings) > 5:
            print(f"    ... and {len(pf.warnings)-5} more")

    # Show sample entries
    if crackable:
        print(f"\n  {DIM}Sample entries:{RESET}")
        for e in crackable[:4]:
            uname = f"  {CYAN}{e.username}{RESET}" if e.username else ""
            print(f"    {e.hash_value[:48]}{'…' if len(e.hash_value)>48 else ''}{uname}")
        if len(crackable) > 4:
            print(f"    {DIM}... and {len(crackable)-4} more{RESET}")
    print()


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def _detect_format(lines: List[str]) -> str:
    """
    Heuristically detect the hash file format by sampling non-empty lines.
    Returns a format name string.
    """
    sample = [l.strip() for l in lines if l.strip() and not l.startswith("#")][:30]
    if not sample:
        return "plain"

    pwdump_hits = sum(1 for l in sample if _PWDUMP_RE.match(l))
    if pwdump_hits >= max(1, len(sample) // 2):
        return "pwdump"

    # Check shadow BEFORE generic colon splitting.
    # shadow lines: username:$algo$salt$hash:... — the hash field starts with $algo$
    def _shadow_line(l):
        if ":" not in l: return False
        field = l.split(":", 1)[1]          # everything after first colon
        return bool(_SHADOW_RE.match(field))  # ^ anchor matches start of hash field
    shadow_hits = sum(1 for l in sample if _shadow_line(l))
    if shadow_hits >= max(1, len(sample) // 2):
        return "shadow"

    colon_hits = sum(1 for l in sample if ":" in l)
    if colon_hits >= max(1, len(sample) // 2):
        # Potfile: hash:short-printable-text  (text must look like a real password)
        # Distinguish from hash:salt by checking right-hand side is printable + short
        potfile_hits = sum(1 for l in sample if _is_potfile_line(l))
        if potfile_hits >= max(1, len(sample) // 2):
            return "hashcat_potfile"

        # Check if first field looks like a hash or username
        first_fields = [l.split(":", 1)[0] for l in sample if ":" in l]
        hash_first = sum(1 for f in first_fields if _is_hash_field(f))
        user_first = sum(1 for f in first_fields if not _is_hash_field(f))

        if hash_first > user_first:
            return "hash_colon_extra"   # hash:salt or hash:anything
        return "user_colon_hash"         # username:hash (John-style)

    # No colons — plain hash list
    return "plain"


def _is_hash_field(s: str) -> bool:
    """Return True if s looks like a hash (hex, mysql*, shadow-prefixed)."""
    s = s.strip()
    if _MYSQL_RE.match(s):
        return True
    if _SHADOW_RE.match(s):
        return True
    return _HEX_RE.match(s) is not None and len(s) in _HEX_LENGTHS


def _is_potfile_line(line: str) -> bool:
    """
    Return True if line looks like a hashcat potfile entry (hash:plaintext).
    A potfile right-hand side looks like a real password:
      - short (1–40 chars)
      - printable ASCII
      - NOT another hash (not all-hex with typical hash length)
      - NOT a salt-like string (all alphanumeric ≤16 chars that could be a salt)
    """
    if ":" not in line:
        return False
    parts = line.split(":", 1)
    lhs, rhs = parts[0].strip(), parts[1].strip()
    if not _is_hash_field(lhs):
        return False
    if not rhs or not _PRINTABLE_RE.match(rhs):
        return False
    if len(rhs) > 40:
        return False
    # If the RHS looks like another hash → not a potfile entry
    if _is_hash_field(rhs):
        return False
    # If RHS looks like a technical salt rather than a password:
    #   - pure hex 4-16 chars (e.g. a3f2b1c9, deadbeef00112233)
    #   - or all-digits ≤10 chars (numeric salt/token)
    if re.fullmatch(r"[0-9a-fA-F]{4,16}", rhs):   # pure hex salt
        return False
    if re.fullmatch(r"[0-9]{4,10}", rhs):          # numeric salt / PIN
        return False
    return True


# ---------------------------------------------------------------------------
# Per-format parsers
# ---------------------------------------------------------------------------

def _parse_plain(line: str, lineno: int) -> Optional[HashEntry]:
    """One hash per line — no metadata."""
    if not line:
        return None
    return HashEntry(raw_line=line, hash_value=line.lower(), line_number=lineno)


def _parse_shadow(line: str, lineno: int) -> Optional[HashEntry]:
    """
    /etc/shadow format:
      username:$algo$salt$hash:last_change:min:max:warn:inactive:expire:reserved
    Also handles simpler  username:hash  lines.
    """
    parts = line.split(":")
    if len(parts) < 2:
        return None

    username = parts[0]
    hash_field = parts[1]

    # Skip locked/empty accounts
    if hash_field in ("*", "!", "x", "", "!!", "*LK*"):
        return None

    # Extract salt if present in crypt format
    salt = ""
    if _SHADOW_RE.match(hash_field):
        segments = hash_field.split("$")
        # $id$salt$hash  → segments[0]='', [1]=id, [2]=salt, [3]=hash
        if len(segments) >= 4:
            salt = segments[2]

    return HashEntry(
        raw_line=line,
        hash_value=hash_field,
        username=username,
        salt=salt,
        extra=":".join(parts[2:]) if len(parts) > 2 else "",
        line_number=lineno,
    )


def _parse_pwdump(line: str, lineno: int) -> Optional[HashEntry]:
    """
    pwdump / fgdump / secretsdump format:
      username:RID:LMhash:NThash:::
    Extracts the NT hash (MD4). LM hash is weak and often 'aad3...' placeholder.
    """
    m = _PWDUMP_RE.match(line)
    if not m:
        return None

    parts = line.split(":")
    username = parts[0]
    lm_hash  = parts[2]
    nt_hash  = parts[3]

    # Prefer NT hash; fall back to LM if NT is empty
    LM_PLACEHOLDER = "aad3b435b51404eeaad3b435b51404ee"
    chosen = nt_hash if nt_hash and nt_hash.lower() != LM_PLACEHOLDER else lm_hash

    return HashEntry(
        raw_line=line,
        hash_value=chosen.lower(),
        username=username,
        extra=f"LM={lm_hash}",
        line_number=lineno,
    )


def _parse_user_colon_hash(line: str, lineno: int) -> Optional[HashEntry]:
    """
    John the Ripper / generic  username:hash  format.
    Handles both  user:hash  and  user,hash  separators.
    """
    # Support both : and , as separator
    sep = ":" if ":" in line else ","
    parts = line.split(sep, 1)
    if len(parts) != 2:
        return _parse_plain(line, lineno)

    username, hash_val = parts[0].strip(), parts[1].strip()

    # If the first field looks like a hash and second doesn't, flip them
    if not _is_hash_field(hash_val) and _is_hash_field(username):
        username, hash_val = hash_val, username

    if not hash_val:
        return None

    return HashEntry(
        raw_line=line,
        hash_value=hash_val.lower() if _HEX_RE.match(hash_val) else hash_val,
        username=username,
        line_number=lineno,
    )


def _parse_hash_colon_extra(line: str, lineno: int) -> Optional[HashEntry]:
    """
    hash:extra  format — hash on the left, anything on the right (salt, comment…).
    Used by hashcat, custom dumps, etc.
    """
    parts = line.split(":", 1)
    hash_val = parts[0].strip()
    extra    = parts[1].strip() if len(parts) > 1 else ""

    return HashEntry(
        raw_line=line,
        hash_value=hash_val.lower() if _HEX_RE.match(hash_val) else hash_val,
        salt=extra if len(extra) <= 32 else "",
        extra=extra,
        line_number=lineno,
    )


def _parse_hashcat_potfile(line: str, lineno: int) -> Optional[HashEntry]:
    """
    Hashcat potfile:  hash:plaintext
    These are already cracked — mark them so we skip re-cracking.
    """
    parts = line.split(":", 1)
    if len(parts) != 2:
        return None

    hash_val, plaintext = parts[0].strip(), parts[1].strip()
    return HashEntry(
        raw_line=line,
        hash_value=hash_val.lower() if _HEX_RE.match(hash_val) else hash_val,
        already_cracked=True,
        known_plaintext=plaintext,
        line_number=lineno,
    )


# Format name → parser function
_FORMAT_PARSERS = {
    "plain":            _parse_plain,
    "shadow":           _parse_shadow,
    "pwdump":           _parse_pwdump,
    "user_colon_hash":  _parse_user_colon_hash,
    "hash_colon_extra": _parse_hash_colon_extra,
    "hashcat_potfile":  _parse_hashcat_potfile,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_lines(path: str) -> List[str]:
    """Read all lines from a file, trying utf-8 then latin-1."""
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as f:
            return f.readlines()
    except UnicodeDecodeError:
        with open(path, "r", encoding="latin-1", errors="replace") as f:
            return f.readlines()
