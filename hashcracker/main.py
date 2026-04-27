#!/usr/bin/env python3
"""
HashHunter - Professional Hash Analysis & Cracking Tool
========================================================
For educational and authorized penetration testing only.
Unauthorized use against systems you don't own is illegal.
"""

import argparse
import sys
import os
import time
import signal

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.banner import print_banner, print_warning
from modules.hash_detector import HashDetector
from modules.attack_engine import AttackEngine
from modules.hash_file_parser import parse_hash_file, print_parse_summary
from modules.utilities import (
    load_hashes_from_file,
    save_results,
    setup_logging,
    decode_hash_input,
    validate_file,
)

# ANSI
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"


def parse_args():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="hashhunter",
        description="HashHunter — Professional Hash Analysis & Cracking Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Identify a hash:
    python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --identify-only

  Dictionary attack (single hash):
    python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt

  Crack a hash file (all formats auto-detected):
    python main.py --hash-file /etc/shadow --wordlist rockyou.txt

  Crack a pwdump/NTLM dump:
    python main.py --hash-file dump.ntds --wordlist rockyou.txt --attack-mode hybrid

  Crack a plain hash list file:
    python main.py --hash-file hashes.txt --wordlist rockyou.txt --threads 8

  Brute-force attack:
    python main.py --hash <hash> --attack-mode brute --min-length 3 --max-length 6

  Save results as JSON:
    python main.py --hash-file hashes.txt --wordlist rockyou.txt --output results.json
        """
    )

    # --- Input (mutually exclusive group) ---
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--hash", "-H",
        metavar="HASH",
        help="Single hash value to analyze/crack"
    )
    input_group.add_argument(
        "--hash-file", "--file", "-f",
        metavar="FILE",
        dest="hash_file",
        help=(
            "Hash file to crack. Auto-detects format: plain list, "
            "/etc/shadow, pwdump/NTLM dump, John-the-Ripper, "
            "hashcat potfile, hash:salt, user:hash, and more."
        )
    )

    # --- Attack Configuration ---
    parser.add_argument(
        "--wordlist", "-w",
        metavar="FILE",
        help="Path to wordlist file for dictionary/hybrid attack"
    )
    parser.add_argument(
        "--attack-mode", "-a",
        choices=["dictionary", "brute", "hybrid", "combinator", "rainbow", "auto"],
        default="dictionary",
        metavar="MODE",
        help=(
            "Attack mode (default: dictionary):\n"
            "  dictionary  — wordlist attack (easy→hard ordering)\n"
            "  hybrid      — wordlist + 6-pass mutations (Password@1, p@ssw0rd etc.)\n"
            "  combinator  — word+word combos (davedhruv, adminpass)\n"
            "  brute       — exhaustive charset search\n"
            "  rainbow     — local rainbow table lookup\n"
            "  auto        — tries all modes in order until cracked"
        )
    )
    parser.add_argument(
        "--hash-type", "-t",
        metavar="TYPE",
        help="Force a specific hash type (e.g. md5, sha1, sha256). Auto-detected if omitted."
    )

    # --- Brute Force ---
    parser.add_argument(
        "--min-length",
        type=int,
        default=1,
        metavar="N",
        help="Minimum password length for brute-force (default: 1)"
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=6,
        metavar="N",
        help="Maximum password length for brute-force (default: 6)"
    )
    parser.add_argument(
        "--charset",
        default="lowercase",
        choices=["lowercase", "uppercase", "digits", "mixed", "full", "custom"],
        help="Character set for brute-force (default: lowercase)"
    )
    parser.add_argument(
        "--custom-charset",
        metavar="CHARS",
        help="Custom character set string (use with --charset custom)"
    )

    # --- Performance ---
    parser.add_argument(
        "--threads", "-T",
        type=int,
        default=4,
        metavar="N",
        help="Number of threads/workers (default: 4)"
    )

    # --- Rainbow Table ---
    parser.add_argument(
        "--rainbow-dir",
        metavar="DIR",
        help="Directory containing rainbow table files (.rt or .rtc)"
    )

    # --- Output & Misc ---
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save cracked results to file (.txt, .json, or .csv)"
    )
    parser.add_argument(
        "--identify-only",
        action="store_true",
        help="Only identify the hash type(s), do not crack"
    )
    parser.add_argument(
        "--show-format",
        action="store_true",
        help="Show detected file format and sample entries, then exit"
    )
    parser.add_argument(
        "--encoding",
        choices=["auto", "hex", "base64"],
        default="auto",
        help="Input hash encoding (default: auto-detect)"
    )
    parser.add_argument(
        "--log-file",
        metavar="FILE",
        help="Write detailed logs to this file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the startup banner"
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Identification helper
# ---------------------------------------------------------------------------

def run_identification(hashes, detector, verbose):
    """Run hash identification on a list of hashes and print results."""
    print(f"\n[*] Analyzing {len(hashes)} hash(es)...\n")
    for raw_hash in hashes:
        result = detector.identify(raw_hash)
        print(f"  Hash     : {raw_hash[:64]}{'...' if len(raw_hash) > 64 else ''}")
        print(f"  Length   : {result['length']} chars")
        print(f"  Type(s)  : {', '.join(result['possible_types']) or 'Unknown'}")
        print(f"  Best Bet : {result['best_guess']}")
        print(f"  Entropy  : {result['entropy']:.2f} bits/char")
        if result.get("encoding"):
            print(f"  Encoding : {result['encoding']}")
        print()


# ---------------------------------------------------------------------------
# Result printer
# ---------------------------------------------------------------------------

def print_results(results):
    cracked_count = sum(1 for r in results if r["cracked"])
    print(f"\n{'='*62}")
    print(f"  RESULTS  —  {cracked_count} cracked  /  {len(results)} total")
    print(f"{'='*62}")
    for r in results:
        if r["cracked"]:
            uname = f"  [{r.get('username','')}]" if r.get("username") else ""
            print(f"  {GREEN}✓ CRACKED{RESET}{uname}")
            print(f"    Hash      : {r['hash'][:60]}{'...' if len(r['hash'])>60 else ''}")
            print(f"    Type      : {r['hash_type']}")
            print(f"    Plaintext : {GREEN}{r['plaintext']}{RESET}")
            print(f"    Method    : {r['method']}  ({r['elapsed']:.2f}s)")
        else:
            print(f"  {YELLOW}✗ NOT FOUND{RESET}  {r['hash'][:52]}  [{r['hash_type']}]")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    logger = setup_logging(args.log_file, args.verbose)

    if not args.no_banner:
        print_banner()
        print_warning()
        time.sleep(1)

    detector = HashDetector()

    # -----------------------------------------------------------------------
    # HASH FILE mode  (--hash-file)
    # -----------------------------------------------------------------------
    if args.hash_file:
        if not validate_file(args.hash_file):
            print(f"[!] File not found or unreadable: {args.hash_file}")
            sys.exit(1)

        print(f"\n[*] Parsing hash file: {CYAN}{args.hash_file}{RESET}")
        try:
            parsed = parse_hash_file(args.hash_file, args.encoding)
        except Exception as exc:
            print(f"[!] Failed to parse file: {exc}")
            sys.exit(1)

        print_parse_summary(parsed)

        # --show-format stops here
        if args.show_format:
            sys.exit(0)

        # --identify-only on file
        if args.identify_only:
            run_identification(parsed.unique_hashes, detector, args.verbose)
            sys.exit(0)

        # Validate attack prerequisites
        if args.attack_mode in ("dictionary", "hybrid"):
            if not args.wordlist:
                print("[!] --wordlist is required for dictionary and hybrid attacks.")
                sys.exit(1)
            if not validate_file(args.wordlist):
                print(f"[!] Wordlist file not found: {args.wordlist}")
                sys.exit(1)
        if args.attack_mode == "rainbow":
            if not args.rainbow_dir or not os.path.isdir(args.rainbow_dir):
                print("[!] --rainbow-dir must point to a valid directory.")
                sys.exit(1)

        engine_config = {
            "threads": args.threads,
            "wordlist": args.wordlist,
            "attack_mode": args.attack_mode,
            "min_length": args.min_length,
            "max_length": args.max_length,
            "charset": args.charset,
            "custom_charset": args.custom_charset,
            "rainbow_dir": args.rainbow_dir,
            "hash_type": args.hash_type,
            "verbose": args.verbose,
        }
        engine = AttackEngine(detector, engine_config, logger)

        def handle_interrupt(sig, frame):
            print("\n\n[!] Interrupted. Saving partial results...")
            engine.pause()
            if args.output and engine.results:
                save_results(engine.results, args.output)
                print(f"[+] Partial results saved to '{args.output}'")
            sys.exit(0)

        signal.signal(signal.SIGINT, handle_interrupt)

        print(f"[*] Starting batch crack — {len(parsed.crackable_entries)} unique hash(es)\n")
        results = engine.run_batch_file(parsed)

        print_results(results)

        if args.output:
            save_results(results, args.output)
            print(f"[+] Results saved to '{args.output}'")

        cracked = sum(1 for r in results if r["cracked"])
        logger.info("Batch complete. %d/%d hashes cracked.", cracked, len(results))
        return

    # -----------------------------------------------------------------------
    # SINGLE HASH mode  (--hash)
    # -----------------------------------------------------------------------
    decoded = decode_hash_input(args.hash, args.encoding)
    if not decoded:
        print(f"[!] Could not decode hash input: {args.hash}")
        sys.exit(1)

    if args.identify_only:
        run_identification([decoded], detector, args.verbose)
        sys.exit(0)

    if args.attack_mode in ("dictionary", "hybrid", "combinator", "auto"):
        if not args.wordlist:
            print("[!] --wordlist is required for dictionary, hybrid, combinator and auto attacks.")
            sys.exit(1)
        if not validate_file(args.wordlist):
            print(f"[!] Wordlist file not found: {args.wordlist}")
            sys.exit(1)
    if args.attack_mode == "rainbow":
        if not args.rainbow_dir or not os.path.isdir(args.rainbow_dir):
            print("[!] --rainbow-dir must point to a valid directory.")
            sys.exit(1)
    if args.charset == "custom" and not args.custom_charset:
        print("[!] --custom-charset is required when --charset custom is used.")
        sys.exit(1)

    engine_config = {
        "threads": args.threads,
        "wordlist": args.wordlist,
        "attack_mode": args.attack_mode,
        "min_length": args.min_length,
        "max_length": args.max_length,
        "charset": args.charset,
        "custom_charset": args.custom_charset,
        "rainbow_dir": args.rainbow_dir,
        "hash_type": args.hash_type,
        "verbose": args.verbose,
    }

    engine = AttackEngine(detector, engine_config, logger)

    def handle_interrupt(sig, frame):
        print("\n\n[!] Interrupted. Saving partial results...")
        engine.pause()
        if args.output:
            save_results(engine.results, args.output)
            print(f"[+] Partial results saved to '{args.output}'")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_interrupt)
    results = engine.run([decoded])
    print_results(results)

    if args.output:
        save_results(results, args.output)
        print(f"[+] Results saved to '{args.output}'")

    cracked = sum(1 for r in results if r["cracked"])
    logger.info("Session complete. %d/%d hashes cracked.", cracked, len(results))


if __name__ == "__main__":
    main()
