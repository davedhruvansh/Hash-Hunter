<div align="center">

# 🔍 HashHunter

### Professional Hash Analysis & Cracking Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-informational?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Kali](https://img.shields.io/badge/Kali%20Linux-Compatible-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)

**Auto-detect and crack MD5, SHA1, SHA256, SHA512, bcrypt, NTLM, and 35+ more hash types.**  
Supports single hashes, batch files, /etc/shadow, pwdump/NTLM dumps, and hashcat potfiles.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Algorithms](#-supported-algorithms) • [Examples](#-examples) • [Contributing](#-contributing)

</div>

---

## ⚠️ Legal Disclaimer

> **This tool is intended for EDUCATIONAL PURPOSES and AUTHORIZED PENETRATION TESTING ONLY.**
>
> Using this tool against systems, accounts, or data that you **do not own** or lack **explicit written permission** to test is:
> - Illegal under the **Computer Fraud and Abuse Act (CFAA)**
> - Illegal under the **UK Computer Misuse Act**
> - A criminal offence in most jurisdictions worldwide
>
> The authors assume **no liability** for any misuse of this software.
> By using this tool, you confirm you have proper authorization.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔎 **Auto Hash Detection** | Automatically identifies 35+ hash types — no manual input needed |
| 📖 **Dictionary Attack** | Stream large wordlists (rockyou.txt) with no RAM issues |
| 💥 **Brute-Force Attack** | Configurable charset and length range |
| 🧬 **Hybrid Attack** | Dictionary + 20+ mutation rules (leet, suffixes, reversal, capitalization) |
| 🌈 **Rainbow Table Lookup** | Scan local `.txt` / `.rt` / `.rtc` table directories |
| 📁 **Smart File Parser** | Auto-detects plain list, `/etc/shadow`, pwdump/NTLM, John format, hashcat potfile |
| ⚡ **Multi-threaded** | Parallel hashing across all CPU cores |
| 📊 **Live Progress** | Real-time percentage, speed (H/s → MH/s), and ETA |
| 💾 **Result Export** | Save results as `.txt`, `.json`, or `.csv` |
| 🔐 **Encoding Support** | Auto-detect hex / base64 encoded hashes |
| 📝 **Logging** | Structured file logging with timestamps |
| ⏸️ **Pause / Resume** | Ctrl+C saves partial results gracefully |

---

## 📦 Installation

### Requirements
- Python 3.8 or higher
- No external dependencies for core usage (pure Python standard library)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/HashHunter.git
cd HashHunter

# Optional: install extras for bcrypt and Argon2 support
pip3 install bcrypt argon2-cffi --break-system-packages

# Verify installation works
python3 main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist sample_wordlist.txt --no-banner
```

Expected output:
```
✓ Password found: password
```

### Kali Linux (Recommended)

```bash
# Git and Python3 are pre-installed on Kali
git clone https://github.com/YOUR_USERNAME/HashHunter.git
cd HashHunter

# Unlock the built-in rockyou wordlist (14 million passwords)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Start cracking
python3 main.py --hash <HASH> --wordlist /usr/share/wordlists/rockyou.txt
```

---

## 🚀 Usage

### Basic Syntax

```
python3 main.py [--hash HASH | --hash-file FILE] [OPTIONS]
```

### All CLI Options

| Flag | Short | Description |
|---|---|---|
| `--hash HASH` | `-H` | Single hash to analyze or crack |
| `--hash-file FILE` | `-f` | Hash file to crack (format auto-detected) |
| `--wordlist FILE` | `-w` | Wordlist for dictionary / hybrid attack |
| `--attack-mode MODE` | `-a` | `dictionary` \| `brute` \| `hybrid` \| `rainbow` |
| `--hash-type TYPE` | `-t` | Force hash type — auto-detected if omitted |
| `--min-length N` | | Minimum brute-force length (default: 1) |
| `--max-length N` | | Maximum brute-force length (default: 6) |
| `--charset SET` | | `lowercase` \| `uppercase` \| `digits` \| `mixed` \| `full` \| `custom` |
| `--custom-charset` | | Custom characters (use with `--charset custom`) |
| `--threads N` | `-T` | Worker thread count (default: 4) |
| `--rainbow-dir DIR` | | Directory with rainbow table files |
| `--output FILE` | `-o` | Save results to `.txt`, `.json`, or `.csv` |
| `--identify-only` | | Identify hash type only, do not crack |
| `--show-format` | | Show detected file format and exit |
| `--encoding` | | `auto` \| `hex` \| `base64` (default: auto) |
| `--log-file FILE` | | Write detailed logs to file |
| `--verbose` | `-v` | Enable debug output |
| `--no-banner` | | Suppress the startup banner |

---

## 📖 Examples

### Identify a Hash Type
```bash
python3 main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --identify-only
```
```
Hash     : 5f4dcc3b5aa765d61d8327deb882cf99
Length   : 32 chars
Type(s)  : MD5, NTLM, MD4
Best Bet : MD5
Entropy  : 3.80 bits/char
Encoding : hex
```

---

### Dictionary Attack — Single Hash
```bash
python3 main.py \
  --hash 5f4dcc3b5aa765d61d8327deb882cf99 \
  --wordlist /usr/share/wordlists/rockyou.txt
```

---

### Crack a Whole Hash File
```bash
# Step 1: check what format the file is
python3 main.py --hash-file hashes.txt --show-format

# Step 2: crack it (single wordlist pass for ALL hashes simultaneously)
python3 main.py \
  --hash-file hashes.txt \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --threads 8
```

---

### Crack /etc/shadow (Linux Password File)
```bash
sudo python3 main.py \
  --hash-file /etc/shadow \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --threads 8
```

---

### Crack a pwdump / NTLM Dump
```bash
python3 main.py \
  --hash-file dump.ntds \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --attack-mode hybrid
```

---

### Hybrid Attack — Wordlist + Mutations
```bash
# Tries: password, Password, PASSWORD, p@ssw0rd, password123, etc.
python3 main.py \
  --hash-file hashes.txt \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --attack-mode hybrid \
  --threads 8
```

---

### Brute-Force — Digits Only (e.g. PINs)
```bash
python3 main.py \
  --hash e10adc3949ba59abbe56e057f20f883e \
  --attack-mode brute \
  --charset digits \
  --min-length 4 \
  --max-length 6
```

---

### Brute-Force — Custom Charset
```bash
python3 main.py \
  --hash <HASH> \
  --attack-mode brute \
  --charset custom \
  --custom-charset "abc123!@#" \
  --max-length 8
```

---

### Save Results as JSON
```bash
python3 main.py \
  --hash-file hashes.txt \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --output results.json \
  --threads 8
```

---

### Rainbow Table Lookup
```bash
python3 main.py \
  --hash 5f4dcc3b5aa765d61d8327deb882cf99 \
  --attack-mode rainbow \
  --rainbow-dir ./tables/
```

---

## 🔐 Supported Algorithms

### Standard Hash Functions

| Algorithm | Length | Common Use |
|---|---|---|
| MD4 | 32 chars | Old Windows internals |
| **MD5** | 32 chars | Web apps, old Linux |
| **SHA-1** | 40 chars | Git, old SSL certs |
| SHA-224 | 56 chars | Embedded systems |
| **SHA-256** | 64 chars | Bitcoin, modern apps |
| SHA-384 | 96 chars | TLS certificates |
| **SHA-512** | 128 chars | Modern Linux, secure apps |
| SHA3-224 | 56 chars | Next-gen SHA |
| SHA3-256 | 64 chars | Next-gen SHA |
| SHA3-384 | 96 chars | Next-gen SHA |
| SHA3-512 | 128 chars | Next-gen SHA |
| RIPEMD-128 | 32 chars | Older crypto |
| RIPEMD-160 | 40 chars | Bitcoin addresses |
| RIPEMD-256 | 64 chars | Secure hashing |
| RIPEMD-320 | 80 chars | Secure hashing |
| BLAKE2b-256 | 64 chars | Modern fast hash |
| BLAKE2b-512 | 128 chars | Modern fast hash |
| Whirlpool | 128 chars | ISO standard |
| CRC32 | 8 chars | File checksums |

### Password / KDF Hashes (Slow by Design)

| Algorithm | Prefix | Used In |
|---|---|---|
| **bcrypt** | `$2b$` / `$2y$` | Linux, PHP, Node.js |
| Argon2i | `$argon2i$` | Modern apps |
| **Argon2id** | `$argon2id$` | Django, secure apps |
| scrypt | `$scrypt$` | Crypto wallets |
| PBKDF2-SHA1 | `pbkdf2_sha1$` | Django (legacy) |
| PBKDF2-SHA256 | `pbkdf2_sha256$` | Django (default) |
| PBKDF2-SHA512 | `pbkdf2_sha512$` | Django (strong) |

### Operating System Hashes

| Algorithm | Format | Used In |
|---|---|---|
| MD5crypt | `$1$salt$hash` | Old Linux `/etc/shadow` |
| SHA256crypt | `$5$salt$hash` | Linux `/etc/shadow` |
| **SHA512crypt** | `$6$salt$hash` | Modern Linux `/etc/shadow` |
| Apache MD5 | `$apr1$` | Apache `.htpasswd` |
| **NTLM** | 32 hex chars | Windows login |
| LM Hash | 32 hex chars | Old Windows (pre-Vista) |
| Domain Cached | 32 hex chars | Windows offline login |

### CMS / Application Hashes

| Algorithm | Prefix | Used In |
|---|---|---|
| **WordPress** | `$P$` | WordPress sites |
| Drupal 7 | `$S$` | Drupal CMS |
| phpBB3 | `$H$` | phpBB forums |
| Joomla | `hash:salt` | Joomla CMS |
| vBulletin | `hash:salt` | vBulletin forums |
| MySQL 3.x | 16 hex | Old MySQL |
| MySQL 4.1+ | `*` + 40 hex | Modern MySQL |

### Network / Device Hashes

| Algorithm | Used In |
|---|---|
| Cisco Type 5 | Cisco IOS routers |
| Cisco Type 7 | Cisco (weak, reversible) |
| WPA/WPA2 PSK | WiFi passwords |

---

## 📁 Supported Hash File Formats

HashHunter **automatically detects** the format — just point it at the file:

| Format | Example Line | Auto-Detected |
|---|---|---|
| Plain hash list | `5f4dcc3b5aa765d61d8327deb882cf99` | ✅ |
| user:hash (John) | `alice:5f4dcc3b5aa765d61d8327deb882cf99` | ✅ |
| hash:salt | `5f4dcc3b...:a3f2b1c9` | ✅ |
| /etc/shadow | `root:$6$salt$hash...:18000:0:99999:7:::` | ✅ |
| pwdump / NTLM | `Admin:500:LMhash:NThash:::` | ✅ |
| Hashcat potfile | `5f4dcc3b...:password` | ✅ (skips re-cracking) |
| Mixed algorithms | SHA1 and SHA256 in same file | ✅ |

---

## 🧬 Hybrid Attack — Mutation Rules

Every wordlist entry gets these transformations applied:

| Rule | Input → Output |
|---|---|
| Capitalize | `password` → `Password` |
| Uppercase | `password` → `PASSWORD` |
| Leet speak | `password` → `p@$$w0rd` |
| Reverse | `password` → `drowssap` |
| Append digits | `password` → `password1`, `password123` |
| Append symbols | `password` → `password!`, `password@` |
| Year suffixes | `password` → `password2024` |
| Common prefixes | `password` → `123password` |
| Word doubling | `password` → `passwordpassword` |
| Title case | `hello world` → `Hello World` |

---

## 🗂️ Project Structure

```
HashHunter/
│
├── main.py                       # CLI entry point (argparse)
├── requirements.txt              # Python dependencies
├── sample_wordlist.txt           # Demo wordlist (60 passwords)
├── sample_hashes.txt             # Demo hash batch file
├── .gitignore
├── README.md                     # This file
│
├── modules/
│   ├── __init__.py
│   ├── banner.py                 # ASCII art banner & ethics warning
│   ├── hash_detector.py          # Hash identification engine (35+ types)
│   ├── hash_file_parser.py       # Smart file parser (7 formats)
│   ├── attack_engine.py          # All attack modes + batch engine
│   ├── mutations.py              # Hybrid mutation rules
│   └── utilities.py              # Logging, I/O, encoding helpers
│
└── tests/
    ├── test_hash_detector.py     # 30 unit tests
    └── test_hash_file_parser.py  # 27 unit tests
```

---

## 🧪 Running Tests

```bash
# Run all 57 tests
python3 -m unittest tests/test_hash_detector.py tests/test_hash_file_parser.py -v

# Expected result:
# Ran 57 tests in 0.012s
# OK
```

---

## ⚡ Performance Tips

```bash
# 1. Check your CPU core count
nproc

# 2. Use all cores
python3 main.py --hash-file hashes.txt \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --threads $(nproc)

# 3. Batch mode reads the wordlist ONCE for ALL hashes simultaneously
#    Much faster than cracking hashes one by one

# 4. For bcrypt / Argon2 (intentionally slow), use hashcat with GPU:
hashcat -m 3200 -a 0 hash.txt rockyou.txt    # bcrypt
hashcat -m 1400 -a 0 hash.txt rockyou.txt    # SHA-256
hashcat -m 1800 -a 0 hash.txt rockyou.txt    # SHA-512crypt
```

---

## 🔗 Works Great With These Kali Tools

| Tool | Command | Purpose |
|---|---|---|
| **hashcat** | `hashcat -m 0 hash.txt rockyou.txt` | GPU-accelerated cracking |
| **john** | `john --wordlist=rockyou.txt hash.txt` | John the Ripper |
| **hash-identifier** | `hash-identifier` | Quick hash check |
| **rockyou.txt** | `/usr/share/wordlists/rockyou.txt` | 14M password wordlist |
| **SecLists** | `sudo apt install seclists` | Huge wordlist collection |

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!

```bash
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/HashHunter.git
cd HashHunter

# 3. Create a feature branch
git checkout -b feature/your-feature-name

# 4. Make your changes and add tests

# 5. Run tests
python3 -m unittest tests/ -v

# 6. Commit and push
git add .
git commit -m "Add: description of your feature"
git push origin feature/your-feature-name

# 7. Open a Pull Request on GitHub
```

### Ideas for Contributions
- Support more hash algorithms
- More hybrid mutation rules
- Improved GPU integration with hashcat
- New hash file format parsers
- Better detection accuracy

---

## 📄 License

```
MIT License — Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## ⚖️ Ethical Use

This tool is built for:

| ✅ Allowed | ❌ Not Allowed |
|---|---|
| CTF (Capture The Flag) competitions | Unauthorized access to accounts |
| Learning about password security | Cracking hashes you don't own |
| Authorized penetration testing | Any illegal activity |
| Testing your own systems | Targeting other people's data |
| Security research | Bypassing authentication without permission |

**Always get written permission before testing any system you do not own.**

---

<div align="center">

Made with ❤️ for the cybersecurity community

⭐ **Star this repo if you found it helpful!**

</div>
