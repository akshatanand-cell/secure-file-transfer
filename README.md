# 🔐 Secure File Transfer

> AES-256-GCM encryption · TCP/IP socket transfer · Integrity-verified decryption

---

## Overview

A command-line tool that encrypts any file using **AES-256-GCM** (authenticated encryption), transfers it between two devices over a **raw TCP socket**, and decrypts it on the receiving end — verifying integrity via GCM's authentication tag.

A **browser-based GUI** (React + WebCrypto API) is included as a bonus, enabling drag-and-drop encryption/decryption without the command line.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      SENDER DEVICE                      │
│                                                         │
│  [File] ──► encrypt_file() ──► [.enc file]              │
│                  │                    │                  │
│             AES-256-GCM           TCP Socket ──────────►│
│             (nonce + tag)         port 9000             │
└─────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────┐
│                    RECEIVER DEVICE                      │
│                                                         │
│  TCP Socket ──► [.enc file] ──► decrypt_file()          │
│                                       │                  │
│                                  AES-256-GCM            │
│                                  (verify tag)           │
│                                       │                  │
│                                  [Original File] ✓      │
└─────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Choice | Reason |
|---|---|
| **AES-256-GCM** | Provides both confidentiality and authenticity (AEAD) |
| **Random 96-bit nonce** | Standard GCM nonce size; generated fresh per file |
| **PBKDF2-SHA256** (480k iters) | Password hardening when using `--password` mode |
| **Length-prefixed TCP framing** | Reliable streaming of arbitrary file sizes |
| **JSON metadata header** | Carries nonce + original filename cleanly |

---

## Setup

### Requirements
- Python 3.9+
- Both devices on the same network (or port-forwarded)

### Install
```bash
git clone https://github.com/YOUR_USERNAME/secure-file-transfer
cd secure-file-transfer
pip install -r requirements.txt
```

---

## Usage

### Mode 1 — Password-based (recommended for two humans)

**Receiver** (run first):
```bash
python receiver.py --port 9000 --password mysecretpass
```

**Sender**:
```bash
python sender.py --file document.pdf --host 192.168.1.10 --port 9000 --password mysecretpass
```

---

### Mode 2 — Random key (programmatic use)

**Receiver**:
```bash
python receiver.py --port 9000 --keyfile sender.key
```

**Sender** (saves `sender.key` automatically):
```bash
python sender.py --file photo.jpg --host 192.168.1.10 --port 9000
# copy sender.key to receiver out-of-band, then receiver can decrypt
```

---

## File Structure

```
secure-file-transfer/
├── crypto_utils.py   # AES-256-GCM encrypt/decrypt helpers
├── sender.py         # Encrypt + send over TCP
├── receiver.py       # Receive + decrypt over TCP
├── requirements.txt  # cryptography>=42.0.0
├── gui/
│   └── App.jsx       # Bonus React GUI (WebCrypto API)
└── README.md
```

---

## Security Notes

- **AES-256-GCM** is an AEAD cipher — it encrypts *and* authenticates. Any byte-level tampering during transfer causes decryption to fail loudly.
- The **nonce is never reused** — a fresh random nonce is generated for every encryption operation.
- In password mode, **PBKDF2-SHA256 with 480,000 iterations** is used — resistant to brute-force attacks.
- The raw AES key is **never sent over the network** — only the encrypted ciphertext and nonce travel over TCP.

---

## Bonus — Browser GUI

The `gui/App.jsx` React component uses the **WebCrypto API** (built into all modern browsers) to perform real AES-256-GCM encryption locally — no file ever leaves your device.

Features: drag-and-drop, key copy, visual transfer simulation, and one-click download of encrypted/decrypted files.

---

*FED Entrepreneurship & Skill Development Program — Secure File Transfer Challenge*
