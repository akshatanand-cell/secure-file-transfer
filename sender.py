"""
sender.py — Encrypt a file and send it over TCP to a receiver.
Secure File Transfer Challenge

Usage:
    python sender.py --file secret.txt --host 192.168.1.10 --port 9000
    python sender.py --file photo.jpg  --host 192.168.1.10 --port 9000 --password mypass
"""

import argparse
import json
import os
import socket
import struct
import tempfile

from crypto_utils import (
    generate_key,
    derive_key_from_password,
    encrypt_file,
    save_key,
)

CHUNK = 4096


def send_file(host: str, port: int, file_path: str, password: str = None):
    print(f"\n{'='*55}")
    print("  🔐  SECURE FILE TRANSFER — SENDER")
    print(f"{'='*55}")

    # ── 1. Key setup ──────────────────────────────────────────
    if password:
        salt = os.urandom(16)
        key, salt = derive_key_from_password(password, salt)
        key_info = {"mode": "password", "salt_hex": salt.hex()}
        print(f"  [KEY]  Derived from password (PBKDF2-SHA256, 480k iters)")
    else:
        key = generate_key()
        key_info = {"mode": "random"}
        save_key(key, "sender.key")
        print(f"  [KEY]  Random AES-256 key saved → sender.key")

    # ── 2. Encrypt ────────────────────────────────────────────
    tmp_enc = tempfile.NamedTemporaryFile(delete=False, suffix=".enc")
    tmp_enc.close()

    metadata = encrypt_file(file_path, tmp_enc.name, key)
    metadata.update(key_info)

    print(f"  [ENC]  {file_path} encrypted ({metadata['original_size']} bytes → "
          f"{metadata['encrypted_size']} bytes)")
    print(f"  [ENC]  Nonce: {metadata['nonce'][:16]}...")

    # ── 3. Connect & send ─────────────────────────────────────
    print(f"\n  [NET]  Connecting to {host}:{port} …")
    with socket.create_connection((host, port), timeout=30) as sock:
        print(f"  [NET]  Connected ✓")

        # Send metadata (length-prefixed JSON)
        meta_bytes = json.dumps(metadata).encode()
        sock.sendall(struct.pack("!I", len(meta_bytes)))
        sock.sendall(meta_bytes)

        # Send encrypted file (length-prefixed)
        enc_size = os.path.getsize(tmp_enc.name)
        sock.sendall(struct.pack("!Q", enc_size))
        sent = 0
        with open(tmp_enc.name, "rb") as f:
            while chunk := f.read(CHUNK):
                sock.sendall(chunk)
                sent += len(chunk)
                pct = sent / enc_size * 100
                print(f"  [TX]   {sent}/{enc_size} bytes  ({pct:.1f}%)", end="\r")

        print(f"\n  [TX]   Transfer complete ✓")

    os.unlink(tmp_enc.name)
    print(f"\n  ✅  Done! Receiver can now decrypt with the shared key/password.")
    print(f"{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(description="Encrypt and send a file securely over TCP.")
    parser.add_argument("--file",     required=True,        help="File to encrypt and send")
    parser.add_argument("--host",     required=True,        help="Receiver IP address")
    parser.add_argument("--port",     type=int, default=9000, help="Receiver port (default 9000)")
    parser.add_argument("--password", default=None,         help="Shared password (optional; if omitted, a random key is used)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"❌  File not found: {args.file}")
        return

    send_file(args.host, args.port, args.file, args.password)


if __name__ == "__main__":
    main()
