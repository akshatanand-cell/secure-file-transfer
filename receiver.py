"""
receiver.py — Listen for an incoming encrypted file, then decrypt it.
Secure File Transfer Challenge

Usage:
    python receiver.py --port 9000
    python receiver.py --port 9000 --password mypass
    python receiver.py --port 9000 --keyfile sender.key
"""

import argparse
import json
import os
import socket
import struct

from crypto_utils import (
    derive_key_from_password,
    decrypt_file,
    load_key,
)

CHUNK = 4096


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        data = sock.recv(n - len(buf))
        if not data:
            raise ConnectionError("Connection closed prematurely")
        buf += data
    return buf


def receive_file(port: int, password: str = None, keyfile: str = None, out_dir: str = "."):
    print(f"\n{'='*55}")
    print("  📥  SECURE FILE TRANSFER — RECEIVER")
    print(f"{'='*55}")
    print(f"  [NET]  Listening on port {port} …\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)

    conn, addr = server.accept()
    print(f"  [NET]  Connection from {addr[0]}:{addr[1]} ✓")

    with conn:
        # ── Receive metadata ──────────────────────────────────
        meta_len = struct.unpack("!I", recv_exact(conn, 4))[0]
        metadata  = json.loads(recv_exact(conn, meta_len).decode())

        print(f"  [META] File: {metadata['original_name']}")
        print(f"  [META] Original size: {metadata['original_size']} bytes")
        print(f"  [META] Nonce: {metadata['nonce'][:16]}...")

        # ── Receive encrypted data ────────────────────────────
        enc_size = struct.unpack("!Q", recv_exact(conn, 8))[0]
        tmp_path = os.path.join(out_dir, "__received.enc")

        received = 0
        with open(tmp_path, "wb") as f:
            while received < enc_size:
                to_read = min(CHUNK, enc_size - received)
                chunk = conn.recv(to_read)
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
                pct = received / enc_size * 100
                print(f"  [RX]   {received}/{enc_size} bytes  ({pct:.1f}%)", end="\r")

        print(f"\n  [RX]   Receive complete ✓")

    server.close()

    # ── Key resolution ────────────────────────────────────────
    if password:
        salt = bytes.fromhex(metadata["salt_hex"])
        key, _ = derive_key_from_password(password, salt)
        print(f"  [KEY]  Derived key from password ✓")
    elif keyfile:
        key = load_key(keyfile)
        print(f"  [KEY]  Loaded key from {keyfile} ✓")
    else:
        print("  ❌  No key source provided. Use --password or --keyfile.")
        os.unlink(tmp_path)
        return

    # ── Decrypt ───────────────────────────────────────────────
    out_path = os.path.join(out_dir, "decrypted_" + metadata["original_name"])
    try:
        decrypt_file(tmp_path, out_path, key, metadata["nonce"])
        os.unlink(tmp_path)
        print(f"  [DEC]  Decryption successful ✓")
        print(f"  [DEC]  Saved → {out_path}")
        print(f"\n  ✅  File integrity verified (AES-GCM authentication tag passed).")
    except Exception as e:
        print(f"\n  ❌  Decryption FAILED: {e}")
        print("       The file may have been tampered with, or the key is wrong.")

    print(f"{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(description="Receive and decrypt a file sent over TCP.")
    parser.add_argument("--port",     type=int, default=9000, help="Port to listen on (default 9000)")
    parser.add_argument("--password", default=None,           help="Shared password (must match sender)")
    parser.add_argument("--keyfile",  default=None,           help="Path to key file (sender.key)")
    parser.add_argument("--outdir",   default=".",            help="Output directory (default: current)")
    args = parser.parse_args()

    if not args.password and not args.keyfile:
        print("⚠️  Warning: No --password or --keyfile given. Will prompt after receiving metadata.")

    receive_file(args.port, args.password, args.keyfile, args.outdir)


if __name__ == "__main__":
    main()
