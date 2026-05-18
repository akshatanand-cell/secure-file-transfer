"""
crypto_utils.py — AES-256-GCM encryption/decryption utilities
Secure File Transfer Challenge
"""

import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def generate_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def derive_key_from_password(password: str, salt: bytes = None):
    """Derive an AES-256 key from a human-readable password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    key = kdf.derive(password.encode())
    return key, salt


def encrypt_file(input_path: str, output_path: str, key: bytes) -> dict:
    """
    Encrypt a file using AES-256-GCM.

    Args:
        input_path:  Path to the plaintext file.
        output_path: Path where the encrypted file will be saved.
        key:         32-byte AES key.

    Returns:
        metadata dict containing nonce, original filename, and file size.
    """
    nonce = os.urandom(12)          # 96-bit nonce — GCM standard
    aesgcm = AESGCM(key)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(ciphertext)

    metadata = {
        "nonce":          base64.b64encode(nonce).decode(),
        "original_name":  os.path.basename(input_path),
        "original_size":  len(plaintext),
        "encrypted_size": len(ciphertext),
    }
    return metadata


def decrypt_file(input_path: str, output_path: str, key: bytes, nonce_b64: str) -> bool:
    """
    Decrypt a file using AES-256-GCM.

    Args:
        input_path:  Path to the encrypted file.
        output_path: Path where the decrypted file will be saved.
        key:         32-byte AES key.
        nonce_b64:   Base64-encoded nonce from metadata.

    Returns:
        True on success, raises an exception on failure (tampered data etc.).
    """
    nonce = base64.b64decode(nonce_b64)
    aesgcm = AESGCM(key)

    with open(input_path, "rb") as f:
        ciphertext = f.read()

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)   # raises if tag invalid

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return True


def save_key(key: bytes, path: str):
    """Save a raw AES key to a file (base64-encoded)."""
    with open(path, "w") as f:
        f.write(base64.b64encode(key).decode())


def load_key(path: str) -> bytes:
    """Load a base64-encoded AES key from a file."""
    with open(path, "r") as f:
        return base64.b64decode(f.read().strip())
