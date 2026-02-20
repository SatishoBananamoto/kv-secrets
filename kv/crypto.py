"""Encryption engine for kv.

Key generation, derivation, encrypt/decrypt using ChaCha20-Poly1305 AEAD.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def generate_master_key():
    """Generate a 256-bit random master key."""
    return os.urandom(32)


def derive_env_key(master_key, env_name):
    """Derive a per-environment encryption key from the master key.

    Uses BLAKE2b keyed hash — deterministic, so we never store per-env keys.
    """
    h = hashlib.blake2b(env_name.encode("utf-8"), key=master_key, digest_size=32)
    return h.digest()


def encrypt(key, plaintext, env_name):
    """Encrypt plaintext bytes with ChaCha20-Poly1305.

    Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)
    The environment name is bound as additional authenticated data.
    """
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, env_name.encode("utf-8"))
    return nonce + ciphertext


def decrypt(key, blob, env_name):
    """Decrypt a blob produced by encrypt().

    Raises cryptography.exceptions.InvalidTag on tamper or wrong key.
    """
    nonce = blob[:12]
    ciphertext = blob[12:]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, env_name.encode("utf-8"))


def save_key(key, path):
    """Save a master key as base64url to a file."""
    encoded = base64.urlsafe_b64encode(key).decode("ascii")
    with open(path, "w", encoding="ascii") as f:
        f.write(encoded + "\n")

    # Restrict permissions on Unix (owner-only read/write)
    if os.name != "nt":
        os.chmod(path, 0o600)


def load_key(path):
    """Load a master key from a base64url file."""
    with open(path, "r", encoding="ascii") as f:
        encoded = f.read().strip()
    return base64.urlsafe_b64decode(encoded)


# ── Key sharing ───────────────────────────────────────────

KEY_PREFIX = "kvkey_"


def export_key(master_key):
    """Format a master key as a shareable string: kvkey_<base64url>."""
    encoded = base64.urlsafe_b64encode(master_key).decode("ascii").rstrip("=")
    return KEY_PREFIX + encoded


def import_key(token):
    """Parse a kvkey_<base64url> token back to raw key bytes."""
    if not token.startswith(KEY_PREFIX):
        raise ValueError("invalid key token (must start with kvkey_)")
    encoded = token[len(KEY_PREFIX):]
    # Re-add padding
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    return base64.urlsafe_b64decode(encoded)
