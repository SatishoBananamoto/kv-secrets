"""Encryption engine for kv.

Key generation, derivation, encrypt/decrypt using ChaCha20-Poly1305 AEAD.
Passphrase-based key wrapping with PBKDF2.
TOTP two-factor authentication (RFC 6238, no external deps).
"""

import base64
import hashlib
import hmac
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


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
    """Load a master key from a base64url file (plaintext format)."""
    with open(path, "r", encoding="ascii") as f:
        encoded = f.read().strip()
    return base64.urlsafe_b64decode(encoded)


# ── Passphrase key wrapping ──────────────────────────────

WRAP_MAGIC = b"KVW\x01"  # KV Wrapped, version 1
PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation for SHA-256
WRAP_AAD = b"kv-master-key"


def _derive_wrapping_key(passphrase, salt):
    """Derive a 256-bit wrapping key from passphrase + salt via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def wrap_master_key(master_key, passphrase):
    """Encrypt a master key with a passphrase.

    Returns bytes: MAGIC(4) + salt(16) + nonce(12) + ciphertext+tag(48).
    """
    salt = os.urandom(16)
    wrapping_key = _derive_wrapping_key(passphrase, salt)
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(wrapping_key)
    ciphertext = cipher.encrypt(nonce, master_key, WRAP_AAD)
    return WRAP_MAGIC + salt + nonce + ciphertext


def unwrap_master_key(wrapped_blob, passphrase):
    """Decrypt a master key from a wrapped blob.

    Raises cryptography.exceptions.InvalidTag on wrong passphrase.
    """
    if len(wrapped_blob) < 4 or wrapped_blob[:4] != WRAP_MAGIC:
        raise ValueError("not a wrapped key (bad magic)")
    salt = wrapped_blob[4:20]
    nonce = wrapped_blob[20:32]
    ciphertext = wrapped_blob[32:]
    wrapping_key = _derive_wrapping_key(passphrase, salt)
    cipher = ChaCha20Poly1305(wrapping_key)
    return cipher.decrypt(nonce, ciphertext, WRAP_AAD)


def save_wrapped_key(master_key, passphrase, path):
    """Wrap a master key with passphrase and save to file."""
    blob = wrap_master_key(master_key, passphrase)
    with open(path, "wb") as f:
        f.write(blob)
    if os.name != "nt":
        os.chmod(path, 0o600)


def load_wrapped_key(path, passphrase):
    """Load and unwrap a master key from a wrapped file."""
    with open(path, "rb") as f:
        blob = f.read()
    return unwrap_master_key(blob, passphrase)


def is_key_wrapped(path):
    """Check if a key file uses the wrapped (passphrase-protected) format."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == WRAP_MAGIC
    except (FileNotFoundError, IOError):
        return False


# ── TOTP (RFC 6238) ──────────────────────────────────────


def _hotp(key_bytes, counter):
    """HMAC-based OTP (RFC 4226). Returns 6-digit string."""
    msg = struct.pack(">Q", counter)
    h = hmac.new(key_bytes, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)


def generate_totp_secret():
    """Generate a random 160-bit TOTP secret (base32 encoded)."""
    return base64.b32encode(os.urandom(20)).decode("ascii")


def totp_code(secret, t=None, step=30):
    """Generate the current TOTP code for a secret."""
    key = base64.b32decode(secret)
    counter = int(t or time.time()) // step
    return _hotp(key, counter)


def verify_totp(secret, code, window=1, step=30):
    """Verify a TOTP code with ±window tolerance (default ±30s)."""
    now = time.time()
    for offset in range(-window, window + 1):
        t = now + (offset * step)
        if code == totp_code(secret, t, step):
            return True
    return False


def totp_uri(secret, account="kv-secrets", issuer="kv"):
    """Generate otpauth:// URI for authenticator apps."""
    return f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}"


def encrypt_totp_secret(totp_secret, passphrase):
    """Encrypt TOTP secret with passphrase for storage in config."""
    salt = os.urandom(16)
    wrapping_key = _derive_wrapping_key(passphrase, salt)
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(wrapping_key)
    plaintext = totp_secret.encode("ascii")
    ciphertext = cipher.encrypt(nonce, plaintext, b"kv-totp-secret")
    blob = salt + nonce + ciphertext
    return base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_totp_secret(encrypted_b64, passphrase):
    """Decrypt TOTP secret from config."""
    blob = base64.urlsafe_b64decode(encrypted_b64)
    salt = blob[:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    wrapping_key = _derive_wrapping_key(passphrase, salt)
    cipher = ChaCha20Poly1305(wrapping_key)
    plaintext = cipher.decrypt(nonce, ciphertext, b"kv-totp-secret")
    return plaintext.decode("ascii")


# ── Passphrase strength ──────────────────────────────────

# Top 200 most common passwords from breach databases.
# If a passphrase matches any of these, reject it at creation time.
_COMMON_PASSWORDS = frozenset({
    "password", "12345678", "123456789", "1234567890", "qwerty12",
    "iloveyou", "sunshine", "princess", "football", "charlie",
    "shadow12", "passw0rd", "trustno1", "letmein1", "dragon12",
    "baseball", "master12", "michael1", "jennifer", "jordan23",
    "superman", "harley12", "password1", "password2", "password3",
    "qwerty123", "abc12345", "monkey12", "shadow123", "12341234",
    "11111111", "00000000", "abcdefgh", "qwertyui", "asdfghjk",
    "zxcvbnm1", "admin123", "test1234", "welcome1", "mustang1",
    "access14", "master12", "hello123", "charlie1", "donald12",
    "love1234", "ashley12", "michael!", "internet", "whatever",
    "starwars", "computer", "corvette", "maverick", "samantha",
    "steelers", "dolphins", "jackson1", "1q2w3e4r", "q1w2e3r4",
    "1qaz2wsx", "zaq1xsw2", "pass1234", "passpass", "testtest",
    "changeme", "welcome!", "baseball1", "football1", "basketball",
    "qwert123", "1234qwer", "abcd1234", "dragon123", "monkey123",
    "shadow1234", "sunshine1", "princess1", "password!", "password@",
    "p@ssw0rd", "p@ssword", "passw0rd!", "secret12", "secret123",
    "mysecret", "12345678!", "iloveyou1", "trustno1!", "letmein!",
})


def check_passphrase_strength(passphrase):
    """Check if a passphrase is strong enough. Returns (ok, reason)."""
    if len(passphrase) < 8:
        return False, "passphrase must be at least 8 characters"

    # Check against common passwords (case-insensitive, stripped)
    normalized = passphrase.lower().strip()
    if normalized in _COMMON_PASSWORDS:
        return False, "this passphrase is too common — it appears in breach databases"

    # Check for all-same character
    if len(set(passphrase)) == 1:
        return False, "passphrase cannot be a single repeated character"

    # Check for sequential digits
    if passphrase.isdigit() and len(passphrase) <= 10:
        return False, "all-digit passphrases under 10 characters are too weak"

    return True, ""


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
