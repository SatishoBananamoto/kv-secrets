"""Tests for kv crypto — key wrapping and TOTP."""

import os
import tempfile
import time
import unittest

from kv.crypto import (
    generate_master_key,
    wrap_master_key,
    unwrap_master_key,
    save_wrapped_key,
    load_wrapped_key,
    is_key_wrapped,
    save_key,
    load_key,
    generate_totp_secret,
    totp_code,
    verify_totp,
    totp_uri,
    encrypt_totp_secret,
    decrypt_totp_secret,
)


class TestKeyWrapping(unittest.TestCase):
    """Passphrase-based key wrapping with PBKDF2 + ChaCha20Poly1305."""

    def test_wrap_unwrap_roundtrip(self):
        """Wrapping and unwrapping with correct passphrase returns original key."""
        key = generate_master_key()
        passphrase = "test-passphrase-1234"
        wrapped = wrap_master_key(key, passphrase)
        recovered = unwrap_master_key(wrapped, passphrase)
        self.assertEqual(key, recovered)

    def test_wrong_passphrase_fails(self):
        """Unwrapping with wrong passphrase raises InvalidTag."""
        from cryptography.exceptions import InvalidTag

        key = generate_master_key()
        wrapped = wrap_master_key(key, "correct-passphrase")
        with self.assertRaises(InvalidTag):
            unwrap_master_key(wrapped, "wrong-passphrase")

    def test_wrapped_blob_has_magic(self):
        """Wrapped blob starts with KVW\\x01 magic bytes."""
        key = generate_master_key()
        wrapped = wrap_master_key(key, "passphrase")
        self.assertEqual(wrapped[:4], b"KVW\x01")

    def test_different_salts_produce_different_blobs(self):
        """Each wrap uses a random salt, so two wraps of same key differ."""
        key = generate_master_key()
        w1 = wrap_master_key(key, "same-passphrase")
        w2 = wrap_master_key(key, "same-passphrase")
        self.assertNotEqual(w1, w2)  # different salt + nonce
        # But both unwrap to the same key
        self.assertEqual(unwrap_master_key(w1, "same-passphrase"), key)
        self.assertEqual(unwrap_master_key(w2, "same-passphrase"), key)

    def test_save_load_wrapped_key(self):
        """Save wrapped key to file and load it back."""
        key = generate_master_key()
        passphrase = "file-test-passphrase"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            save_wrapped_key(key, passphrase, path)
            recovered = load_wrapped_key(path, passphrase)
            self.assertEqual(key, recovered)
        finally:
            os.unlink(path)

    def test_is_key_wrapped_detects_wrapped(self):
        """is_key_wrapped returns True for wrapped key files."""
        key = generate_master_key()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            save_wrapped_key(key, "passphrase", path)
            self.assertTrue(is_key_wrapped(path))
        finally:
            os.unlink(path)

    def test_is_key_wrapped_detects_plaintext(self):
        """is_key_wrapped returns False for plaintext key files."""
        key = generate_master_key()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            save_key(key, path)
            self.assertFalse(is_key_wrapped(path))
        finally:
            os.unlink(path)

    def test_is_key_wrapped_missing_file(self):
        """is_key_wrapped returns False for missing files."""
        self.assertFalse(is_key_wrapped("/nonexistent/path"))

    def test_unwrap_bad_magic_raises(self):
        """Unwrapping data without KVW magic raises ValueError."""
        with self.assertRaises(ValueError):
            unwrap_master_key(b"BAAD" + b"\x00" * 76, "passphrase")

    def test_key_length_preserved(self):
        """Unwrapped key is exactly 32 bytes."""
        key = generate_master_key()
        self.assertEqual(len(key), 32)
        recovered = unwrap_master_key(
            wrap_master_key(key, "test"), "test"
        )
        self.assertEqual(len(recovered), 32)


class TestTOTP(unittest.TestCase):
    """TOTP two-factor authentication (RFC 6238)."""

    def test_generate_secret_is_base32(self):
        """Generated secret is valid base32."""
        import base64
        secret = generate_totp_secret()
        # Should not raise
        base64.b32decode(secret)
        # Should be 32 chars (160 bits base32-encoded)
        self.assertEqual(len(secret), 32)

    def test_code_is_6_digits(self):
        """TOTP code is always 6 digits."""
        secret = generate_totp_secret()
        code = totp_code(secret)
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_same_secret_same_time_same_code(self):
        """Same secret + same time produces same code."""
        secret = generate_totp_secret()
        t = time.time()
        c1 = totp_code(secret, t)
        c2 = totp_code(secret, t)
        self.assertEqual(c1, c2)

    def test_different_secrets_different_codes(self):
        """Different secrets produce different codes (with high probability)."""
        s1 = generate_totp_secret()
        s2 = generate_totp_secret()
        t = time.time()
        # Could theoretically collide, but 1-in-1M chance
        self.assertNotEqual(totp_code(s1, t), totp_code(s2, t))

    def test_verify_current_code(self):
        """verify_totp accepts the current code."""
        secret = generate_totp_secret()
        code = totp_code(secret)
        self.assertTrue(verify_totp(secret, code))

    def test_verify_wrong_code_fails(self):
        """verify_totp rejects wrong codes."""
        secret = generate_totp_secret()
        self.assertFalse(verify_totp(secret, "000000"))

    def test_verify_window_tolerance(self):
        """verify_totp accepts codes within the time window."""
        secret = generate_totp_secret()
        # Code from 30 seconds ago should still verify with window=1
        past_code = totp_code(secret, time.time() - 30)
        self.assertTrue(verify_totp(secret, past_code, window=1))

    def test_totp_uri_format(self):
        """totp_uri produces valid otpauth:// URI."""
        secret = generate_totp_secret()
        uri = totp_uri(secret, account="test", issuer="kv")
        self.assertTrue(uri.startswith("otpauth://totp/"))
        self.assertIn(secret, uri)
        self.assertIn("issuer=kv", uri)


class TestTOTPSecretEncryption(unittest.TestCase):
    """Encrypting TOTP secret for config storage."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted TOTP secret can be decrypted with same passphrase."""
        secret = generate_totp_secret()
        passphrase = "totp-test-pass"
        encrypted = encrypt_totp_secret(secret, passphrase)
        recovered = decrypt_totp_secret(encrypted, passphrase)
        self.assertEqual(secret, recovered)

    def test_wrong_passphrase_fails(self):
        """Decrypting TOTP secret with wrong passphrase raises."""
        from cryptography.exceptions import InvalidTag

        secret = generate_totp_secret()
        encrypted = encrypt_totp_secret(secret, "correct")
        with self.assertRaises(InvalidTag):
            decrypt_totp_secret(encrypted, "wrong")

    def test_encrypted_is_base64(self):
        """Encrypted TOTP secret is base64url-encoded (safe for JSON config)."""
        import base64
        secret = generate_totp_secret()
        encrypted = encrypt_totp_secret(secret, "pass")
        # Should not raise
        base64.urlsafe_b64decode(encrypted)


class TestPassphraseStrength(unittest.TestCase):
    """Passphrase blocklist and strength checks."""

    def test_rejects_common_passwords(self):
        from kv.crypto import check_passphrase_strength
        weak = ["password", "12345678", "qwerty123", "iloveyou", "admin123"]
        for pw in weak:
            ok, reason = check_passphrase_strength(pw)
            self.assertFalse(ok, f"should reject '{pw}'")
            self.assertIn("common", reason.lower())

    def test_rejects_short(self):
        from kv.crypto import check_passphrase_strength
        ok, _ = check_passphrase_strength("short")
        self.assertFalse(ok)

    def test_rejects_all_same_char(self):
        from kv.crypto import check_passphrase_strength
        ok, _ = check_passphrase_strength("aaaaaaaa")
        self.assertFalse(ok)

    def test_rejects_short_all_digits(self):
        from kv.crypto import check_passphrase_strength
        ok, _ = check_passphrase_strength("98765432")
        self.assertFalse(ok)

    def test_accepts_strong_passphrase(self):
        from kv.crypto import check_passphrase_strength
        ok, _ = check_passphrase_strength("correct-horse-battery-staple")
        self.assertTrue(ok)

    def test_case_insensitive_blocklist(self):
        from kv.crypto import check_passphrase_strength
        ok, _ = check_passphrase_strength("PASSWORD")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
