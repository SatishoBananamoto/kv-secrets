"""Integration tests for vault security — passphrase + TOTP protection."""

import json
import os
import shutil
import tempfile
import unittest

from kv.config import init_project, load_config, save_config, key_path, secrets_dir
from kv.crypto import (
    is_key_wrapped,
    load_key,
    load_wrapped_key,
    save_key,
    save_wrapped_key,
    generate_master_key,
    generate_totp_secret,
    encrypt_totp_secret,
    verify_totp,
    totp_code,
)
from kv.store import SecretStore, VaultLockedError


class TestPassphraseProtectedVault(unittest.TestCase):
    """End-to-end: init with passphrase → set secret → retrieve with passphrase."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_init_with_passphrase_wraps_key(self):
        """kv init with passphrase creates a wrapped key file."""
        init_project(self.tmpdir, passphrase="test-passphrase")
        kp = key_path(self.tmpdir)
        self.assertTrue(is_key_wrapped(kp))

    def test_init_without_passphrase_plaintext_key(self):
        """kv init without passphrase creates a plaintext key file."""
        init_project(self.tmpdir)
        kp = key_path(self.tmpdir)
        self.assertFalse(is_key_wrapped(kp))

    def test_config_records_passphrase_status(self):
        """Config records whether passphrase is enabled."""
        init_project(self.tmpdir, passphrase="test")
        config = load_config(self.tmpdir)
        self.assertTrue(config["security"]["passphrase"])

    def test_store_with_passphrase_works(self):
        """SecretStore with correct passphrase can set and get secrets."""
        init_project(self.tmpdir, passphrase="my-passphrase")
        store = SecretStore(self.tmpdir, passphrase="my-passphrase")
        store.set_secret("dev", "API_KEY", "sk-12345")
        self.assertEqual(store.get_secret("dev", "API_KEY"), "sk-12345")

    def test_store_without_passphrase_raises(self):
        """SecretStore without passphrase on wrapped vault raises VaultLockedError."""
        init_project(self.tmpdir, passphrase="my-passphrase")
        store = SecretStore(self.tmpdir)  # no passphrase
        with self.assertRaises(VaultLockedError):
            store.master_key  # triggers key load

    def test_store_wrong_passphrase_raises(self):
        """SecretStore with wrong passphrase raises InvalidTag."""
        from cryptography.exceptions import InvalidTag
        init_project(self.tmpdir, passphrase="correct")
        store = SecretStore(self.tmpdir, passphrase="wrong")
        with self.assertRaises(InvalidTag):
            store.master_key

    def test_plaintext_vault_no_passphrase_needed(self):
        """SecretStore on plaintext vault works without passphrase (backwards compat)."""
        init_project(self.tmpdir)
        store = SecretStore(self.tmpdir)
        store.set_secret("dev", "KEY", "value")
        self.assertEqual(store.get_secret("dev", "KEY"), "value")

    def test_cat_wrapped_key_is_useless(self):
        """Reading a wrapped key file gives binary blob, not the actual key."""
        init_project(self.tmpdir, passphrase="secret")
        kp = key_path(self.tmpdir)
        with open(kp, "rb") as f:
            raw = f.read()
        # It's binary, starts with magic, NOT base64url text
        self.assertTrue(raw.startswith(b"KVW\x01"))
        # Cannot be decoded as the master key
        self.assertNotEqual(len(raw), 45)  # plaintext key would be ~44 chars + newline


class TestUpgradeSecurity(unittest.TestCase):
    """Upgrading a plaintext vault to passphrase-protected."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_upgrade_preserves_secrets(self):
        """Upgrading to passphrase preserves existing encrypted secrets."""
        # Create plaintext vault with a secret
        init_project(self.tmpdir)
        store = SecretStore(self.tmpdir)
        store.set_secret("dev", "DB_URL", "postgres://localhost/mydb")

        # Read the plaintext key
        kp = key_path(self.tmpdir)
        original_key = load_key(kp)

        # Wrap the key
        save_wrapped_key(original_key, "upgrade-pass", kp)

        # Verify secrets still accessible with passphrase
        store2 = SecretStore(self.tmpdir, passphrase="upgrade-pass")
        self.assertEqual(store2.get_secret("dev", "DB_URL"), "postgres://localhost/mydb")

    def test_upgrade_blocks_no_passphrase_access(self):
        """After upgrade, accessing without passphrase fails."""
        init_project(self.tmpdir)
        store = SecretStore(self.tmpdir)
        store.set_secret("dev", "SECRET", "value")

        # Upgrade
        kp = key_path(self.tmpdir)
        original_key = load_key(kp)
        save_wrapped_key(original_key, "pass", kp)

        # No passphrase → locked
        store2 = SecretStore(self.tmpdir)
        with self.assertRaises(VaultLockedError):
            store2.get_secret("dev", "SECRET")


class TestTOTPIntegration(unittest.TestCase):
    """TOTP secret storage and verification in config."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_totp_secret_survives_config_roundtrip(self):
        """TOTP secret encrypted and stored in config can be recovered."""
        init_project(self.tmpdir, passphrase="pass")
        totp_secret = generate_totp_secret()
        passphrase = "pass"

        # Encrypt and store
        encrypted = encrypt_totp_secret(totp_secret, passphrase)
        config = load_config(self.tmpdir)
        config["security"]["totp"] = True
        config["security"]["totp_secret_enc"] = encrypted
        save_config(self.tmpdir, config)

        # Reload and decrypt
        config2 = load_config(self.tmpdir)
        recovered = encrypt_totp_secret.__module__  # just to verify import works
        from kv.crypto import decrypt_totp_secret
        recovered = decrypt_totp_secret(config2["security"]["totp_secret_enc"], passphrase)
        self.assertEqual(totp_secret, recovered)

    def test_totp_verification_after_config_storage(self):
        """TOTP codes verify correctly after secret is stored and recovered."""
        init_project(self.tmpdir, passphrase="pass")
        totp_secret = generate_totp_secret()

        # Generate a code
        code = totp_code(totp_secret)

        # Encrypt, store, recover, verify
        encrypted = encrypt_totp_secret(totp_secret, "pass")
        from kv.crypto import decrypt_totp_secret
        recovered = decrypt_totp_secret(encrypted, "pass")
        self.assertTrue(verify_totp(recovered, code))


class TestCIFallback(unittest.TestCase):
    """KV_MASTER_KEY env var bypasses passphrase (CI/CD support)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._old_env = os.environ.get("KV_MASTER_KEY")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        if self._old_env is not None:
            os.environ["KV_MASTER_KEY"] = self._old_env
        elif "KV_MASTER_KEY" in os.environ:
            del os.environ["KV_MASTER_KEY"]

    def test_env_var_bypasses_wrapped_key(self):
        """KV_MASTER_KEY env var works even when key file is wrapped."""
        import base64

        # Init with passphrase
        init_project(self.tmpdir, passphrase="pass")
        store = SecretStore(self.tmpdir, passphrase="pass")
        store.set_secret("dev", "CI_SECRET", "ci-value")

        # Get the actual master key
        actual_key = store.master_key

        # Remove the key file to force env var path
        kp = key_path(self.tmpdir)
        os.unlink(kp)

        # Set env var
        os.environ["KV_MASTER_KEY"] = base64.urlsafe_b64encode(actual_key).decode()

        # Access without passphrase via env var
        store2 = SecretStore(self.tmpdir)
        self.assertEqual(store2.get_secret("dev", "CI_SECRET"), "ci-value")


if __name__ == "__main__":
    unittest.main()
