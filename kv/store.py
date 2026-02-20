"""Secret store for kv.

Handles .enc file format, secret CRUD, atomic writes.
"""

import json
import os
from datetime import datetime, timezone

from .crypto import load_key, derive_env_key, encrypt, decrypt
from .config import secrets_dir, key_path, add_environment, list_environments


# .enc file format: magic (3) + version (1) + encrypted payload
MAGIC = b"KV\x00"
VERSION = 1


class SecretStore:
    """Manages encrypted secrets for a project."""

    def __init__(self, project_root):
        self.root = project_root
        self._master_key = None

    @property
    def master_key(self):
        if self._master_key is None:
            kp = key_path(self.root)
            if not os.path.isfile(kp):
                raise FileNotFoundError(
                    f"master key not found: {kp}\n"
                    "  run 'kv init' first, or check your .secrets/ directory"
                )
            self._master_key = load_key(kp)
        return self._master_key

    def _env_key(self, env_name):
        """Derive the encryption key for an environment."""
        return derive_env_key(self.master_key, env_name)

    def _enc_path(self, env_name):
        """Path to the .enc file for an environment."""
        return os.path.join(secrets_dir(self.root), f"{env_name}.enc")

    def load_env(self, env_name):
        """Load and decrypt all secrets for an environment.

        Returns a dict: {"secrets": {...}, "_meta": {...}}
        Returns empty structure if .enc file doesn't exist yet.
        """
        path = self._enc_path(env_name)
        if not os.path.isfile(path):
            return {"_meta": {"updated": None, "count": 0}, "secrets": {}}

        with open(path, "rb") as f:
            raw = f.read()

        # Validate format
        if len(raw) < 4 or raw[:3] != MAGIC:
            raise ValueError(f"corrupted file: {path} (bad magic bytes)")
        if raw[3] != VERSION:
            raise ValueError(
                f"unsupported version {raw[3]} in {path} (expected {VERSION})"
            )

        # Decrypt
        key = self._env_key(env_name)
        plaintext = decrypt(key, raw[4:], env_name)
        return json.loads(plaintext.decode("utf-8"))

    def save_env(self, env_name, data):
        """Encrypt and write all secrets for an environment.

        Uses atomic write: tmp file + os.replace().
        """
        # Update metadata
        data["_meta"]["updated"] = datetime.now(timezone.utc).isoformat()
        data["_meta"]["count"] = len(data["secrets"])

        # Encrypt
        key = self._env_key(env_name)
        plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
        encrypted = encrypt(key, plaintext, env_name)

        # Write with magic + version header
        blob = MAGIC + bytes([VERSION]) + encrypted

        path = self._enc_path(env_name)
        tmp_path = path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(blob)
        os.replace(tmp_path, path)

        # Auto-register environment if not already known
        add_environment(self.root, env_name)

    def set_secret(self, env_name, key, value):
        """Set a single secret. Creates the environment if needed."""
        data = self.load_env(env_name)
        data["secrets"][key] = value
        self.save_env(env_name, data)

    def get_secret(self, env_name, key):
        """Get a single secret value. Returns None if not found."""
        data = self.load_env(env_name)
        return data["secrets"].get(key)

    def list_secrets(self, env_name):
        """List all secret keys for an environment.

        Returns list of (key, value) tuples sorted by key name.
        """
        data = self.load_env(env_name)
        return sorted(data["secrets"].items())

    def remove_secret(self, env_name, key):
        """Remove a secret. Returns True if it existed."""
        data = self.load_env(env_name)
        if key not in data["secrets"]:
            return False
        del data["secrets"][key]
        self.save_env(env_name, data)
        return True

    def get_all_secrets(self, env_name):
        """Get all secrets as a plain dict."""
        data = self.load_env(env_name)
        return dict(data["secrets"])

    def copy_env(self, src_env, dst_env):
        """Copy all secrets from one environment to another."""
        src_data = self.load_env(src_env)
        dst_data = self.load_env(dst_env)
        dst_data["secrets"].update(src_data["secrets"])
        self.save_env(dst_env, dst_data)
        return len(src_data["secrets"])

    def env_count(self, env_name):
        """Count secrets in an environment."""
        data = self.load_env(env_name)
        return len(data["secrets"])

    def read_raw_blob(self, env_name):
        """Read the raw .enc file bytes (for sync). Returns None if no file."""
        path = self._enc_path(env_name)
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    def write_raw_blob(self, env_name, blob_bytes):
        """Write raw .enc bytes (from sync). Atomic write."""
        path = self._enc_path(env_name)
        tmp_path = path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(blob_bytes)
        os.replace(tmp_path, path)
        add_environment(self.root, env_name)
