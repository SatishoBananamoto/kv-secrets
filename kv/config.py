"""Project configuration for kv.

Handles .secrets/ directory, config.json, project discovery.
"""

import json
import os
from datetime import datetime, timezone

from .crypto import generate_master_key, save_key, save_wrapped_key


SECRETS_DIR = ".secrets"
CONFIG_FILE = "config.json"
KEY_FILE = "key"
GITIGNORE_FILE = ".gitignore"

GITIGNORE_CONTENT = """\
# kv — encrypted secrets management
# The key file must NEVER be committed
key

# Encrypted files are safe to commit
!*.enc
!config.json
"""


def find_project_root(start=None):
    """Walk up from start directory looking for .secrets/.

    Returns the project root (parent of .secrets/), or None.
    """
    path = os.path.abspath(start or os.getcwd())
    while True:
        secrets_dir = os.path.join(path, SECRETS_DIR)
        if os.path.isdir(secrets_dir):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def secrets_dir(project_root):
    """Get the .secrets/ directory path."""
    return os.path.join(project_root, SECRETS_DIR)


def init_project(project_root=None, passphrase=None):
    """Initialize a new kv project.

    Creates .secrets/ with master key, config.json, .gitignore, and default dev env.
    If passphrase is provided, the master key is encrypted with it.
    Returns the project root path.
    """
    root = project_root or os.getcwd()
    sdir = os.path.join(root, SECRETS_DIR)

    if os.path.exists(sdir):
        raise FileExistsError(f"already initialized: {sdir}")

    os.makedirs(sdir)

    # Generate and save master key
    master = generate_master_key()
    kp = os.path.join(sdir, KEY_FILE)
    if passphrase:
        save_wrapped_key(master, passphrase, kp)
    else:
        save_key(master, kp)

    # Write config
    config = {
        "version": 1,
        "created": datetime.now(timezone.utc).isoformat(),
        "default_env": "dev",
        "environments": ["dev"],
        "cipher": "chacha20-poly1305",
        "security": {
            "passphrase": bool(passphrase),
            "totp": False,
        },
    }
    _write_config(sdir, config)

    # Write .gitignore
    with open(os.path.join(sdir, GITIGNORE_FILE), "w", encoding="utf-8") as f:
        f.write(GITIGNORE_CONTENT)

    return root


def load_config(project_root):
    """Load config.json from a project."""
    sdir = secrets_dir(project_root)
    config_path = os.path.join(sdir, CONFIG_FILE)
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(project_root, config):
    """Save config.json to a project."""
    sdir = secrets_dir(project_root)
    _write_config(sdir, config)


def add_environment(project_root, name):
    """Register a new environment in config."""
    config = load_config(project_root)
    if name in config["environments"]:
        return False
    config["environments"].append(name)
    save_config(project_root, config)
    return True


def list_environments(project_root):
    """Get all registered environment names."""
    config = load_config(project_root)
    return config["environments"]


def get_default_env(project_root):
    """Get the default environment name."""
    config = load_config(project_root)
    return config.get("default_env", "dev")


def key_path(project_root):
    """Get the path to the master key file."""
    return os.path.join(secrets_dir(project_root), KEY_FILE)


def _write_config(sdir, config):
    """Write config.json atomically."""
    config_path = os.path.join(sdir, CONFIG_FILE)
    tmp_path = config_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    os.replace(tmp_path, config_path)
