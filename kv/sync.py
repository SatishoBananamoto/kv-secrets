"""Sync logic for kv — push/pull encrypted blobs to/from server."""

import base64
import hashlib
import os

from .auth import get_api_url, get_auth_headers, require_session
from .config import find_project_root, load_config, save_config
from .remote import push_blob, pull_blob, sync_status, RemoteError
from .store import SecretStore


def compute_blob_hash(blob_bytes):
    """SHA-256 hex digest of raw .enc bytes."""
    return hashlib.sha256(blob_bytes).hexdigest()


def get_project_id(project_root):
    """Get the project ID for sync.

    Uses config.json remote.project_id if set,
    otherwise defaults to the directory name.
    """
    config = load_config(project_root)
    remote = config.get("remote", {})
    if remote.get("project_id"):
        return remote["project_id"]
    return os.path.basename(project_root)


def push_env(project_root, env_name):
    """Push a single environment's .enc blob to the server.

    Returns {version, pushed_at} from server.
    """
    store = SecretStore(project_root)
    blob_bytes = store.read_raw_blob(env_name)
    if blob_bytes is None:
        raise FileNotFoundError(f"no .enc file for environment '{env_name}'")

    api_url = get_api_url()
    headers = get_auth_headers()
    project_id = get_project_id(project_root)

    blob_b64 = base64.b64encode(blob_bytes).decode("ascii")
    blob_hash = compute_blob_hash(blob_bytes)

    result = push_blob(api_url, headers, project_id, env_name, blob_b64, blob_hash)

    # Update sync state in config
    _update_sync_state(project_root, env_name, result["version"], blob_hash)

    return result


def pull_env(project_root, env_name):
    """Pull a single environment's .enc blob from the server.

    Returns {version, blob_hash, pushed_at}.
    """
    api_url = get_api_url()
    headers = get_auth_headers()
    project_id = get_project_id(project_root)

    result = pull_blob(api_url, headers, project_id, env_name)

    blob_bytes = base64.b64decode(result["blob"])

    store = SecretStore(project_root)
    store.write_raw_blob(env_name, blob_bytes)

    _update_sync_state(project_root, env_name, result["version"], result["blob_hash"])

    return {
        "version": result["version"],
        "blob_hash": result["blob_hash"],
        "pushed_at": result["pushed_at"],
    }


def get_remote_status(project_root):
    """Get sync status for all environments on the server.

    Returns list of {env_name, version, blob_hash, pushed_at}.
    """
    api_url = get_api_url()
    headers = get_auth_headers()
    project_id = get_project_id(project_root)

    return sync_status(api_url, headers, project_id)


def push_all(project_root):
    """Push all local environments to the server."""
    config = load_config(project_root)
    results = {}
    for env_name in config.get("environments", []):
        store = SecretStore(project_root)
        if store.read_raw_blob(env_name) is not None:
            results[env_name] = push_env(project_root, env_name)
    return results


def pull_all(project_root):
    """Pull all environments from the server."""
    statuses = get_remote_status(project_root)
    results = {}
    for entry in statuses:
        results[entry["env_name"]] = pull_env(project_root, entry["env_name"])
    return results


def _update_sync_state(project_root, env_name, version, blob_hash):
    """Record sync state in config.json."""
    from datetime import datetime, timezone
    config = load_config(project_root)
    remote = config.setdefault("remote", {})
    remote.setdefault("api_url", get_api_url())
    last_sync = remote.setdefault("last_sync", {})
    last_sync[env_name] = {
        "version": version,
        "blob_hash": blob_hash,
        "synced_at": datetime.now(timezone.utc).isoformat(),
    }
    save_config(project_root, config)
