"""Authentication for kv CLI.

Manages user sessions, login/signup flows, and token storage.
Session stored at ~/.kv/session.json (per-user, not per-project).
"""

import json
import os


SESSION_DIR = ".kv"
SESSION_FILE = "session.json"

# Default server URL — overridden by KV_API_URL env var
DEFAULT_API_URL = "http://127.0.0.1:8000"


def get_user_config_dir():
    """Get ~/.kv/ directory, create if needed."""
    home = os.path.expanduser("~")
    d = os.path.join(home, SESSION_DIR)
    os.makedirs(d, exist_ok=True)
    # Restrict permissions on Unix (owner-only access)
    if os.name != "nt":
        os.chmod(d, 0o700)
    return d


def session_path():
    """Full path to session.json."""
    return os.path.join(get_user_config_dir(), SESSION_FILE)


def load_session():
    """Load the current session, or None if not logged in."""
    path = session_path()
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_session(session):
    """Write session to disk."""
    path = session_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    # Restrict permissions on Unix (owner-only read/write)
    if os.name != "nt":
        os.chmod(path, 0o600)


def delete_session():
    """Remove session file (logout)."""
    path = session_path()
    if os.path.isfile(path):
        os.remove(path)


def get_api_url():
    """Get the API server URL."""
    session = load_session()
    if session and session.get("api_url"):
        return session["api_url"]
    return os.environ.get("KV_API_URL", DEFAULT_API_URL)


def get_auth_headers():
    """Get Authorization headers from session or KV_TOKEN env var.

    Returns dict with Authorization header, or empty dict.
    """
    # CI/CD token takes priority
    env_token = os.environ.get("KV_TOKEN")
    if env_token:
        return {"Authorization": f"Token {env_token}"}

    session = load_session()
    if session and session.get("token"):
        return {"Authorization": f"Bearer {session['token']}"}

    return {}


def require_session():
    """Get current session or raise with helpful message."""
    session = load_session()
    if not session:
        raise RuntimeError("not logged in — run 'python -m kv login' first")
    return session
