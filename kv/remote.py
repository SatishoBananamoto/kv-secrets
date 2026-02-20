"""HTTP client for kv cloud API.

Uses stdlib urllib.request — no extra dependencies.
All functions accept api_url and headers, return parsed JSON or raise RemoteError.
"""

import json
import urllib.parse
import urllib.request
import urllib.error


def _encode(value):
    """URL-encode a query parameter value."""
    return urllib.parse.quote(str(value), safe="")


class RemoteError(Exception):
    """Error from the kv server."""
    def __init__(self, status, message):
        self.status = status
        self.message = message
        super().__init__(f"[{status}] {message}")


def _request(method, url, data=None, headers=None):
    """Make an HTTP request, return parsed JSON response."""
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode("utf-8"))
            msg = detail.get("detail", detail.get("error", str(detail)))
        except Exception:
            msg = str(e)
        raise RemoteError(e.code, msg)


# ── Auth ──────────────────────────────────────────────────

def register(api_url, email, password):
    """POST /auth/register → {user_id, email, token, refresh_token}."""
    return _request("POST", f"{api_url}/auth/register", {"email": email, "password": password})


def login(api_url, email, password):
    """POST /auth/login → {user_id, email, token, refresh_token, team_id}."""
    return _request("POST", f"{api_url}/auth/login", {"email": email, "password": password})


def refresh_token(api_url, refresh_tok):
    """POST /auth/refresh → {token}."""
    return _request("POST", f"{api_url}/auth/refresh", {"refresh_token": refresh_tok})


# ── Sync ──────────────────────────────────────────────────

def push_blob(api_url, headers, project_id, env_name, blob_b64, blob_hash):
    """POST /sync/push → {version, pushed_at}."""
    return _request("POST", f"{api_url}/sync/push", {
        "project_id": project_id,
        "env_name": env_name,
        "blob": blob_b64,
        "blob_hash": blob_hash,
    }, headers)


def pull_blob(api_url, headers, project_id, env_name):
    """GET /sync/pull → {blob, version, blob_hash, pushed_at}."""
    return _request("GET", f"{api_url}/sync/pull?project_id={_encode(project_id)}&env_name={_encode(env_name)}",
                     headers=headers)


def sync_status(api_url, headers, project_id):
    """GET /sync/status → [{env_name, version, blob_hash, pushed_at}]."""
    return _request("GET", f"{api_url}/sync/status?project_id={_encode(project_id)}", headers=headers)


# ── Teams ─────────────────────────────────────────────────

def create_team(api_url, headers, name):
    """POST /team/create → {team_id, name}."""
    return _request("POST", f"{api_url}/team/create", {"name": name}, headers)


def invite_member(api_url, headers, email):
    """POST /team/invite → {ok}."""
    return _request("POST", f"{api_url}/team/invite", {"email": email}, headers)


def list_members(api_url, headers):
    """GET /team/members → [{user_id, email, role, joined_at}]."""
    return _request("GET", f"{api_url}/team/members", headers=headers)


def revoke_member(api_url, headers, user_id):
    """DELETE /team/revoke → {ok}."""
    return _request("DELETE", f"{api_url}/team/revoke?user_id={_encode(user_id)}", headers=headers)


# ── Tokens ────────────────────────────────────────────────

def create_api_token(api_url, headers, name, scopes=None, project_id=None, env_names=None, expires_days=None):
    """POST /tokens/create → {token_id, token, name}."""
    data = {"name": name}
    if scopes:
        data["scopes"] = scopes
    if project_id:
        data["project_id"] = project_id
    if env_names:
        data["env_names"] = env_names
    if expires_days:
        data["expires_days"] = expires_days
    return _request("POST", f"{api_url}/tokens/create", data, headers)


def list_api_tokens(api_url, headers):
    """GET /tokens/list → [{token_id, name, scopes, ...}]."""
    return _request("GET", f"{api_url}/tokens/list", headers=headers)


def revoke_api_token(api_url, headers, token_id):
    """DELETE /tokens/revoke → {ok}."""
    return _request("DELETE", f"{api_url}/tokens/revoke?token_id={_encode(token_id)}", headers=headers)
