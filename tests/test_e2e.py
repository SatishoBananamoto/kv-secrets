"""End-to-end tests for kv CLI + kv_server.

Spins up the server in a subprocess, then runs CLI-level operations
through the HTTP API. Covers auth, sync, teams, tokens, security fixes
(RVW-20260219-001 through 003), permission matrix, audit trail, and
rate limiting.

Usage: python test_e2e.py
"""

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

# Windows encoding fix
for stream in (sys.stdout, sys.stderr, sys.stdin):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")

# --Paths ------------------------------------------------
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_TEST_DIR)  # kv-project/
sys.path.insert(0, PROJECT_ROOT)
# Propagate to subprocesses (kv_server is gitignored = not pip-installed)
_pypath = os.environ.get("PYTHONPATH", "")
if PROJECT_ROOT not in _pypath.split(os.pathsep):
    os.environ["PYTHONPATH"] = PROJECT_ROOT + (os.pathsep + _pypath if _pypath else "")

# --Config -----------------------------------------------

import random as _rng
_TEST_PORT = str(_rng.randint(9100, 9900))
API_URL = f"http://127.0.0.1:{_TEST_PORT}"
UNIQUE = uuid.uuid4().hex[:8]
OWNER_EMAIL = f"owner-{UNIQUE}@test.dev"
MEMBER_EMAIL = f"member-{UNIQUE}@test.dev"
ADMIN_EMAIL = f"admin-{UNIQUE}@test.dev"
OUTSIDER_EMAIL = f"outsider-{UNIQUE}@test.dev"
PASSWORD = "testpass123"

passed = 0
failed = 0
server_proc = None


# --Helpers ----------------------------------------------

def api(method, path, data=None, headers=None):
    """Make an HTTP request to the test server."""
    url = f"{API_URL}{path}"
    req_headers = {"Content-Type": "application/json", "Connection": "close"}
    if headers:
        req_headers.update(headers)
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode("utf-8"))
        except Exception:
            detail = str(e)
        return e.code, detail
    except urllib.error.URLError as e:
        return -1, {"error": str(e)}


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def token_header(raw_token):
    return {"Authorization": f"Token {raw_token}"}


def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[31mFAIL\033[0m {name} — {detail}")


def wait_for_server(url, timeout=10):
    """Poll until the server responds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{url}/health")
            return True
        except Exception:
            time.sleep(0.3)
    return False


# --Server lifecycle -------------------------------------

def _clean_pycache():
    """Remove stale .pyc files that can mask code changes."""
    import glob
    for f in glob.glob(os.path.join(PROJECT_ROOT, "kv_server", "**", "__pycache__", "*.pyc"), recursive=True):
        try:
            os.remove(f)
        except OSError:
            pass


def start_server():
    global server_proc
    _clean_pycache()  # prevent stale bytecode
    env = os.environ.copy()
    env["KV_PORT"] = _TEST_PORT
    env["KV_DEBUG"] = "0"
    env["KV_JWT_SECRET"] = "test-jwt-secret-for-e2e"
    _db_path = os.path.join(_TEST_DIR, f"test_e2e_{UNIQUE}.db").replace("\\", "/")
    env["KV_DATABASE_URL"] = f"sqlite+aiosqlite:///{_db_path}"
    env["PYTHONDONTWRITEBYTECODE"] = "1"  # prevent stale .pyc issues

    server_proc = subprocess.Popen(
        [sys.executable, "-Bu", "-m", "kv_server"],
        env=env,
        cwd=PROJECT_ROOT,
        stdout=open(os.path.join(_TEST_DIR, f"test_server_{UNIQUE}_out.log"), "w"),
        stderr=open(os.path.join(_TEST_DIR, f"test_server_{UNIQUE}_err.log"), "w"),
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )
    if not wait_for_server(API_URL):
        print("FATAL: server failed to start")
        stop_server()
        sys.exit(1)
    print(f"Server started (PID {server_proc.pid})\n")


def stop_server():
    global server_proc
    if server_proc:
        if sys.platform == "win32":
            server_proc.terminate()
        else:
            os.kill(server_proc.pid, signal.SIGTERM)
        try:
            server_proc.wait(timeout=5)
        except Exception:
            pass
        server_proc = None
        time.sleep(1)  # let DB file release

    # Clean up test DB (best effort)
    db_file = os.path.join(_TEST_DIR, f"test_e2e_{UNIQUE}.db")
    for f in [db_file]:
        try:
            if os.path.isfile(f):
                os.remove(f)
        except OSError:
            pass  # file locked, will be cleaned next run


# --Tests ------------------------------------------------

def run_tests():
    os.system("")  # enable ANSI on Windows

    # --1. Health check ----------------------------------
    status, data = api("GET", "/health")
    test("health check", status == 200)

    # --1b. Health ready (DB ping) -----------------------
    status, data = api("GET", "/health/ready")
    test("health ready (DB ping)", status == 200 and data.get("db") == "connected")

    # --2. Register owner --------------------------------
    status, data = api("POST", "/auth/register", {
        "email": OWNER_EMAIL, "password": PASSWORD
    })
    test("register owner", status == 200 and "token" in data)
    owner_token = data.get("token", "")
    owner_refresh = data.get("refresh_token", "")
    owner_id = data.get("user_id", "")

    # --3. Duplicate register rejected -------------------
    status, _ = api("POST", "/auth/register", {
        "email": OWNER_EMAIL, "password": PASSWORD
    })
    test("duplicate register rejected", status == 409)

    # --4. Login -----------------------------------------
    status, data = api("POST", "/auth/login", {
        "email": OWNER_EMAIL, "password": PASSWORD
    })
    test("login", status == 200 and "token" in data)
    owner_token = data.get("token", owner_token)

    # --5. Refresh token ---------------------------------
    status, data = api("POST", "/auth/refresh", {
        "refresh_token": owner_refresh
    })
    test("refresh token", status == 200 and "token" in data)
    owner_token = data.get("token", owner_token)

    # --6. Create team -----------------------------------
    status, data = api("POST", "/team/create", {
        "name": f"test-team-{UNIQUE}"
    }, auth_header(owner_token))
    test("create team", status == 200 and "team_id" in data)
    team_id = data.get("team_id", "")

    # Re-login to get team_id in token
    status, data = api("POST", "/auth/login", {
        "email": OWNER_EMAIL, "password": PASSWORD
    })
    owner_token = data.get("token", owner_token)

    # --7. Push blob -------------------------------------
    import base64
    import hashlib
    fake_blob = b"KV\x00encrypted-test-data-v1"
    blob_b64 = base64.b64encode(fake_blob).decode("ascii")
    blob_hash = hashlib.sha256(fake_blob).hexdigest()

    status, data = api("POST", "/sync/push", {
        "project_id": "test-project",
        "env_name": "dev",
        "blob": blob_b64,
        "blob_hash": blob_hash,
    }, auth_header(owner_token))
    test("push blob", status == 200 and data.get("version") == 1)

    # --8. Push v2 ---------------------------------------
    fake_blob_v2 = b"KV\x00encrypted-test-data-v2"
    blob_b64_v2 = base64.b64encode(fake_blob_v2).decode("ascii")
    blob_hash_v2 = hashlib.sha256(fake_blob_v2).hexdigest()

    status, data = api("POST", "/sync/push", {
        "project_id": "test-project",
        "env_name": "dev",
        "blob": blob_b64_v2,
        "blob_hash": blob_hash_v2,
    }, auth_header(owner_token))
    test("push v2", status == 200 and data.get("version") == 2)

    # --9. Pull blob -------------------------------------
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=auth_header(owner_token))
    test("pull blob", status == 200 and data.get("blob") == blob_b64_v2)

    # --10. Sync status ---------------------------------
    status, data = api("GET", "/sync/status?project_id=test-project",
                        headers=auth_header(owner_token))
    test("sync status", status == 200 and isinstance(data, list) and len(data) >= 1)

    # --11. Register member ------------------------------
    status, data = api("POST", "/auth/register", {
        "email": MEMBER_EMAIL, "password": PASSWORD
    })
    test("register member", status == 200)
    member_id = data.get("user_id", "")
    member_token_pre_team = data.get("token", "")

    # --12. Invite member --------------------------------
    status, data = api("POST", "/team/invite", {
        "email": MEMBER_EMAIL
    }, auth_header(owner_token))
    test("invite member", status == 200)

    # Re-login member to get team_id in token
    status, data = api("POST", "/auth/login", {
        "email": MEMBER_EMAIL, "password": PASSWORD
    })
    member_token = data.get("token", "")

    # --13. List members ---------------------------------
    status, data = api("GET", "/team/members", headers=auth_header(owner_token))
    test("list members", status == 200 and len(data) == 2)

    # --14. Token create (owner) -------------------------
    status, data = api("POST", "/tokens/create", {
        "name": "ci-deploy",
        "scopes": ["pull"],
    }, auth_header(owner_token))
    test("token create (owner)", status == 200 and "token" in data)
    ci_token = data.get("token", "")
    ci_token_id = data.get("token_id", "")

    # --15. Token list (owner) ---------------------------
    status, data = api("GET", "/tokens/list", headers=auth_header(owner_token))
    test("token list (owner)", status == 200 and len(data) >= 1)

    # --16. API token pull -------------------------------
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=token_header(ci_token))
    test("API token pull", status == 200 and data.get("blob") == blob_b64_v2)

    # =======================================================
    # SECURITY FIXES — RVW-20260219-001
    # =======================================================

    # --17. [HIGH] Member CANNOT list tokens -------------
    status, data = api("GET", "/tokens/list", headers=auth_header(member_token))
    test("member cannot list tokens (403)",
         status == 403,
         f"expected 403, got {status}")

    # --18. [HIGH] Member CANNOT revoke tokens -----------
    status, data = api("DELETE", f"/tokens/revoke?token_id={ci_token_id}",
                        headers=auth_header(member_token))
    test("member cannot revoke tokens (403)",
         status == 403,
         f"expected 403, got {status}")

    # --19. [HIGH] Member CANNOT create tokens -----------
    status, data = api("POST", "/tokens/create", {
        "name": "hacker-token",
        "scopes": ["pull", "push", "admin"],
    }, auth_header(member_token))
    test("member cannot create tokens (403)",
         status == 403,
         f"expected 403, got {status}")

    # --20. [HIGH] Pull-only API token CANNOT list tokens
    status, data = api("GET", "/tokens/list",
                        headers=token_header(ci_token))
    test("pull-only API token cannot list tokens (403)",
         status == 403,
         f"expected 403, got {status}")

    # --21. [HIGH] Pull-only API token CANNOT revoke tokens
    status, data = api("DELETE", f"/tokens/revoke?token_id={ci_token_id}",
                        headers=token_header(ci_token))
    test("pull-only API token cannot revoke tokens (403)",
         status == 403,
         f"expected 403, got {status}")

    # --22. Owner CAN still revoke token (no regression) -
    status, data = api("DELETE", f"/tokens/revoke?token_id={ci_token_id}",
                        headers=auth_header(owner_token))
    test("owner can revoke token (200)",
         status == 200,
         f"expected 200, got {status}")

    # --23. [MEDIUM] URL encoding — special chars in project name
    special_project = "my project&evil=true"
    special_blob = b"KV\x00special-chars-test"
    special_b64 = base64.b64encode(special_blob).decode("ascii")
    special_hash = hashlib.sha256(special_blob).hexdigest()

    # Push with special chars should work
    status, data = api("POST", "/sync/push", {
        "project_id": special_project,
        "env_name": "staging test",
        "blob": special_b64,
        "blob_hash": special_hash,
    }, auth_header(owner_token))
    test("push with special chars in project/env",
         status == 200,
         f"expected 200, got {status}")

    # Pull with special chars — we need to URL-encode the query params
    import urllib.parse
    encoded_project = urllib.parse.quote(special_project, safe="")
    encoded_env = urllib.parse.quote("staging test", safe="")
    status, data = api("GET",
                        f"/sync/pull?project_id={encoded_project}&env_name={encoded_env}",
                        headers=auth_header(owner_token))
    test("pull with URL-encoded special chars",
         status == 200 and data.get("blob") == special_b64,
         f"status={status}, blob_match={data.get('blob') == special_b64 if status == 200 else 'N/A'}")

    # --24. Owner push all still works (regression check) -
    status, data = api("POST", "/sync/push", {
        "project_id": "test-project",
        "env_name": "prod",
        "blob": blob_b64,
        "blob_hash": blob_hash,
    }, auth_header(owner_token))
    test("push to prod env", status == 200)

    # --25. Member CAN pull (non-admin operation) --------
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=auth_header(member_token))
    test("member can pull (non-admin ok)",
         status == 200,
         f"expected 200, got {status}")

    # =======================================================
    # CRITICAL FIX -- RVW-20260219-002: JWT revocation bypass
    # =======================================================

    # --26. Revoke member ---------------------------------
    status, data = api("DELETE",
                        f"/team/revoke?user_id={member_id}",
                        headers=auth_header(owner_token))
    test("revoke member", status == 200, f"expected 200, got {status}")

    # --27. [CRITICAL] Revoked member CANNOT pull ---------
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=auth_header(member_token))
    test("revoked member cannot pull (401/403)",
         status in (401, 403),
         f"expected 401/403, got {status}")

    # --28. [CRITICAL] Revoked member CANNOT push ---------
    status, data = api("POST", "/sync/push", {
        "project_id": "test-project",
        "env_name": "dev",
        "blob": blob_b64,
        "blob_hash": blob_hash,
    }, auth_header(member_token))
    test("revoked member cannot push (401/403)",
         status in (401, 403),
         f"expected 401/403, got {status}")

    # --29. Owner still works after revoking member -------
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=auth_header(owner_token))
    test("owner can still pull after revoking member",
         status == 200,
         f"expected 200, got {status}")

    # =======================================================
    # SECURITY HARDENING -- RVW-20260219-003 conditions
    # =======================================================

    # --30. Register admin + invite with role="admin" ----
    status, data = api("POST", "/auth/register", {
        "email": ADMIN_EMAIL, "password": PASSWORD
    })
    test("register admin user", status == 200)
    admin_user_id = data.get("user_id", "")

    status, data = api("POST", "/team/invite", {
        "email": ADMIN_EMAIL, "role": "admin"
    }, auth_header(owner_token))
    test("invite admin member (role=admin)",
         status == 200,
         f"expected 200, got {status}")

    # Re-login admin to get team_id in token
    status, data = api("POST", "/auth/login", {
        "email": ADMIN_EMAIL, "password": PASSWORD
    })
    admin_token = data.get("token", "")

    # --31. Admin creates API token, verify it works ------
    status, data = api("POST", "/tokens/create", {
        "name": "admin-ci-token",
        "scopes": ["pull"],
    }, auth_header(admin_token))
    test("admin creates API token",
         status == 200 and "token" in data,
         f"expected 200, got {status}")
    admin_ci_token = data.get("token", "")
    admin_ci_token_id = data.get("token_id", "")

    # Verify admin's token works
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=token_header(admin_ci_token))
    test("admin API token can pull",
         status == 200,
         f"expected 200, got {status}")

    # --32. Owner revokes admin from team -----------------
    status, data = api("DELETE",
                        f"/team/revoke?user_id={admin_user_id}",
                        headers=auth_header(owner_token))
    test("revoke admin from team",
         status == 200,
         f"expected 200, got {status}")

    # --33. [MEDIUM] Revoked admin's API token DENIED -----
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=token_header(admin_ci_token))
    test("revoked admin API token denied (401)",
         status == 401,
         f"expected 401, got {status}")

    # --34. Revoked admin's tokens show revoked in list ---
    status, data = api("GET", "/tokens/list", headers=auth_header(owner_token))
    # Admin's token should NOT appear (it's been cascade-revoked)
    admin_token_visible = any(
        t.get("token_id") == admin_ci_token_id
        for t in (data if isinstance(data, list) else [])
    )
    test("revoked admin tokens not in list (cascade)",
         status == 200 and not admin_token_visible,
         f"status={status}, admin_token_visible={admin_token_visible}")

    # --35. Owner's tokens still work (regression) --------
    # Create a fresh owner token and verify
    status, data = api("POST", "/tokens/create", {
        "name": "owner-regression-token",
        "scopes": ["pull"],
    }, auth_header(owner_token))
    test("owner creates token after admin revoke",
         status == 200,
         f"expected 200, got {status}")
    owner_regression_token = data.get("token", "")
    owner_regression_token_id = data.get("token_id", "")

    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=token_header(owner_regression_token))
    test("owner API token still works (regression)",
         status == 200,
         f"expected 200, got {status}")

    # =======================================================
    # PERMISSION MATRIX ENFORCEMENT
    # =======================================================

    # --36. API token cannot access /team/members (403) ---
    status, data = api("GET", "/team/members",
                        headers=token_header(owner_regression_token))
    test("API token cannot access team members (403)",
         status == 403,
         f"expected 403, got {status}")

    # --37. API token cannot access /billing/status (403) -
    status, data = api("GET", "/billing/status",
                        headers=token_header(owner_regression_token))
    test("API token cannot access billing (403)",
         status == 403,
         f"expected 403, got {status}")

    # --38. Re-invite member for perm matrix tests --------
    # Re-invite the original member (was revoked in test 26)
    status, data = api("POST", "/team/invite", {
        "email": MEMBER_EMAIL
    }, auth_header(owner_token))
    test("re-invite member for perm tests",
         status == 200,
         f"expected 200, got {status}")

    # Re-login member
    status, data = api("POST", "/auth/login", {
        "email": MEMBER_EMAIL, "password": PASSWORD
    })
    member_token_2 = data.get("token", "")

    # Member cannot invite
    status, data = api("POST", "/team/invite", {
        "email": "nobody@test.dev"
    }, auth_header(member_token_2))
    test("member cannot invite (403)",
         status == 403,
         f"expected 403, got {status}")

    # =======================================================
    # RVW-20260219-004 FIXES: owner protection, API token gate, audit integrity
    # =======================================================

    # -- [Critical] Admin cannot revoke the owner ----------
    # Re-invite admin to test owner protection
    status, data = api("POST", "/team/invite", {
        "email": ADMIN_EMAIL, "role": "admin"
    }, auth_header(owner_token))
    test("re-invite admin for owner-protection test",
         status == 200,
         f"expected 200, got {status}")

    # Re-login admin
    status, data = api("POST", "/auth/login", {
        "email": ADMIN_EMAIL, "password": PASSWORD
    })
    admin_token_2 = data.get("token", "")

    # Admin tries to revoke owner → must be 403
    status, data = api("DELETE",
                        f"/team/revoke?user_id={owner_id}",
                        headers=auth_header(admin_token_2))
    test("admin cannot revoke owner (403)",
         status == 403,
         f"expected 403, got {status}")

    # Owner cannot self-revoke
    status, data = api("DELETE",
                        f"/team/revoke?user_id={owner_id}",
                        headers=auth_header(owner_token))
    test("owner cannot self-revoke (400)",
         status == 400,
         f"expected 400, got {status}")

    # Owner can still revoke admin → 200 (regression)
    status, data = api("DELETE",
                        f"/team/revoke?user_id={admin_user_id}",
                        headers=auth_header(owner_token))
    test("owner can revoke admin (200)",
         status == 200,
         f"expected 200, got {status}")

    # -- [High] API admin-scope token blocked from token mgmt --
    # Create an API token with admin scope
    status, data = api("POST", "/tokens/create", {
        "name": "admin-scope-api-token",
        "scopes": ["pull", "push", "admin"],
    }, auth_header(owner_token))
    test("create admin-scope API token",
         status == 200 and "token" in data,
         f"expected 200, got {status}")
    admin_api_token = data.get("token", "")
    admin_api_token_id = data.get("token_id", "")

    # Admin API token cannot list tokens
    status, data = api("GET", "/tokens/list",
                        headers=token_header(admin_api_token))
    test("admin API token cannot list tokens (403)",
         status == 403,
         f"expected 403, got {status}")

    # Admin API token cannot create tokens
    status, data = api("POST", "/tokens/create", {
        "name": "self-replicate",
        "scopes": ["pull"],
    }, token_header(admin_api_token))
    test("admin API token cannot create tokens (403)",
         status == 403,
         f"expected 403, got {status}")

    # Admin API token cannot revoke tokens
    status, data = api("DELETE",
                        f"/tokens/revoke?token_id={admin_api_token_id}",
                        headers=token_header(admin_api_token))
    test("admin API token cannot revoke tokens (403)",
         status == 403,
         f"expected 403, got {status}")

    # Admin API token CAN still pull (sync routes allow API tokens)
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=token_header(admin_api_token))
    test("admin API token can still pull (200)",
         status == 200,
         f"expected 200, got {status}")

    # =======================================================
    # REPLAY / IDEMPOTENCY TESTS
    # =======================================================

    # --39. Double revoke token is idempotent -------------
    # Revoke the owner regression token
    status, data = api("DELETE",
                        f"/tokens/revoke?token_id={owner_regression_token_id}",
                        headers=auth_header(owner_token))
    test("revoke token (first time)",
         status == 200,
         f"expected 200, got {status}")

    # Double revoke is idempotent (already revoked in test 39)
    status, data = api("DELETE",
                        f"/tokens/revoke?token_id={owner_regression_token_id}",
                        headers=auth_header(owner_token))
    test("double revoke token is idempotent (200)",
         status == 200,
         f"expected 200, got {status}")

    # --40. Revoked token cannot pull ---------------------
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=token_header(owner_regression_token))
    test("explicitly revoked token cannot pull (401)",
         status == 401,
         f"expected 401, got {status}")

    # =======================================================
    # CROSS-TEAM TOKEN MISUSE
    # =======================================================

    # --41. Cross-team token cannot access other team -----
    # Register outsider, create their own team + token
    status, data = api("POST", "/auth/register", {
        "email": OUTSIDER_EMAIL, "password": PASSWORD
    })
    test("register outsider", status == 200)
    outsider_token_jwt = data.get("token", "")

    status, data = api("POST", "/team/create", {
        "name": f"outsider-team-{UNIQUE}"
    }, auth_header(outsider_token_jwt))
    test("outsider creates team", status == 200)

    # Re-login to get team_id in token
    status, data = api("POST", "/auth/login", {
        "email": OUTSIDER_EMAIL, "password": PASSWORD
    })
    outsider_token_jwt = data.get("token", "")

    # Outsider creates an API token in their team
    status, data = api("POST", "/tokens/create", {
        "name": "outsider-ci",
        "scopes": ["pull", "push"],
    }, auth_header(outsider_token_jwt))
    test("outsider creates API token", status == 200)
    outsider_api_token = data.get("token", "")

    # Try to pull data from original team's project
    status, data = api("GET", "/sync/pull?project_id=test-project&env_name=dev",
                        headers=token_header(outsider_api_token))
    test("cross-team token cannot pull other team data (404)",
         status == 404,
         f"expected 404, got {status}")

    # =======================================================
    # AUDIT TRAIL
    # =======================================================

    # --42. Audit log records token creation --------------
    status, data = api("GET", "/audit?event_type=token.created",
                        headers=auth_header(owner_token))
    test("audit log records token.created events",
         status == 200 and isinstance(data, list) and len(data) >= 1,
         f"status={status}, entries={len(data) if isinstance(data, list) else 'N/A'}")

    # -- [Medium fix] Audit target_id is non-null for token.created --
    # Every token.created audit entry must have a non-null target_id
    if status == 200 and isinstance(data, list):
        all_have_target = all(
            entry.get("target_id") is not None
            for entry in data
            if entry.get("event_type") == "token.created"
        )
        test("audit token.created target_id is non-null",
             all_have_target,
             f"found null target_id in audit entries")
    else:
        test("audit token.created target_id is non-null (SKIP: no data)", False)

    # Verify audit log records member revocation
    status, data = api("GET", "/audit?event_type=member.revoked",
                        headers=auth_header(owner_token))
    test("audit log records member.revoked events",
         status == 200 and isinstance(data, list) and len(data) >= 1,
         f"status={status}, entries={len(data) if isinstance(data, list) else 'N/A'}")

    # =======================================================
    # RATE LIMITING
    # =======================================================

    # --43. Rate limit on /tokens/create ------------------
    # Hit token create rapidly -- limit is 10/min
    rate_limit_hit = False
    for i in range(12):
        status, data = api("POST", "/tokens/create", {
            "name": f"rate-limit-test-{i}",
            "scopes": ["pull"],
        }, auth_header(owner_token))
        if status == 429:
            rate_limit_hit = True
            break
    test("rate limit on /tokens/create (429 after burst)",
         rate_limit_hit,
         f"never got 429 after {i+1} requests")


def test_jwt_config_failfast():
    """Test that missing KV_JWT_SECRET crashes in production mode."""
    print("\n--JWT Config Fail-Fast ------------------------")

    env = os.environ.copy()
    env["KV_DEBUG"] = "0"
    # Remove KV_JWT_SECRET if set
    env.pop("KV_JWT_SECRET", None)
    env["KV_PORT"] = "8878"

    result = subprocess.run(
        [sys.executable, "-B", "-c", "from kv_server.config import Settings; Settings()"],
        env=env,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    test("JWT fail-fast in prod mode (no KV_JWT_SECRET)",
         result.returncode != 0 and "KV_JWT_SECRET" in result.stderr,
         f"rc={result.returncode}, stderr={result.stderr[:200]}")

    # With secret set, should work
    env["KV_JWT_SECRET"] = "test-secret-for-prod"
    result = subprocess.run(
        [sys.executable, "-B", "-c", "from kv_server.config import Settings; Settings()"],
        env=env,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    test("JWT works in prod mode with KV_JWT_SECRET set",
         result.returncode == 0,
         f"rc={result.returncode}, stderr={result.stderr[:200]}")

    # Dev mode (KV_DEBUG=1) should work without secret
    env["KV_DEBUG"] = "1"
    env.pop("KV_JWT_SECRET", None)
    result = subprocess.run(
        [sys.executable, "-B", "-c", "from kv_server.config import Settings; Settings()"],
        env=env,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    test("JWT works in dev mode without KV_JWT_SECRET",
         result.returncode == 0,
         f"rc={result.returncode}, stderr={result.stderr[:200]}")


def test_url_encoding():
    """Test that kv/remote.py correctly URL-encodes query params."""
    print("\n--URL Encoding (remote.py) --------------------")

    # Import the _encode helper (PROJECT_ROOT already on sys.path)
    from kv.remote import _encode

    test("_encode spaces", _encode("my project") == "my%20project",
         f"got: {_encode('my project')}")
    test("_encode ampersand", _encode("a&b=c") == "a%26b%3Dc",
         f"got: {_encode('a&b=c')}")
    test("_encode hash", _encode("foo#bar") == "foo%23bar",
         f"got: {_encode('foo#bar')}")
    test("_encode slash", _encode("path/name") == "path%2Fname",
         f"got: {_encode('path/name')}")
    test("_encode safe string", _encode("simple") == "simple")


# --Main -------------------------------------------------

if __name__ == "__main__":
    os.system("")  # enable ANSI on Windows
    print(f"kv e2e tests (run {UNIQUE})\n")
    print("=" * 55)

    # Unit-level tests (no server needed)
    test_url_encoding()
    test_jwt_config_failfast()

    # Integration tests (need server)
    print("\n--Server Integration Tests --------------------")
    try:
        start_server()
        run_tests()
    finally:
        stop_server()

    # Summary
    total = passed + failed
    print(f"\n{'=' * 55}")
    if failed == 0:
        print(f"\033[32m  ALL {total} TESTS PASSED\033[0m")
    else:
        print(f"\033[31m  {failed}/{total} TESTS FAILED\033[0m")
    sys.exit(1 if failed else 0)
