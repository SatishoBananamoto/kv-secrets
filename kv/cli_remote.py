"""Remote CLI commands for kv — login, sync, team, token management."""

import getpass
import sys

from . import __version__
from .auth import (
    get_api_url, get_auth_headers, load_session, save_session,
    delete_session, require_session,
)
from .config import find_project_root, load_config, save_config, key_path
from .crypto import export_key, import_key, load_key, save_key
from .remote import RemoteError
from .store import SecretStore

# Import ANSI constants from main CLI
from .cli import (
    RESET, BOLD, DIM, GREEN, YELLOW, CYAN, RED, VALUE, MUTED,
    _info, _success, _error, _header, _kv_line, _require_project,
)


# ── Auth commands ─────────────────────────────────────────

def cmd_signup(args):
    """Create a new account."""
    from . import remote as api

    api_url = getattr(args, "api_url", None) or get_api_url()
    _header("sign up")
    print()

    email = input(f"  {YELLOW}Email{RESET}: ").strip()
    password = getpass.getpass(f"  {YELLOW}Password{RESET}: ")
    confirm = getpass.getpass(f"  {YELLOW}Confirm{RESET}: ")

    if password != confirm:
        _error("passwords don't match")
        sys.exit(1)

    if len(password) < 8:
        _error("password must be at least 8 characters")
        sys.exit(1)

    try:
        result = api.register(api_url, email, password)
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)

    save_session({
        "api_url": api_url,
        "token": result["token"],
        "refresh_token": result["refresh_token"],
        "email": result["email"],
        "user_id": result["user_id"],
        "team_id": result.get("team_id"),
    })

    _success(f"account created: {result['email']}")
    _info(f"{DIM}session saved to ~/.kv/session.json{RESET}")
    print()


def cmd_login(args):
    """Log in to kv cloud."""
    from . import remote as api

    api_url = getattr(args, "api_url", None) or get_api_url()
    _header("log in")
    print()

    email = input(f"  {YELLOW}Email{RESET}: ").strip()
    password = getpass.getpass(f"  {YELLOW}Password{RESET}: ")

    try:
        result = api.login(api_url, email, password)
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)

    save_session({
        "api_url": api_url,
        "token": result["token"],
        "refresh_token": result["refresh_token"],
        "email": result["email"],
        "user_id": result["user_id"],
        "team_id": result.get("team_id"),
    })

    team_msg = f"  team: {result['team_id'][:8]}..." if result.get("team_id") else f"  {DIM}no team yet — run 'kv team create NAME'{RESET}"
    _success(f"logged in as {result['email']}")
    _info(team_msg)
    print()


def cmd_logout(args):
    """Log out (clear session)."""
    delete_session()
    _success("logged out")


# ── Sync commands ─────────────────────────────────────────

def cmd_push(args):
    """Push encrypted secrets to the server."""
    from .sync import push_env, push_all

    root = _require_project()
    require_session()

    if args.all:
        _header("pushing all environments")
        print()
        results = push_all(root)
        for env_name, result in results.items():
            _success(f"  {env_name}  v{result['version']}")
        if not results:
            _info(f"{DIM}no environments to push{RESET}")
    else:
        env = _get_env_remote(args, root)
        try:
            result = push_env(root, env)
            _success(f"pushed {BOLD}{env}{RESET}{GREEN}  v{result['version']}{RESET}")
        except FileNotFoundError:
            _error(f"no secrets in {env} — nothing to push")
            sys.exit(1)
        except RemoteError as e:
            _error(str(e.message))
            sys.exit(1)


def cmd_pull(args):
    """Pull encrypted secrets from the server."""
    from .sync import pull_env, pull_all

    root = _require_project()
    require_session()

    if args.all:
        _header("pulling all environments")
        print()
        results = pull_all(root)
        for env_name, result in results.items():
            _success(f"  {env_name}  v{result['version']}")
        if not results:
            _info(f"{DIM}no environments on server{RESET}")
    else:
        env = _get_env_remote(args, root)
        try:
            result = pull_env(root, env)
            _success(f"pulled {BOLD}{env}{RESET}{GREEN}  v{result['version']}{RESET}")
        except RemoteError as e:
            _error(str(e.message))
            sys.exit(1)


def cmd_remote_status(args):
    """Show sync status for all environments."""
    from .sync import get_remote_status

    root = _require_project()
    require_session()

    try:
        statuses = get_remote_status(root)
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)

    if not statuses:
        _header("remote status")
        print()
        _info(f"{DIM}no environments synced yet{RESET}")
        print()
        return

    _header(f"remote status ({len(statuses)} env{'s' if len(statuses) != 1 else ''})")
    print()
    for s in statuses:
        _info(f"  {GREEN}{s['env_name']}{RESET}  v{s['version']}  {DIM}{s['pushed_at'][:19]}{RESET}")
    print()


# ── Team commands ─────────────────────────────────────────

def cmd_team(args):
    """Team management dispatcher."""
    action = args.team_action if hasattr(args, "team_action") else None
    if not action:
        _error("usage: kv team <create|invite|members|revoke|key|join>")
        sys.exit(1)

    handlers = {
        "create": _team_create,
        "invite": _team_invite,
        "members": _team_members,
        "revoke": _team_revoke,
        "key": _team_key,
        "join": _team_join,
    }
    handler = handlers.get(action)
    if handler:
        handler(args)
    else:
        _error(f"unknown team action: {action}")
        sys.exit(1)


def _team_create(args):
    """Create a new team."""
    from . import remote as api

    require_session()
    api_url = get_api_url()
    headers = get_auth_headers()

    try:
        result = api.create_team(api_url, headers, args.name)
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)

    # Update session with team_id
    session = load_session()
    session["team_id"] = result["team_id"]
    save_session(session)

    _success(f"team created: {BOLD}{result['name']}{RESET}")
    _info(f"{DIM}team_id: {result['team_id']}{RESET}")
    _info(f"{DIM}re-login to use the new team: kv login{RESET}")
    print()


def _team_invite(args):
    """Invite a member by email."""
    from . import remote as api

    require_session()
    try:
        api.invite_member(get_api_url(), get_auth_headers(), args.email)
        _success(f"invited {args.email}")
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)


def _team_members(args):
    """List team members."""
    from . import remote as api

    require_session()
    try:
        members = api.list_members(get_api_url(), get_auth_headers())
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)

    _header(f"team members ({len(members)})")
    print()
    for m in members:
        role_color = YELLOW if m["role"] == "owner" else MUTED
        _info(f"  {GREEN}{m['email']}{RESET}  {role_color}{m['role']}{RESET}")
    print()


def _team_revoke(args):
    """Revoke a team member."""
    from . import remote as api

    require_session()
    # Need to find user_id by email — list members first
    try:
        members = api.list_members(get_api_url(), get_auth_headers())
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)

    target = None
    for m in members:
        if m["email"] == args.email:
            target = m
            break

    if not target:
        _error(f"'{args.email}' is not a team member")
        sys.exit(1)

    try:
        api.revoke_member(get_api_url(), get_auth_headers(), target["user_id"])
        _success(f"revoked {args.email}")
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)


def _team_key(args):
    """Display the master key as a shareable token."""
    root = _require_project()
    kp = key_path(root)
    master = load_key(kp)
    token = export_key(master)

    _header("team master key")
    print()
    _info(f"  {BOLD}{token}{RESET}")
    print()
    _info(f"{DIM}Share this with teammates via a secure channel (Signal, 1Password, etc.)")
    _info(f"They run: kv team join {token}{RESET}")
    print()


def _team_join(args):
    """Accept a team master key."""
    root = _require_project()
    kp = key_path(root)

    try:
        master = import_key(args.key)
    except ValueError as e:
        _error(str(e))
        sys.exit(1)

    if len(master) != 32:
        _error("invalid key length (expected 32 bytes)")
        sys.exit(1)

    save_key(master, kp)
    _success("master key updated from team key")
    _info(f"{DIM}you can now push/pull secrets with the team{RESET}")
    print()


# ── Token commands ────────────────────────────────────────

def cmd_token(args):
    """API token management dispatcher."""
    action = args.token_action if hasattr(args, "token_action") else None
    if not action:
        _error("usage: kv token <create|list|revoke>")
        sys.exit(1)

    handlers = {
        "create": _token_create,
        "list": _token_list,
        "revoke": _token_revoke,
    }
    handler = handlers.get(action)
    if handler:
        handler(args)
    else:
        _error(f"unknown token action: {action}")
        sys.exit(1)


def _token_create(args):
    """Create a new API token."""
    from . import remote as api

    require_session()
    scopes = [args.scope] if hasattr(args, "scope") and args.scope else ["pull"]
    env_names = [args.token_env] if hasattr(args, "token_env") and args.token_env else None
    expires = args.expires if hasattr(args, "expires") else None

    try:
        result = api.create_api_token(
            get_api_url(), get_auth_headers(),
            args.name, scopes=scopes, env_names=env_names, expires_days=expires,
        )
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)

    _header("api token created")
    print()
    _info(f"  {YELLOW}Name{RESET}   {result['name']}")
    _info(f"  {YELLOW}Token{RESET}  {BOLD}{result['token']}{RESET}")
    print()
    _info(f"  {RED}Save this token now — it won't be shown again.{RESET}")
    _info(f"  {DIM}Use as: KV_TOKEN={result['token']} python -m kv pull{RESET}")
    print()


def _token_list(args):
    """List API tokens."""
    from . import remote as api

    require_session()
    try:
        tokens = api.list_api_tokens(get_api_url(), get_auth_headers())
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)

    if not tokens:
        _header("api tokens")
        print()
        _info(f"{DIM}no tokens{RESET}")
        print()
        return

    _header(f"api tokens ({len(tokens)})")
    print()
    for t in tokens:
        scopes = ", ".join(t["scopes"])
        last = t["last_used"][:10] if t.get("last_used") else "never"
        _info(f"  {GREEN}{t['name']}{RESET}  {DIM}[{scopes}]  last used: {last}{RESET}")
    print()


def _token_revoke(args):
    """Revoke an API token."""
    from . import remote as api

    require_session()
    # Find token by name
    try:
        tokens = api.list_api_tokens(get_api_url(), get_auth_headers())
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)

    target = None
    for t in tokens:
        if t["name"] == args.name:
            target = t
            break

    if not target:
        _error(f"no token named '{args.name}'")
        sys.exit(1)

    try:
        api.revoke_api_token(get_api_url(), get_auth_headers(), target["token_id"])
        _success(f"revoked token: {args.name}")
    except RemoteError as e:
        _error(str(e.message))
        sys.exit(1)


# ── Helpers ───────────────────────────────────────────────

def _get_env_remote(args, root):
    """Get environment name from args for remote commands."""
    if hasattr(args, "env") and args.env:
        return args.env
    config = load_config(root)
    return config.get("default_env", "dev")
