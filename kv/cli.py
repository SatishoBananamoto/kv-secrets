"""CLI for kv — command dispatch, argument parsing, formatted output."""

import argparse
import getpass
import os
import sys

from . import __version__
from .config import (
    find_project_root, init_project, load_config, save_config,
    list_environments, add_environment, secrets_dir, key_path,
)
from .crypto import is_key_wrapped
from .store import SecretStore, VaultLockedError


# ── ANSI formatting ────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[38;2;100;200;150m"
YELLOW = "\033[38;2;255;200;100m"
CYAN = "\033[38;2;140;180;255m"
RED = "\033[38;2;255;100;100m"
VALUE = "\033[38;2;150;220;130m"
MUTED = "\033[38;2;120;120;140m"


def _info(msg):
    print(f"  {msg}")


def _success(msg):
    print(f"  {GREEN}{msg}{RESET}")


def _error(msg):
    print(f"  {RED}{msg}{RESET}", file=sys.stderr)


def _header(msg):
    print(f"\n  {BOLD}{CYAN}kv{RESET} {DIM}--{RESET} {msg}")


def _kv_line(key, value="", extra=""):
    k = f"{YELLOW}{key}{RESET}"
    v = f"{VALUE}{value}{RESET}" if value else ""
    e = f"{MUTED}{extra}{RESET}" if extra else ""
    parts = [f"  {k}"]
    if v:
        parts.append(v)
    if e:
        parts.append(e)
    print("  ".join(parts))


# ── Helpers ────────────────────────────────────────────────

def _require_project():
    """Find project root or exit with error."""
    root = find_project_root()
    if root is None:
        _error("not a kv project (no .secrets/ found)")
        _info(f"{DIM}run 'python -m kv init' to initialize{RESET}")
        sys.exit(1)
    return root


def _get_store():
    """Get a SecretStore for the current project.

    If the vault is passphrase-protected, prompts for passphrase (and TOTP
    if configured). Agents cannot respond to interactive prompts — this is
    the security boundary.
    """
    root = _require_project()
    kp = key_path(root)

    if os.path.isfile(kp) and is_key_wrapped(kp):
        config = load_config(root)
        security = config.get("security", {})
        has_totp = security.get("totp", False)

        # Show lock status
        lock_type = "passphrase + 2FA" if has_totp else "passphrase"
        print(f"\n  {BOLD}{CYAN}kv{RESET} {DIM}--{RESET} vault locked {DIM}({lock_type}){RESET}\n")

        passphrase = getpass.getpass(f"  {YELLOW}Passphrase{RESET}: ")

        # Check TOTP if configured
        if has_totp:
            totp_enc = security.get("totp_secret_enc")
            if totp_enc:
                from .crypto import decrypt_totp_secret, verify_totp
                try:
                    totp_secret = decrypt_totp_secret(totp_enc, passphrase)
                except Exception:
                    _error("wrong passphrase")
                    sys.exit(1)
                code = input(f"  {YELLOW}TOTP code{RESET}:  ").strip()
                if not verify_totp(totp_secret, code):
                    _error("invalid TOTP code")
                    sys.exit(1)

        # Verify passphrase by trying to load key
        try:
            store = SecretStore(root, passphrase=passphrase)
            _ = store.master_key
        except Exception:
            _error("wrong passphrase")
            sys.exit(1)

        print(f"  {GREEN}unlocked{RESET}\n")
        return store

    return SecretStore(root)


def _get_env(args):
    """Get the environment name from args, falling back to default."""
    if args.env:
        return args.env
    root = _require_project()
    config = load_config(root)
    return config.get("default_env", "dev")


# ── Commands ───────────────────────────────────────────────

def cmd_init(args):
    """Initialize a new kv project."""
    # Check FIRST — don't prompt for passphrase if already initialized
    from .config import secrets_dir as _sdir, SECRETS_DIR
    check_path = os.path.join(os.getcwd(), SECRETS_DIR)
    if os.path.exists(check_path):
        _error("already initialized in this directory")
        _info(f"{DIM}vault exists at {check_path}{RESET}")
        sys.exit(1)

    # Prompt for passphrase (recommended)
    passphrase = None
    if not args.no_passphrase:
        _header("vault setup")
        print()
        _info(f"Set a passphrase to protect your master key.")
        _info(f"{DIM}This prevents AI agents from reading secrets via shell access.{RESET}")
        _info(f"{DIM}Press Enter to skip (not recommended).{RESET}")
        print()
        p1 = getpass.getpass(f"  {YELLOW}Passphrase{RESET}: ")
        if p1:
            p2 = getpass.getpass(f"  {YELLOW}Confirm{RESET}:    ")
            if p1 != p2:
                _error("passphrases don't match")
                sys.exit(1)
            from .crypto import check_passphrase_strength
            ok, reason = check_passphrase_strength(p1)
            if not ok:
                _error(reason)
                sys.exit(1)
            passphrase = p1
        else:
            print(f"  {YELLOW}!{RESET} skipping passphrase {DIM}-- master key stored in plaintext{RESET}")
            print()

    root = init_project(passphrase=passphrase)

    sdir = secrets_dir(root)
    _header("initialized")
    print()
    if passphrase:
        _info(f"{YELLOW}Master key{RESET}   {sdir}{os.sep}key  {GREEN}(passphrase-protected){RESET}")
    else:
        _info(f"{YELLOW}Master key{RESET}   {sdir}{os.sep}key  {RED}{BOLD}(DO NOT COMMIT){RESET}")
    _info(f"{YELLOW}Config{RESET}       {sdir}{os.sep}config.json")
    _info(f"{YELLOW}Gitignore{RESET}    {sdir}{os.sep}.gitignore  {DIM}(auto-configured){RESET}")
    print()
    _info(f"Environments: {GREEN}dev{RESET} (default)")
    if passphrase:
        _info(f"{DIM}Add 2FA: kv setup-2fa{RESET}")
    _info(f"{DIM}Set your first secret: kv set DATABASE_URL=...{RESET}")
    print()


def cmd_set(args):
    """Set a secret."""
    store = _get_store()
    env = _get_env(args)

    # Parse KEY=VALUE or prompt for value
    if "=" in args.secret:
        key, value = args.secret.split("=", 1)
    else:
        key = args.secret
        value = getpass.getpass(f"  Value for {YELLOW}{key}{RESET}: ")

    if not key:
        _error("key cannot be empty")
        sys.exit(1)

    store.set_secret(env, key, value)
    _success(f"set {BOLD}{key}{RESET}{GREEN}  ({env})  [encrypted]{RESET}")


def cmd_get(args):
    """Get a secret value."""
    store = _get_store()
    env = _get_env(args)

    value = store.get_secret(env, args.key)
    if value is None:
        _error(f"'{args.key}' not found in {env}")
        sys.exit(1)

    # Print raw value (no formatting) for piping
    print(value)


def cmd_ls(args):
    """List secrets."""
    store = _get_store()
    env = _get_env(args)

    secrets = store.list_secrets(env)
    if not secrets:
        _header(f"{env} {DIM}(empty){RESET}")
        _info(f"{DIM}no secrets set{RESET}")
        print()
        return

    _header(f"{env} ({len(secrets)} secret{'s' if len(secrets) != 1 else ''})")
    print()

    if args.reveal:
        for key, value in secrets:
            _kv_line(key, value)
    else:
        # Calculate column width
        max_key = max(len(k) for k, _ in secrets)
        for key, _ in secrets:
            padded = key.ljust(max_key + 2)
            print(f"  {YELLOW}{padded}{RESET}{MUTED}********{RESET}")
    print()


def cmd_rm(args):
    """Remove a secret."""
    store = _get_store()
    env = _get_env(args)

    if not args.force:
        confirm = input(f"  Remove '{args.key}' from {env}? [y/N] ").strip().lower()
        if confirm not in ("y", "yes"):
            _info("cancelled")
            return

    if store.remove_secret(env, args.key):
        _success(f"removed {BOLD}{args.key}{RESET}{GREEN} from {env}{RESET}")
    else:
        _error(f"'{args.key}' not found in {env}")
        sys.exit(1)


def cmd_run(args):
    """Run a command with secrets injected as env vars."""
    from .env import inject_and_run

    store = _get_store()
    env = _get_env(args)

    # REMAINDER gives us a list of command parts
    cmd_parts = args.cmd
    # Strip leading '--' that REMAINDER sometimes includes
    if cmd_parts and cmd_parts[0] == "--":
        cmd_parts = cmd_parts[1:]
    if not cmd_parts:
        _error("no command specified")
        _info(f"{DIM}usage: kv run [-e ENV] COMMAND...{RESET}")
        sys.exit(1)

    secrets = store.get_all_secrets(env)
    if not secrets:
        _error(f"no secrets in {env}")
        sys.exit(1)

    if not args.quiet:
        count = len(secrets)
        _header(f"injecting {count} secret{'s' if count != 1 else ''} ({env})")
        print()

    exit_code = inject_and_run(secrets, cmd_parts)
    sys.exit(exit_code)


def cmd_export(args):
    """Export secrets as .env format."""
    from .env import export_dotenv

    store = _get_store()
    env = _get_env(args)

    secrets = store.get_all_secrets(env)
    if not secrets:
        _error(f"no secrets in {env}")
        sys.exit(1)

    output = export_dotenv(secrets, args.output)

    if args.output:
        _success(f"exported {len(secrets)} secrets to {args.output}")
    else:
        # Already printed to stdout via export_dotenv
        pass


def cmd_import(args):
    """Import secrets from a .env file."""
    from .env import import_dotenv

    store = _get_store()
    env = _get_env(args)

    if not os.path.isfile(args.file):
        _error(f"file not found: {args.file}")
        sys.exit(1)

    secrets = import_dotenv(args.file)
    if not secrets:
        _error("no secrets found in file")
        sys.exit(1)

    for key, value in secrets.items():
        store.set_secret(env, key, value)

    _success(f"imported {len(secrets)} secrets into {env}")


def cmd_envs(args):
    """List all environments."""
    root = _require_project()
    envs = list_environments(root)
    store = SecretStore(root)

    _header(f"{len(envs)} environment{'s' if len(envs) != 1 else ''}")
    print()
    for env in envs:
        count = store.env_count(env)
        _info(f"{GREEN}{env}{RESET}  {DIM}({count} secret{'s' if count != 1 else ''}){RESET}")
    print()


def cmd_env(args):
    """Environment subcommands."""
    if args.env_action == "create":
        root = _require_project()
        if add_environment(root, args.name):
            _success(f"created environment: {args.name}")
        else:
            _error(f"environment '{args.name}' already exists")
            sys.exit(1)

    elif args.env_action == "copy":
        store = _get_store()
        count = store.copy_env(args.src, args.dst)
        _success(f"copied {count} secrets from {args.src} to {args.dst}")

    else:
        _error("usage: kv env create NAME  or  kv env copy SRC DST")
        sys.exit(1)


def cmd_status(args):
    """Show project status."""
    root = _require_project()
    config = load_config(root)
    store = SecretStore(root)
    envs = config["environments"]

    _header("project status")
    print()

    kp = key_path(root)
    key_exists = os.path.isfile(kp)
    key_status = f"{GREEN}present{RESET}" if key_exists else f"{RED}MISSING{RESET}"
    _info(f"{YELLOW}Key{RESET}            {kp} ({key_status})")
    _info(f"{YELLOW}Cipher{RESET}         {config['cipher']}")
    _info(f"{YELLOW}Created{RESET}        {config.get('created', 'unknown')}")

    env_parts = []
    for env in envs:
        count = store.env_count(env)
        env_parts.append(f"{env} ({count})")
    _info(f"{YELLOW}Environments{RESET}   {', '.join(env_parts)}")
    print()


def cmd_version(args):
    """Print version."""
    print(f"kv {__version__}")


def cmd_mcp(args):
    """Print MCP server config JSON for AI agents."""
    import json

    mcp_args = ["-m", "kv_mcp"]
    if args.allow_mutate:
        mcp_args.append("--allow-mutate")
    if args.allow_reveal:
        mcp_args.append("--allow-reveal")

    root = _require_project()

    config = {
        "mcpServers": {
            "kv": {
                "command": sys.executable,
                "args": mcp_args,
                "cwd": root,
            }
        }
    }

    _header("MCP server config")
    print()
    _info(f"Add this to your AI editor's MCP config file:")
    print()
    print(json.dumps(config, indent=2))
    print()
    if not args.allow_mutate and not args.allow_reveal:
        _info(f"{DIM}Default: safe tools only (status, envs, list, run){RESET}")
        _info(f"{DIM}Add --allow-mutate for set/rm, --allow-reveal for get{RESET}")
    print()


# ── Key Sharing ─────────────────────────────────────────


def cmd_export_key(args):
    """Export master key as a shareable kvkey_ string."""
    from .crypto import export_key
    root = _require_project()
    store = SecretStore(root)
    token = export_key(store.master_key)
    _header("export key")
    print()
    _info(f"Share this token with teammates via a secure channel:")
    print()
    print(f"  {token}")
    print()
    _info(f"{DIM}Teammate runs: kv import-key {token[:20]}...{RESET}")
    print()


def cmd_import_key(args):
    """Import a shared master key from a kvkey_ token."""
    from .crypto import import_key, save_key
    root = _require_project()
    kp = key_path(root)

    if os.path.isfile(kp):
        _error("master key already exists")
        _info(f"{DIM}Delete .secrets/key first if you want to replace it{RESET}")
        sys.exit(1)

    try:
        raw = import_key(args.token)
    except Exception as e:
        _error(f"invalid key token: {e}")
        sys.exit(1)

    if len(raw) != 32:
        _error(f"invalid key: expected 32 bytes, got {len(raw)}")
        sys.exit(1)

    save_key(raw, kp)
    _success("master key imported successfully")


# ── Doctor ──────────────────────────────────────────────


def cmd_doctor(args):
    """Run diagnostics on kv installation and project."""
    import importlib

    _header("doctor")
    print()

    errors = 0
    warnings = 0
    passed = 0

    def _pass(msg):
        nonlocal passed
        passed += 1
        print(f"  {GREEN}\u2713{RESET} {msg}")

    def _fail(msg):
        nonlocal errors
        errors += 1
        print(f"  {RED}\u2717{RESET} {msg}")

    def _warn(msg):
        nonlocal warnings
        warnings += 1
        print(f"  {YELLOW}!{RESET} {msg}")

    # 1. Python version
    v = sys.version_info
    if v >= (3, 10):
        _pass(f"Python {v.major}.{v.minor}.{v.micro}")
    else:
        _fail(f"Python {v.major}.{v.minor}.{v.micro} (3.10+ required)")

    # 2. Project initialized
    root = find_project_root()
    if root:
        _pass(f"Project found  {DIM}{root}{RESET}")
    else:
        _fail("No kv project found (run kv init)")
        print()
        _print_doctor_summary(passed, errors, warnings)
        sys.exit(1)

    # 3. Master key (file or KV_MASTER_KEY env var)
    kp = key_path(root)
    key = None
    if os.path.isfile(kp):
        try:
            from .crypto import load_key
            key = load_key(kp)
            if len(key) == 32:
                _pass("Master key readable (256-bit)")
            else:
                _fail(f"Master key wrong size ({len(key)} bytes, expected 32)")
                key = None
        except Exception as e:
            _fail(f"Master key unreadable: {e}")
    elif os.environ.get("KV_MASTER_KEY", "").strip():
        try:
            import base64
            key = base64.urlsafe_b64decode(os.environ["KV_MASTER_KEY"].strip())
            if len(key) == 32:
                _pass(f"Master key from KV_MASTER_KEY env var (256-bit)")
            else:
                _fail(f"KV_MASTER_KEY wrong size ({len(key)} bytes, expected 32)")
                key = None
        except Exception as e:
            _fail(f"KV_MASTER_KEY env var invalid: {e}")
    else:
        _fail(f"Master key missing  {DIM}{kp}{RESET}")

    # 4. Config valid
    config = None
    try:
        config = load_config(root)
        env_count = len(config.get("environments", []))
        _pass(f"Config valid ({env_count} environment{'s' if env_count != 1 else ''})")
    except Exception as e:
        _fail(f"Config error: {e}")

    # 5. Environments exist
    envs = []
    if config:
        envs = config.get("environments", [])
        if envs:
            _pass(f"Environments: {', '.join(envs)}")
        else:
            _fail("No environments configured")

    # 6. Default env decryptable
    if key and envs:
        default_env = config.get("default_env", envs[0])
        try:
            store = SecretStore(root)
            data = store.load_env(default_env)
            secrets = data.get("secrets", {})
            count = len(secrets)
            _pass(f"Decrypt OK  {DIM}{default_env} ({count} secret{'s' if count != 1 else ''}){RESET}")
        except FileNotFoundError:
            _pass(f"Decrypt OK  {DIM}{default_env} (empty, no .enc file yet){RESET}")
        except Exception as e:
            _fail(f"Decrypt failed for {default_env}: {e}")

    # 7. MCP module
    try:
        importlib.import_module("kv_mcp")
        _pass("MCP server module available")
    except ImportError:
        _warn("MCP server module not found (kv_mcp)")

    # 8. Editor MCP configs
    for editor, cfg in _EDITOR_CONFIGS.items():
        config_path = os.path.join(root, cfg["file"])
        if os.path.isfile(config_path):
            try:
                import json as _json
                with open(config_path, "r", encoding="utf-8") as f:
                    data = _json.load(f)
                servers = data.get(cfg["key"], {})
                if isinstance(servers, dict) and "kv" in servers:
                    _pass(f"{editor} MCP configured  {DIM}{cfg['file']}{RESET}")
                else:
                    _warn(f"{editor} config exists but no kv entry")
            except Exception:
                _warn(f"{editor} config exists but invalid JSON")
        else:
            _warn(f"{editor} MCP not configured  {DIM}{cfg['file']}{RESET}")

    print()
    _print_doctor_summary(passed, errors, warnings)
    if errors:
        sys.exit(1)


def _print_doctor_summary(passed, errors, warnings):
    total = passed + errors + warnings
    parts = []
    if passed:
        parts.append(f"{GREEN}{passed} passed{RESET}")
    if errors:
        parts.append(f"{RED}{errors} error{'s' if errors != 1 else ''}{RESET}")
    if warnings:
        parts.append(f"{YELLOW}{warnings} warning{'s' if warnings != 1 else ''}{RESET}")
    _info(", ".join(parts))
    print()


# ── MCP Editor Setup ─────────────────────────────────────

# Config file paths per editor (relative to project root unless absolute)
_EDITOR_CONFIGS = {
    "cursor": {
        "file": ".cursor/mcp.json",
        "scope": "project",
        "key": "mcpServers",
    },
    "claude-code": {
        "file": ".mcp.json",
        "scope": "project",
        "key": "mcpServers",
    },
    "vscode": {
        "file": ".vscode/mcp.json",
        "scope": "project",
        "key": "servers",
    },
}


def cmd_setup(args):
    """Auto-configure MCP for an AI editor."""
    import json

    editor = args.editor
    if editor not in _EDITOR_CONFIGS:
        _error(f"unknown editor: {editor}")
        _info(f"{DIM}supported: {', '.join(sorted(_EDITOR_CONFIGS))}{RESET}")
        sys.exit(1)

    root = _require_project()
    cfg = _EDITOR_CONFIGS[editor]

    # Build MCP server entry
    mcp_args = ["-m", "kv_mcp"]
    if args.allow_mutate:
        mcp_args.append("--allow-mutate")
    if args.allow_reveal:
        mcp_args.append("--allow-reveal")

    server_entry = {
        "command": sys.executable,
        "args": mcp_args,
        "cwd": root,
    }

    # Determine config file path
    config_path = os.path.join(root, cfg["file"])
    config_dir = os.path.dirname(config_path)

    # Load existing config or start fresh
    existing = {}
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
                if not isinstance(existing, dict):
                    _error(f"{config_path} is not a JSON object")
                    _info(f"{DIM}expected {{...}}, got {type(existing).__name__}{RESET}")
                    sys.exit(1)
        except json.JSONDecodeError:
            _error(f"malformed JSON in {config_path}")
            _info(f"{DIM}fix the file manually or delete it, then re-run kv setup{RESET}")
            sys.exit(1)
        except OSError as exc:
            _error(f"cannot read {config_path}: {exc}")
            sys.exit(1)

    # Merge — add kv server without overwriting other servers
    servers_key = cfg["key"]
    if servers_key not in existing:
        existing[servers_key] = {}
    elif not isinstance(existing[servers_key], dict):
        _error(f"'{servers_key}' in {config_path} is not an object")
        _info(f"{DIM}expected a JSON object ({{}}), got {type(existing[servers_key]).__name__}{RESET}")
        sys.exit(1)
    existing[servers_key]["kv"] = server_entry

    # Write config
    os.makedirs(config_dir, exist_ok=True)
    tmp_path = config_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
        f.write("\n")
    os.replace(tmp_path, config_path)

    _header(f"MCP configured for {editor}")
    print()
    _success(f"wrote {config_path}")
    print()

    # Show what was configured
    profiles = ["safe"]
    if args.allow_mutate:
        profiles.append("mutate")
    if args.allow_reveal:
        profiles.append("reveal")
    _info(f"{YELLOW}Profiles{RESET}   {', '.join(profiles)}")
    _info(f"{YELLOW}Tools{RESET}      {4 + (2 if args.allow_mutate else 0) + (1 if args.allow_reveal else 0)}")

    if not args.allow_mutate and not args.allow_reveal:
        print()
        _info(f"{DIM}Default: safe tools only (status, envs, list, run){RESET}")
        _info(f"{DIM}Add --allow-mutate for set/rm, --allow-reveal for get{RESET}")
    print()
    _info(f"{DIM}Restart {editor} to activate{RESET}")
    print()


# ── Security commands ─────────────────────────────────────


def cmd_setup_2fa(args):
    """Set up TOTP two-factor authentication."""
    from .crypto import (
        generate_totp_secret, totp_uri, verify_totp,
        encrypt_totp_secret, is_key_wrapped,
    )

    root = _require_project()
    config = load_config(root)
    security = config.get("security", {})

    if not security.get("passphrase"):
        _error("2FA requires a passphrase-protected vault")
        _info(f"{DIM}run 'kv upgrade-security' first{RESET}")
        sys.exit(1)

    if security.get("totp"):
        _error("2FA is already configured")
        _info(f"{DIM}to reconfigure, remove 'totp' from .secrets/config.json{RESET}")
        sys.exit(1)

    _header("2FA setup")
    print()

    # Need passphrase to encrypt the TOTP secret
    passphrase = getpass.getpass(f"  {YELLOW}Passphrase{RESET}: ")

    # Verify passphrase works by trying to load the key
    kp = key_path(root)
    try:
        from .crypto import load_wrapped_key
        load_wrapped_key(kp, passphrase)
    except Exception:
        _error("wrong passphrase")
        sys.exit(1)

    print(f"  {GREEN}verified{RESET}\n")

    # Generate TOTP secret
    secret = generate_totp_secret()
    uri = totp_uri(secret)

    _info("Scan this QR code with your authenticator app:")
    _info(f"{DIM}(Google Authenticator, Authy, or any TOTP app){RESET}")
    print()

    # Try to render QR code in terminal
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
        print()
    except ImportError:
        _info(f"{DIM}install 'qrcode' for QR display: pip install kv-secrets[totp]{RESET}")
        print()

    _info(f"{DIM}Or enter manually:{RESET}")
    _kv_line("Secret", secret)
    print()

    _info(f"Verify setup {DIM}-- enter a code from your app:{RESET}")
    code = input(f"  {YELLOW}Code{RESET}:  ").strip()
    if not verify_totp(secret, code):
        _error("invalid code — 2FA not enabled")
        _info(f"{DIM}check your authenticator app time is synced{RESET}")
        sys.exit(1)

    # Encrypt and store TOTP secret in config
    encrypted = encrypt_totp_secret(secret, passphrase)
    security["totp"] = True
    security["totp_secret_enc"] = encrypted
    config["security"] = security
    save_config(root, config)

    print()
    _success(f"2FA enabled {DIM}-- passphrase + authenticator code required{RESET}")
    print()


def cmd_upgrade_security(args):
    """Upgrade an existing plaintext vault to passphrase-protected."""
    from .crypto import load_key, save_wrapped_key, is_key_wrapped

    root = _require_project()
    kp = key_path(root)

    if not os.path.isfile(kp):
        _error("no master key found")
        sys.exit(1)

    if is_key_wrapped(kp):
        _error("vault is already passphrase-protected")
        sys.exit(1)

    # Read the plaintext key
    master_key = load_key(kp)

    _header("upgrade security")
    print()
    _info("Encrypt your master key with a passphrase.")
    _info(f"{DIM}After this, every operation requires your passphrase.{RESET}")
    _info(f"{DIM}AI agents with shell access will not be able to read secrets.{RESET}")
    print()

    p1 = getpass.getpass(f"  {YELLOW}New passphrase{RESET}: ")
    from .crypto import check_passphrase_strength
    ok, reason = check_passphrase_strength(p1)
    if not ok:
        _error(reason)
        sys.exit(1)
    p2 = getpass.getpass(f"  {YELLOW}Confirm{RESET}:        ")
    if p1 != p2:
        _error("passphrases don't match")
        sys.exit(1)

    # Wrap and overwrite
    save_wrapped_key(master_key, p1, kp)

    # Update config
    config = load_config(root)
    if "security" not in config:
        config["security"] = {}
    config["security"]["passphrase"] = True
    save_config(root, config)

    print()
    _success(f"master key encrypted {DIM}-- passphrase required for all operations{RESET}")
    _info(f"{DIM}next: add 2FA with 'kv setup-2fa'{RESET}")
    print()


def cmd_agent(args):
    """Start the kv agent daemon — unlock once, use everywhere."""
    from .agent import is_agent_running, run_agent

    if is_agent_running():
        _error("agent is already running")
        _info(f"{DIM}stop it first with Ctrl+C in the agent terminal{RESET}")
        sys.exit(1)

    root = _require_project()
    kp = key_path(root)

    # Prompt for passphrase + TOTP
    passphrase = None
    if os.path.isfile(kp) and is_key_wrapped(kp):
        config = load_config(root)
        security = config.get("security", {})
        has_totp = security.get("totp", False)

        lock_type = "passphrase + 2FA" if has_totp else "passphrase"
        _header(f"agent unlock ({lock_type})")
        print()

        passphrase = getpass.getpass(f"  {YELLOW}Passphrase{RESET}: ")

        if has_totp:
            totp_enc = security.get("totp_secret_enc")
            if totp_enc:
                from .crypto import decrypt_totp_secret, verify_totp
                try:
                    totp_secret = decrypt_totp_secret(totp_enc, passphrase)
                except Exception:
                    _error("wrong passphrase")
                    sys.exit(1)
                code = input(f"  {YELLOW}TOTP code{RESET}:  ").strip()
                if not verify_totp(totp_secret, code):
                    _error("invalid TOTP code")
                    sys.exit(1)

    store = SecretStore(root, passphrase=passphrase)
    try:
        _ = store.master_key
    except Exception:
        _error("wrong passphrase")
        sys.exit(1)

    from .config import get_default_env
    default_env = get_default_env(root)
    run_agent(store, default_env)


# ── Argument parser ────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="kv",
        description="Encrypted secrets management for developers.",
    )
    parser.add_argument(
        "--version", action="version", version=f"kv {__version__}"
    )

    sub = parser.add_subparsers(dest="command")

    # init
    p = sub.add_parser("init", help="Initialize a new kv project")
    p.add_argument(
        "--no-passphrase", action="store_true",
        help="Skip passphrase setup (not recommended)",
    )

    # set
    p = sub.add_parser("set", help="Set a secret")
    p.add_argument("secret", help="KEY=VALUE or just KEY (prompts for value)")
    p.add_argument("-e", "--env", help="Environment (default: dev)")

    # get
    p = sub.add_parser("get", help="Get a secret value")
    p.add_argument("key", help="Secret key name")
    p.add_argument("-e", "--env", help="Environment (default: dev)")

    # ls
    p = sub.add_parser("ls", help="List secrets")
    p.add_argument("-e", "--env", help="Environment (default: dev)")
    p.add_argument("--reveal", action="store_true", help="Show decrypted values")

    # rm
    p = sub.add_parser("rm", help="Remove a secret")
    p.add_argument("key", help="Secret key to remove")
    p.add_argument("-e", "--env", help="Environment (default: dev)")
    p.add_argument("-f", "--force", action="store_true", help="Skip confirmation")

    # run — flags MUST come before positional (REMAINDER swallows everything)
    p = sub.add_parser("run", help="Run command with secrets injected")
    p.add_argument("-e", "--env", help="Environment (default: dev)")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress kv output")
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run")

    # export
    p = sub.add_parser("export", help="Export secrets as .env format")
    p.add_argument("-e", "--env", help="Environment (default: dev)")
    p.add_argument("-o", "--output", help="Output file (default: stdout)")

    # import
    p = sub.add_parser("import", help="Import secrets from .env file")
    p.add_argument("file", help="Path to .env file")
    p.add_argument("-e", "--env", help="Environment (default: dev)")

    # envs
    sub.add_parser("envs", help="List all environments")

    # env (create/copy)
    p = sub.add_parser("env", help="Manage environments")
    env_sub = p.add_subparsers(dest="env_action")

    p_create = env_sub.add_parser("create", help="Create a new environment")
    p_create.add_argument("name", help="Environment name")

    p_copy = env_sub.add_parser("copy", help="Copy secrets between environments")
    p_copy.add_argument("src", help="Source environment")
    p_copy.add_argument("dst", help="Destination environment")

    # status
    sub.add_parser("status", help="Show project status")

    # doctor
    sub.add_parser("doctor", help="Check project health")

    # export-key
    sub.add_parser("export-key", help="Export master key as shareable string")

    # import-key
    p = sub.add_parser("import-key", help="Import a shared master key")
    p.add_argument("token", help="Key token (kvkey_...)")

    # version
    sub.add_parser("version", help="Print version")

    # mcp
    p = sub.add_parser("mcp", help="Show MCP server config for AI agents")
    p.add_argument("--allow-mutate", action="store_true", help="Include mutate flag")
    p.add_argument("--allow-reveal", action="store_true", help="Include reveal flag")

    # setup
    p = sub.add_parser("setup", help="Auto-configure MCP for your AI editor")
    p.add_argument("editor", help="Editor name: cursor, claude-code, vscode")
    p.add_argument("--allow-mutate", action="store_true", help="Enable mutate tools")
    p.add_argument("--allow-reveal", action="store_true", help="Enable reveal tools")

    # security
    sub.add_parser("setup-2fa", help="Enable TOTP two-factor authentication")
    sub.add_parser("upgrade-security", help="Add passphrase protection to existing vault")
    sub.add_parser("agent", help="Start agent daemon — unlock once, use everywhere")

    # ── Remote commands ───────────────────────────────────

    # signup / login / logout
    p = sub.add_parser("signup", help="Create a kv cloud account")
    p.add_argument("--api-url", help="Server URL (default: from session or env)")

    p = sub.add_parser("login", help="Log in to kv cloud")
    p.add_argument("--api-url", help="Server URL (default: from session or env)")

    sub.add_parser("logout", help="Log out (clear session)")

    # push / pull
    p = sub.add_parser("push", help="Push secrets to server")
    p.add_argument("-e", "--env", help="Environment (default: dev)")
    p.add_argument("--all", action="store_true", help="Push all environments")

    p = sub.add_parser("pull", help="Pull secrets from server")
    p.add_argument("-e", "--env", help="Environment (default: dev)")
    p.add_argument("--all", action="store_true", help="Pull all environments")

    # remote status
    sub.add_parser("remote", help="Show remote sync status")

    # team
    p = sub.add_parser("team", help="Team management")
    team_sub = p.add_subparsers(dest="team_action")

    p_tc = team_sub.add_parser("create", help="Create a team")
    p_tc.add_argument("name", help="Team name")

    p_ti = team_sub.add_parser("invite", help="Invite a member")
    p_ti.add_argument("email", help="Email address")

    team_sub.add_parser("members", help="List team members")

    p_tr = team_sub.add_parser("revoke", help="Revoke a member")
    p_tr.add_argument("email", help="Email address")

    team_sub.add_parser("key", help="Show shareable master key")

    p_tj = team_sub.add_parser("join", help="Join with a team key")
    p_tj.add_argument("key", help="Team key (kvkey_...)")

    # token
    p = sub.add_parser("token", help="API token management")
    tok_sub = p.add_subparsers(dest="token_action")

    p_tokc = tok_sub.add_parser("create", help="Create an API token")
    p_tokc.add_argument("name", help="Token name")
    p_tokc.add_argument("--scope", default="pull", help="Scope: pull, push, or admin")
    p_tokc.add_argument("--env", dest="token_env", help="Restrict to environment")
    p_tokc.add_argument("--expires", type=int, help="Expire in N days")

    tok_sub.add_parser("list", help="List API tokens")

    p_tokr = tok_sub.add_parser("revoke", help="Revoke an API token")
    p_tokr.add_argument("name", help="Token name")

    return parser


# ── Import remote commands ────────────────────────────────
from .cli_remote import (
    cmd_signup, cmd_login, cmd_logout,
    cmd_push, cmd_pull, cmd_remote_status,
    cmd_team, cmd_token,
)

COMMANDS = {
    "init": cmd_init,
    "set": cmd_set,
    "get": cmd_get,
    "ls": cmd_ls,
    "rm": cmd_rm,
    "run": cmd_run,
    "export": cmd_export,
    "import": cmd_import,
    "envs": cmd_envs,
    "env": cmd_env,
    "status": cmd_status,
    "doctor": cmd_doctor,
    "export-key": cmd_export_key,
    "import-key": cmd_import_key,
    "version": cmd_version,
    "mcp": cmd_mcp,
    "setup": cmd_setup,
    "setup-2fa": cmd_setup_2fa,
    "upgrade-security": cmd_upgrade_security,
    "agent": cmd_agent,
    # Remote
    "signup": cmd_signup,
    "login": cmd_login,
    "logout": cmd_logout,
    "push": cmd_push,
    "pull": cmd_pull,
    "remote": cmd_remote_status,
    "team": cmd_team,
    "token": cmd_token,
}


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handler = COMMANDS.get(args.command)
    if handler:
        try:
            handler(args)
        except KeyboardInterrupt:
            print()
            sys.exit(130)
        except Exception as e:
            _error(str(e))
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)
