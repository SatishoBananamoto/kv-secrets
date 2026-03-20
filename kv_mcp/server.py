"""MCP server lifecycle, dispatch, and profile enforcement.

Handles: initialize, notifications/initialized, tools/list, tools/call.
Enforces tool profiles (safe/mutate/reveal) and version negotiation.
"""

import os
import sys
import time

from kv.config import find_project_root, get_default_env, load_config, key_path
from kv.crypto import is_key_wrapped, decrypt_totp_secret, verify_totp
from kv.store import SecretStore


def _tty_prompt(prompt, hide=False):
    """Read input directly from /dev/tty, bypassing stdin.

    MCP uses stdin for JSON-RPC. We must read auth prompts from the
    terminal directly so the passphrase never enters the MCP channel.

    Fallback chain:
      1. /dev/tty (Unix — reads from controlling terminal regardless of stdin)
      2. getpass (tries /dev/tty internally, then stderr+stdin fallback)
      3. KV_PASSPHRASE env var (CI/headless — less secure but functional)
      4. Fail with clear message
    """
    # Attempt 1: /dev/tty (cleanest — completely bypasses stdin)
    try:
        tty_fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        tty_file = os.fdopen(tty_fd, "r+", closefd=True)
        try:
            tty_file.write(prompt)
            tty_file.flush()
            if hide:
                try:
                    import termios
                    old = termios.tcgetattr(tty_file)
                    new = list(old)
                    new[3] = new[3] & ~termios.ECHO
                    termios.tcsetattr(tty_file, termios.TCSANOW, new)
                    value = tty_file.readline().rstrip("\n")
                    tty_file.write("\n")
                    tty_file.flush()
                    termios.tcsetattr(tty_file, termios.TCSANOW, old)
                except ImportError:
                    value = tty_file.readline().rstrip("\n")
            else:
                value = tty_file.readline().rstrip("\n")
        finally:
            tty_file.close()
        return value
    except OSError:
        pass

    # Attempt 2: getpass (for passphrase — has its own /dev/tty + fallback logic)
    if hide:
        import getpass
        sys.stderr.write(prompt)
        sys.stderr.flush()
        try:
            return getpass.getpass("")
        except EOFError:
            pass

    # Attempt 3: environment variable (headless/CI fallback)
    if hide:
        env_pass = os.environ.get("KV_PASSPHRASE", "").strip()
        if env_pass:
            log("using KV_PASSPHRASE from environment (headless mode)")
            return env_pass

    # No terminal available
    log("error: no terminal available for interactive auth")
    log("  options:")
    log("  1. run 'python -m kv_mcp' from a terminal with a TTY")
    log("  2. set KV_PASSPHRASE env var (less secure, for headless/CI)")
    sys.exit(1)

from .protocol import read_message, write_message, make_response, make_error, log, ParseError
from .tools import TOOLS, HANDLERS, get_tools_for_profiles

# MCP protocol versions we support (stdio transport is identical across both)
SUPPORTED_VERSIONS = {"2025-11-25", "2025-03-26"}
LATEST_VERSION = "2025-11-25"

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def run_server(profiles):
    """Run the MCP stdio server with the given enabled profiles.

    profiles: set of enabled profile names (always includes 'safe')
    """
    # Discover kv project
    root = find_project_root()
    if root is None:
        log("error: no kv project found (run 'kv init' first)")
        sys.exit(1)

    # Passphrase + TOTP authentication at startup
    #
    # Critical: MCP uses stdin/stdout for JSON-RPC. We read auth prompts
    # from /dev/tty directly so the passphrase never touches the MCP channel.
    # The agent cannot see or intercept the prompts.
    # The decrypted key lives only in this process's memory.
    passphrase = None
    kp = key_path(root)
    if is_key_wrapped(kp):
        log("vault is passphrase-protected — prompting via /dev/tty")
        passphrase = _tty_prompt("  kv passphrase: ", hide=True)

        config = load_config(root)
        security = config.get("security", {})
        if security.get("totp"):
            totp_enc = security.get("totp_secret_enc")
            if totp_enc:
                try:
                    totp_secret = decrypt_totp_secret(totp_enc, passphrase)
                except Exception:
                    log("wrong passphrase")
                    sys.exit(1)
                code = _tty_prompt("  TOTP code: ", hide=False)
                if not verify_totp(totp_secret, code):
                    log("invalid TOTP code")
                    sys.exit(1)

        # Verify passphrase works before entering the server loop
        try:
            test_store = SecretStore(root, passphrase=passphrase)
            _ = test_store.master_key  # triggers unwrap
        except Exception:
            log("wrong passphrase")
            sys.exit(1)

        log("vault unlocked — key held in memory")

    store = SecretStore(root, passphrase=passphrase)
    default_env = get_default_env(root)

    log(f"started (root={root}, profiles={sorted(profiles)})")

    initialized = False
    negotiated_version = LATEST_VERSION

    while True:
        try:
            msg = read_message()
        except ParseError as exc:
            write_message(make_error(None, PARSE_ERROR, f"parse error: {exc}"))
            log(f"parse error: {exc}")
            continue
        except Exception as exc:
            log(f"read error: {exc}")
            break

        if msg is None:
            # EOF — client disconnected
            log("client disconnected (EOF)")
            break

        method = msg.get("method")
        msg_id = msg.get("id")  # None for notifications
        params = msg.get("params", {})

        # --- initialize ---
        if method == "initialize":
            client_version = params.get("protocolVersion", LATEST_VERSION)
            if client_version in SUPPORTED_VERSIONS:
                negotiated_version = client_version
            else:
                negotiated_version = LATEST_VERSION

            result = {
                "protocolVersion": negotiated_version,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "kv",
                    "version": "1.0.0",
                },
            }
            write_message(make_response(msg_id, result))
            log(f"initialized (version={negotiated_version})")
            continue

        # --- notifications/initialized ---
        if method == "notifications/initialized":
            initialized = True
            log("client confirmed initialization")
            # Notification — no response
            continue

        # --- Init enforcement: reject operational calls before handshake ---
        if not initialized and method not in ("initialize", "notifications/initialized", "ping"):
            if msg_id is not None:
                write_message(make_error(msg_id, INVALID_REQUEST, "server not initialized"))
                log(f"rejected {method} (not initialized)")
            continue

        # --- tools/list ---
        if method == "tools/list":
            tools = get_tools_for_profiles(profiles)
            write_message(make_response(msg_id, {"tools": tools}))
            log(f"tools/list -> {len(tools)} tools")
            continue

        # --- tools/call ---
        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            # Unknown tool
            if tool_name not in TOOLS:
                write_message(make_error(
                    msg_id, METHOD_NOT_FOUND,
                    f"unknown tool: {tool_name}"
                ))
                log(f"tools/call {tool_name} -> unknown tool")
                continue

            # Profile gate — tool exists but not enabled
            tool_profile = TOOLS[tool_name]["profile"]
            if tool_profile not in profiles:
                write_message(make_error(
                    msg_id, INVALID_REQUEST,
                    f"tool '{tool_name}' requires the '{tool_profile}' profile "
                    f"(enable with --allow-{tool_profile})"
                ))
                log(f"tools/call {tool_name} -> blocked (profile={tool_profile})")
                continue

            # Dispatch to handler
            handler = HANDLERS[tool_name]
            start = time.monotonic()
            try:
                result = handler(tool_args, store, default_env)
                elapsed_ms = int((time.monotonic() - start) * 1000)
                write_message(make_response(msg_id, result))
                status = "error" if result.get("isError") else "ok"
                log(f"tool={tool_name} env={tool_args.get('env', default_env)} "
                    f"duration_ms={elapsed_ms} status={status}")
            except Exception as exc:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                error_result = {
                    "content": [{"type": "text", "text": f"internal error: {type(exc).__name__}"}],
                    "isError": True,
                }
                write_message(make_response(msg_id, error_result))
                log(f"tool={tool_name} duration_ms={elapsed_ms} status=exception "
                    f"error={type(exc).__name__}: {exc}")
            continue

        # --- ping ---
        if method == "ping":
            write_message(make_response(msg_id, {}))
            continue

        # --- Unknown method ---
        if msg_id is not None:
            # It's a request (has id) — must respond with error
            write_message(make_error(
                msg_id, METHOD_NOT_FOUND,
                f"unknown method: {method}"
            ))
            log(f"unknown method: {method}")
        else:
            # It's a notification — just log and ignore
            log(f"unknown notification: {method}")
