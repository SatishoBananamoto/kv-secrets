"""MCP server lifecycle, dispatch, and profile enforcement.

Handles: initialize, notifications/initialized, tools/list, tools/call.
Enforces tool profiles (safe/mutate/reveal) and version negotiation.
"""

import sys
import time

from kv.config import find_project_root, get_default_env
from kv.store import SecretStore

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

    store = SecretStore(root)
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
