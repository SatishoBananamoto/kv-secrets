"""Entry point for kv MCP server: python -m kv_mcp

Usage:
    python -m kv_mcp                              # safe profile only (default)
    python -m kv_mcp --allow-mutate               # safe + mutate
    python -m kv_mcp --allow-reveal               # safe + reveal
    python -m kv_mcp --allow-mutate --allow-reveal  # all profiles

MCP config example (for Claude Code, Cursor, etc.):
    {
      "mcpServers": {
        "kv": {
          "command": "python",
          "args": ["-m", "kv_mcp"],
          "cwd": "/path/to/your/project"
        }
      }
    }
"""

import argparse
import os
import sys


def main():
    # Windows encoding fix — MCP uses JSON over stdio, must be UTF-8
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr, sys.stdin):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8")
        os.system("")  # Enable ANSI on Windows (for stderr logging)

    parser = argparse.ArgumentParser(
        prog="kv_mcp",
        description="kv MCP server — encrypted secrets for AI agents",
    )
    parser.add_argument(
        "--allow-mutate",
        action="store_true",
        help="Enable mutate tools (kv_set, kv_rm)",
    )
    parser.add_argument(
        "--allow-reveal",
        action="store_true",
        help="Enable reveal tools (kv_get) — WARNING: exposes secret values to AI",
    )
    args = parser.parse_args()

    # Build profile set
    profiles = {"safe"}
    if args.allow_mutate:
        profiles.add("mutate")
    if args.allow_reveal:
        profiles.add("reveal")

    if args.allow_reveal:
        print(
            "WARNING: --allow-reveal is enabled.\n"
            "  The AI agent can call kv_get to read secret values in plaintext.\n"
            "  Consider using kv_run instead — secrets are injected into\n"
            "  subprocesses without exposing values to the agent.\n",
            file=sys.stderr,
        )

    from .server import run_server
    run_server(profiles)


if __name__ == "__main__":
    main()
