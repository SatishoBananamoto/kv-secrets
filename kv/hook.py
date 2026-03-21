"""kv PreToolUse hook — blocks reads of files created during kv_run.

Registered as a Claude Code PreToolUse hook. When the agent tries to
read a file that was created during a secret-injected subprocess,
the hook denies the operation without prompting the user.

This closes the last exfiltration gap: even if a subprocess writes
an encoded secret to disk, the agent cannot read it back.

Usage in .claude/settings.local.json:
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read",
        "command": "python3 -m kv.hook"
      }
    ]
  }
}
"""

import json
import sys

from .agent import is_agent_running, agent_request


# Commands that read files
_READ_COMMANDS = {"cat", "head", "tail", "less", "more", "bat", "hexdump", "xxd", "strings"}


def _extract_file_paths_from_bash(command_str):
    """Extract potential file paths from a Bash command."""
    paths = []
    parts = command_str.split()
    skip_next = False
    for i, part in enumerate(parts):
        if skip_next:
            skip_next = False
            continue
        # Skip flags
        if part.startswith("-"):
            # Some flags take arguments (-n, -c, etc.)
            if part in ("-n", "-c", "-o", "-e"):
                skip_next = True
            continue
        # Skip the command itself
        if i == 0 or part in _READ_COMMANDS:
            continue
        # Skip pipes and redirects
        if part in ("|", ">", ">>", "<", "&&", "||", ";"):
            continue
        # Remaining tokens are likely file paths
        if "/" in part or "." in part:
            paths.append(part)
    return paths


def main():
    """Hook entry point — reads PreToolUse JSON from stdin."""
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)  # can't parse, allow

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # Only check if daemon is running (has tracked files)
    if not is_agent_running():
        sys.exit(0)  # no daemon, allow

    paths_to_check = []

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        # Check if command starts with a read command
        first_word = command.strip().split()[0] if command.strip() else ""
        if first_word in _READ_COMMANDS:
            paths_to_check = _extract_file_paths_from_bash(command)

    elif tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        if file_path:
            paths_to_check = [file_path]

    if not paths_to_check:
        sys.exit(0)  # no file reads detected, allow

    # Check each path against the daemon's tracked files
    for path in paths_to_check:
        try:
            result = agent_request("check_file", path=path)
            if result.get("tracked"):
                # This file was created during a kv_run — block the read
                output = {
                    "hookSpecificOutput": {
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"[kv-secrets] blocked: '{path}' was created during a "
                            f"secret-injected subprocess (kv_run). Reading it could "
                            f"expose encoded secret values."
                        ),
                    }
                }
                print(json.dumps(output))
                sys.exit(0)
        except Exception:
            continue  # daemon unreachable, allow

    # No tracked files found in this command
    sys.exit(0)


if __name__ == "__main__":
    main()
