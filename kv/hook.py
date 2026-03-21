"""kv PreToolUse hook — blocks reads of files created during kv_run.

Matches SVX's proven hook pattern:
- Reads tool input from stdin as JSON
- Outputs {} for allow, hookSpecificOutput for deny
- Always exits 0

Usage in .claude/settings.local.json:
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read",
        "hooks": [
          {"type": "command", "command": "python3 -m kv.hook"}
        ]
      }
    ]
  }
}
"""

import json
import sys
import os


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
        if part.startswith("-"):
            if part in ("-n", "-c", "-o", "-e"):
                skip_next = True
            continue
        if i == 0 or part in _READ_COMMANDS:
            continue
        if part in ("|", ">", ">>", "<", "&&", "||", ";"):
            continue
        if "/" in part or "." in part:
            paths.append(part)
    return paths


def _allow():
    """Allow the tool call (print empty JSON, exit 0)."""
    print(json.dumps({}))
    sys.exit(0)


def _deny(reason):
    """Deny the tool call (print hookSpecificOutput, exit 0)."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def main():
    """Hook entry point — reads PreToolUse JSON from stdin."""
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError, EOFError):
        _allow()  # can't parse, fail open

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # Only check if daemon is running (has tracked files)
    from kv.agent import is_agent_running, agent_request
    if not is_agent_running():
        _allow()

    paths_to_check = []

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        first_word = command.strip().split()[0] if command.strip() else ""
        if first_word in _READ_COMMANDS:
            paths_to_check = _extract_file_paths_from_bash(command)

    elif tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        if file_path:
            paths_to_check = [file_path]

    if not paths_to_check:
        _allow()

    # Check each path against the daemon's tracked files
    for path in paths_to_check:
        try:
            result = agent_request("check_file", path=path)
            if result.get("tracked"):
                _deny(
                    f"[kv-secrets] blocked: '{path}' was created during a "
                    f"secret-injected subprocess (kv_run). Reading it could "
                    f"expose encoded secret values."
                )
        except Exception:
            continue

    _allow()


if __name__ == "__main__":
    main()
