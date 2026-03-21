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


def _extract_all_paths(command_str):
    """Extract all tokens that look like file paths from a Bash command.

    Checks every token — not just arguments to read commands.
    Any command (grep, cp, base64, awk, python3, etc.) that references
    a tracked file path will be caught.
    """
    import shlex
    paths = []
    try:
        parts = shlex.split(command_str)
    except ValueError:
        parts = command_str.split()

    for part in parts:
        # Skip flags, operators, and very short tokens
        if part.startswith("-"):
            continue
        if part in ("|", ">", ">>", "<", "&&", "||", ";", "2>&1"):
            continue
        # Anything with a / or starting with . or ~ looks like a path
        if "/" in part or part.startswith(".") or part.startswith("~"):
            # Expand ~ to home dir
            expanded = os.path.expanduser(part)
            paths.append(expanded)
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
        # Check ALL tokens in the command for tracked file paths
        # Don't filter by command name — any command can read files
        paths_to_check = _extract_all_paths(command)

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
