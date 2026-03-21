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

    # Get tracked files from daemon
    try:
        tracked = agent_request("tracked_files")
        tracked_paths = tracked.get("files", [])
    except Exception:
        _allow()

    if not tracked_paths:
        _allow()

    # Build keyword fragments from tracked filenames.
    # For /tmp/xor_secret.bin, generate:
    #   "xor_secret.bin", "xor_secret", "secret.bin"
    # This catches path construction: os.path.join('/tmp', 'xor' + '_secret.bin')
    keywords = set()
    for tracked_path in tracked_paths:
        filename = os.path.basename(tracked_path)       # xor_secret.bin
        stem = os.path.splitext(filename)[0]             # xor_secret

        keywords.add(filename)                           # full filename
        if len(stem) >= 6:
            keywords.add(stem)                           # stem without extension

        # Sliding substrings (min length 8) catch partial matches
        for length in range(8, len(filename) + 1):
            for start in range(len(filename) - length + 1):
                keywords.add(filename[start:start + length])

    if tool_name == "Bash":
        command = tool_input.get("command", "")

        # Check 1: Token-based path matching (catches direct references)
        paths_to_check = _extract_all_paths(command)
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

        # Check 2: Keyword matching — only when command has file-access patterns
        # Prevents false positives on git commits, echo, etc. that mention
        # tracked filenames as text but don't access them.
        _FILE_ACCESS_PATTERNS = (
            "open(", ".read(", "os.path", "pathlib",
            "glob.", "glob(", "shutil.", "with open",
            "readlines", "readline", "read_bytes",
        )
        has_file_access = any(p in command for p in _FILE_ACCESS_PATTERNS)
        if has_file_access:
            for keyword in keywords:
                if keyword in command:
                    _deny(
                        f"[kv-secrets] blocked: command contains file-access code "
                        f"referencing '{keyword}' which matches a file created during "
                        f"a secret-injected subprocess (kv_run)."
                    )

    elif tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        if file_path:
            try:
                result = agent_request("check_file", path=file_path)
                if result.get("tracked"):
                    _deny(
                        f"[kv-secrets] blocked: '{file_path}' was created during a "
                        f"secret-injected subprocess (kv_run). Reading it could "
                        f"expose encoded secret values."
                    )
            except Exception:
                pass

    _allow()


if __name__ == "__main__":
    main()
