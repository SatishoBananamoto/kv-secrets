"""kv hooks — PreToolUse (block/warn) and PostToolUse (leak detection).

Two hooks:
  PreToolUse:  Blocks reads of tracked files. Flags suspicious commands.
  PostToolUse: Scans Bash output for leaked secret values. Alerts user.

Usage in .claude/settings.local.json:
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read",
        "hooks": [
          {"type": "command", "command": "python3 -m kv.hook pre"}
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "python3 -m kv.hook post"}
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
    """Extract all tokens that look like file paths from a Bash command."""
    import shlex
    paths = []
    try:
        parts = shlex.split(command_str)
    except ValueError:
        parts = command_str.split()

    for part in parts:
        if part.startswith("-"):
            continue
        if part in ("|", ">", ">>", "<", "&&", "||", ";", "2>&1"):
            continue
        if "/" in part or part.startswith(".") or part.startswith("~"):
            expanded = os.path.expanduser(part)
            paths.append(expanded)
    return paths


def _allow():
    """Allow the tool call."""
    print(json.dumps({}))
    sys.exit(0)


def _deny(reason):
    """Deny the tool call."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(output))
    sys.exit(0)


# Patterns that indicate encoded data handling — suspicious when combined
# with file-access patterns and tracked files exist
_ENCODING_PATTERNS = (
    "base64", "b64decode", "b64encode",
    "bytes.fromhex", "fromhex", ".hex()",
    "binascii", "codecs.decode", "rot13",
    "chr(", "ord(", "bytearray",
    "decode(", "encode(",
)

_FILE_ACCESS_PATTERNS = (
    "open(", ".read(", "os.path", "pathlib",
    "glob.", "glob(", "shutil.", "with open",
    "readlines", "readline", "read_bytes",
    "scandir", "listdir", "walk(",
)


def _pre_hook(data):
    """PreToolUse: block tracked file access, flag suspicious commands."""
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    from kv.agent import is_agent_running, agent_request
    if not is_agent_running():
        _allow()

    try:
        tracked = agent_request("tracked_files")
        tracked_paths = tracked.get("files", [])
    except Exception:
        _allow()

    if not tracked_paths:
        _allow()

    # Build keyword fragments from tracked filenames
    keywords = set()
    for tracked_path in tracked_paths:
        filename = os.path.basename(tracked_path)
        stem = os.path.splitext(filename)[0]

        keywords.add(filename)
        if len(stem) >= 6:
            keywords.add(stem)

        for length in range(8, len(filename) + 1):
            for start in range(len(filename) - length + 1):
                keywords.add(filename[start:start + length])

    if tool_name == "Bash":
        command = tool_input.get("command", "")

        # Check 1: Token-based path matching
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

        # Check 2: Keyword matching with file-access patterns
        has_file_access = any(p in command for p in _FILE_ACCESS_PATTERNS)
        if has_file_access:
            for keyword in keywords:
                if keyword in command:
                    _deny(
                        f"[kv-secrets] blocked: command contains file-access code "
                        f"referencing '{keyword}' which matches a tracked file."
                    )

        # Check 3: Suspicious encoding + file access pattern
        # Can't block (might be legitimate) but WARN the user
        has_encoding = any(p in command for p in _ENCODING_PATTERNS)
        if has_file_access and has_encoding:
            # Write warning to stderr — user sees it, agent doesn't
            sys.stderr.write(
                "\n\033[38;2;255;100;100m"
                "[kv-secrets WARNING]\033[0m Suspicious command detected:\n"
                "  File-access code with encoding/decoding patterns.\n"
                "  This may be an attempt to read tracked files via encoded paths.\n"
                f"  Command: {command[:120]}...\n"
                "  \033[33mReview before allowing.\033[0m\n\n"
            )

    elif tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        if file_path:
            try:
                result = agent_request("check_file", path=file_path)
                if result.get("tracked"):
                    _deny(
                        f"[kv-secrets] blocked: '{file_path}' was created during a "
                        f"secret-injected subprocess (kv_run)."
                    )
            except Exception:
                pass

    _allow()


def _post_hook(data):
    """PostToolUse: scan Bash output for leaked secret values.

    If a secret value appears in the tool output, alert the user via stderr.
    Can't undo the leak (agent already saw it) but can:
    1. Alert the user immediately
    2. Tell them which key to rotate
    3. Log the incident
    """
    tool_name = data.get("tool_name", "")
    if tool_name != "Bash":
        _allow()

    # Get the tool output/result
    tool_output = data.get("tool_result", "")
    if not tool_output:
        # Try alternate field names
        tool_output = data.get("tool_response", "")
    if not tool_output:
        _allow()

    # Convert to string if needed
    if isinstance(tool_output, dict):
        tool_output = json.dumps(tool_output)
    tool_output = str(tool_output)

    from kv.agent import is_agent_running, agent_request
    if not is_agent_running():
        _allow()

    # Get secret values from daemon for scanning
    try:
        result = agent_request("secret_names")
        secret_names = result.get("names", [])
    except Exception:
        _allow()

    if not secret_names:
        _allow()

    # Ask daemon to check output for leaked values
    # The daemon has the actual secret values — we don't want them in the hook
    try:
        result = agent_request("check_leak", text=tool_output)
        leaked = result.get("leaked", [])
    except Exception:
        _allow()

    if leaked:
        # ALERT — secret values found in Bash output
        leak_list = ", ".join(leaked)
        sys.stderr.write(
            "\n\033[1;38;2;255;50;50m"
            "=== KV-SECRETS LEAK DETECTED ===\033[0m\n\n"
            f"  Secret values found in command output: \033[1m{leak_list}\033[0m\n\n"
            "  The AI agent has seen these values. They are compromised.\n"
            "  \033[1;33mRotate these keys immediately:\033[0m\n"
        )
        for name in leaked:
            sys.stderr.write(f"    - {name}\n")
        sys.stderr.write(
            "\n  After rotating, update kv:\n"
        )
        for name in leaked:
            sys.stderr.write(f"    kv set {name}\n")
        sys.stderr.write("\n")

    _allow()


def main():
    """Dispatch to pre or post hook based on argument."""
    mode = sys.argv[1] if len(sys.argv) > 1 else "pre"

    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError, EOFError):
        _allow()

    if mode == "post":
        _post_hook(data)
    else:
        _pre_hook(data)


if __name__ == "__main__":
    main()
