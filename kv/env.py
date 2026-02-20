"""Environment management for kv.

Secret injection into subprocesses, .env import/export.
"""

import os
import subprocess
import sys


def inject_and_run(secrets, cmd_parts):
    """Run a command with secrets injected as environment variables.

    cmd_parts: list of command arguments (e.g. ["python", "-c", "print(1)"])
    Returns the exit code of the child process.
    """
    # Build env: inherit current + overlay secrets
    env = dict(os.environ)
    env.update(secrets)

    result = subprocess.run(cmd_parts, env=env)
    return result.returncode


def export_dotenv(secrets, output_path=None):
    """Export secrets as .env format.

    If output_path is None, prints to stdout.
    """
    lines = []
    for key in sorted(secrets):
        value = secrets[key]
        # Quote values that contain spaces, #, or newlines
        if any(c in value for c in (' ', '#', '\n', '"', "'")):
            escaped = value.replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f'{key}="{escaped}"')
        else:
            lines.append(f"{key}={value}")

    content = "\n".join(lines) + "\n"

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        sys.stdout.write(content)


def import_dotenv(path):
    """Import secrets from a .env file.

    Returns a dict of {KEY: VALUE}.
    Handles: comments, blank lines, quotes, export prefix.
    """
    secrets = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Strip optional "export " prefix
            if line.startswith("export "):
                line = line[7:]

            # Parse KEY=VALUE
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if not key:
                continue

            # Strip surrounding quotes
            if len(value) >= 2:
                if (value[0] == '"' and value[-1] == '"') or \
                   (value[0] == "'" and value[-1] == "'"):
                    value = value[1:-1]

            # Unescape
            value = value.replace('\\"', '"').replace("\\n", "\n")

            secrets[key] = value

    return secrets
