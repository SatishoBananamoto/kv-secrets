"""MCP tool definitions and handlers for kv.

7 tools across 3 profiles:
  safe (default): kv_status, kv_envs, kv_list, kv_run
  mutate (opt-in): kv_set, kv_rm
  reveal (opt-in): kv_get
"""

import subprocess
import sys
import time

from kv.config import find_project_root, list_environments, get_default_env
from kv.store import SecretStore

# -- Tool definitions (MCP JSON Schema format) --------------------------------

TOOLS = {
    # --- safe profile ---
    "kv_status": {
        "name": "kv_status",
        "description": (
            "[SAFE] Show kv project status. "
            "Returns whether a kv project is initialized, the current environment, "
            "and the number of secrets stored."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "profile": "safe",
    },
    "kv_envs": {
        "name": "kv_envs",
        "description": (
            "[SAFE] List available environments (e.g. dev, staging, prod). "
            "Does not reveal any secret values."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "profile": "safe",
    },
    "kv_list": {
        "name": "kv_list",
        "description": (
            "[SAFE] List secret key names in an environment. "
            "Returns names only — no secret values are revealed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "env": {
                    "type": "string",
                    "description": "Environment name (default: project default)",
                },
            },
        },
        "profile": "safe",
    },
    "kv_run": {
        "name": "kv_run",
        "description": (
            "[EXECUTE] Run a command with secrets injected as environment variables. "
            "Returns exit code only — no stdout/stderr is captured. "
            "Secrets are available to the subprocess via env vars but are NOT "
            "returned to the AI context. The subprocess CAN access the secrets "
            "and could print or transmit them — this tool prevents the AI agent "
            "from seeing values in the tool response, but cannot prevent the "
            "subprocess itself from using them. "
            "The MCP client SHOULD prompt for user confirmation before calling. "
            "30-second timeout; process is killed if it exceeds this."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "argv": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Command and arguments as an array (e.g. [\"python\", \"app.py\"])",
                },
                "env_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Secret names to inject. If omitted, all secrets are injected.",
                },
                "env": {
                    "type": "string",
                    "description": "Environment name (default: project default)",
                },
            },
            "required": ["argv"],
        },
        "profile": "safe",
    },
    # --- mutate profile ---
    "kv_set": {
        "name": "kv_set",
        "description": (
            "[MUTATE] Store or update an encrypted secret. "
            "The value is encrypted immediately using ChaCha20-Poly1305. "
            "The MCP client SHOULD prompt for user confirmation before calling."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Secret key name (e.g. OPENAI_API_KEY)",
                },
                "value": {
                    "type": "string",
                    "description": "Secret value to store",
                },
                "env": {
                    "type": "string",
                    "description": "Environment name (default: project default)",
                },
            },
            "required": ["name", "value"],
        },
        "profile": "mutate",
    },
    "kv_rm": {
        "name": "kv_rm",
        "description": (
            "[MUTATE] Remove a secret from the encrypted store. "
            "This action is irreversible. "
            "The MCP client SHOULD prompt for user confirmation before calling."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Secret key name to remove",
                },
                "env": {
                    "type": "string",
                    "description": "Environment name (default: project default)",
                },
            },
            "required": ["name"],
        },
        "profile": "mutate",
    },
    # --- reveal profile ---
    "kv_get": {
        "name": "kv_get",
        "description": (
            "[REVEAL] Get a secret value by name. "
            "WARNING: The decrypted value is returned in plaintext to the AI context. "
            "This means the secret will be visible to the language model. "
            "Prefer kv_run to use secrets without revealing them. "
            "The MCP client SHOULD prompt for user confirmation before calling."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Secret key name to retrieve",
                },
                "env": {
                    "type": "string",
                    "description": "Environment name (default: project default)",
                },
            },
            "required": ["name"],
        },
        "profile": "reveal",
    },
}


def get_tools_for_profiles(profiles):
    """Return tool definitions for the given set of enabled profiles.

    Always includes 'safe'. 'mutate' and 'reveal' are opt-in.
    """
    result = []
    for tool in TOOLS.values():
        if tool["profile"] in profiles:
            # Return MCP-compliant tool def (without internal 'profile' field)
            result.append({
                "name": tool["name"],
                "description": tool["description"],
                "inputSchema": tool["inputSchema"],
            })
    return result


# -- Tool handlers ------------------------------------------------------------

MAX_ARGV_COUNT = 50
MAX_ARGV_LEN = 4096
RUN_TIMEOUT = 30
MAX_LIST_KEYS = 1000


def _get_env_name(args, default_env):
    """Extract environment name from tool args, falling back to project default."""
    return args.get("env") or default_env


def handle_kv_status(args, store, default_env):
    """Handle kv_status tool call."""
    root = store.root
    envs = list_environments(root)
    count = store.env_count(default_env)
    text = f"project: initialized\nroot: {root}\ndefault_env: {default_env}\nenvironments: {len(envs)}\nsecrets ({default_env}): {count}"
    return {"content": [{"type": "text", "text": text}], "isError": False}


def handle_kv_envs(args, store, default_env):
    """Handle kv_envs tool call."""
    root = store.root
    envs = list_environments(root)
    text = "\n".join(envs) if envs else "(no environments)"
    return {"content": [{"type": "text", "text": text}], "isError": False}


def handle_kv_list(args, store, default_env):
    """Handle kv_list tool call. Returns key names only — no values."""
    env = _get_env_name(args, default_env)
    secrets = store.list_secrets(env)
    names = [k for k, v in secrets][:MAX_LIST_KEYS]
    text = "\n".join(names) if names else "(no secrets)"
    return {"content": [{"type": "text", "text": text}], "isError": False}


def handle_kv_run(args, store, default_env):
    """Handle kv_run tool call. Runs command with secrets as env vars.

    Returns exit code only — no stdout/stderr captured.
    """
    import os

    argv = args.get("argv")
    if not argv or not isinstance(argv, list):
        return {"content": [{"type": "text", "text": "error: argv is required and must be an array"}], "isError": True}

    # Validate argv
    if len(argv) > MAX_ARGV_COUNT:
        return {"content": [{"type": "text", "text": f"error: too many arguments (max {MAX_ARGV_COUNT})"}], "isError": True}
    for i, arg in enumerate(argv):
        if not isinstance(arg, str):
            return {"content": [{"type": "text", "text": f"error: argv[{i}] must be a string"}], "isError": True}
        if len(arg) > MAX_ARGV_LEN:
            return {"content": [{"type": "text", "text": f"error: argv[{i}] exceeds max length ({MAX_ARGV_LEN})"}], "isError": True}

    env_name = _get_env_name(args, default_env)
    all_secrets = store.get_all_secrets(env_name)

    # Filter to requested env_names if specified
    # None/absent = inject all secrets; empty list = inject none
    env_names = args.get("env_names")
    if env_names is not None:
        secrets = {k: v for k, v in all_secrets.items() if k in env_names}
    else:
        secrets = all_secrets

    # Build env: inherit current + overlay secrets
    run_env = dict(os.environ)
    run_env.update(secrets)

    is_error = False
    try:
        result = subprocess.run(
            argv,
            env=run_env,
            shell=False,
            timeout=RUN_TIMEOUT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        text = f"exit code: {result.returncode}"
    except subprocess.TimeoutExpired:
        text = f"error: command timed out after {RUN_TIMEOUT}s (process killed)"
        is_error = True
    except FileNotFoundError:
        text = f"error: command not found: {argv[0]}"
        is_error = True
    except Exception as exc:
        text = f"error: {type(exc).__name__}"
        is_error = True

    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def handle_kv_set(args, store, default_env):
    """Handle kv_set tool call."""
    name = args.get("name")
    value = args.get("value")
    if not name or value is None:
        return {"content": [{"type": "text", "text": "error: name and value are required"}], "isError": True}

    env = _get_env_name(args, default_env)
    store.set_secret(env, name, value)
    text = f"stored {name} in {env}"
    return {"content": [{"type": "text", "text": text}], "isError": False}


def handle_kv_rm(args, store, default_env):
    """Handle kv_rm tool call."""
    name = args.get("name")
    if not name:
        return {"content": [{"type": "text", "text": "error: name is required"}], "isError": True}

    env = _get_env_name(args, default_env)
    existed = store.remove_secret(env, name)
    if existed:
        text = f"removed {name} from {env}"
    else:
        text = f"{name} not found in {env}"
    return {"content": [{"type": "text", "text": text}], "isError": False}


def handle_kv_get(args, store, default_env):
    """Handle kv_get tool call. WARNING: returns plaintext secret value."""
    name = args.get("name")
    if not name:
        return {"content": [{"type": "text", "text": "error: name is required"}], "isError": True}

    env = _get_env_name(args, default_env)
    value = store.get_secret(env, name)
    if value is None:
        text = f"{name} not found in {env}"
        return {"content": [{"type": "text", "text": text}], "isError": True}

    return {"content": [{"type": "text", "text": value}], "isError": False}


# -- Dispatcher ---------------------------------------------------------------

HANDLERS = {
    "kv_status": handle_kv_status,
    "kv_envs": handle_kv_envs,
    "kv_list": handle_kv_list,
    "kv_run": handle_kv_run,
    "kv_set": handle_kv_set,
    "kv_rm": handle_kv_rm,
    "kv_get": handle_kv_get,
}
