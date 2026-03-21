"""kv agent — daemon that holds decrypted secrets in memory.

Like ssh-agent: unlock once, all processes use it until you stop it.
Listens on a Unix domain socket. Only serves safe operations:
  - run: execute command with secrets injected, return redacted output
  - list: return secret key names (no values)
  - status: return agent status
  - envs: return environment names

Does NOT serve:
  - get: never returns secret values through the socket
  - export: never dumps secrets

Security: the socket is chmod 600 (owner only). The agent can connect
to the socket but cannot extract secret values — only run commands
with secrets injected and see redacted output.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import ssl

SOCK_DIR = os.path.join(tempfile.gettempdir(), "kv-agent")
SOCK_FILENAME = "kv.sock"
MAX_MSG = 1024 * 1024  # 1MB max message size
RUN_TIMEOUT = 60  # seconds

# Patterns that indicate file-write exfiltration attempts
_EXFIL_PATTERNS = [
    "printenv >", "printenv>>", "env >", "env>>",
    "export >", "export>>", "echo $", "echo ${",
    "> /tmp/", ">> /tmp/", "tee /tmp/", "tee -a /tmp/",
    "> /var/tmp/", ">> /var/tmp/",
    ">/tmp/", ">>/tmp/",
]


def _check_exfiltration(argv):
    """Check if a command looks like a secret exfiltration attempt.

    Returns (safe, reason). This is advisory — catches obvious attacks
    like 'printenv > /tmp/file' but not sophisticated ones.
    """
    cmd_str = " ".join(argv).lower()
    for pattern in _EXFIL_PATTERNS:
        if pattern.lower() in cmd_str:
            return False, f"blocked: command matches exfiltration pattern '{pattern.strip()}'"
    return True, ""


def _scan_for_leaked_files(secrets, before_times, scan_dirs=None):
    """Scan for files created/modified during subprocess execution
    that contain secret values. Returns list of (path, secret_name) tuples.
    """
    if scan_dirs is None:
        scan_dirs = [tempfile.gettempdir()]

    leaked = []
    for scan_dir in scan_dirs:
        if not os.path.isdir(scan_dir):
            continue
        try:
            for entry in os.scandir(scan_dir):
                if not entry.is_file():
                    continue
                try:
                    mtime = entry.stat().st_mtime
                    # Only check files modified after subprocess started
                    if mtime < before_times:
                        continue
                    # Read and check for secret values
                    with open(entry.path, "r", errors="ignore") as f:
                        content = f.read(1024 * 1024)  # max 1MB
                    for name, value in secrets.items():
                        if value and len(value) >= 8 and value in content:
                            leaked.append((entry.path, name))
                            break
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            continue
    return leaked


def _redact(text, secrets):
    """Replace secret values in text with [REDACTED]."""
    for value in secrets.values():
        if value and len(value) >= 4:
            text = text.replace(value, "[REDACTED]")
    return text


def _sock_path():
    """Get the agent socket path."""
    return os.path.join(SOCK_DIR, SOCK_FILENAME)


def is_agent_running():
    """Check if a kv agent is running and reachable."""
    path = _sock_path()
    if not os.path.exists(path):
        return False
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(path)
        sock.send(json.dumps({"cmd": "status"}).encode())
        data = sock.recv(4096)
        sock.close()
        return True
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        # Stale socket file — clean it up
        try:
            os.unlink(path)
        except OSError:
            pass
        return False


def agent_request(cmd, **kwargs):
    """Send a request to the running agent. Returns response dict."""
    path = _sock_path()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(RUN_TIMEOUT + 5)
    sock.connect(path)

    request = {"cmd": cmd, **kwargs}
    sock.send(json.dumps(request).encode())

    # Read response
    chunks = []
    while True:
        data = sock.recv(65536)
        if not data:
            break
        chunks.append(data)
    sock.close()

    return json.loads(b"".join(chunks))


API_TIMEOUT = 120  # seconds — API calls can be slow (image gen, long completions)


def _providers_module():
    """Lazy import to avoid circular deps."""
    from . import providers
    return providers


def _handle_api_call(request, all_secrets, env_name):
    """Handle an 'api' command — make HTTP call with injected credentials.

    The API key never leaves this process. The agent gets the response body.
    """
    provider_name = request.get("provider")
    if not provider_name:
        return {"error": "provider is required (e.g. openai, anthropic, google)"}

    providers = _providers_module()
    provider = providers.get_provider(provider_name)
    if not provider:
        available = ", ".join(providers.list_providers())
        return {"error": f"unknown provider: {provider_name}. available: {available}"}

    # Get the secret for this provider
    secrets = all_secrets.get(env_name, {})
    secret_name = provider["secret_name"]
    secret_value = secrets.get(secret_name)
    if not secret_value:
        return {"error": f"secret '{secret_name}' not found in env '{env_name}'"}

    # Build the request
    path = request.get("path", "/")
    method = request.get("method", "POST").upper()
    body = request.get("body")
    extra_headers = request.get("headers", {})

    # Build auth
    auth_headers, auth_params = providers.build_auth(provider, secret_value)
    url = providers.build_url(provider, path, auth_params)

    # Merge headers: default + auth + extra (extra can override)
    headers = {**auth_headers, **extra_headers}

    # Encode body
    body_bytes = None
    if body is not None:
        if isinstance(body, (dict, list)):
            body_bytes = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8")

    # Make the HTTP call
    try:
        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
        ctx = ssl.create_default_context()

        with urllib.request.urlopen(req, timeout=API_TIMEOUT, context=ctx) as resp:
            resp_body = resp.read().decode("utf-8")
            status = resp.status

            # Redact any secret values from response (defense-in-depth)
            resp_body = _redact(resp_body, secrets)

            # Try to parse as JSON for clean output
            try:
                resp_json = json.loads(resp_body)
                return {"status": status, "body": resp_json}
            except json.JSONDecodeError:
                return {"status": status, "body": resp_body}

    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
            error_body = _redact(error_body, secrets)
        except Exception:
            pass
        return {"error": f"HTTP {e.code}: {e.reason}", "status": e.code, "body": error_body}

    except urllib.error.URLError as e:
        return {"error": f"connection error: {e.reason}"}

    except TimeoutError:
        return {"error": f"timeout ({API_TIMEOUT}s)"}

    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)}"}


def run_agent(store, default_env):
    """Run the kv agent daemon. Blocks until interrupted.

    Args:
        store: SecretStore with master key already loaded
        default_env: default environment name
    """
    # Load all secrets into memory
    from .config import list_environments
    all_secrets = {}
    envs = list_environments(store.root)
    for env in envs:
        try:
            all_secrets[env] = store.get_all_secrets(env)
        except Exception:
            all_secrets[env] = {}

    # Create socket directory
    os.makedirs(SOCK_DIR, mode=0o700, exist_ok=True)

    # Clean up stale socket
    path = _sock_path()
    if os.path.exists(path):
        try:
            os.unlink(path)
        except OSError:
            pass

    # Create Unix socket
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chmod(path, 0o600)  # owner only
    server.listen(5)
    server.settimeout(1.0)  # allow periodic interrupt check

    # Handle graceful shutdown
    running = True

    def _shutdown(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    pid = os.getpid()
    secret_count = sum(len(v) for v in all_secrets.values())
    env_count = len(envs)

    sys.stderr.write(f"\n  kv agent running (PID {pid})\n")
    sys.stderr.write(f"  {env_count} environment{'s' if env_count != 1 else ''}, "
                     f"{secret_count} secret{'s' if secret_count != 1 else ''} loaded\n")
    sys.stderr.write(f"  socket: {path}\n")
    sys.stderr.write(f"\n  Ctrl+C to stop\n\n")

    while running:
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            data = conn.recv(MAX_MSG)
            if not data:
                conn.close()
                continue

            request = json.loads(data)
            cmd = request.get("cmd")
            env_name = request.get("env", default_env)

            if cmd == "run":
                # Execute command with secrets injected
                argv = request.get("argv", [])
                if not argv:
                    response = {"error": "argv required", "exit_code": 1}
                else:
                    # Layer 1: Block obvious exfiltration patterns
                    safe, reason = _check_exfiltration(argv)
                    if not safe:
                        response = {"error": reason, "exit_code": 1}
                    else:
                        secrets = all_secrets.get(env_name, {})
                        run_env = dict(os.environ)
                        run_env.update(secrets)
                        scan_dirs = [
                            tempfile.gettempdir(),
                            os.path.expanduser("~"),
                            os.getcwd(),
                        ]
                        before_time = time.time()
                        try:
                            result = subprocess.run(
                                argv, env=run_env, shell=False,
                                capture_output=True, text=True,
                                timeout=RUN_TIMEOUT,
                            )
                            stdout = _redact(result.stdout, secrets) if result.stdout else ""
                            stderr = _redact(result.stderr, secrets) if result.stderr else ""

                            # Layer 2: Post-execution scan for leaked files
                            leaked = _scan_for_leaked_files(secrets, before_time, scan_dirs)
                            leak_warning = ""
                            if leaked:
                                for path, name in leaked:
                                    try:
                                        os.unlink(path)
                                    except OSError:
                                        pass
                                leak_names = [f"{name} → {path}" for path, name in leaked]
                                leak_warning = (
                                    f"\n[SECURITY] detected and deleted {len(leaked)} "
                                    f"file(s) containing secrets: {', '.join(leak_names)}"
                                )

                            response = {
                                "exit_code": result.returncode,
                                "stdout": stdout,
                                "stderr": stderr,
                            }
                            if leak_warning:
                                response["warning"] = leak_warning

                        except subprocess.TimeoutExpired:
                            response = {"error": f"timeout ({RUN_TIMEOUT}s)", "exit_code": 1}
                        except FileNotFoundError:
                            response = {"error": f"command not found: {argv[0]}", "exit_code": 1}

            elif cmd == "list":
                # Return key names only — NEVER values
                secrets = all_secrets.get(env_name, {})
                response = {"keys": sorted(secrets.keys()), "env": env_name}

            elif cmd == "envs":
                response = {"environments": envs}

            elif cmd == "status":
                response = {
                    "running": True,
                    "pid": pid,
                    "environments": env_count,
                    "secrets": secret_count,
                    "providers": list(_providers_module().list_providers()),
                }

            elif cmd == "api":
                # Make HTTP API call with credentials injected
                # The agent specifies provider + path + body
                # The daemon injects auth and makes the call
                # The key NEVER leaves this process
                response = _handle_api_call(request, all_secrets, env_name)

            else:
                response = {"error": f"unknown command: {cmd}"}

            conn.send(json.dumps(response).encode())

        except Exception as e:
            try:
                conn.send(json.dumps({"error": str(e)}).encode())
            except Exception:
                pass
        finally:
            conn.close()

    # Cleanup
    server.close()
    try:
        os.unlink(path)
    except OSError:
        pass

    sys.stderr.write("  agent stopped\n")
