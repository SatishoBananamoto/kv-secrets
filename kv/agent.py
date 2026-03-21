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

SOCK_DIR = os.path.join(tempfile.gettempdir(), "kv-agent")
SOCK_FILENAME = "kv.sock"
MAX_MSG = 1024 * 1024  # 1MB max message size
RUN_TIMEOUT = 60  # seconds


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
                    secrets = all_secrets.get(env_name, {})
                    run_env = dict(os.environ)
                    run_env.update(secrets)
                    try:
                        result = subprocess.run(
                            argv, env=run_env, shell=False,
                            capture_output=True, text=True,
                            timeout=RUN_TIMEOUT,
                        )
                        stdout = _redact(result.stdout, secrets) if result.stdout else ""
                        stderr = _redact(result.stderr, secrets) if result.stderr else ""
                        response = {
                            "exit_code": result.returncode,
                            "stdout": stdout,
                            "stderr": stderr,
                        }
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
                }

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
