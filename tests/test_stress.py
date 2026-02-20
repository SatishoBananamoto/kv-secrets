"""Stress test: hammer /health to find the request count that kills the server."""

import http.client
import os
import random
import subprocess
import sys
import time
import urllib.request
import urllib.error

# --Paths ------------------------------------------------
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_TEST_DIR)  # kv-project/

PORT = str(random.randint(9100, 9900))
API_URL = f"http://127.0.0.1:{PORT}"
UNIQUE = "stress"

_db_path = os.path.join(_TEST_DIR, f"test_stress_{UNIQUE}.db").replace("\\", "/")

env = os.environ.copy()
env["KV_PORT"] = PORT
env["KV_DEBUG"] = "0"
env["KV_JWT_SECRET"] = "test-jwt-secret-stress"
env["KV_DATABASE_URL"] = f"sqlite+aiosqlite:///{_db_path}"
env["PYTHONDONTWRITEBYTECODE"] = "1"

proc = subprocess.Popen(
    [sys.executable, "-Bu", "-m", "kv_server"],
    env=env,
    cwd=PROJECT_ROOT,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
)

# Wait for server
deadline = time.time() + 10
while time.time() < deadline:
    try:
        urllib.request.urlopen(f"{API_URL}/health")
        break
    except Exception:
        time.sleep(0.3)
else:
    print("Server failed to start")
    proc.terminate()
    sys.exit(1)

print(f"Server started (PID {proc.pid})")

# Use a PERSISTENT http.client connection (keep-alive) to avoid socket exhaustion
conn = http.client.HTTPConnection("127.0.0.1", int(PORT), timeout=5)
for i in range(200):
    try:
        conn.request("GET", "/health")
        resp = conn.getresponse()
        resp.read()
        if (i + 1) % 10 == 0:
            print(f"  {i+1} requests OK (status={resp.status})")
    except Exception as e:
        print(f"  FAILED at request {i+1}: {e}")
        # Try reconnecting
        try:
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", int(PORT), timeout=5)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            resp.read()
            print(f"  Reconnected at {i+1}")
        except Exception as e2:
            print(f"  Reconnect also failed: {e2}")
            break

conn.close()
proc.terminate()
try:
    proc.wait(timeout=5)
except Exception:
    pass

# Cleanup
try:
    os.remove(os.path.join(_TEST_DIR, f"test_stress_{UNIQUE}.db"))
except OSError:
    pass

print("Done")
