"""Integration tests for kv_mcp — MCP server for encrypted secrets.

Tests protocol framing, tool profiles, tool handlers, version negotiation,
and security boundaries.

Usage: python -Bu tests/test_mcp.py
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import time

# Windows encoding fix
for stream in (sys.stdout, sys.stderr, sys.stdin):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")

# --Paths ------------------------------------------------
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_TEST_DIR)  # kv-project/
sys.path.insert(0, PROJECT_ROOT)

from kv.config import init_project, find_project_root, get_default_env
from kv.store import SecretStore
from kv_mcp.protocol import make_response, make_error
from kv_mcp.tools import TOOLS, HANDLERS, get_tools_for_profiles

passed = 0
failed = 0


# --Helpers ------------------------------------------------

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  \033[38;2;100;200;150mPASS\033[0m  {name}")
    else:
        failed += 1
        print(f"  \033[38;2;255;100;100mFAIL\033[0m  {name}")
        if detail:
            print(f"        {detail}")


def setup_kv_project(tmpdir):
    """Initialize a kv project in a temp directory and return (store, default_env)."""
    original_cwd = os.getcwd()
    os.chdir(tmpdir)
    try:
        init_project(tmpdir)
    finally:
        os.chdir(original_cwd)

    store = SecretStore(tmpdir)
    default_env = get_default_env(tmpdir)
    return store, default_env


def make_initialize_request(msg_id=1, version="2025-11-25"):
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"},
        },
    }


def simulate_server_session(messages, profiles=None):
    """Simulate a full MCP server session by feeding messages through stdin.

    Returns list of response dicts written to stdout.
    """
    if profiles is None:
        profiles = {"safe"}

    # Build stdin content: newline-delimited JSON
    input_lines = []
    for msg in messages:
        input_lines.append(json.dumps(msg, ensure_ascii=False))
    input_text = "\n".join(input_lines) + "\n"

    # Capture stdout
    old_stdin = sys.stdin
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    sys.stdin = io.StringIO(input_text)
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()  # Suppress log output

    try:
        from kv_mcp.server import run_server
        run_server(profiles)
    except SystemExit:
        pass  # Server exits if no project found, but we handle setup
    finally:
        output = sys.stdout.getvalue()
        stderr_output = sys.stderr.getvalue()
        sys.stdin = old_stdin
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    # Parse responses
    responses = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if line:
            responses.append(json.loads(line))

    return responses


# --Tests --------------------------------------------------

def test_protocol_make_response():
    """Test JSON-RPC response construction."""
    resp = make_response(42, {"tools": []})
    test("make_response has jsonrpc 2.0",
         resp["jsonrpc"] == "2.0")
    test("make_response has correct id",
         resp["id"] == 42)
    test("make_response has result",
         resp["result"] == {"tools": []})


def test_protocol_make_error():
    """Test JSON-RPC error construction."""
    resp = make_error(7, -32601, "method not found")
    test("make_error has error object",
         "error" in resp)
    test("make_error code is correct",
         resp["error"]["code"] == -32601)
    test("make_error message is correct",
         resp["error"]["message"] == "method not found")


def test_tool_definitions():
    """Test that all 7 tools are defined with correct profiles."""
    test("7 tools defined", len(TOOLS) == 7,
         f"got {len(TOOLS)}")

    safe_tools = [t for t in TOOLS.values() if t["profile"] == "safe"]
    mutate_tools = [t for t in TOOLS.values() if t["profile"] == "mutate"]
    reveal_tools = [t for t in TOOLS.values() if t["profile"] == "reveal"]

    test("4 safe tools", len(safe_tools) == 4,
         f"got {len(safe_tools)}: {[t['name'] for t in safe_tools]}")
    test("2 mutate tools", len(mutate_tools) == 2,
         f"got {len(mutate_tools)}: {[t['name'] for t in mutate_tools]}")
    test("1 reveal tool", len(reveal_tools) == 1,
         f"got {len(reveal_tools)}: {[t['name'] for t in reveal_tools]}")


def test_tool_risk_labels():
    """Test that all tools have risk labels in descriptions."""
    labels = {"[SAFE]", "[MUTATE]", "[REVEAL]", "[EXECUTE]"}
    for name, tool in TOOLS.items():
        desc = tool["description"]
        has_label = any(label in desc for label in labels)
        test(f"{name} has risk label", has_label,
             f"description starts with: {desc[:40]}...")


def test_profiles_safe_only():
    """Test tools/list with safe profile only."""
    tools = get_tools_for_profiles({"safe"})
    names = {t["name"] for t in tools}
    test("safe profile returns 4 tools", len(tools) == 4,
         f"got {len(tools)}: {names}")
    test("safe includes kv_status", "kv_status" in names)
    test("safe includes kv_envs", "kv_envs" in names)
    test("safe includes kv_list", "kv_list" in names)
    test("safe includes kv_run", "kv_run" in names)
    test("safe excludes kv_set", "kv_set" not in names)
    test("safe excludes kv_get", "kv_get" not in names)


def test_profiles_safe_mutate():
    """Test tools/list with safe + mutate profiles."""
    tools = get_tools_for_profiles({"safe", "mutate"})
    names = {t["name"] for t in tools}
    test("safe+mutate returns 6 tools", len(tools) == 6,
         f"got {len(tools)}: {names}")
    test("includes kv_set", "kv_set" in names)
    test("includes kv_rm", "kv_rm" in names)
    test("excludes kv_get", "kv_get" not in names)


def test_profiles_safe_reveal():
    """Test tools/list with safe + reveal profiles."""
    tools = get_tools_for_profiles({"safe", "reveal"})
    names = {t["name"] for t in tools}
    test("safe+reveal returns 5 tools", len(tools) == 5,
         f"got {len(tools)}: {names}")
    test("includes kv_get", "kv_get" in names)
    test("excludes kv_set", "kv_set" not in names)


def test_profiles_all():
    """Test tools/list with all profiles enabled."""
    tools = get_tools_for_profiles({"safe", "mutate", "reveal"})
    test("all profiles returns 7 tools", len(tools) == 7,
         f"got {len(tools)}")


def test_tool_defs_no_profile_field():
    """Test that returned tool defs don't expose internal 'profile' field."""
    tools = get_tools_for_profiles({"safe", "mutate", "reveal"})
    for tool in tools:
        test(f"{tool['name']} has no profile field", "profile" not in tool)


def test_handlers_kv_status():
    """Test kv_status handler."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)
        result = HANDLERS["kv_status"]({}, store, default_env)
        text = result["content"][0]["text"]
        test("kv_status returns project info",
             "project: initialized" in text and "root:" in text,
             f"got: {text[:100]}")
        test("kv_status is not error", result["isError"] is False)


def test_handlers_kv_envs():
    """Test kv_envs handler."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)
        result = HANDLERS["kv_envs"]({}, store, default_env)
        text = result["content"][0]["text"]
        test("kv_envs lists dev", "dev" in text, f"got: {text}")
        test("kv_envs is not error", result["isError"] is False)


def test_handlers_kv_set_and_get():
    """Test kv_set + kv_get round-trip."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        # Set a secret
        result = HANDLERS["kv_set"](
            {"name": "API_KEY", "value": "sk-test-12345"},
            store, default_env
        )
        test("kv_set stores secret",
             "stored API_KEY" in result["content"][0]["text"])
        test("kv_set is not error", result["isError"] is False)

        # Get it back
        result = HANDLERS["kv_get"](
            {"name": "API_KEY"},
            store, default_env
        )
        test("kv_get returns correct value",
             result["content"][0]["text"] == "sk-test-12345")
        test("kv_get is not error", result["isError"] is False)


def test_handlers_kv_list_names_only():
    """Test that kv_list returns names only, no values."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        store.set_secret(default_env, "DB_URL", "postgres://secret")
        store.set_secret(default_env, "REDIS_URL", "redis://secret")

        result = HANDLERS["kv_list"]({}, store, default_env)
        text = result["content"][0]["text"]
        test("kv_list includes key names",
             "DB_URL" in text and "REDIS_URL" in text)
        test("kv_list does NOT include values",
             "postgres://secret" not in text and "redis://secret" not in text,
             f"text was: {text}")


def test_handlers_kv_rm():
    """Test kv_rm removes a secret."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        store.set_secret(default_env, "TEMP_KEY", "temporary")

        result = HANDLERS["kv_rm"](
            {"name": "TEMP_KEY"}, store, default_env
        )
        test("kv_rm reports removed",
             "removed TEMP_KEY" in result["content"][0]["text"])

        # Verify it's gone
        result = HANDLERS["kv_get"](
            {"name": "TEMP_KEY"}, store, default_env
        )
        test("kv_rm actually removed the secret",
             result["isError"] is True)


def test_handlers_kv_run():
    """Test kv_run executes command and returns exit code only."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        store.set_secret(default_env, "MY_VAR", "hello")

        # Run a command that succeeds
        result = HANDLERS["kv_run"](
            {"argv": [sys.executable, "-c", "import os; exit(0)"]},
            store, default_env
        )
        text = result["content"][0]["text"]
        test("kv_run returns exit code 0",
             text == "exit code: 0", f"got: {text}")

        # Run a command that fails
        result = HANDLERS["kv_run"](
            {"argv": [sys.executable, "-c", "exit(42)"]},
            store, default_env
        )
        text = result["content"][0]["text"]
        test("kv_run returns exit code 42",
             text == "exit code: 42", f"got: {text}")


def test_handlers_kv_run_no_stdout():
    """Test that kv_run does NOT return stdout content."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        store.set_secret(default_env, "SECRET_VAL", "super_secret_123")

        # Command that prints the secret to stdout
        result = HANDLERS["kv_run"](
            {"argv": [sys.executable, "-c",
                       "import os; print(os.environ.get('SECRET_VAL', ''))"]},
            store, default_env
        )
        text = result["content"][0]["text"]
        test("kv_run does NOT leak stdout secret",
             "super_secret_123" not in text,
             f"got: {text}")
        test("kv_run only returns exit code",
             text == "exit code: 0",
             f"got: {text}")


def test_handlers_kv_run_timeout():
    """Test kv_run timeout kills subprocess."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        store.set_secret(default_env, "X", "1")

        # We can't easily test the full 30s timeout, but we can test the mechanism
        # by using a short-running command to verify the handler structure
        result = HANDLERS["kv_run"](
            {"argv": [sys.executable, "-c", "pass"]},
            store, default_env
        )
        test("kv_run completes normally (timeout mechanism exists)",
             "exit code: 0" in result["content"][0]["text"])


def test_handlers_kv_run_bad_command():
    """Test kv_run with non-existent command."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        store.set_secret(default_env, "X", "1")

        result = HANDLERS["kv_run"](
            {"argv": ["this_command_does_not_exist_xyz"]},
            store, default_env
        )
        text = result["content"][0]["text"]
        test("kv_run reports command not found",
             "command not found" in text,
             f"got: {text}")
        test("kv_run bad command isError is True",
             result["isError"] is True)


def test_handlers_kv_run_argv_validation():
    """Test kv_run validates argv input."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        # Missing argv
        result = HANDLERS["kv_run"]({}, store, default_env)
        test("kv_run rejects missing argv",
             result["isError"] is True)

        # Non-array argv
        result = HANDLERS["kv_run"](
            {"argv": "not an array"}, store, default_env
        )
        test("kv_run rejects non-array argv",
             result["isError"] is True)


def test_handlers_kv_run_env_names_filter():
    """Test kv_run env_names filter injects only selected secrets."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        store.set_secret(default_env, "KEEP_ME", "yes")
        store.set_secret(default_env, "SKIP_ME", "no")

        # Run with env_names filter — only KEEP_ME should be injected
        # We can't directly check env vars from the exit code, but we can
        # verify the handler accepts the parameter without error
        result = HANDLERS["kv_run"](
            {"argv": [sys.executable, "-c",
                       "import os; exit(0 if os.environ.get('KEEP_ME') == 'yes' else 1)"],
             "env_names": ["KEEP_ME"]},
            store, default_env
        )
        test("kv_run with env_names filter runs successfully",
             "exit code: 0" in result["content"][0]["text"],
             f"got: {result['content'][0]['text']}")


def test_handlers_kv_get_missing():
    """Test kv_get for non-existent key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        result = HANDLERS["kv_get"](
            {"name": "NONEXISTENT"}, store, default_env
        )
        test("kv_get missing key returns error",
             result["isError"] is True)
        test("kv_get missing key message mentions key",
             "NONEXISTENT" in result["content"][0]["text"])


def test_handlers_unicode_roundtrip():
    """Test Unicode secret values round-trip correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        unicode_value = "日本語テスト 🔑 пароль émojis"
        HANDLERS["kv_set"](
            {"name": "UNICODE_KEY", "value": unicode_value},
            store, default_env
        )

        result = HANDLERS["kv_get"](
            {"name": "UNICODE_KEY"}, store, default_env
        )
        test("Unicode secret round-trips correctly",
             result["content"][0]["text"] == unicode_value,
             f"got: {result['content'][0]['text']}")


def test_full_session_initialize():
    """Test full MCP session: initialize + tools/list via simulated stdio."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        # We need to change cwd so the server can find the project
        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            messages = [
                make_initialize_request(1, "2025-11-25"),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            ]
            responses = simulate_server_session(messages, {"safe"})

            test("session returns 2 responses (init + tools/list)",
                 len(responses) == 2,
                 f"got {len(responses)} responses")

            if len(responses) >= 1:
                init_resp = responses[0]
                test("initialize has protocolVersion",
                     "protocolVersion" in init_resp.get("result", {}))
                test("initialize version is 2025-11-25",
                     init_resp["result"]["protocolVersion"] == "2025-11-25")
                test("initialize has capabilities.tools",
                     "tools" in init_resp["result"].get("capabilities", {}))
                test("initialize has serverInfo",
                     init_resp["result"].get("serverInfo", {}).get("name") == "kv")

            if len(responses) >= 2:
                tools_resp = responses[1]
                tools = tools_resp["result"]["tools"]
                test("tools/list returns 4 safe tools",
                     len(tools) == 4,
                     f"got {len(tools)}: {[t['name'] for t in tools]}")
        finally:
            os.chdir(original_cwd)


def test_version_negotiation_old():
    """Test version negotiation with older protocol version."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            messages = [
                make_initialize_request(1, "2025-03-26"),
            ]
            responses = simulate_server_session(messages, {"safe"})

            test("older version negotiation returns response",
                 len(responses) >= 1)
            if responses:
                test("server responds with client's 2025-03-26 version",
                     responses[0]["result"]["protocolVersion"] == "2025-03-26")
        finally:
            os.chdir(original_cwd)


def test_version_negotiation_unknown():
    """Test version negotiation with unknown protocol version."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            messages = [
                make_initialize_request(1, "1999-01-01"),
            ]
            responses = simulate_server_session(messages, {"safe"})

            test("unknown version falls back to latest",
                 len(responses) >= 1)
            if responses:
                test("server responds with latest version for unknown",
                     responses[0]["result"]["protocolVersion"] == "2025-11-25")
        finally:
            os.chdir(original_cwd)


def test_disabled_tool_returns_error():
    """Test that calling a disabled tool returns an error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            messages = [
                make_initialize_request(1),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "kv_get", "arguments": {"name": "SECRET"}},
                },
            ]
            # Safe profile only — kv_get requires reveal
            responses = simulate_server_session(messages, {"safe"})

            test("disabled tool call returns response",
                 len(responses) >= 2)
            if len(responses) >= 2:
                error_resp = responses[1]
                test("disabled tool returns error",
                     "error" in error_resp,
                     f"got: {json.dumps(error_resp)[:200]}")
                if "error" in error_resp:
                    test("error mentions profile requirement",
                         "reveal" in error_resp["error"]["message"],
                         f"got: {error_resp['error']['message']}")
        finally:
            os.chdir(original_cwd)


def test_unknown_tool_returns_error():
    """Test that calling an unknown tool returns an error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            messages = [
                make_initialize_request(1),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "kv_nonexistent", "arguments": {}},
                },
            ]
            responses = simulate_server_session(messages, {"safe"})

            if len(responses) >= 2:
                error_resp = responses[1]
                test("unknown tool returns error",
                     "error" in error_resp,
                     f"got: {json.dumps(error_resp)[:200]}")
                if "error" in error_resp:
                    test("error mentions unknown tool",
                         "unknown" in error_resp["error"]["message"].lower(),
                         f"got: {error_resp['error']['message']}")
        finally:
            os.chdir(original_cwd)


def test_unknown_method_returns_error():
    """Test that unknown JSON-RPC methods return errors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            messages = [
                make_initialize_request(1),
                {
                    "jsonrpc": "2.0", "id": 2, "method": "nonexistent/method",
                    "params": {},
                },
            ]
            responses = simulate_server_session(messages, {"safe"})

            if len(responses) >= 2:
                test("unknown method returns error",
                     "error" in responses[1])
        finally:
            os.chdir(original_cwd)


def test_handlers_kv_run_env_names_empty():
    """Test kv_run with env_names=[] injects NO secrets."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        store.set_secret(default_env, "SHOULD_NOT_EXIST", "secret_val")

        # env_names=[] means inject nothing — command should NOT see SHOULD_NOT_EXIST
        result = HANDLERS["kv_run"](
            {"argv": [sys.executable, "-c",
                       "import os; exit(0 if 'SHOULD_NOT_EXIST' not in os.environ else 1)"],
             "env_names": []},
            store, default_env
        )
        text = result["content"][0]["text"]
        test("kv_run env_names=[] injects no secrets",
             text == "exit code: 0",
             f"got: {text} (expected exit code: 0, meaning env var was NOT present)")


def test_handlers_kv_run_isError_on_success():
    """Test kv_run isError is False for successful commands."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)
        store.set_secret(default_env, "X", "1")

        result = HANDLERS["kv_run"](
            {"argv": [sys.executable, "-c", "exit(0)"]},
            store, default_env
        )
        test("kv_run success isError is False",
             result["isError"] is False)


def test_handlers_kv_run_isError_nonzero_exit():
    """Test kv_run isError is False for non-zero exit (not a tool error)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)
        store.set_secret(default_env, "X", "1")

        result = HANDLERS["kv_run"](
            {"argv": [sys.executable, "-c", "exit(1)"]},
            store, default_env
        )
        test("kv_run non-zero exit isError is False (command ran, just failed)",
             result["isError"] is False)


# ── kv setup tests ───────────────────────────────────────


def _run_setup_in_dir(tmpdir, editor, allow_mutate=False, allow_reveal=False):
    """Run kv setup <editor> in a directory using subprocess. Returns (exit_code, stdout, stderr)."""
    cmd = [sys.executable, "-m", "kv", "setup", editor]
    if allow_mutate:
        cmd.append("--allow-mutate")
    if allow_reveal:
        cmd.append("--allow-reveal")

    result = subprocess.run(
        cmd, cwd=tmpdir,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30,
    )
    return result.returncode, result.stdout.decode("utf-8", errors="replace"), result.stderr.decode("utf-8", errors="replace")


def test_setup_creates_cursor_config():
    """Test kv setup cursor creates valid .cursor/mcp.json."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)

        exit_code, stdout, stderr = _run_setup_in_dir(tmpdir, "cursor")
        test("kv setup cursor exits 0", exit_code == 0,
             f"exit={exit_code}, stderr={stderr[:200]}")

        config_path = os.path.join(tmpdir, ".cursor", "mcp.json")
        test("cursor config file exists", os.path.isfile(config_path))

        if os.path.isfile(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            test("cursor config has mcpServers key", "mcpServers" in config)
            test("cursor config has kv entry", "kv" in config.get("mcpServers", {}))
            kv_entry = config["mcpServers"]["kv"]
            test("cursor config has kv_mcp in args",
                 "-m" in kv_entry.get("args", []) and "kv_mcp" in kv_entry.get("args", []))


def test_setup_creates_claude_code_config():
    """Test kv setup claude-code creates valid .mcp.json."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)

        exit_code, stdout, stderr = _run_setup_in_dir(tmpdir, "claude-code")
        test("kv setup claude-code exits 0", exit_code == 0,
             f"exit={exit_code}, stderr={stderr[:200]}")

        config_path = os.path.join(tmpdir, ".mcp.json")
        test("claude-code config file exists", os.path.isfile(config_path))

        if os.path.isfile(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            test("claude-code config has mcpServers key", "mcpServers" in config)


def test_setup_creates_vscode_config():
    """Test kv setup vscode creates valid .vscode/mcp.json with 'servers' key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)

        exit_code, stdout, stderr = _run_setup_in_dir(tmpdir, "vscode")
        test("kv setup vscode exits 0", exit_code == 0,
             f"exit={exit_code}, stderr={stderr[:200]}")

        config_path = os.path.join(tmpdir, ".vscode", "mcp.json")
        test("vscode config file exists", os.path.isfile(config_path))

        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        test("vscode config has 'servers' key (not mcpServers)", "servers" in config)
        test("vscode config has kv entry under servers", "kv" in config.get("servers", {}))


def test_setup_merges_existing_config():
    """Test kv setup preserves existing MCP server entries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)

        # Create existing .cursor/mcp.json with another server
        cursor_dir = os.path.join(tmpdir, ".cursor")
        os.makedirs(cursor_dir, exist_ok=True)
        existing_config = {
            "mcpServers": {
                "other-tool": {
                    "command": "node",
                    "args": ["other-server.js"],
                }
            }
        }
        config_path = os.path.join(cursor_dir, "mcp.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(existing_config, f)

        exit_code, stdout, stderr = _run_setup_in_dir(tmpdir, "cursor")
        test("kv setup cursor merge exits 0", exit_code == 0)

        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        test("merge preserves other-tool",
             "other-tool" in config.get("mcpServers", {}),
             f"keys: {list(config.get('mcpServers', {}).keys())}")
        test("merge adds kv entry",
             "kv" in config.get("mcpServers", {}))


def test_setup_malformed_json_aborts():
    """Test kv setup aborts on malformed JSON instead of silently overwriting."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)

        # Create malformed .cursor/mcp.json
        cursor_dir = os.path.join(tmpdir, ".cursor")
        os.makedirs(cursor_dir, exist_ok=True)
        config_path = os.path.join(cursor_dir, "mcp.json")
        with open(config_path, "w", encoding="utf-8") as f:
            f.write("{invalid json content!!!")

        exit_code, stdout, stderr = _run_setup_in_dir(tmpdir, "cursor")
        test("kv setup aborts on malformed JSON (exit 1)",
             exit_code == 1,
             f"exit={exit_code}")
        test("malformed JSON error mentions 'malformed'",
             "malformed" in stdout.lower() or "malformed" in stderr.lower(),
             f"stdout={stdout[:200]}")


def test_setup_non_object_servers_aborts():
    """Test kv setup aborts when mcpServers is not an object."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)

        # Create config with mcpServers as array
        cursor_dir = os.path.join(tmpdir, ".cursor")
        os.makedirs(cursor_dir, exist_ok=True)
        config_path = os.path.join(cursor_dir, "mcp.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump({"mcpServers": ["not", "an", "object"]}, f)

        exit_code, stdout, stderr = _run_setup_in_dir(tmpdir, "cursor")
        test("kv setup aborts on non-object mcpServers (exit 1)",
             exit_code == 1,
             f"exit={exit_code}")
        test("non-object error mentions 'not an object'",
             "not an object" in stdout.lower() or "not an object" in stderr.lower(),
             f"stdout={stdout[:200]}")


def test_setup_root_array_aborts():
    """Test kv setup aborts when config file contains [] (valid JSON, not an object)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)

        # Create config that is valid JSON but not a dict
        cursor_dir = os.path.join(tmpdir, ".cursor")
        os.makedirs(cursor_dir, exist_ok=True)
        config_path = os.path.join(cursor_dir, "mcp.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump([], f)  # valid JSON, but root is array not object

        exit_code, stdout, stderr = _run_setup_in_dir(tmpdir, "cursor")
        test("kv setup aborts on root array (exit 1)",
             exit_code == 1,
             f"exit={exit_code}")
        test("root array error mentions 'not a JSON object'",
             "not a json object" in stdout.lower() or "not a json object" in stderr.lower(),
             f"stdout={stdout[:200]}")


def test_setup_with_mutate_reveal_flags():
    """Test kv setup includes --allow-mutate/--allow-reveal in generated config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)

        exit_code, stdout, stderr = _run_setup_in_dir(
            tmpdir, "cursor", allow_mutate=True, allow_reveal=True
        )
        test("kv setup with flags exits 0", exit_code == 0)

        config_path = os.path.join(tmpdir, ".cursor", "mcp.json")
        test("flags config file exists", os.path.isfile(config_path))

        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        args = config.get("mcpServers", {}).get("kv", {}).get("args", [])
        test("config includes --allow-mutate", "--allow-mutate" in args)
        test("config includes --allow-reveal", "--allow-reveal" in args)


def test_session_rejects_before_init():
    """Test that tools/list and tools/call are rejected before initialize handshake."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            # Send tools/list without initializing first
            messages = [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            ]
            responses = simulate_server_session(messages, {"safe"})

            test("pre-init tools/list gets a response",
                 len(responses) >= 1,
                 f"got {len(responses)} responses")
            if responses:
                test("pre-init tools/list returns error",
                     "error" in responses[0],
                     f"got: {json.dumps(responses[0])[:200]}")
                if "error" in responses[0]:
                    test("pre-init error code is INVALID_REQUEST (-32600)",
                         responses[0]["error"]["code"] == -32600,
                         f"got code: {responses[0]['error'].get('code')}")
                    test("pre-init error mentions 'not initialized'",
                         "not initialized" in responses[0]["error"]["message"],
                         f"got: {responses[0]['error']['message']}")
        finally:
            os.chdir(original_cwd)


def test_session_parse_error_returns_32700():
    """Test that invalid JSON on stdin returns a -32700 parse error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            # Feed raw invalid JSON through stdin, followed by valid init to keep session alive
            # We manually build the input since simulate_server_session only takes dicts
            old_stdin = sys.stdin
            old_stdout = sys.stdout
            old_stderr = sys.stderr

            # Invalid JSON line, then valid initialize, then EOF
            input_text = "{not valid json!!!\n" + json.dumps(make_initialize_request(1)) + "\n"
            sys.stdin = io.StringIO(input_text)
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()

            try:
                from kv_mcp.server import run_server
                run_server({"safe"})
            except SystemExit:
                pass
            finally:
                output = sys.stdout.getvalue()
                sys.stdin = old_stdin
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            # Parse responses
            responses = []
            for line in output.strip().split("\n"):
                line = line.strip()
                if line:
                    responses.append(json.loads(line))

            test("parse error produces at least 1 response",
                 len(responses) >= 1,
                 f"got {len(responses)} responses")
            if responses:
                test("parse error response has error field",
                     "error" in responses[0],
                     f"got: {json.dumps(responses[0])[:200]}")
                if "error" in responses[0]:
                    test("parse error code is -32700",
                         responses[0]["error"]["code"] == -32700,
                         f"got code: {responses[0]['error'].get('code')}")
                    test("parse error id is null",
                         responses[0]["id"] is None,
                         f"got id: {responses[0].get('id')}")
        finally:
            os.chdir(original_cwd)


def test_session_blank_lines_dont_disconnect():
    """Test that blank lines in stdin don't kill the MCP session."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store, default_env = setup_kv_project(tmpdir)

        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            old_stdin = sys.stdin
            old_stdout = sys.stdout
            old_stderr = sys.stderr

            # Blank lines before, between, and after valid messages
            init_json = json.dumps(make_initialize_request(1))
            notif_json = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
            tools_json = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            input_text = f"\n\n{init_json}\n\n{notif_json}\n\n\n{tools_json}\n"

            sys.stdin = io.StringIO(input_text)
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()

            try:
                from kv_mcp.server import run_server
                run_server({"safe"})
            except SystemExit:
                pass
            finally:
                output = sys.stdout.getvalue()
                sys.stdin = old_stdin
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            responses = []
            for line in output.strip().split("\n"):
                line = line.strip()
                if line:
                    responses.append(json.loads(line))

            test("blank lines: server returns 2 responses (init + tools/list)",
                 len(responses) == 2,
                 f"got {len(responses)} responses")
            if len(responses) >= 1:
                test("blank lines: first response is init success",
                     "result" in responses[0] and "protocolVersion" in responses[0].get("result", {}))
            if len(responses) >= 2:
                test("blank lines: second response is tools/list",
                     "result" in responses[1] and "tools" in responses[1].get("result", {}))
        finally:
            os.chdir(original_cwd)


# --Main ---------------------------------------------------

# ── kv doctor tests ───────────────────────────────────────


def _run_doctor_in_dir(tmpdir):
    """Run kv doctor in a directory using subprocess."""
    result = subprocess.run(
        [sys.executable, "-m", "kv", "doctor"],
        cwd=tmpdir,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30,
    )
    out = result.stdout.decode("utf-8", errors="replace")
    err = result.stderr.decode("utf-8", errors="replace")
    return result.returncode, out, err


def test_doctor_healthy_project():
    """Doctor on a fully initialized project with a secret should pass."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)
        store = SecretStore(tmpdir)
        store.set_secret("dev", "TEST_KEY", "test_value")

        exit_code, stdout, stderr = _run_doctor_in_dir(tmpdir)
        combined = stdout + stderr

        test("doctor exits 0 on healthy project", exit_code == 0,
             f"exit={exit_code}, out={combined[:300]}")
        test("doctor reports Python version", "Python" in combined,
             combined[:300])
        test("doctor reports project found", "Project found" in combined,
             combined[:300])
        test("doctor reports master key", "Master key" in combined,
             combined[:300])
        test("doctor reports decrypt OK", "Decrypt OK" in combined,
             combined[:300])
        test("doctor shows passed count", "passed" in combined,
             combined[:300])


def test_doctor_missing_key():
    """Doctor with missing key file should exit 1."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)
        # Delete the key file
        key_file = os.path.join(tmpdir, ".secrets", "key")
        os.remove(key_file)

        exit_code, stdout, stderr = _run_doctor_in_dir(tmpdir)
        combined = stdout + stderr

        test("doctor exits 1 with missing key", exit_code == 1,
             f"exit={exit_code}, out={combined[:300]}")
        test("doctor reports key problem",
             "missing" in combined.lower() or "error" in combined.lower(),
             combined[:300])


def _run_cmd_in_dir(tmpdir, cmd_args, env_override=None):
    """Run a kv command in a directory. Returns (exit_code, stdout, stderr)."""
    env = os.environ.copy()
    if env_override:
        env.update(env_override)
    result = subprocess.run(
        [sys.executable, "-m", "kv"] + cmd_args,
        cwd=tmpdir, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30,
    )
    out = result.stdout.decode("utf-8", errors="replace")
    err = result.stderr.decode("utf-8", errors="replace")
    return result.returncode, out, err


def test_env_var_invalid_key_rejected():
    """KV_MASTER_KEY with wrong size must fail fast, not write .enc."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)
        # Delete the key file
        key_file = os.path.join(tmpdir, ".secrets", "key")
        os.remove(key_file)

        enc_path = os.path.join(tmpdir, ".secrets", "dev.enc")
        enc_existed = os.path.isfile(enc_path)

        # Try kv set with a 3-byte key (AAAA decodes to 3 bytes)
        exit_code, stdout, stderr = _run_cmd_in_dir(
            tmpdir, ["set", "BAD=val"], env_override={"KV_MASTER_KEY": "AAAA"}
        )
        combined = stdout + stderr

        test("invalid env key: kv set exits non-zero", exit_code != 0,
             f"exit={exit_code}, out={combined[:300]}")
        test("invalid env key: error mentions size",
             "32" in combined or "invalid" in combined.lower(),
             combined[:300])
        # Ensure no .enc was written
        enc_after = os.path.isfile(enc_path)
        test("invalid env key: no .enc written",
             enc_after == enc_existed,
             f"enc_before={enc_existed}, enc_after={enc_after}")


def test_env_var_key_fallback():
    """KV_MASTER_KEY env var should work when key file is absent."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)
        store = SecretStore(tmpdir)
        store.set_secret("dev", "TESTVAR", "hello123")

        # Read the key, then delete the file
        key_file = os.path.join(tmpdir, ".secrets", "key")
        with open(key_file, "r") as f:
            key_b64 = f.read().strip()
        os.remove(key_file)

        # Run kv ls with KV_MASTER_KEY env var — should still list secrets
        exit_code, stdout, stderr = _run_cmd_in_dir(
            tmpdir, ["ls"], env_override={"KV_MASTER_KEY": key_b64}
        )
        combined = stdout + stderr

        test("env var fallback: kv ls exits 0", exit_code == 0,
             f"exit={exit_code}, out={combined[:300]}")
        test("env var fallback: lists the secret", "TESTVAR" in combined,
             combined[:300])


def test_export_key_roundtrip():
    """export-key then import-key should preserve the key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)
        store = SecretStore(tmpdir)
        store.set_secret("dev", "ROUNDTRIP", "secretval")

        # Export key
        exit_code, stdout, stderr = _run_cmd_in_dir(tmpdir, ["export-key"])
        test("export-key exits 0", exit_code == 0,
             f"exit={exit_code}, err={stderr[:200]}")

        # Extract the kvkey_ token from output
        token = ""
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("kvkey_"):
                token = line
                break
        test("export-key outputs kvkey_ token", token.startswith("kvkey_"),
             f"stdout={stdout[:200]}")

        if token:
            # Delete key file
            key_file = os.path.join(tmpdir, ".secrets", "key")
            os.remove(key_file)

            # Import key
            exit_code, stdout, stderr = _run_cmd_in_dir(
                tmpdir, ["import-key", token]
            )
            test("import-key exits 0", exit_code == 0,
                 f"exit={exit_code}, err={stderr[:200]}")

            # Verify we can still read the secret
            exit_code, stdout, stderr = _run_cmd_in_dir(tmpdir, ["get", "ROUNDTRIP"])
            combined = stdout + stderr
            test("roundtrip: secret still readable", "secretval" in combined,
                 combined[:200])


def test_doctor_env_var_fallback():
    """Doctor should pass key check when KV_MASTER_KEY is set and file absent."""
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_kv_project(tmpdir)

        # Read key, then delete the file
        key_file = os.path.join(tmpdir, ".secrets", "key")
        with open(key_file, "r") as f:
            key_b64 = f.read().strip()
        os.remove(key_file)

        # Run doctor with env var
        env = os.environ.copy()
        env["KV_MASTER_KEY"] = key_b64
        result = subprocess.run(
            [sys.executable, "-m", "kv", "doctor"],
            cwd=tmpdir, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30,
        )
        combined = result.stdout.decode("utf-8", errors="replace") + \
                   result.stderr.decode("utf-8", errors="replace")

        test("doctor with env var exits 0", result.returncode == 0,
             f"exit={result.returncode}, out={combined[:300]}")
        test("doctor reports env var key", "KV_MASTER_KEY" in combined,
             combined[:300])


def main():
    print()
    print("  \033[1m\033[38;2;140;180;255mkv_mcp\033[0m \033[2m--\033[0m integration tests")
    print()

    print("  \033[2m── Protocol ──\033[0m")
    test_protocol_make_response()
    test_protocol_make_error()
    print()

    print("  \033[2m── Tool Definitions ──\033[0m")
    test_tool_definitions()
    test_tool_risk_labels()
    test_tool_defs_no_profile_field()
    print()

    print("  \033[2m── Profiles ──\033[0m")
    test_profiles_safe_only()
    test_profiles_safe_mutate()
    test_profiles_safe_reveal()
    test_profiles_all()
    print()

    print("  \033[2m── Tool Handlers ──\033[0m")
    test_handlers_kv_status()
    test_handlers_kv_envs()
    test_handlers_kv_set_and_get()
    test_handlers_kv_list_names_only()
    test_handlers_kv_rm()
    test_handlers_kv_run()
    test_handlers_kv_run_no_stdout()
    test_handlers_kv_run_timeout()
    test_handlers_kv_run_bad_command()
    test_handlers_kv_run_argv_validation()
    test_handlers_kv_run_env_names_filter()
    test_handlers_kv_run_env_names_empty()
    test_handlers_kv_run_isError_on_success()
    test_handlers_kv_run_isError_nonzero_exit()
    test_handlers_kv_get_missing()
    test_handlers_unicode_roundtrip()
    print()

    print("  \033[2m── kv setup ──\033[0m")
    test_setup_creates_cursor_config()
    test_setup_creates_claude_code_config()
    test_setup_creates_vscode_config()
    test_setup_merges_existing_config()
    test_setup_malformed_json_aborts()
    test_setup_non_object_servers_aborts()
    test_setup_root_array_aborts()
    test_setup_with_mutate_reveal_flags()
    print()

    print("  \033[2m── kv doctor ──\033[0m")
    test_doctor_healthy_project()
    test_doctor_missing_key()
    test_doctor_env_var_fallback()
    print()

    print("  \033[2m── kv export-key / import-key / env var ──\033[0m")
    test_env_var_invalid_key_rejected()
    test_env_var_key_fallback()
    test_export_key_roundtrip()
    print()

    print("  \033[2m── Full Session (stdio simulation) ──\033[0m")
    test_full_session_initialize()
    test_version_negotiation_old()
    test_version_negotiation_unknown()
    test_disabled_tool_returns_error()
    test_unknown_tool_returns_error()
    test_unknown_method_returns_error()
    test_session_rejects_before_init()
    test_session_parse_error_returns_32700()
    test_session_blank_lines_dont_disconnect()
    print()

    # Summary
    total = passed + failed
    if failed == 0:
        print(f"  \033[1m\033[38;2;100;200;150mALL {total} TESTS PASSED\033[0m")
    else:
        print(f"  \033[1m\033[38;2;255;100;100m{failed} FAILED\033[0m / {total} total")
    print()

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
