"""JSON-RPC 2.0 message framing for MCP stdio transport.

Messages are newline-delimited JSON on stdin/stdout.
stderr is free for logging (MCP spec compliant).
"""

import json
import sys


class ParseError(Exception):
    """Raised when stdin contains invalid JSON."""
    pass


def read_message():
    """Read one JSON-RPC message from stdin.

    Returns parsed dict, or None on EOF.
    Raises ParseError on invalid JSON (caller should return -32700).
    Skips blank lines (does not treat them as EOF).
    """
    while True:
        line = sys.stdin.readline()
        if not line:
            return None  # EOF — client closed stdin (readline returns "")
        line = line.strip()
        if not line:
            continue  # blank line — skip, keep reading
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            raise ParseError(str(exc))


def write_message(msg):
    """Write one JSON-RPC message to stdout.

    Serializes as compact JSON + newline, flushes immediately.
    """
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def make_response(msg_id, result):
    """Build a JSON-RPC 2.0 success response."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": result,
    }


def make_error(msg_id, code, message):
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def log(message):
    """Write a log message to stderr (MCP-compliant logging)."""
    sys.stderr.write(f"[kv_mcp] {message}\n")
    sys.stderr.flush()
