# kv_api — Build Tracker

## Goal

Build `kv_api` — an MCP tool and daemon command that makes HTTP API calls with credentials injected by the kv agent daemon. The agent never sees the API keys. The daemon IS the API client.

## Architecture

```
Agent (sandboxed or not)
  → calls kv_api(provider="openai", path="/v1/chat/completions", body={...})
  → MCP server forwards to kv agent daemon via Unix socket
  → daemon looks up OPENAI_API_KEY from memory
  → daemon makes HTTPS request with auth header injected
  → daemon returns response to agent
  → key never left daemon memory
```

## Chunks

### Chunk 1: Provider config
- [x] Create `kv/providers.py` — provider registry (base URLs, auth patterns, key names)
- [x] Support: openai, anthropic, google, github, google-cloud
- [x] Auth types: bearer header, x-api-key header, query param, basic
- [x] Tests: 16 passing (registry, auth injection, URL building, secret placement)

### Chunk 2: HTTP forwarding in daemon
- [x] Add `api` command to `kv/agent.py` socket handler
- [x] Build HTTP request from provider config + agent's request
- [x] Inject auth (header or query param based on provider)
- [x] Make HTTPS call using urllib (no new deps)
- [x] Return response body + status code (JSON parsed when possible)
- [x] Redact any secret values from response (defense-in-depth)
- [x] Error handling: HTTPError, URLError, timeout, generic exceptions
- [ ] Tests: mock HTTP responses, verify auth injection (deferred to after MCP tool)

### Chunk 3: MCP tool
- [x] Add `kv_api` tool definition to `kv_mcp/tools.py` (safe profile)
- [x] Add handler — daemon mode (delegates via socket) + direct mode (fallback)
- [x] Input: provider, path, method, body, headers, env
- [x] Output: status code + response body (JSON parsed, secrets redacted)
- [x] 104 tests passing (all existing + 16 provider tests)

### Chunk 4: CLI command (optional)
- [ ] Add `kv api` CLI command for human testing
- [ ] `kv api openai /v1/models` — quick test from terminal

### Chunk 5: Live test
- [x] Test with real OpenAI API call — `/v1/models` returned full model list (100+ models)
- [ ] Test with real Anthropic API call
- [x] Verify key never appears in agent context — confirmed
- [x] Verify key never appears in response — confirmed, clean JSON

### Chunk 6: kv_run exfiltration protection
- [x] Layer 1: command pattern validation (printenv >, env >, echo $, tee)
- [x] Layer 2: post-execution file scan (/tmp, ~, cwd) — top-level only
- [x] Layer 2 fix: recursive directory scan (max depth 3, cycle-safe)
- [x] Layer 2 fix: base64, urlsafe-b64, hex, reversed variant detection
- [ ] Known limitation: network exfiltration (requires OS egress control, can't fix in app)

### Chunk 7: PreToolUse hook — block reads of files created during kv_run
- [x] kv_run: track ALL new files created during execution in daemon memory
- [x] New daemon commands: `check_file` (single path check) + `tracked_files` (list all)
- [x] kv hook: `python3 -m kv.hook` reads PreToolUse JSON, checks tracked files via daemon
- [x] Hook blocks: cat, head, tail, less, more, Read tool → deny without prompt
- [ ] Register kv as PreToolUse hook in .claude/settings (needs user to configure)
- [ ] Live test: write encoded secret via kv_run → try to read via Bash → blocked

### Chunk 8: Commit + push
- [ ] Update BUILD.md with results
- [ ] Commit with descriptive message
- [ ] Push to GitHub

## Session Log

### 2026-03-21 — Session 1 (this session)
- Context: 43% used, 54% free
- Prior work: passphrase + TOTP + daemon + output redaction + security analysis
- Starting kv_api build after security research and architecture design

## Decision Log

| ID | Decision | Reasoning |
|----|----------|-----------|
| A-001 | urllib not httpx | Zero new deps. kv-secrets has only `cryptography`. urllib handles HTTPS fine. |
| A-002 | Non-streaming v1 | MCP is request-response. Streaming (SSE) needs different architecture. Full response returned. |
| A-003 | Provider config as code, not YAML | Simple dict. No parsing, no file I/O. Easy to extend. |
| A-004 | Response redaction | Defense-in-depth. Some APIs echo keys in error messages. |
