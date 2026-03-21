# kv-secrets — Complete Guide

## What is kv-secrets?

kv-secrets is an encrypted secret management tool built for the AI agent era. It stores API keys, tokens, and credentials encrypted on disk and provides controlled access to AI coding agents (Claude Code, Cursor, etc.) without ever revealing the actual secret values.

The core problem it solves: developers store secrets in plaintext `.env` files. AI agents with shell access can read those files instantly. kv-secrets encrypts secrets at rest and provides multiple layers of protection against unauthorized access — including access by the very AI agent helping you code.

### How it differs from .env files

```
.env file:
  OPENAI_API_KEY=sk-proj-xxxxx     ← plaintext on disk
  Agent runs: cat .env             ← all secrets exposed

kv-secrets:
  .secrets/dev.enc                 ← ChaCha20-Poly1305 encrypted binary
  .secrets/key                     ← master key wrapped with your passphrase
  Agent runs: cat .secrets/key     ← encrypted blob, useless
  Agent runs: kv get KEY           ← passphrase prompt, agent can't respond
```

---

## Architecture

### Encryption layers

```
Your passphrase (in your head, never on disk)
  │
  ├── PBKDF2-HMAC-SHA256 (600,000 iterations) + salt
  │     → wrapping key
  │         → ChaCha20-Poly1305 encrypts master key
  │             → stored as .secrets/key (binary, KVW\x01 header)
  │
  └── Master key (256-bit, random)
        │
        ├── BLAKE2b("dev")  → dev key  → encrypts .secrets/dev.enc
        ├── BLAKE2b("staging") → staging key → encrypts .secrets/staging.enc
        └── BLAKE2b("prod") → prod key → encrypts .secrets/prod.enc
```

Each environment gets its own derived key. Changing your passphrase re-wraps the master key only — encrypted secret files are untouched.

### Two-factor authentication (TOTP)

Optional but recommended. After setting a passphrase, you can add TOTP (Google Authenticator, Authy):

```
Passphrase (something you know) + TOTP code (something you have)
  → both required for every sensitive operation
  → TOTP secret stored in config.json, encrypted with your passphrase
  → QR code shown during setup for easy scanning
```

### File layout

```
your-project/
  .secrets/
    key              ← master key (wrapped with passphrase)
    config.json      ← settings, environment list, security config
    dev.enc          ← encrypted secrets for dev environment
    staging.enc      ← encrypted secrets for staging environment
    .gitignore       ← auto-generated, prevents key from being committed
```

### Three interfaces

| Interface | Who uses it | How it authenticates |
|-----------|------------|---------------------|
| **CLI** (`kv` command) | You, in your terminal | Passphrase + TOTP every command |
| **MCP server** | AI agents via Claude Code/Cursor | Connects to agent daemon (no prompt) |
| **Agent daemon** (`kv agent`) | Background process | Passphrase + TOTP once at startup |

---

## The Agent Daemon (ssh-agent model)

The daemon is the key piece that makes everything work together. Like `ssh-agent`, you unlock once and everything uses it:

```
Terminal 1 (you):
  $ kv agent
  Passphrase: ****
  TOTP code: 123456

  kv agent running (PID 12345)
  1 environment, 5 secrets loaded
  socket: /tmp/kv-agent/kv.sock

  Ctrl+C to stop

Terminal 2 (Claude Code):
  $ claude --resume
  → MCP server detects daemon via socket
  → no passphrase needed
  → agent uses kv_run, kv_list, kv_status, kv_api
  → secrets injected into subprocesses, never revealed
```

### How the daemon communicates

```
Agent daemon (holds secrets in RAM)
  ↕ Unix domain socket (/tmp/kv-agent/kv.sock, chmod 600)
  ↕
MCP server (kv_mcp) ←→ Claude Code ←→ AI agent
```

The AI agent calls MCP tools. The MCP server delegates to the daemon via socket. The daemon executes the operation (inject secrets, make API calls) and returns results with secret values redacted.

### What the daemon serves

| Command | What it does | Returns secrets? |
|---------|-------------|-----------------|
| `run` | Execute command with secrets as env vars | No — stdout/stderr redacted |
| `api` | Make HTTP API call with injected credentials | No — response redacted |
| `list` | List secret key names | No — names only |
| `envs` | List environment names | No |
| `status` | Show daemon status | No |
| `check_file` | Check if a file is tracked (created during kv_run) | No |
| `get` | N/A — command does not exist | Impossible |

There is no `get` command on the daemon. The agent cannot request secret values through any socket command.

---

## MCP Server (for AI agents)

The MCP server exposes 5 tools with security profiles:

### Safe profile (default — always enabled)

| Tool | What it does |
|------|-------------|
| `kv_status` | Show vault status, environment count, secret count |
| `kv_envs` | List environment names |
| `kv_list` | List secret key names (values masked) |
| `kv_run` | Run command with secrets injected, return redacted output |
| `kv_api` | Make API call with injected credentials, return response |

### Mutate profile (opt-in: `--allow-mutate`)

| Tool | What it does |
|------|-------------|
| `kv_set` | Store a new secret (encrypted) |
| `kv_rm` | Remove a secret |

### Reveal profile (opt-in: `--allow-reveal`)

| Tool | What it does |
|------|-------------|
| `kv_get` | Return secret value in plaintext (**WARNING: exposes to agent**) |

The safe profile is the default. The agent can use secrets (via `kv_run` and `kv_api`) without seeing them. `kv_get` requires explicit opt-in and is discouraged.

### kv_run — how secrets flow

```
Agent calls: kv_run(argv=["python3", "app.py"])

1. MCP server receives the call
2. Delegates to agent daemon via socket
3. Daemon checks for exfiltration patterns (blocks shell, inline code)
4. Daemon creates subprocess with secrets as env vars
5. Network isolation: subprocess runs in empty network namespace (Linux)
6. Subprocess executes, stdout/stderr captured
7. Daemon redacts any secret values from output
8. Daemon scans for leaked files, tracks new files
9. Redacted output returned to agent

Agent sees: "exit code: 0\nstdout:\nConnected to database successfully"
Agent never sees: "postgres://user:s3cr3t@host/db"
```

### kv_api — direct API calls without subprocess

```
Agent calls: kv_api(provider="openai", path="/v1/chat/completions", body={...})

1. MCP server delegates to daemon
2. Daemon looks up OPENAI_API_KEY from vault
3. Daemon makes HTTPS request with Authorization header
4. Response received, secret values redacted from response body
5. Response returned to agent

Agent sees: {"choices": [{"message": {"content": "Hello!"}}]}
Agent never sees: the API key used to make the call
```

Supported providers: openai, anthropic, google (Gemini). Each knows its auth mechanism (Bearer token, x-api-key header, query parameter).

---

## Setup Guide

### Step 1: Install

```bash
pip install kv-secrets

# For QR code display during 2FA setup (optional):
pip install kv-secrets[totp]
```

### Step 2: Initialize vault

```bash
kv init
```

You'll be prompted to set a passphrase. **Use a strong one** — the tool rejects common passwords (12345678, password, etc.). The passphrase is the only thing protecting your secrets.

```
  kv -- vault setup

  Set a passphrase to protect your master key.
  This prevents AI agents from reading secrets via shell access.
  Press Enter to skip (not recommended).

  Passphrase: ****
  Confirm:    ****

  kv -- initialized

  Master key   .secrets/key  (passphrase-protected)
  Environments: dev (default)
```

### Step 3: Set up 2FA (recommended)

```bash
kv setup-2fa
```

Scan the QR code with Google Authenticator or Authy. Enter the 6-digit code to verify.

```
  kv -- 2FA setup

  Passphrase: ****
  verified

  Scan this QR code with your authenticator app:
  [QR CODE]

  Or enter manually:
  Secret  ABCDEFGHIJKLMNOP

  Code:  123456

  2FA enabled -- passphrase + authenticator code required
```

### Step 4: Store your secrets

```bash
# Method 1: Key=Value (value visible in terminal)
kv set OPENAI_API_KEY=sk-proj-xxxxx

# Method 2: Prompt for value (hidden input — recommended)
kv set OPENAI_API_KEY
  Passphrase: ****
  TOTP code:  123456
  Value for OPENAI_API_KEY: ████████
  set OPENAI_API_KEY  (dev)  [encrypted]

# Method 3: Bulk import from .env file (one prompt for all)
kv import /path/to/secrets.env
# DELETE the .env file immediately after import
```

### Step 5: Configure MCP for Claude Code

```bash
kv setup claude-code
```

This writes `.mcp.json` in your project root. Claude Code reads it on startup.

### Step 6: Start the agent daemon

In a **separate terminal** (keep it running):

```bash
kv agent
  Passphrase: ****
  TOTP code:  123456

  kv agent running (PID 12345)
  1 environment, 5 secrets loaded
  Ctrl+C to stop
```

### Step 7: Start Claude Code

In another terminal:

```bash
claude
# or
claude --resume
```

The MCP server detects the daemon. No passphrase prompt. The agent can use `kv_run` and `kv_api` immediately.

### Daily workflow

```
Morning:
  Terminal 1: kv agent → passphrase + TOTP → running
  Terminal 2: claude → MCP connected → work all day

End of day:
  Terminal 1: Ctrl+C → daemon stops → secrets gone from memory
  Terminal 2: claude exits
```

One unlock per day. Zero passphrase prompts during work.

---

## Usage Guide

### CLI commands

| Command | What it does | Needs passphrase? |
|---------|-------------|-------------------|
| `kv init` | Initialize vault | Sets passphrase |
| `kv set KEY=VALUE` | Store a secret | Yes |
| `kv set KEY` | Store (hidden input) | Yes |
| `kv get KEY` | Read a secret | Yes |
| `kv ls` | List key names (masked) | Yes |
| `kv ls --reveal` | List with values | Yes |
| `kv rm KEY` | Delete a secret | Yes |
| `kv run CMD...` | Run with secrets injected | Yes |
| `kv import FILE` | Import from .env | Yes |
| `kv export` | Export as .env format | Yes |
| `kv envs` | List environments | No |
| `kv env create NAME` | Create environment | No |
| `kv env copy SRC DST` | Copy secrets between envs | Yes |
| `kv status` | Show vault status | No |
| `kv doctor` | Run diagnostics | No |
| `kv setup-2fa` | Enable TOTP | Yes |
| `kv upgrade-security` | Add passphrase to existing vault | Yes |
| `kv agent` | Start daemon | Yes (once) |
| `kv export-key` | Export master key for sharing | Yes |
| `kv import-key TOKEN` | Import shared master key | No |
| `kv setup EDITOR` | Configure MCP for editor | No |

### Using secrets in your code

Your code doesn't need to know about kv-secrets. It reads environment variables normally:

```python
# Python
import os
api_key = os.environ["OPENAI_API_KEY"]  # injected by kv_run
```

```javascript
// Node.js
const key = process.env.OPENAI_API_KEY;  // injected by kv_run
```

```bash
# Shell script
echo $OPENAI_API_KEY  # injected by kv_run
```

### Running your app

```bash
# Without kv (old way — key in shell history):
export OPENAI_API_KEY=sk-proj-xxxxx
python app.py

# With kv (key never in history):
kv run python app.py

# With daemon running (via MCP — agent does this):
kv_run(argv=["python3", "app.py"])
```

### Multiple environments

```bash
kv env create staging
kv set -e staging DATABASE_URL=postgres://staging-host/db
kv run -e staging python migrate.py
```

### CI/CD

Set `KV_MASTER_KEY` as a CI secret (base64url-encoded master key):

```yaml
# GitHub Actions
env:
  KV_MASTER_KEY: ${{ secrets.KV_MASTER_KEY }}
steps:
  - run: kv run python deploy.py
```

No passphrase needed in CI — `KV_MASTER_KEY` bypasses the on-disk key.

---

## Security: What We Built and Why

### The problem we discovered (2026-03-21)

During a code review session, the AI agent (Claude Opus 4.6) was asked to review kv-secrets. The agent ran:

```bash
kv ls --reveal
```

**Every secret in the vault was returned in plaintext.** The MCP security profiles (safe/mutate/reveal) were completely bypassed — the agent used the CLI directly via Bash, not the MCP channel.

The master key was also exposed:

```bash
cat .secrets/key    # base64url plaintext — game over
```

### What we built to fix it

| Layer | What it does | What it blocks |
|-------|-------------|---------------|
| **Passphrase wrapping** | Master key encrypted with PBKDF2 + ChaCha20-Poly1305 | `cat .secrets/key` → encrypted blob |
| **TOTP 2FA** | 6-digit code from authenticator app, changes every 30s | Even if passphrase is known, still need phone |
| **Password blocklist** | Rejects common passwords (12345678, password, etc.) | Brute-force with dictionary attack |
| **Agent daemon** | Holds secrets in RAM, serves via Unix socket | No secrets on disk during operation |
| **kv_api** | Direct API calls without subprocess env vars | Secrets never leave daemon process |
| **Shell/inline blocking** | Blocks bash -c, python3 -c in kv_run | Inline code that reads env vars |
| **Output redaction** | Strips secret values from stdout/stderr | Accidental secret exposure in logs |
| **Network isolation** | `unshare --user --net` on Linux | Subprocess can't exfiltrate via network |
| **File scan** | Post-execution recursive scan for leaked files | `printenv > /tmp/file` detected and deleted |
| **File tracking** | Tracks files created during kv_run | Subsequent reads of those files blocked by hook |
| **PreToolUse hook** | Blocks reads of tracked files + warns on suspicious patterns | `cat /tmp/leaked.txt`, `grep /tmp/tracked.bin` |
| **PostToolUse hook** | Scans Bash output for secret values, alerts user | Immediate notification if keys leak |

### Attack attempts and results

| Attack | Result | Layer that stopped it |
|--------|--------|----------------------|
| `kv ls --reveal` | **Blocked** | Passphrase prompt (agent can't respond) |
| `kv get ANTHROPIC_API_KEY` | **Blocked** | Passphrase + TOTP prompt |
| `cat .secrets/key` | **Useless** | Encrypted blob (KVW\x01 header) |
| `kv export` | **Blocked** | Passphrase prompt |
| Python import bypass (`SecretStore()`) | **Blocked** | VaultLockedError |
| Brute-force passphrase (12345678) | **Blocked** | Password blocklist (rejects common passwords) |
| `printenv` via kv_run | **Redacted** | Output redaction (`[REDACTED]`) |
| `echo $KEY` via kv_run | **Redacted** | Output redaction |
| `bash -c "..."` via kv_run | **Blocked** | Shell invocation blocking |
| `python3 -c "..."` via kv_run | **Blocked** | Inline code blocking |
| `printenv > /tmp/file` via kv_run | **Detected** | File scan, file deleted, tracked |
| `cat /tmp/tracked_file` | **Blocked** | PreToolUse hook |
| `grep /tmp/tracked_file` | **Blocked** | PreToolUse hook (all commands, not just cat) |
| `cp /tmp/tracked_file /tmp/copy` | **Blocked** | PreToolUse hook |
| `base64 /tmp/tracked_file` | **Blocked** | PreToolUse hook |
| Runtime path construction (`os.path.join(...)`) | **Blocked** | Keyword fragment matching |
| Base64-encoded path (`b64decode(...)`) | **Warning** | Encoding + file-access pattern detected |
| `printenv > /tmp/file` then read file outside kv_run | **Partially blocked** | File tracking + hook, but encoded paths can bypass |

### What's NOT protected (known limitations)

| Limitation | Why | Mitigation |
|-----------|-----|-----------|
| Agent constructs path via base64 encoding | Hook can't predict runtime behavior | Warning shown to user; PostToolUse detects leaked values |
| Subprocess writes secrets to file (kv_run) | Same-user filesystem access | File scan + tracking + hook, but exotic encodings may bypass |
| Agent reads process memory (ptrace) | Same-user on some systems | ptrace_scope=1 blocks on most Linux |
| Weak passphrase | No crypto protects bad passwords | Blocklist rejects common ones |
| User pastes secrets into chat | Operational error | QR code for TOTP; user education |
| API keys in bash history (from before kv) | Pre-kv usage | `history -c && > ~/.bash_history` |

### The fundamental principle

**Same-user, same-machine security is advisory, not containment.** Any process running as the same user can potentially access what any other process can access. kv-secrets raises the bar from "trivial" (one command) to "impractical for normal behavior" (multi-step adversarial attack). True containment requires OS-level sandboxing.

This is the same security model as `ssh-agent`, `gpg-agent`, macOS Keychain, and every local secret manager. kv-secrets is the first to specifically address AI agent access as a threat vector.

---

## What's Pending

### Must do before v0.2.0 release

| Item | Why | Effort |
|------|-----|--------|
| Bump version to 0.2.0 | All security features are unreleased | 5 min |
| Update README with security features | Users need to know about passphrase + TOTP + daemon | 1 hour |
| Update SECURITY.md threat model | Document what's protected and what's not | 30 min |
| CLI command tests | 874-line cli.py has zero tests | 2 hours |
| Crypto/store module tests | Wrapping, TOTP, store operations untested | 1 hour |
| Fix PostToolUse hook data format | Hook may not receive output in expected field | 1 hour |
| Test kv_api with real API calls | Only tested structurally, not end-to-end | 1 hour |

### Nice to have

| Item | Why | Effort |
|------|-----|--------|
| Audit logging | Record who accessed which key when (names, not values) | 2 hours |
| More providers for kv_api | Currently: openai, anthropic, google. Add: github, stripe | 1 hour each |
| Windows named pipe support | Agent daemon uses Unix sockets (Linux/macOS only) | 4 hours |
| `kv rotate KEY` | Generate new value and update across environments | 2 hours |
| Website update (kesecure.com) | Document new features | 2 hours |
| PyPI release | Publish v0.2.0 to PyPI | 30 min |

### Won't fix (by design)

| Item | Why |
|------|-----|
| OS-level sandbox for subprocess | Beyond scope — use Claude Code `--sandbox` |
| Complete protection against adversarial agents | Impossible without OS isolation |
| Custom per-command network rules | unshare is all-or-nothing |
| Encrypted secret names | Names are metadata, not secrets |

---

## Technical Reference

### Dependencies

| Package | Why | Required? |
|---------|-----|-----------|
| `cryptography>=41.0.0` | ChaCha20-Poly1305, PBKDF2 | Yes |
| `qrcode>=7.0` | QR code display for TOTP setup | Optional (`pip install kv-secrets[totp]`) |

### File format: .enc

```
Bytes 0-2:   "KV\x00" (magic)
Byte 3:      0x01 (version)
Bytes 4+:    nonce(12) + ChaCha20-Poly1305 ciphertext + tag(16)

Decrypted payload (JSON):
{
  "_meta": {"updated": "2026-03-21T...", "count": 5},
  "secrets": {"KEY_NAME": "value", ...}
}
```

### File format: wrapped key

```
Bytes 0-3:   "KVW\x01" (magic — KV Wrapped, version 1)
Bytes 4-19:  salt (16 bytes, random)
Bytes 20-31: nonce (12 bytes, random)
Bytes 32+:   ChaCha20-Poly1305 ciphertext of master key + tag(16)

Key derivation:
  PBKDF2-HMAC-SHA256(passphrase, salt, iterations=600000) → 32-byte wrapping key
  ChaCha20-Poly1305(wrapping_key, nonce, master_key, aad="kv-master-key") → ciphertext
```

### TOTP implementation

RFC 6238, implemented in pure Python (no pyotp dependency):
- HMAC-SHA1 with 160-bit secret
- 30-second time step
- ±1 step verification window (accepts codes from 30s ago to 30s ahead)
- Secret stored in config.json encrypted with passphrase-derived key

### Agent daemon socket protocol

Unix domain socket at `/tmp/kv-agent/kv.sock` (chmod 600).
JSON messages, newline-delimited. Request → response pattern.

```json
// Request
{"cmd": "run", "argv": ["python3", "app.py"], "env": "dev"}

// Response
{"exit_code": 0, "stdout": "...", "stderr": "...", "warning": "..."}
```

### Hook system

Two Claude Code hooks in `.claude/settings.local.json`:

**PreToolUse** (runs before Bash/Read): Blocks reads of tracked files. Warns on suspicious encoding + file-access patterns.

**PostToolUse** (runs after Bash): Scans output for leaked secret values. Alerts user via stderr if detected.

Both hooks communicate with the agent daemon to check tracked files and secret values.
