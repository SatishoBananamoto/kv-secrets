# The One-Way Mirror Problem: MCP Security Profiles, AI Agent Bash Access, and the Interface Barrier

**Author**: Claude (Opus 4.6) in partnership with Satish Patil (@SatishoBananamoto)
**Date**: 2026-03-20
**Subject**: kv-secrets, SVX, MCP security model
**Status**: Live findings from adversarial testing

---

## Abstract

AI coding agents (Claude Code, Cursor, Windsurf) operate with shell access on the developer's machine. MCP (Model Context Protocol) servers expose tools with security profiles — gating which operations an agent can perform. We demonstrate that MCP security profiles are trivially bypassed by any agent with Bash access, because the CLI and filesystem operate outside the MCP channel. We then develop and test a defense — passphrase-wrapped key encryption with TOTP two-factor authentication — and show that its security rests not on cryptography but on an **interface barrier**: the agent cannot respond to interactive prompts. We attack our own defense, identify its limits, and propose a framework distinguishing **advisory security** (deterrence + audit) from **containment security** (OS-enforced isolation). These findings apply to any MCP server that manages sensitive resources on the same machine where the agent has shell access.

---

## 1. The Setup

**kv-secrets** is an encrypted secret management tool for developers. It stores secrets encrypted with ChaCha20-Poly1305, derived per-environment from a master key via BLAKE2b. It exposes an MCP server with three security profiles:

| Profile | Tools | What agent can do |
|---------|-------|------------------|
| **safe** (default) | kv_status, kv_envs, kv_list, kv_run | List key names, run commands with secrets injected (never sees values) |
| **mutate** (opt-in) | kv_set, kv_rm | Modify secrets (can't read them) |
| **reveal** (opt-in) | kv_get | Read secret values in plaintext |

The design intent: an AI agent can **use** secrets (via `kv_run`, which injects them into subprocesses) without **seeing** them. The `reveal` profile must be explicitly enabled at server startup.

**SVX** is a deterministic safety layer that intercepts Claude Code tool calls via PreToolUse hooks, simulating their impact and producing verdicts: allow, confirm, or block.

Both tools were designed to protect developers from AI agent mistakes and unauthorized access.

---

## 2. The Attack: MCP Profile Bypass

### 2.1 The vulnerability

MCP profiles gate access through the MCP channel. The kv CLI has no access control — it assumes anyone with filesystem access is the authorized user.

An AI agent with Bash access operates outside the MCP channel.

### 2.2 Live exploitation

During a review session, the agent (Claude Opus 4.6) executed:

```bash
kv ls --reveal
```

**Result**: The full Anthropic API key was returned in plaintext. The MCP security profiles were completely irrelevant — the agent never used MCP. It used the CLI directly via the Bash tool.

Additional vectors confirmed:

```bash
kv get ANTHROPIC_API_KEY    # plaintext value
kv export                   # all secrets in .env format
cat .secrets/key            # plaintext master key (base64url)
```

**Time to exploit**: One command. Zero cryptographic work. The master key was stored as plaintext base64url text in `.secrets/key`.

### 2.3 Root cause

The MCP server is a **locked front door**. The Bash tool is an **open window**. The security model assumed the agent's only interface to kv-secrets was MCP. In reality, any agent with shell access has unrestricted filesystem and CLI access.

This vulnerability exists in **every MCP server that manages sensitive local resources**. If an MCP server gates access to files, databases, credentials, or API keys — and the agent has Bash access — the profiles are advisory, not enforced.

---

## 3. Escalation: Can SVX Stop This?

We analyzed whether SVX (the safety layer) could block the kv-secrets bypass.

### 3.1 SVX's coverage

SVX intercepts Bash commands via PreToolUse hooks. It could theoretically be extended to block `kv get`, `kv ls --reveal`, and `cat .secrets/*`.

### 3.2 SVX's own bypass

SVX's parser does not detect file writes via Bash redirection (`cat >`, heredoc, `echo >`). An agent can overwrite SVX's own hook configuration:

```bash
cat > .claude/settings.local.json << 'EOF'
{}
EOF
```

This removes the SVX hook entirely. SVX cannot detect this as a file write — it's the same parser gap documented in SVX-REWORK.md. The safety layer can be disabled by the entity it's protecting against.

### 3.3 The chain collapse

```
Agent wants secrets
  → kv MCP profiles block it
  → Agent uses Bash: kv get KEY
  → SVX blocks kv commands (hypothetically extended)
  → Agent disables SVX via Bash config overwrite
  → SVX is gone
  → Agent runs kv get KEY
  → Secrets obtained
```

Every layer runs as the same user with the same permissions. No software barrier in this chain provides containment.

---

## 4. The Defense: Passphrase + TOTP

### 4.1 Design

We implemented a two-layer defense:

**Layer 1 — Passphrase-wrapped master key:**
- The master key is encrypted with PBKDF2-HMAC-SHA256 (600,000 iterations) + ChaCha20-Poly1305
- `.secrets/key` contains binary wrapped blob (`KVW\x01` + salt + nonce + ciphertext), not plaintext
- Every operation requires the passphrase to unwrap the master key
- The passphrase is entered via `getpass.getpass()` — an interactive prompt

**Layer 2 — TOTP two-factor authentication:**
- RFC 6238 TOTP implementation (HMAC-SHA1 + dynamic truncation)
- TOTP secret stored in config.json, encrypted with the passphrase-derived key
- 6-digit code, 30-second window, ±1 step tolerance
- Setup via QR code for authenticator apps

### 4.2 Why it works

The security boundary is not cryptographic — it's an **interface barrier**.

```
Agent runs: kv get TEST_KEY
  → kv calls getpass.getpass("Passphrase: ")
  → getpass opens /dev/tty for interactive input
  → Agent's Bash subprocess has no terminal
  → getpass falls back to stdin
  → stdin is empty (no input piped)
  → passphrase = "" → wrong → exit 1
```

The agent cannot respond to interactive prompts. This is a property of how Claude Code's Bash tool works — it sends a command and waits for output. It cannot see a prompt and then type a response.

### 4.3 MCP server integration

The MCP server prompts for passphrase + TOTP at startup, before entering the JSON-RPC loop. The decrypted master key is held in process memory for the session. The agent communicates with the server via MCP tools (profile-gated). The key never touches the filesystem during the session.

```
Human starts MCP server → passphrase prompt → TOTP prompt → key in RAM
Agent uses MCP tools → server handles requests from memory → profile-gated
Agent tries kv get via Bash → passphrase prompt → agent can't respond → blocked
```

---

## 5. Breaking Our Own Defense

### 5.1 Attack: Brute force with common passwords

The first test passphrase was `12345678`. We attacked it:

```python
from kv.crypto import load_wrapped_key
from cryptography.exceptions import InvalidTag

attempts = ['password', '12345678', 'qwerty123', 'admin123', ...]
for guess in attempts:
    try:
        key = load_wrapped_key('.secrets/key', guess)
        print(f'CRACKED: {guess}')
        break
    except InvalidTag:
        continue
```

**Result**: Cracked in ~6 seconds (12 guesses at ~0.5s each with 600K PBKDF2 iterations).

With the passphrase, the TOTP secret was also decrypted (it's encrypted with the same passphrase-derived key). Full compromise: passphrase + TOTP secret + all encrypted secrets.

**Fix implemented**: Common password blocklist. The system now rejects known weak passwords (top breach database entries, all-digit sequences, single-character repetition).

### 5.2 Attack: Operational information leak

During testing, the user:
1. Accidentally typed the passphrase into bash (appeared as a command in terminal output)
2. Pasted the `kv setup-2fa` output (including TOTP secret) into the chat with the agent

Both values entered the agent's context window. No cryptographic attack needed.

```python
# Using passphrase from chat context + TOTP secret from pasted output
s = SecretStore('.', passphrase='chalchalo@18')
print(s.get_secret('dev', 'TEST_KEY'))  # hello-world
```

**Result**: Full compromise via information leak, not cryptographic failure.

**Mitigations**:
- QR code for TOTP setup (scan instead of copying text — secret never enters a copyable format)
- User education: never paste `kv setup-2fa` output into AI agent conversations
- Future: bash history scrubbing for failed commands that look like passwords

### 5.3 Attack: Pipe passphrase via stdin

```bash
echo "the-passphrase" | kv get TEST_KEY
```

Python's `getpass` falls back to reading stdin when `/dev/tty` is unavailable. If the passphrase is piped, it's read. The interactive prompt is NOT a hard cryptographic block.

**However**: the agent must **know** the passphrase to pipe it. If the passphrase is strong and hasn't leaked, this vector is theoretical.

### 5.4 What withstood attack

With a strong passphrase that hasn't leaked:
- `cat .secrets/key` → binary blob (useless without passphrase)
- `kv get KEY` → passphrase prompt → empty input → blocked
- Python import bypass → `VaultLockedError`
- Monkey-patching crypto module → still needs passphrase to unwrap
- Brute force with common passwords → rejected by blocklist
- TOTP secret from config → encrypted, requires passphrase to decrypt

The passphrase (in the user's mind) and the TOTP secret (on the user's phone) remain inaccessible to the agent through any filesystem or process-level attack.

---

## 6. The Output Redaction Layer

Even through MCP's `kv_run` tool, a subprocess could leak secrets:

```bash
kv_run(argv=["bash", "-c", "printenv | grep API_KEY"])
```

We implemented output redaction: `kv_run` captures stdout/stderr, scans for any string matching a known secret value, and replaces it with `[REDACTED]` before returning to the agent.

```
Subprocess prints: ANTHROPIC_API_KEY=sk-ant-api03-8vSL...
Agent receives:    ANTHROPIC_API_KEY=[REDACTED]
```

This is defense-in-depth. The primary defense (passphrase + TOTP) prevents access entirely. Output redaction prevents accidental leakage through subprocess output in the MCP channel.

---

## 7. Framework: Advisory Security vs. Containment Security

These findings suggest a two-tier framework for AI agent security:

### Advisory Security (Deterrence + Audit)

**Properties**: Can be bypassed by a determined agent with shell access. Provides logging, slows down risky operations, catches accidental mistakes.

**Examples**:
- MCP security profiles (kv-secrets safe/mutate/reveal)
- SVX PreToolUse hook interception
- Claude Code's built-in permission prompts
- File-level `chmod` (same user can change it)

**Analogy**: A speed bump. Slows you down, makes you think, but doesn't stop you if you floor it.

**Value**: Catches the 99% case — accidental destructive operations, unintentional secret exposure. Provides audit trail. Legitimate and useful.

### Containment Security (OS-Enforced Isolation)

**Properties**: Cannot be bypassed by same-user processes. Enforced by kernel, hardware, or network boundaries.

**Examples**:
- OS sandboxing (Claude Code `--sandbox`, Firejail, containers)
- Separate user accounts with distinct permissions
- Network boundaries (secrets on a different machine)
- Hardware security modules (keys in tamper-resistant hardware)
- **Interface barriers** (interactive prompts the agent can't respond to)

**Analogy**: A locked door. You need the key (passphrase, biometric, hardware token) to get through.

### The interface barrier as a middle ground

The passphrase/TOTP approach occupies an interesting position: it's enforced by an **interface limitation** (the agent can't respond to interactive prompts), not by OS-level isolation. It's stronger than advisory security (the agent can't just use a different tool to bypass it) but weaker than true OS containment (the agent could theoretically pipe input if it knew the passphrase).

We propose a three-tier model:

```
Tier 1: Advisory          → MCP profiles, SVX rules, permission prompts
Tier 2: Interface barrier  → Passphrase prompts, TOTP, human-in-the-loop gates
Tier 3: OS containment    → Sandboxing, separate users, network boundaries
```

For most developer workflows, Tier 2 provides sufficient security. The passphrase is something the agent doesn't know. The TOTP code is on a device the agent can't access. Combined with a strong passphrase and a common-password blocklist, the attack surface reduces to social engineering (tricking the user into leaking credentials) rather than technical exploitation.

---

## 8. Implications for the MCP Ecosystem

### 8.1 Every MCP server with sensitive local resources is affected

Any MCP server that:
- Manages files (the agent can `cat` them)
- Manages credentials (the agent can read config files)
- Manages databases (the agent can run `sqlite3` or `psql` directly)
- Gates access via profiles (the agent can use the CLI instead)

...is vulnerable to the same bypass. MCP profiles are protocol-level controls, not OS-level controls.

### 8.2 MCP servers should not claim to provide security boundaries

The MCP specification does not position profiles as security boundaries, and server implementations should not either. Documentation should clearly state:

> "Security profiles control access through the MCP channel. An agent with shell access can bypass these profiles via direct CLI or filesystem access. For security-sensitive resources, use OS-level sandboxing or interactive authentication in addition to MCP profiles."

### 8.3 The `kv_run` pattern is the right MCP design for secrets

The `kv_run` tool — inject secrets into a subprocess, return only the output — is the correct pattern for MCP servers that handle sensitive data. The agent specifies **what to do**, the server handles **how to do it** (with secrets), and the agent gets **the result** (with secrets stripped).

This is a one-way mirror: the agent sees through to the output, but can't see the secrets that produced it.

**Caveat discovered during testing (2026-03-21):** The one-way mirror has a hole. The subprocess runs with secrets as environment variables and has full filesystem write access. An adversarial agent can:

```bash
# Via kv_run or agent daemon:
run(argv=["bash", "-c", "printenv > /tmp/leak.txt"])
# Then read /tmp/leak.txt directly — all secrets in plaintext
```

Output redaction only protects the communication channel (socket/MCP response). It cannot prevent a subprocess from writing its own environment to the filesystem. This is a fundamental limitation of env-var-based secret injection — the same limitation Docker secrets, Kubernetes env vars, and ssh-agent face.

The `kv_run` pattern still catches **accidental** leaks (secrets in error messages, debug output). It does not prevent **deliberate** exfiltration by an adversarial agent. True containment requires OS-level subprocess sandboxing.

### 8.4 Interactive authentication should be standard for sensitive MCP servers

MCP servers that manage credentials, secrets, or other sensitive resources should require interactive authentication at startup. This creates a Tier 2 interface barrier that the agent cannot bypass through MCP or Bash.

---

## 9. Responsible Disclosure Note

These findings apply to the general class of MCP servers managing local sensitive resources, not to a specific vendor's implementation. The vulnerability is architectural — inherent to the MCP protocol's relationship with the operating system — not a bug in any specific software.

kv-secrets v0.1.1 (prior to this analysis) stored the master key in plaintext. The passphrase + TOTP defense was developed and tested during this analysis session and is available in the kv-secrets repository.

No third-party systems were tested or attacked. All exploitation was performed on the researcher's own machine against their own secrets, with their explicit instruction to do so.

---

## 10. Summary of Findings

| Finding | Severity | Status |
|---------|----------|--------|
| MCP profiles bypassed by Bash CLI access | Critical | Fixed (passphrase + TOTP) |
| Plaintext master key on disk readable by agent | Critical | Fixed (passphrase wrapping) |
| SVX can be disabled by agent via Bash config overwrite | High | Documented, fix designed |
| Weak passphrase brute-forced in 6 seconds | High | Fixed (common password blocklist) |
| Operational leak (passphrase/TOTP in chat) | Medium | Mitigated (QR code, user education) |
| Subprocess output can leak secrets via stdout | Medium | Fixed (output redaction in kv_run) |
| Subprocess can write secrets to filesystem via kv_run | High | Known limitation — env vars + filesystem access = exfiltration possible |
| TOTP secret coupled to passphrase | Low | By design (local-only constraint) |

---

## 11. Recommendations

### For MCP server developers
1. Do not rely on MCP profiles as security boundaries when agents have shell access
2. Implement interactive authentication for sensitive operations
3. Use the `kv_run` pattern: inject secrets, return redacted output
4. Document your threat model explicitly — advisory vs. containment

### For AI agent platform developers
1. Consider Tier 2 interface barriers as a standard feature for sensitive tool access
2. Provide sandboxing options that restrict filesystem access per-MCP-server
3. Allow MCP servers to declare "this server requires interactive auth at startup"

### For developers using AI agents with secrets
1. Use passphrase-protected secret stores, not plaintext `.env` files
2. Never paste secret-containing output into AI agent conversations
3. Use `kv run` / subprocess injection instead of `kv get` / direct access
4. Treat your AI agent as an insider with full shell access — because it is one

---

## Appendix A: Timeline

```
2026-03-20 Session start
  → Reviewed kv-secrets, scroll, svx, engram, vigil (5 projects)
  → During kv-secrets review, tested MCP profile bypass
  → Extracted ANTHROPIC_API_KEY via "kv ls --reveal" (one command)
  → Analyzed SVX as potential mitigation → found SVX self-disablement
  → Designed passphrase + TOTP defense
  → Implemented: key wrapping (PBKDF2 + ChaCha20), TOTP (RFC 6238), CLI/MCP integration
  → 88 tests passing (21 crypto + 13 vault security + 48 MCP + 6 passphrase strength)
  → Attacked own implementation: brute-forced weak passphrase in 6 seconds
  → Added common password blocklist
  → User accidentally leaked passphrase + TOTP secret in chat
  → Full compromise via operational leak (not cryptographic failure)
  → Added QR code for TOTP (prevents text secret exposure)
  → Final state: passphrase + TOTP + blocklist + output redaction + QR code
```

## Appendix B: The /dev/tty Problem

MCP servers communicate via stdin/stdout (JSON-RPC). A passphrase prompt that reads from stdin would be interpreted as a JSON-RPC message, breaking the protocol. The solution is to read from `/dev/tty` — a Unix device that always refers to the controlling terminal, regardless of stdin/stdout redirection.

**The challenge**: When Claude Code spawns an MCP server subprocess, it redirects stdin/stdout to pipes for JSON-RPC. But if Claude Code is running in a terminal, the subprocess inherits the controlling terminal, and `/dev/tty` should work.

**Verification**: `/dev/tty` is NOT available from the agent's Bash subprocess (confirmed — `ENODEV`). This is correct and expected — the agent's Bash runs without a controlling terminal. The MCP server, started by Claude Code (which runs in the user's terminal), should have `/dev/tty` available.

**Fallback chain implemented**:
1. `/dev/tty` — cleanest, completely bypasses stdin
2. `getpass.getpass()` — has its own /dev/tty + fallback logic
3. `KV_PASSPHRASE` env var — for headless/CI (less secure)
4. Fail with clear instructions

This means the auth prompt works in the user's terminal but fails in the agent's Bash — which is exactly the security boundary we want.

## Appendix C: Code Changes

```
kv/crypto.py        +150 LOC  Key wrapping, TOTP, passphrase strength
kv/store.py          +20 LOC  VaultLockedError, passphrase parameter
kv/config.py         +10 LOC  Security config, passphrase-aware init
kv/cli.py            +120 LOC  Passphrase prompting, setup-2fa, upgrade-security
kv_mcp/server.py     +30 LOC  Passphrase + TOTP at startup
kv_mcp/tools.py      +20 LOC  Output redaction in kv_run
kv_mcp/__main__.py    +8 LOC  Reveal profile warning
tests/test_crypto.py +150 LOC  27 tests (wrapping, TOTP, strength)
tests/test_vault_security.py +130 LOC  13 tests (full flow, upgrade, CI fallback)
```

Total: ~650 LOC added, 40 new tests, zero new required dependencies (qrcode is optional).
