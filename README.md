# kv

Encrypted secrets management for developers and AI coding agents.

**kv** encrypts your API keys, database URLs, and tokens with ChaCha20-Poly1305 — then lets your AI editor (Cursor, Claude Code, VS Code) use them safely through MCP.

```
pip install kv-secrets
```

## Why kv?

Your AI coding agent needs your API keys to run and test code. But pasting secrets into chat is dangerous — they end up in logs, training data, and prompt history.

**kv keeps secrets encrypted on disk and injects them only at runtime.** Your AI agent never sees the plaintext values.

## Quick Start

```bash
# Initialize in your project
kv init

# Store secrets
kv set API_KEY sk-live-abc123
kv set DATABASE_URL postgres://user:pass@host/db

# Run commands with secrets injected
kv run -- python app.py
kv run -- npm start

# List keys (values stay hidden)
kv ls
```

## MCP Integration (AI Editors)

kv includes an MCP server so Cursor, Claude Code, and VS Code Copilot can manage secrets without ever seeing them.

```bash
# Auto-configure your editor (one command)
kv setup cursor
kv setup claude-code
kv setup vscode
```

That's it. Your AI agent now has access to these tools:

| Tool | Profile | What it does |
|------|---------|-------------|
| `kv_status` | safe | Check if kv is initialized |
| `kv_envs` | safe | List environments (dev, staging, prod) |
| `kv_list` | safe | List secret names (no values) |
| `kv_run` | safe | Run commands with secrets injected |
| `kv_set` | mutate | Store a secret (opt-in) |
| `kv_rm` | mutate | Remove a secret (opt-in) |
| `kv_get` | reveal | Read a secret value (opt-in) |

**Security profiles** control what your AI can do:

```bash
# Default: safe only (list + run)
kv setup cursor

# Allow storing secrets
kv setup cursor --allow-mutate

# Allow reading values (use with caution)
kv setup cursor --allow-reveal
```

## How It Works

```
You: "run the tests"

AI Agent                          kv
   |                               |
   |-- kv_run ["pytest"] --------->|
   |                               |-- decrypt secrets
   |                               |-- inject into env
   |                               |-- subprocess.run(pytest)
   |                               |-- return exit code only
   |<-- "exit code: 0" -----------|

Secret values never appear in the chat.
```

## Encryption

- **Algorithm:** ChaCha20-Poly1305 (AEAD)
- **Key derivation:** BLAKE2b with environment name as context
- **Storage:** Binary `.enc` files — safe to commit to git
- **Master key:** Stored in `.secrets/key` — add to `.gitignore`

## Multi-Environment

```bash
# Switch environments
kv env staging
kv env prod

# Set per-environment secrets
kv set API_KEY sk-live-prod --env prod
kv set API_KEY sk-test-dev --env dev

# Run in specific environment
kv run --env prod -- python deploy.py
```

## All Commands

```
kv init          Initialize kv in current project
kv set KEY VAL   Store an encrypted secret
kv get KEY       Decrypt and print a secret
kv ls            List secret names
kv rm KEY        Remove a secret
kv run -- CMD    Run command with secrets in env
kv envs          List environments
kv env NAME      Switch default environment
kv export        Export as .env format
kv import FILE   Import from .env file
kv status        Show project info
kv setup EDITOR  Configure MCP for your editor
kv version       Print version
```

## Key Sharing

Share the master key with teammates out-of-band (Signal, 1Password, etc.):

```bash
# Export key as portable string
kv export-key
# kvkey_dGhpcyBpcyBhIHRlc3Qga2V5...

# Teammate imports it
kv import-key kvkey_dGhpcyBpcyBhIHRlc3Qga2V5...
```

The `.enc` files are safe to commit — without the key, they're just noise.

## Security Model

| What | Where | Safe to share? |
|------|-------|---------------|
| `.enc` files | Project dir | Yes (commit to git) |
| Master key | `.secrets/key` | No (share via secure channel) |
| Plaintext | Never on disk | N/A |

- Zero-knowledge design — even the cloud sync server (coming soon) never sees plaintext
- Encrypted blobs are opaque to anyone without the key
- `kv run` uses `stdout=DEVNULL` — your AI agent only sees exit codes, never output

## Requirements

- Python 3.10+
- `cryptography` (installed automatically)

## License

MIT
