# kv

[![tests](https://github.com/SatishoBananamoto/kv-secrets/actions/workflows/test.yml/badge.svg)](https://github.com/SatishoBananamoto/kv-secrets/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/kv-secrets)](https://pypi.org/project/kv-secrets/)
[![Python](https://img.shields.io/pypi/pyversions/kv-secrets)](https://pypi.org/project/kv-secrets/)
[![License](https://img.shields.io/github/license/SatishoBananamoto/kv-secrets)](LICENSE)

Encrypted secrets management for developers and AI coding agents.

**kv** encrypts your API keys, database URLs, and tokens with ChaCha20-Poly1305 — then lets your AI editor (Cursor, Claude Code, VS Code) use them safely through MCP. Your AI agent never sees the plaintext values.

```
pip install kv-secrets
```

## Get Started in 30 Seconds

```bash
cd your-project
kv init                              # Create encrypted vault
kv set API_KEY sk-live-abc123        # Store a secret
kv run -- python app.py              # Run with secrets injected
```

That's it. Your secrets are encrypted on disk. The `kv run` command injects them as environment variables at runtime — they never touch plaintext files, chat logs, or AI context.

## MCP Integration (AI Editors)

kv includes an MCP server so Cursor, Claude Code, and VS Code Copilot can manage secrets without ever seeing them.

```bash
# Auto-configure your editor (one command)
kv setup cursor
kv setup claude-code
kv setup vscode
```

Your AI agent now has access to these tools:

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

## Use in GitHub Actions

Your `.enc` files are safe to commit — they're encrypted noise without the key. Use this in CI:

```yaml
steps:
  - uses: actions/checkout@v4

  - name: Install kv
    run: pip install kv-secrets

  - name: Run tests with secrets
    run: kv run -- pytest
    env:
      # Copy the contents of .secrets/key into a GitHub Actions secret
      # named KV_MASTER_KEY — kv reads it automatically when the file is absent
      KV_MASTER_KEY: ${{ secrets.KV_MASTER_KEY }}
```

Commit `.secrets/*.enc` and `.secrets/config.json` to git. The `.secrets/key` file is auto-gitignored. In CI, kv reads the master key from the `KV_MASTER_KEY` environment variable when the key file isn't present.

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

## Diagnostics

Verify your setup:

```bash
kv doctor
```

```
  kv -- doctor

  ✓ Python 3.12.3
  ✓ Project found
  ✓ Master key readable (256-bit)
  ✓ Config valid (2 environments)
  ✓ Decrypt OK  dev (3 secrets)
  ✓ MCP server module available
  ✓ Cursor MCP configured

  7 passed
```

## Encryption

- **Algorithm:** ChaCha20-Poly1305 (AEAD) — same cipher family as WireGuard
- **Key derivation:** BLAKE2b with environment name as context
- **Storage:** Binary `.enc` files — safe to commit to git
- **Master key:** 256-bit random, stored in `.secrets/key` — never commit this

## Multi-Environment

```bash
# Create environments
kv env create staging
kv env create prod

# Set per-environment secrets
kv set API_KEY sk-test-dev --env dev
kv set API_KEY sk-live-prod --env prod

# Run in specific environment
kv run --env prod -- python deploy.py
```

## All Commands

**Local**

```
kv init            Initialize kv in current project
kv set KEY VAL     Store an encrypted secret
kv get KEY         Decrypt and print a secret
kv ls              List secret names
kv rm KEY          Remove a secret
kv run -- CMD      Run command with secrets in env
kv envs            List environments
kv env create NAME Create a new environment
kv export          Export as .env format
kv import FILE     Import from .env file
kv export-key      Export master key as shareable string
kv import-key TOK  Import a shared master key
kv status          Show project info
kv doctor          Check project health
kv version         Print version
```

**MCP (AI editors)**

```
kv setup EDITOR    Configure MCP for your editor
kv mcp             Show MCP server config JSON
```

**Remote (requires [kvsecure.com](https://kvsecure.com) account — coming soon)**

```
kv signup          Create account
kv login / logout  Sign in / sign out
kv push / pull     Sync encrypted secrets to cloud
kv remote          Show sync status
kv team            Manage team members
kv token           Manage API tokens for CI/CD
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

## Comparison

| Feature | kv | .env files | 1Password CLI | HashiCorp Vault |
|---------|:--:|:----------:|:-------------:|:---------------:|
| Encrypted at rest | Yes | No | Yes | Yes |
| MCP server for AI agents | Yes | No | No | No |
| Zero config setup | Yes | Yes | No | No |
| Works offline | Yes | Yes | No | No |
| Free for individuals | Yes | Yes | No | No |
| Single dependency | Yes | Yes | No | No |
| Team sharing (paid) | Yes | No | Yes | Yes |

## Security

See [SECURITY.md](SECURITY.md) for the full security model, vulnerability reporting process, and static analysis status.

| What | Where | Safe to share? |
|------|-------|---------------|
| `.enc` files | Project dir | Yes (commit to git) |
| Master key | `.secrets/key` | No (share via secure channel) |
| Plaintext | Never on disk | N/A |

- Zero-knowledge architecture — cloud sync server never sees plaintext
- `kv run` injects secrets via env vars, returns only exit codes
- MCP profiles gate what AI agents can access (safe/mutate/reveal)
- Semgrep Pro scanned: 0 blocking findings across 2,538 rules

## Requirements

- Python 3.10+
- `cryptography` (installed automatically)

## License

MIT — see [LICENSE](LICENSE)
