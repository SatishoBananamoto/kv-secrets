# kv

Encrypted secrets management for developers. Set, get, inject — no plaintext `.env` files.

```
pip install cryptography
```

```
python -m kv init
python -m kv set DATABASE_URL=postgres://localhost/mydb
python -m kv set API_KEY                          # prompts for value (hidden)
python -m kv run python app.py                    # secrets injected as env vars
```

## Why

Teams share `.env` files through Slack and email. That's plaintext secrets in chat logs, email servers, and clipboard history. Existing solutions are either encryption-only (dotenvx), cloud-only and expensive (Doppler at $21/user), or overkill (HashiCorp Vault).

**kv** encrypts secrets locally with ChaCha20-Poly1305 (same cipher as WireGuard and TLS 1.3), supports multiple environments, and injects secrets into any command — all from a two-letter CLI.

## Commands

```
kv init                              Initialize project
kv set KEY=VALUE [-e ENV]            Set a secret
kv set KEY [-e ENV]                  Set interactively (hidden input)
kv get KEY [-e ENV]                  Decrypt and print a secret
kv ls [-e ENV] [--reveal]            List secrets (values hidden by default)
kv rm KEY [-e ENV] [-f]              Remove a secret
kv run [-e ENV] [-q] COMMAND...      Run command with secrets as env vars
kv export [-e ENV] [-o FILE]         Export as .env format
kv import FILE [-e ENV]              Import from .env file
kv envs                              List all environments
kv env create NAME                   Create a new environment
kv env copy SRC DST                  Copy secrets between environments
kv status                            Project overview
kv --version                         Print version
```

### Quick start

```bash
# Initialize — creates .secrets/ with master key and config
python -m kv init

# Store secrets
python -m kv set DATABASE_URL=postgres://localhost:5432/mydb
python -m kv set STRIPE_KEY=sk_test_abc123
python -m kv set SESSION_SECRET           # hidden prompt, nothing on screen

# Retrieve
python -m kv get DATABASE_URL             # prints raw value (pipe-friendly)
python -m kv ls                           # list keys, values masked
python -m kv ls --reveal                  # list keys with decrypted values

# Inject into any command
python -m kv run python app.py
python -m kv run node server.js
python -m kv run -e staging python migrate.py

# Multiple environments
python -m kv set -e staging DATABASE_URL=postgres://staging-host/db
python -m kv set -e prod DATABASE_URL=postgres://prod-host/db
python -m kv envs                         # dev, staging, prod
python -m kv env copy dev staging         # clone secrets across envs

# Import/export
python -m kv export -o .env               # decrypt to .env file
python -m kv import legacy.env -e prod    # encrypt from .env file

# Remove
python -m kv rm API_KEY                   # confirmation prompt
python -m kv rm API_KEY -f                # skip confirmation
```

## How it works

### Encryption

- **Cipher**: ChaCha20-Poly1305 AEAD (authenticated encryption with associated data)
- **Master key**: 32 random bytes generated at `kv init`, stored in `.secrets/key`
- **Per-environment keys**: Derived from master key via BLAKE2b keyed hash — deterministic, no per-env key storage needed
- **Nonce**: 12 random bytes per write, prepended to ciphertext
- **AAD**: Environment name is bound as additional authenticated data — tampering or swapping `.enc` files between environments is detected
- **Payload**: All secrets for an environment are encrypted as a single JSON blob — key names are never visible without the master key

### Storage

```
your-project/
  .secrets/
    key              Master key (base64url). NEVER commit this.
    config.json      Project metadata (environments, cipher, version)
    dev.enc          Encrypted secrets for dev
    staging.enc      Encrypted secrets for staging
    prod.enc         Encrypted secrets for prod
    .gitignore       Auto-generated: ignores key, allows *.enc
```

The `.gitignore` inside `.secrets/` is auto-configured:
- `key` is ignored (your master key never enters git)
- `*.enc` files are allowed (encrypted blobs are safe to commit)
- `config.json` is allowed (no sensitive data)

This means `.enc` files can live in your repo. Anyone without the `key` file sees binary gibberish. Share the key through a secure channel once — after that, secrets travel with the code.

### Binary format

Each `.enc` file:
```
Bytes 0-2:   KV\x00        Magic bytes
Byte 3:      0x01           Version
Bytes 4-15:  nonce          12-byte random nonce
Bytes 16+:   ciphertext     ChaCha20-Poly1305 encrypted payload + 16-byte auth tag
```

Decrypted payload (JSON):
```json
{
  "_meta": {"updated": "2026-02-18T14:35:00+00:00", "count": 3},
  "secrets": {
    "DATABASE_URL": "postgres://localhost/mydb",
    "API_KEY": "sk-test123",
    "SESSION_SECRET": "a1b2c3d4"
  }
}
```

## Security model

**What's protected:**
- Secret values are encrypted at rest with a 256-bit key
- Secret key names are encrypted (single-blob-per-env design)
- Environment isolation — per-env derived keys, AAD binding
- Tamper detection — Poly1305 authentication tag catches any modification
- Atomic writes — tmp file + `os.replace()` prevents partial writes on crash

**What's NOT protected (yet):**
- The master key in `.secrets/key` is plaintext on disk (protected by file permissions, `.gitignore`)
- No access control — anyone with the key can read/write all environments
- No audit log — no record of who changed what
- No key rotation — changing the master key requires re-encrypting everything manually

These are the features that make up the paid team tier (cloud sync, RBAC, audit logs, rotation).

## Architecture

```
kv/
  __init__.py     Package version
  __main__.py     Entry point (python -m kv), Windows terminal fixes
  crypto.py       ChaCha20-Poly1305 encrypt/decrypt, BLAKE2b key derivation
  store.py        SecretStore class, .enc binary format, atomic CRUD
  config.py       Project init, find_project_root(), environment registry
  cli.py          argparse commands, ANSI-colored output
  env.py          Subprocess injection, .env import/export
```

**Single dependency**: `cryptography` (for ChaCha20-Poly1305). Everything else is stdlib.

## Platform

Works on Windows, macOS, and Linux. Tested primarily on Windows with PowerShell.

Run from any subdirectory — `kv` walks up the directory tree to find `.secrets/` (like `git` finds `.git/`).

```powershell
# From project root
python -m kv set FOO=bar

# From a subdirectory — still works
cd src/
python -m kv get FOO    # finds .secrets/ in parent
```
