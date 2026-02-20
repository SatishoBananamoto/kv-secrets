# kv — Design Document

## What
Encrypted secrets management CLI for developers. Local-first, CLI-first, designed to grow into a paid team product.

## Why
- Dev teams share `.env` files through Slack/email (insecure)
- dotenvx = encryption only, no team features
- Doppler = $21/user, cloud-only
- Vault = overkill for small teams
- **Gap**: Simple CLI + real encryption + multi-environment + future team sync

## Name Choice: `kv`
- Two letters, universally understood (key-value)
- Reads naturally: `kv set`, `kv get`, `kv run`
- Rejected: `stash` (git collision), `seal` (vague), `crypt` (scary), `vault` (taken)

## Dependency Choice
- **`cryptography`** (single dependency) — Python stdlib has no symmetric cipher
- ChaCha20-Poly1305 AEAD — same as WireGuard, TLS 1.3
- Industry-standard, audited, constant-time

## Encryption Architecture
- **Master key**: 32 random bytes, stored as base64url in `.secrets/key`
- **Per-env keys**: Derived via BLAKE2b keyed hash (stdlib) — no per-env key storage
- **Cipher**: ChaCha20-Poly1305 with 12-byte random nonce + environment name as AAD
- **Storage**: Entire secrets dict encrypted as single JSON blob (no key name leakage)

## Storage Format
```
.secrets/
  key             # Master key. NEVER committed.
  config.json     # Project metadata
  dev.enc         # KV\x00 + version(1) + nonce(12) + ciphertext+tag
  staging.enc
  .gitignore      # Auto-generated
```

## CLI Interface
```
kv init                              Initialize project
kv set KEY=VALUE [-e ENV]            Set a secret
kv set KEY [-e ENV]                  Set interactively (hidden input)
kv get KEY [-e ENV]                  Decrypt and print
kv ls [-e ENV] [--reveal]            List keys
kv run COMMAND [-e ENV]              Run with secrets injected
kv export [-e ENV] [-o FILE]         Export as .env
kv import FILE [-e ENV]              Import .env file
kv rm KEY [-e ENV]                   Remove a secret
kv envs                              List environments
kv env create NAME                   Create environment
kv env copy SRC DST                  Copy between environments
kv status                            Project status
```

## Key Decisions
1. **Single blob per env** — no key name leakage, atomic reads/writes
2. **BLAKE2b for key derivation** — master key is high-entropy, no slow KDF needed
3. **`find_project_root()` walks up dirs** — works from subdirectories (like git)
4. **Atomic writes** — tmp + `os.replace()` prevents corruption
5. **`.enc` safe to commit, `key` is not** — enables future git-based team sharing

## Monetization
- **Free**: Local CLI (12 commands, full encryption, multi-environment)
- **$15/team/month**: Cloud sync, team management, CI/CD tokens, basic RBAC
- **$99/team/month**: Rotation automation, advanced RBAC, audit logs
- Undercuts Doppler ($21/user x 5 = $105/mo) with per-team pricing

## Package Structure
```
kv/                       # CLI package
  __init__.py             # Version
  __main__.py             # Entry point, Windows fixes
  cli.py                  # argparse (20 commands), dispatch, ANSI output
  cli_remote.py           # Remote command handlers (login, push/pull, team, token)
  crypto.py               # ChaCha20 encrypt/decrypt, BLAKE2b derivation, kvkey_ export/import
  store.py                # .enc file format, secret CRUD, raw blob read/write, atomic writes
  env.py                  # Secret injection, .env import/export
  config.py               # Project init, config.json, find_project_root, sync state
  auth.py                 # Session management (~/.kv/session.json), auth headers
  remote.py               # HTTP client (urllib.request), all API calls
  sync.py                 # Push/pull orchestration, hash computation, conflict detection

kv_server/                # API server package
  __init__.py             # Version
  __main__.py             # uvicorn entry (python -m kv_server)
  app.py                  # FastAPI app factory, CORS, lifespan
  config.py               # Settings from env vars
  database.py             # SQLAlchemy models (5 tables), engine, session
  models.py               # Pydantic request/response schemas
  auth.py                 # JWT, bcrypt, API token validation
  billing.py              # Stripe integration (checkout, portal, webhooks)
  middleware.py            # Rate limiting placeholder
  routes/
    __init__.py            # Route registration
    auth_routes.py         # /auth/register, /auth/login, /auth/refresh
    sync_routes.py         # /sync/push, /sync/pull, /sync/status
    team_routes.py         # /team/create, /team/invite, /team/members, /team/revoke
    token_routes.py        # /tokens/create, /tokens/list, /tokens/revoke
    billing_routes.py      # /billing/status, /billing/checkout, /billing/portal, /billing/webhook
```

## Build Status — Local CLI (v0.1)
- [x] Package entry (__init__, __main__)
- [x] Encryption engine (crypto.py) — ChaCha20-Poly1305, BLAKE2b derivation, key I/O
- [x] Project config (config.py) — init, find_project_root, env registry
- [x] Secret store (store.py) — .enc format, CRUD, atomic writes, tamper detection
- [x] CLI commands (cli.py) — 12 local commands, ANSI output
- [x] Env injection + import/export (env.py) — subprocess injection, .env parsing
- [x] Full test suite — 20/20 local tests passing
- [x] README.md

## Build Status — Paid Tier (v0.2)
- [x] Server foundation (kv_server/) — FastAPI, SQLAlchemy, 5 DB tables, JWT auth
- [x] CLI auth (kv/auth.py) — login/signup/logout, session at ~/.kv/session.json
- [x] HTTP client (kv/remote.py) — stdlib urllib.request, all API calls
- [x] Push/pull sync (kv/sync.py) — encrypted blob transfer, hash-based conflict detection
- [x] Team management — create, invite, members, revoke, kvkey_ key sharing
- [x] CI/CD tokens — scoped API tokens (pull/push/admin), env restriction, expiry
- [x] Stripe billing — checkout, portal, webhook handler, trial period
- [x] CLI commands (cli.py) — expanded to 20 commands total
- [x] End-to-end test suite — 20/20 integration tests passing

## Paid Tier Architecture
- **Zero-knowledge**: Server stores raw .enc blobs, never sees plaintext
- **Auth**: JWT (1h access + 30d refresh) for CLI, API tokens (kvt_...) for CI/CD
- **Key sharing**: `kvkey_` prefix + base64url master key, shared out-of-band
- **Sync**: Client reads .enc blob -> base64 -> POST /sync/push, reverse for pull
- **Conflict resolution**: Last-write-wins with version numbers + blob hashes
- **Billing**: $15/team/month, 14-day trial, Stripe Checkout + webhooks
- **Server deps**: fastapi, uvicorn, sqlalchemy[asyncio], aiosqlite, python-jose, bcrypt, stripe

## Gotchas Found During Build
- `argparse.REMAINDER` field must not collide with subparser `dest` field name — renamed to `cmd`
- `subprocess.run` needs list args (not joined string) to preserve quoting for `python -c "..."`
- Optional flags (`-e`, `-q`) MUST come before REMAINDER positional in parser definition
- passlib + bcrypt compatibility broken on Python 3.12 — use `bcrypt` directly instead
- SQLite returns naive datetimes — normalize to UTC before comparing with aware datetimes
- Pydantic `EmailStr` requires `email-validator` package — use plain `str` to avoid extra dep
