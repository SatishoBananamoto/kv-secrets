# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Email **support@kvsecure.com** with:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a remediation timeline within 5 business days.

## Security Model

kv uses a zero-knowledge encryption architecture:

- **Encryption:** ChaCha20-Poly1305 AEAD (via `cryptography` library)
- **Key derivation:** BLAKE2b keyed hash, per-environment (env name as AAD)
- **Master key:** 256-bit random, stored locally in `.secrets/key`
- **Storage:** Binary `.enc` files with magic bytes + version header
- **Cloud sync:** Server stores raw encrypted blobs — never sees plaintext
- **MCP server:** Profile-gated tools (`safe`/`mutate`/`reveal`); `kv_run` injects secrets without exposing values to AI agents

The `.enc` files are safe to commit. The master key must never be committed.

## Static Analysis

The codebase is scanned with Semgrep Pro (2,538 rules). Current status: 0 blocking findings.

## What Is NOT a Vulnerability

- Feature requests or enhancement suggestions
- Issues requiring physical access to the machine where kv is installed
- Denial of service through local file deletion
- Bugs in upstream dependencies (report those to the dependency maintainer)
- The MCP `kv_get` tool returning plaintext to an AI agent (by design; use `kv_run` for the secure path)

## Dependencies

kv's CLI has one runtime dependency: [`cryptography`](https://pypi.org/project/cryptography/). We track upstream security advisories and update promptly.
