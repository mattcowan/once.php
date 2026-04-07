# once.php

A self-destructing encrypted note-sharing application. Single-file PHP, no frameworks, no dependencies, no build step.

Notes are encrypted at rest, protected by a 6-character passcode, and permanently deleted after a single view or after 72 hours -- whichever comes first.

## Why This Exists

Sometimes you need to share a password, API key, or sensitive message with someone and don't want it sitting in a Slack thread or email forever. This app creates a one-time-use link that self-destructs after reading.

## Encryption Modes

### Server-Side Encryption

The server encrypts note content with **AES-256-GCM** before writing to disk. Encryption keys are managed via an automatically rotating keyring (`private-notes/.keyring`):

1. `PRIVATE_NOTES_KEY` environment variable (recommended for production)
2. Auto-generated keys that **rotate every 24 hours**

Each note stores a `key_id` referencing the specific key used to encrypt it. Old keys are retained in the keyring until they're older than the note TTL (72h) plus a safety buffer, then pruned by the cleanup script. This limits the blast radius of a key compromise to notes created during that key's active window.

The server holds the keys, so it can theoretically read notes. Use E2E mode if that's a concern.

### End-to-End Encryption (E2E)

The browser generates a random 256-bit key, encrypts content with **AES-GCM via the Web Crypto API**, and sends only the ciphertext to the server. The decryption key travels exclusively in the URL fragment (`#key=...`), which browsers never send to the server.

The server stores ciphertext it cannot decrypt. Even a compromised server cannot read E2E notes.

## Security Design

### Threat Model

- **At rest:** Notes are AES-256-GCM encrypted. Raw content never touches disk.
- **In transit:** Relies on HTTPS (deployment responsibility). E2E mode adds a layer where even the server is untrusted.
- **Brute-force:** Passcode verification is rate-limited (10 attempts, then 1-hour lockout). Passcodes are hashed with Argon2ID.
- **Timing attacks:** Missing notes still run a dummy `password_verify()` to prevent note ID enumeration via response timing.
- **Concurrency:** All view/consume operations use `flock(LOCK_EX)` for atomic read-verify-decrement-write, preventing race conditions on simultaneous requests.
- **CSRF:** All form submissions are protected with session-based CSRF tokens.

### What's Hardened

| Area | Implementation |
|------|---------------|
| Symmetric encryption | AES-256-GCM with 12-byte random IV per note |
| Passcode hashing | Argon2ID via PHP `password_hash()` |
| Note IDs | 128-bit random (`random_bytes(16)`, hex-encoded) |
| Rate limiting | Per-note failed attempt counter with lockout, stored under file lock |
| CSRF protection | Session tokens with `SameSite=Strict` cookies |
| HTTP headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Key rotation | 24-hour automatic rotation via keyring; old keys pruned after TTL expiry |
| File permissions | `0700` directory, `0600` keyring file |
| Timing side-channels | Constant-time passcode verification for missing notes |
| Key isolation | `.keyring` blocked via `.htaccess`, never logged or exposed |
| Input validation | Note IDs validated as 32-char hex; passcode capped at 128 bytes; content capped at 100KB |
| CSP | Nonce-based Content-Security-Policy (no `unsafe-inline`) |

### Post-Quantum Considerations

AES-256-GCM provides approximately 128-bit security against quantum adversaries (via Grover's algorithm), which NIST considers adequate for post-quantum symmetric encryption. For a 72-hour TTL note application, this is more than sufficient.

The encryption functions are cleanly abstracted to support future algorithm upgrades when the PHP/browser ecosystem gains post-quantum support.

## How It Works

```
Create:  Browser ──POST──> Server encrypts ──> Writes note JSON to disk
                                                Returns one-time link + passcode

View:    Browser ──GET───> Server checks note exists, shows passcode form
         Browser ──POST──> Server verifies passcode under file lock
                           Decrypts content, deletes file, returns plaintext

E2E:     Browser encrypts locally ──POST──> Server stores ciphertext
         Browser ──POST fetch──> Server verifies passcode, returns ciphertext
                                 Deletes file
         Browser decrypts locally using key from URL fragment
```

### Note JSON Schema

```json
{
  "type": "server|e2e",
  "key_id": "<hex, server-side only>",
  "ciphertext": "<base64>",
  "iv": "<base64>",
  "tag": "<base64>",
  "passcode_hash": "<argon2id hash>",
  "remaining_views": 1,
  "failed_attempts": 0,
  "locked_until": 0,
  "created_at": 1234567890,
  "expires_at": 1234567890
}
```

## Setup

### Requirements

- Apache with `mod_rewrite`
- PHP 8.0+ with the OpenSSL extension
- Write permissions on the application directory

### Installation

1. Clone the repository into your web root:
   ```bash
   git clone https://github.com/yourusername/send-private-note.git
   ```

2. Ensure the `private-notes/` directory is writable by the web server.

3. (Optional) Set a persistent encryption key for production:
   ```bash
   export PRIVATE_NOTES_KEY=$(openssl rand -base64 32)
   ```
   If unset, a key is auto-generated and stored in `private-notes/.secretkey`.

4. Access via browser: `http://yourserver/once.php/`

### Cleanup

Expired and consumed notes are deleted automatically on view. For additional cleanup, run the included script via cron:

```bash
# Run every hour
0 * * * * php /path/to/cleanup_private_notes.php
```

## Files

| File | Purpose |
|------|---------|
| `index.php` | Entire application -- routing, encryption, HTML output |
| `cleanup_private_notes.php` | CLI utility to purge expired/consumed notes and stale keys |
| `private-notes/.htaccess` | Blocks web access to `.keyring` and `.secretkey` |

## License

[GPL-3.0](LICENSE)
