# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Single-file PHP web application for creating and sharing temporary, self-destructing private notes. Pure PHP, no frameworks, no build step.

## Key Files

- [index.php](index.php) — entire application (routing, encryption, HTML output)
- [cleanup_private_notes.php](cleanup_private_notes.php) — CLI utility to purge expired/consumed notes
- [private-notes/.htaccess](private-notes/.htaccess) — blocks web access to `.secretkey` and `.keyring`

## Running the App

Access via WAMP: `http://localhost/once.php/`

Cleanup expired notes: `php cleanup_private_notes.php`

## Architecture

All logic lives in `index.php`. The router branches on `$method` and `$_GET['note']`:

1. **Create** — `POST action=create` → validates passcode (must be exactly 6 chars), encrypts content, writes `private-notes/note_{32-hex}.json`, returns a share link
2. **View (server-side)** — `GET ?note={id}` shows passcode form; `POST action=view` verifies passcode, decrypts, renders content, deletes file
3. **View (E2E)** — `GET ?note={id}` detects `type=e2e`, serves JS viewer; `POST action=fetch` verifies passcode, returns ciphertext JSON, deletes file; browser decrypts using key from URL `#fragment`

### Encryption Modes

- **Server-side** (`type=server`): PHP encrypts with AES-256-GCM. Keys are managed via a rotating keyring (`private-notes/.keyring`). Key source priority: `PRIVATE_NOTES_KEY` env var → keyring file → auto-generated. Keys rotate every 24 hours; each note stores its `key_id` for decryption lookup. Legacy `.secretkey` files are auto-migrated.
- **End-to-end** (`type=e2e`): Browser generates a 32-byte random key, encrypts with AES-GCM via Web Crypto API, sends only ciphertext to server. Decryption key travels only in the URL `#fragment` (never sent to server).

### Note JSON Schema

```json
{
  "type": "server|e2e",
  "key_id": "<hex, server-side only>",
  "ciphertext": "<base64>",
  "iv": "<base64>",
  "tag": "<base64>",
  "passcode_hash": "<password_hash Argon2ID>",
  "remaining_views": 1,
  "failed_attempts": 0,
  "locked_until": 0,
  "created_at": 1234567890,
  "expires_at": 1234567890
}
```

### Concurrency / Safety

All view/fetch operations open the file with `fopen` + `flock(LOCK_EX)` to atomically read-verify-decrement-write, preventing race conditions on concurrent requests for the same note.

## Security Constraints

- Passcode is always exactly 6 characters; hashed with `password_hash` (Argon2ID default)
- Note IDs are 32-char hex from `random_bytes(16)`
- `html()` helper (`htmlspecialchars`) must wrap all user-derived output
- `.secretkey` and `.keyring` are blocked from web access via `.htaccess`; never expose them or log key material
- `remaining_views` is decremented atomically under file lock before the file is deleted

## Deployment Requirements

- Apache with mod_rewrite + PHP with OpenSSL extension
- Write permissions on application directory
- Set `PRIVATE_NOTES_KEY` env var (base64 or hex-encoded 32-byte value) for production key management
