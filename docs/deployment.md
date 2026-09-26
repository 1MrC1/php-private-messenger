# Deployment

This describes the runtime the application expects. Every path and account name
below is an example — substitute your own. Nothing here contains credentials,
and none should ever be committed.

## Web server

Point the document root at the repository root. The shipped `.htaccess` carries
security controls, not conveniences:

- Only `api/attachment.php`, `api/auth.php`, `api/avatar.php`, `api/chat.php`,
  `api/profile.php` and `api/settings.php` are reachable. Every other `.php`
  path, every dot-path, and the `classes`, `config`, `docs`, `migrations`,
  `tests` and `vendor` directories are denied.
- `uploads/` is denied outright. Stored media is delivered only by the
  authenticated endpoints.
- `LimitRequestBody` per endpoint mirrors the stricter in-application limits, so
  oversized bodies are rejected before PHP parses them. If you raise an upload
  limit in PHP, raise it here too or the request never arrives.
- Two content security policies are emitted, switched by the `PM_PRIVATE_MEDIA`
  environment flag: a sandboxed `default-src 'none'` for media responses, and the
  application policy elsewhere.

**On nginx**, translate all of the above before going live. A config that merely
serves the files leaves every internal PHP file reachable. Verify with:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://example.test/            # 200
curl -sS -o /dev/null -w '%{http_code}\n' https://example.test/classes/Chat.php   # 403
curl -sS -o /dev/null -w '%{http_code}\n' https://example.test/uploads/avatars/x  # 403
```

Consider duplicating the critical denials in the server configuration as well as
`.htaccess`, so a compromised application process cannot remove them.

## PHP

PHP 8.2 or 8.3 with `fileinfo`, `gd`, `iconv`, `mbstring`, `mysqli`, `pcntl`,
`sodium` and `zip`. APCu is optional; without it, rate limiting and media
validation fall back to slower paths.

Run the pool as its own unprivileged account (`messenger` in these examples), not
as the web server user, and keep sessions outside the document root.

## Session storage

Sessions live in a private directory owned by the service account. Every
directory in the path must be traversable by it — a `0700 root:root` parent makes
`session_start()` fail even when the child has the right owner.

The tracked policy in
[`security/messenger-runtime.tmpfiles.conf`](security/messenger-runtime.tmpfiles.conf)
creates the expected layout:

```sh
install -o root -g root -m 0644 \
  docs/security/messenger-runtime.tmpfiles.conf \
  /etc/tmpfiles.d/messenger-runtime.conf
systemd-tmpfiles --create /etc/tmpfiles.d/messenger-runtime.conf
namei -l /var/lib/messenger/sessions
runuser -u messenger -- test -w /var/lib/messenger/sessions
```

Point `session.save_path` at `/var/lib/messenger/sessions`. Session files should
end up `0600` and owned by the service account; the application verifies this
before starting a session and refuses otherwise.

## Configuration

All configuration comes from the process environment — see the table in the
[README](../README.md) and `.env.example`. Supply it through the PHP-FPM pool:

```ini
env[PM_DB_HOST] = 127.0.0.1
env[PM_DB_NAME] = messenger
env[PM_DB_USERNAME] = messenger
env[PM_DB_PASSWORD] = ...
env[PM_BACKUP_CODE_PEPPER] = ...
env[PM_TOTP_ENCRYPTION_KEY] = ...
```

Keep the file root-owned and mode `0600`. Back up `PM_TOTP_ENCRYPTION_KEY`
separately from the database: with the database but not the key, nobody can use
two-factor authentication; with both in one backup, an attacker who takes that
backup has both halves.

## Malware scanning

Uploads fail closed unless `MalwareScanner` gets one clean verdict for the exact
bytes about to be stored. Set:

```text
PM_CLAMD_ENDPOINT=unix:///run/clamav/clamd.sock
```

Unix sockets only; TCP endpoints are rejected deliberately. Give the socket
directory mode `0750` owned `root:messenger` and the socket `0660`, expose no TCP
listener, and keep definitions fresh (alert if they are missing or more than a
few hours old). Run the daemon with a read-only root filesystem, all
capabilities dropped, `no-new-privileges`, and CPU/memory/PID limits.

If you choose to run without a scanner, understand that uploads will be refused
outright — that is the intended failure mode, not a bug.

## Database

Apply `migrations/` in filename order. Two of them are staged rollouts:

- **TOTP secret encryption** (`20260808_encrypt_totp_secrets.*`) and **backup
  code hashing** (`20260808_hash_legacy_backup_codes.php`) migrate existing rows.
  Run the SQL first, then the PHP one-shot, and back up before either.
- **Message idempotency** (`20260808_add_message_idempotency.sql`) is gated by
  `PM_MESSAGE_IDEMPOTENCY_ENABLED`. Keep the flag unset until the schema is
  applied and every application node runs compatible code; then set it to exactly
  `1` and reload. Unset it and reload before any rollback — it is the immediate
  kill switch, and a positive schema check may stay cached for five minutes.

Set the MySQL session time zone to UTC (`+00:00`); the application assumes stored
timestamps are UTC and formats them client-side.

## Backups and monitoring

At minimum: a nightly database dump plus the `uploads/` tree, with a checksum
manifest, stored off-host and encrypted. A local copy is not disaster recovery.

Worth alerting on: the scanner being unreachable or its definitions stale, the
socket's ownership or mode changing, a spike in `4xx`/`5xx` from the API
endpoints, and backup age. If you reconcile orphaned upload files, keep the job
read-only and review before deleting anything.
