# php-private-messenger

**English** · [简体中文](README.zh-Hans.md)

Self-hosted private messaging in plain PHP 8 and MySQL. No framework, no build
step, no bundler, no JavaScript toolchain — clone it, point a web server at it,
run `composer install`, and it works.

It is a small, deliberately boring codebase with an unusually strict security
posture: a hardened session model, two-factor authentication with encrypted
TOTP secrets, private media served only through authenticated endpoints, upload
malware scanning that fails closed, and a content security policy that forbids
inline handlers and `eval`. Every one of those properties has a regression test.

> **This is not end-to-end encrypted.** TLS protects data in transit, but the
> server can read stored messages and attachments. See
> [docs/security/e2ee-readiness.md](docs/security/e2ee-readiness.md) for the
> design that would be required, and do not describe a deployment of this code
> as E2EE.

## Screenshots

All sample data below is invented; no real account or conversation appears.

| Conversation | Settings |
|---|---|
| ![A direct message thread, with a quoted reply, read receipts and unread badges in the conversation list](docs/screenshots/conversation.png) | ![The settings panel open on the profile section](docs/screenshots/settings.png) |

| Sign in | Mobile |
|---|---|
| ![The sign-in dialog, with login and register tabs and a language selector](docs/screenshots/sign-in.png) | <img src="docs/screenshots/mobile.png" alt="The conversation list on a phone-width screen, with a bottom navigation bar" width="280"> |

## Features

- One-to-one and group chats, replies, reactions, edits, deletes, read receipts,
  typing indicators, and message search.
- Attachments (images, documents, archives) with MIME, image, and archive
  validation, plus optional ClamAV scanning.
- Accounts with TOTP two-factor authentication and hashed, peppered backup codes.
- Five interface languages (English, Spanish, Arabic, Simplified and Traditional
  Chinese) with right-to-left support.
- Responsive single-page interface; mobile layout with a bottom navigation bar.
- **No third-party requests.** Bootstrap and Font Awesome are vendored in
  `assets/vendor/`, so the app loads nothing from a CDN, works with outbound
  traffic blocked, and tells no one who is using your instance. The content
  security policy names no external origin — `tests/csp_posture_test.php` keeps it
  that way.

The interface calls itself **Messenger**. That name is a placeholder: it lives in
`index.html` and the `locales/*.json` catalogs, so rename it to whatever you like —
just keep the English strings in `index.html` identical to `locales/en.json`, or the
i18n test will tell you.

## Requirements

- PHP **8.2** or **8.3**, with `fileinfo`, `gd`, `iconv`, `mbstring`, `mysqli`,
  `pcntl`, `sodium`, and `zip`. APCu is optional but recommended (it backs rate
  limiting and media validation caching).
- MySQL 8 or MariaDB 10.5+.
- Apache with `mod_rewrite` and `mod_headers`, or nginx with the equivalent rules
  translated (see [Deployment](docs/deployment.md)).
- Composer.

## Quick start

The fastest way to try it:

```sh
git clone https://github.com/<you>/php-private-messenger.git
cd php-private-messenger
docker compose up --build        # then open http://127.0.0.1:8088
```

That brings up nginx, PHP-FPM and MySQL, applies `schema.sql` and every
migration, and serves the app through the same rules a real deployment uses, so
what you exercise locally has the same exposure surface. It is a **development**
stack: the database password is a published string, there is no TLS, and uploads
are refused because no malware scanner is attached. See [`compose.yaml`](compose.yaml).

### Installing it yourself

```sh
git clone https://github.com/<you>/php-private-messenger.git
cd php-private-messenger
composer install --no-dev
cp .env.example .env     # then fill it in; see Configuration
mysql -u root -p -e "CREATE DATABASE messenger CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
mysql -u root -p messenger < schema.sql
for m in migrations/*.sql; do mysql -u root -p messenger < "$m"; done
```

Point the web server's document root at the repository root. The shipped
`.htaccess` is **load-bearing security**, not cosmetic: it restricts which PHP
files are reachable, blocks direct access to `uploads/`, and sets the security
headers. Do not drop it, and if you use nginx, port every rule.

## Configuration

Nothing is read from a committed file. All configuration comes from the
environment of the PHP process, and every consumer fails closed rather than
falling back to a default. Copy `.env.example` and supply real values through
your PHP-FPM pool (`env[...]`), Apache (`ProxyFCGISetEnvIf`), or systemd.

| Variable | Required | Purpose |
|---|---|---|
| `PM_DB_HOST`, `PM_DB_NAME`, `PM_DB_USERNAME` | yes | Database connection. |
| `PM_DB_PASSWORD` | yes | Database password; **minimum 32 characters.** |
| `PM_BACKUP_CODE_PEPPER` | yes | Pepper for two-factor backup codes; minimum 32 characters. Changing it invalidates every existing backup code. |
| `PM_TOTP_ENCRYPTION_KEY` | yes | Encrypts TOTP secrets at rest. Losing it locks every account out of 2FA. |
| `PM_CLAMD_ENDPOINT` | no | ClamAV daemon, Unix socket only (`unix:///run/clamd.sock`). TCP endpoints are deliberately rejected. Without it, uploads are refused — see [Deployment](docs/deployment.md). |
| `PM_MESSAGE_IDEMPOTENCY_ENABLED` | no | Set to exactly `1` to enable `client_message_id` send de-duplication. Leave unset until the schema migration is applied everywhere. |

`config/database.php` also defines `SITE_URL`, which must match your real origin
— the API rejects cross-origin state changes by comparing against it.

## Database

`schema.sql` creates the seven tables the application uses — `users`, `chats`,
`chat_participants`, `messages`, `message_status`, `typing_indicators` and
`backup_codes` — ordered so foreign keys resolve as they are created. Apply it to
an empty database, then run everything in `migrations/` in filename order.

Those migrations are **idempotent**: each one checks `information_schema` and
builds its DDL only if the column is missing, so running them against a fresh
database is safe and re-running them is harmless. Two of them also have a PHP
half (`*_encrypt_totp_secrets.php`, `*_hash_legacy_backup_codes.php`) that
rewrites existing rows; on a new install there is nothing to rewrite, but run
them anyway so the tracked state is consistent, and take a backup first on an
existing one.

`tests/schema_test.php` checks that `schema.sql` covers every table the code
queries and carries no data.

## Architecture

```
index.html          single-page interface; all markup lives here
api/*.php           six POST-JSON endpoints, thin action dispatchers
classes/*.php       the actual logic (Chat, Auth, TwoFactor, Safe*, I18n, …)
assets/js/*.js      six scripts, loaded in order, no modules
locales/*.json      one catalog per language
tests/*.php|js      plain scripts; no PHPUnit, no Jest
```

**Request path.** Everything is `index.html` plus six endpoints:
`attachment`, `auth`, `avatar`, `chat`, `profile`, `settings`. Any other `.php`
file is unreachable over HTTP by design — the allow-list lives in `.htaccess`,
and `tests/repository_exposure_test.php` pins it. Adding an endpoint means
editing that rule.

**Endpoints are thin.** They validate input, enforce same-origin, and apply rate
limits *before opening a database connection*, then delegate to a class. Keep
that ordering; `tests/protected_api_pre_db_rate_limit_test.php` enforces it.

**Private media.** Stored files are never addressable under `/uploads`. Avatars
and attachments are delivered only by `api/avatar.php` and `api/attachment.php`
after session, authorization, path, MIME, and file-identity checks, with
per-account and per-source byte budgets.

**Front end.** Six scripts load in a fixed order. `security-hardening.js`
overrides the legacy bundle's DOM rendering with safe node builders and gates
application start-up on reaching its own last line — so a parse failure leaves
the interface inert instead of falling back to unsafe rendering. Do not
reintroduce `innerHTML` rendering, and do not add code after that gate. All six
share one cache-busting query string; bump every occurrence together.

**Localization.** `I18n::encodeResponse()` translates only the top-level
`message`/`error` of a JSON envelope; chat and profile data stays
language-neutral. Every visible English string in `index.html` must exist
verbatim in `locales/en.json`, and all five catalogs must have identical keys and
placeholders — `tests/i18n_catalog_test.php` checks all of it.

## Tests

No PHPUnit and no Jest; tests are plain scripts that print `PASS:` lines and exit
non-zero on failure.

```sh
for t in tests/*_test.php; do php "$t"; done          # 21 PHP suites
for t in tests/*_runtime_test.js; do node "$t"; done   # 2 client suites
php tests/i18n_catalog_test.php                        # a single suite
```

Lint the way the workflows do:

```sh
git ls-files -z '*.php' ':!:vendor/**' | xargs -0 -n1 php -l
git ls-files -z '*.js' | xargs -0 -n1 node --check
composer audit --locked
```

They are pure unit tests: no database, no network, no fixtures to provision.
Many of them assert on source text, so they double as a guard against
accidentally removing a security control.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: run the suite before opening a
pull request, don't reformat untouched lines (the tree has historical whitespace
debt), and expect changes that weaken a security control to need a test
explaining why.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
