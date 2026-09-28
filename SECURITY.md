# Security policy

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Security" → "Report a vulnerability").

Please include what you did, what happened, and what you expected. A minimal
reproduction is worth more than a scanner report. There is no bug bounty.

## Scope

This project is self-hosted, so the deployment matters as much as the code. Bugs
in the code are in scope. A misconfigured deployment usually is not, though
reports that the documentation *leads* people into an insecure configuration are
very welcome.

## What this software does not do

It is **not end-to-end encrypted.** The server can read stored messages and
attachments. This is a deliberate, documented design position, not an oversight
— see [docs/security/e2ee-readiness.md](docs/security/e2ee-readiness.md). Reports
that "the server can read messages" will be closed as by-design; reports that a
*deployment* claims E2EE are a documentation bug worth raising.

## Protected conversations are experimental and unaudited

There is an opt-in encrypted path, off unless `PM_PROTECTED_CHATS_ENABLED=1`. It
wraps OpenMLS (RFC 9420) compiled to WebAssembly. It has **not** had an
independent cryptographic review, the interface says so in all five languages, and
nothing in the project may call it end-to-end encrypted until the gate in
[docs/security/e2ee-readiness.md](docs/security/e2ee-readiness.md) is closed.

Findings against that path are extremely welcome — it is the part most in need of
outside eyes. [docs/security/review-scope.md](docs/security/review-scope.md) says
what to look at, what is already covered by tests, and which claims are worth
attacking; [docs/security/threat-model.md](docs/security/threat-model.md) states
what is and is not being defended against, including that cross-site scripting in
the origin defeats browser-held keys entirely.

Delivery metadata (who talked to whom, and when) is stored in plain form and is
visible to whoever runs the server.

## Security properties worth preserving

Several tests exist specifically to stop a refactor from quietly removing a
control. If you find one of these obstructive, that is the test doing its job:

- Only the six allow-listed API entry points are reachable over HTTP.
- Rate limits are reserved *before* a database connection is opened.
- Stored media is only reachable through the authenticated delivery endpoints.
- Uploads fail closed when the malware scanner is unreachable.
- The front end never renders HTML strings; `security-hardening.js` gates
  start-up on its own successful load.
- TOTP secrets are encrypted at rest and backup codes are hashed and peppered.
