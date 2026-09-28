# End-to-end encryption readiness

Status: design decision; this project does **not** currently claim end-to-end
encryption. TLS protects transport, but the application server can read stored
message and attachment content.

## Decision

Use the IETF Messaging Layer Security (MLS) protocol for authenticated group
key agreement rather than designing a custom message cipher. The normative
protocol is [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), with the
deployment model and security considerations described by
[RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html). Browser cryptographic
operations must use an audited MLS implementation and the Web Cryptography API;
ad-hoc JavaScript cryptography is not acceptable.

Do not label a partial rollout as E2EE. A production release requires an
independent cryptographic review, protocol test vectors, multi-device recovery,
and downgrade protection.

## Required architecture

- Give every device its own signing identity, MLS credential, key package, and
  revocation state. Bind device enrollment to the existing authenticated
  account and a recent password/second-factor proof.
- Maintain a verifiable device directory. Users need safety-number or QR
  verification, and the service needs an append-only/key-transparency design so
  the server cannot silently substitute a device key.
- Store only versioned ciphertext envelopes for protected chats: protocol
  version, conversation identifier, MLS epoch, sender leaf, content type,
  ciphertext, and authenticated associated data. Reject unknown versions and
  epoch rollback.
- Encrypt each attachment locally with a fresh content key and authenticated
  chunk framing. Put only the encrypted attachment key and authenticated digest
  in the MLS application message. Never reuse nonces or derive them from a
  filename.
- Keep a random logical message identifier for retry deduplication. In E2EE
  mode, bind it to the authenticated ciphertext envelope; the current
  plaintext fingerprint must not be used as a content oracle.
- Make key recovery explicit: verified device-to-device transfer or a
  passphrase-protected encrypted backup. The server must not possess an
  unwrapped recovery key. Explain that losing every device and the recovery
  secret loses message history.
- Block protected sends when any active participant lacks a compatible client.
  Never silently fall back to plaintext. Surface additions, removals, and key
  changes as security events in the conversation.

## Product and operations consequences

Server-side search, link previews, content moderation, and plaintext backups do
not work for protected conversations. Malware scanning also moves to the
sender/recipient devices: the server-side ClamAV gate introduced for current
plaintext uploads cannot inspect ciphertext without breaking E2EE. Encrypted
attachments still need strict size/rate limits and safe download handling.

The service will continue to observe delivery metadata unless a separate
metadata-hiding design is adopted. E2EE must not be described as anonymity.

## What exists today

Two pieces of groundwork have landed. Neither encrypts anything.

1. **The origin no longer trusts a third party** (see below). This was a
   prerequisite, not a feature.
2. **Storage for protected conversations**, behind `PM_PROTECTED_CHATS_ENABLED`:
   `classes/ProtectedChat.php`, four tables added by
   `migrations/20260928_add_chat_protection_and_envelopes.sql`, and actions on
   the existing `api/chat.php`. The server stores opaque ciphertext and relays
   MLS handshake material; it performs no cryptography and cannot tell whether
   what a client called ciphertext actually is any.

   Decisions worth keeping: protection is chosen when a conversation is created
   and is irreversible, because upgrading would leave the server holding the
   plaintext history of a conversation the interface had begun calling
   protected; a protected message stores `content = ''`, so `LIKE`-based search
   fails closed with no extra code; and the retry fingerprint has a second
   domain computed over ciphertext, so it stops being an offline oracle for
   guessed plaintext.

3. **The MLS engine**: `crypto/` wraps OpenMLS 0.9.0 and is compiled to
   WebAssembly, committed with checksums. `self_test()` performs a full
   two-party exchange — identities, key package, group, welcome, seal, open —
   and it passes in a browser. The engine works; the messenger around it does
   not exist yet.

4. **Device identity and key transport**: `classes/DeviceDirectory.php` with
   three more tables. Devices, not accounts, are MLS members. Key packages are
   consumed exactly once under a lock, a revoked device stops being offered and
   loses its unclaimed packages, and every change is appended to a hash chain a
   client can verify. That chain detects a server that later rewrites history;
   it is not key transparency, and it does not catch a server that lies
   consistently to a client which has never seen the truth.

5. **The browser client**: `assets/js/protected-chat.js` enrolls a device,
   protects a conversation, admits the other account's devices, sends, receives
   and resumes after a reload. Session state lives in IndexedDB wrapped with a
   non-extractable AES-GCM key. `tests/protected_client_runtime_test.js` drives
   two devices through a simulated server with the real MLS build and asserts
   the server holds ciphertext that does not contain the message.

6. **Visible state**: the chat list marks protected conversations and a banner
   states, in all five languages, that the encryption is unaudited and that
   search, previews and malware scanning do not work there. Not a padlock — that
   symbol implies a guarantee this does not have, and a test fails if one
   appears.

7. **The interface**: an option when starting a conversation, an enrollment
   dialog demanding the password and a second factor, sending routed through the
   encrypting client, and decrypted text written into the rows the existing
   renderer drew.

8. **Encrypted attachments**: each file gets a fresh AES-GCM content key, the
   ciphertext goes to a separate blob store, and the key travels inside the
   sealed envelope. The server therefore **cannot scan these files for
   malware** — the ordinary pipeline's MIME allow-list, image and archive
   parsing and fail-closed ClamAV scan all need readable bytes. The interface
   states that loss in all five languages rather than hiding it.

   Note what actually protects an attachment: AES-GCM authentication, because
   the key came through the sealed envelope. The digest the server reports is a
   check against corruption, not against the server itself, which could report a
   digest matching whatever it served.

9. **Verification, recovery and removal**: a safety number both sides can
   compare out of band, derived from the group's exporter secret so it changes
   if the membership does; a passphrase-protected recovery file, where the
   passphrase is *generated* (~124 bits) rather than chosen, because the only
   key derivation a browser offers without more WebAssembly is PBKDF2 and a
   generated passphrase does not depend on the derivation being strong; and
   member removal, so a lost device stops being able to read.

   Three properties are now proven by tests rather than asserted in prose:
   `tests/mls_fuzz_runtime_test.js` puts 400 deterministic mutations of a sealed
   message through `open()` and requires every one to be refused or to yield
   something other than the plaintext, requires a replayed message to be
   refused, and requires the session to still work afterwards;
   `tests/mls_session_runtime_test.js` requires that a removed device cannot
   read what is sent after its removal.

10. **Staying in step, and a bug this found**: a membership change moves the
   committer to a new epoch. Until now nothing applied those commits on the
   other devices, so every existing member was left in the old epoch and would
   have stopped being able to read as soon as anyone was added or removed — and
   there was no way to admit a device enrolled after a conversation started, or
   to remove one at all. `apply_handshake()` applies a commit found in the
   server's queue, reporting `applied`, `already-applied`, `unknown-group`,
   `proposal` or `not-a-handshake` instead of throwing, because a client walking
   a shared queue must be able to tell "not mine" from "broken". `admitDevices()`
   adds a later device and skips any already in the group, which otherwise gets
   two leaves. `removeMember()` publishes a removal.

   Envelopes now declare the epoch and leaf they really came from, read from the
   group rather than sent as `0`. That constant had quietly disabled the server's
   epoch-rollback check, and a test now fails if it returns.

11. **Conformance against the published answers**: the MLS working group's own
   RFC 9420 known-answer tests run in `crypto/tests/rfc9420_vectors.rs` — tree
   math and the key schedule through OpenMLS's own runners, `crypto-basics`
   through the provider this project compiles in. The vectors are pinned by
   digest and `tests/crypto_artifact_test.php` verifies those digests with no
   Rust toolchain, because vectors that can be edited to match a failing build
   prove nothing. Each of the three suites was checked to fail on a single
   flipped digit before being trusted.

   The limit is worth stating plainly: the suites that would demonstrate
   *protocol* conformance — message protection, welcome, treekem, transcript,
   secret tree, PSK secret, passive client — need OpenMLS internals that a
   dependent crate cannot reach, so they do not run. What runs covers the
   primitives, the label encodings and the epoch key schedule.

   What remains is the one thing that cannot be written here: the independent
   review of this integration (#7), the protocol-level vectors above, and a
   browser interoperability matrix. Until those land the wording stays as it is
   — "experimental", "unaudited", and never "end-to-end encrypted".

## Prerequisite: nothing else may serve script into this origin

Any host in `script-src` can run code in the origin that would hold the keys.
Until 2026-09-28 this application loaded Bootstrap, jQuery and Font Awesome from a
public CDN, which meant a third party could have served script into the page that
holds private key material. No end-to-end encryption claim is defensible while
that is true, no matter how good the protocol underneath is.

Those dependencies are now vendored in `assets/vendor/`, and the application
policy names no external origin in `script-src`, `style-src`, `font-src` or
`connect-src`. `tests/csp_posture_test.php` fails the build if one returns.

Two related facts for whoever implements the protocol:

- The policy currently has no `'wasm-unsafe-eval'`, so a WebAssembly MLS
  implementation **cannot instantiate** until that is deliberately added, and
  `worker-src 'none'` forbids moving cryptography off the main thread. Both are
  deliberate weakenings to be argued for in review, not slipped in.
- `assets/js/security-hardening.js` replaces the legacy rendering paths at load
  time; it does not delete them. That is sound for message rendering and is *not*
  a sufficient last line of defence for long-lived key material. The honest
  boundary this design can defend is the server operator's database and backups —
  not a browser-side compromise. A cross-site scripting bug defeats it.

## Safe rollout gates

1. Write and review the threat model, device lifecycle, recovery design, and
   abuse-handling policy.
2. Select and pin an actively maintained MLS implementation with browser/WASM
   support; validate official vectors and fuzz envelope parsing.
3. Add versioned schema alongside the existing plaintext schema. No destructive
   conversion and no automatic downgrade.
4. Ship opt-in test conversations with conspicuous verification and backup UX.
5. Commission an independent protocol and implementation audit.
6. Only after all supported clients pass interoperability, recovery, removal,
   replay, reordering, and rollback tests may the product claim E2EE.
