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
