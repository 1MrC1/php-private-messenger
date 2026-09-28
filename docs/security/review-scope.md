# Brief for an independent review

The last open gate in `e2ee-readiness.md` is an independent cryptographic review
of **this integration**. It cannot be closed from inside this repository: no
amount of self-testing is an independent review, and OpenMLS's own
[SRLabs audit](https://blog.phnx.im/openmls-independent-security-audit/) covers
the library, not the wrapper, envelope format, schema, directory or recovery
design around it.

This file exists so that review is cheap to commission and cheap to perform: what
to look at, in what order, what is already covered by tests so no budget is spent
re-deriving it, and which claims are worth attacking.

## What to review, in rough order of consequence

1. **`crypto/src/session.rs`** (~545 lines) — the whole wrapper. It calls
   `MlsGroup` and marshals bytes. Two constructions are ours and sit outside the
   protocol: the storage framing in `encode_storage`/`decode_storage` (OpenMLS's
   own `MemoryStorage` serialiser is `test-utils`-only and documented as being for
   known-answer tests), and `safety_number()`, a SHA-256 over sorted member
   signature keys. Both deserve scrutiny. So does `apply_handshake()`'s use of
   "the message's epoch is behind ours" to recognise an already-applied commit.
2. **`assets/js/protected-chat.js`** — key storage (non-extractable AES-GCM
   wrapping key in IndexedDB), the recovery file, attachment encryption, and the
   claim/admit/remove flows. This is where a browser-side mistake would live.
3. **`classes/ProtectedChat.php`** — what the server accepts and stores.
   Particularly: `parseEnvelope()`, the refusal to mix plaintext and envelopes in
   one conversation, the irreversibility of protection, and the epoch-rollback
   check.
4. **`classes/DeviceDirectory.php`** — one-time key package claiming under a
   lock, the hash chain, revocation, and `participantDevices()`.
5. **`classes/EncryptedBlob.php`** — the deliberately reduced checks on
   ciphertext, and whether the reduction is bounded where it is claimed to be.
6. **The threat model itself** — `threat-model.md` ends with six assumptions we
   would most like someone else to attack.

## What is already covered, so you need not re-derive it

- **RFC 9420 conformance of the library**: 16 known-answer suites, including
  passive-client, against a crate archive checked byte for byte against
  `crypto/Cargo.lock` — `docs/security/rfc9420-vectors.md`.
- **Reachable vectors in-repo**: crypto-basics, key schedule, tree math, each
  verified to fail on one flipped digit — `crypto/tests/rfc9420_vectors.rs`.
- **Cross-engine interop**: all nine ordered pairs of Chromium, Firefox and
  WebKit, plus the browser features the client depends on —
  `docs/security/browser-interop.md`.
- **Fuzzing**: 400 mutations of a sealed message and 200 of a commit; refusal of
  replay, truncation, extension, splicing; the epoch never moves on a mutated
  commit — `tests/mls_fuzz_runtime_test.js`.
- **Multi-device behaviour**: three devices across an add and a removal, a device
  enrolled later admitted without duplicating one already there, a removed device
  unable to read what follows, a revoked device removed and stopped, a recovery
  file catching up — `tests/mls_session_runtime_test.js`,
  `tests/protected_client_runtime_test.js`.
- **Reproducibility**: rebuilding the WebAssembly reproduced the committed
  artifact byte for byte, and `test-utils` is confined to `[dev-dependencies]` —
  `crypto/BUILDING.md`.

## Claims we would most like attacked

1. The server cannot read message or attachment content in a protected
   conversation, **even though it stores both**.
2. Nothing in the protected path can be made to fall back to plaintext, in either
   direction, by any input a client or a malicious server can send.
3. A device removed or revoked cannot read anything sent after the removal commit.
4. The retry fingerprint over ciphertext is not an oracle for guessed plaintext.
5. The recovery file's strength does not depend on PBKDF2 being strong.
6. Nothing the server returns can cause a client to accept a key it did not
   expect without the safety number changing.

## Out of scope

- Metadata confidentiality. Deliberately not claimed; see the threat model.
- The plaintext core of the messenger, which makes no confidentiality claim
  against the server.
- Cross-site scripting as a *complete* break of the browser key store. We agree it
  is one. Bugs that make XSS reachable are very much in scope.
- Deployment configuration, except where the documentation leads someone into an
  insecure one — that is a documentation bug and welcome.

## How to build and run everything

```sh
# the ordinary suite: no toolchain beyond PHP and Node
for t in tests/*_test.php; do php "$t"; done
for t in tests/*_runtime_test.js; do node "$t"; done

# the wrapper, natively, including the reachable RFC 9420 vectors
cd crypto && cargo test --release

# rebuild the WebAssembly and verify it matches what is committed
wasm-pack build --target web --release --out-dir pkg
sha256sum pkg/pm_mls.js pkg/pm_mls_bg.wasm
cat ../assets/vendor/mls/ARTIFACTS.sha256

# the protocol-level suites, through OpenMLS's own harness
crypto/vectors/upstream-kats.sh

# cross-browser, with Playwright's browsers installed
node crypto/interop/run.mjs
```

Protected conversations are off unless `PM_PROTECTED_CHATS_ENABLED=1`; see
`.env.example`. `compose.yaml` brings up a working deployment.

## What a useful deliverable looks like

Findings with severity and reproduction, and an explicit statement about the six
claims above — including which ones the review did **not** attempt. A review that
silently omits a claim cannot close the gate for it.

## Reporting

Privately, through GitHub's private vulnerability reporting on this repository —
see `SECURITY.md`. There is no bug bounty. If you have reviewed this and are
willing to be named, say so and it will be recorded in issue #7 alongside the
scope you covered.
