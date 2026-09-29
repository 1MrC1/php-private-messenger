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
   compare out of band. Its history is worth keeping, because it is a lesson in
   what a document can hide: this file and several commit messages described it
   as derived from the group's exporter secret while the code hashed only the
   sorted member signature keys, which is why two separately keyed groups with
   the same members produced the same number. It now hashes the group id and a
   secret exported from the group at its current epoch as well — so the
   description is finally true, and the gap it hid is closed.

   Also a passphrase-protected recovery file, where the
   passphrase is *generated* (118.9 bits, by rejection sampling over a
   31-symbol alphabet — an earlier `% 31` cost three bits of min-entropy, and
   the figure of ~124 bits quoted here before was simply wrong) rather than
   chosen, because the only
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

   The protocol-level suites — message protection, welcome, treekem, tree
   validation and operations, secret tree, PSK secret, transcript hashes,
   messages, and the three passive-client vectors — are exercised by test code
   OpenMLS keeps behind `#[cfg(test)]`, which no dependent crate can call. They
   run through OpenMLS's own harness instead: `crypto/vectors/upstream-kats.sh`
   fetches the crate from crates.io, **checks its SHA-256 against the `checksum`
   line in `crypto/Cargo.lock`** — the same bytes cargo compiles for our
   WebAssembly, verified rather than assumed — pins the vectors by digest, and
   runs them. Sixteen suites, all passing, against checksum
   `b6b08d90…99a8c8`. Recorded in `docs/security/rfc9420-vectors.md`.

   What that establishes and what it does not: the implementation inside the
   committed artifact is the published OpenMLS 0.9.0 and passes every published
   suite. It says nothing about the wrapper, which adds no protocol logic — the
   two constructions that are ours, the storage framing and the safety number,
   sit outside the protocol and are documented as such.

12. **Revocation that actually reaches the conversation**: revoking a device in
   settings stops it being offered new key packages. On its own that does
   nothing to a device already inside a group — it holds those keys, and no
   server action can take them back, because the server has none. So a client
   still in the conversation publishes the removal:
   `list_participant_devices` returns each participant device's signature key
   and revoked flag (no labels — a key is already public to the group through
   the ratchet tree, a device's name is not, and only a participant may ask),
   and `enforceRevocations()` removes any revoked device that is still a member.
   The interface runs it when a conversation is opened and says so if it fails,
   because a security control that fails quietly is worse than one that is
   absent.

   Proven end to end in `tests/protected_client_runtime_test.js`: a device reads,
   is revoked, is removed, and then cannot read what follows while the remaining
   devices can. Running the check again removes nothing.

   The limit: only a current member can publish a removal, so a conversation
   where every remaining device is offline stays unenforced until one of them
   opens it.

13. **Interoperability across engines**: `crypto/interop/run.mjs` puts one
   device in each of Chromium, Firefox and WebKit and has them hold a real
   conversation in every ordered pair — identity, welcome, a message sealed in
   one engine and opened in another, a reply back, the safety number agreeing
   across engines, a membership change applied, a removal refused to the removed
   device, and exported state surviving a reload. All nine pairs pass. It also
   probes what the client needs besides WebAssembly: a non-extractable AES-GCM
   key, that key surviving IndexedDB, and PBKDF2-SHA512 at 600 000 iterations.
   Versions, timings and limits are in `docs/security/browser-interop.md`.

   Limits, stated there and worth repeating: headless desktop builds on one
   machine, no real mobile browsers, and nothing about interoperability with
   *other* MLS implementations, which is what the protocol-level vectors above
   would show.

   What remains is the one thing that cannot be written here at all: the
   independent review of this integration (#7). Until it happens the wording
   stays as it is — "experimental", "unaudited", and never "end-to-end
   encrypted".

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

1. ~~Write and review the threat model, device lifecycle, recovery design, and
   abuse-handling policy.~~ Written: `threat-model.md`. "Reviewed" belongs to
   gate 5.
2. ~~Select and pin an actively maintained MLS implementation with browser/WASM
   support; validate official vectors and fuzz envelope parsing.~~ OpenMLS 0.9.0,
   pinned exactly and by checksum; 16 known-answer suites plus the reachable ones
   (`rfc9420-vectors.md`); envelopes and commits fuzzed.
3. **Add versioned schema alongside the existing plaintext schema. No
   destructive conversion and no automatic downgrade.** The schema half is done —
   `envelope_version`, protection chosen at creation and irreversible, plaintext
   and envelopes refused in each other's conversations, and since the second
   review a database trigger that enforces it. "No automatic downgrade" was
   marked complete twice and was wrong twice: first because only the protected
   path checked, then because the check raced the write. It is not marked complete
   again here. What can be said is what is tested: the paths that exist refuse,
   the invariant is enforced in the database, and a client no longer takes the
   server's word for whether a conversation is protected.
4. ~~Ship opt-in test conversations with conspicuous verification and backup
   UX.~~ Done: opt-in at creation, an unaudited-encryption banner, a safety
   number to compare, a recovery file.
5. **Commission an independent protocol and implementation audit.** Open, and the
   only gate left. `review-scope.md` is the brief: what to review, what tests
   already cover, and the claims worth attacking.
6. Only after all supported clients pass interoperability, recovery, removal,
   replay, reordering, and rollback tests may the product claim E2EE. Where these
   stand, honestly: interoperability passes across Chromium, Firefox and WebKit
   (`browser-interop.md`); replay, reordering and rollback are covered by
   `tests/mls_fuzz_runtime_test.js` and `tests/mls_fork_runtime_test.js`; removal
   and recovery each failed a second review after being called done once, and are
   now tested against those reproductions — which is evidence, not proof. The
   claim waits on gate 5 regardless, and gate 5 is the one that decides whether
   the rest of this list was read correctly.

## The 2026-09-29 review, and what it changed

An adversarial review of commit `46cc789` found sixteen findings. It is the
reason several statements above are now marked as corrections rather than
claims, and the reason two boxes on #7 went back to unticked. The review report
is not committed here — it describes defects, some still open — but every
finding was reproduced before it was acted on.

**Fixed.**

- *Critical.* The ordinary send, upload and edit paths wrote plaintext into
  protected conversations. `assertProtectionMatches()` guarded only the
  protected path, so the mode boundary did not exist where the writes happened.
  Reproduced against MySQL, including plaintext stored beside a genuine
  envelope. The refusal now lives in `Chat` itself, and an undeterminable
  protection state refuses too.
- *High.* A competing commit from the same epoch was reported
  `already-applied`, which silently skipped a genuine removal. Retries are now
  recognised by exact digest, a stale different commit is a fork, and a forked
  session stops sending.
- *High.* MLS's authenticated sender was discarded in favour of the server's
  `sender_id`. It is now returned, mapped through the directory, and a
  disagreement is shown.
- *High.* The directory's advertised key was never compared with the key inside
  a key package, so a mismatch produced an unremovable device. Admission now
  refuses the mismatch.
- *High.* Admission ignored publication failures while reporting success.
- *High.* Revocation was checked once per page-local record.
- *Low.* The state parser accepted trailing bytes, duplicate keys and a length
  that truncated to zero on wasm32; the recovery passphrase was drawn with
  `% 31`; `compose.yaml` applied four of six migrations; the readiness probe
  checked four of eight tables; the blob cap advertised 8 MiB while the
  transport allowed about 49 KiB.

**Also fixed, in the days after.**

- *The safety number bound nothing but membership*, so two separately keyed
  groups with the same people showed the same number. It now includes the group
  id and a secret exported from the group at its current epoch.
- *Device state was shared across accounts on one origin.* Storage identifiers
  are scoped to the account and the account is sealed inside the record.
- *Any account could exhaust another's key packages.* A claim must name a
  conversation both are in.
- *A reload emptied a protected conversation.* The chat-to-group mapping and the
  text of messages this device has already opened are kept in a store sealed with
  the same non-extractable key, bounded to the most recent five hundred per
  conversation. **Plaintext at rest is a real cost**, named here rather than
  buried: it is sealed, it never leaves the device, and the alternative was a
  messenger that forgot every conversation when the tab closed, which would have
  pushed people back to the plaintext path.
- *No client verified the directory hash chain.* `verifyDirectory()` walks it
  against the head this device last saw, refuses a gap or an entry that does not
  continue that history, and the interface refuses to send while it disagrees.
  The boundary is unchanged and worth repeating: this catches a server that
  rewrites what it has already shown, not one that has lied from the start.
- *The ciphertext retry fingerprint had no caller*, so protected sends had no
  retry protection. They carry a retry identifier now; a replay returns the
  original message and a conflicting one is refused.
- *Encrypted attachments were never linked to their message*, so an in-use blob
  looked identical to an abandoned upload. They are linked, and `pruneOrphans()`
  removes unreferenced ciphertext.
- *The attachment, recovery and admission helpers had no interface calling them*
  — the most embarrassing kind of finding, because this document called them
  shipped. Choosing a file in a protected conversation now encrypts it, a
  decrypted attachment renders as something openable, opening a conversation
  admits devices the other account enrolled since, and a settings entry
  downloads or restores a recovery file.

## The second review, the same day

A second adversarial review took the first round's fixes apart and found eight
more problems, most of them in the seams rather than in the cryptography. That is
the useful shape of a review, and it is recorded here in full because a list of
fixes without the failures that preceded them reads as confidence rather than
history.

- **The plaintext refusal had a race.** The check ran before the transaction that
  wrote, so a send could pass it, protection could commit, and the plaintext
  could commit afterwards. Both sides now take the same `chats` row lock and ask
  again inside the transaction, and
  `migrations/20260929_enforce_protected_plaintext.sql` puts the invariant in the
  database, where no future call site can forget it.
- **Authorship was still forgeable.** The chain hashed neither account nor
  device, so the mapping from key to account came from the same response that was
  lying. The preimage now binds entry type, account, device, public id and key;
  the client recomputes it against the chain it has pinned and pins each key's
  owner on first sighting.
- **A removal could hide beyond the first page** of handshakes, and a message
  beyond the first page of envelopes was never fetched at all. Both paths page
  until the history runs out; a gap or an unreadable handshake stops this device
  sending.
- **A failed publication was forgotten on reload**, while the MLS state it
  invalidated was durable. The block is sealed on the device now.
- **Out-of-order delivery lost messages**, because the group kept no past epochs.
  Eight are kept; the cost is in the threat model.
- **The recovery file could not reopen anything**: it held the keys but not which
  group each conversation used.
- **Key-package exhaustion still worked**, because anyone who can start a
  conversation satisfied the participation check. Claims are bounded per
  claimant, per target, per hour, and replenishment finally has a caller.
- **The client asked the server whether to encrypt.** Protection is irreversible,
  so this device's own record now outranks the server's flag.
- And **one of my own tests passed vacuously** — `\u{1F512}` is not PCRE syntax,
  so the pattern never compiled and the assertion could not fail. It is fixed,
  and it now proves it matches before it is trusted.

**Still open.**

- The independent cryptographic review (#7), which is external by definition.
- Metadata is visible to the server by construction, and always was. Not a
  finding; a documented position.
- Forward secrecy and post-compromise security are whatever MLS gives for the
  epochs a device holds: nothing here forces a periodic key update.
- The directory chain is not key transparency, and cannot become it here. A
  server that withholds an entry it has never shown cannot be caught by any
  amount of chain walking; comparing safety numbers out of band is the answer,
  and it only works if people do it.
- A removal is published by whichever remaining device next opens the
  conversation, so it can sit pending while they are all offline.
- Eight past epochs of keys stay on the device, which is a deliberate trade for
  not losing out-of-order messages.
