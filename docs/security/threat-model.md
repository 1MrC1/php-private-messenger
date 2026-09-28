# Threat model for protected conversations

The first rollout gate in `e2ee-readiness.md` asks for this in writing before a
review, because a reviewer cannot judge a design whose intended guarantees are
implicit. It describes the **experimental, unaudited** protected-conversation
path, not the plaintext core, which makes no confidentiality claim against the
server at all.

## Who is being defended against, and how well

| Adversary | Capability assumed | What this design does |
|---|---|---|
| **Someone who steals the database or a backup** | Full read of MySQL and `uploads/` | Defended. Message content is a sealed MLS envelope; attachments are AES-GCM ciphertext whose key travels inside the envelope. `messages.content` is the empty string. Nothing stored decrypts without a device's private state. |
| **The server operator, passively** | Reads storage and all traffic, does not modify | Defended for content. **Not** for metadata: who talks to whom, when, how often, how large, and the membership of every group are all visible by construction. |
| **The server operator, actively** | Adds a device, substitutes a key package, rewrites the directory, withholds or reorders handshakes | Partly defended, and this is the sharpest edge. The directory is a hash chain, so a *rewrite* of history is detectable. It is **not key transparency**: a server that lies consistently to a client which has never seen the truth is not caught by the chain. The safety number is what catches a substituted key — and only if two people actually compare it out of band. Withholding a handshake is a denial of service, not a read. |
| **A network attacker** | Full control of the network, no valid certificate | Defended by TLS, then by MLS underneath it. |
| **Someone holding a revoked or removed device** | All state that device ever had | Defended forward, not backward. It keeps what it already received — it holds those keys — and cannot read anything sent after the removal commit is published. Publishing that commit requires a remaining member to open the conversation. |
| **Cross-site scripting in the origin** | Runs script in the page | **Not defended.** This is stated rather than hedged: script in the origin reaches the WebAssembly memory and the IndexedDB handles while a tab is open. The content security policy (no inline script, no `eval`, `'wasm-unsafe-eval'` only), the node-building renderers, and the absence of any third-party script in `script-src` are what stand in the way. There is no second line behind them. |
| **Someone with the device unlocked** | Local access to a logged-in browser | Not defended. The wrapping key is non-extractable, so raw key bytes cannot be exported, but the session can be used. |
| **A malicious participant** | Is legitimately in the conversation | Out of scope by definition. They can read what they are sent and can screenshot it. |

## What is deliberately not claimed

- **No forward secrecy claim beyond MLS's own.** Epochs advance on membership
  changes; this project does not force periodic updates, so an attacker with a
  device's state reads the current epoch.
- **No post-compromise security claim** without a key update, which nothing in
  the interface currently triggers on a schedule.
- **No metadata protection.** No cover traffic, no sealed sender, no padding
  beyond what MLS does.
- **No protection against a malicious server denying service.** It can withhold
  handshakes and envelopes; clients notice missing messages, not censorship.
- **No malware scanning inside protected conversations.** The ordinary pipeline's
  MIME allow-list, image and archive parsing, and fail-closed ClamAV scan all
  need readable bytes. Ciphertext has none. The interface says so in all five
  languages.

## Device lifecycle

1. **Enrollment** happens in settings, behind the current password *and* a fresh
   second factor — the same gate as disabling 2FA, reusing that code path rather
   than inventing one. The device generates its identity locally; the server sees
   a signature public key, a credential, and one-time key packages.
2. **Joining a conversation**: key packages are claimed exactly once, under a
   lock, by conditional update. A device already in the group is skipped rather
   than added twice. If any live device of the other account has no key packages
   left, starting the conversation is refused rather than silently excluding it.
3. **Staying in step**: commits are applied from the server's ordered queue. A
   device that skips them is stranded in a dead epoch, so `apply_handshake()`
   reports `applied`, `already-applied`, `unknown-group`, `proposal` or
   `not-a-handshake` instead of throwing, and the interface syncs whenever a
   conversation is opened.
4. **Revocation** marks the device in the directory, drops its unclaimed key
   packages, and appends to the hash chain. That alone does not stop it reading:
   a remaining member publishes a removal commit, which the client does when a
   conversation is opened. Until some remaining device is online, the removal is
   pending.
5. **Loss** is handled by a recovery file, below, or by enrolling a new device —
   which can read only from the epoch it joins.

## Recovery design

A recovery file is AES-GCM over the device's exported session state under a key
derived with PBKDF2-SHA512 at 600 000 iterations. Two decisions worth attacking
in review:

- **The passphrase is generated, not chosen** (~124 bits, unambiguous alphabet,
  grouped for transcription). PBKDF2 is the strongest derivation a browser offers
  without shipping more WebAssembly, and it is materially weaker against a GPU
  than Argon2id. A generated passphrase does not depend on the derivation being
  strong; a human-chosen one would.
- **The file is download-only.** The server never receives it. Handing it an
  encrypted copy would make the passphrase the only barrier for whoever holds the
  database — the very adversary the design is strongest against.

A file written before a membership change restores a device one epoch behind; it
catches up by applying the handshakes it missed, and cannot read until it does.

## Abuse handling

Protected conversations remove the operator's ability to read reported content.
That is the point, and it has a cost worth stating: report-and-review moderation
does not work here. What remains available to an operator is metadata (who, when,
how often), account-level action, and the reporter's own copy of a conversation —
which they can screenshot. An operator who needs content-based moderation should
not enable `PM_PROTECTED_CHATS_ENABLED`.

## Assumptions a reviewer should challenge

1. That serving no third-party script, denying inline handlers and `eval`, and
   building DOM nodes instead of parsing HTML is enough to make browser-held keys
   worth having at all.
2. That the directory hash chain is worth its complexity given that it is not key
   transparency.
3. That the safety number is meaningful when nothing forces anyone to compare it.
4. That `'wasm-unsafe-eval'` and the absence of `worker-src` are acceptable
   weakenings of the policy.
5. That storing envelopes in `messages` with `content = ''`, so `LIKE`-based
   search fails closed with no extra code, has no path that leaks plaintext.
6. That the retry fingerprint over ciphertext is not an oracle, where the
   plaintext one was.
