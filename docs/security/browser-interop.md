# Browser interoperability of the MLS build

A claim that encryption "works in browsers" is worth nothing without saying which
browsers, when, and how it was checked. This file records that, and is updated
when the artifact or the toolchain changes.

## Run it yourself

```sh
node crypto/interop/run.mjs
```

It needs Playwright's browsers and nothing else:

```sh
npm i -D playwright && npx playwright install chromium firefox webkit
# or, against an existing installation:
PLAYWRIGHT_MODULE=/path/to/node_modules/playwright node crypto/interop/run.mjs
```

It is deliberately **not** part of `tests/`. The suite has to run for someone
with only PHP and Node, and browser automation is a large dependency for a
project whose point is that it has almost none. An engine that is not installed
is reported as not run rather than failing the matrix, and the run fails if fewer
than two engines were present, because one engine is not a matrix.

`crypto/interop/harness.html` can also simply be opened in any browser — a phone
included — and it runs a round trip and prints the result. It obeys the
application's own content security policy: no inline script, no inline style.

## What the matrix does

For **every ordered pair** of engines, one device runs in each browser and they
hold a real conversation through the committed WebAssembly artifact:

- identity, key package, group creation, welcome, and the joiner landing in the
  same group id
- a sealed message opened in the other engine, and a reply opened back — a
  one-way check would miss an engine that can read but not write
- the safety number computed on both sides, which must not depend on the engine
- a third device admitted, with the existing member applying the commit, and all
  three reading the next message at the same epoch
- a removal: the remaining member keeps reading, the removed one cannot
- exported state restored and still decrypting, which is what a page reload does

It also probes what the client needs from the browser besides WebAssembly: a
non-extractable AES-GCM key, that key surviving a round trip through IndexedDB,
and PBKDF2-SHA512 at 600 000 iterations for recovery files.

## Results

**2026-09-28**, `pm_mls.js` / `pm_mls_bg.wasm` as committed (digests in
`assets/vendor/mls/ARTIFACTS.sha256`), OpenMLS 0.9.0, cipher suite 1
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), Ubuntu 24.04, headless:

| Engine | Version | Round trip | AES-GCM | Non-extractable key | CryptoKey in IndexedDB | PBKDF2-SHA512 600k |
|---|---|---|---|---|---|---|
| Chromium (V8) | 145.0.7632.6 | pass | yes | yes | yes | 328 ms |
| Firefox (SpiderMonkey) | 146.0.1 | pass | yes | yes | yes | 872 ms |
| WebKit (JavaScriptCore) | 26.0 | pass | yes | yes | yes | 330 ms |

All **nine** ordered pairs interoperated, including every cross-engine
combination: a message sealed in Firefox opens in WebKit, one sealed in WebKit
opens in Chromium, and so on.

## The Ed25519 question

There is nothing to fall back to, which is the decision rather than an omission.
Signatures, HPKE and the key schedule all happen inside WebAssembly, in OpenMLS's
Rust provider. WebCrypto's uneven Ed25519 support therefore never enters the
picture, and the project depends on it nowhere. What it does depend on from
WebCrypto is AES-GCM and PBKDF2 — both long-standing and present in all three
engines above, and both probed by the matrix rather than assumed.

## Limits of this result

- Headless desktop builds on one Linux machine. Real mobile browsers — iOS
  Safari, Android Chrome, and the in-app webviews people actually read messages
  in — were **not** tested, and a WebAssembly memory limit or an IndexedDB quirk
  on a phone would not show up here.
- No older browsers. The artifact needs WebAssembly and `'wasm-unsafe-eval'` in
  the policy; anything that lacks either does not run protected conversations at
  all, and the interface has to say so rather than failing silently.
- Interoperability *with other MLS implementations* is a different question and
  is not answered here. That needs the protocol-level RFC 9420 vectors, which
  `crypto/tests/rfc9420_vectors.rs` cannot reach — see
  `docs/security/e2ee-readiness.md`.
- PBKDF2 at 600 000 iterations costs under a second in every engine, which is
  the honest reason the recovery passphrase is generated rather than chosen: the
  derivation is not what carries the strength.
