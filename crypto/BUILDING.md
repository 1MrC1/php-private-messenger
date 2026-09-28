# Rebuilding the MLS layer

`assets/vendor/mls/pm_mls.js` and `pm_mls_bg.wasm` are **committed build
outputs**. You do not need any of this to run the application, to contribute PHP,
or to deploy — that is the point. You need it only to change the cryptography
layer or to verify for yourself that the committed artifacts match the source.

## What this crate is

A thin wrapper around [OpenMLS](https://openmls.tech/), the Rust implementation
of MLS (RFC 9420). It implements **no cryptographic primitive**. Every operation
is OpenMLS's; this crate exists to expose a small surface to a browser.

OpenMLS is MIT licensed, so the project stays MIT, and it carries an independent
[security audit by SRLabs](https://blog.phnx.im/openmls-independent-security-audit/)
whose fixes shipped in 0.8.1. We pin **0.9.0**, which postdates them.

That audit covers **the library**. It does not cover this wrapper, the envelope
format, the storage schema, device enrollment, or anything else in this
repository. Using an audited library does not transfer its audit.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack          # or download a release binary

cd crypto
cargo test --release             # the round trip, natively
wasm-pack build --target web --release --out-dir pkg

cp pkg/pm_mls.js pkg/pm_mls_bg.wasm ../assets/vendor/mls/
cd ../assets/vendor/mls && sha256sum pm_mls.js pm_mls_bg.wasm > ARTIFACTS.sha256
```

`tests/crypto_artifact_test.php` recomputes those digests from disk on every test
run, so an artifact swapped in a pull request fails the build without anyone
needing a Rust toolchain.

## Verifying the committed artifacts

Build from a clean checkout and compare:

```sh
cd crypto && wasm-pack build --target web --release --out-dir /tmp/verify
sha256sum /tmp/verify/pm_mls_bg.wasm
diff <(sha256sum < /tmp/verify/pm_mls_bg.wasm) <(sha256sum < ../assets/vendor/mls/pm_mls_bg.wasm)
```

Rust builds are not bit-for-bit reproducible across differing toolchain
versions, so a mismatch is not automatically evidence of tampering — but a match
is strong evidence of its absence. Record the toolchain you used:

    rustc 1.98.1, wasm-pack 0.13.1, openmls 0.9.0

## Gotchas already paid for

- **Two getrandom majors.** A transitive dependency still uses `getrandom` 0.2,
  which needs its own `js` feature for wasm; the 0.3 entry does not cover it.
  Both are declared directly so the features unify.
- **OpenMLS needs its `js` feature** for browser randomness and time, otherwise
  the build fails on an unresolved `web_time` import.
- **Companion crate versions are not the same number as OpenMLS.** `openmls`
  0.9.0 goes with `openmls_rust_crypto`, `openmls_basic_credential` and
  `openmls_traits` at **0.6.0**. Mismatched versions fail with confusing
  "trait not implemented" errors, because each is built against a different
  `openmls_traits`.
- **`'wasm-unsafe-eval'` is required in the content security policy.** Without
  it the module cannot instantiate. It permits WebAssembly only; it does not
  restore `eval()` or inline script.

## The session API

`MlsSession` is the stateful half: `create_identity`, `create_key_package`,
`create_group`, `add_member`, `join_group`, `seal`, `open`, and
`export_state` / `restore` so state survives a page reload.

`export_state()` returns private key material. Wrap it with a non-extractable
key before it touches storage, and be clear about what that buys: at rest it is
inert without the wrapping key, but while the tab is open the material is in
WebAssembly memory where a cross-site scripting bug can reach it.

OpenMLS's own serialiser for `MemoryStorage` is behind its `test-utils` feature
and documented as being for known-answer tests, so this crate frames the public
`values` map itself rather than depending on a test-only API.

`tests/mls_session_runtime_test.js` runs the whole flow against the committed
artifacts on every test run.

## What still does not exist

The engine works, the server stores what it produces, and the browser client
drives both. What is missing is not wiring any more — it is assurance:

- the **independent review of this integration**, which OpenMLS's own audit does
  not cover, and which no amount of work in this repository can substitute for
- the RFC 9420 official test vectors run against this build, so conformance is
  demonstrated rather than assumed
- an interoperability matrix across browsers and MLS implementations

Until those exist the application is not end-to-end encrypted in any sense worth
claiming, and the interface says so in all five languages. See
`docs/security/e2ee-readiness.md` for the full gate.
