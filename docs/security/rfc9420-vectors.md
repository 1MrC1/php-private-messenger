# RFC 9420 known-answer tests

Two suites run, for one reason: OpenMLS keeps most of its own known-answer test
code behind `#[cfg(test)]`, where no dependent crate can call it. So the vectors
a dependent crate *can* reach run in this repository, and the rest run through
OpenMLS's own harness against the exact crate bytes our build compiles.

## 1. What runs in this repository

```sh
cd crypto && cargo test --test rfc9420_vectors -- --nocapture
```

`crypto/tests/rfc9420_vectors.rs`, against vectors committed in
`crypto/test-vectors/` and pinned by digest:

| Suite | How it runs |
|---|---|
| tree-math | OpenMLS's own KAT runner, reached via `test-utils` |
| key-schedule | OpenMLS's own KAT runner — the library's real epoch derivation, every epoch in the vector |
| crypto-basics | Here, through the provider: `RefHash` and `SignWithLabel` use the library's own code; `KDFLabel` and `EncryptContext` are written out from RFC 9420 §5.3 and §8 |

Three cipher suites are covered, and the run fails if the suite this project pins
was skipped as unsupported. Each was checked to fail on a single flipped digit
before being trusted. `tests/crypto_artifact_test.php` verifies the vector
digests with no Rust toolchain, so vectors edited to make a failing build pass
fail the ordinary suite instead.

## 2. What runs through OpenMLS's own harness

```sh
crypto/vectors/upstream-kats.sh
```

This fetches the crate from crates.io, **checks its SHA-256 against the
`checksum` line in `crypto/Cargo.lock`** — the same bytes cargo compiles for our
WebAssembly, verified rather than assumed — fetches the vectors at the matching
release tag, checks them against `crypto/vectors/UPSTREAM-VECTORS.sha256`, and
runs the suites.

It also rewrites exactly one line: in 0.9.0 the secret-tree KAT refers to
`openmls::storage::OpenMlsProvider` from inside the crate itself, where the crate
is not in scope, so the test target does not build. The script fails loudly if
that line is not exactly what it expects, because a patch that silently matched
something else would be worse than no patch.

**Result, 2026-09-28, openmls 0.9.0, checksum
`b6b08d90fc020cb5354d5f08ca17711b84c82e2bcc7331753fd94f000d99a8c8`: 16 suites,
all passing.**

| Suite | Covers |
|---|---|
| passive-client (welcome, random, handling-commit) | a client driven through real epochs, checking every derived secret |
| message-protection | application and handshake message framing, both directions |
| welcome | joining from a welcome |
| treekem | the ratchet tree's key encapsulation |
| tree-validation, tree-operations | tree integrity and the operations on it |
| secret-tree | per-leaf secret derivation |
| key-schedule | epoch secrets |
| psk_secret | pre-shared key derivation |
| transcript-hashes | confirmed and interim transcript hashes |
| messages | wire-format encoding of every message type |
| crypto-basics, tree-math | the primitives and the tree arithmetic |
| deserialization | variable-length encoding edge cases |
| encryption | OpenMLS's own encryption KAT |
| storage-stability | stored state stays readable across versions |

## What this does and does not establish

**Does:** the MLS implementation compiled into `assets/vendor/mls/pm_mls_bg.wasm`
is the published OpenMLS 0.9.0, verified by checksum, and that implementation
passes every RFC 9420 known-answer suite the working group publishes, including
the passive-client vectors.

**Does not:** conformance of anything in this repository. `crypto/src/` calls
`MlsGroup` and marshals bytes; it implements no protocol logic, and the two
constructions that *are* ours sit outside the protocol and are documented as
such:

- the storage framing in `encode_storage`/`decode_storage`, because OpenMLS's own
  serialiser for `MemoryStorage` is behind `test-utils` and documented as being
  for known-answer tests;
- the safety number, a SHA-256 over the sorted member signature keys, which is a
  comparison aid for people and not part of MLS.

Nor does any of it substitute for the independent review of this integration,
which `docs/security/e2ee-readiness.md` still requires and which is the reason
the product says *experimental* and *unaudited*.

## A note on two different crypto-basics files

OpenMLS vendors its own copy of `crypto-basics.json`, and it differs from the one
in `crypto/test-vectors/`. They are not in conflict: these vectors are generated,
so the two files are different random instances of the same tests. Both pass.
Ours comes from `mlswg/mls-implementations`, which is the authoritative source.
