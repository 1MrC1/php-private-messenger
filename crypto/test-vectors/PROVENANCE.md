# Where these vectors come from

These files are the MLS working group's own known-answer tests, copied verbatim
from the repository the RFC 9420 authors maintain for exactly this purpose:

- Source: <https://github.com/mlswg/mls-implementations/tree/main/test-vectors>
- Commit: `89134d5de0222bd99598ba5849003d2e85e63116` (2025-11-30)
- Retrieved: 2026-09-28

`SHA256SUMS` pins the bytes. `tests/crypto_artifact_test.php` checks it on every
ordinary test run, so a vector quietly edited to make a failing build pass fails
the build instead — and that check needs no Rust toolchain.

Only the three files that are actually executed are kept here. The others in the
upstream directory (message protection, welcome, treekem, transcript, secret
tree, PSK secret, passive client) need OpenMLS internals that a dependent crate
cannot reach, so keeping them would imply a coverage this project does not have.

Run them with:

```sh
cd crypto && cargo test --test rfc9420_vectors -- --nocapture
```

What each one proves, and what it does not, is written at the top of
`crypto/tests/rfc9420_vectors.rs`. In short: the key schedule and tree math go
through OpenMLS's own runners; `crypto-basics` goes through the provider with the
label encodings written out from the RFC. None of it is protocol-level
conformance, and none of it substitutes for the independent review that
`docs/security/e2ee-readiness.md` still requires.

## Why OpenMLS's own copy differs

OpenMLS vendors `crypto-basics.json` too, and its file is not byte-identical to
this one. They are not in conflict: the vectors are generated, so the two are
different random instances of the same tests, and both pass. The copy here comes
from the working group, which is the authoritative source. The protocol-level
suites that run through OpenMLS's own harness use its vendored copies, pinned
separately in `crypto/vectors/UPSTREAM-VECTORS.sha256` — see
`docs/security/rfc9420-vectors.md`.
