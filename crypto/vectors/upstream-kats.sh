#!/usr/bin/env bash
#
# Run the protocol-level RFC 9420 known-answer tests against the exact OpenMLS
# bytes this project compiles into WebAssembly.
#
# WHY THIS EXISTS SEPARATELY. `crypto/tests/rfc9420_vectors.rs` runs the vectors
# a dependent crate can reach: crypto-basics, the key schedule, tree math. The
# rest — message protection, welcome, treekem, tree validation and operations,
# the secret tree, PSK secrets, transcript hashes, and the passive-client
# suites — are exercised by test code inside OpenMLS that is `#[cfg(test)]`, so
# no dependent crate can call it. The only honest way to run them is to run
# OpenMLS's own harness, which is what this does.
#
# WHAT MAKES IT MEAN SOMETHING. The crate archive is fetched from crates.io and
# its SHA-256 is checked against the `checksum` line in `crypto/Cargo.lock` —
# the same bytes cargo compiles for our build, verified, not assumed. The
# vectors are fetched at the tag matching that release and checked against
# `UPSTREAM-VECTORS.sha256`.
#
# WHAT IT DOES NOT SHOW. This is conformance of the library, not of the wrapper
# in `crypto/src/`. The wrapper adds no protocol logic — it calls `MlsGroup` and
# marshals bytes — but "no protocol logic" is a claim a reader should check
# rather than take, and nothing here substitutes for the independent review in
# docs/security/e2ee-readiness.md.
#
# Usage: crypto/vectors/upstream-kats.sh [workdir]

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="${1:-$(mktemp -d)}"
mkdir -p "$work"

# The version and checksum come from the lock file, so this cannot drift from
# what the build uses.
version="$(awk '/^name = "openmls"$/{found=1; next} found && /^version = /{gsub(/[",]/,""); print $3; exit}' "$repo/crypto/Cargo.lock")"
checksum="$(awk '/^name = "openmls"$/{found=1} found && /^checksum = /{gsub(/[",]/,""); print $3; exit}' "$repo/crypto/Cargo.lock")"
tag="openmls-v${version}"

if [ -z "$version" ] || [ -z "$checksum" ]; then
    echo "could not read the pinned openmls version and checksum from crypto/Cargo.lock" >&2
    exit 1
fi
echo "pinned: openmls $version, checksum $checksum"

cd "$work"

# ---- the crate, verified against the lock file ------------------------------

if [ ! -f "openmls-$version.crate" ]; then
    curl -sSLo "openmls-$version.crate" "https://static.crates.io/crates/openmls/openmls-$version.crate"
fi
actual="$(sha256sum "openmls-$version.crate" | cut -d' ' -f1)"
if [ "$actual" != "$checksum" ]; then
    echo "REFUSING TO RUN: the crate archive does not match the checksum in Cargo.lock" >&2
    echo "  expected $checksum" >&2
    echo "  got      $actual" >&2
    exit 1
fi
echo "the crate archive matches the checksum cargo verified for our build"

rm -rf crate && mkdir crate
tar xzf "openmls-$version.crate" -C crate --strip-components=1

# ---- the vectors, verified against the digests recorded in this repository ---

if [ ! -f "vectors.tar.gz" ]; then
    curl -sSLo vectors.tar.gz "https://codeload.github.com/openmls/openmls/tar.gz/refs/tags/$tag"
fi
rm -rf vectors && mkdir vectors
tar xzf vectors.tar.gz -C vectors --strip-components=3 --wildcards "*/openmls/test_vectors/*.json"
(cd vectors && sha256sum --quiet --check "$here/UPSTREAM-VECTORS.sha256")
echo "the vectors match the digests recorded in crypto/vectors/UPSTREAM-VECTORS.sha256"

cp vectors/*.json crate/test_vectors/ 2>/dev/null || { mkdir -p crate/test_vectors && cp vectors/*.json crate/test_vectors/; }

# ---- one upstream line that does not compile --------------------------------
#
# In 0.9.0 the secret-tree KAT refers to `openmls::storage::OpenMlsProvider`
# from inside the crate itself, where the crate is not in scope, so the test
# target does not build. This rewrites that one reference and nothing else, and
# fails loudly if the line is not exactly what is expected — a patch that
# silently matched something else would be worse than no patch.
target="crate/src/tree/tests_and_kats/kats/secret_tree.rs"
expected='pub fn run_test_vector<Provider: openmls::storage::OpenMlsProvider>('
if [ "$(grep -c -F "$expected" "$target")" != "1" ]; then
    echo "the upstream line this patches has changed; review $target by hand" >&2
    exit 1
fi
sed -i "s|Provider: openmls::storage::OpenMlsProvider|Provider: crate::storage::OpenMlsProvider|" "$target"
echo "patched one test-only line so the upstream test target compiles"

# ---- run them ---------------------------------------------------------------

cd crate
cargo test --features test-utils --lib -- --test-threads "${KAT_THREADS:-4}" \
    read_test_vectors test_read_vectors kat_storage_stability::test

echo
echo "All of OpenMLS's known-answer suites passed against the pinned crate."
