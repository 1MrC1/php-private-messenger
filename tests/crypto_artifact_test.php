<?php

declare(strict_types=1);

/**
 * The MLS layer ships as a committed build output, which is the one place in
 * this repository where a reviewer cannot read what they are running. The
 * mitigation is that its digests are recorded and checked on every test run, so
 * an artifact replaced in a pull request fails the build — and the check needs
 * no Rust toolchain, so it runs for everyone.
 *
 * See crypto/BUILDING.md to rebuild and verify against source.
 */

function cryptoArtifactAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$root = dirname(__DIR__);
$dir = $root . '/assets/vendor/mls';

$manifestPath = $dir . '/ARTIFACTS.sha256';
cryptoArtifactAssert(is_file($manifestPath), 'the artifact manifest is present');
$manifest = (string)file_get_contents($manifestPath);

$expected = [];
foreach (explode("\n", trim($manifest)) as $line) {
    if (preg_match('/^([a-f0-9]{64})\s+\*?(\S+)$/', trim($line), $match) === 1) {
        $expected[$match[2]] = $match[1];
    }
}
cryptoArtifactAssert($expected !== [], 'the manifest lists at least one artifact');
cryptoArtifactAssert(
    isset($expected['pm_mls.js'], $expected['pm_mls_bg.wasm']),
    'the manifest covers both the loader and the WebAssembly module'
);

foreach ($expected as $name => $digest) {
    $path = $dir . '/' . $name;
    cryptoArtifactAssert(is_file($path), 'the artifact exists: ' . $name);
    $actual = hash_file('sha256', $path);
    cryptoArtifactAssert(
        hash_equals($digest, (string)$actual),
        'the artifact matches its recorded digest: ' . $name
    );
}

// Nothing may ship that the manifest does not cover.
$unlisted = [];
foreach ((array)scandir($dir) as $entry) {
    if ($entry === '.' || $entry === '..' || $entry === 'ARTIFACTS.sha256') {
        continue;
    }
    if (!isset($expected[$entry])) {
        $unlisted[] = $entry;
    }
}
cryptoArtifactAssert(
    $unlisted === [],
    'every shipped file is covered by the manifest' .
        ($unlisted === [] ? '' : ': ' . implode(', ', $unlisted))
);

// The module is useless without the policy that lets it instantiate.
$accessRules = (string)file_get_contents($root . '/.htaccess');
cryptoArtifactAssert(
    str_contains($accessRules, "'wasm-unsafe-eval'"),
    "the content security policy permits WebAssembly instantiation"
);
cryptoArtifactAssert(
    !preg_match("/script-src[^;]*'unsafe-eval'/", $accessRules) &&
        !preg_match("/script-src[^;]*'unsafe-inline'/", $accessRules),
    'permitting WebAssembly did not also restore eval() or inline script'
);

// The wrapper must stay a wrapper.
$source = (string)file_get_contents($root . '/crypto/src/lib.rs');
cryptoArtifactAssert(
    str_contains($source, 'openmls') && !preg_match('/\bfn\s+(encrypt|decrypt|kdf|hkdf|aead)\b/', $source),
    'the crate delegates to OpenMLS rather than implementing primitives'
);
cryptoArtifactAssert(
    str_contains($source, 'const CIPHERSUITE'),
    'the cipher suite is pinned rather than negotiated'
);

$manifestVersions = (string)file_get_contents($root . '/crypto/Cargo.toml');
cryptoArtifactAssert(
    str_contains($manifestVersions, 'openmls = { version = "=0.9.0"'),
    'OpenMLS is pinned to an exact version'
);

// `test-utils` unlocks OpenMLS internals for the known-answer tests. It must
// stay a development dependency: the artifact people run has to be built from
// the ordinary dependency set, and a rebuild proving that is recorded in
// crypto/BUILDING.md.
$sections = explode('[dev-dependencies]', $manifestVersions);
cryptoArtifactAssert(count($sections) === 2, 'the crate declares development dependencies once');
cryptoArtifactAssert(
    !str_contains($sections[0], 'test-utils') && str_contains($sections[1], 'test-utils'),
    'the test-utils feature is confined to development dependencies'
);

// ---------------------------------------------------------------------------
// The official RFC 9420 vectors.
//
// Pinning them here matters as much as pinning the artifact: a known-answer
// test whose answers can be edited to match a failing build proves nothing.
// ---------------------------------------------------------------------------

$vectorDir = $root . '/crypto/test-vectors';
$sumsPath = $vectorDir . '/SHA256SUMS';
cryptoArtifactAssert(is_file($sumsPath), 'the test vectors record their digests');

$vectorDigests = [];
foreach (explode("\n", trim((string)file_get_contents($sumsPath))) as $line) {
    if (preg_match('/^([a-f0-9]{64})\s+\*?(\S+)$/', trim($line), $match) === 1) {
        $vectorDigests[$match[2]] = $match[1];
    }
}
cryptoArtifactAssert($vectorDigests !== [], 'at least one vector file is pinned');

foreach ($vectorDigests as $name => $digest) {
    $path = $vectorDir . '/' . $name;
    cryptoArtifactAssert(is_file($path), 'the vector file exists: ' . $name);
    cryptoArtifactAssert(
        hash_equals($digest, (string)hash_file('sha256', $path)),
        'the vector file matches the answers published upstream: ' . $name
    );
}

$unpinned = [];
foreach ((array)glob($vectorDir . '/*.json') as $path) {
    $name = basename((string)$path);
    if (!isset($vectorDigests[$name])) {
        $unpinned[] = $name;
    }
}
cryptoArtifactAssert(
    $unpinned === [],
    'every vector file present is pinned' . ($unpinned === [] ? '' : ': ' . implode(', ', $unpinned))
);

cryptoArtifactAssert(
    is_file($vectorDir . '/PROVENANCE.md') &&
        str_contains((string)file_get_contents($vectorDir . '/PROVENANCE.md'), 'mlswg/mls-implementations'),
    'the vectors record where they came from'
);

// The runner must keep using the library's own known-answer runners for the two
// suites that have them, rather than quietly reimplementing the comparison.
$runner = (string)file_get_contents($root . '/crypto/tests/rfc9420_vectors.rs');
foreach (['key_schedule::run_test_vector', 'kat_treemath::run_test_vector'] as $call) {
    cryptoArtifactAssert(
        str_contains($runner, $call),
        "the vectors run through OpenMLS's own runner: " . $call
    );
}
cryptoArtifactAssert(
    str_contains($runner, 'covered_pinned') && str_contains($runner, 'const PINNED'),
    'the run fails if the pinned cipher suite was skipped as unsupported'
);

echo "Crypto artifact tests passed.\n";
