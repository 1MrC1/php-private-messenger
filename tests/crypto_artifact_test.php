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

echo "Crypto artifact tests passed.\n";
