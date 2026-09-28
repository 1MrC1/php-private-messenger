<?php

declare(strict_types=1);

/**
 * The content security policy is the boundary that decides what may execute in
 * this origin. Any third-party host in `script-src` can serve code into the
 * page, which is why the front-end dependencies are vendored rather than loaded
 * from a CDN: an origin that lets someone else supply script cannot make a
 * meaningful confidentiality claim about anything the page holds.
 *
 * This test keeps that property from being quietly given away again.
 */

function cspAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$root = dirname(__DIR__);
$accessRules = (string)file_get_contents($root . '/.htaccess');
$page = (string)file_get_contents($root . '/index.html');
cspAssert($accessRules !== '' && $page !== '', 'the policy and the page are readable');

preg_match_all('/Content-Security-Policy "([^"]+)"/', $accessRules, $policyMatches);
$policies = $policyMatches[1];
cspAssert(count($policies) >= 2, 'both the private-media and application policies are present');

$application = '';
foreach ($policies as $policy) {
    if (str_contains($policy, 'script-src')) {
        $application = $policy;
    }
}
cspAssert($application !== '', 'the application policy declares script-src');

// Directive values, split out so each assertion can name what it inspected.
$directive = static function (string $policy, string $name): string {
    foreach (explode(';', $policy) as $part) {
        $part = trim($part);
        if ($part === $name || str_starts_with($part, $name . ' ')) {
            return trim(substr($part, strlen($name)));
        }
    }
    return '';
};

foreach (['script-src', 'style-src', 'font-src', 'connect-src'] as $name) {
    $value = $directive($application, $name);
    $external = array_values(array_filter(
        preg_split('/\s+/', $value) ?: [],
        static fn(string $source): bool => str_contains($source, '//')
    ));
    cspAssert(
        $external === [],
        $name . ' names no external origin' . ($external === [] ? '' : ': ' . implode(', ', $external))
    );
}

foreach (["'unsafe-inline'", "'unsafe-eval'"] as $escape) {
    cspAssert(
        !str_contains($application, $escape),
        'the application policy never allows ' . $escape
    );
}
cspAssert(
    str_contains($application, "script-src-attr 'none'") &&
        str_contains($application, "style-src-attr 'none'") &&
        str_contains($application, "object-src 'none'") &&
        str_contains($application, "base-uri 'self'"),
    'inline handlers, plugins and base-tag hijacking stay denied'
);

// The page must not reach out to anyone either, regardless of what the policy
// would tolerate.
cspAssert(
    !preg_match('#(?:src|href)="https?://#i', $page),
    'the page loads no resource over the network'
);
cspAssert(
    !str_contains($page, 'integrity='),
    'no subresource integrity attributes remain, since every asset is local'
);

// The vendored libraries the page now depends on.
$vendored = [
    'assets/vendor/css/bootstrap.min.css',
    'assets/vendor/css/fontawesome.min.css',
    'assets/vendor/js/bootstrap.bundle.min.js',
];
foreach ($vendored as $path) {
    cspAssert(is_file($root . '/' . $path), 'vendored asset is present: ' . $path);
    cspAssert(str_contains($page, $path), 'the page references the local copy: ' . $path);
}

$fontCss = (string)file_get_contents($root . '/assets/vendor/css/fontawesome.min.css');
preg_match_all('#\.\./webfonts/([a-z0-9.-]+\.woff2)#', $fontCss, $fontMatches);
$fonts = array_unique($fontMatches[1]);
cspAssert($fonts !== [], 'the icon stylesheet declares webfonts');
foreach ($fonts as $font) {
    cspAssert(
        is_file($root . '/assets/vendor/webfonts/' . $font),
        'the webfont it asks for is vendored: ' . $font
    );
}

// The directory reserved for a future cryptography toolchain must never be
// served, and is denied before it exists.
cspAssert(
    str_contains($accessRules, 'crypto|docs|migrations'),
    'the crypto toolchain directory is denied over HTTP'
);

echo "Content security posture tests passed.\n";
