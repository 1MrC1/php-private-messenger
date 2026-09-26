<?php

declare(strict_types=1);

function repositoryExposureAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$root = dirname(__DIR__);
$accessRules = file_get_contents($root . '/.htaccess');
$ignoreRules = file_get_contents($root . '/.gitignore');
$index = file_get_contents($root . '/index.html');

repositoryExposureAssert(
    is_string($accessRules) && is_string($ignoreRules) && is_string($index),
    'repository exposure controls are readable'
);

repositoryExposureAssert(
    str_contains($accessRules, 'classes|config|docs|migrations|tests|vendor|websocket') &&
        str_contains($accessRules, 'RewriteRule "(^|/)\\." - [F,L,NC]'),
    'internal code, operational material, tests, and dot paths are denied over HTTP'
);

repositoryExposureAssert(
    str_contains(
        $accessRules,
        '!^/api/(?:attachment|auth|avatar|chat|profile|settings)\\.php$'
    ) && str_contains($accessRules, 'RewriteRule \.php(?:/|$) - [F,L,NC]'),
    'only the explicit API PHP entry points are executable over HTTP'
);

foreach (['a.php', 'websocket/server.php', 'assets/js/script.js'] as $dormantPath) {
    repositoryExposureAssert(
        !is_file($root . '/' . $dormantPath) && !str_contains($index, $dormantPath),
        'dormant executable is absent: ' . $dormantPath
    );
}

repositoryExposureAssert(
    str_contains($ignoreRules, '/.env') &&
        str_contains($ignoreRules, '*.pem') &&
        str_contains($ignoreRules, '*.key') &&
        str_contains($ignoreRules, '/config/runtime-secrets.php'),
    'common local credential files are excluded from source control'
);

echo "Repository exposure hardening tests passed.\n";
