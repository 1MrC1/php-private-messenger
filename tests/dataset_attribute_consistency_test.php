<?php

declare(strict_types=1);

/**
 * The front end binds behaviour through `data-pm-*` attributes read back as
 * `element.dataset.pmSomething`. The two spellings are coupled by the DOM, not
 * by anything the compiler checks: rename the attribute and the reader silently
 * returns undefined, so every click quietly stops working.
 *
 * This test pins the pairing in both directions.
 */

function datasetAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$root = dirname(__DIR__);
$sources = [];
foreach (['assets/js/*.js', '*.html', 'api/*.php', 'classes/*.php'] as $pattern) {
    foreach (glob($root . '/' . $pattern) as $path) {
        $sources[$path] = (string)file_get_contents($path);
    }
}
datasetAssert($sources !== [], 'front-end sources are readable');

$camel = static function (string $attribute): string {
    $parts = explode('-', $attribute);
    return $parts[0] . implode('', array_map('ucfirst', array_slice($parts, 1)));
};

$attributes = [];
$reads = [];
foreach ($sources as $path => $source) {
    foreach ((array)(preg_match_all('/data-pm-([a-z0-9-]+)/', $source, $m) ? $m[1] : []) as $attribute) {
        $attributes[$camel($attribute)] = true;
    }
    foreach ((array)(preg_match_all('/dataset\.pm([A-Za-z0-9]+)/', $source, $m) ? $m[1] : []) as $read) {
        $reads[lcfirst($read)][$path] = true;
    }
}

datasetAssert($attributes !== [] && $reads !== [], 'the markup sets data-pm-* attributes and scripts read them back');

$orphanReads = [];
foreach ($reads as $key => $paths) {
    if (!isset($attributes[$key])) {
        $orphanReads[] = $key . ' (' . implode(', ', array_map('basename', array_keys($paths))) . ')';
    }
}
datasetAssert(
    $orphanReads === [],
    'every dataset.pm* read has a matching data-pm-* attribute' .
        ($orphanReads === [] ? '' : ': ' . implode('; ', $orphanReads))
);

echo "Dataset attribute consistency tests passed.\n";
