<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/SafeArchive.php';

function safeArchiveAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

function safeArchiveLocalEntry(
    string $name,
    string $content,
    int $flags = 0,
    int $method = 0,
    ?int $declaredUncompressedSize = null
): string {
    $payload = $method === 8 ? gzdeflate($content, 9) : $content;
    if (!is_string($payload)) {
        throw new RuntimeException('Unable to create test payload');
    }
    $crcData = unpack('Ncrc', hash('crc32b', $content, true));
    $crc = is_array($crcData) ? (int)($crcData['crc'] ?? 0) : 0;
    $uncompressedSize = $declaredUncompressedSize ?? strlen($content);

    return "PK\x03\x04" . pack(
        'vvvvvVVVvv',
        20,
        $flags,
        $method,
        0,
        0,
        $crc,
        strlen($payload),
        $uncompressedSize,
        strlen($name),
        0
    ) . $name . $payload;
}

/** @param list<string> $temporaryPaths */
function safeArchiveTemporaryFile(string $content, array &$temporaryPaths): string
{
    $path = tempnam(sys_get_temp_dir(), 'pm-archive-');
    if (!is_string($path) || file_put_contents($path, $content) !== strlen($content)) {
        throw new RuntimeException('Unable to create archive fixture');
    }
    $temporaryPaths[] = $path;
    return $path;
}

$temporaryPaths = [];
try {
    $wordContentType =
        '<Types><Override PartName="/word/document.xml" ContentType="' .
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
    $safeDocx =
        safeArchiveLocalEntry('[Content_Types].xml', $wordContentType, 0, 8) .
        safeArchiveLocalEntry('word/document.xml', '<document/>') .
        "PK\x01\x02";
    $safeDocxPath = safeArchiveTemporaryFile($safeDocx, $temporaryPaths);
    safeArchiveAssert(
        SafeArchive::detectOoxmlMime($safeDocxPath, 'application/zip') ===
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'bounded local-entry inspection preserves safely provable OOXML detection'
    );

    $centralDirectoryBombPath = safeArchiveTemporaryFile(
        $safeDocx . str_repeat("PK\x01\x02" . str_repeat('X', 42), 100000),
        $temporaryPaths
    );
    $memoryBefore = memory_get_usage(true);
    $bombMime = SafeArchive::detectOoxmlMime($centralDirectoryBombPath, 'application/zip');
    $memoryGrowth = memory_get_usage(true) - $memoryBefore;
    safeArchiveAssert(
        $bombMime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' &&
            $memoryGrowth < 2 * 1024 * 1024,
        'a large attacker-controlled central directory is never materialized'
    );

    $descriptorArchivePath = safeArchiveTemporaryFile(
        safeArchiveLocalEntry('[Content_Types].xml', $wordContentType, 0x0008, 8) . "PK\x01\x02",
        $temporaryPaths
    );
    safeArchiveAssert(
        SafeArchive::detectOoxmlMime($descriptorArchivePath, 'application/zip') === 'application/zip',
        'data-descriptor ambiguity fails closed to generic ZIP'
    );

    $ambiguousTypes = $wordContentType .
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml';
    $ambiguousArchivePath = safeArchiveTemporaryFile(
        safeArchiveLocalEntry('[Content_Types].xml', $ambiguousTypes) .
        safeArchiveLocalEntry('word/document.xml', '<document/>') .
        safeArchiveLocalEntry('xl/workbook.xml', '<workbook/>') .
        "PK\x01\x02",
        $temporaryPaths
    );
    safeArchiveAssert(
        SafeArchive::detectOoxmlMime($ambiguousArchivePath, 'application/zip') === 'application/zip',
        'packages claiming multiple OOXML families fail closed to generic ZIP'
    );

    $oversizedXml = str_repeat('A', 1024 * 1024 + 1);
    $oversizedXmlPath = safeArchiveTemporaryFile(
        safeArchiveLocalEntry('[Content_Types].xml', $oversizedXml, 0, 8) .
        safeArchiveLocalEntry('word/document.xml', '<document/>') .
        "PK\x01\x02",
        $temporaryPaths
    );
    safeArchiveAssert(
        SafeArchive::detectOoxmlMime($oversizedXmlPath, 'application/zip') === 'application/zip',
        'oversized decompressed package metadata is rejected before inflation'
    );

    $manyEntries = '';
    $emptyCrc = safeArchiveLocalEntry('x', '');
    for ($index = 0; $index <= 10000; $index++) {
        $manyEntries .= $emptyCrc;
    }
    $manyEntriesPath = safeArchiveTemporaryFile($manyEntries . "PK\x01\x02", $temporaryPaths);
    safeArchiveAssert(
        SafeArchive::detectOoxmlMime($manyEntriesPath, 'application/zip') === 'application/zip',
        'local-entry work is capped before attacker-controlled amplification'
    );

    $chatSource = file_get_contents(__DIR__ . '/../classes/Chat.php');
    $attachmentSource = file_get_contents(__DIR__ . '/../api/attachment.php');
    safeArchiveAssert(
        is_string($chatSource) && is_string($attachmentSource) &&
            !str_contains($chatSource, 'ZipArchive') && !str_contains($attachmentSource, 'ZipArchive'),
        'request paths never invoke an unbounded ZIP library parser'
    );
} finally {
    foreach ($temporaryPaths as $temporaryPath) {
        @unlink($temporaryPath);
    }
}

echo "Safe archive hardening tests passed.\n";
