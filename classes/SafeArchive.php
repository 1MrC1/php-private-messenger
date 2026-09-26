<?php

declare(strict_types=1);

/**
 * Bounded OOXML recognition without asking libzip to materialize an untrusted
 * central directory. Generic ZIP files remain generic ZIP files.
 */
final class SafeArchive
{
    private const MAX_ARCHIVE_BYTES = 50 * 1024 * 1024;
    private const MAX_LOCAL_ENTRIES = 10000;
    private const MAX_ENTRY_NAME_BYTES = 1024;
    private const MAX_CONTENT_TYPES_BYTES = 1024 * 1024;
    private const MAX_COMPRESSED_CONTENT_TYPES_BYTES = 2 * 1024 * 1024;

    public static function detectOoxmlMime(string $path, string $detectedMime): string
    {
        if (!in_array($detectedMime, ['application/octet-stream', 'application/zip'], true)) {
            return $detectedMime;
        }

        $ooxmlMime = self::inspectLocalEntries($path);
        return $ooxmlMime ?? $detectedMime;
    }

    private static function inspectLocalEntries(string $path): ?string
    {
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }

        try {
            $stat = fstat($handle);
            $fileSize = is_array($stat) && isset($stat['size']) && is_int($stat['size'])
                ? $stat['size']
                : 0;
            if ($fileSize < 4 || $fileSize > self::MAX_ARCHIVE_BYTES) {
                return null;
            }

            $entryCount = 0;
            $contentTypes = null;
            $mainParts = [
                'word/document.xml' => false,
                'xl/workbook.xml' => false,
                'ppt/presentation.xml' => false
            ];

            while (($position = ftell($handle)) !== false && $position < $fileSize) {
                $signature = self::readExact($handle, 4);
                if ($signature === null) {
                    return null;
                }

                // The first central-directory record ends the bounded local
                // scan. Its attacker-controlled entry count is never parsed or
                // allocated in this request process.
                if (in_array($signature, ["PK\x01\x02", "PK\x05\x06", "PK\x06\x06"], true)) {
                    return self::classifyPackage($contentTypes, $mainParts);
                }
                if ($signature !== "PK\x03\x04" || ++$entryCount > self::MAX_LOCAL_ENTRIES) {
                    return null;
                }

                $header = self::readExact($handle, 26);
                if ($header === null) {
                    return null;
                }
                $fields = unpack(
                    'vversion/vflags/vmethod/vtime/vdate/Vcrc/Vcompressed/Vuncompressed/' .
                    'vname_length/vextra_length',
                    $header
                );
                if (!is_array($fields)) {
                    return null;
                }

                $flags = $fields['flags'] ?? null;
                $method = $fields['method'] ?? null;
                $crc = $fields['crc'] ?? null;
                $compressedSize = $fields['compressed'] ?? null;
                $uncompressedSize = $fields['uncompressed'] ?? null;
                $nameLength = $fields['name_length'] ?? null;
                $extraLength = $fields['extra_length'] ?? null;
                if (!is_int($flags) || !is_int($method) || !is_int($crc) ||
                    !is_int($compressedSize) || !is_int($uncompressedSize) ||
                    !is_int($nameLength) || !is_int($extraLength) ||
                    // Data descriptors and encryption make local sizes
                    // unauthoritative, so classify the archive only as ZIP.
                    ($flags & 0x0009) !== 0 ||
                    $compressedSize === 0xFFFFFFFF || $uncompressedSize === 0xFFFFFFFF ||
                    $nameLength < 1 || $nameLength > self::MAX_ENTRY_NAME_BYTES) {
                    return null;
                }

                $entryName = self::readExact($handle, $nameLength);
                if ($entryName === null || strpos($entryName, "\0") !== false ||
                    !self::skipBytes($handle, $extraLength, $fileSize)) {
                    return null;
                }

                if (array_key_exists($entryName, $mainParts)) {
                    $mainParts[$entryName] = true;
                }

                if ($entryName === '[Content_Types].xml') {
                    if ($contentTypes !== null) {
                        return null;
                    }
                    $contentTypes = self::readContentTypes(
                        $handle,
                        $method,
                        $crc,
                        $compressedSize,
                        $uncompressedSize,
                        $fileSize
                    );
                    if ($contentTypes === null) {
                        return null;
                    }
                } elseif (!self::skipBytes($handle, $compressedSize, $fileSize)) {
                    return null;
                }
            }
        } finally {
            fclose($handle);
        }

        return null;
    }

    private static function readContentTypes(
        $handle,
        int $method,
        int $expectedCrc,
        int $compressedSize,
        int $uncompressedSize,
        int $fileSize
    ): ?string {
        if ($uncompressedSize < 1 || $uncompressedSize > self::MAX_CONTENT_TYPES_BYTES ||
            $compressedSize < 1 || $compressedSize > self::MAX_COMPRESSED_CONTENT_TYPES_BYTES) {
            return null;
        }

        $compressed = self::readExactBounded($handle, $compressedSize, $fileSize);
        if ($compressed === null) {
            return null;
        }
        if ($method === 0) {
            $content = $compressedSize === $uncompressedSize ? $compressed : null;
        } elseif ($method === 8) {
            $inflated = @gzinflate($compressed, self::MAX_CONTENT_TYPES_BYTES + 1);
            $content = is_string($inflated) ? $inflated : null;
        } else {
            return null;
        }

        if (!is_string($content) || strlen($content) !== $uncompressedSize) {
            return null;
        }
        $crcData = unpack('Ncrc', hash('crc32b', $content, true));
        $actualCrc = is_array($crcData) ? ($crcData['crc'] ?? null) : null;
        return is_int($actualCrc) && $actualCrc === $expectedCrc ? $content : null;
    }

    /** @param array<string, bool> $mainParts */
    private static function classifyPackage(?string $contentTypes, array $mainParts): ?string
    {
        if ($contentTypes === null) {
            return null;
        }

        $packages = [
            'word/document.xml' => [
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            ],
            'xl/workbook.xml' => [
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            ],
            'ppt/presentation.xml' => [
                'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation'
            ]
        ];
        $matches = [];
        foreach ($packages as $mainPart => [$contentType, $mimeType]) {
            if (!empty($mainParts[$mainPart]) && strpos($contentTypes, $contentType) !== false) {
                $matches[] = $mimeType;
            }
        }

        // A package claiming multiple mutually exclusive Office document
        // families is ambiguous and remains a generic ZIP.
        return count($matches) === 1 ? $matches[0] : null;
    }

    private static function readExact($handle, int $length): ?string
    {
        if ($length < 0) {
            return null;
        }
        $buffer = '';
        while (strlen($buffer) < $length) {
            $chunk = fread($handle, $length - strlen($buffer));
            if (!is_string($chunk) || $chunk === '') {
                return null;
            }
            $buffer .= $chunk;
        }
        return $buffer;
    }

    private static function readExactBounded($handle, int $length, int $fileSize): ?string
    {
        $position = ftell($handle);
        if (!is_int($position) || $length < 0 || $position > $fileSize ||
            $length > $fileSize - $position) {
            return null;
        }
        return self::readExact($handle, $length);
    }

    private static function skipBytes($handle, int $length, int $fileSize): bool
    {
        $position = ftell($handle);
        if (!is_int($position) || $length < 0 || $position > $fileSize ||
            $length > $fileSize - $position) {
            return false;
        }
        return $length === 0 || fseek($handle, $length, SEEK_CUR) === 0;
    }
}
