<?php

declare(strict_types=1);

/**
 * Canonical download names derived from server-detected MIME types.
 *
 * The uploader's basename remains recognizable, but its extension never
 * controls how a recipient's operating system treats the downloaded file.
 */
final class AttachmentName
{
    // Stay comfortably below the 255-byte component limit used by common
    // Linux, macOS, and Windows filesystems. This also leaves room for a
    // browser or desktop to add a collision suffix when saving the file.
    private const MAX_FILENAME_BYTES = 180;

    private const EXTENSION_BY_MIME = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp',
        'audio/aac' => 'aac',
        'audio/flac' => 'flac',
        'audio/mp4' => 'm4a',
        'audio/mpeg' => 'mp3',
        'audio/ogg' => 'ogg',
        'audio/wav' => 'wav',
        'audio/webm' => 'webm',
        'audio/x-flac' => 'flac',
        'audio/x-wav' => 'wav',
        'video/mp4' => 'mp4',
        'video/ogg' => 'ogv',
        'video/quicktime' => 'mov',
        'video/webm' => 'webm',
        'video/x-matroska' => 'mkv',
        'video/x-msvideo' => 'avi',
        'video/avi' => 'avi',
        'application/msword' => 'doc',
        'application/pdf' => 'pdf',
        'application/rtf' => 'rtf',
        'application/vnd.ms-excel' => 'xls',
        'application/vnd.ms-powerpoint' => 'ppt',
        'application/vnd.oasis.opendocument.presentation' => 'odp',
        'application/vnd.oasis.opendocument.spreadsheet' => 'ods',
        'application/vnd.oasis.opendocument.text' => 'odt',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation' => 'pptx',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
        'application/x-7z-compressed' => '7z',
        'application/x-rar-compressed' => 'rar',
        'application/zip' => 'zip',
        'text/csv' => 'csv',
        'text/plain' => 'txt',
    ];

    public static function extensionForMime(string $mimeType): ?string
    {
        return self::EXTENSION_BY_MIME[strtolower(trim($mimeType))] ?? null;
    }

    public static function canonicalDisplayName(string $originalName, string $extension): string
    {
        $extension = strtolower(trim($extension));
        if (preg_match('/\A[a-z0-9]{1,8}\z/D', $extension) !== 1) {
            throw new InvalidArgumentException('Invalid attachment extension');
        }

        $name = basename(str_replace('\\', '/', $originalName));
        if (preg_match('//u', $name) !== 1) {
            $name = '';
        } else {
            // Cover the forbidden Windows characters, the legacy macOS path
            // separator, Linux/macOS NUL and slash, and all Unicode control
            // characters that could affect a Content-Disposition header.
            $name = preg_replace('/[\p{Cc}\p{Zl}\p{Zp}<>:&"\'\/\\|?*]+/u', '_', $name) ?? '';
            // Remove bidirectional controls and default-ignorable/zero-width
            // characters that can visually disguise the canonical extension.
            // Variation selectors are harmless in ordinary prose but have no
            // useful role in a security-sensitive download filename.
            $name = preg_replace(
                '/[\p{Cf}\x{034F}\x{115F}\x{1160}\x{17B4}\x{17B5}' .
                    '\x{180B}-\x{180F}\x{3164}\x{FE00}-\x{FE0F}\x{FFA0}' .
                    '\x{E0100}-\x{E01EF}]+/u',
                '_',
                $name
            ) ?? '';

            // NFC avoids visually identical names with different byte
            // sequences on normalization-aware macOS filesystems. Keep this
            // optional so filename safety does not depend on ext-intl.
            if (class_exists('Normalizer')) {
                $normalizedName = Normalizer::normalize($name, Normalizer::FORM_C);
                if (is_string($normalizedName)) {
                    $name = $normalizedName;
                }
            }
        }
        $name = trim($name, " .\t\n\r\0\x0B_");

        $lastDot = strrpos($name, '.');
        $base = is_int($lastDot) && $lastDot > 0 ? substr($name, 0, $lastDot) : $name;
        $base = trim($base, " .\t\n\r\0\x0B_");
        if ($base === '') {
            $base = 'attachment';
        }
        $base = self::neutralizePlatformSpecialName($base);

        $maximumBaseBytes = self::MAX_FILENAME_BYTES - strlen($extension) - 1;
        if (strlen($base) > $maximumBaseBytes) {
            $base = self::utf8ByteCut($base, $maximumBaseBytes);
            // Do not trim a leading underscore: it may be the marker that
            // makes a Windows device basename safe.
            $base = trim($base, " .\t\n\r\0\x0B");
        }
        if ($base === '' || preg_match('//u', $base) !== 1) {
            $base = 'attachment';
        }
        $base = self::neutralizePlatformSpecialName($base);

        return $base . '.' . $extension;
    }

    /** @return array{0: string, 1: string} ASCII fallback and UTF-8 filename. */
    public static function dispositionNames(string $originalName, string $mimeType): array
    {
        $extension = self::extensionForMime($mimeType);
        if ($extension === null) {
            throw new InvalidArgumentException('Unsupported attachment MIME type');
        }

        $utf8Name = self::canonicalDisplayName($originalName, $extension);
        $lastDot = strrpos($utf8Name, '.');
        $utf8Base = is_int($lastDot) ? substr($utf8Name, 0, $lastDot) : $utf8Name;
        $asciiBase = preg_replace('/[^A-Za-z0-9._-]+/', '_', $utf8Base) ?? '';
        $asciiBase = trim($asciiBase, ' ._-');
        if ($asciiBase === '') {
            $asciiBase = 'attachment';
        }
        $asciiBase = self::neutralizePlatformSpecialName($asciiBase);
        $maximumBaseBytes = self::MAX_FILENAME_BYTES - strlen($extension) - 1;
        $asciiBase = substr($asciiBase, 0, $maximumBaseBytes);

        return [$asciiBase . '.' . $extension, $utf8Name];
    }

    private static function neutralizePlatformSpecialName(string $base): string
    {
        // Leading dashes are valid filesystem characters, but become command
        // options too easily when a downloaded file is handled from a shell.
        if (isset($base[0]) && $base[0] === '-') {
            $base = '_' . $base;
        }

        // Windows treats a reserved DOS device stem as special even when it
        // has one or more additional extensions (for example CON.foo.txt),
        // and ignores spaces immediately before the first dot. Superscript
        // 1/2/3 are also recognized for COM/LPT by Windows.
        $firstDot = strpos($base, '.');
        $deviceStem = $firstDot === false ? $base : substr($base, 0, $firstDot);
        $deviceStem = rtrim($deviceStem, ' ');
        if (preg_match(
            '/\A(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|' .
                '(?:COM|LPT)(?:[1-9]|\x{00B9}|\x{00B2}|\x{00B3}))\z/iuD',
            $deviceStem
        ) === 1) {
            $base = '_' . $base;
        }

        return $base;
    }

    private static function utf8ByteCut(string $value, int $maximumBytes): string
    {
        if (strlen($value) <= $maximumBytes) {
            return $value;
        }
        if (function_exists('mb_strcut')) {
            return mb_strcut($value, 0, $maximumBytes, 'UTF-8');
        }

        $value = substr($value, 0, $maximumBytes);
        while ($value !== '' && preg_match('//u', $value) !== 1) {
            $value = substr($value, 0, -1);
        }
        return $value;
    }
}
