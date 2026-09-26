<?php

declare(strict_types=1);

/**
 * Header-only image validation for content that browsers render inline.
 *
 * The checks deliberately avoid decoding attacker-controlled pixels. They
 * enforce a bounded canvas and reject animated containers, whose cumulative
 * decoded size can be far larger than their file size or first-frame canvas.
 */
final class SafeImage
{
    private const GIF_MAX_SUB_BLOCKS = 100000;

    public const AVATAR_MAX_DIMENSION = 4096;
    public const AVATAR_MAX_PIXELS = 8000000;
    public const INLINE_MAX_DIMENSION = 8192;
    public const INLINE_MAX_PIXELS = 12000000;

    public static function isSafeStaticImage(
        string $path,
        string $expectedMimeType,
        int $maximumDimension,
        int $maximumPixels
    ): bool {
        $expectedMimeType = strtolower($expectedMimeType);
        if ($path === '' || $maximumDimension < 1 || $maximumPixels < 1 ||
            !in_array($expectedMimeType, ['image/jpeg', 'image/png', 'image/gif', 'image/webp'], true) ||
            !is_file($path) || !is_readable($path) || !function_exists('getimagesize')) {
            return false;
        }

        $imageInfo = @getimagesize($path);
        if (!is_array($imageInfo) || !isset($imageInfo[0], $imageInfo[1], $imageInfo['mime']) ||
            !is_int($imageInfo[0]) || !is_int($imageInfo[1]) ||
            $imageInfo[0] < 1 || $imageInfo[1] < 1 ||
            !is_string($imageInfo['mime']) ||
            !hash_equals($expectedMimeType, strtolower($imageInfo['mime']))) {
            return false;
        }

        $width = $imageInfo[0];
        $height = $imageInfo[1];
        if ($width > $maximumDimension || $height > $maximumDimension ||
            $width > intdiv($maximumPixels, $height)) {
            return false;
        }

        switch ($expectedMimeType) {
            case 'image/jpeg':
                // JPEG does not have a multi-frame browser animation format.
                return true;
            case 'image/png':
                return self::isStaticPng($path);
            case 'image/gif':
                return self::isSingleFrameGif($path, $maximumDimension, $maximumPixels);
            case 'image/webp':
                return self::isStaticWebp($path, $maximumDimension, $maximumPixels);
        }

        return false;
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

    private static function skipBytes($handle, int $length, int $fileSize): bool
    {
        $position = ftell($handle);
        if (!is_int($position) || $length < 0 || $position > $fileSize ||
            $length > $fileSize - $position) {
            return false;
        }

        return $length === 0 || fseek($handle, $length, SEEK_CUR) === 0;
    }

    private static function streamSize($handle): ?int
    {
        $stat = fstat($handle);
        return is_array($stat) && isset($stat['size']) && is_int($stat['size']) && $stat['size'] > 0
            ? $stat['size']
            : null;
    }

    private static function isStaticPng(string $path): bool
    {
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }

        try {
            $fileSize = self::streamSize($handle);
            if ($fileSize === null || $fileSize < 33 ||
                self::readExact($handle, 8) !== "\x89PNG\r\n\x1a\n") {
                return false;
            }

            $chunkCount = 0;
            $sawImageData = false;
            while (($position = ftell($handle)) !== false && $position < $fileSize) {
                if (++$chunkCount > 100000) {
                    return false;
                }

                $header = self::readExact($handle, 8);
                if ($header === null) {
                    return false;
                }
                $lengthData = unpack('Nlength', substr($header, 0, 4));
                $length = is_array($lengthData) ? ($lengthData['length'] ?? null) : null;
                $type = substr($header, 4, 4);
                if (!is_int($length) || $length < 0 || preg_match('/\A[A-Za-z]{4}\z/D', $type) !== 1 ||
                    ($chunkCount === 1 && ($type !== 'IHDR' || $length !== 13))) {
                    return false;
                }

                if ($type === 'acTL') {
                    return false;
                }
                if ($type === 'IDAT') {
                    $sawImageData = true;
                }

                if (!self::skipBytes($handle, $length + 4, $fileSize)) {
                    return false;
                }
                if ($type === 'IEND') {
                    return $length === 0 && $sawImageData;
                }
            }
        } finally {
            fclose($handle);
        }

        return false;
    }

    private static function skipGifSubBlocks($handle, int $fileSize, int &$remainingSubBlocks): bool
    {
        while (true) {
            if ($remainingSubBlocks-- <= 0) {
                return false;
            }
            $sizeByte = self::readExact($handle, 1);
            if ($sizeByte === null) {
                return false;
            }
            $blockSize = ord($sizeByte);
            if ($blockSize === 0) {
                return true;
            }
            if (!self::skipBytes($handle, $blockSize, $fileSize)) {
                return false;
            }
        }
    }

    private static function isSingleFrameGif(
        string $path,
        int $maximumDimension,
        int $maximumPixels
    ): bool
    {
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }

        try {
            $fileSize = self::streamSize($handle);
            $header = self::readExact($handle, 13);
            if ($fileSize === null || $fileSize < 14 || $header === null ||
                !in_array(substr($header, 0, 6), ['GIF87a', 'GIF89a'], true)) {
                return false;
            }

            $screenData = unpack('vwidth/vheight', substr($header, 6, 4));
            $screenWidth = is_array($screenData) ? ($screenData['width'] ?? null) : null;
            $screenHeight = is_array($screenData) ? ($screenData['height'] ?? null) : null;
            if (!is_int($screenWidth) || !is_int($screenHeight) ||
                $screenWidth < 1 || $screenHeight < 1 ||
                $screenWidth > $maximumDimension || $screenHeight > $maximumDimension ||
                $screenWidth > intdiv($maximumPixels, $screenHeight)) {
                return false;
            }

            $logicalScreenFlags = ord($header[10]);
            if (($logicalScreenFlags & 0x80) !== 0) {
                $globalColorTableSize = 3 * (1 << (($logicalScreenFlags & 0x07) + 1));
                if (!self::skipBytes($handle, $globalColorTableSize, $fileSize)) {
                    return false;
                }
            }

            $frameCount = 0;
            $blockCount = 0;
            $remainingSubBlocks = self::GIF_MAX_SUB_BLOCKS;
            while (($position = ftell($handle)) !== false && $position < $fileSize) {
                if (++$blockCount > 100000) {
                    return false;
                }

                $markerData = self::readExact($handle, 1);
                if ($markerData === null) {
                    return false;
                }
                $marker = ord($markerData);

                if ($marker === 0x3B) {
                    return $frameCount === 1;
                }
                if ($marker === 0x21) {
                    if (self::readExact($handle, 1) === null ||
                        !self::skipGifSubBlocks($handle, $fileSize, $remainingSubBlocks)) {
                        return false;
                    }
                    continue;
                }
                if ($marker !== 0x2C) {
                    return false;
                }

                $frameCount++;
                if ($frameCount > 1) {
                    return false;
                }
                $descriptor = self::readExact($handle, 9);
                if ($descriptor === null) {
                    return false;
                }
                $descriptorData = unpack('vleft/vtop/vwidth/vheight/Cflags', $descriptor);
                if (!is_array($descriptorData)) {
                    return false;
                }
                $left = $descriptorData['left'] ?? null;
                $top = $descriptorData['top'] ?? null;
                $frameWidth = $descriptorData['width'] ?? null;
                $frameHeight = $descriptorData['height'] ?? null;
                $imageFlags = $descriptorData['flags'] ?? null;
                if (!is_int($left) || !is_int($top) || !is_int($frameWidth) ||
                    !is_int($frameHeight) || !is_int($imageFlags) ||
                    $frameWidth < 1 || $frameHeight < 1 ||
                    $frameWidth > $maximumDimension || $frameHeight > $maximumDimension ||
                    $frameWidth > intdiv($maximumPixels, $frameHeight) ||
                    $left > $screenWidth || $top > $screenHeight ||
                    $frameWidth > $screenWidth - $left ||
                    $frameHeight > $screenHeight - $top) {
                    return false;
                }
                if (($imageFlags & 0x80) !== 0) {
                    $localColorTableSize = 3 * (1 << (($imageFlags & 0x07) + 1));
                    if (!self::skipBytes($handle, $localColorTableSize, $fileSize)) {
                        return false;
                    }
                }
                if (self::readExact($handle, 1) === null ||
                    !self::skipGifSubBlocks($handle, $fileSize, $remainingSubBlocks)) {
                    return false;
                }
            }
        } finally {
            fclose($handle);
        }

        return false;
    }

    private static function littleEndian24(string $bytes): ?int
    {
        if (strlen($bytes) !== 3) {
            return null;
        }

        return ord($bytes[0]) | (ord($bytes[1]) << 8) | (ord($bytes[2]) << 16);
    }

    private static function dimensionsAreBounded(
        int $width,
        int $height,
        int $maximumDimension,
        int $maximumPixels
    ): bool {
        return $width > 0 && $height > 0 &&
            $width <= $maximumDimension && $height <= $maximumDimension &&
            $width <= intdiv($maximumPixels, $height);
    }

    private static function isStaticWebp(
        string $path,
        int $maximumDimension,
        int $maximumPixels
    ): bool
    {
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }

        try {
            $fileSize = self::streamSize($handle);
            $header = self::readExact($handle, 12);
            if ($fileSize === null || $fileSize < 20 || $header === null ||
                substr($header, 0, 4) !== 'RIFF' || substr($header, 8, 4) !== 'WEBP') {
                return false;
            }

            $riffData = unpack('Vlength', substr($header, 4, 4));
            $riffLength = is_array($riffData) ? ($riffData['length'] ?? null) : null;
            if (!is_int($riffLength) || $riffLength < 12 || $riffLength !== $fileSize - 8) {
                return false;
            }
            $riffEnd = $riffLength + 8;
            $sawImageData = false;
            $canvasWidth = null;
            $canvasHeight = null;
            $chunkCount = 0;

            while (($position = ftell($handle)) !== false && $position < $riffEnd) {
                if (++$chunkCount > 100000 || $position > $riffEnd - 8) {
                    return false;
                }
                $chunkHeader = self::readExact($handle, 8);
                if ($chunkHeader === null) {
                    return false;
                }
                $chunkType = substr($chunkHeader, 0, 4);
                $lengthData = unpack('Vlength', substr($chunkHeader, 4, 4));
                $chunkLength = is_array($lengthData) ? ($lengthData['length'] ?? null) : null;
                if (!is_int($chunkLength) || $chunkLength < 0) {
                    return false;
                }

                if ($chunkType === 'ANIM' || $chunkType === 'ANMF') {
                    return false;
                }
                if ($chunkType === 'VP8X') {
                    if ($chunkCount !== 1 || $chunkLength !== 10 || $canvasWidth !== null) {
                        return false;
                    }
                    $extendedHeader = self::readExact($handle, 10);
                    if ($extendedHeader === null || (ord($extendedHeader[0]) & 0x02) !== 0 ||
                        (ord($extendedHeader[0]) & 0xC1) !== 0 ||
                        substr($extendedHeader, 1, 3) !== "\x00\x00\x00") {
                        return false;
                    }
                    $storedWidth = self::littleEndian24(substr($extendedHeader, 4, 3));
                    $storedHeight = self::littleEndian24(substr($extendedHeader, 7, 3));
                    if (!is_int($storedWidth) || !is_int($storedHeight)) {
                        return false;
                    }
                    $canvasWidth = $storedWidth + 1;
                    $canvasHeight = $storedHeight + 1;
                    if (!self::dimensionsAreBounded(
                        $canvasWidth,
                        $canvasHeight,
                        $maximumDimension,
                        $maximumPixels
                    )) {
                        return false;
                    }
                } elseif ($chunkType === 'VP8 ') {
                    if ($sawImageData || $chunkLength < 10 || ($canvasWidth === null && $chunkCount !== 1)) {
                        return false;
                    }
                    $frameHeader = self::readExact($handle, 10);
                    if ($frameHeader === null || (ord($frameHeader[0]) & 0x01) !== 0 ||
                        substr($frameHeader, 3, 3) !== "\x9d\x01\x2a") {
                        return false;
                    }
                    $widthData = unpack('vwidth', substr($frameHeader, 6, 2));
                    $heightData = unpack('vheight', substr($frameHeader, 8, 2));
                    $frameWidth = is_array($widthData) ? (($widthData['width'] ?? 0) & 0x3FFF) : 0;
                    $frameHeight = is_array($heightData) ? (($heightData['height'] ?? 0) & 0x3FFF) : 0;
                    if (!self::dimensionsAreBounded(
                        $frameWidth,
                        $frameHeight,
                        $maximumDimension,
                        $maximumPixels
                    ) || ($canvasWidth !== null &&
                        ($frameWidth > $canvasWidth || $frameHeight > $canvasHeight)) ||
                        !self::skipBytes($handle, $chunkLength - 10, $riffEnd)) {
                        return false;
                    }
                    $sawImageData = true;
                } elseif ($chunkType === 'VP8L') {
                    if ($sawImageData || $chunkLength < 5 || ($canvasWidth === null && $chunkCount !== 1)) {
                        return false;
                    }
                    $losslessHeader = self::readExact($handle, 5);
                    if ($losslessHeader === null || ord($losslessHeader[0]) !== 0x2F) {
                        return false;
                    }
                    $byte1 = ord($losslessHeader[1]);
                    $byte2 = ord($losslessHeader[2]);
                    $byte3 = ord($losslessHeader[3]);
                    $byte4 = ord($losslessHeader[4]);
                    $frameWidth = 1 + $byte1 + (($byte2 & 0x3F) << 8);
                    $frameHeight = 1 + ($byte2 >> 6) + ($byte3 << 2) + (($byte4 & 0x0F) << 10);
                    if (!self::dimensionsAreBounded(
                        $frameWidth,
                        $frameHeight,
                        $maximumDimension,
                        $maximumPixels
                    ) || ($canvasWidth !== null &&
                        ($frameWidth > $canvasWidth || $frameHeight > $canvasHeight)) ||
                        !self::skipBytes($handle, $chunkLength - 5, $riffEnd)) {
                        return false;
                    }
                    $sawImageData = true;
                } else {
                    if (!self::skipBytes($handle, $chunkLength, $riffEnd)) {
                        return false;
                    }
                }

                if (($chunkLength & 1) === 1 && !self::skipBytes($handle, 1, $riffEnd)) {
                    return false;
                }
            }

            return ftell($handle) === $riffEnd && $sawImageData;
        } finally {
            fclose($handle);
        }
    }
}
