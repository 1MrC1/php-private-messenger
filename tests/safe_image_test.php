<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/SafeImage.php';

function safeImageAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

function safeImageWrite(string $path, string $bytes): void
{
    if (file_put_contents($path, $bytes, LOCK_EX) !== strlen($bytes)) {
        throw new RuntimeException('Unable to create image test fixture');
    }
}

function safeImageLittleEndian24(int $value): string
{
    return chr($value & 0xff) . chr(($value >> 8) & 0xff) . chr(($value >> 16) & 0xff);
}

if (!extension_loaded('gd')) {
    throw new RuntimeException('The GD extension is required for SafeImage tests');
}

$testDirectory = sys_get_temp_dir() . '/pm-safe-image-' . bin2hex(random_bytes(8));
if (!mkdir($testDirectory, 0700)) {
    throw new RuntimeException('Unable to create SafeImage test directory');
}

$createdPaths = [];
try {
    $image = imagecreatetruecolor(2, 2);
    if ($image === false) {
        throw new RuntimeException('Unable to create image fixture');
    }
    $color = imagecolorallocate($image, 25, 120, 220);
    imagefilledrectangle($image, 0, 0, 1, 1, $color);

    $pngPath = $testDirectory . '/static.png';
    $jpegPath = $testDirectory . '/static.jpg';
    $gifPath = $testDirectory . '/static.gif';
    $createdPaths = [$pngPath, $jpegPath, $gifPath];
    imagepng($image, $pngPath);
    imagejpeg($image, $jpegPath, 85);
    imagegif($image, $gifPath);

    safeImageAssert(
        SafeImage::isSafeStaticImage($pngPath, 'image/png', 32, 1024),
        'static PNG passes bounded validation'
    );
    safeImageAssert(
        SafeImage::isSafeStaticImage($jpegPath, 'image/jpeg', 32, 1024),
        'static JPEG passes bounded validation'
    );
    safeImageAssert(
        SafeImage::isSafeStaticImage($gifPath, 'image/gif', 32, 1024),
        'single-frame GIF passes bounded validation'
    );
    safeImageAssert(
        !SafeImage::isSafeStaticImage($pngPath, 'image/jpeg', 32, 1024),
        'MIME confusion is rejected'
    );
    safeImageAssert(
        !SafeImage::isSafeStaticImage($pngPath, 'image/png', 1, 1024),
        'oversized dimensions are rejected'
    );
    safeImageAssert(
        !SafeImage::isSafeStaticImage($pngPath, 'image/png', 32, 3),
        'oversized pixel canvases are rejected'
    );

    $gifBytes = file_get_contents($gifPath);
    $imageSeparator = is_string($gifBytes) ? strpos($gifBytes, "\x2c") : false;
    $trailer = is_string($gifBytes) ? strrpos($gifBytes, "\x3b") : false;
    if (!is_string($gifBytes) || !is_int($imageSeparator) || !is_int($trailer) ||
        $imageSeparator >= $trailer) {
        throw new RuntimeException('Unable to construct animated GIF fixture');
    }
    $animatedGifPath = $testDirectory . '/animated.gif';
    $createdPaths[] = $animatedGifPath;
    $frameBlock = substr($gifBytes, $imageSeparator, $trailer - $imageSeparator);
    safeImageWrite(
        $animatedGifPath,
        substr($gifBytes, 0, $trailer) . $frameBlock . "\x3b"
    );
    safeImageAssert(
        !SafeImage::isSafeStaticImage($animatedGifPath, 'image/gif', 32, 1024),
        'multi-frame GIF is rejected'
    );

    $oversizedFrameGifPath = $testDirectory . '/oversized-frame.gif';
    $createdPaths[] = $oversizedFrameGifPath;
    $oversizedFrameGif = substr_replace(
        $gifBytes,
        "\xff\xff\xff\xff",
        $imageSeparator + 5,
        4
    );
    safeImageWrite($oversizedFrameGifPath, $oversizedFrameGif);
    safeImageAssert(
        getimagesize($oversizedFrameGifPath)[0] === 2 &&
        !SafeImage::isSafeStaticImage($oversizedFrameGifPath, 'image/gif', 32, 1024),
        'GIF frame dimensions cannot exceed the bounded logical canvas'
    );

    $subBlockFloodGifPath = $testDirectory . '/sub-block-flood.gif';
    $createdPaths[] = $subBlockFloodGifPath;
    safeImageWrite(
        $subBlockFloodGifPath,
        substr($gifBytes, 0, $imageSeparator) .
            "\x21\xfe" . str_repeat("\x01A", 100001) . "\x00" .
            substr($gifBytes, $imageSeparator)
    );
    safeImageAssert(
        !SafeImage::isSafeStaticImage($subBlockFloodGifPath, 'image/gif', 32, 1024),
        'GIF sub-block work amplification is bounded'
    );

    $pngBytes = file_get_contents($pngPath);
    if (!is_string($pngBytes) || strlen($pngBytes) < 33) {
        throw new RuntimeException('Unable to construct animated PNG fixture');
    }
    $animationControlData = pack('NN', 2, 0);
    $animationControlTypeAndData = 'acTL' . $animationControlData;
    $animationControlChunk = pack('N', strlen($animationControlData)) .
        $animationControlTypeAndData . pack('N', crc32($animationControlTypeAndData));
    $animatedPngPath = $testDirectory . '/animated.png';
    $createdPaths[] = $animatedPngPath;
    safeImageWrite(
        $animatedPngPath,
        substr($pngBytes, 0, 33) . $animationControlChunk . substr($pngBytes, 33)
    );
    safeImageAssert(
        !SafeImage::isSafeStaticImage($animatedPngPath, 'image/png', 32, 1024),
        'APNG animation control is rejected'
    );

    if (function_exists('imagewebp')) {
        $webpPath = $testDirectory . '/static.webp';
        $createdPaths[] = $webpPath;
        imagewebp($image, $webpPath, 80);
        safeImageAssert(
            SafeImage::isSafeStaticImage($webpPath, 'image/webp', 32, 1024),
            'static WebP passes bounded validation'
        );

        $webpBytes = file_get_contents($webpPath);
        if (!is_string($webpBytes) || strlen($webpBytes) < 20 ||
            substr($webpBytes, 0, 4) !== 'RIFF' || substr($webpBytes, 8, 4) !== 'WEBP') {
            throw new RuntimeException('Unable to construct animated WebP fixture');
        }
        $vp8xData = "\x02\x00\x00\x00" . safeImageLittleEndian24(1) . safeImageLittleEndian24(1);
        $extendedBody = 'VP8X' . pack('V', strlen($vp8xData)) . $vp8xData . substr($webpBytes, 12);
        $animatedWebpPath = $testDirectory . '/animated.webp';
        $createdPaths[] = $animatedWebpPath;
        safeImageWrite(
            $animatedWebpPath,
            'RIFF' . pack('V', strlen($extendedBody) + 4) . 'WEBP' . $extendedBody
        );
        safeImageAssert(
            !SafeImage::isSafeStaticImage($animatedWebpPath, 'image/webp', 32, 1024),
            'animated WebP feature flag is rejected'
        );

        $vp8ChunkOffset = strpos($webpBytes, 'VP8 ', 12);
        if (is_int($vp8ChunkOffset) && strlen($webpBytes) >= $vp8ChunkOffset + 18) {
            $oversizedVp8 = substr_replace(
                $webpBytes,
                pack('vv', 0x3fff, 0x3fff),
                $vp8ChunkOffset + 14,
                4
            );
            $staticVp8xData = "\x00\x00\x00\x00" .
                safeImageLittleEndian24(1) . safeImageLittleEndian24(1);
            $mismatchedBody = 'VP8X' . pack('V', strlen($staticVp8xData)) .
                $staticVp8xData . substr($oversizedVp8, 12);
            $mismatchedWebpPath = $testDirectory . '/mismatched-frame.webp';
            $createdPaths[] = $mismatchedWebpPath;
            safeImageWrite(
                $mismatchedWebpPath,
                'RIFF' . pack('V', strlen($mismatchedBody) + 4) . 'WEBP' . $mismatchedBody
            );
            $mismatchedInfo = getimagesize($mismatchedWebpPath);
            safeImageAssert(
                is_array($mismatchedInfo) && $mismatchedInfo[0] === 2 &&
                !SafeImage::isSafeStaticImage($mismatchedWebpPath, 'image/webp', 32, 1024),
                'WebP coded frame dimensions cannot hide behind a small VP8X canvas'
            );
        }
    }

    imagedestroy($image);
    echo "SafeImage hardening tests passed.\n";
} finally {
    if (isset($image) && $image instanceof GdImage) {
        imagedestroy($image);
    }
    foreach ($createdPaths as $createdPath) {
        if (is_string($createdPath) && is_file($createdPath)) {
            unlink($createdPath);
        }
    }
    rmdir($testDirectory);
}
