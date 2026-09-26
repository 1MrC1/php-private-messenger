<?php

declare(strict_types=1);

function mediaRateLimitAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

function mediaRateLimitConstant(string $source, string $name): int
{
    $matched = preg_match(
        '/^const\s+' . preg_quote($name, '/') . '\s*=\s*([0-9]+);(?:\s*\/\/.*)?$/m',
        $source,
        $matches
    );
    if ($matched !== 1) {
        throw new RuntimeException("Missing integer constant {$name}");
    }
    return (int)$matches[1];
}

$attachmentSource = file_get_contents(__DIR__ . '/../api/attachment.php');
$avatarSource = file_get_contents(__DIR__ . '/../api/avatar.php');
mediaRateLimitAssert(
    is_string($attachmentSource) && is_string($avatarSource),
    'private media endpoint sources are readable'
);

$attachmentUserLimit = mediaRateLimitConstant($attachmentSource, 'ATTACHMENT_USER_REQUEST_LIMIT');
$attachmentIpLimit = mediaRateLimitConstant($attachmentSource, 'ATTACHMENT_IP_REQUEST_LIMIT');
$avatarUserLimit = mediaRateLimitConstant($avatarSource, 'AVATAR_USER_REQUEST_LIMIT');
$avatarIpLimit = mediaRateLimitConstant($avatarSource, 'AVATAR_IP_REQUEST_LIMIT');
mediaRateLimitAssert(
    $attachmentUserLimit >= 120 && $attachmentIpLimit > $attachmentUserLimit &&
        $avatarUserLimit >= 500 && $avatarIpLimit > $avatarUserLimit,
    'request budgets preserve normal attachment, range, and large chat-list bursts'
);

foreach ([$attachmentSource, $avatarSource] as $source) {
    mediaRateLimitAssert(
        str_contains($source, "\$_SERVER['REMOTE_ADDR']") &&
            str_contains($source, 'inet_pton($remoteAddress)') &&
            !str_contains($source, "\$_SERVER['HTTP_X_FORWARDED_FOR']") &&
            !str_contains($source, "\$_SERVER['HTTP_CF_CONNECTING_IP']"),
        'private media IP admission ignores spoofable forwarding headers'
    );
}

$attachmentSession = strpos($attachmentSource, 'if (!Auth::startExistingSession())');
$attachmentAdmission = strpos($attachmentSource, 'if (!attachmentReserveRequestBudget(');
$attachmentDatabase = strpos($attachmentSource, '$database = new Database();');
$avatarSession = strpos($avatarSource, "if (!Auth::startExistingSession(['read_and_close' => true]))");
$avatarAdmission = strpos($avatarSource, 'if (!avatarReserveRequestBudget(');
$avatarDatabase = strpos($avatarSource, '$database = new Database();');
mediaRateLimitAssert(
    is_int($attachmentSession) && is_int($attachmentAdmission) && is_int($attachmentDatabase) &&
        $attachmentSession < $attachmentAdmission && $attachmentAdmission < $attachmentDatabase &&
        is_int($avatarSession) && is_int($avatarAdmission) && is_int($avatarDatabase) &&
        $avatarSession < $avatarAdmission && $avatarAdmission < $avatarDatabase,
    'only authenticated sessions consume budgets and admission precedes database/file work'
);

mediaRateLimitAssert(
    str_contains($attachmentSource, "'attachment_read_ip_request'") &&
        str_contains($attachmentSource, "'attachment_read_user_request'") &&
        str_contains(
            $attachmentSource,
            "Auth::releaseRateLimitAttempt('attachment_read_ip_request', \$remoteIdentity)"
        ) &&
        str_contains($avatarSource, "'avatar_read_ip_request'") &&
        str_contains($avatarSource, "'avatar_read_user_request'") &&
        str_contains(
            $avatarSource,
            "Auth::releaseRateLimitAttempt('avatar_read_ip_request', \$remoteIdentity)"
        ),
    'IP-first composite reservations roll back the IP slot when account admission fails'
);

$byteUnit = mediaRateLimitConstant($attachmentSource, 'ATTACHMENT_BYTE_RATE_UNIT');
$userByteUnits = mediaRateLimitConstant($attachmentSource, 'ATTACHMENT_USER_BYTE_RATE_UNITS');
$ipByteUnits = mediaRateLimitConstant($attachmentSource, 'ATTACHMENT_IP_BYTE_RATE_UNITS');
mediaRateLimitAssert(
    $byteUnit === 1048576 && $userByteUnits >= 1024 && $ipByteUnits > $userByteUnits,
    'attachment delivery has a conservative shared per-MiB account and IP budget'
);
mediaRateLimitAssert(
    str_contains($attachmentSource, 'attachmentReleaseRateUnits($scope, $identity, $reserved)') &&
        str_contains(
            $attachmentSource,
            "attachmentReleaseRateUnits('attachment_read_ip_mib', \$remoteIdentity, \$units)"
        ),
    'partial MiB reservations and failed account reservations release exactly their own IP tokens'
);

$responseLength = strpos(
    $attachmentSource,
    '$responseLength = $isPartialResponse ? $rangeEnd - $rangeStart + 1 : $fileSize;'
);
$byteAdmission = strpos(
    $attachmentSource,
    "if (\$method === 'GET' &&\n        !attachmentReserveByteBudget("
);
$responseHeaders = strpos($attachmentSource, "header('Content-Length: ' . (string) \$responseLength)");
mediaRateLimitAssert(
    is_int($responseLength) && is_int($byteAdmission) && is_int($responseHeaders) &&
        $responseLength < $byteAdmission && $byteAdmission < $responseHeaders,
    'GET byte admission charges the exact full/range response before streaming'
);
mediaRateLimitAssert(
    substr_count($attachmentSource, 'attachmentReserveByteBudget(') === 2 &&
        str_contains($attachmentSource, "if (\$method === 'HEAD')") &&
        str_contains($attachmentSource, 'http_response_code(416)') &&
        str_contains($attachmentSource, "header('Retry-After: ' . ATTACHMENT_BYTE_RATE_WINDOW_SECONDS)"),
    'HEAD and invalid ranges remain response-byte-free while byte denials return retry guidance'
);
mediaRateLimitAssert(
    str_contains($attachmentSource, 'attachmentEndWithStatus(429)') &&
        str_contains($avatarSource, 'avatarEndWithStatus(429)') &&
        str_contains($avatarSource, "header('Retry-After: ' . AVATAR_REQUEST_RATE_WINDOW_SECONDS)"),
    'both private media endpoints return 429 with Retry-After on admission denial'
);

$attachmentInspectionUnit = mediaRateLimitConstant(
    $attachmentSource,
    'ATTACHMENT_INSPECTION_RATE_UNIT'
);
$attachmentUserInspectionUnits = mediaRateLimitConstant(
    $attachmentSource,
    'ATTACHMENT_USER_INSPECTION_RATE_UNITS'
);
$attachmentIpInspectionUnits = mediaRateLimitConstant(
    $attachmentSource,
    'ATTACHMENT_IP_INSPECTION_RATE_UNITS'
);
$avatarInspectionUnit = mediaRateLimitConstant($avatarSource, 'AVATAR_INSPECTION_RATE_UNIT');
$avatarUserInspectionUnits = mediaRateLimitConstant(
    $avatarSource,
    'AVATAR_USER_INSPECTION_RATE_UNITS'
);
$avatarIpInspectionUnits = mediaRateLimitConstant(
    $avatarSource,
    'AVATAR_IP_INSPECTION_RATE_UNITS'
);
mediaRateLimitAssert(
    $attachmentInspectionUnit >= 1048576 && $attachmentInspectionUnit <= 8388608 &&
        $attachmentInspectionUnit * $attachmentUserInspectionUnits >= 8 * 1024 * 1024 * 1024 &&
        $attachmentIpInspectionUnits > $attachmentUserInspectionUnits &&
        $avatarInspectionUnit >= 262144 && $avatarInspectionUnit <= 1048576 &&
        $avatarInspectionUnit * $avatarUserInspectionUnits >= 2 * 1024 * 1024 * 1024 &&
        $avatarIpInspectionUnits > $avatarUserInspectionUnits,
    'full-file inspection work has finite account and source byte budgets with normal-use headroom'
);
mediaRateLimitAssert(
    str_contains($attachmentSource, "'attachment_inspect_ip_units'") &&
        str_contains($attachmentSource, "'attachment_inspect_user_units'") &&
        str_contains(
            $attachmentSource,
            "attachmentReleaseRateUnits('attachment_inspect_ip_units', \$remoteIdentity, \$units)"
        ) &&
        str_contains($avatarSource, "'avatar_inspect_ip_units'") &&
        str_contains($avatarSource, "'avatar_inspect_user_units'") &&
        str_contains(
            $avatarSource,
            "avatarReleaseRateUnits('avatar_inspect_ip_units', \$remoteIdentity, \$units)"
        ),
    'inspection reservations are IP-first and exactly roll back partial composite reservations'
);

$attachmentCacheLookup = strpos(
    $attachmentSource,
    '$cachedValidation = attachmentCachedValidation($cacheKey, $allowedMimeTypes[$messageType]);'
);
$attachmentInspectionAdmission = strpos(
    $attachmentSource,
    "if (!attachmentReserveInspectionBudget(\n            \$userId,"
);
$attachmentPathHash = strpos($attachmentSource, '$validatedContentHash = hash_file');
$avatarCacheLookup = strpos(
    $avatarSource,
    '$cachedValidation = avatarCachedValidation($cacheKey, $allowedMimeTypes);'
);
$avatarInspectionAdmission = strpos(
    $avatarSource,
    "if (!avatarReserveInspectionBudget(\n            \$userId,"
);
$avatarPathHash = strpos($avatarSource, '$validatedContentHash = hash_file');
mediaRateLimitAssert(
    is_int($attachmentCacheLookup) && is_int($attachmentInspectionAdmission) &&
        is_int($attachmentPathHash) &&
        $attachmentCacheLookup < $attachmentInspectionAdmission &&
        $attachmentInspectionAdmission < $attachmentPathHash &&
        is_int($avatarCacheLookup) && is_int($avatarInspectionAdmission) &&
        is_int($avatarPathHash) &&
        $avatarCacheLookup < $avatarInspectionAdmission &&
        $avatarInspectionAdmission < $avatarPathHash,
    'cache-aware full-file budgets are reserved before every pathname hash or content parser'
);
mediaRateLimitAssert(
    str_contains($attachmentSource, '$inspectionPasses = $cachedValidation === null ? 2 : 1;') &&
        str_contains($avatarSource, '$inspectionPasses = $cachedValidation === null ? 2 : 1;') &&
        str_contains($attachmentSource, 'attachmentHashOpenStream($fileHandle, $streamStat)') &&
        str_contains($avatarSource, 'avatarHashOpenStream($fileHandle, $streamStat)') &&
        str_contains($attachmentSource, "\$fileSize,\n            \$inspectionPasses") &&
        str_contains($avatarSource, "\$fileSize,\n            \$inspectionPasses"),
    'cache misses cost two full-file passes while positive GET hits still hash opened bytes once'
);
mediaRateLimitAssert(
    str_contains($attachmentSource, "header('Retry-After: ' . ATTACHMENT_INSPECTION_RATE_WINDOW_SECONDS)") &&
        str_contains($avatarSource, "header('Retry-After: ' . AVATAR_INSPECTION_RATE_WINDOW_SECONDS)"),
    'inspection denials return explicit fixed-window retry guidance'
);

$avatarIdentityCheck = strpos($avatarSource, '$streamStat = fstat($fileHandle);');
$avatarConditional = strpos($avatarSource, "if (\$requestEtag !== '' && hash_equals(\$etag, \$requestEtag))");
mediaRateLimitAssert(
    is_int($avatarIdentityCheck) && is_int($avatarConditional) &&
        $avatarIdentityCheck < $avatarConditional && $avatarConditional < $avatarInspectionAdmission &&
        str_contains($avatarSource, "http_response_code(304);") &&
        str_contains($avatarSource, "if (\$method === 'HEAD' && \$cachedValidation !== null)") &&
        strpos($avatarSource, "header('Content-Type: ' . \$mimeType);") <
            strrpos($avatarSource, "if (\$method === 'HEAD')"),
    'authorized descriptor-bound avatar 304 and cached HEAD requests avoid unneeded content work'
);
mediaRateLimitAssert(
    str_contains($attachmentSource, 'ATTACHMENT_VALIDATION_CACHE_TTL_SECONDS = 300') &&
        str_contains($avatarSource, 'AVATAR_VALIDATION_CACHE_TTL_SECONDS = 300') &&
        str_contains($attachmentSource, 'count($cached) !== 2') &&
        str_contains($avatarSource, 'count($cached) !== 2') &&
        substr_count($attachmentSource, 'attachmentCacheValidation(') === 2 &&
        substr_count($avatarSource, 'avatarCacheValidation(') === 2,
    'only strict positive content verdicts are cached briefly; failures and authorization are not cached'
);

echo "Private media rate-limit hardening tests passed.\n";
