<?php

declare(strict_types=1);

function privateMediaAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$profileSource = file_get_contents(__DIR__ . '/../api/profile.php');
$chatApiSource = file_get_contents(__DIR__ . '/../api/chat.php');
$chatSource = file_get_contents(__DIR__ . '/../classes/Chat.php');
$attachmentSource = file_get_contents(__DIR__ . '/../api/attachment.php');
$avatarSource = file_get_contents(__DIR__ . '/../api/avatar.php');
privateMediaAssert(
    is_string($profileSource) && is_string($chatApiSource) && is_string($chatSource) &&
        is_string($attachmentSource) && is_string($avatarSource),
    'media sources are readable'
);

privateMediaAssert(
    str_contains($profileSource, 'SELECT avatar FROM users WHERE id = ? FOR UPDATE') &&
        substr_count($profileSource, 'lockCurrentAvatarPath(') === 3 &&
        !str_contains($profileSource, "deleteStoredAvatarFile(\$currentUser['avatar']"),
    'avatar replacement deletes the predecessor selected under a user-row lock'
);
privateMediaAssert(
    str_contains($profileSource, '$commitAttempted = true;') &&
        str_contains($profileSource, 'is_string($pendingAvatarPath) && !$commitAttempted') &&
        str_contains($profileSource, 'ambiguous profile commit outcome'),
    'an ambiguous profile commit cannot delete a possibly committed avatar'
);
privateMediaAssert(
    str_contains($profileSource, "!array_key_exists('action', \$_POST)") &&
        str_contains($profileSource, "!array_key_exists('username', \$_POST)") &&
        str_contains($profileSource, "!array_key_exists('bio', \$_POST)") &&
        str_contains($profileSource, "!array_key_exists('phone', \$_POST)"),
    'avatar-only requests cannot silently discard partial profile fields'
);

$rawAvatarSelects = preg_match_all('/^\s*u\.avatar\s*,\s*$/m', $chatSource);
privateMediaAssert(
    substr_count(
        $chatSource,
        'CASE WHEN u.show_profile_photo = TRUE THEN u.avatar ELSE NULL END AS avatar'
    ) >= 3 && $rawAvatarSelects === 0 &&
        !str_contains($chatSource, 'private function getOtherParticipant('),
    'message queries and participant helpers do not expose hidden sender avatars'
);
privateMediaAssert(
    substr_count($chatSource, 'last_seen > DATE_SUB(NOW(), INTERVAL 2 MINUTE)') >= 4 &&
        !str_contains($chatSource, 'CASE WHEN show_last_seen = TRUE THEN is_online') &&
        !str_contains($chatSource, 'CASE WHEN u.show_last_seen = TRUE THEN u.is_online'),
    'public and profile presence expires from last activity instead of trusting stale flags'
);
privateMediaAssert(
    str_contains($chatApiSource, "Auth::reserveRateLimitAttempt(\n            'attachment_upload'") &&
        !str_contains($chatApiSource, "\$_SESSION['attachment_upload_attempts']"),
    'attachment parser attempts are limited account-wide across browser sessions'
);
privateMediaAssert(
    str_contains($attachmentSource, '$validatedContentHash = hash_file') &&
        str_contains($attachmentSource, 'attachmentHashOpenStream($fileHandle, $streamStat)') &&
        str_contains($attachmentSource, 'hash_equals($validatedContentHash, $streamContentHash)') &&
        strpos($attachmentSource, '$validatedContentHash = hash_file') <
            strpos($attachmentSource, '$finfo = finfo_open(FILEINFO_MIME_TYPE);'),
    'attachment delivery rejects ordinary changes between path validation and the opened stream'
);
privateMediaAssert(
    str_contains($avatarSource, '$validatedContentHash = hash_file') &&
        str_contains($avatarSource, 'avatarHashOpenStream($fileHandle, $streamStat)') &&
        str_contains($avatarSource, 'hash_equals($validatedContentHash, $streamContentHash)') &&
        strpos($avatarSource, '$validatedContentHash = hash_file') <
            strpos($avatarSource, '$pathMimeDetector = finfo_open(FILEINFO_MIME_TYPE);'),
    'avatar delivery rejects ordinary changes between image validation and the opened stream'
);
privateMediaAssert(
    substr_count($attachmentSource, "['dev', 'ino', 'mode', 'nlink', 'size', 'mtime', 'ctime']") >= 3 &&
        substr_count($avatarSource, "['dev', 'ino', 'mode', 'nlink', 'size', 'mtime', 'ctime']") >= 3 &&
        str_contains($attachmentSource, '$streamStat[\'nlink\'] !== 1') &&
        str_contains($avatarSource, '$streamStat[\'nlink\'] !== 1'),
    'private delivery binds validation caches and final hashes to complete regular-file identity'
);
privateMediaAssert(
    str_contains($attachmentSource, "in_array(\$messageType, ['image', 'audio', 'video'], true)") &&
        str_contains($attachmentSource, "? 'inline'") &&
        str_contains($attachmentSource, "header('Accept-Ranges: bytes')") &&
        str_contains($attachmentSource, "header('Content-Disposition: ' . \$contentDisposition)"),
    'authenticated audio and video may render inline while preserving disposition and Range controls'
);

echo "Private media hardening tests passed.\n";
