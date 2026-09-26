<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/MessageIdempotency.php';

function messageIdempotencyAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$uuid = '123e4567-e89b-42d3-a456-426614174000';
messageIdempotencyAssert(
    MessageIdempotency::canonicalClientMessageId(strtoupper($uuid)) === $uuid,
    'UUID v4 identifiers are validated and canonicalized case-insensitively'
);
foreach ([
    '',
    '123e4567-e89b-12d3-a456-426614174000',
    '123e4567-e89b-42d3-7456-426614174000',
    '00000000-0000-0000-0000-000000000000',
    $uuid . 'x',
    "{$uuid}\n",
] as $invalidUuid) {
    messageIdempotencyAssert(
        MessageIdempotency::canonicalClientMessageId($invalidUuid) === null,
        'non-v4 or non-canonical client message identifier is rejected'
    );
}

$base = MessageIdempotency::fingerprint(7, 'hello', 'text', null, null);
messageIdempotencyAssert(strlen($base) === 32, 'logical message fingerprints are raw SHA-256 values');
messageIdempotencyAssert(
    hash_equals($base, MessageIdempotency::fingerprint(7, 'hello', 'text', null, null)),
    'the same logical text send has a deterministic fingerprint'
);
foreach ([
    MessageIdempotency::fingerprint(8, 'hello', 'text', null, null),
    MessageIdempotency::fingerprint(7, 'hello!', 'text', null, null),
    MessageIdempotency::fingerprint(7, 'hello', 'text', 3, null),
] as $differentFingerprint) {
    messageIdempotencyAssert(
        !hash_equals($base, $differentFingerprint),
        'chat, content, and reply changes produce a conflict fingerprint'
    );
}

$attachment = [
    'sha256' => str_repeat('a', 64),
    'size' => 123,
    'mime_type' => 'application/pdf',
    'file_name' => 'report.pdf',
];
$attachmentBase = MessageIdempotency::fingerprint(7, 'report', 'file', null, $attachment);
foreach (['sha256', 'size', 'mime_type', 'file_name'] as $field) {
    $changed = $attachment;
    $changed[$field] = match ($field) {
        'sha256' => str_repeat('b', 64),
        'size' => 124,
        'mime_type' => 'text/plain',
        default => 'renamed.pdf',
    };
    messageIdempotencyAssert(
        !hash_equals(
            $attachmentBase,
            MessageIdempotency::fingerprint(7, 'report', 'file', null, $changed)
        ),
        "attachment {$field} participates in the logical-send fingerprint"
    );
}

messageIdempotencyAssert(
    !hash_equals(
        MessageIdempotency::fingerprint(7, 'ab', 'text', null, null),
        MessageIdempotency::fingerprint(7, 'a', 'text', null, null)
    ),
    'length framing keeps adjacent logical values unambiguous'
);

$chatSource = file_get_contents(__DIR__ . '/../classes/Chat.php');
$apiSource = file_get_contents(__DIR__ . '/../api/chat.php');
$migrationSource = file_get_contents(__DIR__ . '/../migrations/20260808_add_message_idempotency.sql');
messageIdempotencyAssert(
    is_string($chatSource) && is_string($apiSource) && is_string($migrationSource),
    'message idempotency implementation sources are readable'
);

messageIdempotencyAssert(
    str_contains($migrationSource, 'client_message_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin') &&
        str_contains($migrationSource, 'client_message_fingerprint BINARY(32)') &&
        str_contains($migrationSource, 'UNIQUE KEY uq_messages_sender_client_message (sender_id, client_message_id)') &&
        substr_count($migrationSource, 'ALGORITHM=INSTANT') === 2 &&
        str_contains($migrationSource, 'ALGORITHM=INPLACE, LOCK=NONE') &&
        str_contains($migrationSource, 'MAX(sub_part) IS NULL') &&
        substr_count($migrationSource, 'information_schema.') >= 3,
    'idempotent migration demands online algorithms for its columns and sender-scoped key'
);

messageIdempotencyAssert(
    str_contains($chatSource, 'WHERE sender_id = ? AND client_message_id = ?') &&
        str_contains($chatSource, 'client_message_id, client_message_fingerprint') &&
        str_contains($chatSource, "'idempotent_replay' => true") &&
        str_contains($chatSource, "'http_status' => 409") &&
        str_contains($chatSource, "'error_code' => 'idempotency_conflict'"),
    'backend resolves exact sender-scoped retries and distinguishes payload conflicts'
);

$rolloutGate = strpos($chatSource, "getenv('PM_MESSAGE_IDEMPOTENCY_ENABLED') !== '1'");
$metadataCheck = strpos($chatSource, 'FROM information_schema.columns');
messageIdempotencyAssert(
    is_int($rolloutGate) && is_int($metadataCheck) && $rolloutGate < $metadataCheck &&
        str_contains($chatSource, "'pm:chat:idempotency-schema-ready:'") &&
        str_contains($chatSource, 'apcu_fetch($cacheKey, $cacheHit)') &&
        str_contains($chatSource, 'apcu_store($cacheKey, true, self::IDEMPOTENCY_SCHEMA_CACHE_TTL)') &&
        str_contains($chatSource, 'private const IDEMPOTENCY_SCHEMA_CACHE_TTL = 300;') &&
        !str_contains($chatSource, 'apcu_store($cacheKey, false') &&
        str_contains($migrationSource, 'PM_MESSAGE_IDEMPOTENCY_ENABLED=1'),
    'capability needs an exact fleet rollout gate and caches only exact positive schema verification'
);

$existingLookup = strpos($chatSource, '$existing = $this->findMessageByClientId');
$rateCheck = strpos($chatSource, '$this->messageRateLimitReached');
$storeUpload = strpos($chatSource, '$this->storeInspectedFileUpload');
messageIdempotencyAssert(
    is_int($existingLookup) && is_int($rateCheck) && is_int($storeUpload) &&
        $existingLookup < $rateCheck && $existingLookup < $storeUpload,
    'exact retries resolve before message quotas and before any uploaded file is moved'
);

messageIdempotencyAssert(
    str_contains($chatSource, '$this->isDuplicateKeyError($insertError, $stmt)') &&
        str_contains($chatSource, '$this->conn->rollback();') &&
        str_contains($chatSource, 'if (!$this->removeStoredAttachment($file_path))') &&
        str_contains($chatSource, 'Unable to remove losing idempotent attachment') &&
        str_contains($chatSource, '$this->createMessageStatus($message_id, $recipientIds);'),
    'concurrent unique-key losers roll back statuses and verify cleanup of only their upload'
);

messageIdempotencyAssert(
    str_contains($chatSource, '$commitAttempted = true;') &&
        str_contains($chatSource, '!$messageCommitted && !$commitAttempted') &&
        str_contains($chatSource, 'ambiguous message commit outcome'),
    'an ambiguous database commit cannot delete a possibly committed attachment'
);

messageIdempotencyAssert(
    str_contains($apiSource, '$clientMessageId = optionalClientMessageId($_POST);') &&
        str_contains($apiSource, '$clientMessageId = optionalClientMessageId($input);') &&
        str_contains($apiSource, 'applyChatApiResponseStatus($response);') &&
        str_contains($apiSource, "if (!array_key_exists('client_message_id', \$input))") &&
        str_contains($apiSource, "'message_idempotency_ready' => \$chat->supportsMessageIdempotency()") &&
        str_contains($chatSource, 'Message retry protection is temporarily unavailable') &&
        str_contains($chatSource, 'Temporary compatibility for pre-idempotency clients') &&
        str_contains($chatSource, 'is_nullable') &&
        str_contains($chatSource, 'column_name, sub_part') &&
        str_contains($chatSource, "\$indexRow['sub_part']"),
    'API capability gating preserves legacy sends until the exact schema and index are ready'
);

echo "Message idempotency tests passed.\n";
