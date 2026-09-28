<?php

declare(strict_types=1);

/**
 * Canonical client message identifiers and stable logical-send fingerprints.
 *
 * The fingerprint is deliberately computed from length-framed fields rather
 * than JSON. That keeps it independent of object ordering and prevents two
 * different field sequences from producing the same byte stream.
 */
final class MessageIdempotency
{
    private const UUID_V4_PATTERN =
        '/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/Di';

    public static function canonicalClientMessageId($value): ?string
    {
        if (!is_string($value) || preg_match(self::UUID_V4_PATTERN, $value) !== 1) {
            return null;
        }

        return strtolower($value);
    }

    /**
     * Return a raw 32-byte SHA-256 fingerprint suitable for BINARY(32).
     *
     * Attachment metadata must describe the server-validated upload, not
     * client-provided MIME metadata. A null attachment denotes a text send.
     */
    public static function fingerprint(
        int $chatId,
        string $content,
        string $messageType,
        ?int $replyTo,
        ?array $attachment
    ): string {
        if ($chatId < 1 || ($replyTo !== null && $replyTo < 1)) {
            throw new InvalidArgumentException('Invalid message fingerprint identity');
        }
        if (!in_array($messageType, ['text', 'image', 'file', 'audio', 'video'], true)) {
            throw new InvalidArgumentException('Invalid message fingerprint type');
        }

        $fields = [
            'pm-message-idempotency-v1',
            (string)$chatId,
            $content,
            $messageType,
            $replyTo === null ? 'none' : (string)$replyTo,
        ];

        if ($attachment === null) {
            $fields[] = 'no-attachment';
        } else {
            foreach (['sha256', 'size', 'mime_type', 'file_name'] as $field) {
                if (!array_key_exists($field, $attachment) ||
                    (!is_string($attachment[$field]) && !is_int($attachment[$field]))) {
                    throw new InvalidArgumentException('Invalid attachment fingerprint');
                }
            }
            $sha256 = strtolower((string)$attachment['sha256']);
            $size = is_int($attachment['size'])
                ? $attachment['size']
                : (preg_match('/\A[1-9][0-9]*\z/D', (string)$attachment['size']) === 1
                    ? (int)$attachment['size']
                    : 0);
            if (preg_match('/\A[a-f0-9]{64}\z/D', $sha256) !== 1 || $size < 1 ||
                !is_string($attachment['mime_type']) || $attachment['mime_type'] === '' ||
                !is_string($attachment['file_name']) || $attachment['file_name'] === '') {
                throw new InvalidArgumentException('Invalid attachment fingerprint');
            }

            $fields[] = 'attachment';
            $fields[] = $sha256;
            $fields[] = (string)$size;
            $fields[] = $attachment['mime_type'];
            $fields[] = $attachment['file_name'];
        }

        return self::digest($fields);
    }

    /**
     * The same retry protection for a protected conversation, without the
     * content oracle.
     *
     * fingerprint() hashes the plaintext, which is exactly what must not happen
     * for an encrypted message: anyone holding the database or a backup could
     * confirm a guessed message by recomputing the digest. Here the ciphertext
     * and the authenticated-data digest stand in for the content, so the
     * fingerprint reveals nothing that is not already in the same row.
     *
     * A separate domain tag keeps the two schemes from ever colliding.
     *
     * The client must seal once and retry the same bytes. Re-encrypting on retry
     * produces different ciphertext, so the retry would not be recognised as one
     * — and it would burn MLS key-schedule state.
     */
    public static function envelopeFingerprint(
        int $chatId,
        string $ciphertext,
        string $aadDigest,
        ?int $replyTo,
        ?array $blob
    ): string {
        if ($chatId < 1 || ($replyTo !== null && $replyTo < 1)) {
            throw new InvalidArgumentException('Invalid message fingerprint identity');
        }
        if ($ciphertext === '' || strlen($aadDigest) !== 32) {
            throw new InvalidArgumentException('Invalid envelope fingerprint input');
        }

        $fields = [
            'pm-message-envelope-idempotency-v1',
            (string)$chatId,
            $ciphertext,
            $aadDigest,
            $replyTo === null ? 'none' : (string)$replyTo,
        ];

        if ($blob === null) {
            $fields[] = 'no-blob';
        } else {
            // Only what the server can already observe about an encrypted blob.
            // Deliberately no mime_type and no file_name: for a protected
            // attachment those are inside the envelope, not metadata.
            foreach (['sha256', 'size'] as $field) {
                if (!array_key_exists($field, $blob)) {
                    throw new InvalidArgumentException('Invalid blob fingerprint');
                }
            }
            $sha256 = strtolower((string)$blob['sha256']);
            $size = is_int($blob['size']) ? $blob['size'] : 0;
            if (preg_match('/\A[a-f0-9]{64}\z/D', $sha256) !== 1 || $size < 1) {
                throw new InvalidArgumentException('Invalid blob fingerprint');
            }
            $fields[] = 'blob';
            $fields[] = $sha256;
            $fields[] = (string)$size;
        }

        return self::digest($fields);
    }

    /** @param list<string> $fields */
    private static function digest(array $fields): string
    {
        $context = hash_init('sha256');
        foreach ($fields as $field) {
            // Every field is already bounded by the API/upload limits. An
            // unsigned 64-bit length keeps framing portable and unambiguous.
            $length = strlen($field);
            hash_update($context, pack('N2', intdiv($length, 4294967296), $length % 4294967296));
            hash_update($context, $field);
        }

        return hash_final($context, true);
    }
}
