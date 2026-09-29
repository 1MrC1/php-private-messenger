<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/MessageIdempotency.php';

/**
 * Storage and delivery for protected conversations: the server-side half of a
 * future end-to-end encrypted mode, which does not exist yet.
 *
 * WHAT THIS IS NOT: this class performs no cryptography. It stores opaque
 * ciphertext produced by a client and relays the MLS handshake material that is
 * public by design in RFC 9420. Until a client exists that can produce those
 * bytes, and until that client has been independently reviewed, nothing here
 * entitles anyone to describe this application as end-to-end encrypted. See
 * docs/security/e2ee-readiness.md.
 *
 * The two invariants worth stating plainly, because everything else follows:
 *
 *  1. A conversation is protected or it is not, decided when it is created and
 *     never afterwards. There is no upgrade path, because upgrading would leave
 *     the server holding the plaintext history of a conversation the interface
 *     had started calling protected.
 *  2. Plaintext never enters a protected chat and an envelope never enters a
 *     plaintext one. Both directions are hard failures, never a fallback.
 */
final class ProtectedChat
{
    public const PROTOCOL = 'mls';
    public const ENVELOPE_VERSION = 1;

    /** Matches message_envelopes.ciphertext. */
    public const MAX_CIPHERTEXT_BYTES = 24576;
    public const MAX_HANDSHAKE_BYTES = 65535;
    public const MAX_PAGE = 100;

    /** 1 text, 2 attachment descriptor, 3 security event. */
    public const CONTENT_TYPES = [1, 2, 3];
    /** 1 proposal, 2 commit, 3 welcome. */
    public const HANDSHAKE_KINDS = [1, 2, 3];

    private const SCHEMA_CACHE_TTL = 300;

    private static ?bool $schemaReady = null;

    private Database $db;
    private mysqli $conn;

    public function __construct()
    {
        $this->db = new Database();
        $this->conn = $this->db->connect();
    }

    // ---- availability ------------------------------------------------------

    /**
     * The fleet-wide gate. Like message idempotency, schema readiness alone is
     * not enough: a mixed-version fleet must not start accepting envelopes
     * until every node can serve them back.
     */
    public static function isEnabled(): bool
    {
        return getenv('PM_PROTECTED_CHATS_ENABLED') === '1';
    }

    public function supportsProtectedChats(): bool
    {
        if (!self::isEnabled()) {
            return false;
        }
        if (self::$schemaReady === true) {
            return true;
        }

        $cacheKey = 'pm_protected_schema_' . hash('sha256', (string)($this->conn->host_info ?? ''));
        if (function_exists('apcu_fetch')) {
            try {
                $hit = false;
                $cached = apcu_fetch($cacheKey, $hit);
                if ($hit && $cached === true) {
                    self::$schemaReady = true;
                    return true;
                }
            } catch (Throwable $ignored) {
                // Fall through to exact verification.
            }
        }

        try {
            $tables = $this->conn->query("
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = DATABASE()
                  AND table_name IN (
                        'chat_protection', 'message_envelopes', 'mls_groups', 'mls_handshake_messages',
                        'e2ee_devices', 'e2ee_key_packages', 'e2ee_directory_log', 'encrypted_blobs'
                      )
            ");
            // All eight, not the first four: a review found this advertising
            // readiness while the device directory and blob tables were absent,
            // which is a conversation that can be protected but never joined.
            if ($tables === false || $tables->num_rows !== 8) {
                return false;
            }

            // The ciphertext column must be binary. If it ever became a text
            // type a character set would start rewriting ciphertext, which
            // would corrupt messages silently rather than loudly.
            $column = $this->conn->query("
                SELECT data_type, character_maximum_length
                FROM information_schema.columns
                WHERE table_schema = DATABASE()
                  AND table_name = 'message_envelopes'
                  AND column_name = 'ciphertext'
            ");
            $row = $column === false ? null : $column->fetch_assoc();
            $row = is_array($row) ? array_change_key_case($row, CASE_LOWER) : null;
            if (($row['data_type'] ?? null) !== 'varbinary' ||
                (int)($row['character_maximum_length'] ?? 0) !== self::MAX_CIPHERTEXT_BYTES) {
                return false;
            }

            self::$schemaReady = true;
            if (function_exists('apcu_store')) {
                try {
                    // Positive results only, exactly as the idempotency gate does.
                    apcu_store($cacheKey, true, self::SCHEMA_CACHE_TTL);
                } catch (Throwable $ignored) {
                }
            }
            return true;
        } catch (Throwable $ignored) {
            return false;
        }
    }

    // ---- protection state --------------------------------------------------

    /** @return array{protocol:string,protocol_version:int,latest_epoch:int}|null */
    public function protectionFor(int $chatId): ?array
    {
        $rows = $this->select(
            'SELECT protocol, protocol_version, latest_epoch FROM chat_protection WHERE chat_id = ?',
            'i',
            [$chatId]
        );
        if ($rows === []) {
            return null;
        }
        return [
            'protocol' => (string)$rows[0]['protocol'],
            'protocol_version' => (int)$rows[0]['protocol_version'],
            'latest_epoch' => (int)$rows[0]['latest_epoch'],
        ];
    }

    public function isProtected(int $chatId): bool
    {
        return $this->protectionFor($chatId) !== null;
    }

    /**
     * The single chokepoint. Both mismatches throw; neither degrades.
     *
     * @throws ProtectedChatMismatch
     */
    public function assertProtectionMatches(int $chatId, bool $expectProtected): void
    {
        $actual = $this->isProtected($chatId);
        if ($actual === $expectProtected) {
            return;
        }
        throw new ProtectedChatMismatch(
            $actual
                ? 'This conversation is protected and cannot accept plaintext'
                : 'This conversation is not protected and cannot accept an envelope',
            $actual ? 'chat_protected' : 'chat_not_protected'
        );
    }

    public function isParticipant(int $chatId, int $userId): bool
    {
        $rows = $this->select(
            'SELECT 1 AS present FROM chat_participants WHERE chat_id = ? AND user_id = ? AND left_at IS NULL',
            'ii',
            [$chatId, $userId]
        );
        return $rows !== [];
    }

    // ---- establishing a protected conversation -----------------------------

    /**
     * Mark a chat protected and register its MLS group. Irreversible by design,
     * and refused if the chat already holds any message: a conversation with
     * plaintext history cannot become one the interface calls protected.
     */
    public function establishProtection(int $chatId, int $userId, string $groupIdBase64, int $cipherSuite): array
    {
        $groupId = self::decodeExact($groupIdBase64, 32, 'group identifier');
        if ($cipherSuite < 1 || $cipherSuite > 65535) {
            throw new ProtectedChatMismatch('Unsupported cipher suite', 'invalid_cipher_suite');
        }
        if (!$this->isParticipant($chatId, $userId)) {
            throw new ProtectedChatMismatch('You are not in this conversation', 'not_a_participant');
        }
        if ($this->isProtected($chatId)) {
            throw new ProtectedChatMismatch('This conversation is already protected', 'chat_protected');
        }
        if ($this->select('SELECT 1 AS present FROM messages WHERE chat_id = ? LIMIT 1', 'i', [$chatId]) !== []) {
            throw new ProtectedChatMismatch(
                'A conversation with existing messages cannot be protected',
                'chat_has_history'
            );
        }

        $this->conn->begin_transaction();
        try {
            $this->execute(
                'INSERT INTO chat_protection (chat_id, protocol, protocol_version, established_by)
                 VALUES (?, ?, ?, ?)',
                'isii',
                [$chatId, self::PROTOCOL, self::ENVELOPE_VERSION, $userId]
            );
            $this->execute(
                'INSERT INTO mls_groups (chat_id, group_id, cipher_suite) VALUES (?, ?, ?)',
                'isi',
                [$chatId, $groupId, $cipherSuite]
            );
            $this->conn->commit();
        } catch (Throwable $error) {
            $this->conn->rollback();
            throw $error;
        }

        return ['chat_id' => $chatId, 'protocol' => self::PROTOCOL, 'protocol_version' => self::ENVELOPE_VERSION];
    }

    // ---- envelopes ---------------------------------------------------------

    /**
     * Check the shape of an envelope, without touching the database.
     *
     * Deliberately separate from storing it: everything here is decidable from
     * the envelope alone, so it can be tested directly, and a new caller cannot
     * accidentally skip it. Nothing here inspects the ciphertext — the server
     * cannot and must not be able to.
     *
     * @param array<string, mixed> $envelope
     * @return array{version: int, content_type: int, epoch: int, sender_leaf: int, group_id: string, aad_digest: string, ciphertext: string}
     */
    public static function parseEnvelope(array $envelope): array
    {
        $version = (int)($envelope['envelope_version'] ?? 0);
        if ($version !== self::ENVELOPE_VERSION) {
            throw new ProtectedChatMismatch('Unsupported envelope version', 'unsupported_envelope_version');
        }
        $contentType = (int)($envelope['content_type'] ?? 0);
        if (!in_array($contentType, self::CONTENT_TYPES, true)) {
            throw new ProtectedChatMismatch('Unsupported envelope content type', 'invalid_envelope');
        }
        $epoch = (int)($envelope['epoch'] ?? -1);
        $senderLeaf = (int)($envelope['sender_leaf'] ?? -1);
        if ($epoch < 0 || $senderLeaf < 0) {
            throw new ProtectedChatMismatch('Invalid envelope position', 'invalid_envelope');
        }

        return [
            'version' => $version,
            'content_type' => $contentType,
            'epoch' => $epoch,
            'sender_leaf' => $senderLeaf,
            'group_id' => self::decodeExact((string)($envelope['group_id'] ?? ''), 32, 'group identifier'),
            'aad_digest' => self::decodeExact((string)($envelope['aad_digest'] ?? ''), 32, 'authenticated data digest'),
            'ciphertext' => self::decodeBounded(
                (string)($envelope['ciphertext'] ?? ''),
                self::MAX_CIPHERTEXT_BYTES,
                'ciphertext'
            ),
        ];
    }

    /**
     * Store one sealed message. `messages.content` is written as the empty
     * string: it is already a legal value here, every existing reader tolerates
     * it, and `content LIKE '%needle%'` cannot match it — so server-side search
     * fails closed for protected chats with no extra code.
     */
    public function storeEnvelope(
        int $chatId,
        int $senderId,
        array $envelope,
        ?string $clientMessageId = null,
        ?int $blobId = null
    ): array {
        $this->assertProtectionMatches($chatId, true);
        if (!$this->isParticipant($chatId, $senderId)) {
            throw new ProtectedChatMismatch('You are not in this conversation', 'not_a_participant');
        }

        [
            'version' => $version,
            'content_type' => $contentType,
            'epoch' => $epoch,
            'sender_leaf' => $senderLeaf,
            'group_id' => $groupId,
            'aad_digest' => $aadDigest,
            'ciphertext' => $ciphertext,
        ] = self::parseEnvelope($envelope);

        // Retry protection over ciphertext.
        //
        // The plaintext path has had this since the idempotency work; the
        // protected path had the function and no caller, which a review noticed.
        // The domain is separate and the input is what the server can already
        // see, so unlike the plaintext fingerprint this cannot be used as an
        // oracle for guessed content.
        $normalizedClientMessageId = null;
        $fingerprint = null;
        if ($clientMessageId !== null) {
            $normalizedClientMessageId = MessageIdempotency::canonicalClientMessageId($clientMessageId);
            if ($normalizedClientMessageId === null) {
                throw new ProtectedChatMismatch('Message retry identifier is invalid', 'invalid_client_message_id');
            }
            $fingerprint = MessageIdempotency::envelopeFingerprint(
                $chatId,
                $ciphertext,
                $aadDigest,
                null,
                $blobId === null ? null : ['sha256' => hash('sha256', 'blob:' . $blobId), 'size' => $blobId]
            );

            $existing = $this->select(
                'SELECT id, client_message_fingerprint FROM messages
                  WHERE sender_id = ? AND client_message_id = ?',
                'is',
                [$senderId, $normalizedClientMessageId]
            );
            if ($existing !== []) {
                // The same identifier for the same bytes is a retry; for
                // different bytes it is a client bug or an attempt to overwrite,
                // and either way it must not quietly replace anything.
                if (!hash_equals((string)$existing[0]['client_message_fingerprint'], $fingerprint)) {
                    throw new ProtectedChatMismatch(
                        'client_message_id was already used for a different message',
                        'idempotency_conflict'
                    );
                }
                return [
                    'message_id' => (int)$existing[0]['id'],
                    'chat_id' => $chatId,
                    'replayed' => true,
                ];
            }
        }

        $group = $this->select('SELECT group_id, current_epoch FROM mls_groups WHERE chat_id = ?', 'i', [$chatId]);
        if ($group === [] || !hash_equals((string)$group[0]['group_id'], $groupId)) {
            throw new ProtectedChatMismatch('Envelope does not belong to this conversation', 'group_mismatch');
        }

        // Epoch rollback is refused. This is an ordering aid, not a security
        // property: the real defence is that clients reject out-of-epoch
        // messages themselves.
        $protection = $this->protectionFor($chatId);
        if ($protection !== null && $epoch < $protection['latest_epoch']) {
            throw new ProtectedChatMismatch('Envelope epoch is behind the conversation', 'epoch_rollback');
        }

        $this->conn->begin_transaction();
        try {
            if ($normalizedClientMessageId === null) {
                $this->execute(
                    "INSERT INTO messages (chat_id, sender_id, message_type, content) VALUES (?, ?, 'text', '')",
                    'ii',
                    [$chatId, $senderId]
                );
            } else {
                $this->execute(
                    "INSERT INTO messages
                        (chat_id, sender_id, message_type, content, client_message_id, client_message_fingerprint)
                     VALUES (?, ?, 'text', '', ?, ?)",
                    'iiss',
                    [$chatId, $senderId, $normalizedClientMessageId, $fingerprint]
                );
            }
            $messageId = (int)$this->conn->insert_id;

            $this->execute(
                'INSERT INTO message_envelopes
                    (message_id, envelope_version, protocol, group_id, epoch, sender_leaf, content_type, ciphertext, aad_digest)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                'iissiiiss',
                [$messageId, $version, self::PROTOCOL, $groupId, $epoch, $senderLeaf, $contentType, $ciphertext, $aadDigest]
            );
            $this->execute(
                'UPDATE chat_protection SET latest_epoch = GREATEST(latest_epoch, ?) WHERE chat_id = ?',
                'ii',
                [$epoch, $chatId]
            );
            $this->conn->commit();
        } catch (Throwable $error) {
            $this->conn->rollback();
            throw $error;
        }

        return ['message_id' => $messageId, 'epoch' => $epoch];
    }

    /** @return list<array<string, mixed>> envelopes after a cursor, oldest first */
    public function envelopesAfter(int $chatId, int $userId, int $afterMessageId, int $limit): array
    {
        $this->assertProtectionMatches($chatId, true);
        if (!$this->isParticipant($chatId, $userId)) {
            throw new ProtectedChatMismatch('You are not in this conversation', 'not_a_participant');
        }
        $limit = max(1, min(self::MAX_PAGE, $limit));

        $rows = $this->select(
            'SELECT e.message_id, e.envelope_version, e.protocol, e.epoch, e.sender_leaf,
                    e.content_type, e.ciphertext, e.aad_digest, m.sender_id, m.created_at, m.is_deleted
             FROM message_envelopes e
             JOIN messages m ON m.id = e.message_id
             WHERE m.chat_id = ? AND e.message_id > ? AND m.is_deleted = 0
             ORDER BY e.message_id
             LIMIT ' . $limit,
            'ii',
            [$chatId, $afterMessageId]
        );

        return array_map(static function (array $row): array {
            return [
                'message_id' => (int)$row['message_id'],
                'envelope_version' => (int)$row['envelope_version'],
                'protocol' => (string)$row['protocol'],
                'epoch' => (int)$row['epoch'],
                'sender_leaf' => (int)$row['sender_leaf'],
                'content_type' => (int)$row['content_type'],
                // Base64 on the wire: responses are encoded with
                // JSON_INVALID_UTF8_SUBSTITUTE, which would silently replace
                // raw ciphertext bytes.
                'ciphertext' => base64_encode((string)$row['ciphertext']),
                'aad_digest' => base64_encode((string)$row['aad_digest']),
                'sender_id' => (int)$row['sender_id'],
                'created_at' => (string)$row['created_at'],
            ];
        }, $rows);
    }

    // ---- handshake relay ---------------------------------------------------

    /**
     * Append one handshake message and give it the next sequence number for the
     * group. The sequence is assigned while holding the group row, so two
     * concurrent commits cannot claim the same slot; the unique key turns any
     * remaining race into a database error rather than a silent divergence.
     */
    public function postHandshake(int $chatId, int $userId, int $kind, int $epoch, string $payloadBase64): array
    {
        $this->assertProtectionMatches($chatId, true);
        if (!$this->isParticipant($chatId, $userId)) {
            throw new ProtectedChatMismatch('You are not in this conversation', 'not_a_participant');
        }
        if (!in_array($kind, self::HANDSHAKE_KINDS, true) || $epoch < 0) {
            throw new ProtectedChatMismatch('Invalid handshake message', 'invalid_handshake');
        }
        $payload = self::decodeBounded($payloadBase64, self::MAX_HANDSHAKE_BYTES, 'handshake payload');

        $this->conn->begin_transaction();
        try {
            $locked = $this->select(
                'SELECT next_sequence, current_epoch FROM mls_groups WHERE chat_id = ? FOR UPDATE',
                'i',
                [$chatId]
            );
            if ($locked === []) {
                throw new ProtectedChatMismatch('This conversation has no group', 'group_missing');
            }
            $sequence = (int)$locked[0]['next_sequence'];

            $this->execute(
                'INSERT INTO mls_handshake_messages (chat_id, sequence, epoch, kind, sender_user_id, payload)
                 VALUES (?, ?, ?, ?, ?, ?)',
                'iiiiis',
                [$chatId, $sequence, $epoch, $kind, $userId, $payload]
            );
            $this->execute(
                'UPDATE mls_groups
                    SET next_sequence = next_sequence + 1,
                        current_epoch = GREATEST(current_epoch, ?)
                  WHERE chat_id = ?',
                'ii',
                [$epoch, $chatId]
            );
            $this->conn->commit();
        } catch (Throwable $error) {
            $this->conn->rollback();
            throw $error;
        }

        return ['sequence' => $sequence, 'epoch' => $epoch];
    }

    /** @return list<array<string, mixed>> handshakes after a cursor, in order */
    public function handshakesAfter(int $chatId, int $userId, int $afterSequence, int $limit): array
    {
        $this->assertProtectionMatches($chatId, true);
        if (!$this->isParticipant($chatId, $userId)) {
            throw new ProtectedChatMismatch('You are not in this conversation', 'not_a_participant');
        }
        $limit = max(1, min(self::MAX_PAGE, $limit));

        $rows = $this->select(
            'SELECT sequence, epoch, kind, sender_user_id, payload, created_at
             FROM mls_handshake_messages
             WHERE chat_id = ? AND sequence > ?
             ORDER BY sequence
             LIMIT ' . $limit,
            'ii',
            [$chatId, $afterSequence]
        );

        return array_map(static fn(array $row): array => [
            'sequence' => (int)$row['sequence'],
            'epoch' => (int)$row['epoch'],
            'kind' => (int)$row['kind'],
            'sender_id' => $row['sender_user_id'] === null ? null : (int)$row['sender_user_id'],
            'payload' => base64_encode((string)$row['payload']),
            'created_at' => (string)$row['created_at'],
        ], $rows);
    }

    // ---- encoding helpers --------------------------------------------------

    /** Strict base64: no whitespace, no alternative alphabets, exact round-trip. */
    public static function decodeBase64(string $value, string $label): string
    {
        if ($value === '' || strlen($value) > 65536) {
            throw new ProtectedChatMismatch('Invalid ' . $label, 'invalid_envelope');
        }
        $decoded = base64_decode($value, true);
        if ($decoded === false || base64_encode($decoded) !== $value) {
            throw new ProtectedChatMismatch('Invalid ' . $label, 'invalid_envelope');
        }
        return $decoded;
    }

    public static function decodeExact(string $value, int $bytes, string $label): string
    {
        $decoded = self::decodeBase64($value, $label);
        if (strlen($decoded) !== $bytes) {
            throw new ProtectedChatMismatch('Invalid ' . $label, 'invalid_envelope');
        }
        return $decoded;
    }

    public static function decodeBounded(string $value, int $maxBytes, string $label): string
    {
        $decoded = self::decodeBase64($value, $label);
        if (strlen($decoded) < 1 || strlen($decoded) > $maxBytes) {
            throw new ProtectedChatMismatch('Invalid ' . $label, 'invalid_envelope');
        }
        return $decoded;
    }

    // ---- small query helpers ----------------------------------------------

    /** @return list<array<string, mixed>> */
    private function select(string $sql, string $types, array $params): array
    {
        $stmt = $this->conn->prepare($sql);
        if ($stmt === false) {
            throw new RuntimeException('Unable to prepare protected chat query');
        }
        try {
            if ($params !== []) {
                $stmt->bind_param($types, ...$params);
            }
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to run protected chat query');
            }
            $result = $stmt->get_result();
            return $result === false ? [] : $result->fetch_all(MYSQLI_ASSOC);
        } finally {
            $stmt->close();
        }
    }

    private function execute(string $sql, string $types, array $params): void
    {
        $stmt = $this->conn->prepare($sql);
        if ($stmt === false) {
            throw new RuntimeException('Unable to prepare protected chat statement');
        }
        try {
            $stmt->bind_param($types, ...$params);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to run protected chat statement');
            }
        } finally {
            $stmt->close();
        }
    }

    public function __destruct()
    {
        try {
            $this->db->close();
        } catch (Throwable $ignored) {
        }
    }
}

/** A refusal that carries a stable machine-readable code for the API layer. */
final class ProtectedChatMismatch extends RuntimeException
{
    private string $errorCode;

    public function __construct(string $message, string $errorCode)
    {
        parent::__construct($message);
        $this->errorCode = $errorCode;
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }
}
