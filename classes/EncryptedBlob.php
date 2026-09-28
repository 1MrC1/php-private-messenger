<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/ProtectedChat.php';

/**
 * Storage for encrypted attachments.
 *
 * WHAT IS DIFFERENT HERE, AND WHY. The ordinary upload path validates bytes it
 * can read: a MIME allow-list, image and archive parsing, and a fail-closed
 * ClamAV scan. Ciphertext defeats all of it — there is nothing to parse and
 * nothing to scan — so this path deliberately does none of those things.
 *
 * What it still does: bounds the size, charges the uploader's quota, records a
 * digest of exactly the bytes it stored, and refuses to serve a blob to anyone
 * who is not in the conversation. What it cannot do is tell you the file is
 * safe. That loss is real and the interface says so; do not quietly present
 * these as equivalent to scanned uploads.
 */
final class EncryptedBlob
{
    /** Ciphertext travels as base64 in JSON, so the cap is deliberately modest. */
    public const MAX_BLOB_BYTES = 8 * 1024 * 1024;
    public const HOURLY_BLOB_BYTES = 64 * 1024 * 1024;
    public const HOURLY_BLOB_COUNT = 30;

    private const DIRECTORY = 'uploads/blobs';

    private Database $db;
    private mysqli $conn;

    public function __construct(?mysqli $conn = null)
    {
        if ($conn instanceof mysqli) {
            $this->conn = $conn;
            return;
        }
        $this->db = new Database();
        $this->conn = $this->db->connect();
    }

    /**
     * Store one encrypted blob for a protected conversation.
     *
     * The caller must already have proved the uploader is in that conversation
     * and that the conversation is protected; both are checked again here,
     * because a storage class that trusts its caller is one refactor away from
     * being wrong.
     */
    public function store(int $uploaderId, int $chatId, string $ciphertext, ProtectedChat $chats): array
    {
        $chats->assertProtectionMatches($chatId, true);
        if (!$chats->isParticipant($chatId, $uploaderId)) {
            throw new ProtectedChatMismatch('You are not in this conversation', 'not_a_participant');
        }

        $size = strlen($ciphertext);
        if ($size < 1 || $size > self::MAX_BLOB_BYTES) {
            throw new ProtectedChatMismatch('That file is too large to send encrypted', 'blob_too_large');
        }
        $this->assertWithinQuota($uploaderId, $size);

        $root = dirname(__DIR__);
        $directory = $root . '/' . self::DIRECTORY;
        if (!is_dir($directory) && !@mkdir($directory, 0750, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to prepare encrypted attachment storage');
        }

        // The name carries no information about the file: it cannot, because
        // the server does not know anything about it.
        $name = 'blob_' . bin2hex(random_bytes(16)) . '.bin';
        $path = $directory . '/' . $name;
        if (file_put_contents($path, $ciphertext, LOCK_EX) !== $size) {
            @unlink($path);
            throw new RuntimeException('Unable to store the encrypted attachment');
        }
        @chmod($path, 0640);

        // Hash what is actually on disk, not what we were handed.
        $digest = hash_file('sha256', $path, true);
        if (!is_string($digest) || !hash_equals(hash('sha256', $ciphertext, true), $digest)) {
            @unlink($path);
            throw new RuntimeException('The stored attachment did not match what was sent');
        }

        $relative = self::DIRECTORY . '/' . $name;
        $this->execute(
            'INSERT INTO encrypted_blobs (uploader_id, chat_id, blob_path, byte_size, sha256)
             VALUES (?, ?, ?, ?, ?)',
            'iisis',
            [$uploaderId, $chatId, $relative, $size, $digest]
        );

        return [
            'blob_id' => (int)$this->conn->insert_id,
            'byte_size' => $size,
            'sha256' => base64_encode($digest),
        ];
    }

    /**
     * Return one blob's ciphertext to a participant.
     *
     * Authorization is evaluated from the database on every request, never
     * cached, and never inferred from the blob id alone.
     */
    public function fetch(int $userId, int $blobId, ProtectedChat $chats): array
    {
        $rows = $this->select(
            'SELECT chat_id, blob_path, byte_size, sha256 FROM encrypted_blobs WHERE id = ?',
            'i',
            [$blobId]
        );
        if ($rows === []) {
            throw new ProtectedChatMismatch('Unknown attachment', 'unknown_blob');
        }
        $chatId = (int)$rows[0]['chat_id'];
        if (!$chats->isParticipant($chatId, $userId)) {
            throw new ProtectedChatMismatch('You are not in this conversation', 'not_a_participant');
        }

        $path = dirname(__DIR__) . '/' . (string)$rows[0]['blob_path'];
        $real = realpath($path);
        $expectedRoot = realpath(dirname(__DIR__) . '/' . self::DIRECTORY);
        if ($real === false || $expectedRoot === false ||
            strncmp($real, $expectedRoot . DIRECTORY_SEPARATOR, strlen($expectedRoot) + 1) !== 0 ||
            !is_file($real) || is_link($real)) {
            throw new ProtectedChatMismatch('Unknown attachment', 'unknown_blob');
        }

        $ciphertext = file_get_contents($real);
        if (!is_string($ciphertext) ||
            !hash_equals((string)$rows[0]['sha256'], hash('sha256', $ciphertext, true))) {
            // Refuse rather than serve bytes that are not the ones recorded.
            throw new ProtectedChatMismatch('That attachment could not be read', 'blob_corrupt');
        }

        return [
            'blob_id' => $blobId,
            'byte_size' => (int)$rows[0]['byte_size'],
            'sha256' => base64_encode((string)$rows[0]['sha256']),
            'ciphertext' => base64_encode($ciphertext),
        ];
    }

    /** Tie a stored blob to the message that carries its key. */
    public function attachToMessage(int $blobId, int $messageId): void
    {
        $this->execute(
            'UPDATE encrypted_blobs SET referenced_message_id = ? WHERE id = ? AND referenced_message_id IS NULL',
            'ii',
            [$messageId, $blobId]
        );
    }

    private function assertWithinQuota(int $uploaderId, int $size): void
    {
        $rows = $this->select(
            'SELECT COUNT(*) AS uploads, COALESCE(SUM(byte_size), 0) AS bytes
             FROM encrypted_blobs
             WHERE uploader_id = ? AND created_at >= (NOW() - INTERVAL 1 HOUR)',
            'i',
            [$uploaderId]
        );
        $uploads = (int)($rows[0]['uploads'] ?? 0);
        $bytes = (int)($rows[0]['bytes'] ?? 0);
        if ($uploads >= self::HOURLY_BLOB_COUNT || $bytes + $size > self::HOURLY_BLOB_BYTES) {
            throw new ProtectedChatMismatch('Hourly attachment limit reached', 'blob_quota');
        }
    }

    /** @return list<array<string, mixed>> */
    private function select(string $sql, string $types, array $params): array
    {
        $stmt = $this->conn->prepare($sql);
        if ($stmt === false) {
            throw new RuntimeException('Unable to prepare attachment query');
        }
        try {
            $stmt->bind_param($types, ...$params);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to run attachment query');
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
            throw new RuntimeException('Unable to prepare attachment statement');
        }
        try {
            $stmt->bind_param($types, ...$params);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to run attachment statement');
            }
        } finally {
            $stmt->close();
        }
    }
}
