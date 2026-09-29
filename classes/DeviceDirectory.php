<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/ProtectedChat.php';

/**
 * Device identities and key transport for protected conversations.
 *
 * In MLS a group member is a device, not an account: a phone and a laptop hold
 * different signature keys and appear as separate leaves. This class stores
 * those public identities, hands out one-time key packages, and records every
 * change in an append-only hash chain.
 *
 * What the chain does and does not give you, stated honestly: a client that has
 * already seen the log can detect a server that later rewrites or drops an
 * entry, because the chain stops extending from the head it remembers. It is
 * not key transparency. There is no third-party monitor and no cross-user
 * gossip, so a server that lies consistently to a client which has never seen
 * the truth is not caught by this alone. Safety numbers are what close that
 * gap, and they are not built yet.
 *
 * No private key ever reaches this class.
 */
final class DeviceDirectory
{
    public const ENTRY_ENROLLED = 1;
    public const ENTRY_REVOKED = 2;

    public const MAX_KEY_PACKAGES_PER_PUBLISH = 20;
    public const MAX_KEY_PACKAGE_BYTES = 16384;
    public const MAX_SIGNATURE_KEY_BYTES = 1024;
    public const MAX_CREDENTIAL_BYTES = 4096;
    public const LOW_WATERMARK = 5;

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

    // ---- enrollment --------------------------------------------------------

    /**
     * Register a device. The caller must already have proved a fresh password
     * and second factor; this method assumes that gate has been passed and does
     * the storage half atomically, so a device and its directory entry either
     * both exist or neither does.
     *
     * @param list<string> $keyPackagesBase64
     */
    public function enrollDevice(
        int $userId,
        string $publicIdBase64,
        string $signatureKeyBase64,
        string $credentialBase64,
        int $cipherSuite,
        ?string $label,
        array $keyPackagesBase64
    ): array {
        $publicId = ProtectedChat::decodeExact($publicIdBase64, 32, 'device identifier');
        $signatureKey = ProtectedChat::decodeBounded($signatureKeyBase64, self::MAX_SIGNATURE_KEY_BYTES, 'signature key');
        $credential = ProtectedChat::decodeBounded($credentialBase64, self::MAX_CREDENTIAL_BYTES, 'credential');
        if ($cipherSuite < 1 || $cipherSuite > 65535) {
            throw new ProtectedChatMismatch('Unsupported cipher suite', 'invalid_cipher_suite');
        }
        if ($label !== null && (strlen($label) > 64 || preg_match('//u', $label) !== 1)) {
            throw new ProtectedChatMismatch('Invalid device label', 'invalid_device_label');
        }
        $packages = $this->decodeKeyPackages($keyPackagesBase64);

        $this->conn->begin_transaction();
        try {
            $this->execute(
                'INSERT INTO e2ee_devices
                    (user_id, public_id, label, signature_public_key, credential, cipher_suite)
                 VALUES (?, ?, ?, ?, ?, ?)',
                'issssi',
                [$userId, $publicId, $label, $signatureKey, $credential, $cipherSuite]
            );
            $deviceId = (int)$this->conn->insert_id;

            $this->insertKeyPackages($deviceId, $packages);
            $this->appendDirectoryEntry(self::ENTRY_ENROLLED, $userId, $deviceId, $publicId . $signatureKey);

            $this->conn->commit();
        } catch (mysqli_sql_exception $error) {
            $this->conn->rollback();
            if ((int)$error->getCode() === 1062) {
                throw new ProtectedChatMismatch('This device is already enrolled', 'device_exists');
            }
            throw $error;
        } catch (Throwable $error) {
            $this->conn->rollback();
            throw $error;
        }

        return ['device_id' => $deviceId, 'key_packages_stored' => count($packages)];
    }

    /**
     * Retire a device. Also consumes its unclaimed key packages, so nobody can
     * still be handed one for a device its owner has just disowned.
     */
    public function revokeDevice(int $userId, int $deviceId): array
    {
        $rows = $this->select(
            'SELECT public_id, revoked_at FROM e2ee_devices WHERE id = ? AND user_id = ?',
            'ii',
            [$deviceId, $userId]
        );
        if ($rows === []) {
            throw new ProtectedChatMismatch('Unknown device', 'unknown_device');
        }
        if ($rows[0]['revoked_at'] !== null) {
            throw new ProtectedChatMismatch('This device is already revoked', 'device_revoked');
        }

        $this->conn->begin_transaction();
        try {
            $this->execute('UPDATE e2ee_devices SET revoked_at = NOW() WHERE id = ?', 'i', [$deviceId]);
            $this->execute(
                'DELETE FROM e2ee_key_packages WHERE device_id = ? AND consumed_at IS NULL',
                'i',
                [$deviceId]
            );
            $this->appendDirectoryEntry(self::ENTRY_REVOKED, $userId, $deviceId, (string)$rows[0]['public_id']);
            $this->conn->commit();
        } catch (Throwable $error) {
            $this->conn->rollback();
            throw $error;
        }

        return ['device_id' => $deviceId, 'revoked' => true];
    }

    /** @return list<array<string, mixed>> the account's devices, newest first */
    public function devicesFor(int $userId): array
    {
        $rows = $this->select(
            'SELECT d.id, d.public_id, d.label, d.cipher_suite, d.created_at, d.last_seen_at, d.revoked_at,
                    (SELECT COUNT(*) FROM e2ee_key_packages k
                      WHERE k.device_id = d.id AND k.consumed_at IS NULL) AS available_key_packages
             FROM e2ee_devices d
             WHERE d.user_id = ?
             ORDER BY d.id DESC',
            'i',
            [$userId]
        );

        return array_map(static fn(array $row): array => [
            'device_id' => (int)$row['id'],
            'public_id' => base64_encode((string)$row['public_id']),
            'label' => $row['label'] === null ? null : (string)$row['label'],
            'cipher_suite' => (int)$row['cipher_suite'],
            'created_at' => (string)$row['created_at'],
            'last_seen_at' => $row['last_seen_at'] === null ? null : (string)$row['last_seen_at'],
            'revoked' => $row['revoked_at'] !== null,
            'available_key_packages' => (int)$row['available_key_packages'],
            'needs_more_key_packages' => (int)$row['available_key_packages'] < self::LOW_WATERMARK,
        ], $rows);
    }

    /**
     * Every device of every participant in one conversation, with its signature
     * key and whether it is revoked.
     *
     * Why this exists: revoking a device stops it being offered new key
     * packages, but a device already inside an MLS group keeps the keys it
     * holds. Nothing the server can do changes that — it has no keys — so a
     * client has to notice and publish a removal. To notice, it needs to know
     * which member keys belong to revoked devices, which is what this returns.
     *
     * Only a participant may ask, and the answer deliberately carries no labels
     * or timestamps: a signature key is already public to the group through the
     * ratchet tree, but a device's name is nobody else's business.
     *
     * @return list<array{device_id: int, user_id: int, signature_public_key: string, revoked: bool}>
     */
    public function participantDevices(int $chatId, int $viewerId, ProtectedChat $chats): array
    {
        if (!$chats->isParticipant($chatId, $viewerId)) {
            throw new ProtectedChatMismatch('You are not in this conversation', 'not_a_participant');
        }

        $rows = $this->select(
            'SELECT d.id, d.user_id, d.signature_public_key, d.revoked_at
             FROM e2ee_devices d
             JOIN chat_participants p ON p.user_id = d.user_id
             WHERE p.chat_id = ? AND p.left_at IS NULL
             ORDER BY d.user_id, d.id',
            'i',
            [$chatId]
        );

        return array_map(static fn(array $row): array => [
            'device_id' => (int)$row['id'],
            'user_id' => (int)$row['user_id'],
            // Stored as bytes, returned as base64 like every other key here.
            'signature_public_key' => base64_encode((string)$row['signature_public_key']),
            'revoked' => $row['revoked_at'] !== null,
        ], $rows);
    }

    // ---- key packages ------------------------------------------------------

    /** @param list<string> $keyPackagesBase64 */
    public function publishKeyPackages(int $userId, int $deviceId, array $keyPackagesBase64): array
    {
        $rows = $this->select(
            'SELECT id FROM e2ee_devices WHERE id = ? AND user_id = ? AND revoked_at IS NULL',
            'ii',
            [$deviceId, $userId]
        );
        if ($rows === []) {
            throw new ProtectedChatMismatch('Unknown device', 'unknown_device');
        }
        $packages = $this->decodeKeyPackages($keyPackagesBase64);

        $this->conn->begin_transaction();
        try {
            $stored = $this->insertKeyPackages($deviceId, $packages);
            $this->conn->commit();
        } catch (Throwable $error) {
            $this->conn->rollback();
            throw $error;
        }

        return ['device_id' => $deviceId, 'key_packages_stored' => $stored];
    }

    /**
     * Take one unconsumed key package for each of a user's live devices.
     *
     * Consumption is a conditional UPDATE inside the transaction: if two callers
     * race, only one can move the row from unconsumed to consumed, so a package
     * cannot be handed out twice.
     *
     * @return list<array<string, mixed>>
     */
    public function claimKeyPackages(
        int $claimingUserId,
        int $targetUserId,
        int $chatId,
        ProtectedChat $chats
    ): array {
        // Both sides must be in the conversation the claim is for. Without this
        // any authenticated account could spend another account's one-time key
        // packages until it had none left and could no longer be added to a
        // protected conversation at all.
        if (!$chats->isParticipant($chatId, $claimingUserId) ||
            !$chats->isParticipant($chatId, $targetUserId)) {
            throw new ProtectedChatMismatch(
                'Key packages can only be claimed for a conversation you are both in',
                'not_a_participant'
            );
        }

        $devices = $this->select(
            'SELECT id, public_id, signature_public_key
               FROM e2ee_devices WHERE user_id = ? AND revoked_at IS NULL ORDER BY id',
            'i',
            [$targetUserId]
        );
        if ($devices === []) {
            throw new ProtectedChatMismatch('That account has no enrolled device', 'no_enrolled_device');
        }

        $claimed = [];
        foreach ($devices as $device) {
            $deviceId = (int)$device['id'];
            $this->conn->begin_transaction();
            try {
                $candidate = $this->select(
                    'SELECT id, key_package FROM e2ee_key_packages
                      WHERE device_id = ? AND consumed_at IS NULL
                      ORDER BY id LIMIT 1 FOR UPDATE',
                    'i',
                    [$deviceId]
                );
                if ($candidate === []) {
                    $this->conn->rollback();
                    // A device with no packages left cannot be added right now.
                    // Saying so is better than silently forming a group without
                    // one of the recipient's devices, which would look like
                    // delivery working while one device can never decrypt.
                    $claimed[] = ['device_id' => $deviceId, 'key_package' => null, 'exhausted' => true];
                    continue;
                }

                $packageId = (int)$candidate[0]['id'];
                $consumed = $this->execute(
                    'UPDATE e2ee_key_packages
                        SET consumed_at = NOW(), consumed_by_user_id = ?
                      WHERE id = ? AND consumed_at IS NULL',
                    'ii',
                    [$claimingUserId, $packageId]
                );
                if ($consumed !== 1) {
                    $this->conn->rollback();
                    throw new ProtectedChatMismatch('Key package was already taken', 'key_package_race');
                }
                $this->conn->commit();

                $claimed[] = [
                    'device_id' => $deviceId,
                    'public_id' => base64_encode((string)$device['public_id']),
                    // The key this device claims to sign with. The admitting
                    // client compares it against the key inside the key package
                    // and refuses a mismatch: a review showed the two were only
                    // ever checked independently, which produced devices that
                    // joined under one key and could not be revoked by the
                    // other.
                    'signature_public_key' => base64_encode((string)$device['signature_public_key']),
                    'key_package' => base64_encode((string)$candidate[0]['key_package']),
                    'exhausted' => false,
                ];
            } catch (Throwable $error) {
                $this->conn->rollback();
                throw $error;
            }
        }

        return $claimed;
    }

    // ---- the directory chain ----------------------------------------------

    /** @return list<array<string, mixed>> log entries after a cursor */
    public function directoryAfter(int $afterSeq, int $limit): array
    {
        $limit = max(1, min(200, $limit));
        $rows = $this->select(
            'SELECT seq, entry_type, user_id, device_id, payload_digest, previous_digest, entry_digest, created_at
             FROM e2ee_directory_log WHERE seq > ? ORDER BY seq LIMIT ' . $limit,
            'i',
            [$afterSeq]
        );

        return array_map(static fn(array $row): array => [
            'seq' => (int)$row['seq'],
            'entry_type' => (int)$row['entry_type'],
            'user_id' => $row['user_id'] === null ? null : (int)$row['user_id'],
            'device_id' => $row['device_id'] === null ? null : (int)$row['device_id'],
            'payload_digest' => base64_encode((string)$row['payload_digest']),
            'previous_digest' => base64_encode((string)$row['previous_digest']),
            'entry_digest' => base64_encode((string)$row['entry_digest']),
            'created_at' => (string)$row['created_at'],
        ], $rows);
    }

    /**
     * Recompute the chain from the beginning and report the first break.
     * A client should do this itself; this exists so the server's own tests can
     * prove the chain it serves is well formed.
     */
    public function verifyDirectory(): array
    {
        $rows = $this->select('SELECT seq, entry_type, payload_digest, previous_digest, entry_digest
                               FROM e2ee_directory_log ORDER BY seq', '', []);
        $previous = str_repeat("\0", 32);
        foreach ($rows as $row) {
            if (!hash_equals($previous, (string)$row['previous_digest'])) {
                return ['valid' => false, 'broken_at' => (int)$row['seq'], 'reason' => 'previous_digest'];
            }
            $expected = self::entryDigest(
                (int)$row['seq'],
                $previous,
                (int)$row['entry_type'],
                (string)$row['payload_digest']
            );
            if (!hash_equals($expected, (string)$row['entry_digest'])) {
                return ['valid' => false, 'broken_at' => (int)$row['seq'], 'reason' => 'entry_digest'];
            }
            $previous = $expected;
        }

        return ['valid' => true, 'entries' => count($rows), 'head' => base64_encode($previous)];
    }

    public static function entryDigest(int $seq, string $previousDigest, int $entryType, string $payloadDigest): string
    {
        return hash('sha256', pack('J', $seq) . $previousDigest . pack('n', $entryType) . $payloadDigest, true);
    }

    private function appendDirectoryEntry(int $entryType, int $userId, int $deviceId, string $payload): void
    {
        $head = $this->select(
            'SELECT entry_digest FROM e2ee_directory_log ORDER BY seq DESC LIMIT 1 FOR UPDATE',
            '',
            []
        );
        $previous = $head === [] ? str_repeat("\0", 32) : (string)$head[0]['entry_digest'];
        $payloadDigest = hash('sha256', $payload, true);

        // The sequence must be known before the digest can be computed, and the
        // digest is part of the row, so reserve the number first.
        $next = $this->select('SELECT COALESCE(MAX(seq), 0) + 1 AS next FROM e2ee_directory_log', '', []);
        $seq = (int)$next[0]['next'];

        $this->execute(
            'INSERT INTO e2ee_directory_log
                (seq, entry_type, user_id, device_id, payload_digest, previous_digest, entry_digest)
             VALUES (?, ?, ?, ?, ?, ?, ?)',
            'iiiisss',
            [
                $seq,
                $entryType,
                $userId,
                $deviceId,
                $payloadDigest,
                $previous,
                self::entryDigest($seq, $previous, $entryType, $payloadDigest),
            ]
        );
    }

    // ---- helpers -----------------------------------------------------------

    /** @param list<string> $keyPackagesBase64 @return list<string> */
    private function decodeKeyPackages(array $keyPackagesBase64): array
    {
        if ($keyPackagesBase64 === [] || count($keyPackagesBase64) > self::MAX_KEY_PACKAGES_PER_PUBLISH) {
            throw new ProtectedChatMismatch('Invalid key package batch', 'invalid_key_packages');
        }
        $decoded = [];
        foreach ($keyPackagesBase64 as $package) {
            if (!is_string($package)) {
                throw new ProtectedChatMismatch('Invalid key package batch', 'invalid_key_packages');
            }
            $decoded[] = ProtectedChat::decodeBounded($package, self::MAX_KEY_PACKAGE_BYTES, 'key package');
        }
        return $decoded;
    }

    /** @param list<string> $packages */
    private function insertKeyPackages(int $deviceId, array $packages): int
    {
        $stored = 0;
        foreach ($packages as $package) {
            $ref = hash('sha256', $package, true);
            try {
                $this->execute(
                    'INSERT INTO e2ee_key_packages (device_id, key_package_ref, key_package) VALUES (?, ?, ?)',
                    'iss',
                    [$deviceId, $ref, $package]
                );
                $stored++;
            } catch (mysqli_sql_exception $error) {
                // Publishing the same package twice is a retry, not an error.
                if ((int)$error->getCode() !== 1062) {
                    throw $error;
                }
            }
        }
        return $stored;
    }

    /** @return list<array<string, mixed>> */
    private function select(string $sql, string $types, array $params): array
    {
        $stmt = $this->conn->prepare($sql);
        if ($stmt === false) {
            throw new RuntimeException('Unable to prepare device query');
        }
        try {
            if ($params !== []) {
                $stmt->bind_param($types, ...$params);
            }
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to run device query');
            }
            $result = $stmt->get_result();
            return $result === false ? [] : $result->fetch_all(MYSQLI_ASSOC);
        } finally {
            $stmt->close();
        }
    }

    /**
     * Returns the number of rows the statement changed. Read it from the
     * statement rather than the connection: closing the statement resets
     * mysqli::$affected_rows, so checking it afterwards reports nothing.
     */
    private function execute(string $sql, string $types, array $params): int
    {
        $stmt = $this->conn->prepare($sql);
        if ($stmt === false) {
            throw new RuntimeException('Unable to prepare device statement');
        }
        try {
            $stmt->bind_param($types, ...$params);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to run device statement');
            }
            return (int)$stmt->affected_rows;
        } finally {
            $stmt->close();
        }
    }
}
