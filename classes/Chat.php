<?php
// classes/Chat.php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/SafeImage.php';
require_once __DIR__ . '/AttachmentName.php';
require_once __DIR__ . '/SafeArchive.php';
require_once __DIR__ . '/MessageIdempotency.php';
require_once __DIR__ . '/MalwareScanner.php';

class Chat
{
    private const USER_ATTACHMENT_QUOTA_BYTES = 1073741824; // 1 GiB active storage
    private const HOURLY_ATTACHMENT_BYTES = 262144000; // 250 MiB
    private const HOURLY_ATTACHMENT_COUNT = 30;
    private const MESSAGES_PER_MINUTE = 60;
    private const MAX_READ_MESSAGE_IDS = 100;
    private const MAX_CONTEXT_MESSAGES_PER_SIDE = 50;
    private const IDEMPOTENCY_SCHEMA_CACHE_TTL = 300;
    private const IDEMPOTENCY_SCHEMA_CACHE_VERSION = 'v1';
    private const UPLOAD_MIME_TYPES = [
        'image/jpeg' => ['message_type' => 'image', 'directory' => 'images', 'extension' => 'jpg'],
        'image/png' => ['message_type' => 'image', 'directory' => 'images', 'extension' => 'png'],
        'image/gif' => ['message_type' => 'image', 'directory' => 'images', 'extension' => 'gif'],
        'image/webp' => ['message_type' => 'image', 'directory' => 'images', 'extension' => 'webp'],
        'application/pdf' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'pdf'],
        'text/plain' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'txt'],
        'text/csv' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'csv'],
        'application/rtf' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'rtf'],
        'application/msword' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'docx'],
        'application/vnd.ms-excel' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'xls'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'xlsx'],
        'application/vnd.ms-powerpoint' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'ppt'],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'pptx'],
        'application/zip' => ['message_type' => 'file', 'directory' => 'documents', 'extension' => 'zip'],
        'audio/mpeg' => ['message_type' => 'audio', 'directory' => 'others', 'extension' => 'mp3'],
        'audio/wav' => ['message_type' => 'audio', 'directory' => 'others', 'extension' => 'wav'],
        'audio/x-wav' => ['message_type' => 'audio', 'directory' => 'others', 'extension' => 'wav'],
        'audio/ogg' => ['message_type' => 'audio', 'directory' => 'others', 'extension' => 'ogg'],
        'audio/mp4' => ['message_type' => 'audio', 'directory' => 'others', 'extension' => 'm4a'],
        'audio/webm' => ['message_type' => 'audio', 'directory' => 'others', 'extension' => 'webm'],
        'audio/flac' => ['message_type' => 'audio', 'directory' => 'others', 'extension' => 'flac'],
        'video/mp4' => ['message_type' => 'video', 'directory' => 'others', 'extension' => 'mp4'],
        'video/webm' => ['message_type' => 'video', 'directory' => 'others', 'extension' => 'webm'],
        'video/quicktime' => ['message_type' => 'video', 'directory' => 'others', 'extension' => 'mov'],
        'video/x-msvideo' => ['message_type' => 'video', 'directory' => 'others', 'extension' => 'avi'],
        'video/avi' => ['message_type' => 'video', 'directory' => 'others', 'extension' => 'avi']
    ];

    private $db;
    private $conn;
    private static $messageIdempotencySchemaReady = null;

    public function __construct()
    {
        $this->db = new Database();
        $this->conn = $this->db->connect();
    }

    private function isPositiveId($value)
    {
        if (is_int($value)) {
            return $value > 0;
        }
        if (!is_string($value) || preg_match('/^[1-9][0-9]*$/D', $value) !== 1) {
            return false;
        }

        return filter_var($value, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => PHP_INT_MAX]
        ]) !== false;
    }

    private function textLength($value)
    {
        return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
    }

    private function isValidText($value, $maximumLength, $allowEmpty = false)
    {
        if (!is_string($value) || preg_match('//u', $value) !== 1 ||
            strpos($value, "\0") !== false || $this->textLength($value) > $maximumLength) {
            return false;
        }

        return $allowEmpty || trim($value) !== '';
    }

    /** Build the stable public error contract used by both send endpoints. */
    private function sendFailureResponse($errorCode, $httpStatus, $message, $retryAfter = null)
    {
        $response = [
            'success' => false,
            'message' => $message,
            'error_code' => $errorCode,
            'http_status' => $httpStatus,
        ];
        if (is_int($retryAfter) && $retryAfter > 0) {
            $response['retry_after'] = $retryAfter;
        }

        return $response;
    }

    private function isReplyTargetInChat($messageId, $chatId)
    {
        $stmt = $this->conn->prepare(
            "SELECT id FROM messages WHERE id = ? AND chat_id = ? AND is_deleted = FALSE LIMIT 1"
        );
        $stmt->bind_param('ii', $messageId, $chatId);
        $stmt->execute();

        return $stmt->get_result()->num_rows === 1;
    }

    private function usersShareActiveChat($firstUserId, $secondUserId)
    {
        $stmt = $this->conn->prepare("
            SELECT 1
            FROM chat_participants first_participant
            JOIN chat_participants second_participant
              ON second_participant.chat_id = first_participant.chat_id
             AND second_participant.left_at IS NULL
            WHERE first_participant.user_id = ?
              AND first_participant.left_at IS NULL
              AND second_participant.user_id = ?
            LIMIT 1
        ");
        $stmt->bind_param('ii', $firstUserId, $secondUserId);
        $stmt->execute();

        return $stmt->get_result()->num_rows === 1;
    }

    /**
     * Lock the conversation row and answer the protection question inside the
     * caller's transaction.
     *
     * The earlier check outside the transaction was a check-then-act race, which
     * a second review reproduced: a plaintext send passed its check, protection
     * committed, and the plaintext then committed after it — leaving readable
     * text in a conversation the interface calls encrypted. Both sides now take
     * the same `chats` row lock, so whichever commits first is seen by the other.
     *
     * Must be called inside a transaction, or the lock is released immediately
     * and buys nothing.
     */
    private function protectionUnderLock($chatId)
    {
        if (!$this->isPositiveId($chatId)) {
            return null;
        }
        $chatId = (int)$chatId;

        try {
            $lock = $this->conn->prepare('SELECT id FROM chats WHERE id = ? FOR UPDATE');
            if ($lock === false) {
                return null;
            }
            try {
                $lock->bind_param('i', $chatId);
                if (!$lock->execute()) {
                    return null;
                }
                $result = $lock->get_result();
                if ($result === false || $result->num_rows === 0) {
                    // No such conversation: nothing to protect and nothing to send to.
                    return null;
                }
            } finally {
                $lock->close();
            }
        } catch (mysqli_sql_exception $error) {
            return null;
        }

        return $this->isProtectedChat($chatId);
    }

    /**
     * Whether a conversation is protected, or null if that cannot be answered.
     *
     * WHY THIS IS HERE AND NOT ONLY IN THE API. An independent review found the
     * hole this closes: `ProtectedChat` asserted the mode on its own paths, so
     * the ordinary send, upload and edit paths wrote plaintext into a
     * conversation the interface calls encrypted — total loss of the one
     * property the feature exists to provide. A check at the API switch would
     * have been the same mistake one layer up; the refusal belongs where the
     * write happens.
     *
     * Three answers, deliberately distinct:
     *   true  — protected, refuse the plaintext write
     *   false — not protected, or protected conversations are not deployed at
     *           all, in which case no chat can be protected
     *   null  — the question could not be answered, so the caller must refuse
     */
    private function isProtectedChat($chatId)
    {
        if (!$this->isPositiveId($chatId)) {
            return null;
        }
        $chatId = (int)$chatId;

        try {
            $stmt = $this->conn->prepare('SELECT 1 AS protected FROM chat_protection WHERE chat_id = ?');
            if ($stmt === false) {
                // 1146 is "table does not exist": protected conversations are
                // not deployed here, so nothing can be protected.
                return $this->conn->errno === 1146 ? false : null;
            }
            try {
                $stmt->bind_param('i', $chatId);
                if (!$stmt->execute()) {
                    return null;
                }
                $result = $stmt->get_result();
                if ($result === false) {
                    return null;
                }
                return $result->num_rows > 0;
            } finally {
                $stmt->close();
            }
        } catch (mysqli_sql_exception $error) {
            return $error->getCode() === 1146 ? false : null;
        }
    }

    private function removeStoredAttachment($relativePath)
    {
        if (!is_string($relativePath) ||
            preg_match('#^uploads/files/(images|documents|others)/([^/]+)$#D', $relativePath, $matches) !== 1 ||
            basename($matches[2]) !== $matches[2]) {
            return false;
        }

        $storageRoot = realpath(__DIR__ . '/../uploads/files');
        $requiredDirectory = $storageRoot !== false
            ? realpath($storageRoot . DIRECTORY_SEPARATOR . $matches[1])
            : false;
        $candidatePath = __DIR__ . '/../' . $relativePath;
        $candidateDirectory = realpath(dirname($candidatePath));
        if ($storageRoot === false || $requiredDirectory === false ||
            $candidateDirectory === false ||
            !hash_equals($requiredDirectory, $candidateDirectory)) {
            return false;
        }

        $pathStat = @lstat($candidatePath);
        if ($pathStat === false) {
            return !file_exists($candidatePath) && !is_link($candidatePath);
        }
        if (!isset($pathStat['mode']) || (($pathStat['mode'] & 0170000) !== 0100000) ||
            is_link($candidatePath)) {
            return false;
        }

        // Unlink the validated directory entry, never a realpath-resolved
        // target that could change during a local symlink race.
        return @unlink($candidatePath);
    }

    private function attachmentLimitError($senderId, $incomingBytes)
    {
        $stmt = $this->conn->prepare("
            SELECT
                COALESCE(SUM(CASE WHEN is_deleted = FALSE THEN file_size ELSE 0 END), 0) AS active_bytes,
                COALESCE(SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                                  THEN file_size ELSE 0 END), 0) AS hourly_bytes,
                COALESCE(SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                                  THEN 1 ELSE 0 END), 0) AS hourly_count
            FROM messages
            WHERE sender_id = ? AND file_path IS NOT NULL
        ");
        $stmt->bind_param('i', $senderId);
        if (!$stmt->execute()) {
            return $this->sendFailureResponse(
                'attachment_storage_unavailable',
                503,
                'Attachment storage is temporarily unavailable'
            );
        }
        $usage = $stmt->get_result()->fetch_assoc();
        $activeBytes = (int) ($usage['active_bytes'] ?? 0);
        $hourlyBytes = (int) ($usage['hourly_bytes'] ?? 0);
        $hourlyCount = (int) ($usage['hourly_count'] ?? 0);

        if ($activeBytes + $incomingBytes > self::USER_ATTACHMENT_QUOTA_BYTES) {
            return $this->sendFailureResponse(
                'attachment_quota_reached',
                413,
                'Your attachment storage quota has been reached'
            );
        }
        if ($hourlyCount >= self::HOURLY_ATTACHMENT_COUNT ||
            $hourlyBytes + $incomingBytes > self::HOURLY_ATTACHMENT_BYTES) {
            return $this->sendFailureResponse(
                'attachment_hourly_limit',
                429,
                'Your hourly attachment limit has been reached',
                3600
            );
        }
        return null;
    }

    private function messageRateLimitReached($senderId)
    {
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) AS recent_messages
            FROM messages
            WHERE sender_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)
        ");
        $stmt->bind_param('i', $senderId);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to read message rate state');
        }
        $row = $stmt->get_result()->fetch_assoc();
        return (int) ($row['recent_messages'] ?? 0) >= self::MESSAGES_PER_MINUTE;
    }

    /**
     * Serialize sends from the same account so the rate and attachment quota
     * checks cannot be bypassed with concurrent requests. MySQL advisory locks
     * are connection-scoped and are also released when this request's database
     * connection closes.
     */
    private function acquireSendLock($senderId)
    {
        $lockName = 'pm:send-user:' . (int) $senderId;

        try {
            $stmt = $this->conn->prepare('SELECT GET_LOCK(?, 1) AS acquired');
            if (!$stmt) {
                return null;
            }
            $stmt->bind_param('s', $lockName);
            if (!$stmt->execute()) {
                return null;
            }
            $row = $stmt->get_result()->fetch_assoc();

            return isset($row['acquired']) && (int) $row['acquired'] === 1
                ? $lockName
                : null;
        } catch (Throwable $_error) {
            return null;
        }
    }

    private function releaseSendLock($lockName)
    {
        try {
            $stmt = $this->conn->prepare('SELECT RELEASE_LOCK(?)');
            if ($stmt) {
                $stmt->bind_param('s', $lockName);
                $stmt->execute();
            }
        } catch (Throwable $_error) {
            // The non-persistent database connection also releases this lock.
        }
    }

    /**
     * Never expose storage paths to the browser. Attachments are addressed by
     * message ID and authorised again when their bytes are requested.
     */
    private function prepareMessageForClient($message)
    {
        if (!is_array($message)) {
            return $message;
        }

        if (!empty($message['file_path']) && !empty($message['id'])) {
            $message['file_path'] = 'api/attachment.php?id=' . (int) $message['id'];
        }
        if (!empty($message['file_name'])) {
            $message['file_name'] = $this->sanitizeDisplayFilename($message['file_name']);
        }
        if (array_key_exists('is_unread_for_user', $message)) {
            $message['is_unread_for_user'] = (int)$message['is_unread_for_user'] === 1;
        }
        if (array_key_exists('reply_is_deleted', $message)) {
            $message['reply_is_deleted'] = (int)$message['reply_is_deleted'] === 1;
            if ($message['reply_is_deleted']) {
                // Deleted-message copy is application chrome, not persisted
                // user content. The client renders it in its active locale.
                $message['reply_content'] = null;
            }
        }

        return $message;
    }

    /** Return unread state from recipient rows without mutating it. */
    private function getUnreadMetadata($chatId, $userId)
    {
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) AS unread_count, MIN(m.id) AS first_unread_message_id
            FROM messages m
            INNER JOIN message_status viewer_status
                ON viewer_status.message_id = m.id
               AND viewer_status.user_id = ?
               AND viewer_status.status IN ('sent', 'delivered')
            WHERE m.chat_id = ?
              AND m.sender_id != ?
              AND m.is_deleted = FALSE
        ");
        $stmt->bind_param('iii', $userId, $chatId, $userId);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to read unread message state');
        }
        $row = $stmt->get_result()->fetch_assoc();
        $firstUnreadMessageId = $row['first_unread_message_id'] ?? null;

        return [
            'unread_count' => (int)($row['unread_count'] ?? 0),
            'first_unread_message_id' => $firstUnreadMessageId === null
                ? null
                : (int)$firstUnreadMessageId,
        ];
    }

    private function findMessageByClientId($senderId, $clientMessageId)
    {
        $stmt = $this->conn->prepare("
            SELECT id, client_message_fingerprint
            FROM messages
            WHERE sender_id = ? AND client_message_id = ?
            LIMIT 1
        ");
        $stmt->bind_param('is', $senderId, $clientMessageId);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to read message idempotency state');
        }

        $row = $stmt->get_result()->fetch_assoc();
        return is_array($row) ? $row : null;
    }

    private function messageIdempotencyCacheKey()
    {
        $host = getenv('PM_DB_HOST');
        $database = getenv('PM_DB_NAME');
        if (!is_string($host) || $host === '' || !is_string($database) || $database === '') {
            return null;
        }

        return 'pm:chat:idempotency-schema-ready:' . self::IDEMPOTENCY_SCHEMA_CACHE_VERSION . ':' .
            hash('sha256', $host . "\0" . $database);
    }

    /**
     * Permit a migration-first rolling deploy without breaking legacy sends.
     * A false result is intentionally not cached. Exact positive verification
     * is shared briefly through APCu to avoid repeated INFORMATION_SCHEMA work.
     */
    private function messageIdempotencySchemaReady()
    {
        // This explicit rollout gate must stay off until every application node
        // understands client_message_id. Schema readiness alone is unsafe in a
        // mixed-version fleet because a retry routed to an old node can duplicate.
        if (getenv('PM_MESSAGE_IDEMPOTENCY_ENABLED') !== '1') {
            return false;
        }
        if (self::$messageIdempotencySchemaReady === true) {
            return true;
        }

        $cacheKey = $this->messageIdempotencyCacheKey();
        if ($cacheKey !== null && function_exists('apcu_fetch')) {
            try {
                $cacheHit = false;
                $cachedReady = apcu_fetch($cacheKey, $cacheHit);
                if ($cacheHit && $cachedReady === true) {
                    self::$messageIdempotencySchemaReady = true;
                    return true;
                }
            } catch (Throwable $_cacheError) {
                // Continue with exact metadata verification when APCu is unavailable.
            }
        }

        try {
            $columns = $this->conn->query("
                SELECT
                    column_name,
                    data_type,
                    character_maximum_length,
                    collation_name,
                    is_nullable
                FROM information_schema.columns
                WHERE table_schema = DATABASE()
                  AND table_name = 'messages'
                  AND column_name IN ('client_message_id', 'client_message_fingerprint')
            ");
            if ($columns === false) {
                return false;
            }
            $readyColumns = [];
            while ($column = $columns->fetch_assoc()) {
                $column = array_change_key_case($column, CASE_LOWER);
                $readyColumns[$column['column_name']] = $column;
            }
            if (($readyColumns['client_message_id']['data_type'] ?? null) !== 'char' ||
                (int)($readyColumns['client_message_id']['character_maximum_length'] ?? 0) !== 36 ||
                ($readyColumns['client_message_id']['collation_name'] ?? null) !== 'ascii_bin' ||
                ($readyColumns['client_message_id']['is_nullable'] ?? null) !== 'YES' ||
                ($readyColumns['client_message_fingerprint']['data_type'] ?? null) !== 'binary' ||
                (int)($readyColumns['client_message_fingerprint']['character_maximum_length'] ?? 0) !== 32 ||
                ($readyColumns['client_message_fingerprint']['is_nullable'] ?? null) !== 'YES') {
                return false;
            }

            $indexRows = $this->conn->query("
                SELECT non_unique, seq_in_index, column_name, sub_part
                FROM information_schema.statistics
                WHERE table_schema = DATABASE()
                  AND table_name = 'messages'
                  AND index_name = 'uq_messages_sender_client_message'
                ORDER BY seq_in_index
            ");
            if ($indexRows === false) {
                return false;
            }
            $indexedColumns = [];
            while ($indexRow = $indexRows->fetch_assoc()) {
                $indexRow = array_change_key_case($indexRow, CASE_LOWER);
                if ((int)($indexRow['non_unique'] ?? 1) !== 0) {
                    return false;
                }
                // A prefix index cannot enforce uniqueness over the complete
                // 36-byte UUID and must never enable retry behavior.
                if (($indexRow['sub_part'] ?? null) !== null) {
                    return false;
                }
                $indexedColumns[] = $indexRow['column_name'] ?? null;
            }
            if ($indexedColumns !== ['sender_id', 'client_message_id']) {
                return false;
            }

            self::$messageIdempotencySchemaReady = true;
            if ($cacheKey !== null && function_exists('apcu_store')) {
                try {
                    // Cache only a positive result reached after every exact
                    // column and full-width unique-index check above succeeds.
                    apcu_store($cacheKey, true, self::IDEMPOTENCY_SCHEMA_CACHE_TTL);
                } catch (Throwable $_cacheError) {
                    // Request-local readiness remains valid without shared cache.
                }
            }
            return true;
        } catch (Throwable $_error) {
            return false;
        }
    }

    public function supportsMessageIdempotency()
    {
        return $this->messageIdempotencySchemaReady();
    }

    private function idempotencyConflictResult()
    {
        return [
            'success' => false,
            'message' => 'client_message_id was already used for a different message',
            'error_code' => 'idempotency_conflict',
            'http_status' => 409,
        ];
    }

    private function replayMessageResult($existing, $fingerprint, $senderId)
    {
        $storedFingerprint = $existing['client_message_fingerprint'] ?? null;
        if (!is_string($storedFingerprint) || strlen($storedFingerprint) !== 32 ||
            !hash_equals($storedFingerprint, $fingerprint)) {
            return $this->idempotencyConflictResult();
        }

        $messageId = $this->isPositiveId($existing['id'] ?? null)
            ? (int)$existing['id']
            : 0;
        $message = $messageId > 0 ? $this->getMessageById($messageId) : null;
        if (!$message) {
            throw new RuntimeException('Unable to hydrate idempotent message');
        }
        $deliveryStatus = $this->getMessageDeliveryStatus($messageId, $senderId);
        $message['read_count'] = $deliveryStatus['read_count'];
        $message['delivered_count'] = $deliveryStatus['delivered_count'];
        $message['total_recipients'] = $deliveryStatus['total_recipients'];

        return [
            'success' => true,
            'message' => $message,
            'idempotent_replay' => true,
        ];
    }

    private function isDuplicateKeyError($error, $statement = null)
    {
        if ($error instanceof mysqli_sql_exception && (int)$error->getCode() === 1062) {
            return true;
        }
        if ($statement instanceof mysqli_stmt && (int)$statement->errno === 1062) {
            return true;
        }

        return (int)$this->conn->errno === 1062;
    }

    private function sanitizeDisplayFilename($filename)
    {
        $filename = basename(str_replace('\\', '/', (string) $filename));
        $filename = preg_replace('/[\x00-\x1F\x7F<>:&"\'\/\\\\|?*]+/', '_', $filename);
        $filename = trim((string) $filename, " .\t\n\r\0\x0B_");

        if ($filename === '') {
            return 'attachment';
        }

        if (strlen($filename) > 180) {
            $filename = function_exists('mb_strcut')
                ? mb_strcut($filename, 0, 180, 'UTF-8')
                : substr($filename, 0, 180);
        }

        return $filename;
    }

    private function detectOoxmlMimeType($path, $detectedMime)
    {
        return SafeArchive::detectOoxmlMime((string)$path, (string)$detectedMime);
    }

    public function getUserChats($user_id)
    {
        try {
            $stmt = $this->conn->prepare("
            SELECT 
                c.id as chat_id,
                c.type,
                c.title,
                c.avatar as chat_avatar,
                cp.role,
                latest_message.id AS last_message_id,
                latest_message.content AS last_message,
                latest_message.message_type AS last_message_type,
                latest_message.sender_id AS last_message_sender_id,
                latest_message.created_at AS last_message_time,
                COALESCE((
                    SELECT COUNT(*)
                    FROM message_status latest_status
                    INNER JOIN users latest_reader ON latest_reader.id = latest_status.user_id
                    WHERE latest_status.message_id = latest_message.id
                      AND latest_status.user_id != latest_message.sender_id
                      AND latest_status.status = 'read'
                      AND latest_reader.read_receipts = TRUE
                ), 0) AS last_message_read_count,
                (
                    SELECT COUNT(*)
                    FROM messages unread_message
                    INNER JOIN message_status unread_status
                        ON unread_status.message_id = unread_message.id
                       AND unread_status.user_id = ?
                       AND unread_status.status IN ('sent', 'delivered')
                    WHERE unread_message.chat_id = c.id
                      AND unread_message.sender_id != ?
                      AND unread_message.is_deleted = FALSE
                ) AS unread_count,
                EXISTS(
                    SELECT 1 FROM chat_protection protection WHERE protection.chat_id = c.id
                ) AS is_protected
            FROM chats c
            JOIN chat_participants cp ON c.id = cp.chat_id
            LEFT JOIN messages latest_message
                ON latest_message.id = (
                    SELECT candidate.id
                    FROM messages candidate
                    WHERE candidate.chat_id = c.id
                      AND candidate.is_deleted = FALSE
                    ORDER BY candidate.created_at DESC, candidate.id DESC
                    LIMIT 1
                )
            WHERE cp.user_id = ? AND cp.left_at IS NULL
            ORDER BY last_message_time DESC, c.id DESC
            LIMIT 500
        ");
            $stmt->bind_param("iii", $user_id, $user_id, $user_id);
            $stmt->execute();
            $result = $stmt->get_result();

            $chats = [];
            while ($row = $result->fetch_assoc()) {
                // For private chats, get the other participant's info with REAL online status
                if ($row['type'] === 'private') {
                    $other_user = $this->getOtherParticipantWithOnlineStatus($row['chat_id'], $user_id);
                    if ($other_user) {
                        $row['title'] = $other_user['first_name'] . ' ' . $other_user['last_name'];
                        $row['chat_avatar'] = $other_user['avatar'];
                        $row['other_user'] = $other_user;
                    }
                }
                $row['is_protected'] = (bool)($row['is_protected'] ?? false);
                $chats[] = $row;
            }

            return $chats;
        } catch (Exception $e) {
            error_log("Get user chats error: " . $e->getMessage());
            return [];
        }
    }

public function getChatMessages($chat_id, $user_id, $limit = 30, $beforeMessageId = null) {
    try {
        if (!$this->isPositiveId($chat_id) || !$this->isPositiveId($user_id)) {
            return ['success' => false, 'message' => 'Invalid chat'];
        }

        $chat_id = (int) $chat_id;
        $user_id = (int) $user_id;
        $limit = max(1, min(100, (int) $limit));
        if ($beforeMessageId !== null && !$this->isPositiveId($beforeMessageId)) {
            return ['success' => false, 'message' => 'Invalid message cursor'];
        }
        $beforeMessageId = $beforeMessageId !== null ? (int) $beforeMessageId : null;

        // Check if user is participant
        if (!$this->isParticipant($chat_id, $user_id)) {
            return ['success' => false, 'message' => 'Access denied'];
        }
        
        $whereClause = "WHERE m.chat_id = ? AND m.is_deleted = FALSE";
        // SELECT/JOIN placeholders occur before the chat cursor placeholders.
        $params = [$user_id, $user_id, $chat_id];
        $types = "iii";
        
        if ($beforeMessageId) {
            $whereClause .= " AND m.id < ?";
            $params[] = $beforeMessageId;
            $types .= "i";
        }
        
        $stmt = $this->conn->prepare("
            SELECT 
                m.id,
                m.content,
                m.message_type,
                m.file_path,
                m.file_name,
                m.file_size,
                m.reply_to_message_id,
                m.is_edited,
                m.created_at,
                m.sender_id,
                u.username,
                u.first_name,
                u.last_name,
                CASE WHEN u.show_profile_photo = TRUE THEN u.avatar ELSE NULL END AS avatar,
                rm.content as reply_content,
                rm.is_deleted as reply_is_deleted,
                ru.first_name as reply_sender_name,
                COALESCE(read_status.read_count, 0) as read_count,
                COALESCE(total_status.total_recipients, 0) as total_recipients,
                CASE
                    WHEN m.sender_id != ? AND viewer_status.status IN ('sent', 'delivered') THEN 1
                    ELSE 0
                END AS is_unread_for_user
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            LEFT JOIN messages rm ON m.reply_to_message_id = rm.id AND rm.chat_id = m.chat_id
            LEFT JOIN users ru ON rm.sender_id = ru.id
            LEFT JOIN message_status viewer_status
                ON viewer_status.message_id = m.id AND viewer_status.user_id = ?
            LEFT JOIN (
                SELECT ms.message_id, COUNT(*) as read_count
                FROM message_status ms
                JOIN users reader ON reader.id = ms.user_id
                WHERE ms.status = 'read' AND reader.read_receipts = TRUE
                GROUP BY ms.message_id
            ) read_status ON m.id = read_status.message_id
            LEFT JOIN (
                SELECT message_id, COUNT(*) as total_recipients 
                FROM message_status 
                GROUP BY message_id
            ) total_status ON m.id = total_status.message_id
            {$whereClause}
            ORDER BY m.created_at DESC, m.id DESC
            LIMIT ?
        ");
        
        $params[] = $limit;
        $types .= "i";
        
        $stmt->bind_param($types, ...$params);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $messages = [];
        while ($row = $result->fetch_assoc()) {
            $messages[] = $this->prepareMessageForClient($row);
        }
        
        // Reverse to get chronological order
        $messages = array_reverse($messages);
        
        $unread = $this->getUnreadMetadata($chat_id, $user_id);

        return [
            'success' => true,
            'messages' => $messages,
            'first_unread_message_id' => $unread['first_unread_message_id'],
            'unread_count' => $unread['unread_count'],
        ];
    } catch (Exception $e) {
        error_log("Get chat messages error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to load messages'];
    }
}
public function getNewMessages($chat_id, $user_id, $afterMessageId) {
    try {
        if (!$this->isPositiveId($chat_id) || !$this->isPositiveId($user_id) ||
            !$this->isPositiveId($afterMessageId)) {
            return ['success' => false, 'message' => 'Invalid message cursor'];
        }

        $chat_id = (int) $chat_id;
        $user_id = (int) $user_id;
        $afterMessageId = (int) $afterMessageId;

        // Check if user is participant
        if (!$this->isParticipant($chat_id, $user_id)) {
            return ['success' => false, 'message' => 'Access denied'];
        }
        
        $stmt = $this->conn->prepare("
            SELECT 
                m.id,
                m.content,
                m.message_type,
                m.file_path,
                m.file_name,
                m.file_size,
                m.reply_to_message_id,
                m.is_edited,
                m.created_at,
                u.id as sender_id,
                u.username,
                u.first_name,
                u.last_name,
                CASE WHEN u.show_profile_photo = TRUE THEN u.avatar ELSE NULL END AS avatar,
                rm.content as reply_content,
                rm.is_deleted as reply_is_deleted,
                ru.first_name as reply_sender_name,
                (SELECT COUNT(*) FROM message_status ms JOIN users reader ON reader.id = ms.user_id WHERE ms.message_id = m.id AND ms.status = 'read' AND ms.user_id != m.sender_id AND reader.read_receipts = TRUE) as read_count,
                (SELECT COUNT(*) FROM message_status ms WHERE ms.message_id = m.id AND ms.user_id != m.sender_id) as total_recipients,
                CASE
                    WHEN m.sender_id != ? AND viewer_status.status IN ('sent', 'delivered') THEN 1
                    ELSE 0
                END AS is_unread_for_user
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            LEFT JOIN messages rm ON m.reply_to_message_id = rm.id AND rm.chat_id = m.chat_id
            LEFT JOIN users ru ON rm.sender_id = ru.id
            LEFT JOIN message_status viewer_status
                ON viewer_status.message_id = m.id AND viewer_status.user_id = ?
            WHERE m.chat_id = ? AND m.is_deleted = FALSE AND m.id > ?
            ORDER BY m.created_at ASC, m.id ASC
            LIMIT 100
        ");
        
        $stmt->bind_param("iiii", $user_id, $user_id, $chat_id, $afterMessageId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $messages = [];
        while ($row = $result->fetch_assoc()) {
            $messages[] = $this->prepareMessageForClient($row);
        }
        
        $unread = $this->getUnreadMetadata($chat_id, $user_id);

        return [
            'success' => true,
            'messages' => $messages,
            'first_unread_message_id' => $unread['first_unread_message_id'],
            'unread_count' => $unread['unread_count'],
        ];
    } catch (Exception $e) {
        error_log("Get new messages error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to load new messages'];
    }
}

    public function sendMessage(
        $chat_id,
        $sender_id,
        $content,
        $message_type = 'text',
        $file_data = null,
        $reply_to = null,
        $client_message_id = null
    ) {
        $file_path = null;
        $messageCommitted = false;
        $commitAttempted = false;
        $transactionStarted = false;
        $sendLockName = null;
        try {
            if (!$this->isPositiveId($chat_id) || !$this->isPositiveId($sender_id) ||
                !$this->isValidText($content, 10000, $file_data !== null)) {
                return $this->sendFailureResponse(
                    'invalid_message',
                    400,
                    'The message is empty, invalid, or too long'
                );
            }

            $chat_id = (int)$chat_id;
            $sender_id = (int)$sender_id;

            // A protected conversation accepts sealed envelopes only. This is
            // the plaintext path — for text and for attachments, which arrive
            // here too — so it must refuse, and must refuse when it cannot tell.
            $protected = $this->isProtectedChat($chat_id);
            if ($protected === null) {
                return $this->sendFailureResponse(
                    'protection_state_unknown',
                    503,
                    'This conversation could not be checked for encryption; nothing was sent'
                );
            }
            if ($protected === true) {
                return $this->sendFailureResponse(
                    'chat_is_protected',
                    409,
                    'This conversation is encrypted, so plaintext cannot be sent to it'
                );
            }

            if (!is_string($message_type) || !in_array($message_type, ['text', 'file'], true)) {
                return $this->sendFailureResponse('invalid_message_type', 400, 'Invalid message type');
            }
            if ($reply_to !== null) {
                if (!$this->isPositiveId($reply_to)) {
                    return $this->sendFailureResponse('invalid_reply_target', 400, 'Invalid reply target');
                }
                $reply_to = (int)$reply_to;
            }

            $normalizedClientMessageId = null;
            if ($client_message_id !== null) {
                $normalizedClientMessageId = MessageIdempotency::canonicalClientMessageId($client_message_id);
                if ($normalizedClientMessageId === null) {
                    return $this->sendFailureResponse(
                        'invalid_client_message_id',
                        400,
                        'Message retry identifier is invalid'
                    );
                }
                if (!$this->messageIdempotencySchemaReady()) {
                    return $this->sendFailureResponse(
                        'idempotency_unavailable',
                        503,
                        'Message retry protection is temporarily unavailable'
                    );
                }
            }

            // Preserve normal chat authorization even for duplicate retries.
            if (!$this->isParticipant($chat_id, $sender_id)) {
                return $this->sendFailureResponse(
                    'chat_access_denied',
                    403,
                    'You no longer have access to this chat'
                );
            }

            $uploadInspection = null;
            $file_name = null;
            $file_size = null;
            if ($file_data && $message_type !== 'text') {
                // Validate and fingerprint the PHP upload before moving it. An
                // exact retry can therefore return the original row without
                // consuming quota or creating a second stored file.
                $uploadInspection = $this->inspectFileUpload($file_data);
                if (!$uploadInspection['success']) {
                    return $uploadInspection;
                }
                $message_type = $uploadInspection['message_type'];
                $file_name = $uploadInspection['file_name'];
                $file_size = $uploadInspection['file_size'];
            } elseif ($message_type !== 'text') {
                return $this->sendFailureResponse(
                    'attachment_required',
                    400,
                    'An attachment is required for this message type'
                );
            }

            $fingerprint = null;
            if ($normalizedClientMessageId !== null) {
                $attachmentFingerprint = $uploadInspection === null ? null : [
                    'sha256' => $uploadInspection['sha256'],
                    'size' => $uploadInspection['file_size'],
                    'mime_type' => $uploadInspection['mime_type'],
                    'file_name' => $uploadInspection['file_name'],
                ];
                $fingerprint = MessageIdempotency::fingerprint(
                    $chat_id,
                    $content,
                    $message_type,
                    $reply_to,
                    $attachmentFingerprint
                );
            }

            $sendLockName = $this->acquireSendLock($sender_id);
            if ($sendLockName === null) {
                return $this->sendFailureResponse(
                    'send_busy',
                    503,
                    'Another message is still being processed. Please retry shortly'
                );
            }

            // Resolve a committed retry before message/quota checks. A replay
            // is not a new message and must not be rejected because the first
            // attempt filled a rate or storage window.
            if ($normalizedClientMessageId !== null) {
                $existing = $this->findMessageByClientId($sender_id, $normalizedClientMessageId);
                if ($existing !== null) {
                    return $this->replayMessageResult($existing, $fingerprint, $sender_id);
                }
            }

            if ($this->messageRateLimitReached($sender_id)) {
                return $this->sendFailureResponse(
                    'message_rate_limited',
                    429,
                    'Message rate limit reached. Please slow down',
                    60
                );
            }
            if ($reply_to !== null && !$this->isReplyTargetInChat($reply_to, $chat_id)) {
                return $this->sendFailureResponse(
                    'reply_unavailable',
                    409,
                    'The message you are replying to is no longer available'
                );
            }

            if ($uploadInspection !== null) {
                $uploadResult = $this->storeInspectedFileUpload($uploadInspection, $sender_id);
                if (!$uploadResult['success']) {
                    return $uploadResult;
                }
                $file_path = $uploadResult['file_path'];
            }

            if (!$this->conn->begin_transaction()) {
                throw new RuntimeException('Unable to start message transaction');
            }
            $transactionStarted = true;

            // The check above happened before this transaction existed, so it can
            // only be trusted once it has been made again under a lock the
            // protecting path also takes.
            $protectedUnderLock = $this->protectionUnderLock($chat_id);
            if ($protectedUnderLock === null) {
                $this->conn->rollback();
                $transactionStarted = false;
                return $this->sendFailureResponse(
                    'protection_state_unknown',
                    503,
                    'This conversation could not be checked for encryption; nothing was sent'
                );
            }
            if ($protectedUnderLock === true) {
                $this->conn->rollback();
                $transactionStarted = false;
                return $this->sendFailureResponse(
                    'chat_is_protected',
                    409,
                    'This conversation is encrypted, so plaintext cannot be sent to it'
                );
            }

            // Freeze the active recipient set before creating the message. The
            // message, every group/private recipient status, and the unique
            // sender/client identifier are committed as one database unit.
            $recipientIds = $this->lockMessageRecipients($chat_id, $sender_id);

            if ($normalizedClientMessageId === null) {
                // Temporary compatibility for pre-idempotency clients and for
                // the safe migration-first deployment window.
                $stmt = $this->conn->prepare("
                    INSERT INTO messages (
                        chat_id, sender_id, content, message_type, file_path,
                        file_name, file_size, reply_to_message_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->bind_param(
                    'iissssii',
                    $chat_id,
                    $sender_id,
                    $content,
                    $message_type,
                    $file_path,
                    $file_name,
                    $file_size,
                    $reply_to
                );
            } else {
                $stmt = $this->conn->prepare("
                    INSERT INTO messages (
                        chat_id, sender_id, content, message_type, file_path,
                        file_name, file_size, reply_to_message_id,
                        client_message_id, client_message_fingerprint
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->bind_param(
                    'iissssiiss',
                    $chat_id,
                    $sender_id,
                    $content,
                    $message_type,
                    $file_path,
                    $file_name,
                    $file_size,
                    $reply_to,
                    $normalizedClientMessageId,
                    $fingerprint
                );
            }

            $insertError = null;
            try {
                $inserted = $stmt->execute();
            } catch (Throwable $error) {
                $inserted = false;
                $insertError = $error;
            }
            if (!$inserted) {
                $isIdempotencyRace = $normalizedClientMessageId !== null &&
                    $this->isDuplicateKeyError($insertError, $stmt);
                if (!$isIdempotencyRace) {
                    if ($insertError instanceof Throwable) {
                        throw $insertError;
                    }
                    throw new RuntimeException('Unable to insert message');
                }

                // A unique-key loser owns only its randomly named upload. Roll
                // back all recipient rows, delete that file, then return or
                // reject against the winner's committed fingerprint.
                $this->conn->rollback();
                $transactionStarted = false;
                if ($file_path !== null) {
                    if (!$this->removeStoredAttachment($file_path)) {
                        error_log('Unable to remove losing idempotent attachment');
                    }
                    $file_path = null;
                }
                $existing = $this->findMessageByClientId($sender_id, $normalizedClientMessageId);
                if ($existing === null) {
                    throw new RuntimeException('Idempotency winner is unavailable');
                }
                return $this->replayMessageResult($existing, $fingerprint, $sender_id);
            }
            $message_id = $this->conn->insert_id;

            $this->createMessageStatus($message_id, $recipientIds);
            // Hydrate before commit so an unexpected response failure can still
            // roll back rather than invite a client retry with an unclear state.
            $message = $this->getMessageById($message_id);
            if (!$message) {
                throw new RuntimeException('Unable to hydrate sent message');
            }
            $deliveryStatus = $this->getMessageDeliveryStatus($message_id, $sender_id);
            $message['read_count'] = $deliveryStatus['read_count'];
            $message['delivered_count'] = $deliveryStatus['delivered_count'];
            $message['total_recipients'] = $deliveryStatus['total_recipients'];

            // Once COMMIT is sent, a lost connection makes the outcome
            // unknowable. Never delete the private file in that state: the
            // database may have committed a row that still references it.
            $commitAttempted = true;
            if (!$this->conn->commit()) {
                throw new RuntimeException('Unable to commit message transaction');
            }
            $transactionStarted = false;
            $messageCommitted = true;

            return ['success' => true, 'message' => $message, 'idempotent_replay' => false];
        } catch (Throwable $e) {
            if ($transactionStarted) {
                try {
                    $this->conn->rollback();
                } catch (Throwable $_rollbackError) {
                    // The connection may already have ended the transaction.
                }
            }
            if (!$messageCommitted && !$commitAttempted && $file_path !== null) {
                if (!$this->removeStoredAttachment($file_path)) {
                    error_log('Unable to remove attachment after failed message transaction');
                }
            } elseif (!$messageCommitted && $commitAttempted && $file_path !== null) {
                error_log('Retained private attachment after ambiguous message commit outcome');
            }
            error_log('Send message error: ' . $e->getMessage());
            if ($commitAttempted && !$messageCommitted) {
                return $this->sendFailureResponse(
                    'send_outcome_unknown',
                    503,
                    'Message delivery could not be confirmed'
                );
            }
            return $this->sendFailureResponse(
                'messaging_unavailable',
                503,
                'Messaging is temporarily unavailable'
            );
        } finally {
            if ($sendLockName !== null) {
                $this->releaseSendLock($sendLockName);
            }
        }
    }

    public function createPrivateChat($user1_id, $user2_id)
    {
        try {
            if (!$this->isPositiveId($user1_id) || !$this->isPositiveId($user2_id) ||
                (int) $user1_id === (int) $user2_id) {
                return ['success' => false, 'message' => 'Invalid chat participant'];
            }

            $user1_id = (int) $user1_id;
            $user2_id = (int) $user2_id;
            $this->conn->begin_transaction();

            // Lock both account rows so simultaneous requests cannot create duplicate chats.
            $firstUserId = min($user1_id, $user2_id);
            $secondUserId = max($user1_id, $user2_id);
            $stmt = $this->conn->prepare(
                'SELECT id, who_can_message FROM users WHERE id IN (?, ?) ORDER BY id FOR UPDATE'
            );
            $stmt->bind_param('ii', $firstUserId, $secondUserId);
            if (!$stmt->execute()) {
                $this->conn->rollback();
                return ['success' => false, 'message' => 'User not found'];
            }
            $lockedUsers = $stmt->get_result();
            if ($lockedUsers->num_rows !== 2) {
                $this->conn->rollback();
                return ['success' => false, 'message' => 'User not found'];
            }
            $targetMessagingPreference = 'everyone';
            while ($lockedUser = $lockedUsers->fetch_assoc()) {
                if ((int) $lockedUser['id'] === $user2_id) {
                    $targetMessagingPreference = $lockedUser['who_can_message'] ?: 'everyone';
                }
            }
            if (!in_array($targetMessagingPreference, ['everyone', 'contacts', 'nobody'], true)) {
                $targetMessagingPreference = 'nobody';
            }

            // Check if chat already exists while participant rows are locked.
            $existing_chat = $this->getPrivateChatBetweenUsers($user1_id, $user2_id);
            if ($existing_chat) {
                $this->conn->commit();
                return ['success' => true, 'chat_id' => $existing_chat['chat_id']];
            }

            if ($targetMessagingPreference === 'nobody' ||
                ($targetMessagingPreference === 'contacts' &&
                 !$this->usersShareActiveChat($user1_id, $user2_id))) {
                $this->conn->rollback();
                return ['success' => false, 'message' => 'This user is not accepting new chats'];
            }

            // Create new chat
            $stmt = $this->conn->prepare("INSERT INTO chats (type, created_by) VALUES ('private', ?)");
            $stmt->bind_param("i", $user1_id);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to create chat');
            }
            $chat_id = $this->conn->insert_id;

            // Add participants
            $stmt = $this->conn->prepare("INSERT INTO chat_participants (chat_id, user_id, role) VALUES (?, ?, 'member'), (?, ?, 'member')");
            $stmt->bind_param("iiii", $chat_id, $user1_id, $chat_id, $user2_id);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to add chat participants');
            }

            $this->conn->commit();

            return ['success' => true, 'chat_id' => $chat_id];
        } catch (Throwable $e) {
            try {
                $this->conn->rollback();
            } catch (Throwable $_rollbackError) {
                // The connection may already have ended the transaction.
            }
            error_log("Create private chat error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to create chat'];
        }
    }

    public function searchUsers($query, $current_user_id)
    {
        try {
            if (!$this->isPositiveId($current_user_id) || !$this->isValidText($query, 50) ||
                $this->textLength(trim($query)) < 2) {
                return [];
            }

            $current_user_id = (int) $current_user_id;
            $escapedQuery = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], trim($query));
            $search_term = '%' . $escapedQuery . '%';
            $stmt = $this->conn->prepare("
                SELECT id, username, first_name, last_name,
                       CASE WHEN show_profile_photo = TRUE THEN avatar ELSE NULL END AS avatar,
                       CASE WHEN show_bio = TRUE THEN bio ELSE NULL END AS bio,
                       CASE
                           WHEN show_last_seen = TRUE
                                AND last_seen > DATE_SUB(NOW(), INTERVAL 2 MINUTE) THEN TRUE
                           ELSE FALSE
                       END AS is_online
                FROM users 
                WHERE (username LIKE ? ESCAPE '\\\\' OR first_name LIKE ? ESCAPE '\\\\'
                       OR last_name LIKE ? ESCAPE '\\\\')
                AND id != ? 
                LIMIT 20
            ");
            $stmt->bind_param("sssi", $search_term, $search_term, $search_term, $current_user_id);
            $stmt->execute();
            $result = $stmt->get_result();

            $users = [];
            while ($row = $result->fetch_assoc()) {
                $users[] = $row;
            }

            return $users;
        } catch (Exception $e) {
            error_log("Search users error: " . $e->getMessage());
            return [];
        }
    }

    public function getUserProfile($targetUserId, $requestingUserId)
    {
        try {
            if (!$this->isPositiveId($targetUserId) || !$this->isPositiveId($requestingUserId)) {
                return null;
            }

            $targetUserId = (int) $targetUserId;
            $requestingUserId = (int) $requestingUserId;
            $stmt = $this->conn->prepare("
                SELECT id, username, email, first_name, last_name, avatar, bio, phone,
                       CASE
                           WHEN last_seen > DATE_SUB(NOW(), INTERVAL 2 MINUTE) THEN TRUE
                           ELSE FALSE
                       END AS is_online,
                       last_seen, show_last_seen, show_profile_photo,
                       show_email, show_bio, show_phone
                FROM users
                WHERE id = ?
                LIMIT 1
            ");
            $stmt->bind_param('i', $targetUserId);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();
            if (!$user) {
                return null;
            }

            $isSelf = $targetUserId === $requestingUserId;
            foreach (['show_last_seen', 'show_profile_photo', 'show_email', 'show_bio', 'show_phone'] as $field) {
                $user[$field] = (bool) $user[$field];
            }
            $user['is_online'] = (bool) $user['is_online'];

            if (!$isSelf) {
                if (!$user['show_email']) {
                    $user['email'] = null;
                }
                if (!$user['show_bio']) {
                    $user['bio'] = null;
                }
                if (!$user['show_phone']) {
                    $user['phone'] = null;
                }
                if (!$user['show_profile_photo']) {
                    $user['avatar'] = null;
                }
                if (!$user['show_last_seen']) {
                    $user['last_seen'] = null;
                    $user['is_online'] = false;
                }
            }

            return $user;
        } catch (Throwable $e) {
            error_log('Get user profile error: ' . $e->getMessage());
            return null;
        }
    }

    public function setTypingStatus($chat_id, $user_id, $is_typing)
    {
        try {
            if (!$this->isPositiveId($chat_id) || !$this->isPositiveId($user_id) ||
                !is_bool($is_typing) || !$this->isParticipant((int) $chat_id, (int) $user_id)) {
                return false;
            }

            $chat_id = (int) $chat_id;
            $user_id = (int) $user_id;
            if ($is_typing) {
                $stmt = $this->conn->prepare("
                    INSERT INTO typing_indicators (chat_id, user_id, is_typing) 
                    VALUES (?, ?, TRUE) 
                    ON DUPLICATE KEY UPDATE is_typing = TRUE, updated_at = NOW()
                ");
            } else {
                $stmt = $this->conn->prepare("
                    UPDATE typing_indicators 
                    SET is_typing = FALSE, updated_at = NOW() 
                    WHERE chat_id = ? AND user_id = ?
                ");
            }
            $stmt->bind_param("ii", $chat_id, $user_id);
            $stmt->execute();

            return true;
        } catch (Exception $e) {
            error_log("Set typing status error: " . $e->getMessage());
            return false;
        }
    }

    public function getTypingUsers($chat_id, $user_id)
    {
        try {
            if (!$this->isPositiveId($chat_id) || !$this->isPositiveId($user_id) ||
                !$this->isParticipant((int) $chat_id, (int) $user_id)) {
                return [];
            }

            $chat_id = (int) $chat_id;
            $stmt = $this->conn->prepare("
                SELECT u.id, u.first_name, u.last_name
                FROM typing_indicators ti
                JOIN users u ON ti.user_id = u.id
                WHERE ti.chat_id = ? AND ti.is_typing = TRUE 
                AND ti.updated_at > DATE_SUB(NOW(), INTERVAL 5 SECOND)
            ");
            $stmt->bind_param("i", $chat_id);
            $stmt->execute();
            $result = $stmt->get_result();

            $typing_users = [];
            while ($row = $result->fetch_assoc()) {
                $typing_users[] = $row;
            }

            return $typing_users;
        } catch (Exception $e) {
            error_log("Get typing users error: " . $e->getMessage());
            return [];
        }
    }

    public function searchMessages($chat_id, $user_id, $query)
    {
        try {
            if (!$this->isPositiveId($chat_id) || !$this->isPositiveId($user_id) ||
                !$this->isValidText($query, 100) || $this->textLength(trim($query)) < 2) {
                return [];
            }

            $chat_id = (int) $chat_id;
            $user_id = (int) $user_id;
            // Check if user is participant
            if (!$this->isParticipant($chat_id, $user_id)) {
                return [];
            }

            $escapedQuery = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], trim($query));
            $search_term = '%' . $escapedQuery . '%';
            $stmt = $this->conn->prepare("
                SELECT 
                    m.id,
                    m.content,
                    m.created_at,
                    u.id as sender_id,
                    u.first_name,
                    u.last_name
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.chat_id = ? AND m.is_deleted = FALSE 
                AND m.content LIKE ? ESCAPE '\\\\'
                ORDER BY m.created_at DESC
                LIMIT 50
            ");
            $stmt->bind_param("is", $chat_id, $search_term);
            $stmt->execute();
            $result = $stmt->get_result();

            $messages = [];
            while ($row = $result->fetch_assoc()) {
                $messages[] = $row;
            }

            return $messages;
        } catch (Exception $e) {
            error_log("Search messages error: " . $e->getMessage());
            return [];
        }
    }

    public function getChatStats($chat_id, $user_id)
    {
        try {
            if (!$this->isPositiveId($chat_id) || !$this->isPositiveId($user_id)) {
                return ['message_count' => 0, 'participants' => []];
            }
            $chat_id = (int) $chat_id;
            $user_id = (int) $user_id;

            // Check if user is participant
            if (!$this->isParticipant($chat_id, $user_id)) {
                return ['message_count' => 0, 'participants' => []];
            }

            // Get message count
            $stmt = $this->conn->prepare("
                SELECT COUNT(*) as message_count
                FROM messages 
                WHERE chat_id = ? AND is_deleted = FALSE
            ");
            $stmt->bind_param("i", $chat_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $messageCount = $result->fetch_assoc()['message_count'];

            // Get participants
            $stmt = $this->conn->prepare("
                SELECT 
                    u.id,
                    u.username,
                    u.first_name,
                    u.last_name,
                    CASE WHEN u.show_profile_photo = TRUE THEN u.avatar ELSE NULL END AS avatar,
                    CASE
                        WHEN u.show_last_seen = TRUE
                             AND u.last_seen > DATE_SUB(NOW(), INTERVAL 2 MINUTE) THEN TRUE
                        ELSE FALSE
                    END AS is_online,
                    CASE WHEN u.show_last_seen = TRUE THEN u.last_seen ELSE NULL END AS last_seen,
                    cp.role,
                    cp.joined_at
                FROM users u
                JOIN chat_participants cp ON u.id = cp.user_id
                WHERE cp.chat_id = ? AND cp.left_at IS NULL
                ORDER BY cp.joined_at ASC
            ");
            $stmt->bind_param("i", $chat_id);
            $stmt->execute();
            $result = $stmt->get_result();

            $participants = [];
            while ($row = $result->fetch_assoc()) {
                $participants[] = $row;
            }

            return [
                'message_count' => $messageCount,
                'participants' => $participants
            ];
        } catch (Exception $e) {
            error_log("Get chat stats error: " . $e->getMessage());
            return ['message_count' => 0, 'participants' => []];
        }
    }

    private function isParticipant($chat_id, $user_id)
    {
        $stmt = $this->conn->prepare("SELECT id FROM chat_participants WHERE chat_id = ? AND user_id = ? AND left_at IS NULL");
        $stmt->bind_param("ii", $chat_id, $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        return $result->num_rows > 0;
    }

  private function getOtherParticipantWithOnlineStatus($chat_id, $user_id)
{
    $stmt = $this->conn->prepare("
        SELECT 
            u.id, 
            u.username, 
            u.first_name, 
            u.last_name, 
            CASE WHEN u.show_profile_photo = TRUE THEN u.avatar ELSE NULL END AS avatar,
            CASE WHEN u.show_email = TRUE THEN u.email ELSE NULL END AS email,
            CASE WHEN u.show_bio = TRUE THEN u.bio ELSE NULL END AS bio,
            CASE WHEN u.show_phone = TRUE THEN u.phone ELSE NULL END AS phone,
            u.show_email,
            u.show_bio,
            u.show_phone,
            CASE WHEN u.show_last_seen = TRUE THEN u.last_seen ELSE NULL END AS last_seen,
            CASE 
                WHEN u.show_last_seen = TRUE
                     AND u.last_seen > DATE_SUB(NOW(), INTERVAL 2 MINUTE) THEN 1
                ELSE 0 
            END as is_online
        FROM users u
        JOIN chat_participants cp ON u.id = cp.user_id
        WHERE cp.chat_id = ? AND cp.user_id != ? AND cp.left_at IS NULL
    ");
    $stmt->bind_param("ii", $chat_id, $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    return $result->fetch_assoc();
}

    private function getPrivateChatBetweenUsers($user1_id, $user2_id)
    {
        $stmt = $this->conn->prepare("
            SELECT c.id as chat_id
            FROM chats c
            JOIN chat_participants cp ON cp.chat_id = c.id AND cp.left_at IS NULL
            WHERE c.type = 'private'
            GROUP BY c.id
            HAVING COUNT(*) = 2
               AND SUM(cp.user_id = ?) = 1
               AND SUM(cp.user_id = ?) = 1
            LIMIT 1
        ");
        $stmt->bind_param("ii", $user1_id, $user2_id);
        $stmt->execute();
        $result = $stmt->get_result();

        return $result->fetch_assoc();
    }

    private function lockMessageRecipients($chat_id, $sender_id)
    {
        $stmt = $this->conn->prepare("
            SELECT cp.user_id
            FROM chat_participants cp
            WHERE cp.chat_id = ? AND cp.left_at IS NULL
            ORDER BY cp.user_id
            FOR UPDATE
        ");
        $stmt->bind_param('i', $chat_id);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to lock message recipients');
        }

        $senderIsActive = false;
        $recipientIds = [];
        $result = $stmt->get_result();
        while ($participant = $result->fetch_assoc()) {
            $participantId = (int) $participant['user_id'];
            if ($participantId === (int) $sender_id) {
                $senderIsActive = true;
            } elseif ($participantId > 0) {
                $recipientIds[$participantId] = $participantId;
            }
        }

        if (!$senderIsActive) {
            throw new RuntimeException('Sender is no longer an active participant');
        }

        return array_values($recipientIds);
    }

    /** Explicitly acknowledge a bounded set of messages in one active chat. */
    public function markMessagesAsRead($chat_id, $user_id, $messageIds)
    {
        try {
            if (!$this->isPositiveId($chat_id) || !$this->isPositiveId($user_id) ||
                !is_array($messageIds) || count($messageIds) < 1 ||
                count($messageIds) > self::MAX_READ_MESSAGE_IDS) {
                return ['success' => false, 'message' => 'Invalid read receipt request'];
            }

            $chat_id = (int)$chat_id;
            $user_id = (int)$user_id;
            $normalizedMessageIds = [];
            foreach ($messageIds as $messageId) {
                if (!$this->isPositiveId($messageId)) {
                    return ['success' => false, 'message' => 'Invalid read receipt request'];
                }
                $normalizedMessageIds[(int)$messageId] = (int)$messageId;
            }
            $normalizedMessageIds = array_values($normalizedMessageIds);

            if (!$this->isParticipant($chat_id, $user_id)) {
                return ['success' => false, 'message' => 'Access denied'];
            }

            $messagePlaceholders = implode(', ', array_fill(0, count($normalizedMessageIds), '?'));
            $stmt = $this->conn->prepare("
                UPDATE message_status ms
                INNER JOIN messages m ON ms.message_id = m.id
                SET ms.status = 'read', ms.timestamp = NOW()
                WHERE m.chat_id = ?
                  AND m.is_deleted = FALSE
                  AND m.sender_id != ?
                  AND ms.user_id = ?
                  AND ms.status IN ('sent', 'delivered')
                  AND m.id IN ({$messagePlaceholders})
            ");
            $params = array_merge([$chat_id, $user_id, $user_id], $normalizedMessageIds);
            $types = str_repeat('i', count($params));
            $stmt->bind_param($types, ...$params);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to update message read status');
            }
            $markedCount = (int)$stmt->affected_rows;
            $unread = $this->getUnreadMetadata($chat_id, $user_id);

            return [
                'success' => true,
                'marked_count' => $markedCount,
                'first_unread_message_id' => $unread['first_unread_message_id'],
                'unread_count' => $unread['unread_count'],
            ];
        } catch (Throwable $e) {
            error_log('Mark messages as read error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to update read status'];
        }
    }

    /** Hydrate only the already-bounded IDs selected for a message context. */
    private function getContextMessagesByIds($chatId, $userId, $messageIds)
    {
        if (empty($messageIds)) {
            return [];
        }

        $messagePlaceholders = implode(', ', array_fill(0, count($messageIds), '?'));
        $stmt = $this->conn->prepare("
            SELECT
                m.id,
                m.content,
                m.message_type,
                m.file_path,
                m.file_name,
                m.file_size,
                m.reply_to_message_id,
                m.is_edited,
                m.created_at,
                m.sender_id,
                u.username,
                u.first_name,
                u.last_name,
                CASE WHEN u.show_profile_photo = TRUE THEN u.avatar ELSE NULL END AS avatar,
                rm.content AS reply_content,
                rm.is_deleted AS reply_is_deleted,
                ru.first_name AS reply_sender_name,
                (SELECT COUNT(*)
                 FROM message_status read_status
                 INNER JOIN users reader ON reader.id = read_status.user_id
                 WHERE read_status.message_id = m.id
                   AND read_status.status = 'read'
                   AND read_status.user_id != m.sender_id
                   AND reader.read_receipts = TRUE) AS read_count,
                (SELECT COUNT(*)
                 FROM message_status recipient_status
                 WHERE recipient_status.message_id = m.id
                   AND recipient_status.user_id != m.sender_id) AS total_recipients,
                CASE
                    WHEN m.sender_id != ? AND viewer_status.status IN ('sent', 'delivered') THEN 1
                    ELSE 0
                END AS is_unread_for_user
            FROM messages m
            INNER JOIN users u ON m.sender_id = u.id
            LEFT JOIN messages rm ON m.reply_to_message_id = rm.id AND rm.chat_id = m.chat_id
            LEFT JOIN users ru ON rm.sender_id = ru.id
            LEFT JOIN message_status viewer_status
                ON viewer_status.message_id = m.id AND viewer_status.user_id = ?
            WHERE m.chat_id = ?
              AND m.is_deleted = FALSE
              AND m.id IN ({$messagePlaceholders})
            ORDER BY m.created_at ASC, m.id ASC
        ");
        $params = array_merge([(int)$userId, (int)$userId, (int)$chatId], $messageIds);
        $types = str_repeat('i', count($params));
        $stmt->bind_param($types, ...$params);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to load message context');
        }

        $messages = [];
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $messages[] = $this->prepareMessageForClient($row);
        }
        return $messages;
    }

    /**
     * Return a small chronological window around one undeleted target.
     * Reply hydration remains one level deep; limits are enforced again here
     * so non-HTTP callers cannot turn this into an unbounded history query.
     */
    public function getMessageContext(
        $chat_id,
        $user_id,
        $message_id,
        $beforeLimit = 20,
        $afterLimit = 20
    ) {
        try {
            if (!$this->isPositiveId($chat_id) || !$this->isPositiveId($user_id) ||
                !$this->isPositiveId($message_id) || !is_int($beforeLimit) ||
                !is_int($afterLimit) || $beforeLimit < 1 || $afterLimit < 1 ||
                $beforeLimit > self::MAX_CONTEXT_MESSAGES_PER_SIDE ||
                $afterLimit > self::MAX_CONTEXT_MESSAGES_PER_SIDE) {
                return ['success' => false, 'message' => 'Invalid message context request'];
            }

            $chat_id = (int)$chat_id;
            $user_id = (int)$user_id;
            $message_id = (int)$message_id;
            if (!$this->isParticipant($chat_id, $user_id)) {
                return ['success' => false, 'message' => 'Access denied'];
            }

            $targetStatement = $this->conn->prepare("
                SELECT id, created_at
                FROM messages
                WHERE id = ? AND chat_id = ? AND is_deleted = FALSE
                LIMIT 1
            ");
            $targetStatement->bind_param('ii', $message_id, $chat_id);
            if (!$targetStatement->execute()) {
                throw new RuntimeException('Unable to load message context target');
            }
            $target = $targetStatement->get_result()->fetch_assoc();
            if (!is_array($target)) {
                return ['success' => false, 'message' => 'Message not found'];
            }
            $targetTimestamp = (string)$target['created_at'];

            $beforeFetchLimit = $beforeLimit + 1;
            $beforeStatement = $this->conn->prepare("
                SELECT id
                FROM messages
                WHERE chat_id = ?
                  AND is_deleted = FALSE
                  AND (created_at < ? OR (created_at = ? AND id < ?))
                ORDER BY created_at DESC, id DESC
                LIMIT ?
            ");
            $beforeStatement->bind_param(
                'issii',
                $chat_id,
                $targetTimestamp,
                $targetTimestamp,
                $message_id,
                $beforeFetchLimit
            );
            if (!$beforeStatement->execute()) {
                throw new RuntimeException('Unable to load earlier message context');
            }
            $beforeIds = [];
            $beforeResult = $beforeStatement->get_result();
            while ($row = $beforeResult->fetch_assoc()) {
                $beforeIds[] = (int)$row['id'];
            }
            $hasMoreBefore = count($beforeIds) > $beforeLimit;
            $beforeIds = array_reverse(array_slice($beforeIds, 0, $beforeLimit));

            $afterFetchLimit = $afterLimit + 1;
            $afterStatement = $this->conn->prepare("
                SELECT id
                FROM messages
                WHERE chat_id = ?
                  AND is_deleted = FALSE
                  AND (created_at > ? OR (created_at = ? AND id > ?))
                ORDER BY created_at ASC, id ASC
                LIMIT ?
            ");
            $afterStatement->bind_param(
                'issii',
                $chat_id,
                $targetTimestamp,
                $targetTimestamp,
                $message_id,
                $afterFetchLimit
            );
            if (!$afterStatement->execute()) {
                throw new RuntimeException('Unable to load later message context');
            }
            $afterIds = [];
            $afterResult = $afterStatement->get_result();
            while ($row = $afterResult->fetch_assoc()) {
                $afterIds[] = (int)$row['id'];
            }
            $hasMoreAfter = count($afterIds) > $afterLimit;
            $afterIds = array_slice($afterIds, 0, $afterLimit);

            $contextIds = array_merge($beforeIds, [$message_id], $afterIds);
            $messages = $this->getContextMessagesByIds($chat_id, $user_id, $contextIds);
            $targetIsPresent = false;
            foreach ($messages as $message) {
                if ((int)($message['id'] ?? 0) === $message_id) {
                    $targetIsPresent = true;
                    break;
                }
            }
            if (!$targetIsPresent) {
                return ['success' => false, 'message' => 'Message not found'];
            }
            $unread = $this->getUnreadMetadata($chat_id, $user_id);

            return [
                'success' => true,
                'messages' => $messages,
                'target_message_id' => $message_id,
                'has_more_before' => $hasMoreBefore,
                'has_more_after' => $hasMoreAfter,
                'first_unread_message_id' => $unread['first_unread_message_id'],
                'unread_count' => $unread['unread_count'],
            ];
        } catch (Throwable $e) {
            error_log('Get message context error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to load message context'];
        }
    }

    private function getMessageDeliveryStatus($message_id, $sender_id)
    {
        try {
            $stmt = $this->conn->prepare("
            SELECT 
                COUNT(*) as total_recipients,
                SUM(CASE WHEN ms.status = 'read' AND reader.read_receipts = TRUE THEN 1 ELSE 0 END) as read_count,
                SUM(CASE WHEN ms.status = 'delivered' THEN 1 ELSE 0 END) as delivered_count
            FROM message_status ms
            JOIN users reader ON reader.id = ms.user_id
            WHERE ms.message_id = ? AND ms.user_id != ?
        ");
            $stmt->bind_param("ii", $message_id, $sender_id);
            $stmt->execute();
            $result = $stmt->get_result();

            return $result->fetch_assoc();
        } catch (Exception $e) {
            error_log("Get message delivery status error: " . $e->getMessage());
            return ['total_recipients' => 0, 'read_count' => 0, 'delivered_count' => 0];
        }
    }

private function createMessageStatus($message_id, $recipientIds) {
    if (empty($recipientIds)) {
        return;
    }

    // Keep individual statements bounded while retaining all-or-nothing
    // behavior through sendMessage's surrounding transaction.
    foreach (array_chunk($recipientIds, 500) as $recipientChunk) {
        $rowPlaceholders = implode(', ', array_fill(0, count($recipientChunk), "(?, ?, 'delivered')"));
        $params = [];
        foreach ($recipientChunk as $recipientId) {
            $params[] = (int) $message_id;
            $params[] = (int) $recipientId;
        }

        $stmt = $this->conn->prepare("
            INSERT INTO message_status (message_id, user_id, status)
            VALUES {$rowPlaceholders}
        ");
        $types = str_repeat('ii', count($recipientChunk));
        $stmt->bind_param($types, ...$params);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to create message delivery status');
        }
    }
}

    private function getMessageById($message_id)
    {
        $stmt = $this->conn->prepare("
        SELECT 
            m.id,
            m.content,
            m.message_type,
            m.file_path,
            m.file_name,
            m.file_size,
            m.reply_to_message_id,
            m.is_edited,
            m.created_at,
            u.id as sender_id,
            u.username,
            u.first_name,
            u.last_name,
            CASE WHEN u.show_profile_photo = TRUE THEN u.avatar ELSE NULL END AS avatar,
            (SELECT COUNT(*) FROM message_status ms JOIN users reader ON reader.id = ms.user_id WHERE ms.message_id = m.id AND ms.status = 'read' AND ms.user_id != m.sender_id AND reader.read_receipts = TRUE) as read_count,
            (SELECT COUNT(*) FROM message_status ms WHERE ms.message_id = m.id AND ms.user_id != m.sender_id) as total_recipients
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.id = ?
    ");
        $stmt->bind_param("i", $message_id);
        $stmt->execute();
        $result = $stmt->get_result();

        $message = $result->fetch_assoc();
        return $message ? $this->prepareMessageForClient($message) : null;
    }

    public function deleteMessage($message_id, $user_id)
    {
        try {
            if (!$this->isPositiveId($message_id) || !$this->isPositiveId($user_id)) {
                return ['success' => false, 'message' => 'Message not found or access denied'];
            }

            $message_id = (int) $message_id;
            $user_id = (int) $user_id;
            $stmt = $this->conn->prepare("
                SELECT file_path
                FROM messages
                WHERE id = ? AND sender_id = ? AND is_deleted = FALSE
                LIMIT 1
            ");
            $stmt->bind_param('ii', $message_id, $user_id);
            $stmt->execute();
            $message = $stmt->get_result()->fetch_assoc();
            if (!$message) {
                return ['success' => false, 'message' => 'Message not found or access denied'];
            }

            $stmt = $this->conn->prepare("
                UPDATE messages
                SET is_deleted = TRUE, content = '', updated_at = NOW()
                WHERE id = ? AND sender_id = ? AND is_deleted = FALSE
            ");
            $stmt->bind_param("ii", $message_id, $user_id);

            if ($stmt->execute() && $stmt->affected_rows === 1) {
                if (!empty($message['file_path'])) {
                    $this->removeStoredAttachment($message['file_path']);
                }
                return ['success' => true, 'message' => 'Message deleted'];
            } else {
                return ['success' => false, 'message' => 'Message not found or access denied'];
            }
        } catch (Exception $e) {
            error_log("Delete message error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to delete message'];
        }
    }

    public function editMessage($message_id, $user_id, $new_content)
    {
        try {
            if (!$this->isPositiveId($message_id) || !$this->isPositiveId($user_id) ||
                !$this->isValidText($new_content, 10000)) {
                return ['success' => false, 'message' => 'Invalid message'];
            }

            $message_id = (int) $message_id;
            $user_id = (int) $user_id;
            // Check if user owns the message
            $stmt = $this->conn->prepare("
                SELECT created_at, chat_id
                FROM messages
                WHERE id = ? AND sender_id = ? AND is_deleted = FALSE AND message_type = 'text'
            ");
            $stmt->bind_param("ii", $message_id, $user_id);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows === 0) {
                return ['success' => false, 'message' => 'Message not found or access denied'];
            }

            $message = $result->fetch_assoc();

            // Editing writes plaintext into `messages.content`, which in a
            // protected conversation would sit in the clear beside the sealed
            // envelope it was supposed to replace. There is no encrypted edit
            // protocol here, so the answer is refusal rather than a best effort.
            $protected = $this->isProtectedChat($message['chat_id'] ?? null);
            if ($protected === null) {
                return [
                    'success' => false,
                    'error_code' => 'protection_state_unknown',
                    'message' => 'This conversation could not be checked for encryption; nothing was changed',
                ];
            }
            if ($protected === true) {
                return [
                    'success' => false,
                    'error_code' => 'chat_is_protected',
                    'message' => 'Messages in an encrypted conversation cannot be edited',
                ];
            }

            // Check if message is not too old (48 hours limit)
            $messageTime = strtotime($message['created_at']);
            $currentTime = time();
            if (($currentTime - $messageTime) > 172800) { // 48 hours
                return ['success' => false, 'message' => 'Cannot edit messages older than 48 hours'];
            }

            // Same race as the send path: protection can commit between the
            // check above and this update, so the answer is taken again under the
            // conversation lock, inside a transaction.
            $this->conn->begin_transaction();
            try {
                $protectedUnderLock = $this->protectionUnderLock($message['chat_id'] ?? null);
                if ($protectedUnderLock !== false) {
                    $this->conn->rollback();
                    return [
                        'success' => false,
                        'error_code' => $protectedUnderLock === true
                            ? 'chat_is_protected'
                            : 'protection_state_unknown',
                        'message' => $protectedUnderLock === true
                            ? 'Messages in an encrypted conversation cannot be edited'
                            : 'This conversation could not be checked for encryption; nothing was changed',
                    ];
                }
            } catch (Throwable $lockError) {
                $this->conn->rollback();
                throw $lockError;
            }

            // Update message
            $stmt = $this->conn->prepare("
                UPDATE messages SET content = ?, is_edited = TRUE, updated_at = NOW()
                WHERE id = ? AND sender_id = ? AND is_deleted = FALSE AND message_type = 'text'
            ");
            $stmt->bind_param("sii", $new_content, $message_id, $user_id);

            // The edit and the protection recheck are one unit: committing the
            // edit without the lock it was checked under would put the race back.
            if ($stmt->execute() && $stmt->affected_rows === 1) {
                $this->conn->commit();
                return ['success' => true, 'message' => 'Message edited'];
            }
            $this->conn->rollback();
            return ['success' => false, 'message' => 'Failed to edit message'];
        } catch (Exception $e) {
            try {
                $this->conn->rollback();
            } catch (Throwable $ignored) {
                // Nothing to roll back; the original failure is what matters.
            }
            error_log("Edit message error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to edit message'];
        }
    }

    public function addReaction($message_id, $user_id, $emoji)
    {
        try {
            if (!$this->isPositiveId($message_id) || !$this->isPositiveId($user_id) ||
                !$this->isValidText($emoji, 32) || preg_match('/[\x00-\x1F\x7F<>"\'&]/u', $emoji)) {
                return ['success' => false, 'message' => 'Invalid reaction'];
            }

            $message_id = (int) $message_id;
            $user_id = (int) $user_id;
            // Check if message exists and user has access
            $stmt = $this->conn->prepare("
                SELECT m.chat_id 
                FROM messages m
                JOIN chat_participants cp ON m.chat_id = cp.chat_id
                WHERE m.id = ? AND m.is_deleted = FALSE
                  AND cp.user_id = ? AND cp.left_at IS NULL
            ");
            $stmt->bind_param("ii", $message_id, $user_id);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows === 0) {
                return ['success' => false, 'message' => 'Message not found or access denied'];
            }

            // Add or update reaction (simplified - you might want a separate reactions table)
            $stmt = $this->conn->prepare("
                INSERT INTO message_reactions (message_id, user_id, emoji, created_at) 
                VALUES (?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE emoji = ?, created_at = NOW()
            ");
            $stmt->bind_param("iiss", $message_id, $user_id, $emoji, $emoji);

            if ($stmt->execute()) {
                return ['success' => true, 'message' => 'Reaction added'];
            } else {
                return ['success' => false, 'message' => 'Failed to add reaction'];
            }
        } catch (Exception $e) {
            error_log("Add reaction error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to add reaction'];
        }
    }

    private function isSafeImageUpload($temporaryPath, $detectedMimeType)
    {
        return is_string($temporaryPath) && is_string($detectedMimeType) &&
            SafeImage::isSafeStaticImage(
                $temporaryPath,
                $detectedMimeType,
                SafeImage::INLINE_MAX_DIMENSION,
                SafeImage::INLINE_MAX_PIXELS
            );
    }

    /** Validate an upload and derive every value used by its logical fingerprint. */
    private function inspectFileUpload($file_data)
    {
        if (!is_array($file_data) ||
            !isset($file_data['error'], $file_data['tmp_name'], $file_data['name']) ||
            !is_string($file_data['tmp_name']) ||
            !is_string($file_data['name'])) {
            return $this->sendFailureResponse('invalid_attachment', 400, 'The attachment upload is invalid');
        }

        $uploadError = $file_data['error'];
        if (is_string($uploadError) && preg_match('/\A[0-8]\z/D', $uploadError) === 1) {
            $uploadError = (int)$uploadError;
        }
        if (!is_int($uploadError)) {
            return $this->sendFailureResponse('invalid_attachment', 400, 'The attachment upload is invalid');
        }
        if (in_array($uploadError, [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true)) {
            return $this->sendFailureResponse(
                'attachment_too_large',
                413,
                'Attachments must be no larger than 50 MB'
            );
        }
        if ($uploadError === UPLOAD_ERR_NO_FILE) {
            return $this->sendFailureResponse('attachment_required', 400, 'No attachment was uploaded');
        }
        if ($uploadError === UPLOAD_ERR_PARTIAL) {
            return $this->sendFailureResponse(
                'attachment_upload_failed',
                422,
                'The attachment upload was incomplete'
            );
        }
        if (in_array($uploadError, [UPLOAD_ERR_NO_TMP_DIR, UPLOAD_ERR_CANT_WRITE, UPLOAD_ERR_EXTENSION], true)) {
            return $this->sendFailureResponse(
                'attachment_storage_unavailable',
                503,
                'Attachment storage is temporarily unavailable'
            );
        }
        if ($uploadError !== UPLOAD_ERR_OK) {
            return $this->sendFailureResponse('invalid_attachment', 400, 'The attachment upload is invalid');
        }

        $temporaryPath = (string) $file_data['tmp_name'];
        if ($temporaryPath === '' || !is_uploaded_file($temporaryPath)) {
            return $this->sendFailureResponse(
                'attachment_changed',
                422,
                'The attachment upload changed during processing'
            );
        }

        $fileSize = filesize($temporaryPath);
        if ($fileSize === false) {
            return $this->sendFailureResponse(
                'attachment_inspection_unavailable',
                503,
                'The attachment could not be inspected'
            );
        }
        if ($fileSize < 1) {
            return $this->sendFailureResponse('invalid_attachment', 422, 'Empty attachments cannot be sent');
        }
        if ($fileSize > UPLOAD_MAX_SIZE) {
            return $this->sendFailureResponse(
                'attachment_too_large',
                413,
                'Attachments must be no larger than 50 MB'
            );
        }
        $temporaryStat = @lstat($temporaryPath);
        if (!is_array($temporaryStat) || !isset(
            $temporaryStat['mode'],
            $temporaryStat['size'],
            $temporaryStat['dev'],
            $temporaryStat['ino'],
            $temporaryStat['nlink']
        ) || (($temporaryStat['mode'] & 0170000) !== 0100000) ||
            (int)$temporaryStat['nlink'] !== 1 ||
            (int)$temporaryStat['size'] !== (int)$fileSize) {
            return $this->sendFailureResponse(
                'attachment_changed',
                422,
                'The attachment upload changed during processing'
            );
        }
        $preValidationHash = hash_file('sha256', $temporaryPath);
        if (!is_string($preValidationHash) ||
            preg_match('/\A[a-f0-9]{64}\z/D', $preValidationHash) !== 1) {
            return $this->sendFailureResponse(
                'attachment_changed',
                422,
                'The attachment upload changed during inspection'
            );
        }

        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = $finfo ? finfo_file($finfo, $temporaryPath) : false;
        if ($finfo) {
            finfo_close($finfo);
        }
        if (is_string($mimeType)) {
            $mimeType = $this->detectOoxmlMimeType($temporaryPath, $mimeType);
        }
        if (!is_string($mimeType) || $mimeType === '') {
            return $this->sendFailureResponse(
                'attachment_inspection_unavailable',
                503,
                'The attachment type could not be inspected'
            );
        }
        if (!isset(self::UPLOAD_MIME_TYPES[$mimeType])) {
            return $this->sendFailureResponse(
                'unsupported_attachment_type',
                415,
                'This attachment type is not supported'
            );
        }

        $uploadType = self::UPLOAD_MIME_TYPES[$mimeType];
        $messageType = $uploadType['message_type'];
        if ($messageType === 'image' && !$this->isSafeImageUpload($temporaryPath, $mimeType)) {
            return $this->sendFailureResponse(
                'unsafe_image',
                422,
                'The image dimensions or animation are not supported'
            );
        }
        $directoryName = $uploadType['directory'];
        $extension = $uploadType['extension'];
        $displayName = AttachmentName::canonicalDisplayName($file_data['name'], $extension);
        $validatedHash = hash_file('sha256', $temporaryPath);
        if (!is_string($validatedHash) ||
            preg_match('/\A[a-f0-9]{64}\z/D', $validatedHash) !== 1 ||
            !hash_equals($preValidationHash, $validatedHash)) {
            return $this->sendFailureResponse(
                'attachment_changed',
                422,
                'The attachment changed during validation'
            );
        }

        return [
            'success' => true,
            'temporary_path' => $temporaryPath,
            'temporary_dev' => (int)$temporaryStat['dev'],
            'temporary_ino' => (int)$temporaryStat['ino'],
            'file_name' => $displayName,
            'file_size' => (int)$fileSize,
            'message_type' => $messageType,
            'mime_type' => $mimeType,
            'directory_name' => $directoryName,
            'extension' => $extension,
            'sha256' => $validatedHash,
        ];
    }

    /** Move one previously inspected upload into private storage. */
    private function storeInspectedFileUpload($inspection, $senderId)
    {
        $temporaryPath = $inspection['temporary_path'];
        $fileSize = (int)$inspection['file_size'];
        $beforeMoveStat = @lstat($temporaryPath);
        if (!is_uploaded_file($temporaryPath) || !is_array($beforeMoveStat) ||
            !isset(
                $beforeMoveStat['mode'],
                $beforeMoveStat['size'],
                $beforeMoveStat['dev'],
                $beforeMoveStat['ino'],
                $beforeMoveStat['nlink']
            ) ||
            (($beforeMoveStat['mode'] & 0170000) !== 0100000) ||
            (int)$beforeMoveStat['nlink'] !== 1 ||
            (int)$beforeMoveStat['size'] !== $fileSize ||
            (int)$beforeMoveStat['dev'] !== (int)$inspection['temporary_dev'] ||
            (int)$beforeMoveStat['ino'] !== (int)$inspection['temporary_ino']) {
            return [
                'success' => false,
                'message' => 'The attachment upload changed during processing',
                'error_code' => 'attachment_changed',
                'http_status' => 422,
            ];
        }

        $limitFailure = $this->attachmentLimitError((int)$senderId, $fileSize);
        if ($limitFailure !== null) {
            return $limitFailure;
        }

        // Exact idempotent replays return before this storage method. Only a
        // genuinely new upload consumes scanner capacity.
        $scanResult = MalwareScanner::scanFile($temporaryPath, UPLOAD_MAX_SIZE);
        if (($scanResult['status'] ?? null) === MalwareScanner::INFECTED) {
            $signature = is_string($scanResult['signature'] ?? null) &&
                strlen($scanResult['signature']) <= 200
                ? $scanResult['signature']
                : 'unknown';
            error_log(
                'Attachment rejected by malware scanner: ' .
                json_encode($signature, JSON_UNESCAPED_SLASHES)
            );
            return $this->sendFailureResponse(
                'attachment_rejected',
                422,
                'This attachment was rejected by security scanning'
            );
        }
        if (($scanResult['status'] ?? null) !== MalwareScanner::CLEAN) {
            $reason = is_string($scanResult['reason'] ?? null) &&
                preg_match('/\A[a-z_]{1,64}\z/D', $scanResult['reason']) === 1
                ? $scanResult['reason']
                : 'unknown';
            if (in_array($reason, ['invalid_file', 'file_unavailable', 'file_changed'], true)) {
                error_log('Attachment changed before malware scanning completed: ' . $reason);
                return $this->sendFailureResponse(
                    'attachment_changed',
                    422,
                    'The attachment changed during security scanning'
                );
            }
            error_log('Attachment malware scanner unavailable: ' . $reason);
            return $this->sendFailureResponse(
                'scanner_unavailable',
                503,
                'Attachment security scanning is temporarily unavailable'
            );
        }
        $scanHash = $scanResult['sha256'] ?? null;
        if (!is_string($scanHash) || preg_match('/\A[a-f0-9]{64}\z/D', $scanHash) !== 1 ||
            !hash_equals($inspection['sha256'], $scanHash)) {
            error_log('Attachment changed during malware scanning');
            return $this->sendFailureResponse(
                'attachment_changed',
                422,
                'The attachment changed during security scanning'
            );
        }

        $directoryName = $inspection['directory_name'];
        $extension = $inspection['extension'];
        $uploadDirectory = __DIR__ . '/../uploads/files/' . $directoryName . '/';

        if (!is_dir($uploadDirectory) && !mkdir($uploadDirectory, 0750, true) && !is_dir($uploadDirectory)) {
            return $this->sendFailureResponse(
                'attachment_storage_unavailable',
                503,
                'Attachment storage is temporarily unavailable'
            );
        }

        try {
            $storedName = 'attachment_' . bin2hex(random_bytes(16)) . '.' . $extension;
        } catch (Throwable $error) {
            error_log('Attachment filename generation error: ' . $error->getMessage());
            return $this->sendFailureResponse(
                'attachment_storage_unavailable',
                503,
                'The attachment could not be saved'
            );
        }

        $absolutePath = $uploadDirectory . $storedName;
        $relativePath = 'uploads/files/' . $directoryName . '/' . $storedName;

        if (!move_uploaded_file($temporaryPath, $absolutePath)) {
            return $this->sendFailureResponse(
                'attachment_storage_unavailable',
                503,
                'The attachment could not be saved'
            );
        }
        if (!@chmod($absolutePath, 0640)) {
            if (!$this->removeStoredAttachment($relativePath)) {
                error_log('Unable to remove unsecured attachment');
            }
            return $this->sendFailureResponse(
                'attachment_storage_unavailable',
                503,
                'The attachment could not be secured'
            );
        }
        $storedStat = @lstat($absolutePath);
        $storedHash = hash_file('sha256', $absolutePath);
        if (!is_array($storedStat) ||
            !isset($storedStat['mode'], $storedStat['size'], $storedStat['nlink']) ||
            (($storedStat['mode'] & 0170000) !== 0100000) ||
            (int)$storedStat['nlink'] !== 1 ||
            (int)$storedStat['size'] !== $fileSize ||
            !is_string($storedHash) || !hash_equals($scanHash, $storedHash)) {
            if (!$this->removeStoredAttachment($relativePath)) {
                error_log('Unable to remove changed attachment');
            }
            return $this->sendFailureResponse(
                'attachment_changed',
                422,
                'The attachment changed while being saved'
            );
        }

        return [
            'success' => true,
            'file_path' => $relativePath,
        ];
    }

    public function __destruct()
    {
        if ($this->db) {
            $this->db->close();
        }
    }
}

?>
