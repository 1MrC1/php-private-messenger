<?php
// api/chat.php
require_once __DIR__ . '/../classes/Auth.php';
require_once __DIR__ . '/../classes/I18n.php';
require_once __DIR__ . '/../classes/Chat.php';
require_once __DIR__ . '/../classes/ProtectedChat.php';
require_once __DIR__ . '/../classes/DeviceDirectory.php';
require_once __DIR__ . '/../classes/EncryptedBlob.php';

Auth::configureSession();
Auth::setPrivateResponseHeaders();
I18n::applyResponseHeaders();
header('Content-Type: application/json; charset=utf-8');
header('Allow: POST, OPTIONS');

// An open conversation currently polls at roughly 72 requests per minute.
// Leave enough room for several tabs while preventing one account or source
// address from opening an unbounded number of Chat database connections.
const CHAT_API_RATE_WINDOW_SECONDS = 60;
const CHAT_API_USER_REQUEST_LIMIT = 360;
const CHAT_API_IP_REQUEST_LIMIT = 2400;
const CHAT_API_USER_SEARCH_LIMIT = 30;
const CHAT_API_IP_SEARCH_LIMIT = 240;
const CHAT_API_MAX_READ_MESSAGE_IDS = 100;
const CHAT_API_MAX_CONTEXT_MESSAGES_PER_SIDE = 50;

final class InvalidClientMessageIdException extends InvalidArgumentException
{
}

$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
if ($method === 'OPTIONS') {
    if (!Auth::isSameOriginRequest()) {
        http_response_code(403);
        echo I18n::encodeResponse(['success' => false, 'message' => 'Cross-origin request denied']);
        exit();
    }
    http_response_code(204);
    exit();
}

if ($method !== 'POST') {
    http_response_code(405);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Method not allowed']);
    exit();
}

if (!Auth::isSameOriginRequest()) {
    http_response_code(403);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Cross-origin request denied']);
    exit();
}

function requirePositiveApiId($value, $fieldName)
{
    if (is_int($value) && $value > 0) {
        return $value;
    }
    if (is_string($value) && preg_match('/^[1-9][0-9]*$/D', $value) === 1) {
        $validated = filter_var($value, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => PHP_INT_MAX]
        ]);
        if ($validated !== false) {
            return $validated;
        }
    }

    throw new InvalidArgumentException($fieldName . ' must be a positive integer');
}

function requireApiString($value, $fieldName, $minimumLength, $maximumLength)
{
    if (!is_string($value) || preg_match('//u', $value) !== 1 || strpos($value, "\0") !== false) {
        throw new InvalidArgumentException($fieldName . ' is invalid');
    }

    $length = function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
    if ($length < $minimumLength || $length > $maximumLength) {
        throw new InvalidArgumentException(
            $fieldName . ' must be between ' . $minimumLength . ' and ' . $maximumLength . ' characters'
        );
    }

    return $value;
}

/** Accept only a compact JSON list of unique canonical positive IDs. */
function requireBoundedApiIdList($value, $fieldName, $maximumCount): array
{
    if (!is_array($value) || !array_is_list($value) || count($value) < 1 ||
        count($value) > $maximumCount) {
        throw new InvalidArgumentException(
            $fieldName . ' must contain between 1 and ' . $maximumCount . ' identifiers'
        );
    }

    $identifiers = [];
    $seen = [];
    foreach ($value as $item) {
        $identifier = requirePositiveApiId($item, $fieldName);
        $key = (string)$identifier;
        if (isset($seen[$key])) {
            throw new InvalidArgumentException($fieldName . ' must not contain duplicates');
        }
        $seen[$key] = true;
        $identifiers[] = $identifier;
    }
    return $identifiers;
}

/** Legacy callers may omit the field; supplied identifiers must be UUID v4. */
function optionalClientMessageId(array $input): ?string
{
    if (!array_key_exists('client_message_id', $input)) {
        return null;
    }

    $clientMessageId = MessageIdempotency::canonicalClientMessageId($input['client_message_id']);
    if ($clientMessageId === null) {
        throw new InvalidClientMessageIdException('Invalid client message identifier');
    }
    return $clientMessageId;
}

/** Consume an internal status hint without exposing it in the JSON contract. */
function applyChatApiResponseStatus(array &$response): void
{
    $status = $response['http_status'] ?? null;
    $retryAfter = $response['retry_after'] ?? null;
    unset($response['http_status'], $response['retry_after']);
    if (is_int($status) && $status >= 400 && $status <= 599) {
        http_response_code($status);
        if ($status === 429 && is_int($retryAfter) && $retryAfter > 0) {
            header('Retry-After: ' . $retryAfter);
        }
    }
}

/**
 * Canonicalize only the web server's peer address. Forwarding headers are not
 * accepted here because a client-controlled value would create unlimited rate
 * limit identities when the origin is reached outside the trusted proxy path.
 */
function chatApiRemoteIdentity(): string
{
    $remoteAddress = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    $packedAddress = $remoteAddress !== '' ? @inet_pton($remoteAddress) : false;

    return $packedAddress === false ? 'unknown' : bin2hex($packedAddress);
}

/**
 * Read only a canonical positive integer from server-owned session state.
 * Numeric-looking values such as exponents, fractions, signs, or overflows
 * must not create attacker-selected account limiter identities.
 */
function chatApiSessionUserId(): ?int
{
    $value = $_SESSION['user_id'] ?? null;
    if (is_int($value)) {
        return $value > 0 ? $value : null;
    }
    if (!is_string($value) || preg_match('/\A[1-9][0-9]*\z/D', $value) !== 1) {
        return null;
    }

    $validated = filter_var($value, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1, 'max_range' => PHP_INT_MAX]
    ]);
    return $validated === false ? null : (int)$validated;
}

/**
 * Bound database-backed session validation itself. The fixed-cardinality IP
 * bucket is always reserved before the stable account bucket; a failed account
 * reservation rolls back only this request's IP slot.
 */
function reserveChatApiRequestBudget(int $userId): bool
{
    $remoteIdentity = chatApiRemoteIdentity();
    $userIdentity = (string)$userId;

    if (!Auth::reserveRateLimitAttempt(
        'chat_api_ip',
        $remoteIdentity,
        CHAT_API_IP_REQUEST_LIMIT,
        CHAT_API_RATE_WINDOW_SECONDS
    )) {
        return false;
    }

    if (!Auth::reserveRateLimitAttempt(
        'chat_api_user',
        $userIdentity,
        CHAT_API_USER_REQUEST_LIMIT,
        CHAT_API_RATE_WINDOW_SECONDS
    )) {
        Auth::releaseRateLimitAttempt('chat_api_ip', $remoteIdentity);
        return false;
    }

    return true;
}

/** Keep the more expensive database search actions on their tighter budget. */
function reserveChatApiSearchBudget(int $userId, string $action): bool
{
    if (!in_array($action, ['search_users', 'search_messages', 'get_message_context'], true)) {
        return true;
    }

    $remoteIdentity = chatApiRemoteIdentity();
    $userIdentity = (string)$userId;

    if (!Auth::reserveRateLimitAttempt(
        'chat_search_ip',
        $remoteIdentity,
        CHAT_API_IP_SEARCH_LIMIT,
        CHAT_API_RATE_WINDOW_SECONDS
    )) {
        return false;
    }

    if (!Auth::reserveRateLimitAttempt(
        'chat_search_user',
        $userIdentity,
        CHAT_API_USER_SEARCH_LIMIT,
        CHAT_API_RATE_WINDOW_SECONDS
    )) {
        Auth::releaseRateLimitAttempt('chat_search_ip', $remoteIdentity);
        return false;
    }

    return true;
}

function rejectChatApiRateLimit(): never
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    http_response_code(429);
    header('Retry-After: ' . CHAT_API_RATE_WINDOW_SECONDS);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Too many requests. Try again shortly.']);
    exit();
}

try {
    $contentLength = $_SERVER['CONTENT_LENGTH'] ?? null;
    if ($contentLength !== null &&
        (!is_string($contentLength) || preg_match('/^[0-9]+$/D', $contentLength) !== 1)) {
        throw new InvalidArgumentException('Invalid Content-Length');
    }
    $requestContentType = strtolower(trim((string)($_SERVER['CONTENT_TYPE'] ?? '')));
    $requestMediaType = trim(explode(';', $requestContentType, 2)[0]);
    $isMultipart = $requestMediaType === 'multipart/form-data';
    $isJson = $requestMediaType === 'application/json';
    if (!$isMultipart && !$isJson) {
        http_response_code(415);
        echo I18n::encodeResponse(['success' => false, 'message' => 'Unsupported Content-Type']);
        exit();
    }
    $maximumRequestBytes = $isMultipart ? UPLOAD_MAX_SIZE + 1048576 : 131072;
    if ($contentLength !== null && (int) $contentLength > $maximumRequestBytes) {
        throw new LengthException('Request body is too large');
    }

    // Handle file upload requests differently
    if ($isMultipart) {
        if (!isset($_POST['action']) || $_POST['action'] !== 'upload_file') {
            throw new InvalidArgumentException('Invalid upload request');
        }

        // Start session and validate
        if (!Auth::startExistingSession()) {
            http_response_code(401);
            echo I18n::encodeResponse(['success' => false, 'message' => 'Invalid or expired session']);
            exit();
        }
        $sessionUserId = chatApiSessionUserId();
        if ($sessionUserId === null) {
            session_write_close();
            http_response_code(401);
            echo I18n::encodeResponse(['success' => false, 'message' => 'Invalid or expired session']);
            exit();
        }
        if (!reserveChatApiRequestBudget($sessionUserId)) {
            rejectChatApiRateLimit();
        }
        $auth = new Auth();
        $sessionResult = $auth->validateSessionFromCookie();

        if (!$sessionResult['success']) {
            http_response_code(401);
            echo I18n::encodeResponse(['success' => false, 'message' => 'Invalid or expired session']);
            exit();
        }

        $currentUser = $sessionResult['user'];
        // Keep malformed and rejected uploads account-wide, not session-wide:
        // opening parallel browser sessions must not multiply parser work.
        if (!Auth::reserveRateLimitAttempt(
            'attachment_upload',
            (string)$currentUser['id'],
            40,
            3600
        )) {
            http_response_code(429);
            header('Retry-After: 3600');
            echo I18n::encodeResponse([
                'success' => false,
                'message' => 'Hourly upload attempt limit reached',
                'error_code' => 'attachment_attempt_limit',
            ]);
            exit();
        }
        $chat = new Chat();

        if (!isset($_FILES['file'])) {
            throw new InvalidArgumentException('No file uploaded');
        }

        if (!isset($_POST['chat_id'])) {
            throw new InvalidArgumentException('Chat ID is required');
        }

        // Handle file upload
        $file = $_FILES['file'];
        $chatId = requirePositiveApiId($_POST['chat_id'], 'Chat ID');
        $messageType = 'file';
        $captionSource = isset($_POST['caption']) ? $_POST['caption'] : ($file['name'] ?? 'Attachment');
        $caption = trim(requireApiString($captionSource, 'Caption', 0, 10000));
        $replyTo = isset($_POST['reply_to']) && $_POST['reply_to'] !== ''
            ? requirePositiveApiId($_POST['reply_to'], 'Reply target')
            : null;
        $clientMessageId = optionalClientMessageId($_POST);

        // Chat validates the upload bytes, chooses the safe storage extension,
        // and derives the final message type from an explicit MIME allow-list.

        $response = $chat->sendMessage(
            $chatId,
            $currentUser['id'],
            $caption,
            $messageType,
            $file,
            $replyTo,
            $clientMessageId
        );

        applyChatApiResponseStatus($response);
        echo I18n::encodeResponse($response, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        exit();
    }

    // Handle regular JSON requests
    // JSON chat actions are all protected. Reject unknown/expired sessions
    // before reading or decoding the request body.
    if (!Auth::startExistingSession()) {
        http_response_code(401);
        echo I18n::encodeResponse(['success' => false, 'message' => 'Invalid or expired session']);
        exit();
    }
    $sessionUserId = chatApiSessionUserId();
    if ($sessionUserId === null) {
        session_write_close();
        http_response_code(401);
        echo I18n::encodeResponse(['success' => false, 'message' => 'Invalid or expired session']);
        exit();
    }
    if (!reserveChatApiRequestBudget($sessionUserId)) {
        rejectChatApiRateLimit();
    }
    $auth = new Auth();
    $sessionResult = $auth->validateSessionFromCookie();

    if (!$sessionResult['success']) {
        http_response_code(401);
        echo I18n::encodeResponse(['success' => false, 'message' => 'Invalid or expired session']);
        exit();
    }

    $currentUser = $sessionResult['user'];
    $rawInput = file_get_contents('php://input', false, null, 0, 131073);
    if ($rawInput === false || strlen($rawInput) > 131072) {
        throw new LengthException('Request body is too large');
    }
    $input = json_decode($rawInput, true);

    if (!is_array($input) || json_last_error() !== JSON_ERROR_NONE ||
        !isset($input['action']) || !is_string($input['action']) ||
        preg_match('/^[a-z_]{1,40}$/D', $input['action']) !== 1) {
        throw new InvalidArgumentException('Invalid request');
    }

    if (!reserveChatApiSearchBudget((int)$currentUser['id'], $input['action'])) {
        rejectChatApiRateLimit();
    }
    $chat = new Chat();
    $response = ['success' => false];

    switch ($input['action']) {
        case 'get_chats':
            $chats = $chat->getUserChats($currentUser['id']);
            $response = [
                'success' => true,
                'chats' => $chats,
                // Remains false until the explicit fleet rollout gate and the
                // exact online schema/index checks are both ready.
                'message_idempotency_ready' => $chat->supportsMessageIdempotency(),
                // Off unless PM_PROTECTED_CHATS_ENABLED is exactly '1' and the
                // storage tables verify. Clients must fail closed on false.
                'protected_chats_ready' => (new ProtectedChat())->supportsProtectedChats()
            ];
            break;

        case 'get_messages':
            if (!isset($input['chat_id'])) {
                throw new InvalidArgumentException('Chat ID is required');
            }

            $chatId = requirePositiveApiId($input['chat_id'], 'Chat ID');
            $limit = isset($input['limit']) ? requirePositiveApiId($input['limit'], 'Limit') : 30;
            if ($limit > 100) {
                throw new InvalidArgumentException('Limit cannot exceed 100');
            }
            $beforeMessageId = isset($input['before_message_id'])
                ? requirePositiveApiId($input['before_message_id'], 'Before message ID')
                : null;

            $response = $chat->getChatMessages($chatId, $currentUser['id'], $limit, $beforeMessageId);
            break;

        case 'get_new_messages':
            if (!isset($input['chat_id'], $input['after_message_id'])) {
                throw new InvalidArgumentException('Chat ID and after message ID are required');
            }

            $chatId = requirePositiveApiId($input['chat_id'], 'Chat ID');
            $afterMessageId = requirePositiveApiId($input['after_message_id'], 'After message ID');
            $response = $chat->getNewMessages($chatId, $currentUser['id'], $afterMessageId);
            break;

        case 'mark_messages_read':
            if (!isset($input['chat_id'], $input['message_ids'])) {
                throw new InvalidArgumentException('Chat ID and message IDs are required');
            }

            $chatId = requirePositiveApiId($input['chat_id'], 'Chat ID');
            $messageIds = requireBoundedApiIdList(
                $input['message_ids'],
                'Message IDs',
                CHAT_API_MAX_READ_MESSAGE_IDS
            );
            $response = $chat->markMessagesAsRead($chatId, $currentUser['id'], $messageIds);
            break;

        case 'get_message_context':
            if (!isset($input['chat_id'], $input['message_id'])) {
                throw new InvalidArgumentException('Chat ID and message ID are required');
            }

            $chatId = requirePositiveApiId($input['chat_id'], 'Chat ID');
            $messageId = requirePositiveApiId($input['message_id'], 'Message ID');
            $beforeLimit = isset($input['before_limit'])
                ? requirePositiveApiId($input['before_limit'], 'Before limit')
                : 20;
            $afterLimit = isset($input['after_limit'])
                ? requirePositiveApiId($input['after_limit'], 'After limit')
                : 20;
            if ($beforeLimit > CHAT_API_MAX_CONTEXT_MESSAGES_PER_SIDE ||
                $afterLimit > CHAT_API_MAX_CONTEXT_MESSAGES_PER_SIDE) {
                throw new InvalidArgumentException('Message context limits cannot exceed 50');
            }
            $response = $chat->getMessageContext(
                $chatId,
                $currentUser['id'],
                $messageId,
                $beforeLimit,
                $afterLimit
            );
            break;

        case 'send_message':
            if (!isset($input['chat_id'], $input['content'])) {
                throw new InvalidArgumentException('Chat ID and content are required');
            }

            $chatId = requirePositiveApiId($input['chat_id'], 'Chat ID');
            $content = requireApiString($input['content'], 'Content', 1, 10000);
            $messageType = isset($input['message_type'])
                ? requireApiString($input['message_type'], 'Message type', 1, 20)
                : 'text';
            if ($messageType !== 'text') {
                throw new InvalidArgumentException('Attachments must use the upload endpoint');
            }
            $replyTo = isset($input['reply_to'])
                ? requirePositiveApiId($input['reply_to'], 'Reply target')
                : null;
            $clientMessageId = optionalClientMessageId($input);

            $response = $chat->sendMessage(
                $chatId,
                $currentUser['id'],
                $content,
                $messageType,
                null, // file_data - for text messages
                $replyTo,
                $clientMessageId
            );
            break;

        case 'create_private_chat':
            if (!isset($input['user_id'])) {
                throw new InvalidArgumentException('User ID is required');
            }

            $targetUserId = requirePositiveApiId($input['user_id'], 'User ID');
            $response = $chat->createPrivateChat($currentUser['id'], $targetUserId);
            break;

        case 'search_users':
            if (!isset($input['query'])) {
                throw new InvalidArgumentException('Search query is required');
            }

            $query = trim(requireApiString($input['query'], 'Search query', 2, 50));
            $users = $chat->searchUsers($query, $currentUser['id']);
            $response = [
                'success' => true,
                'users' => $users
            ];
            break;

        case 'set_typing':
            if (!isset($input['chat_id'], $input['is_typing'])) {
                throw new InvalidArgumentException('Chat ID and typing status are required');
            }

            if (!is_bool($input['is_typing'])) {
                throw new InvalidArgumentException('Typing status must be a boolean');
            }
            $chatId = requirePositiveApiId($input['chat_id'], 'Chat ID');
            $success = $chat->setTypingStatus($chatId, $currentUser['id'], $input['is_typing']);
            $response = [
                'success' => $success,
                'message' => $success ? 'Typing status updated' : 'Failed to update typing status'
            ];
            break;

        case 'get_typing_users':
            if (!isset($input['chat_id'])) {
                throw new InvalidArgumentException('Chat ID is required');
            }

            $chatId = requirePositiveApiId($input['chat_id'], 'Chat ID');
            $typingUsers = $chat->getTypingUsers($chatId, $currentUser['id']);
            $response = [
                'success' => true,
                'typing_users' => $typingUsers
            ];
            break;

        case 'search_messages':
            if (!isset($input['chat_id'], $input['query'])) {
                throw new InvalidArgumentException('Chat ID and search query are required');
            }

            $chatId = requirePositiveApiId($input['chat_id'], 'Chat ID');
            $query = trim(requireApiString($input['query'], 'Search query', 2, 100));
            $messages = $chat->searchMessages($chatId, $currentUser['id'], $query);
            $response = [
                'success' => true,
                'messages' => $messages
            ];
            break;

        case 'get_chat_stats':
            if (!isset($input['chat_id'])) {
                throw new InvalidArgumentException('Chat ID is required');
            }

            $chatId = requirePositiveApiId($input['chat_id'], 'Chat ID');
            $stats = $chat->getChatStats($chatId, $currentUser['id']);
            $response = [
                'success' => true,
                'message_count' => $stats['message_count'],
                'participants' => $stats['participants']
            ];
            break;

        case 'get_user_profile':
            if (!isset($input['user_id'])) {
                throw new InvalidArgumentException('User ID is required');
            }

            $targetUserId = requirePositiveApiId($input['user_id'], 'User ID');
            $user = $chat->getUserProfile($targetUserId, $currentUser['id']);
            if ($user !== null) {
                $response = [
                    'success' => true,
                    'user' => $user
                ];
            } else {
                http_response_code(404);
                $response = ['success' => false, 'message' => 'User not found'];
            }
            break;

        case 'delete_message':
            if (!isset($input['message_id'])) {
                throw new InvalidArgumentException('Message ID is required');
            }

            $messageId = requirePositiveApiId($input['message_id'], 'Message ID');
            $result = $chat->deleteMessage($messageId, $currentUser['id']);
            $response = $result;
            break;

        case 'edit_message':
            if (!isset($input['message_id'], $input['new_content'])) {
                throw new InvalidArgumentException('Message ID and new content are required');
            }

            $messageId = requirePositiveApiId($input['message_id'], 'Message ID');
            $newContent = requireApiString($input['new_content'], 'Message content', 1, 10000);
            $result = $chat->editMessage($messageId, $currentUser['id'], $newContent);
            $response = $result;
            break;

        case 'add_reaction':
            if (!isset($input['message_id'], $input['emoji'])) {
                throw new InvalidArgumentException('Message ID and emoji are required');
            }

            $messageId = requirePositiveApiId($input['message_id'], 'Message ID');
            $emoji = requireApiString($input['emoji'], 'Reaction', 1, 32);
            $result = $chat->addReaction($messageId, $currentUser['id'], $emoji);
            $response = $result;
            break;

        case 'list_devices':
        case 'claim_key_packages':
        case 'list_participant_devices':
        case 'get_directory_log':
            // Device identity and key transport. Everything exchanged here is
            // public by design in MLS; no private key reaches the server.
            // Enrollment and revocation are NOT here: they change account
            // security state, so they live in api/settings.php behind a fresh
            // password and second factor.
            if (!(new ProtectedChat())->supportsProtectedChats()) {
                $response = [
                    'success' => false,
                    'message' => 'The request could not be completed',
                    'error_code' => 'protected_chats_unavailable',
                    'http_status' => 503,
                ];
                break;
            }
            $directory = new DeviceDirectory();
            try {
                switch ($input['action']) {
                    case 'list_devices':
                        $response = [
                            'success' => true,
                            'devices' => $directory->devicesFor((int)$currentUser['id']),
                        ];
                        break;

                    case 'claim_key_packages':
                        $targetUserId = requirePositiveApiId($input['user_id'] ?? null, 'User ID');
                        $response = [
                            'success' => true,
                            'key_packages' => $directory->claimKeyPackages(
                                (int)$currentUser['id'],
                                $targetUserId
                            ),
                        ];
                        break;

                    case 'list_participant_devices':
                        // So a client can notice that a member of the group
                        // belongs to a revoked device and publish a removal.
                        // The server cannot do that itself: it holds no keys.
                        $deviceChatId = requirePositiveApiId($input['chat_id'] ?? null, 'Chat ID');
                        $response = [
                            'success' => true,
                            'devices' => $directory->participantDevices(
                                $deviceChatId,
                                (int)$currentUser['id'],
                                new ProtectedChat()
                            ),
                        ];
                        break;

                    default:
                        $response = [
                            'success' => true,
                            'entries' => $directory->directoryAfter(
                                (int)($input['after_seq'] ?? 0),
                                (int)($input['limit'] ?? 200)
                            ),
                        ];
                        break;
                }
            } catch (ProtectedChatMismatch $mismatch) {
                $response = [
                    'success' => false,
                    'message' => 'The request is invalid',
                    'error_code' => $mismatch->errorCode(),
                    'http_status' => 409,
                ];
            }
            break;

        case 'put_encrypted_blob':
        case 'get_encrypted_blob':
            // Encrypted attachments. The server stores and returns bytes it
            // cannot inspect: no MIME sniffing, no image or archive parsing,
            // and no malware scan, because none of them work on ciphertext.
            // That loss is surfaced in the interface, not hidden here.
            $blobChats = new ProtectedChat();
            if (!$blobChats->supportsProtectedChats()) {
                $response = [
                    'success' => false,
                    'message' => 'The request could not be completed',
                    'error_code' => 'protected_chats_unavailable',
                    'http_status' => 503,
                ];
                break;
            }
            try {
                $blobs = new EncryptedBlob();
                if ($input['action'] === 'put_encrypted_blob') {
                    $blobChatId = requirePositiveApiId($input['chat_id'] ?? null, 'Chat ID');
                    $ciphertext = ProtectedChat::decodeBounded(
                        (string)($input['ciphertext'] ?? ''),
                        EncryptedBlob::MAX_BLOB_BYTES,
                        'attachment'
                    );
                    $response = ['success' => true] + $blobs->store(
                        (int)$currentUser['id'],
                        $blobChatId,
                        $ciphertext,
                        $blobChats
                    );
                } else {
                    $blobId = requirePositiveApiId($input['blob_id'] ?? null, 'Attachment ID');
                    $response = ['success' => true] + $blobs->fetch(
                        (int)$currentUser['id'],
                        $blobId,
                        $blobChats
                    );
                }
            } catch (ProtectedChatMismatch $mismatch) {
                $response = [
                    'success' => false,
                    'message' => 'The request is invalid',
                    'error_code' => $mismatch->errorCode(),
                    'http_status' => 409,
                ];
            }
            break;

        case 'protect_chat':
        case 'send_protected_message':
        case 'get_protected_envelopes':
        case 'post_handshake':
        case 'get_handshakes':
            // Protected conversations are storage-only for now: the server
            // relays opaque ciphertext and public MLS handshake material. No
            // cryptography happens here and none of this is reachable until the
            // fleet-wide flag is set. See docs/security/e2ee-readiness.md before
            // describing any of it as end-to-end encrypted.
            $protected = new ProtectedChat();
            if (!$protected->supportsProtectedChats()) {
                $response = [
                    'success' => false,
                    'message' => 'The request could not be completed',
                    'error_code' => 'protected_chats_unavailable',
                    'http_status' => 503,
                ];
                break;
            }

            $protectedChatId = requirePositiveApiId($input['chat_id'] ?? null, 'Chat ID');
            $currentUserId = (int)$currentUser['id'];

            try {
                switch ($input['action']) {
                    case 'protect_chat':
                        $response = ['success' => true] + $protected->establishProtection(
                            $protectedChatId,
                            $currentUserId,
                            (string)($input['group_id'] ?? ''),
                            (int)($input['cipher_suite'] ?? 0)
                        );
                        break;

                    case 'send_protected_message':
                        $envelope = $input['envelope'] ?? null;
                        if (!is_array($envelope)) {
                            throw new InvalidArgumentException('Envelope is required');
                        }
                        $response = ['success' => true] + $protected->storeEnvelope(
                            $protectedChatId,
                            $currentUserId,
                            $envelope
                        );
                        break;

                    case 'get_protected_envelopes':
                        $response = [
                            'success' => true,
                            'envelopes' => $protected->envelopesAfter(
                                $protectedChatId,
                                $currentUserId,
                                (int)($input['after_message_id'] ?? 0),
                                (int)($input['limit'] ?? ProtectedChat::MAX_PAGE)
                            ),
                        ];
                        break;

                    case 'post_handshake':
                        $response = ['success' => true] + $protected->postHandshake(
                            $protectedChatId,
                            $currentUserId,
                            (int)($input['kind'] ?? 0),
                            (int)($input['epoch'] ?? -1),
                            (string)($input['payload'] ?? '')
                        );
                        break;

                    default:
                        $response = [
                            'success' => true,
                            'handshakes' => $protected->handshakesAfter(
                                $protectedChatId,
                                $currentUserId,
                                (int)($input['after_sequence'] ?? 0),
                                (int)($input['limit'] ?? ProtectedChat::MAX_PAGE)
                            ),
                        ];
                        break;
                }
            } catch (ProtectedChatMismatch $mismatch) {
                // A refusal, never a downgrade: the caller is told which way the
                // mismatch went and nothing is written.
                $response = [
                    'success' => false,
                    'message' => 'The request is invalid',
                    'error_code' => $mismatch->errorCode(),
                    'http_status' => 409,
                ];
            }
            break;

        default:
            throw new InvalidArgumentException('Invalid action');
    }

} catch (LengthException $e) {
    http_response_code(413);
    $response = [
        'success' => false,
        'message' => 'Request body is too large',
        'error_code' => 'request_too_large',
    ];
} catch (InvalidClientMessageIdException $e) {
    http_response_code(400);
    $response = [
        'success' => false,
        'message' => 'Message retry identifier is invalid',
        'error_code' => 'invalid_client_message_id',
    ];
} catch (InvalidArgumentException $e) {
    http_response_code(400);
    $response = [
        'success' => false,
        'message' => 'The request is invalid',
        'error_code' => 'invalid_request',
    ];
} catch (Throwable $e) {
    error_log('Chat API error: ' . $e->getMessage());
    http_response_code(500);
    $response = [
        'success' => false,
        'message' => 'The request could not be completed',
        'error_code' => 'request_failed',
    ];
}

applyChatApiResponseStatus($response);
echo I18n::encodeResponse($response, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
?>
