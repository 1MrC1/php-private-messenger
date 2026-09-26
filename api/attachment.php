<?php
// Authenticated delivery for private chat attachments. Files beneath
// uploads/files remain inaccessible to the web server directly.

declare(strict_types=1);

require_once __DIR__ . '/../classes/SafeImage.php';
require_once __DIR__ . '/../classes/AttachmentName.php';
require_once __DIR__ . '/../classes/SafeArchive.php';
require_once __DIR__ . '/../classes/Auth.php';

const ATTACHMENT_SESSION_TIMEOUT = 1800;
const ATTACHMENT_ABSOLUTE_SESSION_TIMEOUT = 86400;
const ATTACHMENT_MAX_BYTES = 50 * 1024 * 1024;
const ATTACHMENT_REQUEST_RATE_WINDOW_SECONDS = 60;
const ATTACHMENT_USER_REQUEST_LIMIT = 240;
const ATTACHMENT_IP_REQUEST_LIMIT = 2400;
const ATTACHMENT_BYTE_RATE_WINDOW_SECONDS = 3600;
const ATTACHMENT_BYTE_RATE_UNIT = 1048576; // One MiB, rounded up per response.
const ATTACHMENT_USER_BYTE_RATE_UNITS = 1024; // One GiB per hour.
const ATTACHMENT_IP_BYTE_RATE_UNITS = 8192; // Eight GiB per hour per source.
const ATTACHMENT_INSPECTION_RATE_WINDOW_SECONDS = 3600;
const ATTACHMENT_INSPECTION_RATE_UNIT = 8388608; // Eight MiB of opened file work.
const ATTACHMENT_USER_INSPECTION_RATE_UNITS = 1024; // Eight GiB of work per hour.
const ATTACHMENT_IP_INSPECTION_RATE_UNITS = 8192; // 64 GiB per source per hour.
const ATTACHMENT_VALIDATION_CACHE_TTL_SECONDS = 300;

function attachmentRemoteRateIdentity(): string
{
    $remoteAddress = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    $packedAddress = $remoteAddress !== '' ? @inet_pton($remoteAddress) : false;

    return $packedAddress === false ? 'unknown' : bin2hex($packedAddress);
}

function attachmentReleaseRateUnits(string $scope, string $identity, int $units): void
{
    for ($released = 0; $released < $units; $released++) {
        Auth::releaseRateLimitAttempt($scope, $identity);
    }
}

/**
 * Reserve a conservative number of MiB tokens. Each token transition is
 * atomic in Auth's shared backend. If this request cannot reserve its complete
 * response, every token it did reserve is released before denial.
 */
function attachmentReserveRateUnits(
    string $scope,
    string $identity,
    int $units,
    int $limit,
    int $windowSeconds
): bool {
    $reserved = 0;
    while ($reserved < $units) {
        if (!Auth::reserveRateLimitAttempt($scope, $identity, $limit, $windowSeconds)) {
            attachmentReleaseRateUnits($scope, $identity, $reserved);
            return false;
        }
        $reserved++;
    }
    return true;
}

function attachmentReserveRequestBudget(int $userId, string $remoteIdentity): bool
{
    if (!Auth::reserveRateLimitAttempt(
        'attachment_read_ip_request',
        $remoteIdentity,
        ATTACHMENT_IP_REQUEST_LIMIT,
        ATTACHMENT_REQUEST_RATE_WINDOW_SECONDS
    )) {
        return false;
    }
    if (!Auth::reserveRateLimitAttempt(
        'attachment_read_user_request',
        (string)$userId,
        ATTACHMENT_USER_REQUEST_LIMIT,
        ATTACHMENT_REQUEST_RATE_WINDOW_SECONDS
    )) {
        Auth::releaseRateLimitAttempt('attachment_read_ip_request', $remoteIdentity);
        return false;
    }
    return true;
}

function attachmentReserveByteBudget(int $userId, string $remoteIdentity, int $responseBytes): bool
{
    $units = max(1, (int)ceil($responseBytes / ATTACHMENT_BYTE_RATE_UNIT));
    if (!attachmentReserveRateUnits(
        'attachment_read_ip_mib',
        $remoteIdentity,
        $units,
        ATTACHMENT_IP_BYTE_RATE_UNITS,
        ATTACHMENT_BYTE_RATE_WINDOW_SECONDS
    )) {
        return false;
    }
    if (!attachmentReserveRateUnits(
        'attachment_read_user_mib',
        (string)$userId,
        $units,
        ATTACHMENT_USER_BYTE_RATE_UNITS,
        ATTACHMENT_BYTE_RATE_WINDOW_SECONDS
    )) {
        attachmentReleaseRateUnits('attachment_read_ip_mib', $remoteIdentity, $units);
        return false;
    }
    return true;
}

/**
 * Bound hashing and parser work independently of response bytes. A positive
 * validation-cache hit needs one descriptor hash; a miss needs both pathname
 * and descriptor hashes and is therefore charged twice.
 */
function attachmentReserveInspectionBudget(
    int $userId,
    string $remoteIdentity,
    int $fileBytes,
    int $passes
): bool {
    if ($fileBytes < 1 || $fileBytes > ATTACHMENT_MAX_BYTES ||
        ($passes !== 1 && $passes !== 2)) {
        return false;
    }

    $units = max(1, (int)ceil($fileBytes / ATTACHMENT_INSPECTION_RATE_UNIT)) * $passes;
    if (!attachmentReserveRateUnits(
        'attachment_inspect_ip_units',
        $remoteIdentity,
        $units,
        ATTACHMENT_IP_INSPECTION_RATE_UNITS,
        ATTACHMENT_INSPECTION_RATE_WINDOW_SECONDS
    )) {
        return false;
    }
    if (!attachmentReserveRateUnits(
        'attachment_inspect_user_units',
        (string)$userId,
        $units,
        ATTACHMENT_USER_INSPECTION_RATE_UNITS,
        ATTACHMENT_INSPECTION_RATE_WINDOW_SECONDS
    )) {
        attachmentReleaseRateUnits('attachment_inspect_ip_units', $remoteIdentity, $units);
        return false;
    }
    return true;
}

function attachmentSecurityHeaders(): void
{
    header('Cache-Control: private, no-store, max-age=0, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: sandbox; default-src 'none'");
    header('X-Frame-Options: DENY');
    header('Vary: Cookie');
}

function attachmentEndWithStatus(int $status): void
{
    attachmentSecurityHeaders();
    http_response_code($status);
    exit;
}

function attachmentCloseDatabase($database): void
{
    if ($database === null) {
        return;
    }

    try {
        $database->close();
    } catch (Throwable $error) {
        error_log('Attachment database close error: ' . $error->getMessage());
    }
}

function attachmentDetectOoxmlMime(string $path, string $detectedMime): string
{
    return SafeArchive::detectOoxmlMime($path, $detectedMime);
}

/** Build a cache identity from the authorized path and opened file identity. */
function attachmentValidationCacheKey(string $storedPath, array $stat): ?string
{
    foreach (['dev', 'ino', 'mode', 'nlink', 'size', 'mtime', 'ctime'] as $field) {
        if (!isset($stat[$field]) || !is_int($stat[$field])) {
            return null;
        }
    }

    $identity = strlen($storedPath) . ':' . $storedPath . '|' .
        implode('|', array_map(
            static fn(string $field): string => $field . '=' . (string)$stat[$field],
            ['dev', 'ino', 'mode', 'nlink', 'size', 'mtime', 'ctime']
        ));
    return 'pm_attachment_validation_v1_' . hash('sha256', $identity);
}

/** Return only a strictly formed positive verdict. Authorization is never cached. */
function attachmentCachedValidation(string $cacheKey, array $allowedMimeTypes): ?array
{
    if (!function_exists('apcu_fetch')) {
        return null;
    }

    $cached = @apcu_fetch($cacheKey, $success);
    if (!$success || !is_array($cached) || count($cached) !== 2 ||
        !isset($cached['content_hash'], $cached['mime_type']) ||
        !is_string($cached['content_hash']) || !is_string($cached['mime_type']) ||
        preg_match('/\A[a-f0-9]{64}\z/D', $cached['content_hash']) !== 1 ||
        !isset($allowedMimeTypes[$cached['mime_type']])) {
        return null;
    }

    return $cached;
}

function attachmentCacheValidation(string $cacheKey, string $contentHash, string $mimeType): void
{
    if (function_exists('apcu_store')) {
        @apcu_store($cacheKey, [
            'content_hash' => $contentHash,
            'mime_type' => $mimeType
        ], ATTACHMENT_VALIDATION_CACHE_TTL_SECONDS);
    }
}

function attachmentForgetCachedValidation(string $cacheKey): void
{
    if (function_exists('apcu_delete')) {
        @apcu_delete($cacheKey);
    }
}

/** Hash exactly the opened file bytes and restore the stream to byte zero. */
function attachmentHashOpenStream($handle, array $expectedStat): ?string
{
    $expectedBytes = isset($expectedStat['size']) && is_int($expectedStat['size'])
        ? $expectedStat['size']
        : 0;
    if (!is_resource($handle) || $expectedBytes < 1 || rewind($handle) === false) {
        return null;
    }

    $context = hash_init('sha256');
    $readBytes = 0;
    while ($readBytes < $expectedBytes) {
        $chunk = fread($handle, min(65536, $expectedBytes - $readBytes));
        if (!is_string($chunk) || $chunk === '') {
            return null;
        }
        $readBytes += strlen($chunk);
        hash_update($context, $chunk);
    }
    $finalStat = fstat($handle);
    if ($readBytes !== $expectedBytes || !is_array($finalStat) || rewind($handle) === false) {
        return null;
    }
    foreach (['dev', 'ino', 'mode', 'nlink', 'size', 'mtime', 'ctime'] as $field) {
        if (!isset($expectedStat[$field], $finalStat[$field]) ||
            !is_int($expectedStat[$field]) || !is_int($finalStat[$field]) ||
            $expectedStat[$field] !== $finalStat[$field]) {
            return null;
        }
    }
    if ($finalStat['nlink'] !== 1) {
        return null;
    }

    return hash_final($context);
}

attachmentSecurityHeaders();

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') {
    header('Allow: GET, HEAD');
    attachmentEndWithStatus(405);
}

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_samesite', 'Lax');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax'
]);
session_cache_limiter('');
if (!Auth::startExistingSession()) {
    attachmentEndWithStatus(401);
}

$now = time();
$rawUserId = $_SESSION['user_id'] ?? null;
$rawLastActivity = $_SESSION['last_activity'] ?? null;
$rawLoginTime = $_SESSION['login_time'] ?? null;
$rawAuthVersion = $_SESSION['auth_version'] ?? null;
$rawTwoFactorVersion = $_SESSION['two_factor_version'] ?? null;
$hasIntegerUserId = is_int($rawUserId) ||
    (is_string($rawUserId) && preg_match('/\A[1-9][0-9]*\z/D', $rawUserId) === 1);
$hasIntegerActivity = is_int($rawLastActivity) ||
    (is_string($rawLastActivity) && preg_match('/\A[0-9]+\z/D', $rawLastActivity) === 1);
$hasIntegerLoginTime = is_int($rawLoginTime) ||
    (is_string($rawLoginTime) && preg_match('/\A[0-9]+\z/D', $rawLoginTime) === 1);

$userId = $hasIntegerUserId ? (int) $rawUserId : 0;
$lastActivity = $hasIntegerActivity ? (int) $rawLastActivity : 0;
$loginTime = $hasIntegerLoginTime ? (int) $rawLoginTime : 0;
$authVersion = is_string($rawAuthVersion) &&
    preg_match('/\A[a-f0-9]{64}\z/D', $rawAuthVersion) === 1
        ? $rawAuthVersion
        : '';
$twoFactorVersion = is_string($rawTwoFactorVersion) &&
    preg_match('/\A[a-f0-9]{64}\z/D', $rawTwoFactorVersion) === 1
        ? $rawTwoFactorVersion
        : '';
$isAuthenticated = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true &&
    $userId > 0 && $lastActivity > 0 && $lastActivity <= $now && $loginTime > 0 &&
    $loginTime <= $now && ($now - $lastActivity) <= ATTACHMENT_SESSION_TIMEOUT &&
    ($now - $loginTime) <= ATTACHMENT_ABSOLUTE_SESSION_TIMEOUT &&
    $authVersion !== '' && $twoFactorVersion !== '';

if (!$isAuthenticated) {
    session_write_close();
    attachmentEndWithStatus(401);
}

// Reject abusive authenticated request bursts before opening a database
// connection or parsing a stored file. The IP bucket is reserved first so
// forged/high-cardinality session identities cannot churn account keys.
$remoteRateIdentity = attachmentRemoteRateIdentity();
if (!attachmentReserveRequestBudget($userId, $remoteRateIdentity)) {
    session_write_close();
    header('Retry-After: ' . ATTACHMENT_REQUEST_RATE_WINDOW_SECONDS);
    attachmentEndWithStatus(429);
}

// Loading a private attachment is user activity. Persist the sliding timeout,
// then release the session lock before any database or file work.
$_SESSION['last_activity'] = $now;
session_write_close();

$rawMessageId = $_GET['id'] ?? null;
if (!is_string($rawMessageId) ||
    preg_match('/\A[1-9][0-9]{0,9}\z/D', $rawMessageId) !== 1 ||
    (float) $rawMessageId > 2147483647) {
    attachmentEndWithStatus(404);
}
$messageId = (int) $rawMessageId;

$database = null;
$fileHandle = null;

try {
    require_once __DIR__ . '/../config/database.php';

    $database = new Database();
    $connection = $database->connect();
    $statement = $connection->prepare("
        SELECT m.file_path, m.file_name, m.file_size, m.message_type,
               viewer.password_hash, viewer.two_factor_enabled, viewer.two_factor_secret
        FROM messages m
        INNER JOIN chat_participants cp
            ON cp.chat_id = m.chat_id
            AND cp.user_id = ?
            AND cp.left_at IS NULL
        INNER JOIN users viewer
            ON viewer.id = cp.user_id
        WHERE m.id = ?
            AND COALESCE(m.is_deleted, 0) = 0
            AND m.file_path IS NOT NULL
            AND m.file_path <> ''
        LIMIT 1
    ");
    $statement->bind_param('ii', $userId, $messageId);
    $statement->execute();
    $result = $statement->get_result();
    $attachment = $result->fetch_assoc();
    $result->free();
    $statement->close();

    // Authenticated callers receive the same response for an unknown message,
    // a deleted message, and a chat they are not permitted to access.
    if (!is_array($attachment)) {
        attachmentCloseDatabase($database);
        attachmentEndWithStatus(404);
    }

    $currentPasswordHash = $attachment['password_hash'] ?? null;
    $currentTwoFactorState = $attachment['two_factor_enabled'] ?? null;
    $currentTwoFactorSecret = is_string($attachment['two_factor_secret'] ?? null)
        ? $attachment['two_factor_secret']
        : null;
    unset(
        $attachment['password_hash'],
        $attachment['two_factor_enabled'],
        $attachment['two_factor_secret']
    );
    try {
        if (!in_array($currentTwoFactorState, [0, 1, '0', '1'], true)) {
            throw new UnexpectedValueException('Invalid 2FA state');
        }
        $currentTwoFactorVersion = Auth::twoFactorAuthenticationVersion(
            (int)$currentTwoFactorState,
            $currentTwoFactorSecret,
            $userId
        );
    } catch (Throwable $error) {
        $currentTwoFactorVersion = '';
    }
    if (!is_string($currentPasswordHash) ||
        !hash_equals($authVersion, Auth::passwordAuthenticationVersion($currentPasswordHash)) ||
        $currentTwoFactorVersion === '' ||
        !hash_equals($twoFactorVersion, $currentTwoFactorVersion)) {
        attachmentCloseDatabase($database);
        attachmentEndWithStatus(401);
    }
    attachmentCloseDatabase($database);
    $database = null;

    $storedPath = $attachment['file_path'];
    $messageType = $attachment['message_type'];
    if (!is_string($storedPath) || !is_string($messageType) ||
        preg_match('/[\x00-\x1F\x7F\\\\]/', $storedPath) === 1) {
        attachmentCloseDatabase($database);
        attachmentEndWithStatus(404);
    }

    $categoryByMessageType = [
        'image' => 'images',
        'file' => 'documents',
        'audio' => 'others',
        'video' => 'others'
    ];
    if (!isset($categoryByMessageType[$messageType])) {
        attachmentCloseDatabase($database);
        attachmentEndWithStatus(404);
    }

    $pathParts = explode('/', $storedPath);
    $expectedCategory = $categoryByMessageType[$messageType];
    if (count($pathParts) !== 4 || $pathParts[0] !== 'uploads' ||
        $pathParts[1] !== 'files' || $pathParts[2] !== $expectedCategory ||
        $pathParts[3] === '' || $pathParts[3] === '.' || $pathParts[3] === '..' ||
        strlen($pathParts[3]) > 255) {
        attachmentCloseDatabase($database);
        attachmentEndWithStatus(404);
    }

    $attachmentRoot = realpath(__DIR__ . '/../uploads/files');
    $categoryDirectory = $attachmentRoot !== false
        ? realpath($attachmentRoot . DIRECTORY_SEPARATOR . $expectedCategory)
        : false;
    $candidatePath = $categoryDirectory !== false
        ? $categoryDirectory . DIRECTORY_SEPARATOR . $pathParts[3]
        : '';
    $attachmentPath = $candidatePath !== '' ? realpath($candidatePath) : false;
    $rootPrefix = $attachmentRoot !== false ? $attachmentRoot . DIRECTORY_SEPARATOR : '';

    if ($attachmentRoot === false || $categoryDirectory === false || $attachmentPath === false ||
        is_link($candidatePath) ||
        strncmp($attachmentPath, $rootPrefix, strlen($rootPrefix)) !== 0 ||
        dirname($attachmentPath) !== $categoryDirectory || !is_file($attachmentPath) ||
        !is_readable($attachmentPath)) {
        attachmentCloseDatabase($database);
        attachmentEndWithStatus(404);
    }
    $validatedPathStat = @lstat($candidatePath);
    if (!is_array($validatedPathStat) || !isset(
        $validatedPathStat['mode'],
        $validatedPathStat['nlink'],
        $validatedPathStat['size'],
        $validatedPathStat['dev'],
        $validatedPathStat['ino'],
        $validatedPathStat['mtime'],
        $validatedPathStat['ctime']
    ) || (($validatedPathStat['mode'] & 0170000) !== 0100000) ||
        $validatedPathStat['nlink'] !== 1 ||
        $validatedPathStat['size'] < 1 || $validatedPathStat['size'] > ATTACHMENT_MAX_BYTES) {
        attachmentEndWithStatus(404);
    }

    // Open before any pathname parser and bind the eventual response to the
    // regular file identity already checked above.
    $fileHandle = @fopen($attachmentPath, 'rb');
    if ($fileHandle === false) {
        $fileHandle = null;
        attachmentEndWithStatus(404);
    }
    $streamStat = fstat($fileHandle);
    $pathStat = @lstat($candidatePath);
    if (!is_array($streamStat) || !is_array($pathStat) || !isset(
        $streamStat['mode'],
        $streamStat['nlink'],
        $streamStat['size'],
        $streamStat['dev'],
        $streamStat['ino'],
        $streamStat['mtime'],
        $streamStat['ctime'],
        $pathStat['mode'],
        $pathStat['nlink'],
        $pathStat['size'],
        $pathStat['dev'],
        $pathStat['ino'],
        $pathStat['mtime'],
        $pathStat['ctime']
    ) || (($streamStat['mode'] & 0170000) !== 0100000) ||
        (($pathStat['mode'] & 0170000) !== 0100000) ||
        $streamStat['nlink'] !== 1 || $pathStat['nlink'] !== 1 ||
        $streamStat['size'] < 1 || $streamStat['size'] > ATTACHMENT_MAX_BYTES) {
        fclose($fileHandle);
        $fileHandle = null;
        attachmentEndWithStatus(404);
    }
    foreach (['dev', 'ino', 'mode', 'nlink', 'size', 'mtime', 'ctime'] as $identityField) {
        if ($streamStat[$identityField] !== $pathStat[$identityField] ||
            $streamStat[$identityField] !== $validatedPathStat[$identityField]) {
            fclose($fileHandle);
            $fileHandle = null;
            attachmentEndWithStatus(404);
        }
    }
    $fileSize = $streamStat['size'];

    $rangeStart = 0;
    $rangeEnd = max(0, $fileSize - 1);
    $isPartialResponse = false;
    $rangeHeader = $method === 'GET' && isset($_SERVER['HTTP_RANGE']) && is_string($_SERVER['HTTP_RANGE'])
        ? trim($_SERVER['HTTP_RANGE'])
        : '';
    if ($rangeHeader !== '') {
        $rangeIsValid = preg_match('/\Abytes=([0-9]*)-([0-9]*)\z/D', $rangeHeader, $matches) === 1 &&
            ($matches[1] !== '' || $matches[2] !== '') &&
            strlen($matches[1]) <= 18 && strlen($matches[2]) <= 18;

        if ($rangeIsValid && $matches[1] === '') {
            $suffixLength = (int)$matches[2];
            $rangeIsValid = $suffixLength > 0;
            if ($rangeIsValid) {
                $rangeStart = max(0, $fileSize - $suffixLength);
                $rangeEnd = $fileSize - 1;
            }
        } elseif ($rangeIsValid) {
            $rangeStart = (int)$matches[1];
            $requestedEnd = $matches[2] === '' ? $fileSize - 1 : (int)$matches[2];
            $rangeEnd = min($requestedEnd, $fileSize - 1);
            $rangeIsValid = $rangeStart < $fileSize && $rangeEnd >= $rangeStart;
        }

        if (!$rangeIsValid) {
            fclose($fileHandle);
            $fileHandle = null;
            attachmentSecurityHeaders();
            header('Accept-Ranges: bytes');
            header('Content-Range: bytes */' . (string)$fileSize);
            header('Content-Length: 0');
            http_response_code(416);
            exit;
        }
        $isPartialResponse = true;
    }

    $allowedMimeTypes = [
        'image' => [
            'image/jpeg' => true,
            'image/png' => true,
            'image/gif' => true,
            'image/webp' => true
        ],
        'audio' => [
            'audio/aac' => true,
            'audio/flac' => true,
            'audio/mp4' => true,
            'audio/mpeg' => true,
            'audio/ogg' => true,
            'audio/wav' => true,
            'audio/webm' => true,
            'audio/x-flac' => true,
            'audio/x-wav' => true
        ],
        'video' => [
            'video/mp4' => true,
            'video/ogg' => true,
            'video/quicktime' => true,
            'video/webm' => true,
            'video/x-matroska' => true,
            'video/x-msvideo' => true,
            'video/avi' => true
        ],
        'file' => [
            'application/msword' => true,
            'application/pdf' => true,
            'application/rtf' => true,
            'application/vnd.ms-excel' => true,
            'application/vnd.ms-powerpoint' => true,
            'application/vnd.oasis.opendocument.presentation' => true,
            'application/vnd.oasis.opendocument.spreadsheet' => true,
            'application/vnd.oasis.opendocument.text' => true,
            'application/vnd.openxmlformats-officedocument.presentationml.presentation' => true,
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => true,
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => true,
            'application/x-7z-compressed' => true,
            'application/x-rar-compressed' => true,
            'application/zip' => true,
            'text/csv' => true,
            'text/plain' => true
        ]
    ];

    $cacheKey = attachmentValidationCacheKey($storedPath, $streamStat);
    if (!is_string($cacheKey)) {
        fclose($fileHandle);
        $fileHandle = null;
        attachmentEndWithStatus(404);
    }
    $cachedValidation = attachmentCachedValidation($cacheKey, $allowedMimeTypes[$messageType]);
    if ($method === 'HEAD' && $cachedValidation !== null) {
        // A cached positive verdict supplies exact representation headers. No
        // body is emitted, so the opened descriptor need not be hashed again.
        $validatedContentHash = $cachedValidation['content_hash'];
        $mimeType = $cachedValidation['mime_type'];
    } else {
        $inspectionPasses = $cachedValidation === null ? 2 : 1;
        if (!attachmentReserveInspectionBudget(
            $userId,
            $remoteRateIdentity,
            $fileSize,
            $inspectionPasses
        )) {
            fclose($fileHandle);
            $fileHandle = null;
            header('Retry-After: ' . ATTACHMENT_INSPECTION_RATE_WINDOW_SECONDS);
            attachmentEndWithStatus(429);
        }

        if ($cachedValidation !== null) {
            $validatedContentHash = $cachedValidation['content_hash'];
            $mimeType = $cachedValidation['mime_type'];
            $streamContentHash = attachmentHashOpenStream($fileHandle, $streamStat);
            if (!is_string($streamContentHash) ||
                !hash_equals($validatedContentHash, $streamContentHash)) {
                attachmentForgetCachedValidation($cacheKey);
                fclose($fileHandle);
                $fileHandle = null;
                attachmentEndWithStatus(404);
            }
        } else {
            $validatedContentHash = hash_file('sha256', $attachmentPath);
            if (!is_string($validatedContentHash) ||
                preg_match('/\A[a-f0-9]{64}\z/D', $validatedContentHash) !== 1) {
                fclose($fileHandle);
                $fileHandle = null;
                attachmentEndWithStatus(404);
            }

            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo === false) {
                throw new RuntimeException('Unable to initialize MIME detection');
            }
            $mimeType = finfo_file($finfo, $attachmentPath);
            finfo_close($finfo);
            if (is_string($mimeType) && $messageType === 'file') {
                $mimeType = attachmentDetectOoxmlMime($attachmentPath, $mimeType);
            }
            if (!is_string($mimeType) || !isset($allowedMimeTypes[$messageType][$mimeType]) ||
                ($messageType === 'image' &&
                    !SafeImage::isSafeStaticImage(
                        $attachmentPath,
                        $mimeType,
                        SafeImage::INLINE_MAX_DIMENSION,
                        SafeImage::INLINE_MAX_PIXELS
                    ))) {
                fclose($fileHandle);
                $fileHandle = null;
                attachmentEndWithStatus(404);
            }

            $streamContentHash = attachmentHashOpenStream($fileHandle, $streamStat);
            if (!is_string($streamContentHash) ||
                !hash_equals($validatedContentHash, $streamContentHash)) {
                fclose($fileHandle);
                $fileHandle = null;
                attachmentEndWithStatus(404);
            }
            attachmentCacheValidation($cacheKey, $streamContentHash, $mimeType);
        }
    }

    $originalName = is_string($attachment['file_name']) ? $attachment['file_name'] : '';
    try {
        [$asciiName, $utf8Name] = AttachmentName::dispositionNames($originalName, $mimeType);
    } catch (InvalidArgumentException $error) {
        fclose($fileHandle);
        $fileHandle = null;
        attachmentCloseDatabase($database);
        attachmentEndWithStatus(404);
    }

    $responseLength = $isPartialResponse ? $rangeEnd - $rangeStart + 1 : $fileSize;
    // HEAD and rejected ranges never send file bytes. Successful GETs reserve
    // their actual response length, so a small range is not charged as a full
    // 50 MiB download and repeated full downloads cannot monopolize PHP.
    if ($method === 'GET' &&
        !attachmentReserveByteBudget($userId, $remoteRateIdentity, $responseLength)) {
        fclose($fileHandle);
        $fileHandle = null;
        attachmentCloseDatabase($database);
        $database = null;
        header('Retry-After: ' . ATTACHMENT_BYTE_RATE_WINDOW_SECONDS);
        attachmentEndWithStatus(429);
    }

    // Close database resources before emitting any potentially large body.
    attachmentCloseDatabase($database);
    $database = null;

    // Authenticated image/audio/video representations may render in the chat
    // surface. Documents retain download semantics; every media byte still
    // passes through the participant, session, MIME, hash, and Range checks.
    $disposition = in_array($messageType, ['image', 'audio', 'video'], true)
        ? 'inline'
        : 'attachment';
    $contentDisposition = $disposition . '; filename="' . addcslashes($asciiName, '\\"') . '"';
    if ($utf8Name !== null) {
        $contentDisposition .= "; filename*=UTF-8''" . rawurlencode($utf8Name);
    }

    attachmentSecurityHeaders();
    header('Content-Type: ' . $mimeType);
    header('Accept-Ranges: bytes');
    header('Content-Length: ' . (string) $responseLength);
    header('Content-Disposition: ' . $contentDisposition);

    if ($isPartialResponse) {
        http_response_code(206);
        header('Content-Range: bytes ' . $rangeStart . '-' . $rangeEnd . '/' . $fileSize);
    }

    if ($method === 'HEAD') {
        fclose($fileHandle);
        exit;
    }

    if ($isPartialResponse) {
        if (fseek($fileHandle, $rangeStart) !== 0) {
            throw new RuntimeException('Unable to seek attachment stream');
        }
        $bytesRemaining = $responseLength;
        while ($bytesRemaining > 0 && !feof($fileHandle)) {
            $chunk = fread($fileHandle, min(8192, $bytesRemaining));
            if ($chunk === false || $chunk === '') {
                throw new RuntimeException('Unable to read attachment range');
            }
            echo $chunk;
            $bytesRemaining -= strlen($chunk);
        }
    } else {
        fpassthru($fileHandle);
    }
    fclose($fileHandle);
} catch (Throwable $error) {
    if (is_resource($fileHandle)) {
        fclose($fileHandle);
    }
    attachmentCloseDatabase($database);
    error_log('Attachment delivery error: ' . $error->getMessage());
    attachmentEndWithStatus(500);
}
