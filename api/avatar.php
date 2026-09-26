<?php
// Authenticated avatar delivery. The uploads directory is always denied;
// clients receive avatar bytes only through this endpoint.

declare(strict_types=1);

require_once __DIR__ . '/../classes/SafeImage.php';
require_once __DIR__ . '/../classes/Auth.php';

const AVATAR_SESSION_TIMEOUT = 1800;
const AVATAR_ABSOLUTE_SESSION_TIMEOUT = 86400;
const AVATAR_MAX_BYTES = 5 * 1024 * 1024;
const AVATAR_REQUEST_RATE_WINDOW_SECONDS = 60;
const AVATAR_USER_REQUEST_LIMIT = 720;
const AVATAR_IP_REQUEST_LIMIT = 7200;
const AVATAR_INSPECTION_RATE_WINDOW_SECONDS = 3600;
const AVATAR_INSPECTION_RATE_UNIT = 1048576; // One MiB of opened file work.
const AVATAR_USER_INSPECTION_RATE_UNITS = 2048; // Two GiB of work per hour.
const AVATAR_IP_INSPECTION_RATE_UNITS = 16384; // 16 GiB per source per hour.
const AVATAR_VALIDATION_CACHE_TTL_SECONDS = 300;

function avatarRemoteRateIdentity(): string
{
    $remoteAddress = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    $packedAddress = $remoteAddress !== '' ? @inet_pton($remoteAddress) : false;

    return $packedAddress === false ? 'unknown' : bin2hex($packedAddress);
}

function avatarReserveRequestBudget(int $userId, string $remoteIdentity): bool
{
    if (!Auth::reserveRateLimitAttempt(
        'avatar_read_ip_request',
        $remoteIdentity,
        AVATAR_IP_REQUEST_LIMIT,
        AVATAR_REQUEST_RATE_WINDOW_SECONDS
    )) {
        return false;
    }
    if (!Auth::reserveRateLimitAttempt(
        'avatar_read_user_request',
        (string)$userId,
        AVATAR_USER_REQUEST_LIMIT,
        AVATAR_REQUEST_RATE_WINDOW_SECONDS
    )) {
        Auth::releaseRateLimitAttempt('avatar_read_ip_request', $remoteIdentity);
        return false;
    }
    return true;
}

function avatarReleaseRateUnits(string $scope, string $identity, int $units): void
{
    for ($released = 0; $released < $units; $released++) {
        Auth::releaseRateLimitAttempt($scope, $identity);
    }
}

function avatarReserveRateUnits(
    string $scope,
    string $identity,
    int $units,
    int $limit,
    int $windowSeconds
): bool {
    $reserved = 0;
    while ($reserved < $units) {
        if (!Auth::reserveRateLimitAttempt($scope, $identity, $limit, $windowSeconds)) {
            avatarReleaseRateUnits($scope, $identity, $reserved);
            return false;
        }
        $reserved++;
    }
    return true;
}

/** Cache misses perform two full hashes; positive hits still hash once. */
function avatarReserveInspectionBudget(
    int $userId,
    string $remoteIdentity,
    int $fileBytes,
    int $passes
): bool {
    if ($fileBytes < 1 || $fileBytes > AVATAR_MAX_BYTES ||
        ($passes !== 1 && $passes !== 2)) {
        return false;
    }

    $units = max(1, (int)ceil($fileBytes / AVATAR_INSPECTION_RATE_UNIT)) * $passes;
    if (!avatarReserveRateUnits(
        'avatar_inspect_ip_units',
        $remoteIdentity,
        $units,
        AVATAR_IP_INSPECTION_RATE_UNITS,
        AVATAR_INSPECTION_RATE_WINDOW_SECONDS
    )) {
        return false;
    }
    if (!avatarReserveRateUnits(
        'avatar_inspect_user_units',
        (string)$userId,
        $units,
        AVATAR_USER_INSPECTION_RATE_UNITS,
        AVATAR_INSPECTION_RATE_WINDOW_SECONDS
    )) {
        avatarReleaseRateUnits('avatar_inspect_ip_units', $remoteIdentity, $units);
        return false;
    }
    return true;
}

function avatarSecurityHeaders(): void
{
    // Revalidation is mandatory so a browser cannot reuse a private avatar
    // after the session has ended. Authenticated 304 responses remain cheap.
    header('Cache-Control: private, no-cache, max-age=0, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: sandbox; default-src 'none'");
    header('X-Frame-Options: DENY');
    header('Vary: Cookie');
}

function avatarEndWithStatus(int $status): void
{
    avatarSecurityHeaders();
    http_response_code($status);
    exit;
}

function avatarCloseDatabase($database): void
{
    if ($database === null) {
        return;
    }

    try {
        $database->close();
    } catch (Throwable $error) {
        error_log('Avatar database close error: ' . $error->getMessage());
    }
}

function avatarValidationCacheKey(string $filename, array $stat): ?string
{
    foreach (['dev', 'ino', 'mode', 'nlink', 'size', 'mtime', 'ctime'] as $field) {
        if (!isset($stat[$field]) || !is_int($stat[$field])) {
            return null;
        }
    }

    $identity = strlen($filename) . ':' . $filename . '|' .
        implode('|', array_map(
            static fn(string $field): string => $field . '=' . (string)$stat[$field],
            ['dev', 'ino', 'mode', 'nlink', 'size', 'mtime', 'ctime']
        ));
    return 'pm_avatar_validation_v1_' . hash('sha256', $identity);
}

function avatarCachedValidation(string $cacheKey, array $allowedMimeTypes): ?array
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

function avatarCacheValidation(string $cacheKey, string $contentHash, string $mimeType): void
{
    if (function_exists('apcu_store')) {
        @apcu_store($cacheKey, [
            'content_hash' => $contentHash,
            'mime_type' => $mimeType
        ], AVATAR_VALIDATION_CACHE_TTL_SECONDS);
    }
}

function avatarForgetCachedValidation(string $cacheKey): void
{
    if (function_exists('apcu_delete')) {
        @apcu_delete($cacheKey);
    }
}

/** Hash exactly the opened avatar bytes and restore the stream to byte zero. */
function avatarHashOpenStream($handle, array $expectedStat): ?string
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

avatarSecurityHeaders();

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') {
    header('Allow: GET, HEAD');
    avatarEndWithStatus(405);
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
if (!Auth::startExistingSession(['read_and_close' => true])) {
    avatarEndWithStatus(401);
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
    $loginTime <= $now && ($now - $lastActivity) <= AVATAR_SESSION_TIMEOUT &&
    ($now - $loginTime) <= AVATAR_ABSOLUTE_SESSION_TIMEOUT &&
    $authVersion !== '' && $twoFactorVersion !== '';
if (!$isAuthenticated) {
    avatarEndWithStatus(401);
}

// Chat lists may legitimately load hundreds of avatars in a burst, but one
// account or source must not open unlimited database connections and image
// parsers. Reserve the fixed-cardinality IP bucket before the account bucket.
$remoteRateIdentity = avatarRemoteRateIdentity();
if (!avatarReserveRequestBudget($userId, $remoteRateIdentity)) {
    header('Retry-After: ' . AVATAR_REQUEST_RATE_WINDOW_SECONDS);
    avatarEndWithStatus(429);
}

$filename = $_GET['file'] ?? null;
$filenamePattern = '/\Aavatar_([0-9]+)_[0-9]+(?:_[a-f0-9]{8})?\.(?:jpe?g|jfif|png|gif|webp)\z/i';
$filenameMatches = [];
if (!is_string($filename) || preg_match($filenamePattern, $filename, $filenameMatches) !== 1 ||
    !isset($filenameMatches[1]) || (float) $filenameMatches[1] > 2147483647) {
    avatarEndWithStatus(404);
}
$avatarOwnerId = (int) $filenameMatches[1];

$fileHandle = null;
$database = null;

try {
    require_once __DIR__ . '/../config/database.php';

    $database = new Database();
    $connection = $database->connect();
    $relativeAvatarPath = 'uploads/avatars/' . $filename;
    $statement = $connection->prepare("
        SELECT viewer.password_hash, viewer.two_factor_enabled, viewer.two_factor_secret
        FROM users viewer
        INNER JOIN users owner
            ON owner.id = ?
        WHERE viewer.id = ?
            AND owner.avatar = ?
            AND (owner.id = ? OR COALESCE(owner.show_profile_photo, 0) = 1)
        LIMIT 1
    ");
    $statement->bind_param('iisi', $avatarOwnerId, $userId, $relativeAvatarPath, $userId);
    $statement->execute();
    $result = $statement->get_result();
    $authorizedAvatar = $result->fetch_assoc();
    $result->free();
    $statement->close();

    // A stale path, hidden profile photo, unknown owner, and unknown viewer all
    // look identical. Filename knowledge alone never grants access.
    if (!is_array($authorizedAvatar)) {
        avatarCloseDatabase($database);
        $database = null;
        avatarEndWithStatus(404);
    }

    $currentPasswordHash = $authorizedAvatar['password_hash'] ?? null;
    $currentTwoFactorState = $authorizedAvatar['two_factor_enabled'] ?? null;
    $currentTwoFactorSecret = is_string($authorizedAvatar['two_factor_secret'] ?? null)
        ? $authorizedAvatar['two_factor_secret']
        : null;
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
        avatarCloseDatabase($database);
        $database = null;
        avatarEndWithStatus(401);
    }
    avatarCloseDatabase($database);
    $database = null;

    $avatarDirectory = realpath(__DIR__ . '/../uploads/avatars');
    $candidatePath = $avatarDirectory !== false
        ? $avatarDirectory . DIRECTORY_SEPARATOR . $filename
        : '';
    $avatarPath = $candidatePath !== '' ? realpath($candidatePath) : false;
    if ($avatarDirectory === false || $avatarPath === false || is_link($candidatePath) ||
        dirname($avatarPath) !== $avatarDirectory || !is_file($avatarPath) ||
        !is_readable($avatarPath)) {
        avatarEndWithStatus(404);
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
        $validatedPathStat['size'] < 1 || $validatedPathStat['size'] > AVATAR_MAX_BYTES) {
        avatarEndWithStatus(404);
    }

    $fileHandle = @fopen($avatarPath, 'rb');
    if ($fileHandle === false) {
        $fileHandle = null;
        avatarEndWithStatus(404);
    }

    // Compare the opened descriptor with lstat() after opening. This rejects a
    // symlink swap between path validation and fopen(), rather than trusting a
    // second pathname lookup.
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
        $streamStat['size'] < 1 || $streamStat['size'] > AVATAR_MAX_BYTES) {
        fclose($fileHandle);
        $fileHandle = null;
        avatarEndWithStatus(404);
    }
    foreach (['dev', 'ino', 'mode', 'nlink', 'size', 'mtime', 'ctime'] as $identityField) {
        if ($streamStat[$identityField] !== $pathStat[$identityField] ||
            $streamStat[$identityField] !== $validatedPathStat[$identityField]) {
            fclose($fileHandle);
            $fileHandle = null;
            avatarEndWithStatus(404);
        }
    }

    $fileSize = $streamStat['size'];
    $modifiedAt = $streamStat['mtime'];
    $cacheKey = avatarValidationCacheKey($filename, $streamStat);
    if (!is_string($cacheKey)) {
        fclose($fileHandle);
        $fileHandle = null;
        avatarEndWithStatus(404);
    }
    $etag = 'W/"' . hash('sha256', 'avatar-etag-v1|' . $cacheKey) . '"';
    $requestEtag = isset($_SERVER['HTTP_IF_NONE_MATCH']) && is_string($_SERVER['HTTP_IF_NONE_MATCH'])
        ? trim($_SERVER['HTTP_IF_NONE_MATCH'])
        : '';

    // A matching conditional request emits no representation bytes and may
    // stop after fresh authorization and descriptor identity. HEAD uses a
    // cached positive MIME verdict below, or performs normal validation.
    if ($requestEtag !== '' && hash_equals($etag, $requestEtag)) {
        avatarSecurityHeaders();
        header('ETag: ' . $etag);
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $modifiedAt) . ' GMT');
        fclose($fileHandle);
        $fileHandle = null;
        http_response_code(304);
        exit;
    }
    $allowedMimeTypes = [
        'image/jpeg' => true,
        'image/png' => true,
        'image/gif' => true,
        'image/webp' => true
    ];
    $cachedValidation = avatarCachedValidation($cacheKey, $allowedMimeTypes);
    if ($method === 'HEAD' && $cachedValidation !== null) {
        $validatedContentHash = $cachedValidation['content_hash'];
        $mimeType = $cachedValidation['mime_type'];
    } else {
        $inspectionPasses = $cachedValidation === null ? 2 : 1;
        if (!avatarReserveInspectionBudget(
            $userId,
            $remoteRateIdentity,
            $fileSize,
            $inspectionPasses
        )) {
            fclose($fileHandle);
            $fileHandle = null;
            header('Retry-After: ' . AVATAR_INSPECTION_RATE_WINDOW_SECONDS);
            avatarEndWithStatus(429);
        }

        if ($cachedValidation !== null) {
            $validatedContentHash = $cachedValidation['content_hash'];
            $mimeType = $cachedValidation['mime_type'];
            $streamContentHash = avatarHashOpenStream($fileHandle, $streamStat);
            if (!is_string($streamContentHash) ||
                !hash_equals($validatedContentHash, $streamContentHash)) {
                avatarForgetCachedValidation($cacheKey);
                fclose($fileHandle);
                $fileHandle = null;
                avatarEndWithStatus(404);
            }
        } else {
            $validatedContentHash = hash_file('sha256', $avatarPath);
            if (!is_string($validatedContentHash) ||
                preg_match('/\A[a-f0-9]{64}\z/D', $validatedContentHash) !== 1) {
                fclose($fileHandle);
                $fileHandle = null;
                avatarEndWithStatus(404);
            }

            $pathMimeDetector = finfo_open(FILEINFO_MIME_TYPE);
            $pathMimeType = $pathMimeDetector ? finfo_file($pathMimeDetector, $avatarPath) : false;
            if ($pathMimeDetector) {
                finfo_close($pathMimeDetector);
            }
            if (!is_string($pathMimeType) || !isset($allowedMimeTypes[$pathMimeType]) ||
                !SafeImage::isSafeStaticImage(
                    $avatarPath,
                    $pathMimeType,
                    SafeImage::AVATAR_MAX_DIMENSION,
                    SafeImage::AVATAR_MAX_PIXELS
                )) {
                fclose($fileHandle);
                $fileHandle = null;
                avatarEndWithStatus(404);
            }

            $streamContentHash = avatarHashOpenStream($fileHandle, $streamStat);
            if (!is_string($streamContentHash) ||
                !hash_equals($validatedContentHash, $streamContentHash)) {
                fclose($fileHandle);
                $fileHandle = null;
                avatarEndWithStatus(404);
            }
            $sample = fread($fileHandle, min(262144, $fileSize));
            if (!is_string($sample) || $sample === '' || rewind($fileHandle) === false) {
                throw new RuntimeException('Unable to inspect avatar stream');
            }
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mimeType = $finfo ? finfo_buffer($finfo, $sample) : false;
            if ($finfo) {
                finfo_close($finfo);
            }
            if (!is_string($mimeType) || !isset($allowedMimeTypes[$mimeType]) ||
                !hash_equals($pathMimeType, $mimeType)) {
                fclose($fileHandle);
                $fileHandle = null;
                avatarEndWithStatus(404);
            }
            avatarCacheValidation($cacheKey, $streamContentHash, $mimeType);
        }
    }

    avatarSecurityHeaders();
    header('Content-Type: ' . $mimeType);
    header('Content-Length: ' . (string) $fileSize);
    header('Content-Disposition: inline; filename="' . $filename . '"');
    header('ETag: ' . $etag);
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $modifiedAt) . ' GMT');

    if ($method === 'HEAD') {
        fclose($fileHandle);
        $fileHandle = null;
        exit;
    }

    if (fpassthru($fileHandle) === false) {
        throw new RuntimeException('Unable to stream avatar');
    }
    fclose($fileHandle);
} catch (Throwable $error) {
    if (is_resource($fileHandle)) {
        fclose($fileHandle);
    }
    avatarCloseDatabase($database);
    error_log('Avatar delivery error: ' . $error->getMessage());
    avatarEndWithStatus(500);
}
