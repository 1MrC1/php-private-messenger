<?php
// api/profile.php
require_once __DIR__ . '/../classes/Auth.php';
require_once __DIR__ . '/../classes/I18n.php';
require_once __DIR__ . '/../classes/SafeImage.php';
require_once __DIR__ . '/../classes/MalwareScanner.php';
require_once __DIR__ . '/../config/database.php';

final class ProfileUploadSecurityException extends RuntimeException
{
    private int $statusCode;
    private string $errorCode;

    public function __construct(string $message, string $errorCode, int $statusCode)
    {
        parent::__construct($message);
        $this->errorCode = $errorCode;
        $this->statusCode = $statusCode;
    }

    public function statusCode(): int
    {
        return $this->statusCode;
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }
}

Auth::configureSession();
Auth::setPrivateResponseHeaders();
I18n::applyResponseHeaders();

header('Content-Type: application/json; charset=utf-8');

// Profile changes are user-driven rather than polled. A full request can also
// parse an image and perform uniqueness/database work, so bound it well before
// constructing Auth or Database while leaving ample room for UI retries.
const PROFILE_API_RATE_WINDOW_SECONDS = 60;
const PROFILE_API_USER_REQUEST_LIMIT = 60;
const PROFILE_API_IP_REQUEST_LIMIT = 600;

function profileApiRemoteIdentity(): string {
    $remoteAddress = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    $packedAddress = $remoteAddress !== '' ? @inet_pton($remoteAddress) : false;

    return $packedAddress === false ? 'unknown' : bin2hex($packedAddress);
}

function profileApiSessionUserId(): ?int {
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

/** Reserve the fixed-cardinality IP bucket before the stable account bucket. */
function reserveProfileApiRequestBudget(int $userId): bool {
    $remoteIdentity = profileApiRemoteIdentity();
    $userIdentity = (string)$userId;

    if (!Auth::reserveRateLimitAttempt(
        'profile_api_ip',
        $remoteIdentity,
        PROFILE_API_IP_REQUEST_LIMIT,
        PROFILE_API_RATE_WINDOW_SECONDS
    )) {
        return false;
    }
    if (!Auth::reserveRateLimitAttempt(
        'profile_api_user',
        $userIdentity,
        PROFILE_API_USER_REQUEST_LIMIT,
        PROFILE_API_RATE_WINDOW_SECONDS
    )) {
        Auth::releaseRateLimitAttempt('profile_api_ip', $remoteIdentity);
        return false;
    }
    return true;
}

function rejectProfileApiRateLimit(): never {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    http_response_code(429);
    header('Retry-After: ' . PROFILE_API_RATE_WINDOW_SECONDS);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Too many requests. Try again shortly.']);
    exit;
}

$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
if ($method === 'OPTIONS') {
    if (!Auth::isSameOriginRequest()) {
        http_response_code(403);
        echo I18n::encodeResponse(['success' => false, 'message' => 'Cross-origin request denied']);
        exit;
    }
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    http_response_code(204);
    exit;
}

if ($method !== 'POST') {
    header('Allow: POST, OPTIONS');
    http_response_code(405);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

if (!Auth::isSameOriginRequest()) {
    http_response_code(403);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Cross-origin request denied']);
    exit;
}

$contentType = strtolower(trim((string)($_SERVER['CONTENT_TYPE'] ?? '')));
if (!str_starts_with($contentType, 'multipart/form-data;')) {
    http_response_code(415);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Content-Type must be multipart/form-data']);
    exit;
}

if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 6 * 1024 * 1024) {
    http_response_code(413);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Request is too large']);
    exit;
}

$pendingAvatarPath = null;
$currentUser = null;
$conn = null;
$transactionStarted = false;
$commitAttempted = false;

try {
    // Reject anonymous traffic before PHP creates a new session file for a
    // protected endpoint.
    if (!Auth::startExistingSession()) {
        http_response_code(401);
        throw new Exception('Invalid or expired session');
    }
    $sessionUserId = profileApiSessionUserId();
    if ($sessionUserId === null) {
        session_write_close();
        http_response_code(401);
        throw new Exception('Invalid or expired session');
    }
    if (!reserveProfileApiRequestBudget($sessionUserId)) {
        rejectProfileApiRateLimit();
    }
    
    $auth = new Auth();
    $sessionResult = $auth->validateSessionFromCookie();
    
    if (!$sessionResult['success']) {
        http_response_code(401);
        throw new Exception('Invalid or expired session');
    }
    
    $currentUser = $sessionResult['user'];
    $db = new Database();
    $conn = $db->connect();
    
    $response = ['success' => false];

    // PHP can populate the avatar field even when the upload itself failed.
    // Reject malformed or failed uploads before applying any profile fields so
    // the request cannot silently become a partial text-only update.
    $avatarFieldPresent = array_key_exists('avatar', $_FILES);
    $avatarUploadError = UPLOAD_ERR_NO_FILE;
    if ($avatarFieldPresent) {
        if (!is_array($_FILES['avatar']) ||
            !array_key_exists('error', $_FILES['avatar']) ||
            !is_int($_FILES['avatar']['error'])) {
            throw new Exception('Avatar upload failed');
        }

        $avatarUploadError = $_FILES['avatar']['error'];
        if ($avatarUploadError !== UPLOAD_ERR_OK &&
            $avatarUploadError !== UPLOAD_ERR_NO_FILE) {
            throw new Exception('Avatar upload failed');
        }
    }
    
    // This shortcut is only for a genuinely avatar-only form. Do not silently
    // ignore a partial profile payload merely because its required names are
    // absent.
    $isAvatarOnlyUpload = $avatarFieldPresent && $avatarUploadError === UPLOAD_ERR_OK &&
        !array_key_exists('action', $_POST) &&
        !array_key_exists('first_name', $_POST) &&
        !array_key_exists('last_name', $_POST) &&
        !array_key_exists('username', $_POST) &&
        !array_key_exists('bio', $_POST) &&
        !array_key_exists('phone', $_POST);
    $hasAvatarUpload = $avatarFieldPresent && $avatarUploadError === UPLOAD_ERR_OK;

    if ($hasAvatarUpload) {
        // Reserve the account-wide quota before processing bytes. The shared
        // counter admits exactly ten attempts even when several sessions race.
        $avatarRateIdentity = (string)$currentUser['id'];
        if (!Auth::reserveRateLimitAttempt('avatar_upload', $avatarRateIdentity, 10, 3600)) {
            http_response_code(429);
            throw new Exception('Too many avatar uploads. Try again later.');
        }
    }
    
    if ($isAvatarOnlyUpload) {
        // Handle avatar-only upload
        $pendingAvatarPath = handleAvatarUpload($_FILES['avatar'], $currentUser['id']);
        $avatarPath = $pendingAvatarPath;
        if (!$avatarPath) {
            throw new Exception('Avatar upload failed');
        }
        
        // Serialize replacement on the account row. A second session cannot
        // read the same stale predecessor and leave this new file orphaned.
        if (!$conn->begin_transaction()) {
            throw new Exception('Failed to update avatar');
        }
        $transactionStarted = true;
        $previousAvatarPath = lockCurrentAvatarPath($conn, (int)$currentUser['id']);

        // Update only avatar
        $stmt = $conn->prepare("UPDATE users SET avatar = ?, updated_at = NOW() WHERE id = ?");
        $stmt->bind_param("si", $avatarPath, $currentUser['id']);
        if (!$stmt->execute() || $stmt->affected_rows !== 1) {
            throw new Exception('Failed to update avatar');
        }

        // Get updated user data while the replacement row remains locked.
        $stmt = $conn->prepare("SELECT id, username, email, first_name, last_name, avatar, bio, phone FROM users WHERE id = ?");
        $stmt->bind_param("i", $currentUser['id']);
        if (!$stmt->execute()) {
            throw new Exception('Failed to update avatar');
        }
        $updatedUser = $stmt->get_result()->fetch_assoc();
        if (!is_array($updatedUser)) {
            throw new Exception('Failed to update avatar');
        }
        // A connection loss while COMMIT is in flight has an ambiguous
        // outcome. Retain the private file in that case so a committed row can
        // never be left pointing at a deleted avatar.
        $commitAttempted = true;
        if (!$conn->commit()) {
            throw new Exception('Failed to update avatar');
        }
        $transactionStarted = false;

        // The committed database row owns the new file. Delete the exact
        // predecessor observed under FOR UPDATE, not stale session data.
        $pendingAvatarPath = null;
        deleteStoredAvatarFile($previousAvatarPath, $currentUser['id'], $avatarPath);
        $response = [
            'success' => true,
            'message' => 'Avatar updated successfully',
            'user' => $updatedUser
        ];
    } else {
        // Handle full profile update (original functionality)
        if (!isset($_POST['action']) || $_POST['action'] !== 'update_profile') {
            throw new Exception('Invalid action or missing action parameter');
        }
        
        if (!isset($_POST['first_name'], $_POST['last_name'], $_POST['username']) ||
            !is_string($_POST['first_name']) || !is_string($_POST['last_name']) ||
            !is_string($_POST['username']) ||
            (isset($_POST['bio']) && !is_string($_POST['bio'])) ||
            (isset($_POST['phone']) && !is_string($_POST['phone']))) {
            throw new Exception('Profile fields are invalid');
        }

        // Get form data
        $firstName = trim($_POST['first_name']);
        $lastName = trim($_POST['last_name']);
        $username = trim($_POST['username']);
        $bio = trim($_POST['bio'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        
        // Validate required fields
        if (preg_match('//u', $firstName . $lastName . $username . $bio . $phone) !== 1) {
            throw new Exception('Profile fields are invalid');
        }
        if ($firstName === '' || $lastName === '' || profileTextLength($firstName) > 50 ||
            profileTextLength($lastName) > 50 || preg_match('/[<>\x00-\x1F\x7F]/u', $firstName . $lastName)) {
            throw new Exception('First name and last name contain invalid characters');
        }
        if (profileTextLength($username) < 3 || profileTextLength($username) > 50 ||
            preg_match('/^[\p{L}\p{N}_.-]+$/u', $username) !== 1) {
            throw new Exception('Username must be 3-50 letters, numbers, dots, dashes, or underscores');
        }
        if (profileTextLength($bio) > 1000 || strlen($phone) > 20) {
            throw new Exception('Profile data is too long');
        }
        if ($phone !== '' && preg_match('/^\+?[0-9 ()-]{3,20}$/D', $phone) !== 1) {
            throw new Exception('Phone number is invalid');
        }

        if ($username !== $currentUser['username']) {
            $stmt = $conn->prepare('SELECT id FROM users WHERE username = ? AND id != ? LIMIT 1');
            $stmt->bind_param('si', $username, $currentUser['id']);
            $stmt->execute();
            if ($stmt->get_result()->num_rows !== 0) {
                throw new Exception('Username is already taken');
            }
        }

        // Password changes have stronger transaction and row-lock guarantees
        // in api/settings.php. Keeping a second multipart mutation path would
        // allow its factor proof and password update to diverge on failure.
        if (array_key_exists('current_password', $_POST) ||
            array_key_exists('new_password', $_POST)) {
            http_response_code(400);
            throw new Exception('Password changes must use account settings');
        }
        
        // Handle avatar upload
        $avatarPath = null;
        if ($hasAvatarUpload) {
            $pendingAvatarPath = handleAvatarUpload($_FILES['avatar'], $currentUser['id']);
            $avatarPath = $pendingAvatarPath;
            if (!$avatarPath) {
                throw new Exception('Avatar upload failed');
            }
        }

        $previousAvatarPath = null;
        if ($avatarPath) {
            if (!$conn->begin_transaction()) {
                throw new Exception('Failed to update profile');
            }
            $transactionStarted = true;
            $previousAvatarPath = lockCurrentAvatarPath($conn, (int)$currentUser['id']);
        }
        
        // Build update query
        $updateFields = "first_name = ?, last_name = ?, username = ?, bio = ?, phone = ?";
        $params = [$firstName, $lastName, $username, $bio, $phone];
        $types = "sssss";
        
        if ($avatarPath) {
            $updateFields .= ", avatar = ?";
            $params[] = $avatarPath;
            $types .= "s";
        }
        
        $params[] = $currentUser['id'];
        $types .= "i";
        
        // Update user profile
        $stmt = $conn->prepare("UPDATE users SET {$updateFields}, updated_at = NOW() WHERE id = ?");
        $stmt->bind_param($types, ...$params);
        
        if (!$stmt->execute()) {
            throw new Exception('Failed to update profile');
        }

        // Get updated user data
        $stmt = $conn->prepare("SELECT id, username, email, first_name, last_name, avatar, bio, phone FROM users WHERE id = ?");
        $stmt->bind_param("i", $currentUser['id']);
        if (!$stmt->execute()) {
            throw new Exception('Failed to update profile');
        }
        $updatedUser = $stmt->get_result()->fetch_assoc();
        if (!is_array($updatedUser)) {
            throw new Exception('Failed to update profile');
        }
        if ($avatarPath) {
            $commitAttempted = true;
            if (!$conn->commit()) {
                throw new Exception('Failed to update profile');
            }
        }
        if ($avatarPath) {
            $transactionStarted = false;
            $pendingAvatarPath = null;
            deleteStoredAvatarFile($previousAvatarPath, $currentUser['id'], $avatarPath);
        }

        $response = [
            'success' => true,
            'message' => 'Profile updated successfully',
            'user' => $updatedUser
        ];
    }
    
} catch (Throwable $e) {
    if ($transactionStarted && $conn instanceof mysqli) {
        try {
            $conn->rollback();
        } catch (Throwable $ignored) {
        }
        $transactionStarted = false;
    }
    // A file moved before a failed database update must not become an orphan.
    if (is_string($pendingAvatarPath) && !$commitAttempted) {
        deleteStoredAvatarFile($pendingAvatarPath, is_array($currentUser) ? ($currentUser['id'] ?? 0) : 0);
    } elseif (is_string($pendingAvatarPath) && $commitAttempted) {
        error_log('Retained private avatar after ambiguous profile commit outcome');
    }
    error_log("Profile API Error: " . $e->getMessage());
    $securityUploadError = $e instanceof ProfileUploadSecurityException;
    if ($securityUploadError) {
        http_response_code($e->statusCode());
    }
    $safeMessages = [
        'Invalid or expired session',
        'Avatar upload failed',
        'Too many avatar uploads. Try again later.',
        'Failed to update avatar',
        'Invalid action or missing action parameter',
        'Profile fields are invalid',
        'First name and last name contain invalid characters',
        'Username must be 3-50 letters, numbers, dots, dashes, or underscores',
        'Username is already taken',
        'Profile data is too long',
        'Phone number is invalid',
        'Password changes must use account settings',
        'Failed to update profile',
        'This avatar was rejected by security scanning',
        'Avatar security scanning is temporarily unavailable',
        'The avatar changed during security scanning'
    ];
    $publicMessage = in_array($e->getMessage(), $safeMessages, true)
        ? $e->getMessage()
        : 'Profile update failed';
    $response = [
        'success' => false,
        'message' => $publicMessage
    ];
    if ($securityUploadError) {
        $response['error_code'] = $e->errorCode();
    }
}

echo I18n::encodeResponse($response);

function profileTextLength($value) {
    return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
}

function lockCurrentAvatarPath($connection, $userId) {
    $stmt = $connection->prepare('SELECT avatar FROM users WHERE id = ? FOR UPDATE');
    $stmt->bind_param('i', $userId);
    if (!$stmt->execute()) {
        throw new RuntimeException('Unable to lock avatar state');
    }
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        throw new RuntimeException('Unable to lock avatar state');
    }
    $row = $result->fetch_assoc();
    return is_array($row) && is_string($row['avatar'] ?? null) ? $row['avatar'] : null;
}

function deleteStoredAvatarFile($relativePath, $userId, $keepPath = null) {
    if (!is_string($relativePath) || $relativePath === '' ||
        (is_string($keepPath) && hash_equals($relativePath, $keepPath))) {
        return;
    }

    $matches = [];
    $pattern = '#\Auploads/avatars/(avatar_([0-9]+)_[0-9]+(?:_[a-f0-9]{8})?\.(?:jpe?g|jfif|png|gif|webp))\z#i';
    if (preg_match($pattern, $relativePath, $matches) !== 1 ||
        (int) $matches[2] !== (int) $userId || (int) $userId < 1) {
        return;
    }

    $avatarDirectory = realpath(__DIR__ . '/../uploads/avatars');
    $candidatePath = $avatarDirectory !== false
        ? $avatarDirectory . DIRECTORY_SEPARATOR . $matches[1]
        : '';
    $resolvedPath = $candidatePath !== '' ? realpath($candidatePath) : false;
    $pathStat = $candidatePath !== '' ? @lstat($candidatePath) : false;
    if ($avatarDirectory === false || $resolvedPath === false || $pathStat === false ||
        !isset($pathStat['mode']) || (($pathStat['mode'] & 0170000) !== 0100000) ||
        is_link($candidatePath) || dirname($resolvedPath) !== $avatarDirectory) {
        return;
    }

    if (!@unlink($candidatePath) && is_file($candidatePath)) {
        error_log('Unable to remove superseded avatar file');
    }
}

function handleAvatarUpload($file, $userId) {
    if (!is_array($file) || !isset($file['error'], $file['tmp_name']) ||
        !is_scalar($file['error']) || (int) $file['error'] !== UPLOAD_ERR_OK ||
        !is_string($file['tmp_name']) || $file['tmp_name'] === '' ||
        !is_uploaded_file($file['tmp_name']) || (int) $userId < 1) {
        return false;
    }

    // Read the server-side size. Multipart metadata is not authoritative.
    $actualSize = @filesize($file['tmp_name']);
    $temporaryStat = @lstat($file['tmp_name']);
    if ($actualSize === false || $actualSize < 1 || $actualSize > 5 * 1024 * 1024 ||
        !is_array($temporaryStat) || !isset(
            $temporaryStat['mode'],
            $temporaryStat['size'],
            $temporaryStat['dev'],
            $temporaryStat['ino'],
            $temporaryStat['nlink']
        ) || (($temporaryStat['mode'] & 0170000) !== 0100000) ||
        (int)$temporaryStat['nlink'] !== 1 ||
        (int)$temporaryStat['size'] !== (int)$actualSize) {
        return false;
    }
    $preValidationHash = hash_file('sha256', $file['tmp_name']);
    if (!is_string($preValidationHash) ||
        preg_match('/\A[a-f0-9]{64}\z/D', $preValidationHash) !== 1) {
        return false;
    }

    // Detect the actual bytes and choose the extension server-side. Browser
    // MIME metadata and the original filename are not trusted.
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = $finfo ? finfo_file($finfo, $file['tmp_name']) : false;
    if ($finfo) {
        finfo_close($finfo);
    }

    $allowedTypes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'image/webp' => 'webp'
    ];
    if (!is_string($mimeType) || !isset($allowedTypes[$mimeType])) {
        return false;
    }

    if (!SafeImage::isSafeStaticImage(
        $file['tmp_name'],
        $mimeType,
        SafeImage::AVATAR_MAX_DIMENSION,
        SafeImage::AVATAR_MAX_PIXELS
    )) {
        return false;
    }

    $validatedHash = hash_file('sha256', $file['tmp_name']);
    if (!is_string($validatedHash) ||
        preg_match('/\A[a-f0-9]{64}\z/D', $validatedHash) !== 1 ||
        !hash_equals($preValidationHash, $validatedHash)) {
        throw new ProfileUploadSecurityException(
            'The avatar changed during security scanning',
            'avatar_changed',
            422
        );
    }

    $scanResult = MalwareScanner::scanFile($file['tmp_name'], 5 * 1024 * 1024);
    if (($scanResult['status'] ?? null) === MalwareScanner::INFECTED) {
        $signature = is_string($scanResult['signature'] ?? null) &&
            strlen($scanResult['signature']) <= 200
            ? $scanResult['signature']
            : 'unknown';
        error_log(
            'Avatar rejected by malware scanner: ' .
            json_encode($signature, JSON_UNESCAPED_SLASHES)
        );
        throw new ProfileUploadSecurityException(
            'This avatar was rejected by security scanning',
            'avatar_rejected',
            422
        );
    }
    if (($scanResult['status'] ?? null) !== MalwareScanner::CLEAN) {
        $reason = is_string($scanResult['reason'] ?? null) &&
            preg_match('/\A[a-z_]{1,64}\z/D', $scanResult['reason']) === 1
            ? $scanResult['reason']
            : 'unknown';
        if (in_array($reason, ['invalid_file', 'file_unavailable', 'file_changed'], true)) {
            error_log('Avatar changed before malware scanning completed: ' . $reason);
            throw new ProfileUploadSecurityException(
                'The avatar changed during security scanning',
                'avatar_changed',
                422
            );
        }
        error_log('Avatar malware scanner unavailable: ' . $reason);
        throw new ProfileUploadSecurityException(
            'Avatar security scanning is temporarily unavailable',
            'scanner_unavailable',
            503
        );
    }
    $scanHash = $scanResult['sha256'] ?? null;
    if (!is_string($scanHash) || preg_match('/\A[a-f0-9]{64}\z/D', $scanHash) !== 1 ||
        !hash_equals($validatedHash, $scanHash)) {
        error_log('Avatar changed during malware scanning');
        throw new ProfileUploadSecurityException(
            'The avatar changed during security scanning',
            'avatar_changed',
            422
        );
    }

    // Create upload directory if it doesn't exist
    $uploadDir = __DIR__ . '/../uploads/avatars/';
    if (!is_dir($uploadDir)) {
        if (!mkdir($uploadDir, 0750, true) && !is_dir($uploadDir)) {
            return false;
        }
    }

    // Generate unique filename
    try {
        $suffix = bin2hex(random_bytes(4));
    } catch (Throwable $e) {
        error_log('Avatar filename generation failed');
        return false;
    }
    $filename = 'avatar_' . (int) $userId . '_' . time() . '_' . $suffix . '.' . $allowedTypes[$mimeType];
    $filePath = $uploadDir . $filename;

    $beforeMoveStat = @lstat($file['tmp_name']);
    if (!is_uploaded_file($file['tmp_name']) || !is_array($beforeMoveStat) ||
        !isset(
            $beforeMoveStat['mode'],
            $beforeMoveStat['size'],
            $beforeMoveStat['dev'],
            $beforeMoveStat['ino'],
            $beforeMoveStat['nlink']
        ) || (($beforeMoveStat['mode'] & 0170000) !== 0100000) ||
        (int)$beforeMoveStat['nlink'] !== 1 ||
        (int)$beforeMoveStat['size'] !== (int)$actualSize ||
        (int)$beforeMoveStat['dev'] !== (int)$temporaryStat['dev'] ||
        (int)$beforeMoveStat['ino'] !== (int)$temporaryStat['ino']) {
        throw new ProfileUploadSecurityException(
            'The avatar changed during security scanning',
            'avatar_changed',
            422
        );
    }
    
    // Move uploaded file
    if (move_uploaded_file($file['tmp_name'], $filePath)) {
        // PHP, not the web server, is the only component that needs to read
        // stored avatars. Fail closed if local file permissions cannot be set.
        if (!@chmod($filePath, 0640)) {
            deleteStoredAvatarFile('uploads/avatars/' . $filename, $userId);
            return false;
        }
        $storedStat = @lstat($filePath);
        $storedHash = hash_file('sha256', $filePath);
        if (!is_array($storedStat) ||
            !isset($storedStat['mode'], $storedStat['size'], $storedStat['nlink']) ||
            (($storedStat['mode'] & 0170000) !== 0100000) ||
            (int)$storedStat['nlink'] !== 1 ||
            (int)$storedStat['size'] !== (int)$actualSize ||
            !is_string($storedHash) || !hash_equals($scanHash, $storedHash)) {
            deleteStoredAvatarFile('uploads/avatars/' . $filename, $userId);
            throw new ProfileUploadSecurityException(
                'The avatar changed during security scanning',
                'avatar_changed',
                422
            );
        }
        // Return relative path for database storage
        return 'uploads/avatars/' . $filename;
    }
    
    return false;
}
?>
