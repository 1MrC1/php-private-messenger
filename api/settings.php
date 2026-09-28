<?php
// api/settings.php
require_once __DIR__ . '/../classes/Auth.php';
require_once __DIR__ . '/../classes/I18n.php';
require_once __DIR__ . '/../config/database.php';

Auth::configureSession();
Auth::setPrivateResponseHeaders();
I18n::applyResponseHeaders();
header('Content-Type: application/json; charset=utf-8');

const SETTINGS_API_MAX_JSON_BYTES = 131072;
// Settings has no polling loop, but opening the panel can issue several
// requests in a burst. Keep generous UI headroom while bounding account and
// source-driven database work, including storage-usage aggregation.
const SETTINGS_API_RATE_WINDOW_SECONDS = 60;
const SETTINGS_API_USER_REQUEST_LIMIT = 120;
const SETTINGS_API_IP_REQUEST_LIMIT = 1200;

function settingsApiRemoteIdentity(): string {
    $remoteAddress = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    $packedAddress = $remoteAddress !== '' ? @inet_pton($remoteAddress) : false;

    return $packedAddress === false ? 'unknown' : bin2hex($packedAddress);
}

function settingsApiSessionUserId(): ?int {
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
function reserveSettingsApiRequestBudget(int $userId): bool {
    $remoteIdentity = settingsApiRemoteIdentity();
    $userIdentity = (string)$userId;

    if (!Auth::reserveRateLimitAttempt(
        'settings_api_ip',
        $remoteIdentity,
        SETTINGS_API_IP_REQUEST_LIMIT,
        SETTINGS_API_RATE_WINDOW_SECONDS
    )) {
        return false;
    }
    if (!Auth::reserveRateLimitAttempt(
        'settings_api_user',
        $userIdentity,
        SETTINGS_API_USER_REQUEST_LIMIT,
        SETTINGS_API_RATE_WINDOW_SECONDS
    )) {
        Auth::releaseRateLimitAttempt('settings_api_ip', $remoteIdentity);
        return false;
    }
    return true;
}

function rejectSettingsApiRateLimit(): never {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    http_response_code(429);
    header('Retry-After: ' . SETTINGS_API_RATE_WINDOW_SECONDS);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Too many requests. Try again shortly.']);
    exit;
}

function settingsTextLength(string $value): int {
    return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
}

/**
 * Accept the explicit field used by new clients and the legacy `code` field
 * used by the existing 2FA controls. Conflicting values are rejected.
 */
function settingsSecondFactorCode(array $input): ?string {
    $code = null;
    foreach (['second_factor_code', 'code'] as $field) {
        if (!array_key_exists($field, $input)) {
            continue;
        }
        if (!is_string($input[$field])) {
            return null;
        }

        $candidate = strtoupper(trim($input[$field]));
        if ($candidate === '' || ($code !== null && !hash_equals($code, $candidate))) {
            return null;
        }
        $code = $candidate;
    }
    return $code;
}

function settingsClearPendingTwoFactorEnrollment(): void {
    unset(
        $_SESSION['pending_2fa_secret'],
        $_SESSION['pending_2fa_started_at'],
        $_SESSION['pending_2fa_attempts'],
        $_SESSION['pending_2fa_auth_version'],
        $_SESSION['pending_2fa_factor_version']
    );
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

$contentType = strtolower(trim(explode(';', (string)($_SERVER['CONTENT_TYPE'] ?? ''))[0]));
if ($contentType !== 'application/json') {
    http_response_code(415);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Content-Type must be application/json']);
    exit;
}

if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > SETTINGS_API_MAX_JSON_BYTES) {
    http_response_code(413);
    echo I18n::encodeResponse(['success' => false, 'message' => 'Request is too large']);
    exit;
}

try {
    // This endpoint is entirely protected. Prove and validate the existing
    // session before reading even a bounded JSON body so anonymous requests do
    // not consume parser memory or a database connection for settings work.
    if (!Auth::startExistingSession()) {
        http_response_code(401);
        throw new Exception('Invalid or expired session');
    }
    $sessionUserId = settingsApiSessionUserId();
    if ($sessionUserId === null) {
        session_write_close();
        http_response_code(401);
        throw new Exception('Invalid or expired session');
    }
    if (!reserveSettingsApiRequestBudget($sessionUserId)) {
        rejectSettingsApiRateLimit();
    }
    $auth = new Auth();
    $sessionResult = $auth->validateSessionFromCookie();

    if (!$sessionResult['success']) {
        http_response_code(401);
        throw new Exception('Invalid or expired session');
    }

    $currentUser = $sessionResult['user'];

    try {
        // Always cap the actual bytes read. Content-Length may be absent or
        // untrusted (for example, with a chunked request body).
        $rawInput = file_get_contents(
            'php://input',
            false,
            null,
            0,
            SETTINGS_API_MAX_JSON_BYTES + 1
        );
        if ($rawInput === false) {
            throw new Exception('Invalid request');
        }
        if (strlen($rawInput) > SETTINGS_API_MAX_JSON_BYTES) {
            http_response_code(413);
            echo I18n::encodeResponse(['success' => false, 'message' => 'Request is too large']);
            exit;
        }

        $input = json_decode($rawInput, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        throw new Exception('Invalid request');
    }

    if (!is_array($input) || !isset($input['action']) || !is_string($input['action'])) {
        throw new Exception('Invalid request');
    }

    $sessionAuthVersion = $_SESSION['auth_version'] ?? null;
    $sessionTwoFactorVersion = $_SESSION['two_factor_version'] ?? null;
    if (!is_string($sessionAuthVersion) || !is_string($sessionTwoFactorVersion) ||
        preg_match('/^[a-f0-9]{64}$/D', $sessionAuthVersion) !== 1 ||
        preg_match('/^[a-f0-9]{64}$/D', $sessionTwoFactorVersion) !== 1) {
        http_response_code(401);
        throw new Exception('Invalid or expired session');
    }
    $db = new Database();
    $conn = $db->connect();
    $response = ['success' => false];

    switch ($input['action']) {
        case 'get_settings':
            $stmt = $conn->prepare("
    SELECT phone, two_factor_enabled, message_notifications, sound_notifications, 
           desktop_notifications, do_not_disturb, show_last_seen, read_receipts, 
           show_profile_photo, show_email, show_bio, show_phone, who_can_message, 
           theme, font_size, chat_background, auto_download 
    FROM users WHERE id = ?
");
            $stmt->bind_param("i", $currentUser['id']);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows === 1) {
                $settings = $result->fetch_assoc();

                // Convert boolean values
                $booleanFields = ['two_factor_enabled', 'message_notifications', 'sound_notifications',
                    'desktop_notifications', 'do_not_disturb', 'show_last_seen',
                    'read_receipts', 'show_profile_photo', 'show_email', 'show_bio',
                    'show_phone', 'auto_download'];

                foreach ($booleanFields as $field) {
                    $settings[$field] = (bool)$settings[$field];
                }

                $response = [
                    'success' => true,
                    'settings' => $settings
                ];
            } else {
                throw new Exception('User settings not found');
            }
            break;

        case 'update_settings':
            if (!isset($input['settings']) || !is_array($input['settings'])) {
                throw new Exception('Settings data is required');
            }

            $settings = $input['settings'];
            $updateFields = [];
            $params = [];
            $types = "";

            // Define allowed settings and their types
            $allowedSettings = [
                'phone' => 's',
                'message_notifications' => 'i',
                'sound_notifications' => 'i',
                'desktop_notifications' => 'i',
                'do_not_disturb' => 'i',
                'show_last_seen' => 'i',
                'read_receipts' => 'i',
                'show_profile_photo' => 'i',
                'show_email' => 'i',
                'show_bio' => 'i',
                'show_phone' => 'i',
                'who_can_message' => 's',
                'theme' => 's',
                'font_size' => 's',
                'chat_background' => 's',
                'auto_download' => 'i'
            ];

            foreach ($settings as $key => $value) {
                if (isset($allowedSettings[$key])) {
                    $updateFields[] = "$key = ?";

                    // Convert boolean to int for database
                    if ($allowedSettings[$key] === 'i') {
                        if (is_bool($value)) {
                            $value = $value ? 1 : 0;
                        } elseif ($value !== 0 && $value !== 1) {
                            throw new Exception('Invalid setting value');
                        }
                    } elseif (!is_string($value)) {
                        throw new Exception('Invalid setting value');
                    }

                    if ($key === 'phone') {
                        $value = trim($value);
                        if (strlen($value) > 20) {
                            throw new Exception('Phone number is too long');
                        }
                        if ($value !== '' && preg_match('/^\+?[0-9 ()-]{3,20}$/D', $value) !== 1) {
                            throw new Exception('Phone number is invalid');
                        }
                    } elseif ($key === 'who_can_message' &&
                        !in_array($value, ['everyone', 'contacts', 'nobody'], true)) {
                        throw new Exception('Invalid messaging privacy setting');
                    } elseif ($key === 'theme' && !in_array($value, ['dark', 'light'], true)) {
                        throw new Exception('Invalid theme setting');
                    } elseif ($key === 'font_size' &&
                        !in_array($value, ['small', 'medium', 'large', 'extra-large'], true)) {
                        throw new Exception('Invalid font size setting');
                    } elseif ($key === 'chat_background' &&
                        !in_array($value, ['default', 'gradient1', 'gradient2', 'solid'], true)) {
                        throw new Exception('Invalid chat background setting');
                    }

                    $params[] = $value;
                    $types .= $allowedSettings[$key];
                }
            }

            if (empty($updateFields)) {
                throw new Exception('No valid settings to update');
            }

            $params[] = $currentUser['id'];
            $types .= 'i';

            $sql = "UPDATE users SET " . implode(', ', $updateFields) . ", updated_at = NOW() WHERE id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param($types, ...$params);

            if ($stmt->execute()) {
                $response = [
                    'success' => true,
                    'message' => 'Settings updated successfully'
                ];
            } else {
                throw new Exception('Failed to update settings');
            }
            break;

        case 'change_password':
            if (!isset($input['current_password'], $input['new_password']) ||
                !is_string($input['current_password']) || !is_string($input['new_password'])) {
                throw new Exception('Current and new passwords are required');
            }

            if (strlen($input['current_password']) > 1024) {
                throw new Exception('Current password is incorrect');
            }

            // Validate new password
            if (strlen($input['new_password']) < 12 || strlen($input['new_password']) > 72 ||
                str_contains($input['new_password'], "\0")) {
                throw new Exception('New password must be between 12 and 72 characters');
            }
            if (hash_equals($input['current_password'], $input['new_password'])) {
                throw new Exception('New password must be different from current password');
            }

            $secondFactorCode = settingsSecondFactorCode($input);
            // A stolen session must not multiply credential guesses by moving
            // between IP addresses. Sensitive settings are throttled against
            // the stable authenticated account ID.
            $passwordRateIdentity = (string)(int)$currentUser['id'];
            $secondFactorIdentity = $passwordRateIdentity;
            if (!Auth::reserveRateLimitAttempt('account_password', $passwordRateIdentity, 5, 900)) {
                http_response_code(429);
                throw new Exception('Too many password attempts. Try again later.');
            }
            $passwordReserved = true;
            $secondFactorReserved = false;
            if ($secondFactorCode !== null &&
                !Auth::reserveRateLimitAttempt('account_second_factor', $secondFactorIdentity, 5, 900)) {
                Auth::releaseRateLimitAttempt('account_password', $passwordRateIdentity);
                $passwordReserved = false;
                http_response_code(429);
                throw new Exception('Too many 2FA attempts. Try again later.');
            }
            $secondFactorReserved = $secondFactorCode !== null;

            try {
                $newPasswordHash = password_hash($input['new_password'], PASSWORD_DEFAULT);
                if ($newPasswordHash === false) {
                    throw new Exception('Failed to change password');
                }

                require_once __DIR__ . '/../classes/TwoFactor.php';
                $twoFA = new TwoFactorAuthentication();
                $passwordChange = $twoFA->changePasswordWithCredentials(
                    (int)$currentUser['id'],
                    $input['current_password'],
                    $newPasswordHash,
                    $secondFactorCode,
                    $sessionAuthVersion,
                    $sessionTwoFactorVersion
                );

                if (!$passwordChange['success']) {
                    switch ($passwordChange['reason']) {
                        case 'password':
                            if ($secondFactorReserved) {
                                Auth::releaseRateLimitAttempt('account_second_factor', $secondFactorIdentity);
                                $secondFactorReserved = false;
                            }
                            $passwordReserved = false; // Retain the failed password attempt.
                            throw new Exception('Current password is incorrect');
                        case 'factor_required':
                            http_response_code(403);
                            throw new Exception('A fresh 2FA code or backup code is required');
                        case 'factor':
                            Auth::releaseRateLimitAttempt('account_password', $passwordRateIdentity);
                            $passwordReserved = false;
                            $secondFactorReserved = false; // Retain the failed factor attempt.
                            http_response_code(403);
                            throw new Exception('Invalid 2FA code or backup code');
                        case 'stale':
                            http_response_code(401);
                            throw new Exception('Authentication state changed. Please sign in again.');
                        default:
                            throw new Exception('Failed to change password');
                    }
                }

                Auth::clearRateLimit('account_password', $passwordRateIdentity);
                Auth::clearRateLimit('account_second_factor', $secondFactorIdentity);
                $passwordReserved = false;
                $secondFactorReserved = false;
                $sessionRefreshed = $auth->refreshSessionPasswordVersion(
                    (int)$currentUser['id'],
                    $sessionAuthVersion,
                    $sessionTwoFactorVersion,
                    (string)($passwordChange['auth_version'] ?? ''),
                    (string)($passwordChange['two_factor_version'] ?? '')
                );
                if ($sessionRefreshed) {
                    $_SESSION['sensitive_auth_at'] = time();
                }
                $response = [
                    'success' => true,
                    'message' => $sessionRefreshed
                        ? 'Password changed successfully'
                        : 'Password changed. Please sign in again.',
                    'reauthenticate' => !$sessionRefreshed
                ];
            } catch (Throwable $e) {
                if ($passwordReserved) {
                    Auth::releaseRateLimitAttempt('account_password', $passwordRateIdentity);
                }
                if ($secondFactorReserved) {
                    Auth::releaseRateLimitAttempt('account_second_factor', $secondFactorIdentity);
                }
                throw $e;
            }
            break;

        case 'update_profile':
            if (!isset($input['first_name'], $input['last_name'], $input['username']) ||
                !is_string($input['first_name']) || !is_string($input['last_name']) ||
                !is_string($input['username']) ||
                (isset($input['bio']) && !is_string($input['bio'])) ||
                (isset($input['phone']) && !is_string($input['phone']))) {
                throw new Exception('First name and last name are required');
            }

            $firstName = trim($input['first_name']);
            $lastName = trim($input['last_name']);
            $username = trim($input['username'] ?? '');
            $bio = trim($input['bio'] ?? '');
            $phone = trim($input['phone'] ?? '');

            // These values are rendered in several chat HTML templates. Keep
            // display names text-only to prevent persistent markup injection.
            if (preg_match('//u', $firstName . $lastName . $username . $bio . $phone) !== 1) {
                throw new Exception('Profile fields are invalid');
            }
            if ($firstName === '' || $lastName === '' || settingsTextLength($firstName) > 50 ||
                settingsTextLength($lastName) > 50 || preg_match('/[<>\x00-\x1F\x7F]/u', $firstName . $lastName)) {
                throw new Exception('First name and last name contain invalid characters');
            }
            if (settingsTextLength($username) < 3 || settingsTextLength($username) > 50 ||
                !preg_match('/^[\p{L}\p{N}_.-]+$/u', $username)) {
                throw new Exception('Username must be 3-50 letters, numbers, dots, dashes, or underscores');
            }
            if (settingsTextLength($bio) > 1000 || strlen($phone) > 20) {
                throw new Exception('Profile data is too long');
            }
            if ($phone !== '' && preg_match('/^\+?[0-9 ()-]{3,20}$/D', $phone) !== 1) {
                throw new Exception('Phone number is invalid');
            }

            // Check if username is taken (if changed)
            if (!empty($username) && $username !== $currentUser['username']) {
                $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
                $stmt->bind_param("si", $username, $currentUser['id']);
                $stmt->execute();
                if ($stmt->get_result()->num_rows > 0) {
                    throw new Exception('Username is already taken');
                }
            }

            $stmt = $conn->prepare("
                UPDATE users 
                SET first_name = ?, last_name = ?, username = ?, bio = ?, phone = ?, updated_at = NOW() 
                WHERE id = ?
            ");
            $stmt->bind_param("sssssi", $firstName, $lastName, $username, $bio, $phone, $currentUser['id']);

            if ($stmt->execute()) {
                // Get updated user data
                $stmt = $conn->prepare("
                    SELECT id, username, email, first_name, last_name, avatar, bio, phone 
                    FROM users WHERE id = ?
                ");
                $stmt->bind_param("i", $currentUser['id']);
                $stmt->execute();
                $result = $stmt->get_result();
                $updatedUser = $result->fetch_assoc();

                $response = [
                    'success' => true,
                    'message' => 'Profile updated successfully',
                    'user' => $updatedUser
                ];
            } else {
                throw new Exception('Failed to update profile');
            }
            break;

        case 'clear_cache':
            // Simulate cache clearing
            $response = [
                'success' => true,
                'message' => 'Cache cleared successfully'
            ];
            break;

        case 'get_storage_usage':
            // Calculate storage usage
            $stmt = $conn->prepare("
                SELECT 
                    COUNT(*) as message_count,
                    COALESCE(SUM(CASE WHEN m.file_size IS NOT NULL THEN m.file_size ELSE 0 END), 0) as total_file_size
                FROM messages m
                INNER JOIN chat_participants cp
                    ON cp.chat_id = m.chat_id
                   AND cp.user_id = ?
                   AND cp.left_at IS NULL
                WHERE m.is_deleted = FALSE
            ");
            $stmt->bind_param("i", $currentUser['id']);
            $stmt->execute();
            $result = $stmt->get_result();
            $usage = $result->fetch_assoc();
            $messageCount = max(0, (int)($usage['message_count'] ?? 0));
            $messageBytes = max(0, (int)round($messageCount * 0.001 * 1024 * 1024));
            $mediaBytes = max(0, (int)($usage['total_file_size'] ?? 0));
            $documentBytes = 0;
            $totalBytes = $messageBytes + $mediaBytes + $documentBytes;

            $response = [
                'success' => true,
                'storage' => [
                    // Raw values are authoritative so clients can format
                    // numbers and units in the active locale.
                    'messages_bytes' => $messageBytes,
                    'media_bytes' => $mediaBytes,
                    'documents_bytes' => $documentBytes,
                    'total_bytes' => $totalBytes,
                    // Keep the original fields during the client transition.
                    'messages' => round($messageCount * 0.001, 2) . ' MB',
                    'media' => round($mediaBytes / 1024 / 1024, 2) . ' MB',
                    'documents' => '0 MB',
                    'total' => round($totalBytes / 1024 / 1024, 2) . ' MB'
                ]
            ];
            break;

        case 'setup_2fa':
            if (!isset($input['current_password']) || !is_string($input['current_password']) ||
                $input['current_password'] === '') {
                http_response_code(403);
                $response = ['success' => false, 'message' => 'Current password is required'];
                break;
            }

            $setupPasswordIdentity = (string)$currentUser['id'];
            if (strlen($input['current_password']) > 1024) {
                http_response_code(429);
                $response = ['success' => false, 'message' => 'Too many password attempts. Try again later.'];
                break;
            }
            if (!Auth::reserveRateLimitAttempt('account_password', $setupPasswordIdentity, 5, 900)) {
                http_response_code(429);
                $response = ['success' => false, 'message' => 'Too many password attempts. Try again later.'];
                break;
            }
            try {
                $stmt = $conn->prepare("SELECT password_hash FROM users WHERE id = ?");
                $stmt->bind_param("i", $currentUser['id']);
                $stmt->execute();
                $passwordRow = $stmt->get_result()->fetch_assoc();
                $passwordMatches = $passwordRow &&
                    password_verify($input['current_password'], $passwordRow['password_hash']);
            } catch (Throwable $e) {
                Auth::releaseRateLimitAttempt('account_password', $setupPasswordIdentity);
                throw $e;
            }
            if (!$passwordMatches) {
                http_response_code(403);
                $response = ['success' => false, 'message' => 'Current password is incorrect'];
                break;
            }
            Auth::clearRateLimit('account_password', $setupPasswordIdentity);

            require_once __DIR__ . '/../classes/TwoFactor.php';

            try {
                $twoFA = new TwoFactorAuthentication();
                $existingTwoFactor = $twoFA->getUserFactorState((int)$currentUser['id']);
                if ($existingTwoFactor && $existingTwoFactor['two_factor_enabled']) {
                    throw new Exception('2FA is already enabled. Disable it before replacing the authenticator.');
                }

                $setupRateIdentity = (string)(int)$currentUser['id'];
                if (!Auth::reserveRateLimitAttempt('setup_2fa', $setupRateIdentity, 5, 600)) {
                    http_response_code(429);
                    throw new Exception('Too many 2FA setup attempts. Try again later.');
                }

                $secret = $twoFA->generateSecret();
                $label = $currentUser['email']; // or $currentUser['username']
                $_SESSION['pending_2fa_secret'] = $secret;
                $_SESSION['pending_2fa_started_at'] = time();
                $_SESSION['pending_2fa_attempts'] = 0;
                $_SESSION['pending_2fa_auth_version'] = $sessionAuthVersion;
                $_SESSION['pending_2fa_factor_version'] = $sessionTwoFactorVersion;

                // Generate QR code
                $qrCode = $twoFA->generateQRCode($label, $secret);
                $manualKey = $twoFA->getManualEntryKey($secret);

                $response = [
                    'success' => true,
                    'secret' => $secret,
                    'manual_entry_key' => trim($manualKey),
                    'qr_code' => $qrCode,
                    'qr_available' => ($qrCode !== null),
                    'issuer' => 'Messenger',
                    'account' => $label,
                    'qr_text' => $twoFA->getQRText($label, $secret)
                ];
            } catch (Exception $e) {
                error_log("2FA Setup Error: " . $e->getMessage());
                throw new Exception($e->getMessage() === '2FA is already enabled. Disable it before replacing the authenticator.'
                    ? $e->getMessage()
                    : 'Failed to setup 2FA');
            }
            break;

        case 'verify_2fa_setup':
            if (!isset($input['secret'], $input['code']) ||
                !is_string($input['secret']) || !is_string($input['code'])) {
                throw new Exception('Secret and verification code are required');
            }

            require_once __DIR__ . '/../classes/TwoFactor.php';

            $setupVerifyIdentity = '';
            $setupVerifyReserved = false;
            try {
                $twoFA = new TwoFactorAuthentication();
                $code = trim($input['code']);

                if (!isset(
                    $_SESSION['pending_2fa_secret'],
                    $_SESSION['pending_2fa_started_at'],
                    $_SESSION['pending_2fa_auth_version'],
                    $_SESSION['pending_2fa_factor_version']
                ) ||
                    !is_string($_SESSION['pending_2fa_secret']) ||
                    !is_string($_SESSION['pending_2fa_auth_version']) ||
                    !is_string($_SESSION['pending_2fa_factor_version']) ||
                    time() - (int)$_SESSION['pending_2fa_started_at'] > 600 ||
                    !hash_equals($_SESSION['pending_2fa_secret'], trim($input['secret'])) ||
                    !hash_equals($_SESSION['pending_2fa_auth_version'], $sessionAuthVersion) ||
                    !hash_equals($_SESSION['pending_2fa_factor_version'], $sessionTwoFactorVersion)) {
                    settingsClearPendingTwoFactorEnrollment();
                    http_response_code(400);
                    throw new Exception('2FA setup expired. Start again.');
                }

                if (!preg_match('/^\d{6}$/', $code)) {
                    throw new Exception('Invalid verification code');
                }

                $setupVerifyIdentity = (string)(int)$currentUser['id'];
                if ((int)($_SESSION['pending_2fa_attempts'] ?? 0) >= 5) {
                    settingsClearPendingTwoFactorEnrollment();
                    http_response_code(429);
                    throw new Exception('Too many verification attempts. Start 2FA setup again later.');
                }
                if (!Auth::reserveRateLimitAttempt('verify_2fa_setup', $setupVerifyIdentity, 10, 900)) {
                    settingsClearPendingTwoFactorEnrollment();
                    http_response_code(429);
                    throw new Exception('Too many verification attempts. Start 2FA setup again later.');
                }
                $setupVerifyReserved = true;

                $existingTwoFactor = $twoFA->getUserFactorState((int)$currentUser['id']);
                if ($existingTwoFactor && $existingTwoFactor['two_factor_enabled']) {
                    settingsClearPendingTwoFactorEnrollment();
                    throw new Exception('2FA is already enabled. Disable it before replacing the authenticator.');
                }

                $verifiedTimeStep = $twoFA->verifiedTimeStep($_SESSION['pending_2fa_secret'], $code);

                if ($verifiedTimeStep !== null) {
                    // Enabling the secret, recording the setup TOTP step, and
                    // creating recovery codes is one database transaction.
                    $enrollmentResult = $twoFA->enable2FAWithBackupCodes(
                        (int)$currentUser['id'],
                        $_SESSION['pending_2fa_secret'],
                        $verifiedTimeStep,
                        $_SESSION['pending_2fa_auth_version'],
                        $_SESSION['pending_2fa_factor_version']
                    );

                    if (!$enrollmentResult['success']) {
                        if ($enrollmentResult['reason'] === 'stale') {
                            settingsClearPendingTwoFactorEnrollment();
                            http_response_code(401);
                            throw new Exception('Authentication state changed. Please sign in again.');
                        }
                        if ($enrollmentResult['reason'] === 'already_enabled') {
                            settingsClearPendingTwoFactorEnrollment();
                            throw new Exception('2FA is already enabled. Disable it before replacing the authenticator.');
                        }
                        throw new Exception('Failed to enable 2FA');
                    }

                    $sessionRefreshed = $auth->refreshSessionTwoFactorVersion(
                        (int)$currentUser['id'],
                        $sessionAuthVersion,
                        $sessionTwoFactorVersion,
                        (string)($enrollmentResult['auth_version'] ?? ''),
                        (string)($enrollmentResult['two_factor_version'] ?? '')
                    );
                    settingsClearPendingTwoFactorEnrollment();
                    Auth::clearRateLimit('verify_2fa_setup', $setupVerifyIdentity);
                    $setupVerifyReserved = false;
                    $response = [
                        'success' => true,
                        'message' => $sessionRefreshed
                            ? '2FA enabled successfully'
                            : '2FA enabled. Please sign in again.',
                        'backup_codes' => $enrollmentResult['codes'],
                        'reauthenticate' => !$sessionRefreshed
                    ];
                } else {
                    $_SESSION['pending_2fa_attempts'] = (int)($_SESSION['pending_2fa_attempts'] ?? 0) + 1;
                    $setupVerifyReserved = false; // Retain the failed factor attempt.
                    $response = [
                        'success' => false,
                        'message' => 'Invalid verification code. Please try again.'
                    ];
                }
            } catch (Throwable $e) {
                if ($setupVerifyReserved) {
                    Auth::releaseRateLimitAttempt('verify_2fa_setup', $setupVerifyIdentity);
                }
                error_log("2FA Verification Error: " . $e->getMessage());
                $response = [
                    'success' => false,
                    'message' => in_array($e->getMessage(), [
                        '2FA setup expired. Start again.',
                        'Too many verification attempts. Start 2FA setup again later.',
                        'Invalid verification code',
                        '2FA is already enabled. Disable it before replacing the authenticator.',
                        'Authentication state changed. Please sign in again.'
                    ], true) ? $e->getMessage() : 'Verification failed'
                ];
            }
            break;

        case 'enroll_device':
        case 'revoke_device':
            // Enrolling a device adds a key that can read future messages in
            // every protected conversation this account joins, and revoking one
            // takes that away. Both are account security changes, so both
            // demand the current password AND a fresh second factor -- the same
            // bar as disabling two-factor authentication.
            require_once __DIR__ . '/../classes/ProtectedChat.php';
            require_once __DIR__ . '/../classes/DeviceDirectory.php';

            if (!ProtectedChat::isEnabled()) {
                $response = ['success' => false, 'message' => 'Settings request failed'];
                http_response_code(503);
                break;
            }

            $deviceCode = settingsSecondFactorCode($input);
            if (!isset($input['current_password']) || !is_string($input['current_password']) ||
                $input['current_password'] === '' || $deviceCode === null) {
                http_response_code(403);
                throw new Exception('Current password and a fresh 2FA code are required');
            }
            if (strlen($input['current_password']) > 1024) {
                http_response_code(429);
                throw new Exception('Too many password attempts. Try again later.');
            }

            require_once __DIR__ . '/../classes/TwoFactor.php';
            $deviceIdentity = (string)(int)$currentUser['id'];
            if (!Auth::reserveRateLimitAttempt('account_password', $deviceIdentity, 5, 900)) {
                http_response_code(429);
                throw new Exception('Too many password attempts. Try again later.');
            }
            if (!Auth::reserveRateLimitAttempt('device_enrollment', $deviceIdentity, 10, 900)) {
                Auth::releaseRateLimitAttempt('account_password', $deviceIdentity);
                http_response_code(429);
                throw new Exception('Too many verification attempts. Try again later.');
            }

            $storedHash = null;
            $hashStatement = $conn->prepare('SELECT password_hash FROM users WHERE id = ?');
            $hashStatement->bind_param('i', $currentUser['id']);
            $hashStatement->execute();
            $hashRow = $hashStatement->get_result()->fetch_assoc();
            $hashStatement->close();
            $storedHash = is_array($hashRow) ? (string)$hashRow['password_hash'] : null;

            if ($storedHash === null || !password_verify($input['current_password'], $storedHash)) {
                Auth::releaseRateLimitAttempt('device_enrollment', $deviceIdentity);
                http_response_code(403);
                throw new Exception('Current password is incorrect');
            }

            // Binds the factor to the session's authentication versions, so a
            // credential change mid-flow cannot consume a code for a stale one.
            $deviceFactor = (new TwoFactorAuthentication())->verifyAndConsumeSecondFactorForAuthenticationState(
                (int)$currentUser['id'],
                $deviceCode,
                $sessionAuthVersion,
                $sessionTwoFactorVersion
            );
            if (!$deviceFactor['success']) {
                if ($deviceFactor['reason'] === 'stale') {
                    http_response_code(401);
                    throw new Exception('Authentication state changed. Please sign in again.');
                }
                http_response_code(403);
                throw new Exception('Invalid verification code or backup code');
            }

            // The factor is spent from here on. A failure below costs the user
            // one code; it cannot be replayed, so this is a usability cost
            // rather than a security one.
            Auth::clearRateLimit('account_password', $deviceIdentity);
            Auth::clearRateLimit('device_enrollment', $deviceIdentity);

            try {
                $directory = new DeviceDirectory($conn);
                if ($input['action'] === 'enroll_device') {
                    $response = ['success' => true] + $directory->enrollDevice(
                        (int)$currentUser['id'],
                        (string)($input['public_id'] ?? ''),
                        (string)($input['signature_public_key'] ?? ''),
                        (string)($input['credential'] ?? ''),
                        (int)($input['cipher_suite'] ?? 0),
                        isset($input['label']) && is_string($input['label']) ? $input['label'] : null,
                        is_array($input['key_packages'] ?? null) ? $input['key_packages'] : []
                    );
                } else {
                    $response = ['success' => true] + $directory->revokeDevice(
                        (int)$currentUser['id'],
                        (int)($input['device_id'] ?? 0)
                    );
                }
            } catch (ProtectedChatMismatch $mismatch) {
                http_response_code(409);
                $response = [
                    'success' => false,
                    'message' => 'Settings request failed',
                    'error_code' => $mismatch->errorCode(),
                ];
            }
            break;

        case 'disable_2fa':
            $code = settingsSecondFactorCode($input);
            if (!isset($input['current_password']) || !is_string($input['current_password']) ||
                $input['current_password'] === '' || $code === null) {
                http_response_code(403);
                throw new Exception('Current password and a fresh 2FA code are required');
            }

            require_once __DIR__ . '/../classes/TwoFactor.php';

            $passwordRateIdentity = (string)(int)$currentUser['id'];
            $disableRateIdentity = $passwordRateIdentity;
            $passwordReserved = false;
            $disableFactorReserved = false;
            try {
                if (strlen($input['current_password']) > 1024) {
                    http_response_code(429);
                    throw new Exception('Too many password attempts. Try again later.');
                }

                if (!preg_match('/^(?:\d{6}|[A-F0-9]{8})$/', $code)) {
                    throw new Exception('Invalid verification code or backup code');
                }

                if (!Auth::reserveRateLimitAttempt('account_password', $passwordRateIdentity, 5, 900)) {
                    http_response_code(429);
                    throw new Exception('Too many password attempts. Try again later.');
                }
                $passwordReserved = true;
                if (!Auth::reserveRateLimitAttempt('account_second_factor', $disableRateIdentity, 5, 900)) {
                    Auth::releaseRateLimitAttempt('account_password', $passwordRateIdentity);
                    $passwordReserved = false;
                    http_response_code(429);
                    throw new Exception('Too many verification attempts. Try again later.');
                }
                $disableFactorReserved = true;

                $twoFA = new TwoFactorAuthentication();
                $disableResult = $twoFA->disable2FAWithCredentials(
                    (int)$currentUser['id'],
                    $input['current_password'],
                    $code,
                    $sessionAuthVersion,
                    $sessionTwoFactorVersion
                );

                if (!$disableResult['success']) {
                    switch ($disableResult['reason']) {
                        case 'password':
                            Auth::releaseRateLimitAttempt('account_second_factor', $disableRateIdentity);
                            $disableFactorReserved = false;
                            $passwordReserved = false; // Retain the failed password attempt.
                            http_response_code(403);
                            throw new Exception('Current password is incorrect');
                        case 'not_enabled':
                            throw new Exception('2FA is not enabled for this account');
                        case 'factor_required':
                            http_response_code(403);
                            throw new Exception('Current password and a fresh 2FA code are required');
                        case 'factor':
                            Auth::releaseRateLimitAttempt('account_password', $passwordRateIdentity);
                            $passwordReserved = false;
                            $disableFactorReserved = false; // Retain the failed factor attempt.
                            http_response_code(403);
                            throw new Exception('Invalid verification code or backup code');
                        case 'stale':
                            http_response_code(401);
                            throw new Exception('Authentication state changed. Please sign in again.');
                        default:
                            throw new Exception('Failed to disable 2FA');
                    }
                }

                Auth::clearRateLimit('account_password', $passwordRateIdentity);
                Auth::clearRateLimit('account_second_factor', $disableRateIdentity);
                $passwordReserved = false;
                $disableFactorReserved = false;
                $sessionRefreshed = $auth->refreshSessionTwoFactorVersion(
                    (int)$currentUser['id'],
                    $sessionAuthVersion,
                    $sessionTwoFactorVersion,
                    (string)($disableResult['auth_version'] ?? ''),
                    (string)($disableResult['two_factor_version'] ?? '')
                );
                if ($sessionRefreshed) {
                    $_SESSION['sensitive_auth_at'] = time();
                }
                $response = [
                    'success' => true,
                    'message' => $sessionRefreshed
                        ? '2FA disabled successfully'
                        : '2FA disabled. Please sign in again.',
                    'reauthenticate' => !$sessionRefreshed
                ];
            } catch (Throwable $e) {
                if ($passwordReserved) {
                    Auth::releaseRateLimitAttempt('account_password', $passwordRateIdentity);
                }
                if ($disableFactorReserved) {
                    Auth::releaseRateLimitAttempt('account_second_factor', $disableRateIdentity);
                }
                error_log("2FA Disable Error: " . $e->getMessage());
                $response = [
                    'success' => false,
                    'message' => in_array($e->getMessage(), [
                        '2FA is not enabled for this account',
                        'Current password and a fresh 2FA code are required',
                        'Current password is incorrect',
                        'Too many password attempts. Try again later.',
                        'Invalid verification code or backup code',
                        'Too many verification attempts. Try again later.',
                        'Authentication state changed. Please sign in again.'
                    ], true) ? $e->getMessage() : 'Failed to disable 2FA'
                ];
            }
            break;

        case 'get_backup_codes':
            require_once __DIR__ . '/../classes/TwoFactor.php';

            // Recovery codes are equivalent to a second factor. Do not rotate
            // or reveal them using only an ambient browser session.
            if (!isset($input['current_password']) || !is_string($input['current_password']) ||
                $input['current_password'] === '') {
                http_response_code(403);
                $response = ['success' => false, 'message' => 'Current password is required'];
                break;
            }

            $backupRateIdentity = (string)(int)$currentUser['id'];
            if (strlen($input['current_password']) > 1024) {
                http_response_code(429);
                $response = ['success' => false, 'message' => 'Too many password attempts. Try again later.'];
                break;
            }

            $backupFactorIdentity = $backupRateIdentity;
            $backupPasswordReserved = false;
            $backupFactorReserved = false;
            try {
                $code = settingsSecondFactorCode($input);
                if ($code === null) {
                    http_response_code(403);
                    throw new Exception('A fresh 2FA code or backup code is required');
                }
                if (!preg_match('/^(?:\d{6}|[A-F0-9]{8})$/', $code)) {
                    http_response_code(403);
                    throw new Exception('Invalid 2FA code or backup code');
                }

                if (!Auth::reserveRateLimitAttempt('account_password', $backupRateIdentity, 5, 900)) {
                    http_response_code(429);
                    throw new Exception('Too many password attempts. Try again later.');
                }
                $backupPasswordReserved = true;
                if (!Auth::reserveRateLimitAttempt('account_second_factor', $backupFactorIdentity, 5, 900)) {
                    Auth::releaseRateLimitAttempt('account_password', $backupRateIdentity);
                    $backupPasswordReserved = false;
                    http_response_code(429);
                    throw new Exception('Too many 2FA attempts. Try again later.');
                }
                $backupFactorReserved = true;

                $twoFA = new TwoFactorAuthentication();
                $rotationResult = $twoFA->rotateBackupCodesWithCredentials(
                    (int)$currentUser['id'],
                    $input['current_password'],
                    $code,
                    $sessionAuthVersion,
                    $sessionTwoFactorVersion
                );
                if (!$rotationResult['success']) {
                    switch ($rotationResult['reason']) {
                        case 'password':
                            Auth::releaseRateLimitAttempt('account_second_factor', $backupFactorIdentity);
                            $backupFactorReserved = false;
                            $backupPasswordReserved = false; // Retain the failed password attempt.
                            http_response_code(403);
                            throw new Exception('Current password is incorrect');
                        case 'not_enabled':
                            throw new Exception('2FA is not enabled for this account');
                        case 'factor_required':
                            http_response_code(403);
                            throw new Exception('A fresh 2FA code or backup code is required');
                        case 'factor':
                            Auth::releaseRateLimitAttempt('account_password', $backupRateIdentity);
                            $backupPasswordReserved = false;
                            $backupFactorReserved = false; // Retain the failed factor attempt.
                            http_response_code(403);
                            throw new Exception('Invalid 2FA code or backup code');
                        case 'stale':
                            http_response_code(401);
                            throw new Exception('Authentication state changed. Please sign in again.');
                        default:
                            throw new Exception('Failed to generate backup codes');
                    }
                }

                Auth::clearRateLimit('account_password', $backupRateIdentity);
                Auth::clearRateLimit('account_second_factor', $backupFactorIdentity);
                $backupPasswordReserved = false;
                $backupFactorReserved = false;
                $_SESSION['sensitive_auth_at'] = time();
                $response = [
                    'success' => true,
                    'backup_codes' => $rotationResult['codes'],
                    'message' => 'New backup codes generated successfully'
                ];
            } catch (Throwable $e) {
                if ($backupPasswordReserved) {
                    Auth::releaseRateLimitAttempt('account_password', $backupRateIdentity);
                }
                if ($backupFactorReserved) {
                    Auth::releaseRateLimitAttempt('account_second_factor', $backupFactorIdentity);
                }
                error_log("Backup Codes Error: " . $e->getMessage());
                $response = [
                    'success' => false,
                    'message' => in_array($e->getMessage(), [
                        '2FA is not enabled for this account',
                        'Current password is incorrect',
                        'A fresh 2FA code or backup code is required',
                        'Invalid 2FA code or backup code',
                        'Too many password attempts. Try again later.',
                        'Too many 2FA attempts. Try again later.',
                        'Authentication state changed. Please sign in again.'
                    ], true) ? $e->getMessage() : 'Failed to generate backup codes'
                ];
            }
            break;

        default:
            throw new Exception('Invalid action');
    }

} catch (Throwable $e) {
    error_log('Settings API Error: ' . $e->getMessage());
    $safeMessages = [
        'Invalid request',
        'Invalid or expired session',
        'User settings not found',
        'Settings data is required',
        'Invalid setting value',
        'Phone number is too long',
        'Phone number is invalid',
        'Invalid messaging privacy setting',
        'Invalid theme setting',
        'Invalid font size setting',
        'Invalid chat background setting',
        'No valid settings to update',
        'Failed to update settings',
        'Current and new passwords are required',
        'Current password is incorrect',
        'Too many password attempts. Try again later.',
        'New password must be between 12 and 72 characters',
        'New password must be different from current password',
        'A fresh 2FA code or backup code is required',
        'Invalid 2FA code or backup code',
        'Too many 2FA attempts. Try again later.',
        'Current password and a fresh 2FA code are required',
        'Authentication state changed. Please sign in again.',
        'Failed to change password',
        'First name and last name are required',
        'Profile fields are invalid',
        'First name and last name contain invalid characters',
        'Username must be 3-50 letters, numbers, dots, dashes, or underscores',
        'Profile data is too long',
        'Username is already taken',
        'Failed to update profile',
        'Secret and verification code are required',
        'Verification code is required',
        'Invalid action'
    ];
    $response = [
        'success' => false,
        'message' => in_array($e->getMessage(), $safeMessages, true)
            ? $e->getMessage()
            : 'Settings request failed'
    ];
}

echo I18n::encodeResponse($response);
?>
