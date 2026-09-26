<?php
// api/auth.php

require_once __DIR__ . '/../classes/Auth.php';
require_once __DIR__ . '/../classes/I18n.php';
require_once __DIR__ . '/../config/database.php';

Auth::configureSession();
Auth::setPrivateResponseHeaders();
I18n::applyResponseHeaders();
header('Content-Type: application/json; charset=utf-8');

const AUTH_API_MAX_JSON_BYTES = 32768;
// Authenticated status updates normally run once every 30 seconds per tab.
// Keep substantial multi-tab/NAT headroom while bounding database-backed
// session validation across arbitrarily many sessions for the same account.
const AUTH_SESSION_ACTION_RATE_WINDOW_SECONDS = 60;
const AUTH_SESSION_ACTION_USER_REQUEST_LIMIT = 240;
const AUTH_SESSION_ACTION_IP_REQUEST_LIMIT = 2400;
// Pending 2FA is an interactive, short-lived flow and needs far less traffic.
const AUTH_PENDING_ACTION_USER_REQUEST_LIMIT = 60;
const AUTH_PENDING_ACTION_IP_REQUEST_LIMIT = 600;

class AuthApiException extends RuntimeException {
    public int $statusCode;
    public ?string $errorCode;

    public function __construct(
        string $message,
        int $statusCode = 400,
        ?string $errorCode = null
    ) {
        parent::__construct($message);
        $this->statusCode = $statusCode;
        $this->errorCode = $errorCode;
    }
}

function authApiRespond(array $response, int $status = 200): never {
    http_response_code($status);
    echo I18n::encodeResponse($response, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function authApiStringLength(string $value): int {
    return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
}

function authApiRemoteIdentity(): string {
    $remoteAddress = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    $packedAddress = $remoteAddress !== '' ? @inet_pton($remoteAddress) : false;

    return $packedAddress === false ? 'unknown' : bin2hex($packedAddress);
}

/** Accept only a canonical, non-overflowing positive integer session value. */
function authApiCanonicalSessionUserId($value): ?int {
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
 * Use the authenticated account for normal session actions and the account
 * already bound into the temporary session for pending 2FA actions.
 */
function authApiSessionActionUserId(string $action): ?int {
    $pendingAction = in_array($action, ['verify_2fa_login', 'complete_2fa_login'], true);
    $field = $pendingAction ? 'temp_user_id' : 'user_id';
    return authApiCanonicalSessionUserId($_SESSION[$field] ?? null);
}

/** Reserve a fixed-cardinality IP slot before the stable account slot. */
function reserveAuthApiSessionActionBudget(string $action, int $userId): bool {
    $pendingAction = in_array($action, ['verify_2fa_login', 'complete_2fa_login'], true);
    $scopePrefix = $pendingAction ? 'auth_pending_action' : 'auth_session_action';
    $userLimit = $pendingAction
        ? AUTH_PENDING_ACTION_USER_REQUEST_LIMIT
        : AUTH_SESSION_ACTION_USER_REQUEST_LIMIT;
    $ipLimit = $pendingAction
        ? AUTH_PENDING_ACTION_IP_REQUEST_LIMIT
        : AUTH_SESSION_ACTION_IP_REQUEST_LIMIT;
    $remoteIdentity = authApiRemoteIdentity();

    if (!Auth::reserveRateLimitAttempt(
        $scopePrefix . '_ip',
        $remoteIdentity,
        $ipLimit,
        AUTH_SESSION_ACTION_RATE_WINDOW_SECONDS
    )) {
        return false;
    }
    if (!Auth::reserveRateLimitAttempt(
        $scopePrefix . '_user',
        (string)$userId,
        $userLimit,
        AUTH_SESSION_ACTION_RATE_WINDOW_SECONDS
    )) {
        Auth::releaseRateLimitAttempt($scopePrefix . '_ip', $remoteIdentity);
        return false;
    }
    return true;
}

function rejectAuthApiSessionActionRateLimit(): never {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    header('Retry-After: ' . AUTH_SESSION_ACTION_RATE_WINDOW_SECONDS);
    authApiRespond(
        ['success' => false, 'message' => 'Too many requests. Try again shortly.'],
        429
    );
}

function clearPendingTwoFactorLogin(): void {
    unset(
        $_SESSION['temp_user_id'],
        $_SESSION['temp_login_time'],
        $_SESSION['temp_2fa_verified'],
        $_SESSION['temp_2fa_verified_at'],
        $_SESSION['temp_2fa_attempts'],
        $_SESSION['temp_auth_version'],
        $_SESSION['temp_2fa_version']
    );
}

/**
 * Failed public login attempts must not leave attacker-created session files
 * behind. Preserve a session that was already authenticated when the attempt
 * began, but destroy every transient login session and expire its cookie.
 */
function discardTransientLoginSession(bool $preserveExistingAuthenticatedSession): void {
    if ($preserveExistingAuthenticatedSession &&
        isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
        return;
    }
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return;
    }

    $_SESSION = [];
    $sessionName = session_name();
    setcookie($sessionName, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'domain' => '',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    session_destroy();
    unset($_COOKIE[$sessionName]);
}

$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$origin = trim((string)($_SERVER['HTTP_ORIGIN'] ?? ''));

if ($method === 'OPTIONS') {
    if (!Auth::isSameOriginRequest()) {
        authApiRespond(['success' => false, 'message' => 'Cross-origin request denied'], 403);
    }
    if ($origin !== '') {
        header('Access-Control-Allow-Origin: ' . SITE_URL);
        header('Access-Control-Allow-Credentials: true');
    }
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    authApiRespond(['success' => true], 204);
}

if ($method !== 'POST') {
    header('Allow: POST, OPTIONS');
    authApiRespond(['success' => false, 'message' => 'Method not allowed'], 405);
}

if (!Auth::isSameOriginRequest()) {
    authApiRespond(['success' => false, 'message' => 'Cross-origin request denied'], 403);
}

$contentType = strtolower(trim(explode(';', (string)($_SERVER['CONTENT_TYPE'] ?? ''))[0]));
if ($contentType !== 'application/json') {
    authApiRespond(['success' => false, 'message' => 'Content-Type must be application/json'], 415);
}

if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > AUTH_API_MAX_JSON_BYTES) {
    authApiRespond(['success' => false, 'message' => 'Request is too large'], 413);
}

// Initialize response
$response = ['success' => false];

try {
    try {
        // Always cap the actual bytes read. Content-Length may be absent or
        // untrusted (for example, with a chunked request body).
        $rawInput = file_get_contents(
            'php://input',
            false,
            null,
            0,
            AUTH_API_MAX_JSON_BYTES + 1
        );
        if ($rawInput === false) {
            throw new Exception('Invalid request format');
        }
        if (strlen($rawInput) > AUTH_API_MAX_JSON_BYTES) {
            authApiRespond(['success' => false, 'message' => 'Request is too large'], 413);
        }

        $input = json_decode($rawInput, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        throw new Exception('Invalid request format');
    }

    if (!is_array($input) || !isset($input['action']) || !is_string($input['action'])) {
        throw new Exception('Invalid request format');
    }

    // Presence cleanup is an internal maintenance operation and must never be
    // triggerable through the public authentication API.
    if ($input['action'] === 'cleanup_offline_users') {
        authApiRespond(['success' => false, 'message' => 'Action not available'], 403);
    }

    $sessionActions = [
        'logout',
        'validate',
        'update_status',
        'verify_2fa_login',
        'complete_2fa_login'
    ];
    if (!in_array($input['action'], array_merge(['register', 'login'], $sessionActions), true)) {
        throw new Exception('Invalid action');
    }
    if (in_array($input['action'], $sessionActions, true)) {
        if (!Auth::startExistingSession()) {
            throw new AuthApiException('Authentication required', 401);
        }
        $sessionRateUserId = authApiSessionActionUserId($input['action']);
        if ($sessionRateUserId === null) {
            session_write_close();
            throw new AuthApiException('Authentication required', 401);
        }
        if (!reserveAuthApiSessionActionBudget($input['action'], $sessionRateUserId)) {
            rejectAuthApiSessionActionRateLimit();
        }
    }

    $auth = null;
    $getAuth = static function () use (&$auth): Auth {
        if (!$auth instanceof Auth) {
            $auth = new Auth();
        }
        return $auth;
    };

    switch ($input['action']) {
        case 'register':
            foreach (['username', 'email', 'password', 'first_name', 'last_name'] as $field) {
                if (!isset($input[$field]) || !is_string($input[$field])) {
                    throw new Exception('Missing required fields');
                }
            }

            $remoteAddress = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
            if (!Auth::reserveRateLimitAttempt('register_ip', $remoteAddress, 5, 3600)) {
                throw new Exception('Too many registration attempts. Try again later.');
            }

            // Enhanced validation
            $username = trim($input['username']);
            $email = strtolower(trim($input['email']));
            $password = $input['password'];
            $first_name = trim($input['first_name']);
            $last_name = trim($input['last_name']);

            if (authApiStringLength($username) < 3 || authApiStringLength($username) > 50 ||
                !preg_match('/^[\p{L}\p{N}_.-]+$/u', $username)) {
                throw new Exception('Username must be 3-50 letters, numbers, dots, dashes, or underscores');
            }

            if (strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
                throw new Exception('Password must be between 12 and 72 characters');
            }

            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
                throw new Exception('Invalid email address');
            }

            if (preg_match('//u', $first_name . $last_name) !== 1 ||
                authApiStringLength($first_name) < 1 || authApiStringLength($first_name) > 50 ||
                authApiStringLength($last_name) < 1 || authApiStringLength($last_name) > 50 ||
                preg_match('/[<>\x00-\x1F\x7F]/u', $first_name . $last_name)) {
                throw new Exception('First name and last name contain invalid characters');
            }

            $response = $getAuth()->register($username, $email, $password, $first_name, $last_name);
            break;

        case 'login':
            if (!isset($input['username'], $input['password']) ||
                !is_string($input['username']) || !is_string($input['password'])) {
                throw new Exception('Username and password are required');
            }

            $username = trim($input['username']);
            $password = $input['password'];

            if (empty($username) || empty($password)) {
                throw new Exception('Username and password cannot be empty');
            }

            if (strlen($username) > 100 || strlen($password) > 1024) {
                throw new Exception('Invalid credentials');
            }

            $remoteAddress = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
            $normalizedLoginIdentifier = function_exists('mb_strtolower')
                ? mb_strtolower($username, 'UTF-8')
                : strtolower($username);
            $loginIdentity = $remoteAddress . '|' . $normalizedLoginIdentifier;
            // Admit the fixed-cardinality IP bucket first. Once it is full,
            // attacker-controlled usernames cannot churn additional APCu keys.
            if (!Auth::reserveRateLimitAttempt('login_ip', $remoteAddress, 40, 900)) {
                throw new Exception('Too many login attempts. Try again later.');
            }
            // Apply the same global threshold to real and nonexistent exact
            // identifiers before opening the database. This both bounds
            // distributed dummy-hash work and avoids a post-threshold account
            // existence oracle. Auth::login also aggregates username/email
            // aliases under the resolved account ID.
            if (!Auth::reserveRateLimitAttempt(
                'login_identifier',
                $normalizedLoginIdentifier,
                Auth::ACCOUNT_LOGIN_ATTEMPT_LIMIT,
                Auth::ACCOUNT_LOGIN_RATE_WINDOW
            )) {
                Auth::releaseRateLimitAttempt('login_ip', $remoteAddress);
                throw new Exception('Too many login attempts. Try again later.');
            }
            if (!Auth::reserveRateLimitAttempt('login_account_ip', $loginIdentity, 8, 900)) {
                Auth::releaseRateLimitAttempt('login_identifier', $normalizedLoginIdentifier);
                Auth::releaseRateLimitAttempt('login_ip', $remoteAddress);
                throw new Exception('Too many login attempts. Try again later.');
            }

            // Allocate a new/pending login session only after this request has
            // won both shared reservations. Rejected outcomes destroy their
            // transient session before returning, so they leave no file behind.
            if (!session_start()) {
                Auth::releaseRateLimitAttempt('login_account_ip', $loginIdentity);
                Auth::releaseRateLimitAttempt('login_identifier', $normalizedLoginIdentifier);
                Auth::releaseRateLimitAttempt('login_ip', $remoteAddress);
                throw new AuthApiException(
                    'Sign-in is temporarily unavailable. Please try again.',
                    503,
                    'session_unavailable'
                );
            }

            $preserveSessionOnLoginFailure =
                isset(
                    $_SESSION['logged_in'],
                    $_SESSION['user_id'],
                    $_SESSION['auth_version'],
                    $_SESSION['two_factor_version']
                ) && $_SESSION['logged_in'] === true &&
                is_numeric($_SESSION['user_id']) && (int)$_SESSION['user_id'] > 0 &&
                is_string($_SESSION['auth_version']) &&
                preg_match('/^[a-f0-9]{64}$/D', $_SESSION['auth_version']) === 1 &&
                is_string($_SESSION['two_factor_version']) &&
                preg_match('/^[a-f0-9]{64}$/D', $_SESSION['two_factor_version']) === 1;

            try {
                $loginResult = $getAuth()->login($username, $password);
            } catch (Throwable $e) {
                Auth::releaseRateLimitAttempt('login_account_ip', $loginIdentity);
                Auth::releaseRateLimitAttempt('login_identifier', $normalizedLoginIdentifier);
                Auth::releaseRateLimitAttempt('login_ip', $remoteAddress);
                discardTransientLoginSession($preserveSessionOnLoginFailure);
                throw $e;
            }

            if (!empty($loginResult['rate_limited'])) {
                discardTransientLoginSession($preserveSessionOnLoginFailure);
                http_response_code(429);
                $response = $loginResult;
            } elseif ($loginResult['success']) {
                Auth::clearRateLimit('login_account_ip', $loginIdentity);
                Auth::clearRateLimit('login_identifier', $normalizedLoginIdentifier);
                Auth::releaseRateLimitAttempt('login_ip', $remoteAddress);
                $response = $loginResult;
            } elseif (!empty($loginResult['requires_2fa'])) {
                Auth::clearRateLimit('login_account_ip', $loginIdentity);
                Auth::clearRateLimit('login_identifier', $normalizedLoginIdentifier);
                Auth::releaseRateLimitAttempt('login_ip', $remoteAddress);
                $response = $loginResult;
            } elseif (!empty($loginResult['internal_error'])) {
                Auth::releaseRateLimitAttempt('login_account_ip', $loginIdentity);
                Auth::releaseRateLimitAttempt('login_identifier', $normalizedLoginIdentifier);
                Auth::releaseRateLimitAttempt('login_ip', $remoteAddress);
                discardTransientLoginSession($preserveSessionOnLoginFailure);
                http_response_code(503);
                $response = $loginResult;
            } else {
                discardTransientLoginSession($preserveSessionOnLoginFailure);
                http_response_code(401);
                $response = $loginResult;
            }
            break;

        case 'logout':
            // Get current user info before destroying session
            $sessionResult = $getAuth()->validateSessionFromCookie();

            if ($sessionResult['success']) {
                // Update user's online status
                $getAuth()->updateUserOnlineStatus($sessionResult['user']['id'], 0);
            }

            // Complete session cleanup
            $_SESSION = array();

            // Delete session cookie if it exists
            $session_name = session_name();
            if (isset($_COOKIE[$session_name])) {
                setcookie($session_name, '', [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'domain' => '',
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]);
            }

            session_destroy();

            $response = ['success' => true, 'message' => 'Logged out successfully'];
            break;

        case 'validate':
            $response = $getAuth()->validateSessionFromCookie();

            // Update last activity if session is valid
            if ($response['success']) {
                $_SESSION['last_activity'] = time();
            } else {
                http_response_code(401);
            }
            break;

        case 'update_status':
            $sessionResult = $getAuth()->validateSessionFromCookie();
            if ($sessionResult['success']) {
                // Update last activity
                $_SESSION['last_activity'] = time();

                $response = ['success' => true, 'message' => 'Status updated'];
            } else {
                http_response_code(401);
                $response = $sessionResult;
            }
            break;

        case 'verify_2fa_login':
            if (!isset($input['code']) || !is_string($input['code'])) {
                throw new Exception('Verification code is required');
            }

            // Check if we have a temporary login session
            if (!isset(
                $_SESSION['temp_user_id'],
                $_SESSION['temp_login_time'],
                $_SESSION['temp_auth_version'],
                $_SESSION['temp_2fa_version']
            ) || !is_numeric($_SESSION['temp_user_id']) ||
                !is_numeric($_SESSION['temp_login_time']) ||
                !is_string($_SESSION['temp_auth_version']) ||
                !is_string($_SESSION['temp_2fa_version']) ||
                preg_match('/^[a-f0-9]{64}$/D', $_SESSION['temp_auth_version']) !== 1 ||
                preg_match('/^[a-f0-9]{64}$/D', $_SESSION['temp_2fa_version']) !== 1) {
                clearPendingTwoFactorLogin();
                throw new Exception('No pending 2FA verification. Please login again.');
            }

            // Check if temp session hasn't expired (5 minutes)
            if (time() - $_SESSION['temp_login_time'] > 300) {
                clearPendingTwoFactorLogin();
                throw new Exception('2FA verification expired. Please login again.');
            }

            $user_id = $_SESSION['temp_user_id'];
            $code = strtoupper(trim($input['code']));
            if (!preg_match('/^(?:\d{6}|[A-F0-9]{8})$/', $code)) {
                throw new Exception('Invalid 2FA code');
            }

            // A successful factor may already have been consumed even if the
            // browser missed that response. Make verification retry-safe for
            // this exact short-lived pending session; completion still locks
            // and rechecks the saved password/2FA versions before login.
            if (isset($_SESSION['temp_2fa_verified'], $_SESSION['temp_2fa_verified_at']) &&
                is_numeric($_SESSION['temp_2fa_verified']) &&
                is_numeric($_SESSION['temp_2fa_verified_at']) &&
                (int)$_SESSION['temp_2fa_verified'] === (int)$user_id &&
                time() - (int)$_SESSION['temp_2fa_verified_at'] <= 300) {
                $response = ['success' => true, 'message' => '2FA verification successful'];
                break;
            }

            // The pending session is already bound to this user. Limit factor
            // guesses account-wide so moving the same session across IPs does
            // not multiply attempts.
            $twoFactorIdentity = (string)(int)$user_id;
            if ((int)($_SESSION['temp_2fa_attempts'] ?? 0) >= 5) {
                clearPendingTwoFactorLogin();
                http_response_code(429);
                throw new Exception('Too many verification attempts. Please login again later.');
            }
            if (!Auth::reserveRateLimitAttempt('login_2fa', $twoFactorIdentity, 10, 900)) {
                clearPendingTwoFactorLogin();
                http_response_code(429);
                throw new Exception('Too many verification attempts. Please login again later.');
            }

            try {
                $response = $getAuth()->verifyLogin2FA(
                    $user_id,
                    $code,
                    $_SESSION['temp_auth_version'],
                    $_SESSION['temp_2fa_version']
                );
            } catch (Throwable $e) {
                Auth::releaseRateLimitAttempt('login_2fa', $twoFactorIdentity);
                throw $e;
            }

            if ($response['success']) {
                // Completion must prove this exact pending user passed 2FA.
                $_SESSION['temp_2fa_verified'] = (int)$user_id;
                $_SESSION['temp_2fa_verified_at'] = time();
                Auth::clearRateLimit('login_2fa', $twoFactorIdentity);
                $response['message'] = '2FA verification successful';
            } elseif (!empty($response['stale'])) {
                Auth::releaseRateLimitAttempt('login_2fa', $twoFactorIdentity);
                clearPendingTwoFactorLogin();
                http_response_code(401);
            } elseif (!empty($response['internal_error'])) {
                // Infrastructure failures are not factor guesses. Keep the
                // pending flow retryable and give this reservation back.
                Auth::releaseRateLimitAttempt('login_2fa', $twoFactorIdentity);
                http_response_code(503);
            } else {
                $_SESSION['temp_2fa_attempts'] = (int)($_SESSION['temp_2fa_attempts'] ?? 0) + 1;
                http_response_code(403);
            }
            break;

        case 'complete_2fa_login':
            if (!isset(
                $_SESSION['temp_user_id'],
                $_SESSION['temp_login_time'],
                $_SESSION['temp_2fa_verified'],
                $_SESSION['temp_2fa_verified_at'],
                $_SESSION['temp_auth_version'],
                $_SESSION['temp_2fa_version']
            ) || !is_numeric($_SESSION['temp_user_id']) ||
                !is_numeric($_SESSION['temp_login_time']) ||
                !is_numeric($_SESSION['temp_2fa_verified']) ||
                !is_numeric($_SESSION['temp_2fa_verified_at']) ||
                !is_string($_SESSION['temp_auth_version']) ||
                !is_string($_SESSION['temp_2fa_version']) ||
                preg_match('/^[a-f0-9]{64}$/D', $_SESSION['temp_auth_version']) !== 1 ||
                preg_match('/^[a-f0-9]{64}$/D', $_SESSION['temp_2fa_version']) !== 1 ||
                (int)$_SESSION['temp_2fa_verified'] !== (int)$_SESSION['temp_user_id'] ||
                time() - (int)$_SESSION['temp_login_time'] > 300 ||
                time() - (int)$_SESSION['temp_2fa_verified_at'] > 300) {
                clearPendingTwoFactorLogin();
                throw new Exception('2FA verification is required. Please login again.');
            }

            $user_id = (int)$_SESSION['temp_user_id'];
            $expectedAuthVersion = $_SESSION['temp_auth_version'];
            $expectedTwoFactorVersion = $_SESSION['temp_2fa_version'];
            $response = $getAuth()->completeLoginForUserId(
                $user_id,
                $expectedAuthVersion,
                $expectedTwoFactorVersion
            );
            clearPendingTwoFactorLogin();
            if (!$response['success']) {
                if (!empty($response['stale'])) {
                    throw new AuthApiException(
                        'Authentication state changed. Please login again.',
                        401
                    );
                }
                throw new Exception('Login completion failed');
            }
            $_SESSION['sensitive_auth_at'] = time();
            break;

        default:
            throw new Exception('Invalid action');
    }

} catch (Throwable $e) {
    $safeMessages = [
        'Invalid request format',
        'Missing required fields',
        'Too many registration attempts. Try again later.',
        'Username must be 3-50 letters, numbers, dots, dashes, or underscores',
        'Password must be between 12 and 72 characters',
        'Invalid email address',
        'First name and last name contain invalid characters',
        'Username and password are required',
        'Username and password cannot be empty',
        'Invalid credentials',
        'Too many login attempts. Try again later.',
        'Verification code is required',
        'No pending 2FA verification. Please login again.',
        '2FA verification expired. Please login again.',
        'Invalid 2FA code',
        'Too many verification attempts. Please login again later.',
        '2FA verification is required. Please login again.',
        'Authentication state changed. Please login again.',
        'Login completion failed',
        'Invalid action'
    ];
    $isExpected = $e instanceof AuthApiException || in_array($e->getMessage(), $safeMessages, true);
    if (!$isExpected) {
        error_log("Auth API Error: " . $e->getMessage());
    }
    $message = $isExpected ? $e->getMessage() : 'Request failed. Please try again.';
    $response = [
        'success' => false,
        'message' => $message
    ];
    if ($e instanceof AuthApiException && $e->errorCode !== null) {
        $response['error_code'] = $e->errorCode;
    }

    if ($e instanceof AuthApiException) {
        http_response_code($e->statusCode);
        if ($e->statusCode === 503) {
            header('Retry-After: 30');
        }
    } elseif (str_contains($message, 'Too many')) {
        http_response_code(429);
    } elseif (str_contains($message, 'Authentication required') ||
        str_contains($message, 'No pending 2FA verification') ||
        str_contains($message, '2FA verification is required') ||
        str_contains($message, 'verification expired')) {
        http_response_code(401);
    } elseif (str_contains($message, 'Invalid') || str_contains($message, 'required') ||
        str_contains($message, 'must be') || str_contains($message, 'cannot be empty')) {
        http_response_code(400);
    } else {
        http_response_code(500);
    }
}

echo I18n::encodeResponse($response, JSON_UNESCAPED_UNICODE);
?>
