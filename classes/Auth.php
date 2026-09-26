<?php
// classes/Auth.php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/TotpSecret.php';

class Auth {
    // Public so the pre-database identifier bucket can use the exact same
    // threshold as the post-resolution account bucket.
    public const ACCOUNT_LOGIN_ATTEMPT_LIMIT = 20;
    public const ACCOUNT_LOGIN_RATE_WINDOW = 900;

    private $db;
    private $conn;
    
    // Session timeout in seconds (30 minutes)
    private const SESSION_TIMEOUT = 1800;
    // Require a fresh login at least once per day, even while active.
    private const ABSOLUTE_SESSION_TIMEOUT = 86400;
    // Avoid a database write on every authenticated API request.
    private const LAST_SEEN_UPDATE_INTERVAL = 60;
    // Keep nonexistent-account logins on the same expensive verification path.
    private const DUMMY_PASSWORD_HASH = '$2y$10$TNliSBqpmt.OUiU6nJgYz.cBFnSi0ep4Iqmhrm.Sd9oslUZMWKwkO';

    /**
     * Apply one consistent, hardened cookie policy before session_start().
     */
    public static function configureSession(): void {
        if (session_status() !== PHP_SESSION_NONE) {
            return;
        }

        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_strict_mode', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_secure', '1');
        ini_set('session.cookie_samesite', 'Lax');

        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    /**
     * Prove that a protected request references an existing file-backed
     * session before session_start(). Strict mode replaces an unknown cookie
     * with a fresh ID, so syntax validation alone would still let random-SID
     * floods allocate empty session files.
     */
    public static function hasValidSessionCookie(): bool {
        $sessionName = session_name();
        $sessionId = $_COOKIE[$sessionName] ?? null;
        if (!is_string($sessionId) ||
            preg_match('/\A[A-Za-z0-9,-]{16,128}\z/D', $sessionId) !== 1 ||
            session_module_name() !== 'files') {
            return false;
        }

        $savePath = (string)ini_get('session.save_path');
        $pathParts = explode(';', $savePath);
        $directoryDepth = 0;
        if (count($pathParts) === 1) {
            $sessionDirectory = $pathParts[0];
        } elseif (count($pathParts) === 2 && preg_match('/\A[0-9]+\z/D', $pathParts[0]) === 1) {
            $directoryDepth = (int)$pathParts[0];
            $sessionDirectory = $pathParts[1];
        } elseif (count($pathParts) === 3 &&
            preg_match('/\A[0-9]+\z/D', $pathParts[0]) === 1 &&
            preg_match('/\A0?[0-7]{3,4}\z/D', $pathParts[1]) === 1) {
            $directoryDepth = (int)$pathParts[0];
            $sessionDirectory = $pathParts[2];
        } else {
            return false;
        }
        if ($directoryDepth < 0 || $directoryDepth > 5 ||
            $directoryDepth > strlen($sessionId) || $sessionDirectory === '') {
            return false;
        }

        $sessionRoot = realpath($sessionDirectory);
        $rootStat = $sessionRoot !== false ? @lstat($sessionRoot) : false;
        if ($sessionRoot === false || !is_array($rootStat) ||
            ($rootStat['mode'] & 0170000) !== 0040000 ||
            ($rootStat['mode'] & 0077) !== 0 ||
            !self::rateLimitPathOwnedByCurrentUser($rootStat)) {
            return false;
        }

        $candidateDirectory = $sessionRoot;
        for ($index = 0; $index < $directoryDepth; $index++) {
            $candidateDirectory .= DIRECTORY_SEPARATOR . $sessionId[$index];
        }
        $resolvedDirectory = realpath($candidateDirectory);
        $rootPrefix = rtrim($sessionRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if ($resolvedDirectory === false ||
            ($resolvedDirectory !== $sessionRoot &&
                strncmp($resolvedDirectory, $rootPrefix, strlen($rootPrefix)) !== 0)) {
            return false;
        }
        $resolvedDirectoryStat = @lstat($resolvedDirectory);
        if (!is_array($resolvedDirectoryStat) ||
            ($resolvedDirectoryStat['mode'] & 0170000) !== 0040000 ||
            ($resolvedDirectoryStat['mode'] & 0077) !== 0 ||
            !self::rateLimitPathOwnedByCurrentUser($resolvedDirectoryStat)) {
            return false;
        }

        $sessionPath = $resolvedDirectory . DIRECTORY_SEPARATOR . 'sess_' . $sessionId;
        clearstatcache(true, $sessionPath);
        $sessionStat = @lstat($sessionPath);
        return is_array($sessionStat) &&
            ($sessionStat['mode'] & 0170000) === 0100000 &&
            ($sessionStat['mode'] & 0077) === 0 &&
            isset($sessionStat['size']) && (int)$sessionStat['size'] >= 0 &&
            (int)$sessionStat['size'] <= 1048576 &&
            self::rateLimitPathOwnedByCurrentUser($sessionStat);
    }

    /**
     * Start only the exact existing session proven above. Rechecking the ID
     * after startup closes the small GC race between lstat() and PHP's strict
     * mode validation; a replacement ID is destroyed before it can persist.
     */
    public static function startExistingSession(array $options = []): bool {
        if (session_status() !== PHP_SESSION_NONE || !self::hasValidSessionCookie()) {
            return false;
        }

        $expectedId = $_COOKIE[session_name()];
        $readAndClose = !empty($options['read_and_close']);
        unset($options['read_and_close']);
        if (!@session_start($options) || !hash_equals($expectedId, session_id())) {
            $_SESSION = [];
            if (session_status() === PHP_SESSION_ACTIVE) {
                @session_destroy();
            }
            return false;
        }

        if ($readAndClose) {
            session_write_close();
        }
        return true;
    }

    /**
     * Browser requests may only mutate an account from this site's origin.
     * Header-less non-browser clients remain supported; JSON endpoints also
     * require application/json, which browsers cannot submit cross-origin
     * without a successful preflight.
     */
    public static function isSameOriginRequest(): bool {
        $fetchSite = strtolower(trim((string)($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '')));
        if ($fetchSite === 'cross-site') {
            return false;
        }

        $expected = self::normalizeOrigin(defined('SITE_URL') ? SITE_URL : 'https://messenger.example');
        $origin = trim((string)($_SERVER['HTTP_ORIGIN'] ?? ''));
        if ($origin !== '') {
            return hash_equals($expected, self::normalizeOrigin($origin));
        }

        $referer = trim((string)($_SERVER['HTTP_REFERER'] ?? ''));
        if ($referer !== '') {
            return hash_equals($expected, self::normalizeOrigin($referer));
        }

        return true;
    }

    private static function normalizeOrigin(string $url): string {
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return '';
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower(rtrim($parts['host'], '.'));
        $port = isset($parts['port']) ? (int)$parts['port'] : null;
        $defaultPort = ($scheme === 'https') ? 443 : (($scheme === 'http') ? 80 : null);

        return $scheme . '://' . $host . (($port !== null && $port !== $defaultPort) ? ':' . $port : '');
    }

    public static function setPrivateResponseHeaders(): void {
        header('Cache-Control: no-store, max-age=0');
        header('Pragma: no-cache');
        header('X-Content-Type-Options: nosniff');
        header('Cross-Origin-Resource-Policy: same-origin');
        header('Vary: Origin', false);
    }

    private static function rateLimitCacheKey(string $scope, string $identity): string {
        return 'pm_rate_' . hash('sha256', $scope . "\0" . strtolower(trim($identity)));
    }

    private static function canUseApcu(): bool {
        if (!function_exists('apcu_fetch') || !function_exists('apcu_add') ||
            !function_exists('apcu_inc') || !function_exists('apcu_dec') ||
            !function_exists('apcu_delete') ||
            !filter_var(ini_get('apc.enabled'), FILTER_VALIDATE_BOOLEAN)) {
            return false;
        }

        // APCu is disabled for CLI by default. Checking this explicitly keeps
        // command-line workers and tests on the cross-process file backend.
        return PHP_SAPI !== 'cli' ||
            filter_var(ini_get('apc.enable_cli'), FILTER_VALIDATE_BOOLEAN);
    }

    private static function normalizeRateLimitState($state, int $now): ?array {
        if (!is_array($state) || !isset($state['count'], $state['expires']) ||
            !is_int($state['count']) || !is_int($state['expires']) ||
            $state['count'] < 0 || $state['expires'] < 0) {
            return null;
        }

        if ($state['expires'] <= $now) {
            return ['count' => 0, 'expires' => 0];
        }

        return $state;
    }

    private static function rateLimitDirectory(): ?string {
        $base = realpath(sys_get_temp_dir());
        if ($base === false || !is_dir($base)) {
            return null;
        }

        $uid = function_exists('posix_geteuid')
            ? (string)posix_geteuid()
            : substr(hash('sha256', get_current_user()), 0, 12);
        $applicationRoot = realpath(__DIR__ . '/..') ?: __DIR__;
        $directory = rtrim($base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR .
            'pm-rate-limits-' . $uid . '-' . substr(hash('sha256', $applicationRoot), 0, 16);

        clearstatcache(true, $directory);
        $stat = @lstat($directory);
        if ($stat === false) {
            if (!@mkdir($directory, 0700, false)) {
                clearstatcache(true, $directory);
                if (!is_dir($directory)) {
                    return null;
                }
            }
            $stat = @lstat($directory);
        }

        if (!is_array($stat) || ($stat['mode'] & 0170000) !== 0040000 ||
            !self::rateLimitPathOwnedByCurrentUser($stat)) {
            return null;
        }

        if (($stat['mode'] & 0777) !== 0700) {
            if (!@chmod($directory, 0700)) {
                return null;
            }
            clearstatcache(true, $directory);
            $stat = @lstat($directory);
            if (!is_array($stat) || ($stat['mode'] & 0777) !== 0700) {
                return null;
            }
        }

        return $directory;
    }

    private static function rateLimitShardDirectory(string $root, string $shard): ?string {
        if (preg_match('/^[a-f0-9]{2}$/D', $shard) !== 1) {
            return null;
        }

        $directory = $root . DIRECTORY_SEPARATOR . $shard;
        clearstatcache(true, $directory);
        $stat = @lstat($directory);
        if ($stat === false) {
            if (!@mkdir($directory, 0700, false)) {
                clearstatcache(true, $directory);
                if (!is_dir($directory)) {
                    return null;
                }
            }
            $stat = @lstat($directory);
        }

        if (!is_array($stat) || ($stat['mode'] & 0170000) !== 0040000 ||
            !self::rateLimitPathOwnedByCurrentUser($stat)) {
            return null;
        }
        if (($stat['mode'] & 0777) !== 0700 && !@chmod($directory, 0700)) {
            return null;
        }

        clearstatcache(true, $directory);
        $stat = @lstat($directory);
        if (!is_array($stat) || ($stat['mode'] & 0170000) !== 0040000 ||
            ($stat['mode'] & 0777) !== 0700 ||
            !self::rateLimitPathOwnedByCurrentUser($stat)) {
            return null;
        }

        return $directory;
    }

    private static function rateLimitPathOwnedByCurrentUser(array $stat): bool {
        return !function_exists('posix_geteuid') || !isset($stat['uid']) ||
            (int)$stat['uid'] === posix_geteuid();
    }

    /** @return resource|false */
    private static function openRateLimitLockFile(string $path) {
        clearstatcache(true, $path);
        $before = @lstat($path);
        if (is_array($before) && ($before['mode'] & 0170000) !== 0100000) {
            return false;
        }

        $handle = @fopen($path, 'c+b');
        if ($handle === false || !@chmod($path, 0600)) {
            if (is_resource($handle)) {
                fclose($handle);
            }
            return false;
        }

        $opened = @fstat($handle);
        clearstatcache(true, $path);
        $after = @lstat($path);
        if (!is_array($opened) || !is_array($after) ||
            ($opened['mode'] & 0170000) !== 0100000 ||
            ($after['mode'] & 0170000) !== 0100000 ||
            (int)$opened['dev'] !== (int)$after['dev'] ||
            (int)$opened['ino'] !== (int)$after['ino'] ||
            !self::rateLimitPathOwnedByCurrentUser($opened) ||
            ($opened['mode'] & 0777) !== 0600) {
            fclose($handle);
            return false;
        }

        return $handle;
    }

    private static function readFileRateLimitState(string $path): ?array {
        clearstatcache(true, $path);
        $before = @lstat($path);
        if ($before === false) {
            return ['count' => 0, 'expires' => 0];
        }
        if (($before['mode'] & 0170000) !== 0100000 ||
            !self::rateLimitPathOwnedByCurrentUser($before) ||
            ($before['mode'] & 0777) !== 0600 || (int)$before['size'] > 1024) {
            return null;
        }

        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }

        $opened = @fstat($handle);
        clearstatcache(true, $path);
        $after = @lstat($path);
        if (!is_array($opened) || !is_array($after) ||
            (int)$opened['dev'] !== (int)$after['dev'] ||
            (int)$opened['ino'] !== (int)$after['ino'] ||
            ($opened['mode'] & 0170000) !== 0100000 ||
            !self::rateLimitPathOwnedByCurrentUser($opened) ||
            (int)$opened['size'] > 1024) {
            fclose($handle);
            return null;
        }

        $raw = stream_get_contents($handle, 1025);
        fclose($handle);
        if (!is_string($raw) || strlen($raw) > 1024) {
            return null;
        }

        try {
            $state = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            return null;
        }

        return self::normalizeRateLimitState($state, time());
    }

    private static function writeFileRateLimitState(string $path, array $state): bool {
        $encoded = json_encode($state, JSON_UNESCAPED_SLASHES);
        if (!is_string($encoded)) {
            return false;
        }

        try {
            $suffix = bin2hex(random_bytes(12));
        } catch (Throwable $e) {
            return false;
        }

        $temporaryPath = dirname($path) . DIRECTORY_SEPARATOR . '.' . basename($path) .
            '.' . $suffix . '.tmp';
        $handle = @fopen($temporaryPath, 'x+b');
        if ($handle === false || !@chmod($temporaryPath, 0600)) {
            if (is_resource($handle)) {
                fclose($handle);
            }
            @unlink($temporaryPath);
            return false;
        }

        $written = fwrite($handle, $encoded);
        $flushed = $written === strlen($encoded) && fflush($handle);
        if ($flushed && function_exists('fsync')) {
            $flushed = @fsync($handle);
        }
        fclose($handle);

        if (!$flushed || !@rename($temporaryPath, $path)) {
            @unlink($temporaryPath);
            return false;
        }
        @chmod($path, 0600);
        return true;
    }

    /**
     * Amortize stale-state cleanup across requests in one shard. The cursor is
     * stored in the shard lock file, so each pass examines at most 16 entries
     * without repeatedly starting at the beginning of a large directory.
     * This bounds request work while eventually reclaiming expired identities.
     *
     * @param resource $lockHandle
     */
    private static function cleanupFileRateLimitShard(string $directory, $lockHandle): void {
        $cursor = 0;
        rewind($lockHandle);
        $rawCursor = stream_get_contents($lockHandle, 32);
        if (is_string($rawCursor) && preg_match('/^\d{1,20}$/D', trim($rawCursor)) === 1) {
            $cursor = (int)trim($rawCursor);
        }

        try {
            $iterator = new DirectoryIterator($directory);
            try {
                $iterator->seek($cursor);
            } catch (OutOfBoundsException $e) {
                $iterator->rewind();
            }

            $examined = 0;
            while ($iterator->valid() && $examined < 16) {
                if (!$iterator->isDot()) {
                    $filename = $iterator->getFilename();
                    if (preg_match('/^[a-f0-9]{62}\.json$/D', $filename) === 1) {
                        $path = $directory . DIRECTORY_SEPARATOR . $filename;
                        $state = self::readFileRateLimitState($path);
                        if (is_array($state) && $state['count'] === 0) {
                            @unlink($path);
                        }
                    } elseif (str_ends_with($filename, '.tmp') &&
                        $iterator->isFile() && $iterator->getMTime() < time() - 3600) {
                        @unlink($iterator->getPathname());
                    }
                }
                $examined++;
                $iterator->next();
            }
            $nextCursor = $iterator->valid() ? $iterator->key() : 0;
        } catch (UnexpectedValueException $e) {
            return;
        }

        rewind($lockHandle);
        if (ftruncate($lockHandle, 0)) {
            fwrite($lockHandle, (string)$nextCursor);
            fflush($lockHandle);
        }
    }

    /**
     * Run a cross-process file-backed state transition under flock. The lock
     * file is stable, while state replacement is atomic and crash resistant.
     */
    private static function withFileRateLimitLock(
        string $key,
        callable $operation,
        $failureValue,
        bool $resetCorruptState = false
    ) {
        $directory = self::rateLimitDirectory();
        if ($directory === null) {
            return $failureValue;
        }

        $digest = hash('sha256', $key);
        $shardDirectory = self::rateLimitShardDirectory($directory, substr($digest, 0, 2));
        if ($shardDirectory === null) {
            return $failureValue;
        }

        // A finite set of 256 shard locks avoids one permanent lock file for
        // every attacker-controlled identity.
        $lockPath = $shardDirectory . DIRECTORY_SEPARATOR . 'state.lock';
        $statePath = $shardDirectory . DIRECTORY_SEPARATOR . substr($digest, 2) . '.json';
        $handle = self::openRateLimitLockFile($lockPath);
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) {
                fclose($handle);
            }
            return $failureValue;
        }

        try {
            self::cleanupFileRateLimitShard($shardDirectory, $handle);
            $state = self::readFileRateLimitState($statePath);
            if ($state === null) {
                if (!$resetCorruptState) {
                    return $failureValue;
                }
                $state = ['count' => 0, 'expires' => 0];
            }

            $outcome = $operation($state);
            if (!is_array($outcome) || !array_key_exists('result', $outcome)) {
                return $failureValue;
            }
            if (array_key_exists('state', $outcome) &&
                !self::writeFileRateLimitState($statePath, $outcome['state'])) {
                return $failureValue;
            }
            if (!empty($outcome['delete'])) {
                clearstatcache(true, $statePath);
                if (@lstat($statePath) !== false && !@unlink($statePath)) {
                    return $failureValue;
                }
            }

            return $outcome['result'];
        } catch (Throwable $e) {
            return $failureValue;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * Atomically admit and count one credential/factor attempt. Returning false
     * means the attempt must not perform expensive authentication work.
     */
    public static function reserveRateLimitAttempt(
        string $scope,
        string $identity,
        int $limit,
        int $windowSeconds
    ): bool {
        if ($limit < 1 || $windowSeconds < 1) {
            throw new InvalidArgumentException('Invalid rate limit configuration');
        }

        $key = self::rateLimitCacheKey($scope, $identity);
        $operation = static function (array $state) use ($limit, $windowSeconds): array {
            $now = time();
            if ($state['expires'] <= $now) {
                $state = ['count' => 0, 'expires' => 0];
            }
            if ($state['count'] >= $limit) {
                return ['result' => false];
            }

            if ($state['count'] === 0) {
                $state['expires'] = $now + $windowSeconds;
            }
            $state['count']++;
            return ['result' => true, 'state' => $state];
        };

        if (self::canUseApcu()) {
            $counterKey = $key . '_count_v2';
            // add() establishes the TTL. If another worker won that race,
            // inc() atomically reserves the next slot without a check/use gap.
            for ($attempt = 0; $attempt < 4; $attempt++) {
                if (@apcu_add($counterKey, 1, $windowSeconds)) {
                    return true;
                }

                $incremented = @apcu_inc($counterKey, 1, $success);
                if (!$success || !is_int($incremented)) {
                    // The key may have expired between add() and inc(). Retry
                    // so this worker can establish the next fixed window.
                    continue;
                }
                if ($incremented > 0 && $incremented <= $limit) {
                    return true;
                }

                // This worker crossed the exact limit, so roll back only its
                // own reservation and deny the expensive operation.
                $rollbackSuccess = false;
                @apcu_dec($counterKey, 1, $rollbackSuccess);
                return false;
            }

            // Backend uncertainty fails closed.
            return false;
        }

        return self::withFileRateLimitLock($key, $operation, false);
    }

    /** Release one reservation when the attempted path should not count. */
    public static function releaseRateLimitAttempt(string $scope, string $identity): void {
        $key = self::rateLimitCacheKey($scope, $identity);
        $operation = static function (array $state): array {
            $now = time();
            if ($state['expires'] <= $now || $state['count'] <= 1) {
                return ['result' => true, 'delete' => true];
            }

            $state['count']--;
            return ['result' => true, 'state' => $state];
        };

        if (self::canUseApcu()) {
            $counterKey = $key . '_count_v2';
            $decremented = @apcu_dec($counterKey, 1, $success);
            if ($success && is_int($decremented) && $decremented < 0) {
                // Defensive repair for an accidental unmatched release. Normal
                // call sites release exactly one successfully reserved slot.
                $restoreSuccess = false;
                @apcu_inc($counterKey, 1, $restoreSuccess);
            }
            return;
        }

        self::withFileRateLimitLock($key, $operation, false);
    }

    public static function clearRateLimit(string $scope, string $identity): void {
        $key = self::rateLimitCacheKey($scope, $identity);
        if (self::canUseApcu()) {
            @apcu_delete($key . '_count_v2');
            // Remove counters written by the previous limiter implementation.
            @apcu_delete($key . '_count');
            unset($_SESSION['_rate_limits'][$key]);
            return;
        }

        self::withFileRateLimitLock(
            $key,
            static function (array $state): array {
                return ['result' => true, 'delete' => true];
            },
            false,
            true
        );
        unset($_SESSION['_rate_limits'][$key]);
    }

    public static function passwordAuthenticationVersion(string $passwordHash): string {
        return hash('sha256', $passwordHash);
    }

    public static function twoFactorAuthenticationVersion(
        int $enabled,
        ?string $storedSecret,
        int $userId = 0
    ): string {
        if ($enabled !== 0 && $enabled !== 1) {
            throw new InvalidArgumentException('Invalid 2FA state');
        }

        $secret = null;
        if ($enabled === 1) {
            $secret = $userId > 0
                ? TotpSecret::decryptForUser($userId, $storedSecret)
                : null;
            if ($secret === null) {
                throw new InvalidArgumentException('Invalid 2FA state');
            }
        }

        return hash('sha256', "pm-2fa-state\0" . $enabled . "\0" . ($secret ?? ''));
    }
    
    public function __construct() {
        $this->db = new Database();
        $this->conn = $this->db->connect();
    }
    
    public function register($username, $email, $password, $first_name, $last_name) {
        try {
            // Check if username or email already exists
            $stmt = $this->conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
            $stmt->bind_param("ss", $username, $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                return ['success' => false, 'message' => 'Username or email already exists'];
            }
            
            // Hash password
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            
            // Insert new user
            $stmt = $this->conn->prepare("INSERT INTO users (username, email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $username, $email, $password_hash, $first_name, $last_name);
            
            if ($stmt->execute()) {
                return ['success' => true, 'message' => 'Registration successful', 'user_id' => $this->conn->insert_id];
            } else {
                return ['success' => false, 'message' => 'Registration failed'];
            }
        } catch (Exception $e) {
            error_log("Registration error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Registration failed'];
        }
    }
    
    public function login($username, $password) {
        $accountRateIdentity = '';
        $accountRateReserved = false;
        try {
            $username = trim($username);

            // A new password attempt invalidates any older pending 2FA flow.
            unset(
                $_SESSION['temp_user_id'],
                $_SESSION['temp_login_time'],
                $_SESSION['temp_2fa_verified'],
                $_SESSION['temp_2fa_verified_at'],
                $_SESSION['temp_2fa_attempts'],
                $_SESSION['temp_auth_version'],
                $_SESSION['temp_2fa_version']
            );
            
            // Selecting the required factor columns already fails closed when
            // the authentication schema is incomplete; avoid a second schema
            // query on every unauthenticated password attempt.
            $sql = "SELECT id, username, email, password_hash, first_name, last_name, avatar, bio, two_factor_enabled, two_factor_secret FROM users WHERE username = ? OR email = ?";

            $stmt = $this->conn->prepare($sql);
            $stmt->bind_param("ss", $username, $username);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 1) {
                $user = $result->fetch_assoc();

                // Resolve aliases to one stable user ID before expensive
                // password verification. This account-wide bucket cannot be
                // bypassed by case variants, email/username aliases, or a
                // botnet rotating source addresses.
                $accountRateIdentity = (string)(int)$user['id'];
                if (!self::reserveRateLimitAttempt(
                    'account_password',
                    $accountRateIdentity,
                    self::ACCOUNT_LOGIN_ATTEMPT_LIMIT,
                    self::ACCOUNT_LOGIN_RATE_WINDOW
                )) {
                    return [
                        'success' => false,
                        'message' => 'Too many login attempts. Try again later.',
                        'rate_limited' => true
                    ];
                }
                $accountRateReserved = true;
                
                if (password_verify($password, $user['password_hash'])) {
                    if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
                        $oldPasswordHash = $user['password_hash'];
                        $rehash = password_hash($password, PASSWORD_DEFAULT);
                        if ($rehash !== false) {
                            $rehashStmt = $this->conn->prepare("
                                UPDATE users SET password_hash = ?
                                WHERE id = ? AND password_hash = ?
                            ");
                            $rehashStmt->bind_param("sis", $rehash, $user['id'], $oldPasswordHash);
                            if (!$rehashStmt->execute()) {
                                throw new RuntimeException('Unable to update credential hash');
                            }
                            if ($rehashStmt->affected_rows === 1) {
                                $user['password_hash'] = $rehash;
                            } else {
                                // A concurrent credential update won the race;
                                // the password proof must not authorize its state.
                                self::releaseRateLimitAttempt('account_password', $accountRateIdentity);
                                $accountRateReserved = false;
                                return [
                                    'success' => false,
                                    'message' => 'Invalid credentials',
                                    'invalid_credentials' => true
                                ];
                            }
                        }
                    }

                    if (!array_key_exists('two_factor_enabled', $user)) {
                        throw new RuntimeException('Required authentication schema is unavailable');
                    }

                    $twoFactorState = $user['two_factor_enabled'];
                    if (!in_array($twoFactorState, [0, 1, '0', '1'], true)) {
                        throw new RuntimeException('Required authentication schema is unavailable');
                    }

                    // Any non-zero value requires the second factor.
                    if ((int)$twoFactorState !== 0) {
                        // Rotate before establishing a partially authenticated session
                        // so an attacker cannot choose the session identifier.
                        if (!session_regenerate_id(true)) {
                            throw new RuntimeException('Unable to rotate pending login session');
                        }
                        $_SESSION = [];

                        // Store temporary login data in session for 2FA verification
                        $_SESSION['temp_user_id'] = (int)$user['id'];
                        $_SESSION['temp_login_time'] = time();
                        $_SESSION['temp_2fa_attempts'] = 0;
                        $_SESSION['temp_auth_version'] = self::passwordAuthenticationVersion(
                            (string)$user['password_hash']
                        );
                        $_SESSION['temp_2fa_version'] = self::twoFactorAuthenticationVersion(
                            1,
                            is_string($user['two_factor_secret'] ?? null)
                                ? $user['two_factor_secret']
                                : null,
                            (int)$user['id']
                        );

                        self::clearRateLimit('account_password', $accountRateIdentity);
                        $accountRateReserved = false;
                        
                        return [
                            'success' => false,
                            'requires_2fa' => true,
                            'message' => '2FA verification required'
                        ];
                    }
                    
                    // Complete login if no 2FA
                    self::clearRateLimit('account_password', $accountRateIdentity);
                    $accountRateReserved = false;
                    $completion = $this->completeLogin($user);
                    if (empty($completion['success'])) {
                        $completion['internal_error'] = true;
                    }
                    return $completion;
                } else {
                    $accountRateReserved = false; // Retain the failed account attempt.
                    return [
                        'success' => false,
                        'message' => 'Invalid credentials',
                        'invalid_credentials' => true
                    ];
                }
            } else {
                password_verify($password, self::DUMMY_PASSWORD_HASH);
                return [
                    'success' => false,
                    'message' => 'Invalid credentials',
                    'invalid_credentials' => true
                ];
            }
        } catch (Throwable $e) {
            if ($accountRateReserved) {
                self::releaseRateLimitAttempt('account_password', $accountRateIdentity);
            }
            error_log("Login error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Login failed. Please try again.',
                'internal_error' => true
            ];
        }
    }
    
    public function verify2FALogin($code) {
        try {
            // Check if we have a temporary login session
            if (!isset(
                $_SESSION['temp_user_id'],
                $_SESSION['temp_login_time'],
                $_SESSION['temp_auth_version'],
                $_SESSION['temp_2fa_version']
            ) || !is_string($_SESSION['temp_auth_version']) ||
                !is_string($_SESSION['temp_2fa_version'])) {
                return ['success' => false, 'message' => 'No pending 2FA verification'];
            }
            
            // Check if temp session hasn't expired (5 minutes)
            if (time() - $_SESSION['temp_login_time'] > 300) {
                $this->clearPendingTwoFactorSession();
                return ['success' => false, 'message' => '2FA verification expired. Please login again.'];
            }
            
            $user_id = (int)$_SESSION['temp_user_id'];
            $expectedAuthVersion = $_SESSION['temp_auth_version'];
            $expectedTwoFactorVersion = $_SESSION['temp_2fa_version'];

            // Verify 2FA code
            $verificationResult = $this->verifyLogin2FA(
                $user_id,
                $code,
                $expectedAuthVersion,
                $expectedTwoFactorVersion
            );
            
            if ($verificationResult['success']) {
                $result = $this->completeLoginForUserId(
                    $user_id,
                    $expectedAuthVersion,
                    $expectedTwoFactorVersion
                );
                $this->clearPendingTwoFactorSession();
                return $result;
            }

            if (!empty($verificationResult['stale'])) {
                $this->clearPendingTwoFactorSession();
            }
            return $verificationResult;
        } catch (Exception $e) {
            error_log("2FA verification error: " . $e->getMessage());
            return ['success' => false, 'message' => '2FA verification failed'];
        }
    }
    
    private function completeLogin($user) {
        try {
            // Update online status and last seen
            $this->updateOnlineStatus($user['id'], true);
            return $this->establishAuthenticatedSession($user);
        } catch (Throwable $e) {
            error_log("Complete login error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Login completion failed'];
        }
    }

    private function establishAuthenticatedSession(array $user): array {
        if (!isset($user['id'], $user['password_hash']) ||
            !is_numeric($user['id']) || !is_string($user['password_hash']) ||
            $user['password_hash'] === '') {
            return ['success' => false, 'message' => 'Login completion failed'];
        }
        $authenticationVersions = $this->pendingVersionsForUser($user);
        if ($authenticationVersions === null) {
            return ['success' => false, 'message' => 'Login completion failed'];
        }

        if (!session_regenerate_id(true)) {
            return ['success' => false, 'message' => 'Login completion failed'];
        }
        $_SESSION = [];

        $_SESSION['user_id'] = (int)$user['id'];
        $_SESSION['logged_in'] = true;
        $now = time();
        $_SESSION['login_time'] = $now;
        $_SESSION['last_activity'] = $now;
        $_SESSION['last_seen_updated_at'] = $now;
        $_SESSION['auth_version'] = $authenticationVersions['auth'];
        $_SESSION['two_factor_version'] = $authenticationVersions['two_factor'];

        unset(
            $user['password_hash'],
            $user['two_factor_secret'],
            $user['two_factor_enabled']
        );
        return ['success' => true, 'user' => $user];
    }

    private function clearPendingTwoFactorSession(): void {
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
    
    public function logout($user_id = null) {
        try {
            if ($user_id) {
                $this->updateOnlineStatus($user_id, false);
            }
            return ['success' => true, 'message' => 'Logged out successfully'];
        } catch (Exception $e) {
            error_log("Logout error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Logout failed'];
        }
    }
    
    public function validateSessionFromCookie() {
        try {
            if (!isset($_SESSION['user_id']) || 
                !isset($_SESSION['logged_in']) || 
                $_SESSION['logged_in'] !== true ||
                !isset($_SESSION['login_time'], $_SESSION['last_activity']) ||
                !is_numeric($_SESSION['user_id']) || (int)$_SESSION['user_id'] < 1) {
                return ['success' => false, 'message' => 'No active session'];
            }
            
            if ((time() - (int)$_SESSION['last_activity']) > self::SESSION_TIMEOUT ||
                (time() - (int)$_SESSION['login_time']) > self::ABSOLUTE_SESSION_TIMEOUT) {
                $this->destroySession();
                return ['success' => false, 'message' => 'Session expired'];
            }
            
            $userId = (int)$_SESSION['user_id'];
            $stmt = $this->conn->prepare("
                SELECT id, username, email, password_hash, first_name, last_name,
                       avatar, bio, two_factor_enabled, two_factor_secret
                FROM users
                WHERE id = ?
            ");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 1) {
                $user = $result->fetch_assoc();
                $currentVersions = $this->pendingVersionsForUser($user);
                if (!isset($_SESSION['auth_version']) || !is_string($_SESSION['auth_version']) ||
                    !isset($_SESSION['two_factor_version']) ||
                    !is_string($_SESSION['two_factor_version']) ||
                    $currentVersions === null ||
                    !hash_equals($_SESSION['auth_version'], $currentVersions['auth']) ||
                    !hash_equals($_SESSION['two_factor_version'], $currentVersions['two_factor'])) {
                    $this->destroySession();
                    return ['success' => false, 'message' => 'Session expired'];
                }

                unset($user['password_hash'], $user['two_factor_enabled'], $user['two_factor_secret']);
                $now = time();
                $lastSeenUpdatedAt = isset($_SESSION['last_seen_updated_at']) &&
                    is_int($_SESSION['last_seen_updated_at'])
                    ? $_SESSION['last_seen_updated_at']
                    : 0;

                if ($lastSeenUpdatedAt > $now ||
                    ($now - $lastSeenUpdatedAt) >= self::LAST_SEEN_UPDATE_INTERVAL) {
                    // Record the attempt before writing so a temporary database
                    // failure cannot turn each request into another write attempt.
                    $_SESSION['last_seen_updated_at'] = $now;
                    $this->updateOnlineStatus($user['id'], true);
                }
                $_SESSION['last_activity'] = $now;
                return ['success' => true, 'user' => $user];
            } else {
                $this->destroySession();
                return ['success' => false, 'message' => 'User account not found'];
            }
        } catch (Exception $e) {
            error_log("Session validation error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Session validation failed'];
        }
    }
    
    private function updateOnlineStatus($user_id, $is_online) {
        try {
            $stmt = $this->conn->prepare("UPDATE users SET is_online = ?, last_seen = NOW() WHERE id = ?");
            $stmt->bind_param("ii", $is_online, $user_id);
            return $stmt->execute();
        } catch (Exception $e) {
            error_log("Update online status error: " . $e->getMessage());
            return false;
        }
    }
    
    private function destroySession() {
        $_SESSION = array();
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', [
                'expires' => time() - 3600,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Lax'
            ]);
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    public function completeLoginForUserId(
        int $user_id,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ): array {
        if ($user_id < 1 || $expectedAuthVersion === '' || $expectedTwoFactorVersion === '') {
            return ['success' => false, 'message' => 'Authentication state changed. Please login again.', 'stale' => true];
        }

        try {
            if (!$this->conn->begin_transaction()) {
                throw new RuntimeException('Unable to start login completion');
            }

            $stmt = $this->conn->prepare("
                SELECT id, username, email, password_hash, first_name, last_name,
                       avatar, bio, two_factor_enabled, two_factor_secret
                FROM users
                WHERE id = ?
                FOR UPDATE
            ");
            $stmt->bind_param("i", $user_id);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to read authentication state');
            }
            $result = $stmt->get_result();
            if ($result->num_rows !== 1) {
                $this->conn->rollback();
                return ['success' => false, 'message' => 'Authentication state changed. Please login again.', 'stale' => true];
            }

            $user = $result->fetch_assoc();
            $currentVersions = $this->pendingVersionsForUser($user);
            if ($currentVersions === null ||
                !hash_equals($expectedAuthVersion, $currentVersions['auth']) ||
                !hash_equals($expectedTwoFactorVersion, $currentVersions['two_factor'])) {
                $this->conn->rollback();
                return ['success' => false, 'message' => 'Authentication state changed. Please login again.', 'stale' => true];
            }

            $stmt = $this->conn->prepare(
                "UPDATE users SET is_online = 1, last_seen = NOW() WHERE id = ?"
            );
            $stmt->bind_param("i", $user_id);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to update login state');
            }

            // Establish the session while the authentication row is still
            // locked. A password/2FA change cannot slip between the final
            // comparison and session creation.
            $sessionResult = $this->establishAuthenticatedSession($user);
            if (!$sessionResult['success']) {
                throw new RuntimeException('Unable to establish login session');
            }
            if (!$this->conn->commit()) {
                throw new RuntimeException('Unable to commit login completion');
            }
            return $sessionResult;
        } catch (Throwable $e) {
            try {
                $this->conn->rollback();
            } catch (Throwable $ignored) {
            }
            if (!empty($_SESSION['logged_in'])) {
                $this->destroySession();
            }
            error_log("Complete login by user ID error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Login completion failed'];
        }
    }

    /**
     * Advance only the password version produced by the just-committed,
     * state-bound mutation. Never re-read account state here: another
     * credential mutation may already have committed, and copying that newer
     * state into this older session would silently keep it alive.
     */
    public function refreshSessionPasswordVersion(
        int $userId,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion,
        string $postMutationAuthVersion,
        string $postMutationTwoFactorVersion
    ): bool {
        if (!$this->currentSessionMatchesAuthenticationState(
            $userId,
            $expectedAuthVersion,
            $expectedTwoFactorVersion
        ) || !$this->isAuthenticationVersion($postMutationAuthVersion) ||
            !hash_equals($expectedTwoFactorVersion, $postMutationTwoFactorVersion)) {
            $this->destroySession();
            return false;
        }

        if (!session_regenerate_id(true)) {
            $this->destroySession();
            return false;
        }
        $_SESSION['auth_version'] = $postMutationAuthVersion;
        $_SESSION['last_activity'] = time();
        return true;
    }

    /**
     * Keep only the session that performed a 2FA state change alive. Every
     * other session retains the old factor version and expires on its next API
     * request.
     */
    public function refreshSessionTwoFactorVersion(
        int $userId,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion,
        string $postMutationAuthVersion,
        string $postMutationTwoFactorVersion
    ): bool {
        if (!$this->currentSessionMatchesAuthenticationState(
            $userId,
            $expectedAuthVersion,
            $expectedTwoFactorVersion
        ) || !hash_equals($expectedAuthVersion, $postMutationAuthVersion) ||
            !$this->isAuthenticationVersion($postMutationTwoFactorVersion)) {
            $this->destroySession();
            return false;
        }

        if (!session_regenerate_id(true)) {
            $this->destroySession();
            return false;
        }
        $_SESSION['two_factor_version'] = $postMutationTwoFactorVersion;
        $_SESSION['last_activity'] = time();
        return true;
    }

    private function currentSessionMatchesAuthenticationState(
        int $userId,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ): bool {
        return $userId > 0 &&
            isset(
                $_SESSION['user_id'],
                $_SESSION['logged_in'],
                $_SESSION['auth_version'],
                $_SESSION['two_factor_version']
            ) &&
            $_SESSION['logged_in'] === true &&
            (int)$_SESSION['user_id'] === $userId &&
            is_string($_SESSION['auth_version']) &&
            is_string($_SESSION['two_factor_version']) &&
            $this->isAuthenticationVersion($expectedAuthVersion) &&
            $this->isAuthenticationVersion($expectedTwoFactorVersion) &&
            hash_equals($expectedAuthVersion, $_SESSION['auth_version']) &&
            hash_equals($expectedTwoFactorVersion, $_SESSION['two_factor_version']);
    }

    private function isAuthenticationVersion(string $version): bool {
        return preg_match('/^[a-f0-9]{64}$/D', $version) === 1;
    }

    public function updateUserOnlineStatus($user_id, $is_online) {
        return $this->updateOnlineStatus($user_id, $is_online);
    }
    
    public function getUserById($user_id) {
        try {
            $stmt = $this->conn->prepare("SELECT id, username, email, first_name, last_name, avatar, bio, is_online, last_seen FROM users WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 1) {
                return $result->fetch_assoc();
            }
            return null;
        } catch (Exception $e) {
            error_log("Get user error: " . $e->getMessage());
            return null;
        }
    }
    
    public function verifyLogin2FA(
        $user_id,
        $code,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ) {
        require_once __DIR__ . '/TwoFactor.php';
        
        try {
            if (!$this->pendingLoginStateMatches(
                (int)$user_id,
                $expectedAuthVersion,
                $expectedTwoFactorVersion
            )) {
                return [
                    'success' => false,
                    'message' => 'Authentication state changed. Please login again.',
                    'stale' => true
                ];
            }

            $twoFA = new TwoFactorAuthentication();
            // Recheck the saved password/2FA versions under the factor
            // transaction's row lock, then consume either a TOTP step or a
            // one-time recovery code.
            $verification = $twoFA->verifyAndConsumeSecondFactorForAuthenticationState(
                (int)$user_id,
                (string)$code,
                $expectedAuthVersion,
                $expectedTwoFactorVersion
            );

            if ($verification['success']) {
                return ['success' => true];
            }
            if ($verification['reason'] === 'stale') {
                return [
                    'success' => false,
                    'message' => 'Authentication state changed. Please login again.',
                    'stale' => true
                ];
            }
            if ($verification['reason'] === 'failure') {
                return [
                    'success' => false,
                    'message' => 'Verification is temporarily unavailable. Please try again.',
                    'internal_error' => true
                ];
            }
            return ['success' => false, 'message' => 'Invalid 2FA code'];
        } catch (Throwable $e) {
            error_log("2FA Login Verification Error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Verification is temporarily unavailable. Please try again.',
                'internal_error' => true
            ];
        }
    }

    private function pendingLoginStateMatches(
        int $user_id,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ): bool {
        if ($user_id < 1 || $expectedAuthVersion === '' || $expectedTwoFactorVersion === '') {
            return false;
        }

        $stmt = $this->conn->prepare("
            SELECT id, password_hash, two_factor_enabled, two_factor_secret
            FROM users
            WHERE id = ?
        ");
        $stmt->bind_param("i", $user_id);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to verify pending authentication state');
        }
        $result = $stmt->get_result();
        if ($result->num_rows !== 1) {
            return false;
        }

        $versions = $this->pendingVersionsForUser($result->fetch_assoc());
        return $versions !== null &&
            hash_equals($expectedAuthVersion, $versions['auth']) &&
            hash_equals($expectedTwoFactorVersion, $versions['two_factor']);
    }

    /** @return array{auth: string, two_factor: string}|null */
    private function pendingVersionsForUser(array $user): ?array {
        $passwordHash = $user['password_hash'] ?? null;
        $factorState = $user['two_factor_enabled'] ?? null;
        if (!is_string($passwordHash) || $passwordHash === '' ||
            !in_array($factorState, [0, 1, '0', '1'], true)) {
            return null;
        }

        try {
            return [
                'auth' => self::passwordAuthenticationVersion($passwordHash),
                'two_factor' => self::twoFactorAuthenticationVersion(
                    (int)$factorState,
                    is_string($user['two_factor_secret'] ?? null)
                        ? $user['two_factor_secret']
                        : null,
                    is_numeric($user['id'] ?? null) ? (int)$user['id'] : 0
                )
            ];
        } catch (InvalidArgumentException $e) {
            return null;
        }
    }
    
    public function __destruct() {
        if ($this->conn) {
            $this->conn->close();
        }
    }
}
?>
