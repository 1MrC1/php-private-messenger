<?php
// classes/TwoFactor.php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/TotpSecret.php';

use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\Algorithm;
use RobThree\Auth\Providers\Qr\EndroidQrCodeProvider;

class TwoFactorAuthentication {
    private $db;
    private $conn;
    private $tfa;
    
    public function __construct() {
        $this->db = new Database();
        $this->conn = $this->db->connect();
        
        // v3.0 constructor with proper Algorithm enum
        try {
            $qrCodeProvider = new EndroidQrCodeProvider();
            $this->tfa = new TwoFactorAuth(
                qrcodeprovider: $qrCodeProvider,
                issuer: 'Messenger',
                digits: 6,
                period: 30,
                algorithm: Algorithm::Sha1  // Use Algorithm enum instead of string
            );
        } catch (Exception $e) {
            error_log("TwoFactorAuth initialization error: " . $e->getMessage());
            throw new Exception("Failed to initialize 2FA: " . $e->getMessage());
        }
    }
    
    public function generateSecret(int $bits = 160): string {
        return $this->tfa->createSecret($bits);
    }
    
    public function generateQRCode(string $label, string $secret, int $size = 200): ?string {
        try {
            return $this->tfa->getQRCodeImageAsDataUri($label, $secret, $size);
        } catch (Exception $e) {
            error_log("QR Code generation error: " . $e->getMessage());
            return null;
        }
    }
    
    public function getQRText(string $label, string $secret): string {
        return $this->tfa->getQRText($label, $secret);
    }
    
    public function getManualEntryKey(string $secret): string {
        return chunk_split($secret, 4, ' ');
    }
    
    public function verifyCode(string $secret, string $code, int $discrepancy = 1): bool {
        return $this->verifiedTimeStep($secret, $code, $discrepancy) !== null;
    }

    /**
     * Return the exact TOTP time-step accepted by the authenticator library.
     * Callers that authenticate an enabled account must persist this value via
     * verifyAndConsumeSecondFactor() rather than trusting this pure check.
     */
    public function verifiedTimeStep(string $secret, string $code, int $discrepancy = 1): ?int {
        if (!preg_match('/^[A-Z2-7]{16,64}$/i', $secret) || !preg_match('/^\d{6}$/', trim($code))) {
            return null;
        }

        try {
            $timeStep = 0;
            $isValid = $this->tfa->verifyCode(
                strtoupper($secret),
                trim($code),
                $discrepancy,
                null,
                $timeStep
            );
            return $isValid && $timeStep > 0 ? $timeStep : null;
        } catch (Throwable $e) {
            error_log("2FA code verification error: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Enable 2FA and replace the user's recovery codes atomically. The setup
     * TOTP step is recorded as consumed so it cannot authorize another action.
     *
     * The expected versions come from the authenticated session and are
     * compared while the users row is locked. This prevents a setup flow that
     * started before another credential mutation from enabling a new secret.
     *
     * @return array{success: bool, reason: string, codes?: array<int, string>, auth_version?: string, two_factor_version?: string}
     */
    public function enable2FAWithBackupCodes(
        int $user_id,
        string $secret,
        int $verifiedTimeStep,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ): array {
        $secret = strtoupper(trim($secret));
        if ($user_id < 1 || $verifiedTimeStep < 1 ||
            !preg_match('/^[A-Z2-7]{16,64}$/', $secret) ||
            !$this->isAuthenticationVersion($expectedAuthVersion) ||
            !$this->isAuthenticationVersion($expectedTwoFactorVersion)) {
            return $this->operationResult(false, 'stale');
        }

        try {
            $codes = $this->createBackupCodes();
            $storedSecret = TotpSecret::encryptForUser($user_id, $secret);
            if (!$this->conn->begin_transaction()) {
                throw new RuntimeException('Unable to start 2FA enrollment');
            }

            $user = $this->lockAuthenticationState($user_id);
            if ($user === null || !$this->authenticationStateMatches(
                $user,
                $expectedAuthVersion,
                $expectedTwoFactorVersion
            )) {
                $this->conn->rollback();
                return $this->operationResult(false, 'stale');
            }
            $factorState = $this->validatedFactorState($user);
            if ($factorState === null) {
                throw new RuntimeException('Invalid 2FA account state');
            }
            if ($factorState) {
                $this->conn->rollback();
                return $this->operationResult(false, 'already_enabled');
            }

            $stmt = $this->conn->prepare("
                UPDATE users
                SET two_factor_secret = ?, two_factor_enabled = 1,
                    two_factor_last_used_step = ?, updated_at = NOW()
                WHERE id = ? AND two_factor_enabled = 0
            ");
            $stmt->bind_param("sii", $storedSecret, $verifiedTimeStep, $user_id);
            if (!$stmt->execute() || $stmt->affected_rows !== 1) {
                throw new RuntimeException('Unable to enable 2FA');
            }

            $user['two_factor_secret'] = $storedSecret;
            $user['two_factor_enabled'] = 1;
            $versions = $this->authenticationVersionsForLockedUser($user);
            if ($versions === null) {
                throw new RuntimeException('Unable to derive enrolled authentication state');
            }
            $this->replaceBackupCodesWithinTransaction($user_id, $codes);
            if (!$this->conn->commit()) {
                throw new RuntimeException('Unable to commit 2FA enrollment');
            }
            return [
                'success' => true,
                'reason' => 'success',
                'codes' => $codes,
                'auth_version' => $versions['auth'],
                'two_factor_version' => $versions['two_factor']
            ];
        } catch (Throwable $e) {
            $this->rollbackQuietly();
            error_log("Enable 2FA error: " . $e->getMessage());
            return $this->operationResult(false, 'failure');
        }
    }
    
    /**
     * Return only the validated factor state needed by enrollment guards.
     * Decrypted TOTP seeds never leave this class.
     *
     * @return array{two_factor_enabled: bool, two_factor_last_used_step: ?int}|null
     */
    public function getUserFactorState(int $user_id): ?array {
        try {
            $stmt = $this->conn->prepare("
                SELECT two_factor_secret, two_factor_enabled, two_factor_last_used_step
                FROM users WHERE id = ?
            ");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 1) {
                $data = $result->fetch_assoc();
                if (!in_array($data['two_factor_enabled'] ?? null, [0, 1, '0', '1'], true)) {
                    return null;
                }
                $enabled = (int)$data['two_factor_enabled'] === 1;
                $secret = $enabled
                    ? TotpSecret::decryptForUser($user_id, is_string($data['two_factor_secret'] ?? null)
                        ? $data['two_factor_secret']
                        : null)
                    : null;
                if ($enabled && $secret === null) {
                    return null;
                }
                return [
                    'two_factor_enabled' => $enabled,
                    'two_factor_last_used_step' => $data['two_factor_last_used_step'] === null
                        ? null
                        : (int)$data['two_factor_last_used_step']
                ];
            }
            return null;
        } catch (Throwable $e) {
            error_log("Get user factor state error: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Change a password under one account-row lock. If a second factor is
     * enabled, consuming it and updating the password share the transaction so
     * either both changes commit or neither does.
     *
     * @return array{success: bool, reason: string, auth_version?: string, two_factor_version?: string}
     */
    public function changePasswordWithCredentials(
        int $user_id,
        string $currentPassword,
        string $newPasswordHash,
        ?string $code,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ): array {
        if ($user_id < 1 || $newPasswordHash === '' ||
            strlen($currentPassword) > 1024 || strlen($newPasswordHash) > 255 ||
            !$this->isAuthenticationVersion($expectedAuthVersion) ||
            !$this->isAuthenticationVersion($expectedTwoFactorVersion)) {
            return $this->operationResult(false, 'invalid');
        }

        try {
            if (!$this->conn->begin_transaction()) {
                throw new RuntimeException('Unable to start password change');
            }

            $user = $this->lockAuthenticationState($user_id);
            if ($user === null) {
                $this->conn->rollback();
                return $this->operationResult(false, 'not_found');
            }
            if (!$this->authenticationStateMatches(
                $user,
                $expectedAuthVersion,
                $expectedTwoFactorVersion
            )) {
                $this->conn->rollback();
                return $this->operationResult(false, 'stale');
            }
            if (!is_string($user['password_hash'] ?? null) ||
                !password_verify($currentPassword, $user['password_hash'])) {
                $this->conn->rollback();
                return $this->operationResult(false, 'password');
            }

            $factorState = $this->validatedFactorState($user);
            if ($factorState === null) {
                throw new RuntimeException('Invalid 2FA account state');
            }
            if ($factorState) {
                $normalizedCode = $this->normalizeSecondFactorCode($code);
                if ($normalizedCode === null) {
                    $this->conn->rollback();
                    return $this->operationResult(false, $code === null || trim($code) === ''
                        ? 'factor_required'
                        : 'factor');
                }
                if (!$this->consumeSecondFactorWithinTransaction($user_id, $normalizedCode, $user)) {
                    $this->conn->rollback();
                    return $this->operationResult(false, 'factor');
                }
            }

            $stmt = $this->conn->prepare("
                UPDATE users
                SET password_hash = ?, updated_at = NOW()
                WHERE id = ?
            ");
            $stmt->bind_param("si", $newPasswordHash, $user_id);
            if (!$stmt->execute() || $stmt->affected_rows !== 1) {
                throw new RuntimeException('Unable to update password');
            }

            $user['password_hash'] = $newPasswordHash;
            $versions = $this->authenticationVersionsForLockedUser($user);
            if ($versions === null) {
                throw new RuntimeException('Unable to derive changed authentication state');
            }
            if (!$this->conn->commit()) {
                throw new RuntimeException('Unable to commit password change');
            }
            return [
                'success' => true,
                'reason' => 'success',
                'auth_version' => $versions['auth'],
                'two_factor_version' => $versions['two_factor']
            ];
        } catch (Throwable $e) {
            $this->rollbackQuietly();
            error_log("Atomic password change error: " . $e->getMessage());
            return $this->operationResult(false, 'failure');
        }
    }

    /**
     * Verify the account password and a fresh factor, then disable 2FA and
     * remove recovery codes in the same transaction.
     *
     * @return array{success: bool, reason: string, auth_version?: string, two_factor_version?: string}
     */
    public function disable2FAWithCredentials(
        int $user_id,
        string $currentPassword,
        ?string $code,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ): array {
        if ($user_id < 1 || $currentPassword === '' || strlen($currentPassword) > 1024 ||
            !$this->isAuthenticationVersion($expectedAuthVersion) ||
            !$this->isAuthenticationVersion($expectedTwoFactorVersion)) {
            return $this->operationResult(false, 'invalid');
        }

        try {
            if (!$this->conn->begin_transaction()) {
                throw new RuntimeException('Unable to start authenticated 2FA disable');
            }

            $user = $this->lockAuthenticationState($user_id);
            if ($user === null) {
                $this->conn->rollback();
                return $this->operationResult(false, 'not_found');
            }
            if (!$this->authenticationStateMatches(
                $user,
                $expectedAuthVersion,
                $expectedTwoFactorVersion
            )) {
                $this->conn->rollback();
                return $this->operationResult(false, 'stale');
            }
            if (!is_string($user['password_hash'] ?? null) ||
                !password_verify($currentPassword, $user['password_hash'])) {
                $this->conn->rollback();
                return $this->operationResult(false, 'password');
            }

            $factorState = $this->validatedFactorState($user);
            if ($factorState === null) {
                throw new RuntimeException('Invalid 2FA account state');
            }
            if (!$factorState) {
                $this->conn->rollback();
                return $this->operationResult(false, 'not_enabled');
            }

            $normalizedCode = $this->normalizeSecondFactorCode($code);
            if ($normalizedCode === null) {
                $this->conn->rollback();
                return $this->operationResult(false, $code === null || trim($code) === ''
                    ? 'factor_required'
                    : 'factor');
            }
            if (!$this->consumeSecondFactorWithinTransaction($user_id, $normalizedCode, $user)) {
                $this->conn->rollback();
                return $this->operationResult(false, 'factor');
            }

            $stmt = $this->conn->prepare("
                UPDATE users
                SET two_factor_secret = NULL, two_factor_enabled = 0,
                    two_factor_last_used_step = NULL, updated_at = NOW()
                WHERE id = ? AND two_factor_enabled = 1
            ");
            $stmt->bind_param("i", $user_id);
            if (!$stmt->execute() || $stmt->affected_rows !== 1) {
                throw new RuntimeException('Unable to disable 2FA');
            }

            $stmt = $this->conn->prepare("DELETE FROM backup_codes WHERE user_id = ?");
            $stmt->bind_param("i", $user_id);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to remove backup codes');
            }

            $user['two_factor_secret'] = null;
            $user['two_factor_enabled'] = 0;
            $versions = $this->authenticationVersionsForLockedUser($user);
            if ($versions === null) {
                throw new RuntimeException('Unable to derive disabled authentication state');
            }
            if (!$this->conn->commit()) {
                throw new RuntimeException('Unable to commit authenticated 2FA disable');
            }
            return [
                'success' => true,
                'reason' => 'success',
                'auth_version' => $versions['auth'],
                'two_factor_version' => $versions['two_factor']
            ];
        } catch (Throwable $e) {
            $this->rollbackQuietly();
            error_log("Authenticated 2FA disable error: " . $e->getMessage());
            return $this->operationResult(false, 'failure');
        }
    }

    /**
     * Rotate recovery codes only after password and fresh-factor verification.
     * The account lock serializes concurrent rotations and factor consumption
     * is rolled back if replacement-code storage fails.
     *
     * @return array{success: bool, reason: string, codes?: array<int, string>, auth_version?: string, two_factor_version?: string}
     */
    public function rotateBackupCodesWithCredentials(
        int $user_id,
        string $currentPassword,
        ?string $code,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ): array {
        if ($user_id < 1 || $currentPassword === '' || strlen($currentPassword) > 1024 ||
            !$this->isAuthenticationVersion($expectedAuthVersion) ||
            !$this->isAuthenticationVersion($expectedTwoFactorVersion)) {
            return $this->operationResult(false, 'invalid');
        }

        try {
            $codes = $this->createBackupCodes();
            if (!$this->conn->begin_transaction()) {
                throw new RuntimeException('Unable to start authenticated recovery-code rotation');
            }

            $user = $this->lockAuthenticationState($user_id);
            if ($user === null) {
                $this->conn->rollback();
                return $this->operationResult(false, 'not_found');
            }
            if (!$this->authenticationStateMatches(
                $user,
                $expectedAuthVersion,
                $expectedTwoFactorVersion
            )) {
                $this->conn->rollback();
                return $this->operationResult(false, 'stale');
            }
            if (!is_string($user['password_hash'] ?? null) ||
                !password_verify($currentPassword, $user['password_hash'])) {
                $this->conn->rollback();
                return $this->operationResult(false, 'password');
            }

            $factorState = $this->validatedFactorState($user);
            if ($factorState === null) {
                throw new RuntimeException('Invalid 2FA account state');
            }
            if (!$factorState) {
                $this->conn->rollback();
                return $this->operationResult(false, 'not_enabled');
            }

            $normalizedCode = $this->normalizeSecondFactorCode($code);
            if ($normalizedCode === null) {
                $this->conn->rollback();
                return $this->operationResult(false, $code === null || trim($code) === ''
                    ? 'factor_required'
                    : 'factor');
            }
            if (!$this->consumeSecondFactorWithinTransaction($user_id, $normalizedCode, $user)) {
                $this->conn->rollback();
                return $this->operationResult(false, 'factor');
            }

            $versions = $this->authenticationVersionsForLockedUser($user);
            if ($versions === null) {
                throw new RuntimeException('Unable to derive rotated authentication state');
            }
            $this->replaceBackupCodesWithinTransaction($user_id, $codes);
            if (!$this->conn->commit()) {
                throw new RuntimeException('Unable to commit authenticated recovery-code rotation');
            }
            return [
                'success' => true,
                'reason' => 'success',
                'codes' => $codes,
                'auth_version' => $versions['auth'],
                'two_factor_version' => $versions['two_factor']
            ];
        } catch (Throwable $e) {
            $this->rollbackQuietly();
            error_log("Authenticated backup-code rotation error: " . $e->getMessage());
            return $this->operationResult(false, 'failure');
        }
    }

    /**
     * Verify and durably consume one fresh factor. TOTP steps are advanced
     * atomically; recovery codes are marked used under a row lock.
     */
    public function verifyAndConsumeSecondFactor(int $user_id, string $code): bool {
        $normalizedCode = $this->normalizeSecondFactorCode($code);
        if ($user_id < 1 || $normalizedCode === null) {
            return false;
        }

        try {
            if (!$this->conn->begin_transaction()) {
                throw new RuntimeException('Unable to start second-factor verification');
            }
            $user = $this->lockAuthenticationState($user_id);
            if ($user === null || $this->validatedFactorState($user) !== true ||
                !$this->consumeSecondFactorWithinTransaction($user_id, $normalizedCode, $user)) {
                $this->conn->rollback();
                return false;
            }

            if (!$this->conn->commit()) {
                throw new RuntimeException('Unable to commit second-factor verification');
            }
            return true;
        } catch (Throwable $e) {
            $this->rollbackQuietly();
            error_log("Consume second factor error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Login-specific factor verification. Saved password/2FA versions are
     * compared while holding the same row lock used to consume the factor, so
     * an intervening credential change cannot consume a code for a stale flow.
     *
     * @return array{success: bool, reason: string}
     */
    public function verifyAndConsumeSecondFactorForAuthenticationState(
        int $user_id,
        string $code,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ): array {
        $normalizedCode = $this->normalizeSecondFactorCode($code);
        if ($user_id < 1 || $normalizedCode === null ||
            preg_match('/^[a-f0-9]{64}$/D', $expectedAuthVersion) !== 1 ||
            preg_match('/^[a-f0-9]{64}$/D', $expectedTwoFactorVersion) !== 1) {
            return $this->operationResult(false, 'factor');
        }

        try {
            if (!$this->conn->begin_transaction()) {
                throw new RuntimeException('Unable to start state-bound factor verification');
            }
            $user = $this->lockAuthenticationState($user_id);
            if ($user === null) {
                $this->conn->rollback();
                return $this->operationResult(false, 'stale');
            }

            $versions = $this->authenticationVersionsForLockedUser($user);
            if ($versions === null ||
                !hash_equals($expectedAuthVersion, $versions['auth']) ||
                !hash_equals($expectedTwoFactorVersion, $versions['two_factor'])) {
                $this->conn->rollback();
                return $this->operationResult(false, 'stale');
            }
            if ($this->validatedFactorState($user) !== true ||
                !$this->consumeSecondFactorWithinTransaction($user_id, $normalizedCode, $user)) {
                $this->conn->rollback();
                return $this->operationResult(false, 'factor');
            }

            if (!$this->conn->commit()) {
                throw new RuntimeException('Unable to commit state-bound factor verification');
            }
            return $this->operationResult(true, 'success');
        } catch (Throwable $e) {
            $this->rollbackQuietly();
            error_log("State-bound factor verification error: " . $e->getMessage());
            return $this->operationResult(false, 'failure');
        }
    }

    public function verifyAndConsumeTotp(int $user_id, string $code): bool {
        return preg_match('/^\d{6}$/', trim($code)) === 1 &&
            $this->verifyAndConsumeSecondFactor($user_id, trim($code));
    }

    public function verifyBackupCode(int $user_id, string $code): bool {
        $normalizedCode = strtoupper(trim($code));
        return preg_match('/^[A-F0-9]{8}$/', $normalizedCode) === 1 &&
            $this->verifyAndConsumeSecondFactor($user_id, $normalizedCode);
    }

    /** @return array<string, mixed>|null */
    private function lockAuthenticationState(int $user_id): ?array {
        $stmt = $this->conn->prepare("
            SELECT id, password_hash, two_factor_secret, two_factor_enabled,
                   two_factor_last_used_step
            FROM users
            WHERE id = ?
            FOR UPDATE
        ");
        $stmt->bind_param("i", $user_id);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to lock authentication state');
        }
        $result = $stmt->get_result();
        return $result->num_rows === 1 ? $result->fetch_assoc() : null;
    }

    private function validatedFactorState(array $user): ?bool {
        $state = $user['two_factor_enabled'] ?? null;
        if (!in_array($state, [0, 1, '0', '1'], true)) {
            return null;
        }
        if ((int)$state === 1 && TotpSecret::decryptForUser(
            (int)($user['id'] ?? 0),
            is_string($user['two_factor_secret'] ?? null) ? $user['two_factor_secret'] : null
        ) === null) {
            return null;
        }
        return (int)$state === 1;
    }

    /** @return array{auth: string, two_factor: string}|null */
    private function authenticationVersionsForLockedUser(array $user): ?array {
        $passwordHash = $user['password_hash'] ?? null;
        $factorState = $user['two_factor_enabled'] ?? null;
        if (!is_string($passwordHash) || $passwordHash === '' ||
            !in_array($factorState, [0, 1, '0', '1'], true)) {
            return null;
        }

        $enabled = (int)$factorState;
        $secret = $enabled === 1
            ? TotpSecret::decryptForUser(
                (int)($user['id'] ?? 0),
                is_string($user['two_factor_secret'] ?? null) ? $user['two_factor_secret'] : null
            )
            : null;
        if ($enabled === 1 && ($secret === null || $secret === '')) {
            return null;
        }

        return [
            'auth' => hash('sha256', $passwordHash),
            'two_factor' => hash(
                'sha256',
                "pm-2fa-state\0" . $enabled . "\0" . ($secret ?? '')
            )
        ];
    }

    private function isAuthenticationVersion(string $version): bool {
        return preg_match('/^[a-f0-9]{64}$/D', $version) === 1;
    }

    private function authenticationStateMatches(
        array $user,
        string $expectedAuthVersion,
        string $expectedTwoFactorVersion
    ): bool {
        $versions = $this->authenticationVersionsForLockedUser($user);
        return $versions !== null &&
            hash_equals($expectedAuthVersion, $versions['auth']) &&
            hash_equals($expectedTwoFactorVersion, $versions['two_factor']);
    }

    private function normalizeSecondFactorCode(?string $code): ?string {
        if ($code === null) {
            return null;
        }
        $normalized = strtoupper(trim($code));
        return preg_match('/^(?:\d{6}|[A-F0-9]{8})$/', $normalized) === 1
            ? $normalized
            : null;
    }

    /**
     * Consume a factor while the caller holds the users row lock and owns the
     * surrounding transaction. This method deliberately never commits.
     *
     * @param array<string, mixed> $user
     */
    private function consumeSecondFactorWithinTransaction(int $user_id, string $code, array $user): bool {
        if (preg_match('/^\d{6}$/', $code) === 1) {
            $secret = TotpSecret::decryptForUser(
                $user_id,
                is_string($user['two_factor_secret'] ?? null) ? $user['two_factor_secret'] : null
            );
            if ($secret === null) {
                return false;
            }
            $timeStep = $this->verifiedTimeStep($secret, $code);
            $lastUsedStep = $user['two_factor_last_used_step'] ?? null;
            if ($timeStep === null ||
                ($lastUsedStep !== null &&
                    (!is_numeric($lastUsedStep) || (int)$lastUsedStep >= $timeStep))) {
                return false;
            }

            $stmt = $this->conn->prepare("
                UPDATE users
                SET two_factor_last_used_step = ?
                WHERE id = ? AND two_factor_enabled = 1
                  AND (two_factor_last_used_step IS NULL OR two_factor_last_used_step < ?)
            ");
            $stmt->bind_param("iii", $timeStep, $user_id, $timeStep);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to consume TOTP step');
            }
            return $stmt->affected_rows === 1;
        }

        $stmt = $this->conn->prepare("
            SELECT id, code
            FROM backup_codes
            WHERE user_id = ? AND used = 0
              AND BINARY LEFT(code, 2) = BINARY 'H$'
            FOR UPDATE
        ");
        $stmt->bind_param("i", $user_id);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to verify backup code');
        }

        $result = $stmt->get_result();
        $expectedVerifier = null;
        while ($backup = $result->fetch_assoc()) {
            $storedCode = (string)$backup['code'];
            if (preg_match('/\AH\$[A-F0-9]{8}\z/D', $storedCode) !== 1) {
                continue;
            }
            $expectedVerifier ??= $this->backupCodeVerifier($code);
            $matches = hash_equals($storedCode, $expectedVerifier);

            if (!$matches) {
                continue;
            }

            $stmt = $this->conn->prepare(
                "UPDATE backup_codes SET used = 1, used_at = NOW() WHERE id = ? AND used = 0"
            );
            $stmt->bind_param("i", $backup['id']);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to consume backup code');
            }
            return $stmt->affected_rows === 1;
        }

        return false;
    }

    /** @return array{success: bool, reason: string} */
    private function operationResult(bool $success, string $reason): array {
        return ['success' => $success, 'reason' => $reason];
    }

    private function backupCodeVerifier(string $code): string {
        $key = Database::backupCodePepper();
        // Ten characters fit the existing varchar(10): the H$ marker plus
        // eight keyed hex characters. The input itself has 32 bits of entropy.
        return 'H$' . strtoupper(substr(hash_hmac('sha256', strtoupper(trim($code)), $key), 0, 8));
    }

    /** @return array<int, string> */
    private function createBackupCodes(): array {
        $codes = [];
        $uniqueCodes = [];
        $uniqueVerifiers = [];
        while (count($codes) < 10) {
            $code = strtoupper(bin2hex(random_bytes(4)));
            $verifier = $this->backupCodeVerifier($code);
            // Prefix the lookup key so an all-numeric recovery code cannot be
            // coerced by PHP into an integer array key and returned as JSON
            // number instead of an exact eight-character string.
            $lookupKey = 'C$' . $code;
            if (isset($uniqueCodes[$lookupKey]) || isset($uniqueVerifiers[$verifier])) {
                continue;
            }
            $uniqueCodes[$lookupKey] = true;
            $uniqueVerifiers[$verifier] = true;
            $codes[] = $code;
        }
        return $codes;
    }

    /** @param array<int, string> $codes */
    private function replaceBackupCodesWithinTransaction(int $user_id, array $codes): void {
        $stmt = $this->conn->prepare("DELETE FROM backup_codes WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        if (!$stmt->execute()) {
            throw new RuntimeException('Unable to replace backup codes');
        }

        $stmt = $this->conn->prepare("INSERT INTO backup_codes (user_id, code, used) VALUES (?, ?, 0)");
        foreach ($codes as $code) {
            // Store only a keyed verifier; plaintext is returned once and is
            // never persisted in the database.
            $storedCode = $this->backupCodeVerifier($code);
            $stmt->bind_param("is", $user_id, $storedCode);
            if (!$stmt->execute()) {
                throw new RuntimeException('Unable to store backup code');
            }
        }
    }

    private function rollbackQuietly(): void {
        try {
            $this->conn->rollback();
        } catch (Throwable $ignored) {
        }
    }
    
    public function ensureCorrectTime(): bool {
        try {
            $this->tfa->ensureCorrectTime();
            return true;
        } catch (Exception $e) {
            error_log("Time synchronization error: " . $e->getMessage());
            return false;
        }
    }
    
    public function __destruct() {
        if ($this->db) {
            $this->db->close();
        }
    }
}
?>
