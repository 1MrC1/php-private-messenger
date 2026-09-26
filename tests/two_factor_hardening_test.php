<?php
declare(strict_types=1);

require_once __DIR__ . '/../classes/TwoFactor.php';
require_once __DIR__ . '/../classes/Auth.php';

// One rollback case intentionally triggers the class's operational error log.
ini_set('error_log', '/dev/null');

function hardeningAssert(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

final class HardeningFakeTotp {
    public int $timeStep = 1000;

    public function verifyCode(
        string $secret,
        string $code,
        int $discrepancy = 1,
        ?int $time = null,
        ?int &$timeStep = 0
    ): bool {
        $isValid = $secret === 'ABCDEFGHIJKLMNOP' && $code === '123456';
        $timeStep = $isValid ? $this->timeStep : 0;
        return $isValid;
    }
}

final class HardeningFakeResult {
    public int $num_rows;
    private int $offset = 0;

    /** @param array<int, array<string, mixed>> $rows */
    public function __construct(private array $rows) {
        $this->num_rows = count($rows);
    }

    public function fetch_assoc(): ?array {
        return $this->rows[$this->offset++] ?? null;
    }
}

final class HardeningFakeConnection {
    /** @var array<string, mixed> */
    public array $user = [
        'id' => 7,
        'password_hash' => '',
        'two_factor_secret' => 'ABCDEFGHIJKLMNOP',
        'two_factor_enabled' => 1,
        'two_factor_last_used_step' => null,
    ];
    /** @var array<int, string> */
    public array $backupCodes = [];
    /** @var array<int, bool> */
    public array $usedBackupCodes = [];
    public int $commitCount = 0;
    public int $rollbackCount = 0;
    public ?int $failInsertAt = null;
    public int $insertCount = 0;
    public bool $failPasswordUpdate = false;
    public bool $failDisableUpdate = false;
    /** @var array<int, string> */
    public array $preparedSql = [];
    /** @var array<string, mixed>|null */
    private ?array $snapshot = null;

    public function __construct() {
        $passwordHash = password_hash('correct horse battery staple', PASSWORD_DEFAULT);
        if (!is_string($passwordHash)) {
            throw new RuntimeException('Unable to create test password hash');
        }
        $this->user['password_hash'] = $passwordHash;
        $this->user['two_factor_secret'] = TotpSecret::encryptForUser(7, 'ABCDEFGHIJKLMNOP');
    }

    public function begin_transaction(): bool {
        $this->snapshot = [
            'user' => $this->user,
            'backup_codes' => $this->backupCodes,
            'used_backup_codes' => $this->usedBackupCodes,
            'insert_count' => $this->insertCount,
        ];
        return true;
    }

    public function commit(): bool {
        $this->commitCount++;
        $this->snapshot = null;
        return true;
    }

    public function rollback(): bool {
        $this->rollbackCount++;
        if ($this->snapshot !== null) {
            $this->user = $this->snapshot['user'];
            $this->backupCodes = $this->snapshot['backup_codes'];
            $this->usedBackupCodes = $this->snapshot['used_backup_codes'];
            $this->insertCount = $this->snapshot['insert_count'];
            $this->snapshot = null;
        }
        return true;
    }

    public function prepare(string $sql): HardeningFakeStatement {
        $normalized = preg_replace('/\s+/', ' ', trim($sql));
        $this->preparedSql[] = $normalized;
        return new HardeningFakeStatement($this, $normalized);
    }

    public function close(): void {}
}

final class HardeningFakeStatement {
    public int $affected_rows = 0;
    /** @var array<int, mixed> */
    private array $values = [];
    private ?HardeningFakeResult $result = null;

    public function __construct(
        private HardeningFakeConnection $connection,
        private string $sql
    ) {}

    public function bind_param(string $types, &...$values): bool {
        foreach ($values as $index => &$value) {
            $this->values[$index] =& $value;
        }
        return true;
    }

    public function execute(): bool {
        $this->affected_rows = 0;

        if (str_starts_with(
            $this->sql,
            'SELECT id, password_hash, two_factor_secret, two_factor_enabled, two_factor_last_used_step'
        ) || str_starts_with(
            $this->sql,
            'SELECT id, username, email, password_hash, first_name, last_name, avatar, bio, two_factor_enabled, two_factor_secret'
        ) || str_starts_with(
            $this->sql,
            'SELECT id, password_hash, two_factor_enabled, two_factor_secret FROM users'
        ) || str_starts_with(
            $this->sql,
            'SELECT two_factor_secret, two_factor_enabled, two_factor_last_used_step'
        )) {
            $this->result = new HardeningFakeResult([$this->connection->user]);
            return true;
        }

        if (str_starts_with($this->sql, 'SELECT id, two_factor_last_used_step FROM users')) {
            $rows = (bool)$this->connection->user['two_factor_enabled']
                ? [[
                    'id' => $this->connection->user['id'],
                    'two_factor_last_used_step' => $this->connection->user['two_factor_last_used_step'],
                ]]
                : [];
            $this->result = new HardeningFakeResult($rows);
            return true;
        }

        if (str_starts_with($this->sql, 'SELECT id, code FROM backup_codes')) {
            $rows = [];
            foreach ($this->connection->backupCodes as $index => $code) {
                if (!($this->connection->usedBackupCodes[$index] ?? false)) {
                    $rows[] = ['id' => $index + 1, 'code' => $code];
                }
            }
            $this->result = new HardeningFakeResult($rows);
            return true;
        }

        if (str_starts_with($this->sql, 'UPDATE users SET two_factor_last_used_step = ?')) {
            $timeStep = (int)$this->values[0];
            $lastStep = $this->connection->user['two_factor_last_used_step'];
            if ((bool)$this->connection->user['two_factor_enabled'] &&
                ($lastStep === null || (int)$lastStep < $timeStep)) {
                $this->connection->user['two_factor_last_used_step'] = $timeStep;
                $this->affected_rows = 1;
            }
            return true;
        }

        if (str_starts_with($this->sql, 'UPDATE users SET two_factor_secret = ?')) {
            if (!(bool)$this->connection->user['two_factor_enabled']) {
                $this->connection->user['two_factor_secret'] = (string)$this->values[0];
                $this->connection->user['two_factor_enabled'] = 1;
                $this->connection->user['two_factor_last_used_step'] = (int)$this->values[1];
                $this->affected_rows = 1;
            }
            return true;
        }

        if (str_starts_with($this->sql, 'UPDATE users SET password_hash = ?')) {
            if ($this->connection->failPasswordUpdate) {
                return false;
            }
            $this->connection->user['password_hash'] = (string)$this->values[0];
            $this->affected_rows = 1;
            return true;
        }

        if (str_starts_with($this->sql, 'UPDATE users SET two_factor_secret = NULL')) {
            if ($this->connection->failDisableUpdate) {
                return false;
            }
            if ((bool)$this->connection->user['two_factor_enabled']) {
                $this->connection->user['two_factor_secret'] = null;
                $this->connection->user['two_factor_enabled'] = 0;
                $this->connection->user['two_factor_last_used_step'] = null;
                $this->affected_rows = 1;
            }
            return true;
        }

        if (str_starts_with($this->sql, 'DELETE FROM backup_codes')) {
            $this->connection->backupCodes = [];
            $this->connection->usedBackupCodes = [];
            return true;
        }

        if (str_starts_with($this->sql, 'INSERT INTO backup_codes')) {
            $this->connection->insertCount++;
            if ($this->connection->failInsertAt === $this->connection->insertCount) {
                return false;
            }
            $this->connection->backupCodes[] = (string)$this->values[1];
            $this->connection->usedBackupCodes[] = false;
            $this->affected_rows = 1;
            return true;
        }

        if (str_starts_with($this->sql, 'UPDATE backup_codes SET used = 1')) {
            $index = (int)$this->values[0] - 1;
            if (isset($this->connection->backupCodes[$index]) &&
                !($this->connection->usedBackupCodes[$index] ?? false)) {
                $this->connection->usedBackupCodes[$index] = true;
                $this->affected_rows = 1;
            }
            return true;
        }

        throw new RuntimeException('Unexpected SQL in test: ' . $this->sql);
    }

    public function get_result(): HardeningFakeResult {
        if (!$this->result) {
            throw new RuntimeException('No fake result is available');
        }
        return $this->result;
    }
}

final class HardeningFakeDatabase {
    public function close(): void {}
}

function hardeningTwoFactor(HardeningFakeConnection $connection, HardeningFakeTotp $totp): TwoFactorAuthentication {
    $reflection = new ReflectionClass(TwoFactorAuthentication::class);
    /** @var TwoFactorAuthentication $twoFactor */
    $twoFactor = $reflection->newInstanceWithoutConstructor();
    foreach (['conn' => $connection, 'tfa' => $totp, 'db' => new HardeningFakeDatabase()] as $name => $value) {
        $property = $reflection->getProperty($name);
        $property->setAccessible(true);
        $property->setValue($twoFactor, $value);
    }
    return $twoFactor;
}

function hardeningAuth(HardeningFakeConnection $connection): Auth {
    $reflection = new ReflectionClass(Auth::class);
    /** @var Auth $auth */
    $auth = $reflection->newInstanceWithoutConstructor();
    $property = $reflection->getProperty('conn');
    $property->setAccessible(true);
    $property->setValue($auth, $connection);
    return $auth;
}

/** @return array{auth: string, two_factor: string} */
function hardeningAuthenticationVersions(HardeningFakeConnection $connection): array {
    return [
        'auth' => Auth::passwordAuthenticationVersion((string)$connection->user['password_hash']),
        'two_factor' => Auth::twoFactorAuthenticationVersion(
            (int)$connection->user['two_factor_enabled'],
            is_string($connection->user['two_factor_secret'])
                ? $connection->user['two_factor_secret']
                : null,
            (int)$connection->user['id']
        )
    ];
}

putenv('PM_BACKUP_CODE_PEPPER=' . str_repeat('p', 32));
putenv('PM_TOTP_ENCRYPTION_KEY=' . base64_encode(str_repeat('t', 32)));

$libraryTotp = new RobThree\Auth\TwoFactorAuth(
    qrcodeprovider: new RobThree\Auth\Providers\Qr\EndroidQrCodeProvider(),
    issuer: 'Messenger',
    digits: 6,
    period: 30,
    algorithm: RobThree\Auth\Algorithm::Sha1
);
$fixedTime = 1700000000;
$libraryCode = $libraryTotp->getCode('JBSWY3DPEHPK3PXP', $fixedTime);
$libraryTimeStep = 0;
hardeningAssert(
    $libraryTotp->verifyCode('JBSWY3DPEHPK3PXP', $libraryCode, 0, $fixedTime, $libraryTimeStep) &&
        $libraryTimeStep === intdiv($fixedTime, 30),
    'installed TOTP library should return the accepted 30-second time-step'
);

$connection = new HardeningFakeConnection();
$totp = new HardeningFakeTotp();
$twoFactor = hardeningTwoFactor($connection, $totp);

hardeningAssert($twoFactor->verifyAndConsumeTotp(7, '123456'), 'first TOTP use should succeed');
hardeningAssert(
    $connection->user['two_factor_last_used_step'] === 1000,
    'accepted TOTP step should be stored durably'
);
hardeningAssert(!$twoFactor->verifyAndConsumeTotp(7, '123456'), 'same TOTP step must be rejected');
hardeningAssert($connection->commitCount === 1, 'only the first TOTP use should commit');
$totp->timeStep = 1001;
hardeningAssert($twoFactor->verifyAndConsumeTotp(7, '123456'), 'a later TOTP step should succeed');
hardeningAssert(
    $connection->user['two_factor_last_used_step'] === 1001,
    'the replay counter should advance monotonically'
);
$totp->timeStep = 999;
hardeningAssert(!$twoFactor->verifyAndConsumeTotp(7, '123456'), 'an older accepted-window step must remain rejected');

$enrollmentConnection = new HardeningFakeConnection();
$enrollmentConnection->user['two_factor_enabled'] = 0;
$enrollmentConnection->user['two_factor_secret'] = null;
$enrollment = hardeningTwoFactor($enrollmentConnection, $totp);
$enrollmentVersions = hardeningAuthenticationVersions($enrollmentConnection);
$enrollmentResult = $enrollment->enable2FAWithBackupCodes(
    7,
    'ABCDEFGHIJKLMNOP',
    2000,
    $enrollmentVersions['auth'],
    $enrollmentVersions['two_factor']
);
$plainCodes = $enrollmentResult['codes'] ?? [];
hardeningAssert(
    $enrollmentResult['success'] && count($plainCodes) === 10,
    'enrollment should return ten recovery codes'
);
hardeningAssert(
    hash_equals($enrollmentVersions['auth'], (string)$enrollmentResult['auth_version']) &&
        hash_equals(
            hardeningAuthenticationVersions($enrollmentConnection)['two_factor'],
            (string)$enrollmentResult['two_factor_version']
        ),
    'enrollment should return the exact post-mutation authentication versions'
);
hardeningAssert(
    count(array_filter(
        $plainCodes,
        fn(mixed $code): bool => is_string($code) && preg_match('/^[A-F0-9]{8}$/D', $code) === 1
    )) === 10,
    'recovery codes must always remain exact eight-character strings'
);
hardeningAssert($enrollmentConnection->user['two_factor_enabled'] === 1, 'enrollment should enable 2FA');
hardeningAssert(
    is_string($enrollmentConnection->user['two_factor_secret']) &&
        TotpSecret::isEncrypted($enrollmentConnection->user['two_factor_secret']) &&
        TotpSecret::decryptForUser(7, $enrollmentConnection->user['two_factor_secret']) === 'ABCDEFGHIJKLMNOP',
    'enrollment should store an authenticated user-bound TOTP envelope'
);
hardeningAssert(
    $enrollmentConnection->user['two_factor_last_used_step'] === 2000,
    'setup TOTP step should be consumed during enrollment'
);
hardeningAssert(count($enrollmentConnection->backupCodes) === 10, 'all recovery verifiers should be stored');
hardeningAssert(
    count(array_filter($enrollmentConnection->backupCodes, fn(string $code): bool => str_starts_with($code, 'H$'))) === 10,
    'database recovery codes should be keyed verifiers'
);
hardeningAssert(
    $enrollment->verifyAndConsumeSecondFactor(7, $plainCodes[0]),
    'an unused recovery code should authenticate once'
);
hardeningAssert(
    !$enrollment->verifyAndConsumeSecondFactor(7, $plainCodes[0]),
    'a consumed recovery code must not authenticate twice'
);
$legacyCodeConnection = new HardeningFakeConnection();
$legacyCodeConnection->backupCodes = ['ABCDEF12'];
$legacyCodeConnection->usedBackupCodes = [false];
$legacyCodes = hardeningTwoFactor($legacyCodeConnection, new HardeningFakeTotp());
hardeningAssert(
    !$legacyCodes->verifyBackupCode(7, 'ABCDEF12') &&
        $legacyCodeConnection->usedBackupCodes === [false],
    'runtime authentication must reject plaintext legacy recovery codes'
);
$lowercaseVerifierConnection = new HardeningFakeConnection();
$lowercaseVerifier = $enrollmentConnection->backupCodes[1];
$lowercaseVerifier[0] = 'h';
$lowercaseVerifierConnection->backupCodes = [$lowercaseVerifier];
$lowercaseVerifierConnection->usedBackupCodes = [false];
$lowercaseVerifierFactor = hardeningTwoFactor($lowercaseVerifierConnection, new HardeningFakeTotp());
hardeningAssert(
    !$lowercaseVerifierFactor->verifyBackupCode(7, $plainCodes[1]) &&
        $lowercaseVerifierConnection->usedBackupCodes === [false],
    'runtime authentication must reject a lowercase recovery-verifier marker'
);
$enrollmentConnection->user['two_factor_enabled'] = 0;
hardeningAssert(
    !$enrollment->verifyBackupCode(7, $plainCodes[1]),
    'a stale recovery row must not authenticate a disabled account'
);

$rollbackConnection = new HardeningFakeConnection();
$rollbackConnection->user['two_factor_enabled'] = 0;
$rollbackConnection->user['two_factor_secret'] = null;
$rollbackConnection->backupCodes = ['existing'];
$rollbackConnection->failInsertAt = 3;
$rollbackEnrollment = hardeningTwoFactor($rollbackConnection, $totp);
$rollbackEnrollmentVersions = hardeningAuthenticationVersions($rollbackConnection);
$rollbackEnrollmentResult = $rollbackEnrollment->enable2FAWithBackupCodes(
    7,
    'ABCDEFGHIJKLMNOP',
    3000,
    $rollbackEnrollmentVersions['auth'],
    $rollbackEnrollmentVersions['two_factor']
);
hardeningAssert(
    !$rollbackEnrollmentResult['success'],
    'failed recovery-code storage should fail enrollment'
);
hardeningAssert($rollbackConnection->user['two_factor_enabled'] === 0, 'failed enrollment must roll back enabled state');
hardeningAssert($rollbackConnection->backupCodes === ['existing'], 'failed enrollment must restore old recovery rows');

$passwordFailureConnection = new HardeningFakeConnection();
$passwordFailureConnection->failPasswordUpdate = true;
$passwordFailureTotp = new HardeningFakeTotp();
$passwordFailureTotp->timeStep = 4000;
$passwordFailure = hardeningTwoFactor($passwordFailureConnection, $passwordFailureTotp);
$replacementHash = password_hash('different correct horse battery staple', PASSWORD_DEFAULT);
hardeningAssert(is_string($replacementHash), 'replacement password hash should be generated');
$originalHash = $passwordFailureConnection->user['password_hash'];
$passwordFailureVersions = hardeningAuthenticationVersions($passwordFailureConnection);
$passwordFailureResult = $passwordFailure->changePasswordWithCredentials(
    7,
    'correct horse battery staple',
    $replacementHash,
    '123456',
    $passwordFailureVersions['auth'],
    $passwordFailureVersions['two_factor']
);
hardeningAssert(!$passwordFailureResult['success'], 'a failed password update should fail the whole operation');
hardeningAssert(
    $passwordFailureConnection->user['two_factor_last_used_step'] === null,
    'failed password update must roll back the consumed TOTP step'
);
hardeningAssert(
    hash_equals($originalHash, $passwordFailureConnection->user['password_hash']),
    'failed password update must preserve the previous password hash'
);

$rotationFailureConnection = new HardeningFakeConnection();
$rotationFailureConnection->backupCodes = ['ABCDEF12'];
$rotationFailureConnection->usedBackupCodes = [false];
$rotationFailureConnection->failInsertAt = 2;
$rotationFailure = hardeningTwoFactor($rotationFailureConnection, new HardeningFakeTotp());
$rotationFailureVersions = hardeningAuthenticationVersions($rotationFailureConnection);
$rotationFailureResult = $rotationFailure->rotateBackupCodesWithCredentials(
    7,
    'correct horse battery staple',
    'ABCDEF12',
    $rotationFailureVersions['auth'],
    $rotationFailureVersions['two_factor']
);
hardeningAssert(!$rotationFailureResult['success'], 'failed recovery-code replacement should fail rotation');
hardeningAssert(
    $rotationFailureConnection->backupCodes === ['ABCDEF12'] &&
        $rotationFailureConnection->usedBackupCodes === [false],
    'failed rotation must restore the factor code consumed inside its transaction'
);

$disableFailureConnection = new HardeningFakeConnection();
$disableFailureConnection->failDisableUpdate = true;
$disableFailureTotp = new HardeningFakeTotp();
$disableFailureTotp->timeStep = 5000;
$disableFailure = hardeningTwoFactor($disableFailureConnection, $disableFailureTotp);
$disableFailureVersions = hardeningAuthenticationVersions($disableFailureConnection);
$disableFailureResult = $disableFailure->disable2FAWithCredentials(
    7,
    'correct horse battery staple',
    '123456',
    $disableFailureVersions['auth'],
    $disableFailureVersions['two_factor']
);
hardeningAssert(!$disableFailureResult['success'], 'failed 2FA mutation should fail authenticated disable');
hardeningAssert(
    $disableFailureConnection->user['two_factor_enabled'] === 1 &&
        $disableFailureConnection->user['two_factor_last_used_step'] === null,
    'failed 2FA disable must roll back both enabled state and consumed TOTP step'
);

$passwordSuccessConnection = new HardeningFakeConnection();
$passwordSuccessTotp = new HardeningFakeTotp();
$passwordSuccessTotp->timeStep = 5500;
$passwordSuccess = hardeningTwoFactor($passwordSuccessConnection, $passwordSuccessTotp);
$passwordSuccessVersions = hardeningAuthenticationVersions($passwordSuccessConnection);
$passwordSuccessResult = $passwordSuccess->changePasswordWithCredentials(
    7,
    'correct horse battery staple',
    $replacementHash,
    '123456',
    $passwordSuccessVersions['auth'],
    $passwordSuccessVersions['two_factor']
);
hardeningAssert(
    $passwordSuccessResult['success'] &&
        password_verify(
            'different correct horse battery staple',
            $passwordSuccessConnection->user['password_hash']
        ) &&
        $passwordSuccessConnection->user['two_factor_last_used_step'] === 5500,
    'successful password change should commit its new hash and consumed factor together'
);
hardeningAssert(
    hash_equals(
        hardeningAuthenticationVersions($passwordSuccessConnection)['auth'],
        (string)$passwordSuccessResult['auth_version']
    ) && hash_equals(
        $passwordSuccessVersions['two_factor'],
        (string)$passwordSuccessResult['two_factor_version']
    ),
    'password change should return only its exact post-mutation versions'
);

$passwordOnlyConnection = new HardeningFakeConnection();
$passwordOnlyConnection->user['two_factor_enabled'] = 0;
$passwordOnlyConnection->user['two_factor_secret'] = null;
$passwordOnly = hardeningTwoFactor($passwordOnlyConnection, new HardeningFakeTotp());
$passwordOnlyVersions = hardeningAuthenticationVersions($passwordOnlyConnection);
$passwordOnlyResult = $passwordOnly->changePasswordWithCredentials(
    7,
    'correct horse battery staple',
    $replacementHash,
    null,
    $passwordOnlyVersions['auth'],
    $passwordOnlyVersions['two_factor']
);
hardeningAssert(
    $passwordOnlyResult['success'] &&
        password_verify(
            'different correct horse battery staple',
            $passwordOnlyConnection->user['password_hash']
        ),
    'accounts without 2FA should retain atomic password-only changes'
);

$disableSuccessConnection = new HardeningFakeConnection();
$disableSuccessConnection->backupCodes = ['ABCDEF12'];
$disableSuccessConnection->usedBackupCodes = [false];
$disableSuccessTotp = new HardeningFakeTotp();
$disableSuccessTotp->timeStep = 5600;
$disableSuccess = hardeningTwoFactor($disableSuccessConnection, $disableSuccessTotp);
$disableSuccessVersions = hardeningAuthenticationVersions($disableSuccessConnection);
$disableSuccessResult = $disableSuccess->disable2FAWithCredentials(
    7,
    'correct horse battery staple',
    '123456',
    $disableSuccessVersions['auth'],
    $disableSuccessVersions['two_factor']
);
hardeningAssert(
    $disableSuccessResult['success'] &&
        $disableSuccessConnection->user['two_factor_enabled'] === 0 &&
        $disableSuccessConnection->user['two_factor_secret'] === null &&
        $disableSuccessConnection->backupCodes === [],
    'authenticated 2FA disable should commit state reset and recovery-code deletion together'
);
hardeningAssert(
    hash_equals($disableSuccessVersions['auth'], (string)$disableSuccessResult['auth_version']) &&
        hash_equals(
            hardeningAuthenticationVersions($disableSuccessConnection)['two_factor'],
            (string)$disableSuccessResult['two_factor_version']
        ),
    '2FA disable should return the exact post-mutation factor version'
);

$staleMutationAuthVersion = Auth::passwordAuthenticationVersion('superseded password state');
$staleMutationFactorVersion = Auth::twoFactorAuthenticationVersion(0, null);

$staleEnrollmentConnection = new HardeningFakeConnection();
$staleEnrollmentConnection->user['two_factor_enabled'] = 0;
$staleEnrollmentConnection->user['two_factor_secret'] = null;
$staleEnrollment = hardeningTwoFactor($staleEnrollmentConnection, new HardeningFakeTotp());
$staleEnrollmentVersions = hardeningAuthenticationVersions($staleEnrollmentConnection);
$staleEnrollmentResult = $staleEnrollment->enable2FAWithBackupCodes(
    7,
    'ABCDEFGHIJKLMNOP',
    5700,
    $staleMutationAuthVersion,
    $staleEnrollmentVersions['two_factor']
);
hardeningAssert(
    !$staleEnrollmentResult['success'] && $staleEnrollmentResult['reason'] === 'stale' &&
        $staleEnrollmentConnection->user['two_factor_enabled'] === 0 &&
        $staleEnrollmentConnection->backupCodes === [],
    'stale enrollment state must fail under the row lock without enabling 2FA'
);

$stalePasswordConnection = new HardeningFakeConnection();
$stalePassword = hardeningTwoFactor($stalePasswordConnection, new HardeningFakeTotp());
$stalePasswordVersions = hardeningAuthenticationVersions($stalePasswordConnection);
$stalePasswordHash = $stalePasswordConnection->user['password_hash'];
$stalePasswordResult = $stalePassword->changePasswordWithCredentials(
    7,
    'correct horse battery staple',
    $replacementHash,
    '123456',
    $stalePasswordVersions['auth'],
    $staleMutationFactorVersion
);
hardeningAssert(
    !$stalePasswordResult['success'] && $stalePasswordResult['reason'] === 'stale' &&
        hash_equals($stalePasswordHash, $stalePasswordConnection->user['password_hash']) &&
        $stalePasswordConnection->user['two_factor_last_used_step'] === null,
    'stale password changes must not consume a factor or replace the password'
);

$staleDisableConnection = new HardeningFakeConnection();
$staleDisable = hardeningTwoFactor($staleDisableConnection, new HardeningFakeTotp());
$staleDisableVersions = hardeningAuthenticationVersions($staleDisableConnection);
$staleDisableResult = $staleDisable->disable2FAWithCredentials(
    7,
    'correct horse battery staple',
    '123456',
    $staleMutationAuthVersion,
    $staleDisableVersions['two_factor']
);
hardeningAssert(
    !$staleDisableResult['success'] && $staleDisableResult['reason'] === 'stale' &&
        $staleDisableConnection->user['two_factor_enabled'] === 1 &&
        $staleDisableConnection->user['two_factor_last_used_step'] === null,
    'stale 2FA disable must leave the factor and replay state untouched'
);

$staleRotationConnection = new HardeningFakeConnection();
$staleRotationConnection->backupCodes = ['ABCDEF12'];
$staleRotationConnection->usedBackupCodes = [false];
$staleRotation = hardeningTwoFactor($staleRotationConnection, new HardeningFakeTotp());
$staleRotationVersions = hardeningAuthenticationVersions($staleRotationConnection);
$staleRotationResult = $staleRotation->rotateBackupCodesWithCredentials(
    7,
    'correct horse battery staple',
    'ABCDEF12',
    $staleRotationVersions['auth'],
    $staleMutationFactorVersion
);
hardeningAssert(
    !$staleRotationResult['success'] && $staleRotationResult['reason'] === 'stale' &&
        $staleRotationConnection->backupCodes === ['ABCDEF12'] &&
        $staleRotationConnection->usedBackupCodes === [false],
    'stale recovery-code rotation must not consume or replace any code'
);

$passwordVersion = Auth::passwordAuthenticationVersion($originalHash);
$changedPasswordVersion = Auth::passwordAuthenticationVersion($replacementHash);
hardeningAssert(
    !hash_equals($passwordVersion, $changedPasswordVersion),
    'password authentication versions must change with the password hash'
);
$storedTestSecret = TotpSecret::encryptForUser(7, 'ABCDEFGHIJKLMNOP');
$storedChangedTestSecret = TotpSecret::encryptForUser(7, 'ABCDEFGHIJKLMNOPQ');
$twoFactorVersion = Auth::twoFactorAuthenticationVersion(1, $storedTestSecret, 7);
hardeningAssert(
    !hash_equals($twoFactorVersion, Auth::twoFactorAuthenticationVersion(1, $storedChangedTestSecret, 7)) &&
        !hash_equals($twoFactorVersion, Auth::twoFactorAuthenticationVersion(0, null)),
    '2FA authentication versions must bind both enabled state and secret'
);

$atomicStaleConnection = new HardeningFakeConnection();
$atomicStaleFactor = hardeningTwoFactor($atomicStaleConnection, new HardeningFakeTotp());
$atomicStaleResult = $atomicStaleFactor->verifyAndConsumeSecondFactorForAuthenticationState(
    7,
    '123456',
    Auth::passwordAuthenticationVersion('superseded password hash'),
    $twoFactorVersion
);
hardeningAssert(
    !$atomicStaleResult['success'] && $atomicStaleResult['reason'] === 'stale',
    'factor consumption must compare pending authentication versions under its row lock'
);
hardeningAssert(
    $atomicStaleConnection->user['two_factor_last_used_step'] === null &&
        $atomicStaleConnection->commitCount === 0 &&
        $atomicStaleConnection->rollbackCount === 1,
    'state-bound stale factor verification must roll back without consuming the code'
);

$boundFactorConnection = new HardeningFakeConnection();
$boundFactorTotp = new HardeningFakeTotp();
$boundFactorTotp->timeStep = 6000;
$boundFactor = hardeningTwoFactor($boundFactorConnection, $boundFactorTotp);
$boundFactorResult = $boundFactor->verifyAndConsumeSecondFactorForAuthenticationState(
    7,
    '123456',
    Auth::passwordAuthenticationVersion($boundFactorConnection->user['password_hash']),
    $twoFactorVersion
);
hardeningAssert(
    $boundFactorResult['success'] &&
        $boundFactorConnection->user['two_factor_last_used_step'] === 6000 &&
        $boundFactorConnection->commitCount === 1,
    'matching authentication versions should consume and commit one fresh factor'
);

$staleConnection = new HardeningFakeConnection();
$staleAuth = hardeningAuth($staleConnection);
$staleFactorCheck = $staleAuth->verifyLogin2FA(
    7,
    '123456',
    Auth::passwordAuthenticationVersion('superseded password hash'),
    $twoFactorVersion
);
hardeningAssert(
    !$staleFactorCheck['success'] && !empty($staleFactorCheck['stale']),
    'an already-stale pending login must be rejected before consuming its factor'
);
hardeningAssert(
    $staleConnection->user['two_factor_last_used_step'] === null,
    'stale pending login rejection must not consume a TOTP step'
);

$rollbacksBeforeCompletion = $staleConnection->rollbackCount;
$staleCompletion = $staleAuth->completeLoginForUserId(
    7,
    Auth::passwordAuthenticationVersion('superseded password hash'),
    $twoFactorVersion
);
hardeningAssert(
    !$staleCompletion['success'] && !empty($staleCompletion['stale']),
    'pending login completion must reject a changed password/authentication state'
);
hardeningAssert(
    $staleConnection->rollbackCount === $rollbacksBeforeCompletion + 1 &&
        $staleConnection->commitCount === 0,
    'stale pending completion must roll back without committing login state'
);
hardeningAssert(
    count(array_filter(
        $staleConnection->preparedSql,
        fn(string $sql): bool => str_contains($sql, 'FROM users WHERE id = ? FOR UPDATE')
    )) >= 1,
    'pending completion must compare authentication state under a row lock'
);

ini_set('session.use_cookies', '0');
hardeningAssert(session_start(), 'session fixture should start');
$sessionConnection = new HardeningFakeConnection();
$sessionAuth = hardeningAuth($sessionConnection);
$establishMethod = (new ReflectionClass(Auth::class))->getMethod('establishAuthenticatedSession');
$establishMethod->setAccessible(true);
$sessionResult = $establishMethod->invoke($sessionAuth, $sessionConnection->user);
hardeningAssert(
    $sessionResult['success'] &&
        isset($_SESSION['auth_version'], $_SESSION['two_factor_version']),
    'established sessions must bind password and 2FA state versions'
);
$sessionExpectedAuthVersion = (string)$_SESSION['auth_version'];
$sessionExpectedFactorVersion = (string)$_SESSION['two_factor_version'];
$exactMutationFactorVersion = Auth::twoFactorAuthenticationVersion(0, null);
$preparedBeforeRefresh = count($sessionConnection->preparedSql);

// Simulate a second credential mutation committing after the mutation served
// by this request but before its session refresh. Refresh must apply only the
// exact token returned by this request; it must not copy the newer DB state.
$sessionConnection->user['password_hash'] = $replacementHash;
$sessionConnection->user['two_factor_secret'] = TotpSecret::encryptForUser(7, 'ABCDEFGHIJKLMNOPQ');
$factorRefresh = $sessionAuth->refreshSessionTwoFactorVersion(
    7,
    $sessionExpectedAuthVersion,
    $sessionExpectedFactorVersion,
    $sessionExpectedAuthVersion,
    $exactMutationFactorVersion
);
hardeningAssert(
    $factorRefresh &&
        hash_equals($sessionExpectedAuthVersion, (string)$_SESSION['auth_version']) &&
        hash_equals($exactMutationFactorVersion, (string)$_SESSION['two_factor_version']) &&
        count($sessionConnection->preparedSql) === $preparedBeforeRefresh,
    'factor refresh must set only the exact mutation token without re-reading or copying newer DB state'
);
$revokedSession = $sessionAuth->validateSessionFromCookie();
hardeningAssert(
    !$revokedSession['success'] && session_status() !== PHP_SESSION_ACTIVE,
    'a newer concurrent credential state must still revoke the exactly refreshed session'
);

$migration = file_get_contents(__DIR__ . '/../migrations/20260808_add_totp_replay_protection.sql');
hardeningAssert(is_string($migration), 'migration should be readable');
hardeningAssert(
    str_contains($migration, 'two_factor_last_used_step BIGINT UNSIGNED NULL'),
    'migration should add a nullable unsigned BIGINT replay counter'
);
hardeningAssert(
    str_contains($migration, 'information_schema.columns') &&
        str_contains($migration, 'PREPARE pm_totp_replay_statement'),
    'replay migration should be safe to run again'
);

$settingsSource = file_get_contents(__DIR__ . '/../api/settings.php');
$profileSource = file_get_contents(__DIR__ . '/../api/profile.php');
$authSource = file_get_contents(__DIR__ . '/../classes/Auth.php');
$twoFactorSource = file_get_contents(__DIR__ . '/../classes/TwoFactor.php');
$authApiSource = file_get_contents(__DIR__ . '/../api/auth.php');
$attachmentSource = file_get_contents(__DIR__ . '/../api/attachment.php');
$avatarSource = file_get_contents(__DIR__ . '/../api/avatar.php');
$backupMigrationSource = file_get_contents(__DIR__ . '/../migrations/20260808_hash_legacy_backup_codes.php');
hardeningAssert(
    str_contains((string)$settingsSource, 'changePasswordWithCredentials') &&
        str_contains((string)$settingsSource, 'disable2FAWithCredentials') &&
        str_contains((string)$settingsSource, 'rotateBackupCodesWithCredentials'),
    'sensitive settings actions must use atomic authenticated mutations'
);
hardeningAssert(
    str_contains((string)$profileSource, 'Password changes must use account settings') &&
        !str_contains((string)$profileSource, 'password_hash = ?'),
    'the profile endpoint must not retain a weaker password-mutation path'
);
hardeningAssert(
    str_contains((string)$authSource, "temp_auth_version") &&
        str_contains((string)$authSource, "temp_2fa_version") &&
        str_contains((string)$authSource, 'FOR UPDATE'),
    'pending 2FA login must retain and atomically compare authentication versions'
);
hardeningAssert(
    str_contains((string)$authApiSource, "temp_2fa_verified_at") &&
        str_contains((string)$authApiSource, 'already have been consumed'),
    'a lost successful factor response should be retry-safe within the same pending session'
);
hardeningAssert(
    str_contains((string)$authSource, "'internal_error' => true") &&
        str_contains((string)$authApiSource, "!empty(\$response['internal_error'])") &&
        str_contains((string)$authApiSource, "releaseRateLimitAttempt('login_2fa'") &&
        str_contains((string)$authApiSource, 'http_response_code(503)'),
    'backend factor failures must remain retryable and must not consume guess attempts'
);
hardeningAssert(
    str_contains((string)$authSource, "two_factor_version") &&
        str_contains((string)$authSource, 'refreshSessionTwoFactorVersion') &&
        str_contains((string)$attachmentSource, '$rawTwoFactorVersion') &&
        str_contains((string)$avatarSource, '$rawTwoFactorVersion'),
    '2FA state changes must revoke normal and private-media sessions together'
);
hardeningAssert(
    str_contains((string)$settingsSource, "pending_2fa_auth_version") &&
        str_contains((string)$settingsSource, "pending_2fa_factor_version") &&
        str_contains((string)$settingsSource, '$sessionAuthVersion') &&
        str_contains((string)$settingsSource, '$sessionTwoFactorVersion'),
    '2FA enrollment and sensitive settings mutations must carry both expected session versions'
);
hardeningAssert(
    substr_count((string)$settingsSource, "reserveRateLimitAttempt('account_password'") >= 4 &&
        !str_contains((string)$settingsSource, "reserveRateLimitAttempt('setup_2fa_password'") &&
        !str_contains((string)$settingsSource, "reserveRateLimitAttempt('backup_codes'") &&
        str_contains((string)$authSource, "'account_password'") &&
        !str_contains((string)$authSource, "'login_account'"),
    'login and all sensitive settings flows share one account-wide password-guess budget'
);
hardeningAssert(
    str_contains((string)$backupMigrationSource, "['apply']") &&
        str_contains((string)$backupMigrationSource, "hash_hmac('sha256'") &&
        str_contains((string)$backupMigrationSource, 'FOR UPDATE'),
    'legacy recovery-code migration must be explicit, keyed, and atomic'
);
hardeningAssert(
    str_contains((string)$twoFactorSource, "BINARY LEFT(code, 2) = BINARY 'H$'") &&
        !str_contains((string)$twoFactorSource, 'strtoupper((string)$backup'),
    'runtime recovery-code lookup and verifier validation must be byte-exact'
);

echo "PASS: durable TOTP replay prevention\n";
echo "PASS: atomic enrollment and recovery-code rollback\n";
echo "PASS: sensitive account mutations roll back consumed factors on failure\n";
echo "PASS: stale pending 2FA logins are bound to authentication state\n";
echo "PASS: stale settings mutations cannot launder newer state into an old session\n";
