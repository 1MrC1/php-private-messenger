<?php

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../classes/TotpSecret.php';

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This migration is CLI-only.\n");
    exit(1);
}

$options = getopt('', ['apply']);
$apply = array_key_exists('apply', $options);
$database = null;
$connection = null;

try {
    $database = new Database();
    $connection = $database->connect();

    $columnResult = $connection->query("
        SELECT data_type, character_maximum_length, is_nullable
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = 'users'
          AND column_name = 'two_factor_secret'
        LIMIT 1
    ");
    $column = $columnResult ? $columnResult->fetch_assoc() : null;
    if (is_array($column)) {
        // MariaDB returns INFORMATION_SCHEMA column labels in uppercase even
        // when the query spells them in lowercase. Normalize the metadata
        // keys so the fail-closed schema guard works on both MySQL variants.
        $column = array_change_key_case($column, CASE_LOWER);
    }
    if (!is_array($column) || $column['data_type'] !== 'varchar' ||
        (int)$column['character_maximum_length'] < 255 || $column['is_nullable'] !== 'YES') {
        throw new RuntimeException('Apply the TOTP secret schema migration first');
    }

    if (!$connection->begin_transaction()) {
        throw new RuntimeException('Unable to start TOTP secret migration');
    }
    $result = $connection->query("
        SELECT id, two_factor_enabled, two_factor_secret
        FROM users
        WHERE two_factor_enabled = 1 OR two_factor_secret IS NOT NULL
        ORDER BY id
        FOR UPDATE
    ");
    if ($result === false) {
        throw new RuntimeException('Unable to lock TOTP secret rows');
    }

    $summary = [
        'enabled' => 0,
        'already_encrypted' => 0,
        'plaintext' => 0,
        'encrypted' => 0,
        'invalid' => 0,
    ];
    $pendingUpdates = [];
    while ($row = $result->fetch_assoc()) {
        $userId = is_numeric($row['id'] ?? null) ? (int)$row['id'] : 0;
        $enabled = $row['two_factor_enabled'] ?? null;
        $storedSecret = $row['two_factor_secret'] ?? null;
        if ($userId < 1 || !in_array($enabled, [0, 1, '0', '1'], true)) {
            $summary['invalid']++;
            continue;
        }

        if ((int)$enabled !== 1) {
            // Disabled accounts should not retain a seed. Refuse to silently
            // rewrite or discard an inconsistent row during this migration.
            if ($storedSecret !== null) {
                $summary['invalid']++;
            }
            continue;
        }

        $summary['enabled']++;
        if (!is_string($storedSecret)) {
            $summary['invalid']++;
            continue;
        }
        if (TotpSecret::isEncrypted($storedSecret)) {
            if (TotpSecret::decryptForUser($userId, $storedSecret) === null) {
                $summary['invalid']++;
                continue;
            }
            $summary['already_encrypted']++;
            continue;
        }

        $plaintext = TotpSecret::legacyPlaintextForMigration($storedSecret);
        if ($plaintext === null) {
            $summary['invalid']++;
            continue;
        }

        $summary['plaintext']++;
        $encrypted = TotpSecret::encryptForUser($userId, $plaintext);
        if (TotpSecret::decryptForUser($userId, $encrypted) !== $plaintext) {
            throw new RuntimeException('TOTP envelope verification failed');
        }
        $pendingUpdates[] = [$userId, $storedSecret, $encrypted];
    }

    if ($summary['invalid'] !== 0) {
        throw new RuntimeException('Invalid TOTP account state found; no rows changed');
    }

    if ($apply) {
        $statement = $connection->prepare("
            UPDATE users
            SET two_factor_secret = ?
            WHERE id = ? AND two_factor_enabled = 1
              AND BINARY two_factor_secret = BINARY ?
        ");
        foreach ($pendingUpdates as [$userId, $plaintext, $encrypted]) {
            $statement->bind_param('sis', $encrypted, $userId, $plaintext);
            if (!$statement->execute() || $statement->affected_rows !== 1) {
                throw new RuntimeException('A TOTP row changed during migration');
            }
            $summary['encrypted']++;
        }
        if (!$connection->commit()) {
            throw new RuntimeException('Unable to commit TOTP secret migration');
        }
    } else {
        $connection->rollback();
    }

    echo json_encode(
        ['mode' => $apply ? 'apply' : 'dry-run', 'summary' => $summary],
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
    ) . "\n";
    $database->close();
    exit(0);
} catch (Throwable $error) {
    if ($connection instanceof mysqli) {
        try {
            $connection->rollback();
        } catch (Throwable $ignored) {
        }
    }
    if ($database instanceof Database) {
        try {
            $database->close();
        } catch (Throwable $ignored) {
        }
    }
    fwrite(STDERR, $error->getMessage() . "\n");
    exit(1);
}
