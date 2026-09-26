<?php

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This migration is CLI-only.\n");
    exit(1);
}

$options = getopt('', ['apply']);
$apply = array_key_exists('apply', $options);
$database = null;
$connection = null;

/** Accept only the exact positive integer representation returned by mysqli. */
function backupCodeMigrationId($value): ?int
{
    if (is_int($value)) {
        return $value > 0 ? $value : null;
    }
    if (!is_string($value) || preg_match('/\A[1-9][0-9]*\z/D', $value) !== 1) {
        return null;
    }

    $id = (int)$value;
    return $id > 0 && (string)$id === $value ? $id : null;
}

try {
    $database = new Database();
    $connection = $database->connect();
    if (!$connection->begin_transaction()) {
        throw new RuntimeException('Unable to start backup-code migration');
    }

    $result = $connection->query("
        SELECT id, user_id, code
        FROM backup_codes
        ORDER BY user_id, id
        FOR UPDATE
    ");
    if ($result === false) {
        throw new RuntimeException('Unable to lock backup-code rows');
    }

    $pepper = Database::backupCodePepper();
    $summary = ['legacy' => 0, 'already_hashed' => 0, 'hashed' => 0, 'invalid' => 0];
    $updates = [];
    while ($row = $result->fetch_assoc()) {
        $id = backupCodeMigrationId($row['id'] ?? null);
        $userId = backupCodeMigrationId($row['user_id'] ?? null);
        $rawCode = $row['code'] ?? null;
        if ($id === null || $userId === null || !is_string($rawCode)) {
            $summary['invalid']++;
            continue;
        }

        // Hashed rows must already be in the one exact, case-sensitive format
        // accepted by the runtime verifier. Do not let a case-insensitive
        // database collation make lowercase or malformed markers look valid.
        if (preg_match('/\AH\$[A-F0-9]{8}\z/D', $rawCode) === 1) {
            $summary['already_hashed']++;
            continue;
        }
        if (strncasecmp(trim($rawCode), 'H$', 2) === 0) {
            $summary['invalid']++;
            continue;
        }

        $normalizedCode = strtoupper(trim($rawCode));
        if (preg_match('/\A[A-F0-9]{8}\z/D', $normalizedCode) !== 1) {
            $summary['invalid']++;
            continue;
        }

        $summary['legacy']++;
        $verifier = 'H$' . strtoupper(substr(hash_hmac('sha256', $normalizedCode, $pepper), 0, 8));
        // Keep the exact stored bytes for the optimistic UPDATE predicate;
        // hashing uses only the normalized legacy value.
        $updates[] = [$id, $userId, $rawCode, $verifier];
    }
    $result->free();

    if ($summary['invalid'] !== 0) {
        throw new RuntimeException('Invalid legacy backup-code state found; no rows changed');
    }

    if ($apply) {
        $statement = $connection->prepare("
            UPDATE backup_codes
            SET code = ?
            WHERE id = ?
                AND user_id = ?
                AND BINARY code = BINARY ?
                AND LEFT(BINARY code, 2) <> BINARY 'H$'
        ");
        foreach ($updates as [$id, $userId, $rawCode, $verifier]) {
            $statement->bind_param('siis', $verifier, $id, $userId, $rawCode);
            if (!$statement->execute() || $statement->affected_rows !== 1) {
                throw new RuntimeException('A backup-code row changed during migration');
            }
            $summary['hashed']++;
        }
        if (!$connection->commit()) {
            throw new RuntimeException('Unable to commit backup-code migration');
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
