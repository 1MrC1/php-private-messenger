<?php
declare(strict_types=1);

class Database
{
    private string $host;
    private string $db_name;
    private string $username;
    private string $password;
    private ?mysqli $conn = null;

    public function __construct()
    {
        $this->host = self::requiredEnvironmentValue('PM_DB_HOST');
        $this->db_name = self::requiredEnvironmentValue('PM_DB_NAME');
        $this->username = self::requiredEnvironmentValue('PM_DB_USERNAME');
        $this->password = self::requiredEnvironmentValue('PM_DB_PASSWORD', 32);
    }

    private static function requiredEnvironmentValue(string $name, int $minimumLength = 1): string
    {
        $value = getenv($name);
        if (!is_string($value) || strlen($value) < $minimumLength || strlen($value) > 255 ||
            str_contains($value, "\0") || str_contains($value, "\r") || str_contains($value, "\n")) {
            throw new RuntimeException('Runtime security configuration is unavailable');
        }
        return $value;
    }

    /** An optional runtime value, held to the same hygiene as a required one. */
    public static function optionalEnvironmentValue(string $name): ?string
    {
        $value = getenv($name);
        if (!is_string($value) || $value === '') {
            return null;
        }
        if (strlen($value) > 255 || str_contains($value, "\0") ||
            str_contains($value, "\r") || str_contains($value, "\n")) {
            throw new RuntimeException('Runtime security configuration is unavailable');
        }
        return $value;
    }

    public static function backupCodePepper(): string
    {
        return self::requiredEnvironmentValue('PM_BACKUP_CODE_PEPPER', 32);
    }

    public function connect(): mysqli
    {
        if ($this->conn instanceof mysqli) {
            return $this->conn;
        }

        $connection = null;
        try {
            $connection = mysqli_init();
            if (!$connection instanceof mysqli) {
                throw new RuntimeException('Unable to initialize database client');
            }
            $connection->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);

            try {
                $connected = @$connection->real_connect(
                    $this->host,
                    $this->username,
                    $this->password,
                    $this->db_name
                );
            } catch (mysqli_sql_exception $error) {
                $connected = false;
            }
            // All API timestamps are interpreted as UTC by the locale-aware
            // client formatters, so keep MySQL NOW()/DATETIME values aligned.
            if (!$connected || !$connection->set_charset('utf8mb4') ||
                !$connection->query("SET time_zone = '+00:00'")) {
                throw new RuntimeException('Database connection failed');
            }

            $this->conn = $connection;
            return $this->conn;
        } catch (Throwable $error) {
            if ($connection instanceof mysqli) {
                try {
                    $connection->close();
                } catch (Throwable $ignored) {
                }
            }
            error_log('Database connection failed');
            throw new RuntimeException('Database service unavailable');
        }
    }

    public function close(): void
    {
        if ($this->conn instanceof mysqli) {
            $this->conn->close();
            $this->conn = null;
        }
    }
}

// Security configurations
define('SESSION_LIFETIME', 86400); // 24 hours
define('UPLOAD_MAX_SIZE', 50 * 1024 * 1024); // 50MB
define('ALLOWED_FILE_TYPES', ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain']);

// Site configurations
// The origin the API compares against when refusing cross-origin state
// changes. It must match how users actually reach the site, so it comes from
// the environment like everything else; the default keeps existing deployments
// working unchanged.
define('SITE_URL', Database::optionalEnvironmentValue('PM_SITE_URL') ?? 'https://messenger.example');
define('UPLOAD_DIR', 'uploads/');
define('AVATAR_DIR', 'uploads/avatars/');
define('FILES_DIR', 'uploads/files/');
