-- Storage envelope for authenticated encryption of TOTP seeds.
-- Safe to re-run on MySQL and MariaDB.

SET @pm_totp_secret_column_ready = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users'
      AND column_name = 'two_factor_secret'
      AND data_type = 'varchar'
      AND character_maximum_length >= 255
      AND is_nullable = 'YES'
);

SET @pm_totp_secret_ddl = IF(
    @pm_totp_secret_column_ready = 0,
    'ALTER TABLE users MODIFY COLUMN two_factor_secret VARCHAR(255) NULL DEFAULT NULL',
    'SELECT ''two_factor_secret storage already ready'' AS migration_status'
);

PREPARE pm_totp_secret_statement FROM @pm_totp_secret_ddl;
EXECUTE pm_totp_secret_statement;
DEALLOCATE PREPARE pm_totp_secret_statement;

SELECT
    column_name,
    column_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'users'
  AND column_name = 'two_factor_secret';
