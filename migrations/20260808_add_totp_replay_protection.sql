-- Durable TOTP replay protection for enabled accounts.
--
-- Deployment order matters: apply this migration before deploying PHP code
-- that reads two_factor_last_used_step. Existing 2FA accounts intentionally
-- start at NULL; their first successful code records the accepted time-step.
-- Do not populate this column from wall-clock time.

-- Use information_schema + prepared DDL instead of vendor-specific
-- ADD COLUMN IF NOT EXISTS syntax. This keeps repeated deployments safe on
-- both MySQL and MariaDB versions used by existing installations.
SET @pm_totp_replay_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users'
      AND column_name = 'two_factor_last_used_step'
);

SET @pm_totp_replay_ddl = IF(
    @pm_totp_replay_column_exists = 0,
    'ALTER TABLE users ADD COLUMN two_factor_last_used_step BIGINT UNSIGNED NULL DEFAULT NULL COMMENT ''Largest accepted 30-second TOTP counter; blocks replay'' AFTER two_factor_secret',
    'SELECT ''two_factor_last_used_step already exists'' AS migration_status'
);

PREPARE pm_totp_replay_statement FROM @pm_totp_replay_ddl;
EXECUTE pm_totp_replay_statement;
DEALLOCATE PREPARE pm_totp_replay_statement;

-- Post-deploy check (expected: one row, bigint, nullable, unsigned).
SELECT
    column_name,
    column_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'users'
  AND column_name = 'two_factor_last_used_step';
