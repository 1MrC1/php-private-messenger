-- Durable sender-scoped idempotency for message sends.
--
-- Apply this migration before enabling client_message_id writes. Deploy the
-- compatible PHP/JavaScript release to every application node, verify this
-- migration's final metadata checks, and only then set the exact runtime gate
-- PM_MESSAGE_IDEMPOTENCY_ENABLED=1 on every node and reload its PHP workers.
-- Until that coordinated final step, capability discovery remains false.
-- Existing/legacy messages keep NULL in both columns; MySQL/MariaDB unique
-- indexes permit multiple NULL keys, so legacy clients remain compatible.

-- Never sit behind an unexpected long-lived metadata lock. The explicitly
-- requested algorithms below also make the migration fail instead of silently
-- falling back to a table copy or a write-blocking index build.
SET SESSION lock_wait_timeout = 5;

SET @pm_client_message_id_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'messages'
      AND column_name = 'client_message_id'
);

SET @pm_client_message_id_ddl = IF(
    @pm_client_message_id_exists = 0,
    'ALTER TABLE messages ADD COLUMN client_message_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL DEFAULT NULL COMMENT ''RFC 4122 UUID v4 supplied by the sender'' AFTER reply_to_message_id, ALGORITHM=INSTANT',
    'SELECT ''client_message_id already exists'' AS migration_status'
);

PREPARE pm_client_message_id_statement FROM @pm_client_message_id_ddl;
EXECUTE pm_client_message_id_statement;
DEALLOCATE PREPARE pm_client_message_id_statement;

SET @pm_client_message_fingerprint_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'messages'
      AND column_name = 'client_message_fingerprint'
);

SET @pm_client_message_fingerprint_ddl = IF(
    @pm_client_message_fingerprint_exists = 0,
    'ALTER TABLE messages ADD COLUMN client_message_fingerprint BINARY(32) NULL DEFAULT NULL COMMENT ''SHA-256 of canonical logical send'' AFTER client_message_id, ALGORITHM=INSTANT',
    'SELECT ''client_message_fingerprint already exists'' AS migration_status'
);

PREPARE pm_client_message_fingerprint_statement FROM @pm_client_message_fingerprint_ddl;
EXECUTE pm_client_message_fingerprint_statement;
DEALLOCATE PREPARE pm_client_message_fingerprint_statement;

-- The key is scoped to sender_id: two users may independently generate the
-- same UUID, while one sender can never commit it for two message rows.
SET @pm_sender_client_message_index_ready = (
    SELECT COUNT(*)
    FROM (
        SELECT index_name
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'messages'
          AND index_name = 'uq_messages_sender_client_message'
        GROUP BY index_name
        HAVING MIN(non_unique) = 0
           AND GROUP_CONCAT(column_name ORDER BY seq_in_index SEPARATOR ',') =
               'sender_id,client_message_id'
           AND MAX(sub_part) IS NULL
    ) AS ready_indexes
);

SET @pm_sender_client_message_index_ddl = IF(
    @pm_sender_client_message_index_ready = 0,
    'ALTER TABLE messages ADD UNIQUE KEY uq_messages_sender_client_message (sender_id, client_message_id), ALGORITHM=INPLACE, LOCK=NONE',
    'SELECT ''sender/client_message_id unique key already exists'' AS migration_status'
);

PREPARE pm_sender_client_message_index_statement
    FROM @pm_sender_client_message_index_ddl;
EXECUTE pm_sender_client_message_index_statement;
DEALLOCATE PREPARE pm_sender_client_message_index_statement;

-- Post-deploy checks. Expected: two rows with the exact types/collations below,
-- one two-column unique index, and zero inconsistent legacy/application rows.
SELECT
    column_name,
    column_type,
    character_set_name,
    collation_name,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'messages'
  AND column_name IN ('client_message_id', 'client_message_fingerprint')
ORDER BY ordinal_position;

SELECT
    index_name,
    non_unique,
    GROUP_CONCAT(column_name ORDER BY seq_in_index SEPARATOR ',') AS indexed_columns,
    MAX(sub_part) AS maximum_prefix_length
FROM information_schema.statistics
WHERE table_schema = DATABASE()
  AND table_name = 'messages'
  AND index_name = 'uq_messages_sender_client_message'
GROUP BY index_name, non_unique;

SELECT COUNT(*) AS inconsistent_idempotency_rows
FROM messages
WHERE (client_message_id IS NULL) <> (client_message_fingerprint IS NULL);
