-- Protected conversations: storage only.
--
-- This migration adds the tables a future end-to-end encrypted mode needs. It
-- changes no existing column and no existing behaviour. Everything it creates
-- stays unused until PM_PROTECTED_CHATS_ENABLED is set to exactly '1', and even
-- then there is no client able to produce an envelope yet.
--
-- Rollout order:
--   1. Apply this migration everywhere.
--   2. Deploy the application code that understands these tables.
--   3. Only then consider setting the runtime flag.
-- Unset the flag before rolling the application back; the tables are additive
-- and can be left in place.
--
-- The server is a relay here. It stores opaque ciphertext plus the MLS handshake
-- material that is public by design in RFC 9420. It cannot read message content,
-- and it is not trusted for correctness of the group state -- only for durable
-- storage and a single stable ordering per group.

SET SESSION lock_wait_timeout = 5;

-- ---------------------------------------------------------------------------
-- chat_protection: which conversations are protected, and at which epoch.
--
-- A separate table rather than a column on `chats`: protection is sparse and
-- irreversible, a missing row is structurally the safe default ("plaintext"),
-- and the whole feature can be removed without touching a hot table.
-- ---------------------------------------------------------------------------
SET @pm_chat_protection_exists = (
    SELECT COUNT(*)
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = 'chat_protection'
);

SET @pm_chat_protection_ddl = IF(
    @pm_chat_protection_exists = 0,
    'CREATE TABLE chat_protection (
        chat_id INT NOT NULL,
        protocol VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT ''Key agreement protocol, e.g. mls'',
        protocol_version SMALLINT UNSIGNED NOT NULL COMMENT ''Envelope schema version the chat was established with'',
        latest_epoch BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT ''Highest epoch accepted for this chat; never decreases'',
        established_by INT NULL,
        established_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (chat_id),
        CONSTRAINT fk_chat_protection_chat FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
        CONSTRAINT fk_chat_protection_user FOREIGN KEY (established_by) REFERENCES users (id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci',
    'SELECT ''chat_protection already exists'' AS migration_status'
);

PREPARE pm_chat_protection_statement FROM @pm_chat_protection_ddl;
EXECUTE pm_chat_protection_statement;
DEALLOCATE PREPARE pm_chat_protection_statement;

-- ---------------------------------------------------------------------------
-- message_envelopes: the ciphertext, kept out of messages.content on purpose.
--
-- Reusing `content` would have been cheaper and wrong: it is validated as UTF-8
-- text with a character limit, it is overwritten with '' on soft delete, and it
-- is the column `searchMessages()` runs LIKE against -- which would have turned
-- a normal product feature into a ciphertext oracle. A protected message keeps
-- content = '' , which makes server-side search fail closed with no code change.
--
-- Stored as VARBINARY so no character set applies. The API base64-encodes on the
-- way out, because responses are encoded with JSON_INVALID_UTF8_SUBSTITUTE and
-- raw bytes would be silently replaced.
-- ---------------------------------------------------------------------------
SET @pm_message_envelopes_exists = (
    SELECT COUNT(*)
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = 'message_envelopes'
);

SET @pm_message_envelopes_ddl = IF(
    @pm_message_envelopes_exists = 0,
    'CREATE TABLE message_envelopes (
        message_id INT NOT NULL,
        envelope_version SMALLINT UNSIGNED NOT NULL,
        protocol VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        group_id BINARY(32) NOT NULL,
        epoch BIGINT UNSIGNED NOT NULL,
        sender_leaf INT UNSIGNED NOT NULL COMMENT ''MLS leaf index of the sending device'',
        content_type SMALLINT UNSIGNED NOT NULL COMMENT ''1 text, 2 attachment descriptor, 3 security event'',
        ciphertext VARBINARY(24576) NOT NULL,
        aad_digest BINARY(32) NOT NULL COMMENT ''SHA-256 of the authenticated associated data'',
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (message_id),
        KEY idx_message_envelopes_group_epoch (group_id, epoch),
        CONSTRAINT fk_message_envelopes_message FOREIGN KEY (message_id) REFERENCES messages (id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci',
    'SELECT ''message_envelopes already exists'' AS migration_status'
);

PREPARE pm_message_envelopes_statement FROM @pm_message_envelopes_ddl;
EXECUTE pm_message_envelopes_statement;
DEALLOCATE PREPARE pm_message_envelopes_statement;

-- ---------------------------------------------------------------------------
-- mls_groups: one MLS group per protected chat.
--
-- current_epoch is the row the server locks to assign a handshake sequence, so
-- that concurrent commits cannot both claim the same epoch.
-- ---------------------------------------------------------------------------
SET @pm_mls_groups_exists = (
    SELECT COUNT(*)
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = 'mls_groups'
);

SET @pm_mls_groups_ddl = IF(
    @pm_mls_groups_exists = 0,
    'CREATE TABLE mls_groups (
        chat_id INT NOT NULL,
        group_id BINARY(32) NOT NULL,
        cipher_suite SMALLINT UNSIGNED NOT NULL,
        current_epoch BIGINT UNSIGNED NOT NULL DEFAULT 0,
        next_sequence BIGINT UNSIGNED NOT NULL DEFAULT 1 COMMENT ''Next handshake sequence to hand out'',
        tree_hash BINARY(32) NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (chat_id),
        UNIQUE KEY uq_mls_groups_group_id (group_id),
        CONSTRAINT fk_mls_groups_chat FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci',
    'SELECT ''mls_groups already exists'' AS migration_status'
);

PREPARE pm_mls_groups_statement FROM @pm_mls_groups_ddl;
EXECUTE pm_mls_groups_statement;
DEALLOCATE PREPARE pm_mls_groups_statement;

-- ---------------------------------------------------------------------------
-- mls_handshake_messages: the ordered delivery queue for group state.
--
-- MLS needs every member to apply commits in the same order. The server's only
-- real obligation is to publish one gap-free sequence per chat, so a client that
-- asks for everything after N can detect withholding as a missing number. The
-- unique key on (chat_id, sequence) makes a duplicate a database error rather
-- than a divergence nobody notices.
-- ---------------------------------------------------------------------------
SET @pm_mls_handshake_exists = (
    SELECT COUNT(*)
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = 'mls_handshake_messages'
);

SET @pm_mls_handshake_ddl = IF(
    @pm_mls_handshake_exists = 0,
    'CREATE TABLE mls_handshake_messages (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        chat_id INT NOT NULL,
        sequence BIGINT UNSIGNED NOT NULL,
        epoch BIGINT UNSIGNED NOT NULL,
        kind SMALLINT UNSIGNED NOT NULL COMMENT ''1 proposal, 2 commit, 3 welcome'',
        sender_user_id INT NULL,
        payload BLOB NOT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_mls_handshake_sequence (chat_id, sequence),
        KEY idx_mls_handshake_chat_cursor (chat_id, id),
        CONSTRAINT fk_mls_handshake_chat FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
        CONSTRAINT fk_mls_handshake_user FOREIGN KEY (sender_user_id) REFERENCES users (id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci',
    'SELECT ''mls_handshake_messages already exists'' AS migration_status'
);

PREPARE pm_mls_handshake_statement FROM @pm_mls_handshake_ddl;
EXECUTE pm_mls_handshake_statement;
DEALLOCATE PREPARE pm_mls_handshake_statement;

-- ---------------------------------------------------------------------------
-- Post-deploy verification. Each query must return the stated result before the
-- runtime flag is considered.
-- ---------------------------------------------------------------------------

-- Expect exactly 4.
SELECT COUNT(*) AS protected_tables_present
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name IN ('chat_protection', 'message_envelopes', 'mls_groups', 'mls_handshake_messages');

-- Expect 'varbinary' and 24576: the ciphertext column must never become a text
-- type, or a character set would start mangling it.
SELECT data_type AS ciphertext_type, character_maximum_length AS ciphertext_bytes
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'message_envelopes'
  AND column_name = 'ciphertext';

-- Expect 0: the handshake sequence must be unique per chat.
SELECT COUNT(*) AS non_unique_handshake_sequence
FROM information_schema.statistics
WHERE table_schema = DATABASE()
  AND table_name = 'mls_handshake_messages'
  AND index_name = 'uq_mls_handshake_sequence'
  AND non_unique <> 0;

-- Expect 0 rows: no protected chat may hold a message whose content is not
-- empty. Nothing can violate this yet; the query exists so the check is already
-- written when something can.
SELECT COUNT(*) AS protected_messages_with_plaintext
FROM messages m
JOIN chat_protection p ON p.chat_id = m.chat_id
WHERE m.content <> '';
