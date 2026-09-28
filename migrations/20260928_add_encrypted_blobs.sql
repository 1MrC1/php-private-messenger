-- Storage for encrypted attachments.
--
-- A file in a protected conversation cannot go through the ordinary upload
-- pipeline. That pipeline works by reading the bytes: a MIME allow-list, image
-- and archive parsing, and a fail-closed ClamAV scan. None of it can inspect
-- ciphertext, and `application/octet-stream` is deliberately not in the
-- allow-list, so an encrypted blob is rejected at inspection.
--
-- So encrypted attachments are stored separately, with a deliberately smaller
-- set of checks: size, quota, ownership and digest. What is lost is malware
-- scanning, and that loss is stated in the interface rather than hidden.
--
-- Apply after 20260928_add_device_directory.sql.

SET SESSION lock_wait_timeout = 5;

SET @pm_blobs_exists = (
    SELECT COUNT(*) FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = 'encrypted_blobs'
);

SET @pm_blobs_ddl = IF(
    @pm_blobs_exists = 0,
    'CREATE TABLE encrypted_blobs (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        uploader_id INT NOT NULL,
        chat_id INT NOT NULL,
        blob_path VARCHAR(500) NOT NULL COMMENT ''Relative path under uploads/blobs'',
        byte_size INT UNSIGNED NOT NULL COMMENT ''Size of the ciphertext, not the file'',
        sha256 BINARY(32) NOT NULL COMMENT ''Digest of the ciphertext as stored'',
        referenced_message_id INT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_encrypted_blobs_chat (chat_id, id),
        KEY idx_encrypted_blobs_uploader (uploader_id, created_at),
        CONSTRAINT fk_encrypted_blobs_uploader FOREIGN KEY (uploader_id) REFERENCES users (id) ON DELETE CASCADE,
        CONSTRAINT fk_encrypted_blobs_chat FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
        CONSTRAINT fk_encrypted_blobs_message FOREIGN KEY (referenced_message_id) REFERENCES messages (id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci',
    'SELECT ''encrypted_blobs already exists'' AS migration_status'
);

PREPARE pm_blobs_statement FROM @pm_blobs_ddl;
EXECUTE pm_blobs_statement;
DEALLOCATE PREPARE pm_blobs_statement;

-- ---------------------------------------------------------------------------
-- Post-deploy verification.
-- ---------------------------------------------------------------------------

-- Expect 1.
SELECT COUNT(*) AS encrypted_blobs_present
FROM information_schema.tables
WHERE table_schema = DATABASE() AND table_name = 'encrypted_blobs';

-- Expect 'binary' and 32: the digest must stay a fixed-width binary column.
SELECT data_type AS digest_type, character_maximum_length AS digest_bytes
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'encrypted_blobs'
  AND column_name = 'sha256';

-- Expect 0 rows: a blob must belong to a conversation that is protected.
-- Nothing can violate this yet; the check is written before it can.
SELECT COUNT(*) AS blobs_outside_protected_chats
FROM encrypted_blobs b
LEFT JOIN chat_protection p ON p.chat_id = b.chat_id
WHERE p.chat_id IS NULL;
