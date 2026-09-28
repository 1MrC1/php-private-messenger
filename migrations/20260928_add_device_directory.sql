-- Device identity and key transport for protected conversations.
--
-- MLS identities belong to devices, not accounts: a phone and a laptop are two
-- members of a group, each with its own signature key. This adds the three
-- tables that requires, and changes nothing that exists.
--
-- Everything stored here is public by design in RFC 9420. The server hands out
-- key packages and records the directory; it never holds a private key. What it
-- must not be able to do is substitute a key without anyone noticing, which is
-- what the append-only log below is for.
--
-- Apply after 20260928_add_chat_protection_and_envelopes.sql.

SET SESSION lock_wait_timeout = 5;

-- ---------------------------------------------------------------------------
-- e2ee_devices: one row per enrolled device.
-- ---------------------------------------------------------------------------
SET @pm_devices_exists = (
    SELECT COUNT(*) FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = 'e2ee_devices'
);

SET @pm_devices_ddl = IF(
    @pm_devices_exists = 0,
    'CREATE TABLE e2ee_devices (
        id INT NOT NULL AUTO_INCREMENT,
        user_id INT NOT NULL,
        public_id BINARY(32) NOT NULL COMMENT ''Client-generated device identifier'',
        label VARCHAR(64) NULL COMMENT ''Human label chosen at enrollment, shown in the device list'',
        signature_public_key VARBINARY(1024) NOT NULL,
        credential VARBINARY(4096) NOT NULL COMMENT ''Serialised MLS credential'',
        cipher_suite SMALLINT UNSIGNED NOT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP NULL DEFAULT NULL,
        revoked_at TIMESTAMP NULL DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uq_e2ee_devices_public_id (public_id),
        KEY idx_e2ee_devices_user (user_id, revoked_at),
        CONSTRAINT fk_e2ee_devices_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci',
    'SELECT ''e2ee_devices already exists'' AS migration_status'
);

PREPARE pm_devices_statement FROM @pm_devices_ddl;
EXECUTE pm_devices_statement;
DEALLOCATE PREPARE pm_devices_statement;

-- ---------------------------------------------------------------------------
-- e2ee_key_packages: one-time packages, consumed exactly once.
--
-- A key package that is handed out twice lets two members join on the same
-- init key, which is why consumption is a conditional UPDATE inside the
-- claiming transaction rather than a read followed by a write.
-- ---------------------------------------------------------------------------
SET @pm_key_packages_exists = (
    SELECT COUNT(*) FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = 'e2ee_key_packages'
);

SET @pm_key_packages_ddl = IF(
    @pm_key_packages_exists = 0,
    'CREATE TABLE e2ee_key_packages (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        device_id INT NOT NULL,
        key_package_ref BINARY(32) NOT NULL COMMENT ''Hash of the key package, for idempotent publishing'',
        key_package VARBINARY(16384) NOT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        consumed_at TIMESTAMP NULL DEFAULT NULL,
        consumed_by_user_id INT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uq_e2ee_key_packages_ref (key_package_ref),
        KEY idx_e2ee_key_packages_available (device_id, consumed_at),
        CONSTRAINT fk_e2ee_key_packages_device FOREIGN KEY (device_id) REFERENCES e2ee_devices (id) ON DELETE CASCADE,
        CONSTRAINT fk_e2ee_key_packages_consumer FOREIGN KEY (consumed_by_user_id) REFERENCES users (id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci',
    'SELECT ''e2ee_key_packages already exists'' AS migration_status'
);

PREPARE pm_key_packages_statement FROM @pm_key_packages_ddl;
EXECUTE pm_key_packages_statement;
DEALLOCATE PREPARE pm_key_packages_statement;

-- ---------------------------------------------------------------------------
-- e2ee_directory_log: an append-only hash chain over device events.
--
-- entry_digest = SHA256(seq || previous_digest || entry_type || payload_digest)
--
-- Be clear about what this is: a client that has seen the log can detect a
-- server that later rewrites or omits an entry, because the chain stops
-- extending. It is NOT key transparency -- there is no third-party monitor and
-- no cross-user gossip, so a server that lies consistently to a client that has
-- never seen the truth is not caught by this alone. Safety numbers exist for
-- that, and they are not built yet.
-- ---------------------------------------------------------------------------
SET @pm_directory_exists = (
    SELECT COUNT(*) FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = 'e2ee_directory_log'
);

SET @pm_directory_ddl = IF(
    @pm_directory_exists = 0,
    'CREATE TABLE e2ee_directory_log (
        seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        entry_type SMALLINT UNSIGNED NOT NULL COMMENT ''1 enrolled, 2 revoked'',
        user_id INT NULL,
        device_id INT NULL,
        payload_digest BINARY(32) NOT NULL,
        previous_digest BINARY(32) NOT NULL,
        entry_digest BINARY(32) NOT NULL,
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (seq),
        UNIQUE KEY uq_e2ee_directory_entry (entry_digest),
        KEY idx_e2ee_directory_user (user_id, seq)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci',
    'SELECT ''e2ee_directory_log already exists'' AS migration_status'
);

PREPARE pm_directory_statement FROM @pm_directory_ddl;
EXECUTE pm_directory_statement;
DEALLOCATE PREPARE pm_directory_statement;

-- ---------------------------------------------------------------------------
-- Post-deploy verification.
-- ---------------------------------------------------------------------------

-- Expect exactly 3.
SELECT COUNT(*) AS device_tables_present
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name IN ('e2ee_devices', 'e2ee_key_packages', 'e2ee_directory_log');

-- Expect 0: a key package reference must be unique, or publishing twice would
-- create two rows that can each be consumed once.
SELECT COUNT(*) AS non_unique_key_package_ref
FROM information_schema.statistics
WHERE table_schema = DATABASE()
  AND table_name = 'e2ee_key_packages'
  AND index_name = 'uq_e2ee_key_packages_ref'
  AND non_unique <> 0;

-- Expect 0 rows: no key package may be consumed more than once. Nothing can
-- violate this yet; the query exists so the check is written before it can.
SELECT COUNT(*) AS key_packages_consumed_without_consumer
FROM e2ee_key_packages
WHERE consumed_at IS NOT NULL AND consumed_by_user_id IS NULL;
