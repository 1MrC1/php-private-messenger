-- Two fixes a third review asked for.
--
-- 1. Scope a claimed key package to the conversation it was claimed for, so a
--    repeated claim for the same conversation and device is answered from the
--    package already spent instead of consuming another. Without this the hourly
--    cap had to be larger than the number of packages a device publishes, which
--    is exactly why the first attempt at a cap did not stop exhaustion.
--
-- 2. Guard the protected-plaintext invariant from the other side. The triggers
--    added on 2026-09-29 refuse plaintext written into a protected conversation;
--    they did nothing about plaintext written first and protection added after.
--    The review reproduced that with direct SQL. Both directions are refused now.
--
-- Apply after 20260929_enforce_protected_plaintext.sql.

SET SESSION lock_wait_timeout = 5;

SET @pm_claim_scope_exists = (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'e2ee_key_packages'
      AND column_name = 'claimed_for_chat_id'
);

SET @pm_claim_scope_ddl = IF(
    @pm_claim_scope_exists = 0,
    'ALTER TABLE e2ee_key_packages
        ADD COLUMN claimed_for_chat_id INT NULL COMMENT ''The conversation this package was claimed for'',
        ADD KEY idx_e2ee_key_packages_claim_scope (device_id, consumed_by_user_id, claimed_for_chat_id),
        ADD CONSTRAINT fk_e2ee_key_packages_claim_chat
            FOREIGN KEY (claimed_for_chat_id) REFERENCES chats (id) ON DELETE SET NULL',
    'SELECT ''claimed_for_chat_id already exists'' AS migration_status'
);

PREPARE pm_claim_scope_statement FROM @pm_claim_scope_ddl;
EXECUTE pm_claim_scope_statement;
DEALLOCATE PREPARE pm_claim_scope_statement;

-- One claim per conversation per device, enforced rather than checked. The
-- application locks the device rows before deciding, but a constraint is what
-- makes that true regardless of which code path asks next.
SET @pm_claim_unique_exists = (
    SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'e2ee_key_packages'
      AND index_name = 'uniq_e2ee_key_packages_claim_scope'
);

SET @pm_claim_unique_ddl = IF(
    @pm_claim_unique_exists = 0,
    'ALTER TABLE e2ee_key_packages
        ADD UNIQUE KEY uniq_e2ee_key_packages_claim_scope
            (device_id, consumed_by_user_id, claimed_for_chat_id)',
    'SELECT ''claim scope is already unique'' AS migration_status'
);

PREPARE pm_claim_unique_statement FROM @pm_claim_unique_ddl;
EXECUTE pm_claim_unique_statement;
DEALLOCATE PREPARE pm_claim_unique_statement;

DROP TRIGGER IF EXISTS pm_chat_protection_insert;

DELIMITER $$

CREATE TRIGGER pm_chat_protection_insert
BEFORE INSERT ON chat_protection
FOR EACH ROW
BEGIN
    IF EXISTS (
        SELECT 1 FROM messages
         WHERE chat_id = NEW.chat_id
           AND content IS NOT NULL
           AND content <> ''
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'a conversation with plaintext content cannot become protected';
    END IF;
END$$

DELIMITER ;

-- ---------------------------------------------------------------------------
-- Post-deploy verification.
--
-- The previous migration only printed violations, which a review rightly called
-- out: a verification query that cannot fail verifies nothing. These signal.
-- ---------------------------------------------------------------------------

-- Expect 1: the claim scope is unique.
SELECT COUNT(*) AS claim_scope_unique
FROM information_schema.statistics
WHERE table_schema = DATABASE()
  AND table_name = 'e2ee_key_packages'
  AND index_name = 'uniq_e2ee_key_packages_claim_scope'
  AND non_unique = 0;

-- Expect 3: both message triggers plus the new one on chat_protection.
SELECT COUNT(*) AS protection_triggers
FROM information_schema.triggers
WHERE trigger_schema = DATABASE()
  AND trigger_name IN (
        'pm_messages_protected_insert',
        'pm_messages_protected_update',
        'pm_chat_protection_insert'
      );

-- Abort the migration if the invariant is already violated, rather than printing
-- it and carrying on.
SET @pm_violations = (
    SELECT COUNT(*)
      FROM messages m
      JOIN chat_protection p ON p.chat_id = m.chat_id
     WHERE m.content <> ''
);

SET @pm_violation_check = IF(
    @pm_violations = 0,
    'SELECT ''no protected conversation holds plaintext'' AS invariant_status',
    'SELECT * FROM pm_invariant_violated_see_migration_notes'
);

PREPARE pm_violation_statement FROM @pm_violation_check;
EXECUTE pm_violation_statement;
DEALLOCATE PREPARE pm_violation_statement;
