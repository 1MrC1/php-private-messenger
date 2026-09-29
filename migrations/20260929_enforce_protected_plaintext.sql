-- Refuse plaintext in a protected conversation, in the database.
--
-- WHY A TRIGGER, IN A CODEBASE THAT OTHERWISE KEEPS RULES IN PHP. Two reviews
-- found the same class of defect twice: first the application checked protection
-- only on the protected path, then it checked on every path but outside the
-- transaction, leaving a check-then-act race. Both were fixed in PHP. Both were
-- *reachable* because the invariant lived only in code that a new call site can
-- forget.
--
-- This is the invariant itself: a row in `messages` belonging to a conversation
-- in `chat_protection` must have empty `content`. Nothing in the application can
-- violate it, including code nobody has written yet.
--
-- Apply after 20260928_add_encrypted_blobs.sql. Requires TRIGGER privilege.

SET SESSION lock_wait_timeout = 5;

DROP TRIGGER IF EXISTS pm_messages_protected_insert;
DROP TRIGGER IF EXISTS pm_messages_protected_update;

DELIMITER $$

CREATE TRIGGER pm_messages_protected_insert
BEFORE INSERT ON messages
FOR EACH ROW
BEGIN
    IF NEW.content IS NOT NULL AND NEW.content <> '' THEN
        IF EXISTS (SELECT 1 FROM chat_protection WHERE chat_id = NEW.chat_id) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'plaintext content is not allowed in a protected conversation';
        END IF;
    END IF;
END$$

CREATE TRIGGER pm_messages_protected_update
BEFORE UPDATE ON messages
FOR EACH ROW
BEGIN
    IF NEW.content IS NOT NULL AND NEW.content <> '' THEN
        IF EXISTS (SELECT 1 FROM chat_protection WHERE chat_id = NEW.chat_id) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'plaintext content is not allowed in a protected conversation';
        END IF;
    END IF;
END$$

DELIMITER ;

-- ---------------------------------------------------------------------------
-- Post-deploy verification.
-- ---------------------------------------------------------------------------

-- Expect 2.
SELECT COUNT(*) AS protection_triggers
FROM information_schema.triggers
WHERE trigger_schema = DATABASE()
  AND trigger_name IN ('pm_messages_protected_insert', 'pm_messages_protected_update');

-- Expect 0 rows, now enforced rather than hoped for: no protected conversation
-- holds a message with content.
SELECT m.id, m.chat_id
FROM messages m
JOIN chat_protection p ON p.chat_id = m.chat_id
WHERE m.content <> ''
LIMIT 10;
