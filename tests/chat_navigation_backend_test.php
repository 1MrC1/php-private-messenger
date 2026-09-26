<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/Chat.php';

function chatNavigationBackendAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$chatSource = file_get_contents(__DIR__ . '/../classes/Chat.php');
$apiSource = file_get_contents(__DIR__ . '/../api/chat.php');
$attachmentSource = file_get_contents(__DIR__ . '/../api/attachment.php');
chatNavigationBackendAssert(
    is_string($chatSource) && is_string($apiSource) && is_string($attachmentSource),
    'chat navigation backend sources are readable'
);

chatNavigationBackendAssert(
    str_contains($chatSource, 'LEFT JOIN messages latest_message') &&
        str_contains($chatSource, 'candidate.is_deleted = FALSE') &&
        str_contains($chatSource, 'ORDER BY candidate.created_at DESC, candidate.id DESC') &&
        substr_count($chatSource, 'AS last_message_id') === 1 &&
        substr_count($chatSource, 'AS last_message_type') === 1 &&
        substr_count($chatSource, 'AS last_message_sender_id') === 1 &&
        substr_count($chatSource, 'AS last_message_read_count') === 1,
    'chat rows join one deterministic undeleted latest message with delivery metadata'
);

chatNavigationBackendAssert(
    str_contains($chatSource, 'INNER JOIN message_status unread_status') &&
        str_contains($chatSource, "unread_status.status IN ('sent', 'delivered')") &&
        str_contains($chatSource, 'unread_message.is_deleted = FALSE') &&
        !str_contains($chatSource, 'm.id NOT IN (SELECT message_id FROM message_status'),
    'chat-row unread counts require a real unread recipient status and exclude deleted messages'
);

chatNavigationBackendAssert(
    substr_count($chatSource, 'AS is_unread_for_user') >= 3 &&
        str_contains($chatSource, 'private function getUnreadMetadata(') &&
        substr_count($chatSource, "'first_unread_message_id' =>") >= 4 &&
        substr_count($chatSource, "'unread_count' =>") >= 4 &&
        !str_contains($chatSource, '$this->markMessagesAsRead('),
    'message reads expose pre-acknowledgement metadata without an implicit read mutation'
);

chatNavigationBackendAssert(
    str_contains($chatSource, 'public function markMessagesAsRead(') &&
        str_contains($chatSource, 'count($messageIds) > self::MAX_READ_MESSAGE_IDS') &&
        str_contains($chatSource, 'if (!$this->isParticipant($chat_id, $user_id))') &&
        str_contains($chatSource, 'AND m.is_deleted = FALSE') &&
        str_contains($chatSource, "AND ms.status IN ('sent', 'delivered')") &&
        str_contains($chatSource, 'AND m.id IN ({$messagePlaceholders})'),
    'explicit read acknowledgement is bounded, participant-authorized, and chat-scoped'
);

chatNavigationBackendAssert(
    str_contains($apiSource, 'function requireBoundedApiIdList(') &&
        str_contains($apiSource, '!array_is_list($value)') &&
        str_contains($apiSource, "case 'mark_messages_read':") &&
        str_contains($apiSource, 'CHAT_API_MAX_READ_MESSAGE_IDS') &&
        str_contains($apiSource, '$chat->markMessagesAsRead($chatId, $currentUser[\'id\'], $messageIds)'),
    'the read API accepts only a bounded canonical JSON ID list for the authenticated account'
);

$chatWithoutDatabase = (new ReflectionClass(Chat::class))->newInstanceWithoutConstructor();
$oversizedRead = $chatWithoutDatabase->markMessagesAsRead(1, 1, range(1, 101));
$invalidRead = $chatWithoutDatabase->markMessagesAsRead(1, 1, [1, '02']);
chatNavigationBackendAssert(
    $oversizedRead['success'] === false && $invalidRead['success'] === false,
    'class-level read bounds reject oversized and non-canonical lists before database access'
);

chatNavigationBackendAssert(
    str_contains($chatSource, 'public function getMessageContext(') &&
        str_contains($chatSource, 'self::MAX_CONTEXT_MESSAGES_PER_SIDE') &&
        str_contains($chatSource, 'WHERE id = ? AND chat_id = ? AND is_deleted = FALSE') &&
        str_contains($chatSource, 'ORDER BY created_at DESC, id DESC') &&
        str_contains($chatSource, 'ORDER BY created_at ASC, id ASC') &&
        str_contains($chatSource, '$beforeLimit + 1') &&
        str_contains($chatSource, '$afterLimit + 1') &&
        str_contains($chatSource, "'has_more_before' => \$hasMoreBefore") &&
        str_contains($chatSource, "'has_more_after' => \$hasMoreAfter"),
    'message context is participant-authorized, chronological, and hard-bounded on both sides'
);

chatNavigationBackendAssert(
    str_contains($apiSource, "case 'get_message_context':") &&
        str_contains($apiSource, 'CHAT_API_MAX_CONTEXT_MESSAGES_PER_SIDE') &&
        str_contains($apiSource, "['search_users', 'search_messages', 'get_message_context']") &&
        str_contains($apiSource, '$chat->getMessageContext('),
    'context lookups have validated API bounds and share the tighter search budget'
);

$oversizedContext = $chatWithoutDatabase->getMessageContext(1, 1, 1, 51, 20);
chatNavigationBackendAssert(
    $oversizedContext['success'] === false,
    'class-level context bounds reject oversized windows before database access'
);

chatNavigationBackendAssert(
    str_contains($attachmentSource, "in_array(\$messageType, ['image', 'audio', 'video'], true)") &&
        str_contains($attachmentSource, "? 'inline'") &&
        str_contains($attachmentSource, "header('Accept-Ranges: bytes')") &&
        str_contains($attachmentSource, "header('Content-Range: bytes '") &&
        str_contains($attachmentSource, 'INNER JOIN chat_participants cp'),
    'authenticated audio and video render inline without bypassing authorization or Range controls'
);

echo "Chat navigation backend tests passed.\n";
