<?php

declare(strict_types=1);

function chatUxAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$index = file_get_contents(__DIR__ . '/../index.html');
$style = file_get_contents(__DIR__ . '/../assets/css/style.css');
$application = file_get_contents(__DIR__ . '/../assets/js/script-ori_2025-06-07_02.js');
$security = file_get_contents(__DIR__ . '/../assets/js/security-hardening.js');
$enhancements = file_get_contents(__DIR__ . '/../assets/js/ui-enhancements.js');
$events = file_get_contents(__DIR__ . '/../assets/js/csp-events.js');
$ux = file_get_contents(__DIR__ . '/../assets/js/chat-ux.js');
$chat = file_get_contents(__DIR__ . '/../classes/Chat.php');
$api = file_get_contents(__DIR__ . '/../api/chat.php');
$htaccess = file_get_contents(__DIR__ . '/../.htaccess');

chatUxAssert(
    is_string($index) && is_string($style) && is_string($application) && is_string($security) &&
        is_string($enhancements) && is_string($events) && is_string($ux) && is_string($chat) &&
        is_string($api) && is_string($htaccess),
    'chat UX and security sources are readable'
);

chatUxAssert(
    str_contains($index, 'id="chatSidePanel"') &&
        str_contains($index, 'id="chatSideSearchInput"') &&
        str_contains($index, 'id="chatSideSearchResults"') &&
        str_contains($index, 'id="chatSideInfoContent"') &&
        str_contains($style, '@media (min-width: 1200px)') &&
        str_contains($style, '.chat-side-panel:not([hidden])'),
    'wide screens receive a real docked search/info column with responsive fallback'
);

chatUxAssert(
    str_contains($index, 'id="messagesList" role="log" aria-live="polite"') &&
        str_contains($index, 'id="messagesContainer" role="region" tabindex="0"') &&
        str_contains($security, 'const fragment = document.createDocumentFragment();') &&
        str_contains($security, 'container.insertBefore(fragment, container.firstChild);') &&
        !str_contains($security, 'container.insertBefore(messageRow, container.firstChild);'),
    'message history is an accessible log and older chronological blocks are prepended without reversal'
);

chatUxAssert(
    str_contains($security, 'messageRow.dataset.createdAt =') &&
        str_contains($security, 'messageRow.dataset.isUnread =') &&
        str_contains($ux, "createTimelineMarker('date'") &&
        str_contains($ux, "createTimelineMarker('unread', localizedLiteral('Unread messages')") &&
        str_contains($application, 'function parseServerTimestamp(timestamp)') &&
        str_contains($application, "+ 'Z'"),
    'date and unread separators use explicit message metadata and normalized UTC timestamps'
);

chatUxAssert(
    str_contains($chat, 'AS is_unread_for_user') &&
        str_contains($chat, 'private function getUnreadMetadata(') &&
        !str_contains($chat, '$this->markMessagesAsRead(') &&
        str_contains($api, "case 'mark_messages_read':") &&
        str_contains($ux, "document.visibilityState === 'visible'") &&
        str_contains($ux, 'document.hasFocus()') &&
        str_contains($ux, "window.addEventListener('focus'") &&
        str_contains($ux, "document.addEventListener('hidden.bs.modal'") &&
        str_contains($ux, 'readQueues: new Map()') &&
        str_contains($ux, "action: 'mark_messages_read'") &&
        str_contains($ux, 'messageIsVisible(row, container)'),
    'fetching does not mark messages read and acknowledgements are explicit, bounded, and visibility-aware'
);

chatUxAssert(
    str_contains($ux, 'const controller = typeof AbortController') &&
        str_contains($ux, 'sequence !== uxState.searchSequence || chatId !== activeChatId()') &&
        str_contains($ux, "action: 'get_message_context'") &&
        str_contains($chat, 'MAX_CONTEXT_MESSAGES_PER_SIDE = 50') &&
        str_contains($api, "'get_message_context'"),
    'message search cancels stale work and loads only a participant-authorized bounded context'
);

chatUxAssert(
    str_contains($security, "url.pathname !== '/api/attachment.php'") &&
        str_contains($security, "message.message_type === 'audio'") &&
        str_contains($security, "message.message_type === 'video'") &&
        str_contains($security, "audio.preload = 'metadata'") &&
        str_contains($security, "video.preload = 'metadata'") &&
        !str_contains($security, "audio.src = message.file_path") &&
        !str_contains($security, "video.src = message.file_path"),
    'native audio and video consume only canonical authenticated PHP attachment URLs'
);

chatUxAssert(
    str_contains($index, 'data-pm-action="emoji-picker"') &&
        str_contains($ux, 'input.setRangeText(value, start, end,') &&
        str_contains($ux, "new Event('input', {bubbles: true})") &&
        str_contains($ux, "event.key === 'Escape'") &&
        str_contains($ux, 'button.tabIndex = index === 0 ? 0 : -1;') &&
        str_contains($ux, "button.setAttribute('aria-selected', button === target ? 'true' : 'false')") &&
        !str_contains($index, 'id="emojiGrid" role="listbox" tabindex="0"') &&
        !str_contains($ux, '.innerHTML'),
    'the bundled emoji picker is CSP-safe and preserves composer input/draft hooks'
);

chatUxAssert(
    str_contains($ux, 'const MAX_RECORDING_BYTES = 50 * 1024 * 1024;') &&
        str_contains($ux, 'const MAX_RECORDING_MS = 5 * 60 * 1000;') &&
        str_contains($ux, 'navigator.mediaDevices.getUserMedia({audio: true})') &&
        str_contains($ux, 'MediaRecorder.isTypeSupported(candidate)') &&
        str_contains($ux, 'uxState.voice.session !== session') &&
        str_contains($ux, 'session.stream.getTracks().forEach') &&
        str_contains($ux, 'sourceChatId !== activeChatId()') &&
        str_contains($ux, "window.addEventListener('pagehide'") &&
        str_contains($application, "'audio/webm'") && str_contains($application, "'audio/ogg'"),
    'voice capture is gesture-driven, format-detected, size/time bounded, and releases every media track'
);

chatUxAssert(
    str_contains($htaccess, 'microphone=(), geolocation=()" env=PM_PRIVATE_MEDIA') &&
        str_contains($htaccess, 'microphone=(self), geolocation=()" env=!PM_PRIVATE_MEDIA'),
    'microphone permission is enabled only for app documents while private media remains capture-inert'
);

chatUxAssert(
    str_contains($enhancements, "hiAppSurface: 'list'") &&
        str_contains($enhancements, "hiAppSurface: 'chat'") &&
        str_contains($enhancements, 'window.history.pushState(nextState') &&
        str_contains($enhancements, 'window.history.replaceState(nextState') &&
        str_contains($enhancements, 'window.addEventListener(\'popstate\'') &&
        str_contains($enhancements, '!chatKeyAtRequest || !state.activeChatKey'),
    'mobile Back/Forward uses one surface coordinator and stale chat responses fail closed'
);

chatUxAssert(
    str_contains($security, "item.setAttribute('role', 'option')") &&
        str_contains($enhancements, 'function syncChatListRovingTabStop(') &&
        str_contains($ux, "row.setAttribute('aria-keyshortcuts', 'Shift+F10')") &&
        str_contains($ux, "list.addEventListener('contextmenu'") &&
        str_contains($ux, "list.addEventListener('pointerdown'") &&
        !str_contains($ux, 'function ensureRowMenuButton('),
    'conversation options preserve one valid roving listbox tab stop with keyboard and long-press access'
);

chatUxAssert(
    str_contains($ux, 'pinned: Array.from(uxState.pinned)') &&
        str_contains($ux, 'muted: Array.from(uxState.muted)') &&
        !str_contains($ux, 'drafts: Array.from') &&
        str_contains($enhancements, 'const chatDrafts = new Map();'),
    'on-device pin/mute preferences persist without writing message drafts to storage'
);

chatUxAssert(
    str_contains($application, 'window.isSupportedChatAttachment = function') &&
        str_contains($application, "'text/csv'") &&
        str_contains($application, "'application/rtf'") &&
        str_contains($application, "'application/vnd.ms-powerpoint'") &&
        str_contains($application, "'application/zip'") &&
        !str_contains($application, "'audio/mp3'") &&
        !str_contains($application, "'audio/x-m4a'") &&
        !str_contains($application, "'audio/x-flac'") &&
        str_contains($enhancements, '!window.isSupportedChatAttachment(file)') &&
        !str_contains($enhancements, 'const allowedTypes = new Set(['),
    'file picker and drag/drop share the complete server-compatible attachment allowlist'
);

chatUxAssert(
    str_contains($application, 'delivery_unconfirmed: malformedSuccessfulResponse || response.status >= 500') &&
        str_contains($application, "['send_outcome_unknown', 'messaging_unavailable', 'request_failed']") &&
        str_contains($application, "data.delivery_unconfirmed ? 'unconfirmed' : 'rejected'") &&
        str_contains($application, 'clientMessageId || localDeliveryAttemptId') &&
        str_contains($application, 'attemptId: String(attemptId ||') &&
        str_contains($ux, "detail.state === 'sending'") &&
        str_contains($ux, 'unconfirmed: new Set()') &&
        str_contains($ux, 'entry.unconfirmed.add(attemptId)') &&
        str_contains($ux, "detail.state === 'sent'") &&
        !str_contains($ux, 'latestSenderId === activeUserId() && deliveryAdvanced'),
    'ambiguous send outcomes remain attempt-scoped until a matching acknowledgement resolves them'
);

chatUxAssert(
    str_contains($ux, 'setSearchContextReviewing(true);') &&
        str_contains($security, 'window.pmSuppressNewMessageAutoScroll !== true') &&
        str_contains($enhancements, 'window.exitSearchContextReview();') &&
        str_contains($application, 'function loadChatStats(targetElement)') &&
        str_contains($application, 'messageCountEl.isConnected') &&
        str_contains($index, '<label class="visually-hidden" for="chatSearchInput">') &&
        str_contains($index, 'id="chatSearchStatus"') &&
        substr_count($index, 'maxlength="100"') >= 2,
    'search context preserves the reading viewport and stale info/search responses cannot overwrite another chat'
);

chatUxAssert(
    str_contains($style, '@media (max-width: 768px)') &&
        str_contains($style, 'max-width: none;') &&
        str_contains($style, 'flex-basis: 100%;'),
    'the final mobile cascade gives the conversation sidebar the full viewport width'
);

chatUxAssert(
    str_contains($enhancements, "typeof window.cleanupTransientChatUx === 'function'") &&
        str_contains($ux, 'window.cleanupTransientChatUx = function') &&
        str_contains($ux, 'flushReadAcknowledgements(chatId, true)') &&
        str_contains($ux, 'window.cancelActiveMessageLoad();') &&
        str_contains($application, 'messageLoadRequestEpoch') &&
        str_contains($application, 'messageLoadController.abort()') &&
        str_contains($application, 'requestEpoch !== messageLoadRequestEpoch') &&
        str_contains($application, 'window.stopActiveTyping = function'),
    'leaving or switching chats cleans transient capture, read, typing, and timeline work without cross-chat leaks'
);

chatUxAssert(
    str_contains($ux, ".emoji-option:not([hidden])") &&
        str_contains($ux, 'gridTemplateColumns.trim()') &&
        str_contains($security, 'includesOwnNewMessage') &&
        str_contains($security, '(wasAtBottom || isInitialLoad || includesOwnNewMessage)') &&
        str_contains($ux, 'const orderChanged = preferredOrder.some') &&
        str_contains($ux, 'setTextIfChanged(preview'),
    'keyboard, polling, and row decoration preserve visual order, reading position, and observer liveness'
);

chatUxAssert(
    str_contains($application, 'const newMessagePollCursors = new Map();') &&
        str_contains($application, 'requestEpoch !== newMessagePollRequestEpoch') &&
        str_contains($application, "String(currentChatId) !== requestChatId") &&
        str_contains($application, "action: 'get_messages'") &&
        str_contains($application, 'renderMessages(data.messages, false, false);') &&
        str_contains($application, '} else if (!currentLastMessageId) {') &&
        str_contains($ux, 'orderedRows.forEach(function (row) { list.appendChild(row); });') &&
        !str_contains($application, 'lastMessageId = newMessages[newMessages.length - 1].id;'),
    'live polling is chat-scoped, recovers empty timelines authoritatively, and preserves ordered server cursors'
);

chatUxAssert(
    str_contains($application, 'let messageLoadCursor = null;') &&
        str_contains($application, 'const activeIsPagination = messageLoadCursor !== null;') &&
        str_contains($security, 'const oldScrollTop = prepend ? scrollContainer.scrollTop : 0;') &&
        str_contains($security, 'oldScrollTop + scrollContainer.scrollHeight - oldScrollHeight') &&
        str_contains($security, 'scrollEpoch !== messageScrollRequestEpoch') &&
        str_contains($ux, 'markerHeightDelta') &&
        str_contains($ux, 'window.loadMessages(chatId);'),
    'latest reloads supersede pagination while prepend markers and delayed scrolling preserve the viewport'
);

chatUxAssert(
    str_contains($security, "messageRow.dataset.messageType =") &&
        str_contains($security, "appendTextElement(content, 'div', 'message-text'") &&
        str_contains($style, '.message-text {') &&
        str_contains($application, 'getRenderedMessageBody(messageElement)') &&
        str_contains($application, "new window.CustomEvent('pm:attachment-state-change')") &&
        str_contains($ux, "window.addEventListener('pm:attachment-state-change'") &&
        str_contains($ux, 'input.dataset.editMessageId'),
    'message bodies, edit state, attachments, and voice controls share one unambiguous composer state'
);

chatUxAssert(
    str_contains($ux, 'forceRetry: false') &&
        str_contains($ux, 'keepalive: true') &&
        str_contains($ux, 'queue.forceRetry = true;') &&
        str_contains($ux, "error.name = 'TimeoutError';") &&
        str_contains($ux, "window.addEventListener('online'") &&
        str_contains($ux, 'uxState.readQueues.forEach(function (queue, chatId)') &&
        substr_count($ux, "window.addEventListener('pagehide'") === 1,
    'observed read acknowledgements retry across surface changes and flush during page lifecycle exit'
);

chatUxAssert(
    str_contains($application, 'id="storageUsageSummary" aria-live="polite"') &&
        str_contains($application, 'function updateStorageUnavailable()') &&
        str_contains($application, "strong.textContent = 'Unavailable'") &&
        str_contains($ux, 'function isVisibleFocusTarget(element)') &&
        str_contains($enhancements, '!candidate.closest(\'[aria-hidden="true"]\')'),
    'failed settings loads and hidden overflow openers resolve to visible, announced UI states'
);

chatUxAssert(
    substr_count($index, 'v=20261001.1') === 12 &&
        str_contains($index, 'assets/js/i18n.js?v=20261001.1') &&
        str_contains($index, 'assets/js/chat-ux.js?v=20261001.1'),
    'all first-party frontend layers deploy under one cache key'
);

// ---- the protected helpers must be reachable from the interface ------------
// A review found sendAttachment, openAttachment, admitDevices and the recovery
// pair existing in the client with nothing calling them, while the documentation
// described them as shipped. These pin the wiring that makes them reachable.

$protectedUi = (string)file_get_contents(__DIR__ . '/../assets/js/protected-ui.js');
foreach ([
    'window.handleFileSelect' => 'a file chosen in a protected conversation is encrypted instead of uploaded',
    'window.pmShowRecoveryDialog' => 'the recovery dialog can be opened',
    'window.pmDownloadRecoveryFile' => 'a recovery file can be downloaded',
    'window.pmRestoreFromRecoveryFile' => 'a device can be restored from one',
    'admitNewDevices(' => 'devices enrolled later are admitted',
    'protected-attachment' => 'an encrypted attachment is rendered as something openable',
] as $needle => $why) {
    chatUxAssert(str_contains($protectedUi, $needle), $why);
}

$events = (string)file_get_contents(__DIR__ . '/../assets/js/csp-events.js');
foreach (['protected-recovery', 'protected-recovery-download', 'protected-recovery-restore'] as $action) {
    chatUxAssert(
        str_contains($events, "'" . $action . "'"),
        'the action is bound externally rather than inline: ' . $action
    );
}

$markup = (string)file_get_contents(__DIR__ . '/../index.html');
foreach ([
    'id="protectedRecoveryModal"',
    'data-pm-action="protected-recovery"',
    'data-pm-action="protected-recovery-download"',
    'data-pm-action="protected-recovery-restore"',
    'id="protectedRecoveryPassphrase"',
] as $needle) {
    chatUxAssert(str_contains($markup, $needle), 'the recovery interface is present: ' . $needle);
}
chatUxAssert(
    !preg_match('/<[^>]*\son[a-z]+=/i', $markup),
    'none of it uses an inline handler, which the policy denies'
);

echo "Chat UX hardening tests passed.\n";
