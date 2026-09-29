<?php

declare(strict_types=1);

function clientSendAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$script = file_get_contents(__DIR__ . '/../assets/js/script-ori_2025-06-07_02.js');
$security = file_get_contents(__DIR__ . '/../assets/js/security-hardening.js');
$events = file_get_contents(__DIR__ . '/../assets/js/csp-events.js');
$enhancements = file_get_contents(__DIR__ . '/../assets/js/ui-enhancements.js');
$chatUx = file_get_contents(__DIR__ . '/../assets/js/chat-ux.js');
$chat = file_get_contents(__DIR__ . '/../classes/Chat.php');
$api = file_get_contents(__DIR__ . '/../api/chat.php');
$index = file_get_contents(__DIR__ . '/../index.html');
clientSendAssert(
    is_string($script) && is_string($security) && is_string($events) && is_string($chatUx) &&
        is_string($enhancements) && is_string($chat) && is_string($api) && is_string($index),
    'loaded client send sources are readable'
);

clientSendAssert(
    str_contains($script, 'let messageIdempotencyReady = false;') &&
        str_contains($script, 'let chatListRequestEpoch = 0;') &&
        str_contains($script, 'const requestEpoch = ++chatListRequestEpoch;') &&
        str_contains($script, 'if (requestEpoch !== chatListRequestEpoch) return false;') &&
        str_contains($script, 'isValidSuccess && data.message_idempotency_ready === true') &&
        str_contains($script, 'if (requestEpoch === chatListRequestEpoch) {') &&
        str_contains($script, 'setMessageIdempotencyCapability(false);'),
    'message idempotency requires the newest explicit successful capability and fails closed otherwise'
);

clientSendAssert(
    str_contains($script, "formData.append('client_message_id', clientMessageId)") &&
        str_contains($script, 'requestData.client_message_id = clientMessageId') &&
        substr_count($script, 'if (useIdempotency)') >= 3,
    'JSON and multipart UUID fields remain gated during migration-first deployment'
);

clientSendAssert(
    str_contains($script, 'secureCrypto.randomUUID()') &&
        str_contains($script, 'secureCrypto.getRandomValues(bytes)') &&
        str_contains($script, 'bytes[6] = (bytes[6] & 0x0f) | 0x40;') &&
        str_contains($script, 'bytes[8] = (bytes[8] & 0x3f) | 0x80;'),
    'client identifiers use cryptographic RFC4122 UUID v4 generation without a weak fallback'
);

clientSendAssert(
        str_contains($script, 'const MAX_SEND_ATTEMPTS = 2;') &&
        str_contains($script, 'canRetryChatSend(allowRetry, capabilityEpoch, expectedClientMessageId)') &&
        str_contains($script, 'capabilityEpoch === messageIdempotencyEpoch') &&
        str_contains($script, 'pendingClientMessage.id === expectedClientMessageId') &&
        str_contains($script, 'response.status >= 500 && response.status <= 599'),
    'automatic retries are bounded, 5xx-only, and canceled when capability or send semantics change'
);

clientSendAssert(
    str_contains($script, '!response.ok || !payload || payload.success !== true') &&
        str_contains($script, "status === 409") &&
        str_contains($script, "status === 429") &&
        str_contains($script, "error.setAttribute('role', 'alert')") &&
        str_contains($script, 'restoreComposerAfterFailedSend(input)') &&
        str_contains($script, 'semanticEpoch === clientSendSemanticEpoch') &&
        str_contains($script, 'currentAttachment === attachment'),
    'failures are accessible and acknowledgements do not erase newer composer or attachment state'
);

clientSendAssert(
    str_contains($script, 'let chatSendInFlight = false;') &&
        str_contains($script, 'if (chatSendInFlight) return;') &&
        str_contains($script, 'if (!sendBtn || sendBtn.disabled) return;') &&
        str_contains($script, 'chatSendInFlight = true;') &&
        str_contains($script, 'chatSendInFlight = false;') &&
        str_contains($script, 'Promise.resolve()'),
    'one in-flight guard covers keyboard and button sends and always releases in the promise finalizer'
);

clientSendAssert(
    str_contains($script, 'const AUTH_REQUEST_TIMEOUT_MS = 20000;') &&
        str_contains($script, 'const CHAT_SEND_TEXT_TIMEOUT_MS = 30000;') &&
        str_contains($script, 'const CHAT_SEND_ATTACHMENT_TIMEOUT_MS = 120000;') &&
        str_contains($script, 'function fetchWithTimeout(resource, options, timeoutMs, responseHandler)') &&
        str_contains($script, "typeof responseHandler === 'function' ? responseHandler(response) : response") &&
        str_contains($script, 'function fetchChatAttempt(options, timeoutMs, isAttachment)') &&
        str_contains($script, 'return readChatSendResponse(response, isAttachment).then(function (data)') &&
        str_contains($script, 'return Promise.race([request, timeoutPromise]).finally(function ()') &&
        str_contains($enhancements, "}).then(function (response) {\n                    return response.json();") &&
        str_contains($chatUx, "}).then(function (response) {\n            if (!response.ok)") &&
        str_contains($script, 'return completeLoginAfter2FA();'),
    'authentication, send, edit, and read-response bodies are time-bounded while 2FA keeps its UI lock'
);

clientSendAssert(
    str_contains($script, 'const CHAT_SEND_FAILURE_MESSAGES = Object.freeze({') &&
        str_contains($script, 'Object.prototype.hasOwnProperty.call(CHAT_SEND_FAILURE_MESSAGES, errorCode)') &&
        str_contains($script, 'send_outcome_unknown:') &&
        str_contains($script, 'attachment_quota_reached:') &&
        str_contains($script, 'reply_unavailable:') &&
        !str_contains($script, 'return payload.message;') &&
        substr_count($script, 'Delivery could not be confirmed') >= 3,
    'send failures use an allowlisted client mapping and never display arbitrary backend messages'
);

clientSendAssert(
    str_contains($chat, "'send_busy',") &&
        str_contains($chat, "'message_rate_limited',") &&
        str_contains($chat, "'reply_unavailable',") &&
        str_contains($chat, "'attachment_quota_reached',") &&
        str_contains($chat, "'attachment_hourly_limit',") &&
        str_contains($chat, "'attachment_storage_unavailable',") &&
        str_contains($chat, "'send_outcome_unknown',") &&
        str_contains($chat, "'messaging_unavailable',") &&
        str_contains($chat, 'if ($commitAttempted && !$messageCommitted)') &&
        str_contains($api, "unset(\$response['http_status'], \$response['retry_after']);") &&
        str_contains($api, "'error_code' => 'invalid_request'") &&
        str_contains($api, "'error_code' => 'request_failed'"),
    'backend send failures carry stable status/code mappings and distinguish ambiguous commits'
);

clientSendAssert(
    str_contains($script, 'name.textContent = file.name;') &&
        str_contains($script, 'if (currentAttachment !== file || typeof reader.result !==') &&
        str_contains($script, 'reader.onerror = function () {') &&
        str_contains($script, 'content.replaceChildren(row);') &&
        !str_contains($script, "'<div class=\"fw-bold\">' + file.name"),
    'attachment previews render filenames as text and stale FileReader callbacks cannot replace a newer selection'
);

$avatarMimeValidation = strpos(
    $script,
    "['image/jpeg', 'image/png', 'image/gif', 'image/webp'].includes(file.type)"
);
$avatarSizeValidation = strpos($script, 'file.size < 1 || file.size > 5 * 1024 * 1024');
$avatarSelectionToken = strpos($script, 'const selectionToken = ++avatarSelectionEpoch;');
$avatarInputReset = strpos($script, "input.value = '';\n        const selectionToken", $avatarSizeValidation ?: 0);
clientSendAssert(
    is_int($avatarMimeValidation) && is_int($avatarSizeValidation) && is_int($avatarSelectionToken) &&
        is_int($avatarInputReset) &&
        $avatarMimeValidation < $avatarSelectionToken && $avatarSizeValidation < $avatarSelectionToken &&
        $avatarInputReset < $avatarSelectionToken &&
        str_contains($script, 'const selectionToken = ++avatarSelectionEpoch;') &&
        str_contains($script, 'URL.createObjectURL(file)') &&
        str_contains($script, 'container.replaceChildren(image, overlay);') &&
        substr_count($script, 'selectionToken !== avatarSelectionEpoch') >= 3 &&
        str_contains($script, 'let avatarUploadInFlight = false;') &&
        str_contains($script, 'let pendingAvatarUpload = null;') &&
        str_contains($script, 'processNextAvatarUpload();') &&
        str_contains($script, 'if (avatarUploadInFlight || pendingAvatarUpload === null) return;') &&
        str_contains($script, 'result.response.ok && data && data.success === true') &&
        substr_count($script, 'return refreshCurrentUserProfile(selectionToken);') >= 2 &&
        str_contains($script, 'function refreshCurrentUserProfile(selectionToken)') &&
        str_contains($script, 'selectionToken === undefined || selectionToken === avatarSelectionEpoch') &&
        !str_contains($script, "if (!file.type.startsWith('image/'))"),
    'avatar uploads validate before queue mutation, serialize reconciliation, and guard stale rendering'
);

clientSendAssert(
    str_contains($script, 'const originalButtonChildren = Array.from(sendBtn.childNodes') &&
        str_contains($script, 'sendBtn.replaceChildren(spinner);') &&
        str_contains($script, 'sendBtn.replaceChildren(...originalButtonChildren);') &&
        !str_contains($script, 'sendBtn.innerHTML = originalHTML;') &&
        str_contains($enhancements, 'sendButton.replaceChildren(spinner);') &&
        str_contains($enhancements, 'sendButton.replaceChildren(...originalButtonChildren);') &&
        !str_contains($enhancements, 'sendButton.innerHTML = originalHtml;'),
    'send and edit loading states restore cloned nodes without reparsing HTML'
);

clientSendAssert(
    str_contains($security, 'window.pmSecurityHardeningReady = false;') &&
        str_contains($security, 'window.pmSecurityHardeningReady = true;') &&
        str_contains($security, 'requiredLegacyFunctions.every') &&
        str_contains($script, 'window.pmSecurityHardeningReady !== true') &&
        str_contains($events, 'window.pmSecurityHardeningReady !== true') &&
        str_contains($enhancements, 'window.pmSecurityHardeningReady !== true'),
    'application startup and delegated interactions fail closed if hardening is missing or reordered'
);

clientSendAssert(
    str_contains($security, 'const existingItems = new Map();') &&
        str_contains($security, 'refs.avatarUrl !== nextAvatarUrl') &&
        str_contains($security, 'item.__pmChatData = chat;') &&
        str_contains($security, "item.dataset.keyboardReady = 'true';") &&
        !str_contains($enhancements, 'item.dataset.chatId = String(chatId);') &&
        substr_count($enhancements, "item.querySelector('.unread-count:not([hidden])')") === 2,
    'chat polling reconciles stable rows without duplicate keyboard handlers, index-remapping IDs, hidden unread badges, or unchanged avatar images'
);

$secureSelect = strpos($security, 'window.selectChat = function secureSelectChat');
$secureSelectHook = is_int($secureSelect)
    ? strpos($security, 'markClientSendSemanticsChanged();', $secureSelect)
    : false;
$secureSelectAssignment = is_int($secureSelect)
    ? strpos($security, 'currentChatId = safeChatId;', $secureSelect)
    : false;
clientSendAssert(
    str_contains($security, "'markClientSendSemanticsChanged'") &&
        is_int($secureSelectHook) && is_int($secureSelectAssignment) &&
        $secureSelectHook < $secureSelectAssignment,
    'the active hardened chat selector cancels pending retries before changing conversations'
);

clientSendAssert(
    str_contains($index, 'assets/css/style.css?v=20260929.2') &&
        str_contains($index, 'i18n.js?v=20260929.2') &&
        str_contains($index, 'script-ori_2025-06-07_02.js?v=20260929.2') &&
        str_contains($index, 'security-hardening.js?v=20260929.2') &&
        str_contains($index, 'ui-enhancements.js?v=20260929.2') &&
        str_contains($index, 'csp-events.js?v=20260929.2') &&
        str_contains($index, 'chat-ux.js?v=20260929.2'),
    'the deployed client cache key includes message-send hardening'
);

clientSendAssert(
    str_contains($index, 'data-pm-action="chat-home"') &&
        str_contains($index, 'aria-label="Messenger, go to chat home"') &&
        str_contains($events, "'chat-home': function () { invoke('showChatHome'); }") &&
        str_contains($enhancements, 'window.showChatHome = function showChatHome()') &&
        str_contains($enhancements, 'currentChatId = null;') &&
        str_contains($enhancements, "state.activeChatKey = '';") &&
        str_contains($enhancements, 'state.chatSelectionEpoch += 1;') &&
        str_contains($enhancements, 'setSurfaceVisibility(chatContent, false);'),
    'the keyboard-accessible brand action returns every viewport to a deselected chat home'
);

echo "Client send hardening tests passed.\n";
