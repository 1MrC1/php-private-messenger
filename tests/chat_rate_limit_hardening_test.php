<?php

declare(strict_types=1);

function chatRateLimitAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

function chatRateLimitConstant(string $source, string $name): int
{
    $matched = preg_match(
        '/^const\s+' . preg_quote($name, '/') . '\s*=\s*([0-9]+);$/m',
        $source,
        $matches
    );
    if ($matched !== 1) {
        throw new RuntimeException("Missing integer constant {$name}");
    }
    return (int)$matches[1];
}

$source = file_get_contents(__DIR__ . '/../api/chat.php');
chatRateLimitAssert(is_string($source), 'chat API source is readable');

$window = chatRateLimitConstant($source, 'CHAT_API_RATE_WINDOW_SECONDS');
$userLimit = chatRateLimitConstant($source, 'CHAT_API_USER_REQUEST_LIMIT');
$ipLimit = chatRateLimitConstant($source, 'CHAT_API_IP_REQUEST_LIMIT');
$userSearchLimit = chatRateLimitConstant($source, 'CHAT_API_USER_SEARCH_LIMIT');
$ipSearchLimit = chatRateLimitConstant($source, 'CHAT_API_IP_SEARCH_LIMIT');

chatRateLimitAssert(
    $window === 60 && $userLimit >= 300 && $ipLimit > $userLimit,
    'broad budgets leave headroom for several normal polling tabs'
);
chatRateLimitAssert(
    $userSearchLimit > 0 && $userSearchLimit < $userLimit &&
        $ipSearchLimit > $userSearchLimit && $ipSearchLimit < $ipLimit,
    'search actions have tighter per-user and per-IP budgets'
);
chatRateLimitAssert(
    str_contains($source, "in_array(\$action, ['search_users', 'search_messages', 'get_message_context'], true)") &&
        str_contains($source, "'chat_search_user'") &&
        str_contains($source, "'chat_search_ip'"),
    'database search and bounded message-context actions share the tighter search admission path'
);
chatRateLimitAssert(
    str_contains($source, "\$_SERVER['REMOTE_ADDR']") &&
        str_contains($source, 'inet_pton($remoteAddress)') &&
        !str_contains($source, "\$_SERVER['HTTP_X_FORWARDED_FOR']") &&
        !str_contains($source, "\$_SERVER['HTTP_CF_CONNECTING_IP']"),
    'IP budgets use a canonicalized server peer address, not spoofable forwarding headers'
);

$firstSessionStart = strpos($source, 'if (!Auth::startExistingSession())');
$secondSessionStart = $firstSessionStart === false
    ? false
    : strpos($source, 'if (!Auth::startExistingSession())', $firstSessionStart + 1);
$firstSessionIdentity = strpos($source, '$sessionUserId = chatApiSessionUserId();');
$secondSessionIdentity = $firstSessionIdentity === false
    ? false
    : strpos($source, '$sessionUserId = chatApiSessionUserId();', $firstSessionIdentity + 1);
$uploadReservation = strpos($source, 'reserveChatApiRequestBudget($sessionUserId)');
$jsonReservation = $uploadReservation === false
    ? false
    : strpos($source, 'reserveChatApiRequestBudget($sessionUserId)', $uploadReservation + 1);
$firstAuthConstruction = strpos($source, '$auth = new Auth();');
$lastAuthConstruction = strrpos($source, '$auth = new Auth();');
$firstChatConstruction = strpos($source, '$chat = new Chat();');
$lastChatConstruction = strrpos($source, '$chat = new Chat();');
chatRateLimitAssert(
    $firstSessionStart !== false && $secondSessionStart !== false &&
        $firstSessionIdentity !== false && $secondSessionIdentity !== false &&
        $uploadReservation !== false && $jsonReservation !== false &&
        $firstAuthConstruction !== false && $lastAuthConstruction !== false &&
        $firstChatConstruction !== false && $lastChatConstruction !== false &&
        $firstSessionStart < $firstSessionIdentity &&
        $firstSessionIdentity < $uploadReservation &&
        $uploadReservation < $firstAuthConstruction &&
        $secondSessionStart < $secondSessionIdentity &&
        $secondSessionIdentity < $jsonReservation &&
        $jsonReservation < $lastAuthConstruction &&
        $uploadReservation < $firstChatConstruction &&
        $jsonReservation < $lastChatConstruction &&
        substr_count($source, 'reserveChatApiRequestBudget($sessionUserId)') === 2 &&
        substr_count($source, '$auth = new Auth();') === 2 &&
        substr_count($source, '$chat = new Chat();') === 2,
    'multipart and JSON requests reserve broad budgets before Auth and Chat database connections'
);
chatRateLimitAssert(
    str_contains($source, 'function chatApiSessionUserId(): ?int') &&
        str_contains($source, "preg_match('/\\A[1-9][0-9]*\\z/D', \$value)") &&
        str_contains($source, 'FILTER_VALIDATE_INT') &&
        str_contains($source, "'max_range' => PHP_INT_MAX"),
    'the preliminary account identity accepts only canonical positive integers without overflow'
);
chatRateLimitAssert(
    str_contains($source, 'reserveChatApiSearchBudget((int)$currentUser[\'id\'], $input[\'action\'])') &&
        str_contains($source, "'chat_search_user'") &&
        str_contains($source, "'chat_search_ip'"),
    'search-specific limits remain in addition to the early broad budget'
);
chatRateLimitAssert(
    str_contains($source, "Auth::releaseRateLimitAttempt('chat_api_ip', \$remoteIdentity)") &&
        str_contains($source, "Auth::releaseRateLimitAttempt('chat_search_ip', \$remoteIdentity)") &&
        !str_contains($source, "Auth::clearRateLimit('chat_api_") &&
        !str_contains($source, "Auth::clearRateLimit('chat_search_"),
    'partial composite reservations roll back without clearing accepted request history'
);
chatRateLimitAssert(
    str_contains($source, "http_response_code(429)") &&
        str_contains($source, "header('Retry-After: ' . CHAT_API_RATE_WINDOW_SECONDS)"),
    'rate-limit denials return 429 with retry guidance'
);

echo "Chat API rate-limit hardening tests passed.\n";
