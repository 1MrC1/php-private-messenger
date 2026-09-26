<?php

declare(strict_types=1);

function protectedApiAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

function protectedApiConstant(string $source, string $name): int
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

/** @return list<int> */
function protectedApiPositions(string $source, string $needle): array
{
    $positions = [];
    $offset = 0;
    while (($position = strpos($source, $needle, $offset)) !== false) {
        $positions[] = $position;
        $offset = $position + strlen($needle);
    }
    return $positions;
}

/**
 * Verify every protected branch orders its work as:
 * existing session -> strict account identity -> broad reservation -> Auth DB.
 */
function protectedApiAssertEarlyOrdering(
    string $source,
    string $sessionIdentityNeedle,
    string $reservationNeedle,
    int $expectedBranches,
    string $endpoint
): void {
    $starts = protectedApiPositions($source, 'if (!Auth::startExistingSession())');
    $identities = protectedApiPositions($source, $sessionIdentityNeedle);
    $reservations = protectedApiPositions($source, $reservationNeedle);
    $authConstructions = protectedApiPositions($source, '$auth = new Auth();');

    protectedApiAssert(
        count($starts) === $expectedBranches &&
            count($identities) === $expectedBranches &&
            count($reservations) === $expectedBranches &&
            count($authConstructions) === $expectedBranches,
        "{$endpoint} has one complete early-admission sequence per protected branch"
    );

    foreach ($starts as $index => $start) {
        protectedApiAssert(
            $start < $identities[$index] &&
                $identities[$index] < $reservations[$index] &&
                $reservations[$index] < $authConstructions[$index],
            "{$endpoint} branch " . ($index + 1) . ' reserves before Auth opens its database connection'
        );
    }
}

$chat = file_get_contents(__DIR__ . '/../api/chat.php');
$settings = file_get_contents(__DIR__ . '/../api/settings.php');
$profile = file_get_contents(__DIR__ . '/../api/profile.php');
protectedApiAssert(
    is_string($chat) && is_string($settings) && is_string($profile),
    'protected API sources are readable'
);

$chatWindow = protectedApiConstant($chat, 'CHAT_API_RATE_WINDOW_SECONDS');
$chatUserLimit = protectedApiConstant($chat, 'CHAT_API_USER_REQUEST_LIMIT');
$chatIpLimit = protectedApiConstant($chat, 'CHAT_API_IP_REQUEST_LIMIT');
$settingsWindow = protectedApiConstant($settings, 'SETTINGS_API_RATE_WINDOW_SECONDS');
$settingsUserLimit = protectedApiConstant($settings, 'SETTINGS_API_USER_REQUEST_LIMIT');
$settingsIpLimit = protectedApiConstant($settings, 'SETTINGS_API_IP_REQUEST_LIMIT');
$profileWindow = protectedApiConstant($profile, 'PROFILE_API_RATE_WINDOW_SECONDS');
$profileUserLimit = protectedApiConstant($profile, 'PROFILE_API_USER_REQUEST_LIMIT');
$profileIpLimit = protectedApiConstant($profile, 'PROFILE_API_IP_REQUEST_LIMIT');

protectedApiAssert(
    $chatWindow === 60 && $chatUserLimit >= 300 && $chatIpLimit >= $chatUserLimit * 5,
    'chat admission preserves several normal polling tabs and shared-IP headroom'
);
protectedApiAssert(
    $settingsWindow === 60 && $settingsUserLimit >= 60 && $settingsUserLimit <= 180 &&
        $settingsIpLimit >= $settingsUserLimit * 5,
    'settings admission permits UI bursts while bounding aggregation and database work'
);
protectedApiAssert(
    $profileWindow === 60 && $profileUserLimit >= 30 && $profileUserLimit <= 120 &&
        $profileIpLimit >= $profileUserLimit * 5,
    'profile admission permits retries while bounding image and database work'
);

$endpointChecks = [
    'chat' => [
        $chat,
        'chatApiSessionUserId',
        'reserveChatApiRequestBudget',
        'chat_api_ip',
        'chat_api_user',
        'CHAT_API_RATE_WINDOW_SECONDS',
        2
    ],
    'settings' => [
        $settings,
        'settingsApiSessionUserId',
        'reserveSettingsApiRequestBudget',
        'settings_api_ip',
        'settings_api_user',
        'SETTINGS_API_RATE_WINDOW_SECONDS',
        1
    ],
    'profile' => [
        $profile,
        'profileApiSessionUserId',
        'reserveProfileApiRequestBudget',
        'profile_api_ip',
        'profile_api_user',
        'PROFILE_API_RATE_WINDOW_SECONDS',
        1
    ]
];

foreach ($endpointChecks as $endpoint => $check) {
    [$source, $identityFunction, $reservationFunction, $ipScope, $userScope, $windowConstant, $branches] = $check;

    protectedApiAssert(
        str_contains($source, "function {$identityFunction}(): ?int") &&
            str_contains($source, "preg_match('/\\A[1-9][0-9]*\\z/D', \$value)") &&
            str_contains($source, 'FILTER_VALIDATE_INT') &&
            str_contains($source, "'min_range' => 1, 'max_range' => PHP_INT_MAX"),
        "{$endpoint} derives only a canonical, non-overflowing positive session user ID"
    );
    protectedApiAssert(
        str_contains($source, "\$_SERVER['REMOTE_ADDR']") &&
            str_contains($source, 'inet_pton($remoteAddress)') &&
            !str_contains($source, "\$_SERVER['HTTP_X_FORWARDED_FOR']") &&
            !str_contains($source, "\$_SERVER['HTTP_CF_CONNECTING_IP']"),
        "{$endpoint} uses the canonical web-server peer for its fixed-cardinality IP identity"
    );

    $reservationStart = strpos($source, "function {$reservationFunction}(");
    $reservationEnd = $reservationStart === false
        ? false
        : strpos($source, "\n}\n", $reservationStart);
    $reservationBlock = $reservationStart === false || $reservationEnd === false
        ? ''
        : substr($source, $reservationStart, $reservationEnd - $reservationStart + 3);
    $ipPosition = strpos($reservationBlock, "'{$ipScope}'");
    $userPosition = strpos($reservationBlock, "'{$userScope}'");
    protectedApiAssert(
        $reservationBlock !== '' && $ipPosition !== false && $userPosition !== false &&
            $ipPosition < $userPosition &&
            str_contains(
                $reservationBlock,
                "Auth::releaseRateLimitAttempt('{$ipScope}', \$remoteIdentity)"
            ),
        "{$endpoint} reserves IP first and rolls it back if stable-account admission fails"
    );

    protectedApiAssertEarlyOrdering(
        $source,
        "\$sessionUserId = {$identityFunction}();",
        "{$reservationFunction}(\$sessionUserId)",
        $branches,
        $endpoint
    );
    protectedApiAssert(
        str_contains($source, "header('Retry-After: ' . {$windowConstant})") &&
            str_contains($source, 'http_response_code(429)') &&
            !str_contains($source, "Auth::clearRateLimit('{$ipScope}'") &&
            !str_contains($source, "Auth::clearRateLimit('{$userScope}'"),
        "{$endpoint} returns retry guidance without clearing accepted request history"
    );
}

$settingsBody = strpos($settings, "file_get_contents(\n            'php://input'");
$settingsReservation = strpos($settings, 'reserveSettingsApiRequestBudget($sessionUserId)');
$settingsDatabase = strpos($settings, '$db = new Database();');
protectedApiAssert(
    $settingsReservation !== false && $settingsBody !== false && $settingsDatabase !== false &&
        $settingsReservation < $settingsBody && $settingsReservation < $settingsDatabase,
    'settings admission occurs before bounded JSON parsing and direct Database construction'
);

$profileReservation = strpos($profile, 'reserveProfileApiRequestBudget($sessionUserId)');
$profileDatabase = strpos($profile, '$db = new Database();');
protectedApiAssert(
    $profileReservation !== false && $profileDatabase !== false &&
        $profileReservation < $profileDatabase,
    'profile admission occurs before direct Database construction'
);

protectedApiAssert(
    str_contains($chat, 'reserveChatApiSearchBudget((int)$currentUser[\'id\'], $input[\'action\'])') &&
        str_contains($chat, "'attachment_upload'") &&
        str_contains($settings, "'account_password'") &&
        str_contains($settings, "'account_second_factor'") &&
        str_contains($profile, "'avatar_upload'"),
    'existing search, upload, password, and second-factor action limits remain layered'
);

echo "Protected API pre-database rate-limit tests passed.\n";
