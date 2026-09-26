<?php

declare(strict_types=1);

function authSessionRateAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

function authSessionRateConstant(string $source, string $name): int
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

$source = file_get_contents(__DIR__ . '/../api/auth.php');
authSessionRateAssert(is_string($source), 'authentication API source is readable');

$window = authSessionRateConstant($source, 'AUTH_SESSION_ACTION_RATE_WINDOW_SECONDS');
$sessionUserLimit = authSessionRateConstant($source, 'AUTH_SESSION_ACTION_USER_REQUEST_LIMIT');
$sessionIpLimit = authSessionRateConstant($source, 'AUTH_SESSION_ACTION_IP_REQUEST_LIMIT');
$pendingUserLimit = authSessionRateConstant($source, 'AUTH_PENDING_ACTION_USER_REQUEST_LIMIT');
$pendingIpLimit = authSessionRateConstant($source, 'AUTH_PENDING_ACTION_IP_REQUEST_LIMIT');

authSessionRateAssert(
    $window === 60 && $sessionUserLimit >= 120 && $sessionUserLimit <= 360 &&
        $sessionIpLimit >= $sessionUserLimit * 5,
    'authenticated action budget preserves normal multi-tab status polling and NAT headroom'
);
authSessionRateAssert(
    $pendingUserLimit >= 20 && $pendingUserLimit <= 120 &&
        $pendingIpLimit >= $pendingUserLimit * 5 &&
        $pendingUserLimit < $sessionUserLimit,
    'short-lived pending 2FA actions use a tighter but retry-friendly budget'
);

authSessionRateAssert(
    str_contains($source, "\$_SERVER['REMOTE_ADDR']") &&
        str_contains($source, 'inet_pton($remoteAddress)') &&
        !str_contains($source, "\$_SERVER['HTTP_X_FORWARDED_FOR']") &&
        !str_contains($source, "\$_SERVER['HTTP_CF_CONNECTING_IP']"),
    'session-action IP admission uses the canonical web-server peer only'
);
authSessionRateAssert(
    str_contains($source, 'function authApiCanonicalSessionUserId($value): ?int') &&
        str_contains($source, "preg_match('/\\A[1-9][0-9]*\\z/D', \$value)") &&
        str_contains($source, 'FILTER_VALIDATE_INT') &&
        str_contains($source, "'min_range' => 1, 'max_range' => PHP_INT_MAX"),
    'session-action account identities reject signs, fractions, exponents, and overflows'
);
authSessionRateAssert(
    str_contains(
        $source,
        "in_array(\$action, ['verify_2fa_login', 'complete_2fa_login'], true)"
    ) &&
        str_contains($source, "\$field = \$pendingAction ? 'temp_user_id' : 'user_id';"),
    'authenticated actions use user_id while pending 2FA actions use temp_user_id'
);

$reservationStart = strpos($source, 'function reserveAuthApiSessionActionBudget(');
$reservationEnd = $reservationStart === false
    ? false
    : strpos($source, "\n}\n", $reservationStart);
$reservationBlock = $reservationStart === false || $reservationEnd === false
    ? ''
    : substr($source, $reservationStart, $reservationEnd - $reservationStart + 3);
$ipReservation = strpos($reservationBlock, "\$scopePrefix . '_ip'");
$userReservation = strpos($reservationBlock, "\$scopePrefix . '_user'");
authSessionRateAssert(
    $reservationBlock !== '' && $ipReservation !== false && $userReservation !== false &&
        $ipReservation < $userReservation &&
        str_contains(
            $reservationBlock,
            "Auth::releaseRateLimitAttempt(\$scopePrefix . '_ip', \$remoteIdentity)"
        ),
    'fixed-cardinality IP admission precedes account admission with exact partial rollback'
);
authSessionRateAssert(
    str_contains($reservationBlock, "'auth_pending_action'") &&
        str_contains($reservationBlock, "'auth_session_action'") &&
        !str_contains($source, 'clearRateLimit($scopePrefix'),
    'pending and authenticated actions have stable separate scopes that are never cleared per request'
);

$sessionActionDeclaration = strpos($source, '$sessionActions = [');
$sessionStart = strpos($source, 'if (!Auth::startExistingSession())', $sessionActionDeclaration ?: 0);
$identityDerivation = strpos(
    $source,
    '$sessionRateUserId = authApiSessionActionUserId($input[\'action\']);',
    $sessionStart ?: 0
);
$earlyReservation = strpos(
    $source,
    'reserveAuthApiSessionActionBudget($input[\'action\'], $sessionRateUserId)',
    $identityDerivation ?: 0
);
$lazyAuthState = strpos($source, '$auth = null;', $earlyReservation ?: 0);
$lazyAuthConstruction = strpos($source, '$auth = new Auth();', $lazyAuthState ?: 0);
authSessionRateAssert(
    $sessionActionDeclaration !== false && $sessionStart !== false &&
        $identityDerivation !== false && $earlyReservation !== false &&
        $lazyAuthState !== false && $lazyAuthConstruction !== false &&
        $sessionActionDeclaration < $sessionStart &&
        $sessionStart < $identityDerivation &&
        $identityDerivation < $earlyReservation &&
        $earlyReservation < $lazyAuthState &&
        $lazyAuthState < $lazyAuthConstruction,
    'all protected auth actions reserve their budget immediately after existing-session startup and before lazy Auth construction'
);
authSessionRateAssert(
    str_contains($source, "header('Retry-After: ' . AUTH_SESSION_ACTION_RATE_WINDOW_SECONDS)") &&
        str_contains($source, "['success' => false, 'message' => 'Too many requests. Try again shortly.']") &&
        str_contains($source, "429\n    );"),
    'session-action denials return 429 with Retry-After guidance'
);

$loginCase = strpos($source, "case 'login':");
$loginIpReservation = strpos($source, "reserveRateLimitAttempt('login_ip'", $loginCase ?: 0);
$loginIdentifierReservation = strpos($source, "'login_identifier'", $loginIpReservation ?: 0);
$loginPairReservation = strpos($source, "reserveRateLimitAttempt('login_account_ip'", $loginIpReservation ?: 0);
$loginSessionStart = strpos($source, 'if (!session_start())', $loginPairReservation ?: 0);
authSessionRateAssert(
    $loginCase !== false && $loginIpReservation !== false &&
        $loginIdentifierReservation !== false && $loginPairReservation !== false &&
        $loginSessionStart !== false &&
        $loginCase < $loginIpReservation &&
        $loginIpReservation < $loginIdentifierReservation &&
        $loginIdentifierReservation < $loginPairReservation &&
        $loginPairReservation < $loginSessionStart,
    'public login retains its IP, identifier, and pair limiter ordering before session allocation'
);
authSessionRateAssert(
    str_contains($source, "reserveRateLimitAttempt('login_2fa'") &&
        str_contains($source, "clearRateLimit('login_2fa'") &&
        str_contains($source, "releaseRateLimitAttempt('login_2fa'"),
    'pending-flow admission remains layered with the existing account-wide factor-guess limiter'
);

echo "Authentication session-action rate-limit tests passed.\n";
