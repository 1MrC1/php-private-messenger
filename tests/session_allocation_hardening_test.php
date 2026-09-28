<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/Auth.php';

ob_start();

function sessionAllocationAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$previousSavePath = (string)ini_get('session.save_path');
$sessionFixtureDirectory = sys_get_temp_dir() . DIRECTORY_SEPARATOR .
    'pm-session-test-' . bin2hex(random_bytes(8));
$existingSessionId = str_repeat('A', 26);
$existingSessionPath = $sessionFixtureDirectory . DIRECTORY_SEPARATOR .
    'sess_' . $existingSessionId;

if (!mkdir($sessionFixtureDirectory, 0700) || !chmod($sessionFixtureDirectory, 0700) ||
    file_put_contents($existingSessionPath, '') === false || !chmod($existingSessionPath, 0600)) {
    throw new RuntimeException('Unable to create private session fixture');
}

try {
    sessionAllocationAssert(
        ini_set('session.save_path', $sessionFixtureDirectory) !== false,
        'the isolated file-backed session fixture is configured'
    );
    $_COOKIE = [];
    $sessionName = session_name();
    sessionAllocationAssert($sessionName !== '', 'PHP exposes a session cookie name');
    sessionAllocationAssert(
        !Auth::hasValidSessionCookie(),
        'a missing cookie cannot allocate protected session storage'
    );

    $_COOKIE[$sessionName] = $existingSessionId;
    sessionAllocationAssert(
        Auth::hasValidSessionCookie(),
        'an existing private file-backed session cookie is accepted'
    );
    sessionAllocationAssert(
        Auth::startExistingSession(['read_and_close' => true]),
        'the protected-session helper starts only the exact existing session'
    );

    $_COOKIE[$sessionName] = str_repeat('B', 26);
    sessionAllocationAssert(
        !Auth::hasValidSessionCookie(),
        'an unknown but syntactically valid session identifier is rejected'
    );
    $_COOKIE[$sessionName] = str_repeat('A', 15);
    sessionAllocationAssert(
        !Auth::hasValidSessionCookie(),
        'an undersized session identifier is rejected'
    );
    $_COOKIE[$sessionName] = str_repeat('A', 129);
    sessionAllocationAssert(
        !Auth::hasValidSessionCookie(),
        'an oversized session identifier is rejected'
    );
    $_COOKIE[$sessionName] = str_repeat('A', 15) . '/';
    sessionAllocationAssert(
        !Auth::hasValidSessionCookie(),
        'session path metacharacters are rejected'
    );
    $_COOKIE = [];
} finally {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    $_COOKIE = [];
    ini_set('session.save_path', $previousSavePath);
    @unlink($existingSessionPath);
    @rmdir($sessionFixtureDirectory);
}

$authApiSource = file_get_contents(__DIR__ . '/../api/auth.php');
sessionAllocationAssert(is_string($authApiSource), 'authentication API source is readable');
$sessionRoutingPosition = strpos($authApiSource, '$sessionActions = [');
$loginReservationPosition = strpos(
    $authApiSource,
    "Auth::reserveRateLimitAttempt('login_ip'"
);
$loginIdentifierPosition = strpos(
    $authApiSource,
    "'login_identifier'",
    is_int($loginReservationPosition) ? $loginReservationPosition : 0
);
$loginPairPosition = strpos(
    $authApiSource,
    "Auth::reserveRateLimitAttempt('login_account_ip'",
    is_int($loginIdentifierPosition) ? $loginIdentifierPosition : 0
);
$loginSessionPosition = is_int($loginReservationPosition)
    ? strpos($authApiSource, 'if (!session_start())', $loginReservationPosition)
    : false;
$registrationStart = strpos($authApiSource, "case 'register':");
$loginStart = strpos($authApiSource, "case 'login':");
$registrationBlock = is_int($registrationStart) && is_int($loginStart)
    ? substr($authApiSource, $registrationStart, $loginStart - $registrationStart)
    : '';

sessionAllocationAssert(
    is_int($sessionRoutingPosition) &&
        substr_count(substr($authApiSource, 0, $sessionRoutingPosition), 'session_start()') === 0,
    'invalid JSON and unknown auth actions are rejected before session creation'
);
sessionAllocationAssert(
    is_int($loginReservationPosition) && is_int($loginIdentifierPosition) &&
        is_int($loginPairPosition) && is_int($loginSessionPosition) &&
        $loginReservationPosition < $loginIdentifierPosition &&
        $loginIdentifierPosition < $loginPairPosition &&
        $loginPairPosition < $loginSessionPosition,
    'login creates a session only after IP, global identifier, and pair admission'
);
sessionAllocationAssert(
    $registrationBlock !== '' && !str_contains($registrationBlock, 'session_start()'),
    'registration does not allocate unnecessary session storage'
);
sessionAllocationAssert(
    str_contains($authApiSource, 'function discardTransientLoginSession(') &&
        substr_count($authApiSource, 'discardTransientLoginSession($preserveSessionOnLoginFailure)') >= 3,
    'failed, denied, and exceptional logins discard transient session files'
);
sessionAllocationAssert(
    str_contains($authApiSource, "'session_unavailable'") &&
        str_contains(
            $authApiSource,
            "'Sign-in is temporarily unavailable. Please try again.'"
        ) &&
        str_contains($authApiSource, "header('Retry-After: 30');") &&
        !str_contains($authApiSource, "'Unable to start session'"),
    'session infrastructure failures return a stable retryable 503 without raw internals'
);
$authClassSource = file_get_contents(__DIR__ . '/../classes/Auth.php');
sessionAllocationAssert(
    is_string($authClassSource) &&
        str_contains($authClassSource, 'ACCOUNT_LOGIN_ATTEMPT_LIMIT = 20') &&
        !str_contains($authClassSource, 'SHOW COLUMNS FROM users'),
    'real accounts share the pre-database threshold without a redundant schema query'
);

// The tracked open_basedir must permit the session directory the deployment
// documentation tells operators to use. When these disagree, session_start()
// fails and every authenticated request degrades in a way that is easy to miss.
$userIni = (string)file_get_contents(__DIR__ . '/../.user.ini');
preg_match('/^open_basedir=(.*)$/m', $userIni, $baseDirMatch);
$allowedPaths = array_filter(explode(':', trim($baseDirMatch[1] ?? '')));
$sessionRoot = '/var/lib/messenger/';
sessionAllocationAssert(
    in_array($sessionRoot, $allowedPaths, true),
    'open_basedir permits the documented session directory (' . $sessionRoot . ')'
);
sessionAllocationAssert(
    in_array('/var/www/messenger/', $allowedPaths, true),
    'open_basedir still permits the document root'
);

$runtimeDirectoryPolicy = file_get_contents(
    __DIR__ . '/../docs/security/messenger-runtime.tmpfiles.conf'
);
sessionAllocationAssert(
    is_string($runtimeDirectoryPolicy) &&
        str_contains($runtimeDirectoryPolicy, 'd /var/lib/messenger 0710 root messenger -') &&
        str_contains(
            $runtimeDirectoryPolicy,
            'd /var/lib/messenger/sessions 0700 messenger messenger -'
        ) &&
        str_contains(
            $runtimeDirectoryPolicy,
            'd /var/lib/messenger/tmp 0700 messenger messenger -'
        ),
    'deployment preserves a traversable root-owned parent and private messenger session storage'
);

foreach (['attachment.php', 'avatar.php', 'chat.php', 'profile.php', 'settings.php'] as $endpoint) {
    $source = file_get_contents(__DIR__ . '/../api/' . $endpoint);
    sessionAllocationAssert(
        is_string($source) && str_contains($source, 'Auth::startExistingSession('),
        $endpoint . ' starts only an existing protected session before work'
    );
}

$settingsSource = file_get_contents(__DIR__ . '/../api/settings.php');
$settingsSessionPosition = is_string($settingsSource)
    ? strpos($settingsSource, 'Auth::startExistingSession(')
    : false;
$settingsBodyPosition = is_string($settingsSource)
    ? strpos($settingsSource, "file_get_contents(\n            'php://input'")
    : false;
sessionAllocationAssert(
    is_int($settingsSessionPosition) && is_int($settingsBodyPosition) &&
        $settingsSessionPosition < $settingsBodyPosition,
    'the fully protected settings API validates its session before reading JSON'
);

$chatSource = file_get_contents(__DIR__ . '/../api/chat.php');
$chatJsonPosition = is_string($chatSource)
    ? strpos($chatSource, '// Handle regular JSON requests')
    : false;
$chatSessionPosition = is_int($chatJsonPosition)
    ? strpos($chatSource, 'Auth::startExistingSession(', $chatJsonPosition)
    : false;
$chatBodyPosition = is_int($chatJsonPosition)
    ? strpos($chatSource, "file_get_contents('php://input'", $chatJsonPosition)
    : false;
sessionAllocationAssert(
    is_int($chatSessionPosition) && is_int($chatBodyPosition) &&
        $chatSessionPosition < $chatBodyPosition,
    'protected JSON chat requests validate their session before reading the body'
);

echo "Session allocation hardening tests passed.\n";
ob_end_flush();
