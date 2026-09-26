<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/Auth.php';

function rateLimitAssert(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    echo "PASS: {$message}\n";
}

function rateLimitStatePath(string $scope, string $identity): string {
    $uid = function_exists('posix_geteuid')
        ? (string)posix_geteuid()
        : substr(hash('sha256', get_current_user()), 0, 12);
    $applicationRoot = realpath(__DIR__ . '/..') ?: dirname(__DIR__);
    $root = (string)realpath(sys_get_temp_dir()) . DIRECTORY_SEPARATOR .
        'pm-rate-limits-' . $uid . '-' . substr(hash('sha256', $applicationRoot), 0, 16);
    $key = 'pm_rate_' . hash('sha256', $scope . "\0" . strtolower(trim($identity)));
    $digest = hash('sha256', $key);
    return $root . DIRECTORY_SEPARATOR . substr($digest, 0, 2) . DIRECTORY_SEPARATOR .
        substr($digest, 2) . '.json';
}

if (($argv[1] ?? '') === '--worker') {
    $scope = (string)($argv[2] ?? '');
    $identity = (string)($argv[3] ?? '');
    $barrier = (string)($argv[4] ?? '');
    $deadline = microtime(true) + 10;
    while (!is_file($barrier) && microtime(true) < $deadline) {
        usleep(1000);
        clearstatcache(true, $barrier);
    }
    if (!is_file($barrier)) {
        fwrite(STDERR, "barrier timeout\n");
        exit(2);
    }

    fwrite(STDOUT, Auth::reserveRateLimitAttempt($scope, $identity, 3, 60) ? '1' : '0');
    exit(0);
}

$_SESSION = [];
$suffix = bin2hex(random_bytes(12));
$scope = 'rate_limit_basic_' . $suffix;
$identity = 'User@Example.test|' . $suffix;
Auth::clearRateLimit($scope, $identity);

rateLimitAssert(
    Auth::reserveRateLimitAttempt($scope, $identity, 2, 60),
    'first attempt reserves a slot'
);
rateLimitAssert(
    Auth::reserveRateLimitAttempt($scope, $identity, 2, 60),
    'second attempt reserves the exact final slot'
);
rateLimitAssert(
    !Auth::reserveRateLimitAttempt($scope, $identity, 2, 60),
    'attempt beyond the limit is denied atomically'
);

Auth::releaseRateLimitAttempt($scope, $identity);
rateLimitAssert(
    Auth::reserveRateLimitAttempt($scope, $identity, 2, 60),
    'releasing a non-counting attempt restores one slot'
);
Auth::clearRateLimit($scope, $identity);
rateLimitAssert(!is_file(rateLimitStatePath($scope, $identity)), 'cleared fallback state is unlinked');
rateLimitAssert(
    Auth::reserveRateLimitAttempt($scope, $identity, 2, 60),
    'success clearing resets the window'
);
Auth::clearRateLimit($scope, $identity);

$releaseScope = 'rate_limit_release_' . $suffix;
$releaseIdentity = 'release|' . $suffix;
rateLimitAssert(
    Auth::reserveRateLimitAttempt($releaseScope, $releaseIdentity, 1, 60),
    'single-slot reservation succeeds'
);
Auth::releaseRateLimitAttempt($releaseScope, $releaseIdentity);
rateLimitAssert(
    !is_file(rateLimitStatePath($releaseScope, $releaseIdentity)),
    'zero-count fallback state is unlinked'
);

$raceScope = 'rate_limit_race_' . $suffix;
$raceIdentity = 'same-identity|' . $suffix;
Auth::clearRateLimit($raceScope, $raceIdentity);
$barrierDirectory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pm-rate-test-' . $suffix;
rateLimitAssert(mkdir($barrierDirectory, 0700), 'concurrency barrier directory is created');
$barrier = $barrierDirectory . DIRECTORY_SEPARATOR . 'go';
$workers = [];

for ($index = 0; $index < 16; $index++) {
    $pipes = [];
    $workerCommand = [PHP_BINARY];
    if (php_ini_loaded_file() === false) {
        $workerCommand[] = '-n';
    } else {
        array_push(
            $workerCommand,
            '-d',
            'display_errors=0',
            '-d',
            'log_errors=0',
            '-d',
            'error_reporting=0',
            '-d',
            'apc.enable_cli=0'
        );
    }
    array_push($workerCommand, __FILE__, '--worker', $raceScope, $raceIdentity, $barrier);
    $process = proc_open(
        $workerCommand,
        [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes
    );
    rateLimitAssert(is_resource($process), "worker {$index} starts");
    fclose($pipes[0]);
    $workers[] = [$process, $pipes[1], $pipes[2]];
}

rateLimitAssert(touch($barrier), 'workers are released through one barrier');
$admitted = 0;
foreach ($workers as $index => [$process, $stdout, $stderr]) {
    $output = stream_get_contents($stdout);
    $error = stream_get_contents($stderr);
    fclose($stdout);
    fclose($stderr);
    $status = proc_close($process);
    rateLimitAssert($status === 0, "worker {$index} exits cleanly" . ($error !== '' ? ": {$error}" : ''));
    rateLimitAssert($output === '0' || $output === '1', "worker {$index} returns one admission result");
    $admitted += $output === '1' ? 1 : 0;
}

rateLimitAssert($admitted === 3, 'concurrent workers admit exactly the configured limit');
rateLimitAssert(
    !Auth::reserveRateLimitAttempt($raceScope, $raceIdentity, 3, 60),
    'the shared counter remains closed after the concurrent limit'
);
Auth::clearRateLimit($raceScope, $raceIdentity);
@unlink($barrier);
@rmdir($barrierDirectory);

echo "Rate-limit reservation tests passed.\n";
