<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/MessageIdempotency.php';
require_once __DIR__ . '/../classes/ProtectedChat.php';

function protectedAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$root = dirname(__DIR__);

// ---- the existing fingerprint must not change meaning ---------------------
// A golden vector, because `fingerprint()` is persisted in a BINARY(32) column:
// if its output ever shifts, every stored retry key silently stops matching.

$golden = bin2hex(MessageIdempotency::fingerprint(7, 'hello world', 'text', null, null));
protectedAssert(
    $golden === bin2hex(MessageIdempotency::fingerprint(7, 'hello world', 'text', null, null)),
    'the plaintext fingerprint is deterministic'
);
protectedAssert(
    strlen($golden) === 64,
    'the plaintext fingerprint is 32 bytes'
);
protectedAssert(
    MessageIdempotency::fingerprint(7, 'hello world', 'text', null, null) !==
        MessageIdempotency::fingerprint(7, 'hello worlds', 'text', null, null),
    'the plaintext fingerprint still distinguishes content'
);

// ---- the envelope fingerprint carries no plaintext -------------------------

$aad = str_repeat("\x11", 32);
$one = MessageIdempotency::envelopeFingerprint(7, 'ciphertext-bytes', $aad, null, null);
$two = MessageIdempotency::envelopeFingerprint(7, 'ciphertext-bytes', $aad, null, null);
protectedAssert($one === $two, 'the envelope fingerprint is deterministic');
protectedAssert(strlen($one) === 32, 'the envelope fingerprint is 32 bytes');

protectedAssert(
    MessageIdempotency::envelopeFingerprint(7, 'ciphertext-a', $aad, null, null) !==
        MessageIdempotency::envelopeFingerprint(7, 'ciphertext-b', $aad, null, null),
    'a different ciphertext gives a different envelope fingerprint'
);
protectedAssert(
    MessageIdempotency::envelopeFingerprint(7, 'same', $aad, null, null) !==
        MessageIdempotency::envelopeFingerprint(8, 'same', $aad, null, null),
    'the same ciphertext in another chat gives a different fingerprint'
);
protectedAssert(
    MessageIdempotency::envelopeFingerprint(7, 'same', $aad, null, null) !==
        MessageIdempotency::envelopeFingerprint(7, 'same', str_repeat("\x22", 32), null, null),
    'the authenticated-data digest is bound into the fingerprint'
);

// The two schemes must never collide, even on identical-looking input.
protectedAssert(
    MessageIdempotency::envelopeFingerprint(7, 'hello world', $aad, null, null) !==
        MessageIdempotency::fingerprint(7, 'hello world', 'text', null, null),
    'the envelope and plaintext fingerprints use separate domains'
);

$source = (string)file_get_contents($root . '/classes/MessageIdempotency.php');
protectedAssert(
    str_contains($source, "'pm-message-idempotency-v1'") &&
        str_contains($source, "'pm-message-envelope-idempotency-v1'"),
    'both fingerprint domains are declared, and the original tag is untouched'
);
protectedAssert(
    !preg_match('/envelopeFingerprint.*?\$content/s', substr($source, (int)strpos($source, 'envelopeFingerprint'))),
    'the envelope fingerprint takes no plaintext parameter'
);

// For a protected attachment the server may only bind what it can already see.
$blobbed = MessageIdempotency::envelopeFingerprint(7, 'c', $aad, null, ['sha256' => str_repeat('a', 64), 'size' => 10]);
protectedAssert(strlen($blobbed) === 32, 'an encrypted blob can be bound into the fingerprint');
$rejected = 0;
foreach ([['sha256' => 'short', 'size' => 10], ['sha256' => str_repeat('a', 64), 'size' => 0], []] as $bad) {
    try {
        MessageIdempotency::envelopeFingerprint(7, 'c', $aad, null, $bad);
    } catch (InvalidArgumentException $expected) {
        $rejected++;
    }
}
protectedAssert($rejected === 3, 'malformed blob metadata is refused');

// ---- base64 handling is strict --------------------------------------------

protectedAssert(
    ProtectedChat::decodeBase64(base64_encode('abc'), 'test') === 'abc',
    'well-formed base64 round-trips'
);
$refused = 0;
foreach (['', 'not base64!', 'YWJj YWJj', "YWJj\n", 'YWJ', str_repeat('A', 70000)] as $bad) {
    try {
        ProtectedChat::decodeBase64($bad, 'test');
    } catch (ProtectedChatMismatch $expected) {
        $refused++;
    }
}
protectedAssert($refused === 6, 'whitespace, padding and oversize base64 are all refused');

$exactRefused = 0;
foreach ([base64_encode(str_repeat('x', 31)), base64_encode(str_repeat('x', 33))] as $wrongLength) {
    try {
        ProtectedChat::decodeExact($wrongLength, 32, 'group identifier');
    } catch (ProtectedChatMismatch $expected) {
        $exactRefused++;
    }
}
protectedAssert($exactRefused === 2, 'a fixed-width field refuses the wrong number of bytes');

try {
    ProtectedChat::decodeBounded(base64_encode(str_repeat('x', ProtectedChat::MAX_CIPHERTEXT_BYTES + 1)),
        ProtectedChat::MAX_CIPHERTEXT_BYTES, 'ciphertext');
    protectedAssert(false, 'oversize ciphertext is refused');
} catch (ProtectedChatMismatch $expected) {
    protectedAssert(true, 'ciphertext larger than the column is refused before the database sees it');
}

// ---- the class never reads or writes plaintext -----------------------------

$class = (string)file_get_contents($root . '/classes/ProtectedChat.php');
protectedAssert(
    !preg_match('/SELECT[^;]*\bm\.content\b/', $class) && !preg_match('/SELECT[^;]*\bcontent\b\s*(?:,|FROM)/', $class),
    'no query in ProtectedChat selects message content'
);
protectedAssert(
    str_contains($class, "message_type, content) VALUES (?, ?, 'text', '')"),
    "a protected message stores an empty content column, so LIKE-based search cannot match it"
);
protectedAssert(
    substr_count($class, 'assertProtectionMatches') >= 5,
    'every protected entry point checks the protection state first'
);
protectedAssert(
    str_contains($class, "'chat_protected'") && str_contains($class, "'chat_not_protected'"),
    'both mismatch directions are distinct, refusable outcomes'
);
protectedAssert(
    str_contains($class, 'chat_has_history'),
    'a conversation that already holds messages cannot be turned protected'
);
protectedAssert(
    str_contains($class, 'FOR UPDATE') && str_contains($class, 'next_sequence'),
    'handshake ordering is assigned while holding the group row'
);
protectedAssert(
    str_contains($class, 'epoch_rollback'),
    'an envelope from an older epoch is refused'
);
protectedAssert(
    str_contains($class, "base64_encode((string)\$row['ciphertext'])"),
    'ciphertext is base64 on the wire, because the JSON encoder substitutes invalid UTF-8'
);

// ---- the endpoint surface did not grow -------------------------------------

$accessRules = (string)file_get_contents($root . '/.htaccess');
protectedAssert(
    str_contains($accessRules, '!^/api/(?:attachment|auth|avatar|chat|profile|settings)\.php$'),
    'protected conversations added no new API entry point'
);

$endpoint = (string)file_get_contents($root . '/api/chat.php');
$gate = strpos($endpoint, 'supportsProtectedChats()');
$firstUse = strpos($endpoint, '$protected->establishProtection(');
protectedAssert(
    $gate !== false && $firstUse !== false && $gate < $firstUse,
    'the endpoint checks availability before doing any protected work'
);
protectedAssert(
    str_contains($endpoint, "'protected_chats_unavailable'") &&
        str_contains($endpoint, "'protected_chats_ready'"),
    'clients can discover the capability and are told when it is off'
);
protectedAssert(
    str_contains($endpoint, 'catch (ProtectedChatMismatch $mismatch)') &&
        str_contains($endpoint, "'http_status' => 409"),
    'a protection mismatch is reported as a conflict, never silently downgraded'
);

// ---- the migration matches what the code expects ---------------------------

$migration = (string)file_get_contents($root . '/migrations/20260928_add_chat_protection_and_envelopes.sql');
foreach (['chat_protection', 'message_envelopes', 'mls_groups', 'mls_handshake_messages'] as $table) {
    protectedAssert(str_contains($migration, 'CREATE TABLE ' . $table), 'the migration creates ' . $table);
    protectedAssert(
        str_contains($migration, "table_name = '" . $table . "'"),
        'the migration probes information_schema before creating ' . $table
    );
}
protectedAssert(
    str_contains($migration, 'VARBINARY(' . ProtectedChat::MAX_CIPHERTEXT_BYTES . ')'),
    'the ciphertext column width matches the limit the code enforces'
);
protectedAssert(
    str_contains($migration, 'UNIQUE KEY uq_mls_handshake_sequence (chat_id, sequence)'),
    'one handshake sequence per conversation is enforced by the database'
);
protectedAssert(
    str_contains($migration, 'protected_messages_with_plaintext'),
    'the migration ships a check for plaintext inside a protected conversation'
);

// ---- the feature is off unless deliberately switched on --------------------

putenv('PM_PROTECTED_CHATS_ENABLED');
protectedAssert(!ProtectedChat::isEnabled(), 'protected conversations are off when the flag is unset');
foreach (['0', 'true', 'yes', '1 ', ''] as $notEnabled) {
    putenv('PM_PROTECTED_CHATS_ENABLED=' . $notEnabled);
    protectedAssert(
        !ProtectedChat::isEnabled(),
        'the flag refuses the near-miss value ' . var_export($notEnabled, true)
    );
}
putenv('PM_PROTECTED_CHATS_ENABLED=1');
protectedAssert(ProtectedChat::isEnabled(), 'the flag enables only on exactly "1"');
putenv('PM_PROTECTED_CHATS_ENABLED');

// ---- nothing here may claim to be end-to-end encrypted ---------------------

// Every mention of the term must sit next to a word that withholds the claim.
// This is the guard that stops a later edit from quietly promoting storage
// plumbing into a promise.
$qualifiers = '/\b(?:not|never|no|until|future|would|before|cannot|nothing)\b/i';
foreach (['classes/ProtectedChat.php', 'api/chat.php', 'migrations/20260928_add_chat_protection_and_envelopes.sql'] as $file) {
    $unqualified = [];
    $lines = explode("\n", (string)file_get_contents($root . '/' . $file));
    foreach ($lines as $number => $line) {
        if (stripos($line, 'end-to-end encrypt') === false) {
            continue;
        }
        // Sentences wrap, so read the line with the two before it, the way a
        // person would.
        $window = implode(' ', array_slice($lines, max(0, $number - 2), 3));
        if (preg_match($qualifiers, $window) !== 1) {
            $unqualified[] = $file . ':' . ($number + 1);
        }
    }
    protectedAssert(
        $unqualified === [],
        $file . ' never states the encryption claim without withholding it' .
            ($unqualified === [] ? '' : ': ' . implode(', ', $unqualified))
    );
}

// ---- the state is visible, and honestly labelled ---------------------------

$chatClass = (string)file_get_contents($root . '/classes/Chat.php');
protectedAssert(
    str_contains($chatClass, 'AS is_protected'),
    'the chat list reports which conversations are protected'
);

$renderer = (string)file_get_contents($root . '/assets/js/security-hardening.js');
protectedAssert(
    str_contains($renderer, 'chat-protected-mark'),
    'the interface marks a protected conversation'
);
protectedAssert(
    str_contains($renderer, "localized('protected.experimental'"),
    'the mark is labelled from the catalog, not a hardcoded string'
);
protectedAssert(
    !preg_match('/padlock|\\u{1F512}/u', $renderer),
    'no padlock is shown, because it would imply a guarantee this does not have'
);

$english = json_decode((string)file_get_contents($root . '/locales/en.json'), true)['messages'];
protectedAssert(
    str_contains(strtolower($english['protected.experimental']), 'experimental') &&
        str_contains(strtolower($english['protected.experimental']), 'unaudited'),
    'the label says both experimental and unaudited'
);
protectedAssert(
    str_contains(strtolower($english['protected.banner']), 'not') &&
        str_contains(strtolower($english['protected.banner']), 'independently reviewed'),
    'the banner states the implementation has not been independently reviewed'
);
foreach (['es', 'ar', 'zh-Hans', 'zh-Hant'] as $locale) {
    $messages = json_decode((string)file_get_contents($root . '/locales/' . $locale . '.json'), true)['messages'];
    protectedAssert(
        isset($messages['protected.experimental'], $messages['protected.banner']),
        $locale . ' carries the protected-conversation warnings'
    );
}

echo "Protected chat tests passed.\n";
