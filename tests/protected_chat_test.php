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

// ---- the layer has to be connected to the application at all ---------------
// A fifth review found the protected layer reading `window.currentChatId` and
// `window.currentUserId`, neither of which exists: the legacy bundle keeps those
// in top-level `let` bindings, which are lexical, not properties of `window`. So
// every protected send fell through to the legacy plaintext sender in
// production, while five rounds of suites passed because each injected its own
// globals and none loaded the real files together.
//
// `tests/production_bridge_runtime_test.js` is the real guard — it loads the
// actual scripts in one context. These assertions cover the same ground in the
// PHP suite, which is what CI runs first.

$bridgeUi = (string)file_get_contents($root . '/assets/js/protected-ui.js');
$withoutComments = (string)preg_replace(['~/\*.*?\*/~s', '~//[^\n]*~'], ' ', $bridgeUi);
protectedAssert(
    !str_contains($withoutComments, 'window.currentChatId') &&
        !str_contains($withoutComments, 'window.currentUserId'),
    'the protected layer reads no window global that the application never defines'
);
protectedAssert(
    str_contains($bridgeUi, "typeof currentChatId === 'undefined'") &&
        str_contains($bridgeUi, "typeof currentUser === 'undefined'"),
    'it reads the bundle\'s lexical bindings the way chat-ux.js does'
);
$chatUx = (string)file_get_contents($root . '/assets/js/chat-ux.js');
protectedAssert(
    str_contains($chatUx, "typeof currentChatId === 'undefined'"),
    'which is the pattern the rest of the codebase already used'
);
protectedAssert(
    str_contains($bridgeUi, 'if (activeChatId() !== chatId)'),
    'and a conversation switch during the await abandons the send rather than misdirecting it'
);
protectedAssert(
    strpos($bridgeUi, 'const pending = input ? input.value.trim()') !== false &&
        strpos($bridgeUi, 'const pending = input ? input.value.trim()') <
            strpos($bridgeUi, 'await ui.protectedForSend(chatId)'),
    'the composer text is captured before the await, not after'
);

// A block is lifted by applying what it waits for, never by an empty answer.
$clientForBlocks = (string)file_get_contents($root . '/assets/js/protected-chat.js');
// Three rules have been tried for lifting a handshake block and two were
// unsound: a flag (cleared by an empty page), a sequence number (cleared by
// relabelling a different commit), and a payload digest (cleared by supplying
// the missing prerequisite so the same bytes applied). Nothing that *applies*
// can lift one now.
protectedAssert(
    !str_contains($clientForBlocks, 'pendingPayload') &&
        !str_contains($clientForBlocks, 'appliedDigests') &&
        !str_contains($clientForBlocks, 'appliedSequences'),
    'no block is keyed to a sequence, a flag, or a payload digest any more'
);
protectedAssert(
    str_contains($clientForBlocks, 'const pendingRejoin = new Map();') &&
        str_contains(
            $clientForBlocks,
            'if (rejoinedThisWalk && complete && !repairing && deferred.length === 0) {'
        ),
    'a block is lifted only by a re-admission plus a complete, contiguous, fully applied walk'
);
// Repair mode must end at the welcome, or everything published after it is
// skipped — which is how a removal right after a repair welcome was missed.
protectedAssert(
    str_contains($clientForBlocks, 'let repairing = pendingRejoin.has(Number(chatId));') &&
        str_contains($clientForBlocks, 'if (repairing && entry.kind !== 3) {') &&
        strpos($clientForBlocks, 'rejoinedThisWalk = true;') <
            strpos($clientForBlocks, 'repairing = false;'),
    'repair mode is re-read per entry and ends the moment the repair welcome is joined'
);
protectedAssert(
    str_contains($clientForBlocks, 'session.replace_member(groupId, key, material)') &&
        str_contains($clientForBlocks, 'for_repair: repairing,'),
    'a repair replaces the stale leaf in one commit and claims a fresh key package'
);
protectedAssert(
    str_contains($clientForBlocks, 'keyPackageAges.get(reference) || 0) >= mark') &&
        str_contains($clientForBlocks, 'const mark = keyPackagesCreated + 1;'),
    'and only a welcome for a key package created after the failure counts, so a stale one cannot'
);
protectedAssert(
    str_contains($clientForBlocks, 'if (repairing && entry.kind !== 3) {'),
    'a conversation awaiting repair looks only for that welcome, so it is not stuck forever'
);
protectedAssert(
    preg_match('/function markProtected\(chatId\)[\s\S]{0,900}return markedList\(store\)\.includes/', $clientForBlocks) === 1,
    'marking protection reports whether it actually stuck, rather than swallowing a storage failure'
);
protectedAssert(
    str_contains($clientForBlocks, 'unpublished.has(Number(chatId)) ||') &&
        preg_match('/async function knownProtected[\s\S]{0,800}pendingRejoin\.has\(Number\(chatId\)\)/', $clientForBlocks) === 1,
    'and a protection-related block is itself treated as evidence the chat is protected'
);
// Positions again, rather than a pattern with quotes inside quotes.
$markAt = strpos($clientForBlocks, 'markProtected(chatId);');
$requestAt = strpos($clientForBlocks, "action: 'protect_chat',");
protectedAssert(
    $markAt !== false && $requestAt !== false && $markAt < $requestAt,
    'protection is marked before it is requested, so a lost answer cannot leave it unmarked'
);
protectedAssert(
    str_contains($clientForBlocks, 'protect = { success: false, message: error.message };'),
    'and a thrown transport error takes the same path as a refusal'
);

// ---- the routing decision, and what it depends on ---------------------------
// Four rounds of review have found the same shape of defect: a defence that
// depends on something which is not there, or which arrives too late. These pin
// the dependencies rather than the behaviour.

$clientForRouting = (string)file_get_contents($root . '/assets/js/protected-chat.js');
$uiForRouting = (string)file_get_contents($root . '/assets/js/protected-ui.js');

protectedAssert(
    preg_match(
        '/protect_chat.*?rememberConversation\(chatId, toBase64\(groupId\), \{\}\).*?await admit\(/s',
        $clientForRouting
    ) === 1,
    'the creator records the conversation between protecting it and admitting anyone'
);
protectedAssert(
    str_contains($clientForRouting, 'async function remarkProtectedConversations()') &&
        preg_match('/loadBlocks\(\);\s*\n(?:\s*\/\/[^\n]*\n)*\s*await remarkProtectedConversations\(\);/', $clientForRouting) === 1,
    'and a resumed session re-derives the markers from the sealed record'
);
protectedAssert(
    str_contains($uiForRouting, 'async function protectedForSend(chatId)') &&
        preg_match('/await ui\.protectedForSend\(chatId\)/', $uiForRouting) === 1 &&
        substr_count($uiForRouting, 'ui.protectedForSend(chatId)') === 2,
    'both send paths resolve protection before any sender is chosen'
);
protectedAssert(
    preg_match('/if \(!chatId\) \{\s*\n\s*return legacySend\.apply/', $uiForRouting) === 1,
    'and the legacy sender is only reachable after that resolution'
);

// The welcome catch must cover the join and nothing else.
protectedAssert(
    preg_match(
        '/joinedGroupId = session\.join_group\([^;]*;\s*\n\s*joinedHere = true;\s*\n\s*\} catch/s',
        $clientForRouting
    ) === 1,
    'the welcome catch covers joining only'
);
protectedAssert(
    preg_match('/if \(joinedHere\) \{\s*\n(?:\s*\/\/[^\n]*\n)*\s*applied \+= await replayDeferred\(\);/', $clientForRouting) === 1,
    'so a failed replay of a deferred change propagates instead of being swallowed'
);
protectedAssert(
    str_contains($clientForRouting, 'const unaccounted = joinedGroupId !== null && deferred.length > 0;'),
    'and the block is not cleared while a change is still unaccounted for'
);

// The claim has to decide inside the transaction it acts in. Positions rather
// than one long pattern: an assertion that spans a whole method is the kind that
// quietly stops matching.
$directoryForClaims = (string)file_get_contents($root . '/classes/DeviceDirectory.php');
$claimStart = (int)strpos($directoryForClaims, 'public function claimKeyPackages(');
$claimBody = substr($directoryForClaims, $claimStart, 8000);
$claimOrder = [
    'transaction' => strpos($claimBody, 'begin_transaction()'),
    'device lock' => strpos($claimBody, 'FOR UPDATE'),
    'reuse lookup' => strpos($claimBody, 'k.claimed_for_chat_id ='),
    'quota' => strpos($claimBody, 'MAX_CLAIMS_PER_HOUR'),
    'allocation' => strpos($claimBody, 'SET consumed_at = NOW()'),
    'commit' => strpos($claimBody, 'commit()'),
];
protectedAssert(
    !in_array(false, $claimOrder, true),
    'the claim contains every step this checks the order of'
);
$claimPositions = array_values($claimOrder);
$sortedPositions = $claimPositions;
sort($sortedPositions);
protectedAssert(
    $claimPositions === $sortedPositions,
    'a claim locks the devices, then decides reuse and quota, then allocates, then commits'
);
protectedAssert(
    str_contains(
        (string)file_get_contents($root . '/migrations/20260930_scope_key_package_claims.sql'),
        'uniq_e2ee_key_packages_claim_scope'
    ),
    'and the database makes one claim per conversation and device unique'
);

// Readiness must cover everything a claim and the backstop need.
$protectedForReadiness = (string)file_get_contents($root . '/classes/ProtectedChat.php');
protectedAssert(
    str_contains($protectedForReadiness, "column_name = 'claimed_for_chat_id'") &&
        str_contains($protectedForReadiness, "'pm_chat_protection_insert'"),
    'readiness checks the claim column and the protection triggers, not only the tables'
);

// ---- the interface and the client must agree on their contract --------------
// A third review found `protected-ui.js` calling `client.knownProtected()`, which
// the client did not have: the TypeError was swallowed by a catch, the protection
// pin was never set, and the test double implemented the missing method so every
// suite stayed green. The whole class of defect is removed by checking the
// contract here rather than trusting either side.

$uiSource = (string)file_get_contents($root . '/assets/js/protected-ui.js');
$clientSource = (string)file_get_contents($root . '/assets/js/protected-chat.js');

preg_match('/return \{ resume,[^}]*\}/', $clientSource, $exportMatch);
protectedAssert($exportMatch !== [], 'the client has an export list to compare against');
// Strip the literal wrapper, not a character set: trimming the characters of
// "return {}" also ate the first letters of the first name.
$exportedRaw = trim(substr($exportMatch[0], strlen('return {'), -1));
$exported = array_map('trim', explode(',', $exportedRaw));
$exported = array_filter($exported, static fn(string $name): bool => $name !== '');

preg_match_all('/\b(?:client|active)\.([a-zA-Z_][a-zA-Z0-9_]*)\(/', $uiSource, $callMatches);
$called = array_values(array_unique($callMatches[1]));
protectedAssert($called !== [], 'the interface calls the client at all');

$missing = array_values(array_diff($called, $exported));
protectedAssert(
    $missing === [],
    'every client method the interface calls is exported by the client' .
        ($missing === [] ? '' : ': ' . implode(', ', $missing))
);

// The same for the test double: a double that implements more than the client is
// a suite that cannot see a missing method.
$uiTest = (string)file_get_contents($root . '/tests/protected_ui_runtime_test.js');
preg_match('/function fakeClient\(options\) \{.*?\n\}/s', $uiTest, $doubleMatch);
protectedAssert($doubleMatch !== [], 'the interface test has a client double');
// Only the methods, not the bookkeeping fields the double keeps for its own
// assertions.
preg_match_all(
    '/^\s{8}([a-zA-Z_][a-zA-Z0-9_]*):\s*(?:async\s*)?(?:\(|function)/m',
    $doubleMatch[0],
    $doubleMatches
);
$doubled = array_values(array_diff(array_unique($doubleMatches[1]), ['state']));
$inventedByTheDouble = array_values(array_diff($doubled, $exported));
protectedAssert(
    $inventedByTheDouble === [],
    'the double implements nothing the real client lacks' .
        ($inventedByTheDouble === [] ? '' : ': ' . implode(', ', $inventedByTheDouble))
);

// The decision about whether to encrypt must not wait on anything.
protectedAssert(
    preg_match('/function isProtected\(chatId\) \{/', $uiSource) === 1 &&
        preg_match('/async function isProtected/', $uiSource) === 0,
    'the encrypt-or-not decision is synchronous, so no plaintext path can win a race to it'
);
protectedAssert(
    str_contains($uiSource, 'markedProtectedLocally(chatId)'),
    'and it consults what this device established before the server flag'
);
// One definition plus one call from each of the two send paths.
protectedAssert(
    substr_count($uiSource, 'function assertSendable(') === 1 &&
        substr_count($uiSource, 'assertSendable(client, chatId, groupId);') === 2,
    'text and attachment sends share one pre-send guard'
);

// ---- the ciphertext retry path is integrated, not just written -------------
// A review found `envelopeFingerprint()` had no production caller, so the retry
// protection it was written for did not exist in practice. These pin the wiring;
// the behaviour itself was verified against MySQL (a replay returns the original
// message, a different envelope under the same id is refused).

$protectedSource = (string)file_get_contents($root . '/classes/ProtectedChat.php');
protectedAssert(
    str_contains($protectedSource, 'MessageIdempotency::envelopeFingerprint('),
    'storing an envelope computes the ciphertext fingerprint'
);
protectedAssert(
    str_contains($protectedSource, "'idempotency_conflict'") &&
        str_contains($protectedSource, "'replayed' => true"),
    'a repeated retry id returns the original message and a different one is refused'
);
protectedAssert(
    !preg_match('/envelopeFingerprint\([^)]*\$content/s', $protectedSource),
    'the ciphertext fingerprint is never fed plaintext'
);

$clientSource = (string)file_get_contents($root . '/assets/js/protected-chat.js');
protectedAssert(
    substr_count($clientSource, 'client_message_id: newRetryId()') === 2,
    'both the text and attachment sends carry a retry identifier'
);
protectedAssert(
    str_contains($clientSource, 'blob_id: upload.blob_id'),
    'an encrypted attachment is linked to the message that carries its key'
);

$blobSource = (string)file_get_contents($root . '/classes/EncryptedBlob.php');
protectedAssert(
    str_contains($blobSource, 'public function pruneOrphans('),
    'abandoned ciphertext uploads can be pruned'
);
protectedAssert(
    str_contains($blobSource, 'referenced_message_id IS NULL') &&
        str_contains($blobSource, '!is_link($real)'),
    'pruning only removes unreferenced blobs, and never follows a symlink out of the directory'
);

// ---- the plaintext paths must refuse a protected conversation --------------
// An independent review (2026-09-29) found that `assertProtectionMatches()` was
// only ever called on the protected path, so the ordinary send, upload and edit
// paths wrote plaintext into conversations the interface calls encrypted. These
// assertions are source-level because the suite has no database; the fix was
// also verified against a real MySQL instance with the reviewer's own
// reproduction, which now aborts at the first step.

$chatSource = (string)file_get_contents($root . '/classes/Chat.php');

protectedAssert(
    str_contains($chatSource, 'private function isProtectedChat('),
    'Chat has its own protection check, at the layer where writes happen'
);

// Three distinct answers, and "unknown" must not mean "allowed".
protectedAssert(
    str_contains($chatSource, "return \$this->conn->errno === 1146 ? false : null;") &&
        str_contains($chatSource, "return \$error->getCode() === 1146 ? false : null;"),
    'a missing table means no chat is protected; any other failure means unknown'
);
protectedAssert(
    substr_count($chatSource, "'protection_state_unknown'") >= 2 &&
        substr_count($chatSource, "'chat_is_protected'") >= 2,
    'both plaintext paths refuse a protected conversation, and refuse when they cannot tell'
);

// A check outside the transaction is a check-then-act race, which a second
// review reproduced: the send passed its check, protection committed, and the
// plaintext committed after it. Both sides now take the same conversation row.
protectedAssert(
    str_contains($chatSource, 'private function protectionUnderLock(') &&
        str_contains($chatSource, 'SELECT id FROM chats WHERE id = ? FOR UPDATE'),
    'the plaintext paths can re-ask the question under a row lock'
);
protectedAssert(
    substr_count($chatSource, '$this->protectionUnderLock(') === 2,
    'and both of them do, inside their transaction'
);
$protectedSourceForLock = (string)file_get_contents($root . '/classes/ProtectedChat.php');
protectedAssert(
    preg_match(
        '/begin_transaction\(\);.{0,400}SELECT id FROM chats WHERE id = \? FOR UPDATE/s',
        $protectedSourceForLock
    ) === 1,
    'establishing protection takes that same lock, inside its own transaction'
);
protectedAssert(
    is_file($root . '/migrations/20260929_enforce_protected_plaintext.sql') &&
        str_contains(
            (string)file_get_contents($root . '/migrations/20260929_enforce_protected_plaintext.sql'),
            'plaintext content is not allowed in a protected conversation'
        ),
    'and the database refuses it too, so a future code path cannot reopen the hole'
);

// The refusal has to precede the write. Compare positions inside each method.
$sendStart = (int)strpos($chatSource, 'public function sendMessage(');
$sendBody = substr($chatSource, $sendStart, 6000);
$sendGuard = strpos($sendBody, '$this->isProtectedChat(');
$sendInsert = strpos($sendBody, 'INSERT INTO messages');
protectedAssert(
    $sendGuard !== false && ($sendInsert === false || $sendGuard < $sendInsert),
    'sendMessage checks protection before it inserts anything'
);

$editStart = (int)strpos($chatSource, 'public function editMessage(');
$editBody = substr($chatSource, $editStart, 6000);
$editGuard = strpos($editBody, '$this->isProtectedChat(');
$editUpdate = strpos($editBody, 'UPDATE messages');
protectedAssert(
    $editGuard !== false && ($editUpdate === false || $editGuard < $editUpdate),
    'editMessage checks protection before it updates anything'
);
protectedAssert(
    str_contains($editBody, 'SELECT created_at, chat_id'),
    'editMessage reads the chat the message belongs to, rather than trusting the caller'
);

// ---- envelope shape: every rejection has a name ---------------------------
// These run without a database on purpose: the checks are decidable from the
// envelope alone, and the checklist in issue #7 asks for each refusal to be a
// named test rather than a claim in a comment.

$goodEnvelope = [
    'envelope_version' => ProtectedChat::ENVELOPE_VERSION,
    'content_type' => 1,
    'epoch' => 3,
    'sender_leaf' => 1,
    'group_id' => base64_encode(str_repeat("\x22", 32)),
    'aad_digest' => base64_encode(str_repeat("\x33", 32)),
    'ciphertext' => base64_encode('sealed-bytes'),
];

$parsed = ProtectedChat::parseEnvelope($goodEnvelope);
protectedAssert(
    $parsed['epoch'] === 3 && $parsed['sender_leaf'] === 1 && $parsed['ciphertext'] === 'sealed-bytes',
    'a well-formed envelope parses to its declared position and ciphertext'
);

$refusal = static function (array $changes) use ($goodEnvelope): string {
    try {
        ProtectedChat::parseEnvelope($changes + $goodEnvelope);
    } catch (ProtectedChatMismatch $error) {
        return $error->errorCode();
    }
    return 'accepted';
};

protectedAssert(
    $refusal(['envelope_version' => ProtectedChat::ENVELOPE_VERSION + 1]) === 'unsupported_envelope_version',
    'an envelope declaring an unknown version is refused by name'
);
protectedAssert(
    $refusal(['envelope_version' => 0]) === 'unsupported_envelope_version',
    'a missing version is refused rather than defaulted'
);
protectedAssert(
    $refusal(['content_type' => 99]) === 'invalid_envelope',
    'an unknown content type is refused'
);
protectedAssert(
    $refusal(['epoch' => -1]) === 'invalid_envelope' &&
        $refusal(['sender_leaf' => -1]) === 'invalid_envelope',
    'a negative epoch or leaf is refused'
);
protectedAssert(
    $refusal(['group_id' => base64_encode(str_repeat("\x22", 31))]) === 'invalid_envelope' &&
        $refusal(['aad_digest' => 'not base64 at all!!']) === 'invalid_envelope',
    'a group identifier of the wrong length and a non-base64 digest are both refused'
);
protectedAssert(
    $refusal(['ciphertext' => base64_encode(str_repeat('x', ProtectedChat::MAX_CIPHERTEXT_BYTES + 1))]) === 'invalid_envelope',
    'ciphertext beyond the cap is refused'
);
protectedAssert(
    $refusal([]) === 'accepted',
    'the fixture these cases mutate is itself accepted'
);

// The client must declare where a message really came from. An envelope with a
// constant epoch would leave the server's rollback check inert, which is what
// this pins against.
$client = (string)file_get_contents($root . '/assets/js/protected-chat.js');
protectedAssert(
    str_contains($client, 'epoch: Number(session.epoch(groupId))') &&
        str_contains($client, 'sender_leaf: session.own_leaf(groupId)'),
    'the client reads its real epoch and leaf from the group rather than sending a constant'
);
protectedAssert(
    !preg_match('/epoch:\s*0\b/', $client),
    'no envelope or handshake is posted with a hardcoded epoch'
);
protectedAssert(
    str_contains($client, 'session.apply_handshake(payload)') &&
        str_contains($client, "outcome === 'applied'"),
    'the client applies handshakes it fetches, so a membership change does not strand it'
);
// One page was not enough: a review hid a genuine removal past the server's cap.
protectedAssert(
    str_contains($client, 'for (let page = 0; page < 200; page++)') &&
        str_contains($client, 'sequence !== lastSequence + 1'),
    'it pages until the history runs out and refuses a gap in the sequence'
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
// What this has to check is that no padlock is *rendered*. Two mistakes were in
// the way, both found by a second review: PCRE spells a code point \x{...}, so
// the \u{...} this used to say failed to compile and the assertion passed
// whatever the file held; and the word "padlock" legitimately appears in a
// comment explaining why there is no padlock. So: strip comments, then look for a
// glyph or a string literal, and prove the pattern matches before trusting it.
$withoutComments = preg_replace(
    ['~/\*.*?\*/~s', '~(^|\s)//[^\n]*~'],
    ' ',
    $renderer
);
protectedAssert(is_string($withoutComments), 'the renderer can be read without its comments');

$padlockPattern = '/\x{1F512}|\x{1F510}|\x{1F513}|[\'"]padlock/u';
protectedAssert(
    preg_match($padlockPattern, "a \u{1F512} glyph") === 1 &&
        preg_match($padlockPattern, "className = 'padlock'") === 1 &&
        preg_match($padlockPattern, '// a comment mentioning a padlock') === 0,
    'the padlock pattern compiles, matches a glyph and a literal, and ignores prose'
);
protectedAssert(
    preg_match($padlockPattern, (string)$withoutComments) === 0,
    'no padlock is rendered, because it would imply a guarantee this does not have'
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

// ---- encrypted attachments -------------------------------------------------

$blobClass = (string)file_get_contents($root . '/classes/EncryptedBlob.php');
protectedAssert(
    str_contains($blobClass, 'MalwareScanner') === false,
    'the encrypted attachment path does not pretend to scan ciphertext'
);
protectedAssert(
    str_contains($blobClass, 'assertProtectionMatches') && str_contains($blobClass, 'isParticipant'),
    'a blob can only be stored in a protected conversation the uploader is in'
);
protectedAssert(
    str_contains($blobClass, 'hash_equals') && str_contains($blobClass, 'hash_file'),
    'the stored bytes are hashed and compared rather than trusted'
);
protectedAssert(
    str_contains($blobClass, 'is_link($real)') && str_contains($blobClass, 'strncmp($real, $expectedRoot'),
    'a blob path is confined to its directory and may not be a symlink'
);
protectedAssert(
    str_contains($blobClass, 'HOURLY_BLOB_BYTES') && str_contains($blobClass, 'HOURLY_BLOB_COUNT'),
    'encrypted attachments are still charged an hourly quota'
);

$blobMigration = (string)file_get_contents($root . '/migrations/20260928_add_encrypted_blobs.sql');
protectedAssert(
    str_contains($blobMigration, 'CREATE TABLE encrypted_blobs') &&
        str_contains($blobMigration, 'blobs_outside_protected_chats'),
    'the migration creates the blob table and ships a check that blobs stay inside protected chats'
);

$client = (string)file_get_contents($root . '/assets/js/protected-chat.js');
protectedAssert(
    str_contains($client, "subtle.generateKey({ name: 'AES-GCM', length: 256 }"),
    'each attachment gets its own content key'
);
protectedAssert(
    str_contains($client, 'NOT') && str_contains($client, 'a defence against a malicious server'),
    'the code says plainly that the digest is not what protects the attachment'
);

$english = json_decode((string)file_get_contents($root . '/locales/en.json'), true)['messages'];
protectedAssert(
    str_contains(strtolower($english['protected.no_scanning']), 'not scanned for malware'),
    'users are told that files in protected conversations are not scanned'
);
foreach (['es', 'ar', 'zh-Hans', 'zh-Hant'] as $locale) {
    $messages = json_decode((string)file_get_contents($root . '/locales/' . $locale . '.json'), true)['messages'];
    protectedAssert(isset($messages['protected.no_scanning']), $locale . ' carries the scanning caveat');
}

$page = (string)file_get_contents($root . '/index.html');
protectedAssert(
    str_contains($page, 'data-i18n="protected.no_scanning"'),
    'the caveat is shown, not merely translated'
);

echo "Protected chat tests passed.\n";
