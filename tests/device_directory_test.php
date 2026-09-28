<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/DeviceDirectory.php';

function deviceAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$root = dirname(__DIR__);

// ---- the hash chain --------------------------------------------------------

$zero = str_repeat("\0", 32);
$payload = hash('sha256', 'device-one', true);
$first = DeviceDirectory::entryDigest(1, $zero, DeviceDirectory::ENTRY_ENROLLED, $payload);

deviceAssert(strlen($first) === 32, 'a directory entry digest is 32 bytes');
deviceAssert(
    $first === DeviceDirectory::entryDigest(1, $zero, DeviceDirectory::ENTRY_ENROLLED, $payload),
    'the entry digest is deterministic'
);

// Every input must change the digest, or the chain would not bind them.
deviceAssert(
    $first !== DeviceDirectory::entryDigest(2, $zero, DeviceDirectory::ENTRY_ENROLLED, $payload),
    'the sequence number is bound into the digest'
);
deviceAssert(
    $first !== DeviceDirectory::entryDigest(1, str_repeat("\x01", 32), DeviceDirectory::ENTRY_ENROLLED, $payload),
    'the previous digest is bound in, so entries cannot be reordered'
);
deviceAssert(
    $first !== DeviceDirectory::entryDigest(1, $zero, DeviceDirectory::ENTRY_REVOKED, $payload),
    'the entry type is bound in, so an enrollment cannot be replayed as a revocation'
);
deviceAssert(
    $first !== DeviceDirectory::entryDigest(1, $zero, DeviceDirectory::ENTRY_ENROLLED, hash('sha256', 'device-two', true)),
    'the payload is bound in, so a substituted key breaks the chain'
);

// A chain built the way the class builds it verifies; a tampered one does not.
$chain = [];
$previous = $zero;
foreach (['a', 'b', 'c'] as $index => $name) {
    $seq = $index + 1;
    $entryPayload = hash('sha256', $name, true);
    $digest = DeviceDirectory::entryDigest($seq, $previous, DeviceDirectory::ENTRY_ENROLLED, $entryPayload);
    $chain[] = ['seq' => $seq, 'previous' => $previous, 'payload' => $entryPayload, 'digest' => $digest];
    $previous = $digest;
}
$verify = static function (array $chain): bool {
    $previous = str_repeat("\0", 32);
    foreach ($chain as $entry) {
        if (!hash_equals($previous, $entry['previous'])) {
            return false;
        }
        $expected = DeviceDirectory::entryDigest(
            $entry['seq'],
            $previous,
            DeviceDirectory::ENTRY_ENROLLED,
            $entry['payload']
        );
        if (!hash_equals($expected, $entry['digest'])) {
            return false;
        }
        $previous = $expected;
    }
    return true;
};
deviceAssert($verify($chain), 'a well-formed chain verifies');

$tampered = $chain;
$tampered[1]['payload'] = hash('sha256', 'substituted key', true);
deviceAssert(!$verify($tampered), 'substituting a key in the middle breaks the chain');

$dropped = [$chain[0], $chain[2]];
deviceAssert(!$verify($dropped), 'dropping an entry breaks the chain');

$reordered = [$chain[0], $chain[2], $chain[1]];
deviceAssert(!$verify($reordered), 'reordering entries breaks the chain');

// ---- what the class promises, and what it does not --------------------------

$class = (string)file_get_contents($root . '/classes/DeviceDirectory.php');
// Precise rather than clever: no column or bound value may name private key
// material. The public halves are what MLS publishes on purpose.
$secretNames = '/\b(private_key|secret_key|signature_private|init_private|encryption_private|seed)\b/i';
$secretMentions = [];
foreach (token_get_all('<?php ' . $class) as $token) {
    if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING &&
        preg_match($secretNames, $token[1], $found) === 1) {
        $secretMentions[] = $found[1];
    }
}
deviceAssert(
    $secretMentions === [],
    'no stored field names private key material' .
        ($secretMentions === [] ? '' : ': ' . implode(', ', $secretMentions))
);
deviceAssert(
    str_contains($class, 'signature_public_key') && !str_contains($class, 'signature_secret'),
    'only the public half of the signature key is stored'
);
deviceAssert(
    str_contains($class, 'not key transparency'),
    'the documentation refuses to overstate what the log provides'
);
deviceAssert(
    str_contains($class, 'consumed_at IS NULL') && str_contains($class, 'FOR UPDATE'),
    'a key package is consumed under a lock, so it cannot be handed out twice'
);
deviceAssert(
    str_contains($class, "\$consumed !== 1") && str_contains($class, 'key_package_race'),
    'a lost race to consume a key package is an error, never a silent reuse'
);
deviceAssert(
    str_contains($class, "revoked_at IS NULL"),
    'revoked devices are excluded when handing out key packages'
);
deviceAssert(
    str_contains($class, 'DELETE FROM e2ee_key_packages WHERE device_id = ? AND consumed_at IS NULL'),
    'revoking a device withdraws its unclaimed key packages'
);
deviceAssert(
    str_contains($class, "'exhausted' => true"),
    'a device with no key packages left is reported rather than silently skipped'
);
deviceAssert(
    str_contains($class, '(int)$stmt->affected_rows'),
    'affected rows are read from the statement, not the connection, which resets on close'
);

// ---- the migration ---------------------------------------------------------

$migration = (string)file_get_contents($root . '/migrations/20260928_add_device_directory.sql');
foreach (['e2ee_devices', 'e2ee_key_packages', 'e2ee_directory_log'] as $table) {
    deviceAssert(str_contains($migration, 'CREATE TABLE ' . $table), 'the migration creates ' . $table);
    deviceAssert(
        str_contains($migration, "table_name = '" . $table . "'"),
        'the migration probes information_schema before creating ' . $table
    );
}
deviceAssert(
    str_contains($migration, 'UNIQUE KEY uq_e2ee_key_packages_ref'),
    'a key package can only be published once'
);
deviceAssert(
    str_contains($migration, 'UNIQUE KEY uq_e2ee_devices_public_id'),
    'a device identifier is unique across the install'
);

// ---- the endpoint surface --------------------------------------------------

$accessRules = (string)file_get_contents($root . '/.htaccess');
deviceAssert(
    str_contains($accessRules, '!^/api/(?:attachment|auth|avatar|chat|profile|settings)\.php$'),
    'device support added no new API entry point'
);

$endpoint = (string)file_get_contents($root . '/api/chat.php');
deviceAssert(
    str_contains($endpoint, "case 'claim_key_packages':") && str_contains($endpoint, "case 'list_devices':"),
    'the key transport actions are served from the existing chat endpoint'
);
deviceAssert(
    !str_contains($endpoint, "case 'enroll_device'") && !str_contains($endpoint, "case 'revoke_device'"),
    'enrollment and revocation are not reachable from the chat endpoint'
);

// ---- the enrollment gate ---------------------------------------------------
// Enrolling a device adds a key that can read future messages, so it must not
// be reachable with a session alone.

$settings = (string)file_get_contents($root . '/api/settings.php');
$enrollCase = strpos($settings, "case 'enroll_device':");
deviceAssert($enrollCase !== false, 'enrollment is served from the settings endpoint');

$section = substr($settings, $enrollCase, 5000);
$order = [
    'flag' => strpos($section, 'ProtectedChat::isEnabled()'),
    'credentials required' => strpos($section, "Current password and a fresh 2FA code are required"),
    'password limiter' => strpos($section, "'account_password'"),
    'factor limiter' => strpos($section, "'device_enrollment'"),
    'password verified' => strpos($section, 'password_verify('),
    'factor consumed' => strpos($section, 'verifyAndConsumeSecondFactorForAuthenticationState'),
    'device written' => strpos($section, '->enrollDevice('),
];
foreach ($order as $label => $position) {
    deviceAssert($position !== false, 'the enrollment gate includes: ' . $label);
}
$positions = array_values($order);
$sorted = $positions;
sort($sorted);
deviceAssert(
    $positions === $sorted,
    'the gate runs in order: flag, credentials, limits, password, factor, then the write'
);
deviceAssert(
    strpos($section, 'verifyAndConsumeSecondFactorForAuthenticationState') <
        strpos($section, '->enrollDevice('),
    'no device is stored before a second factor has been consumed'
);
deviceAssert(
    str_contains($section, "\$sessionAuthVersion") && str_contains($section, "\$sessionTwoFactorVersion"),
    'the consumed factor is bound to the session authentication state'
);
deviceAssert(
    str_contains($section, "case 'revoke_device':"),
    'revocation is held to the same bar as enrollment'
);

// ---- revocation has to reach the conversation, not just the directory ------
// Revoking a device stops it being offered key packages. A device already inside
// an MLS group keeps the keys it holds, and no server action can take them back,
// so a client has to publish a removal. These pin the parts that make that
// possible, since none of it can be exercised without a database.

$directorySource = (string)file_get_contents($root . '/classes/DeviceDirectory.php');
deviceAssert(
    str_contains($directorySource, 'public function participantDevices('),
    'the directory can list the devices of a conversation\'s participants'
);
deviceAssert(
    preg_match(
        '/function participantDevices\([^)]*\)[^{]*\{\s*if \(!\$chats->isParticipant/',
        $directorySource
    ) === 1,
    'that listing refuses anyone who is not in the conversation, before any other work'
);
deviceAssert(
    !preg_match('/participantDevices.*?label/s', substr(
        $directorySource,
        (int)strpos($directorySource, 'function participantDevices'),
        1400
    )),
    'it returns no device labels: a signature key is already public to the group, a name is not'
);
deviceAssert(
    str_contains($directorySource, "'signature_public_key' => base64_encode("),
    'signature keys leave as base64, like every other key in this API'
);

$api = (string)file_get_contents($root . '/api/chat.php');
deviceAssert(
    substr_count($api, "case 'list_participant_devices':") === 2,
    'the action is both rate-limited with the directory group and dispatched'
);

$client = (string)file_get_contents($root . '/assets/js/protected-chat.js');
deviceAssert(
    str_contains($client, 'async function enforceRevocations(') &&
        str_contains($client, 'session.has_member(groupId, fromBase64(device.signature_public_key))'),
    'the client removes revoked devices that are still members'
);
deviceAssert(
    str_contains($client, "device.signature_public_key === mine"),
    'it never tries to remove itself, which would strand this device'
);
$ui = (string)file_get_contents($root . '/assets/js/protected-ui.js');
deviceAssert(
    str_contains($ui, 'enforceRevocations') && str_contains($ui, 'protected.revocation_check_failed'),
    'the interface runs that check when a conversation is opened and says so if it fails'
);

echo "Device directory tests passed.\n";
