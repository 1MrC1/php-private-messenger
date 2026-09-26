<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/TotpSecret.php';

function totpSecretAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$key = base64_encode(str_repeat("\x5a", SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES));
putenv('PM_TOTP_ENCRYPTION_KEY=' . $key);

$plaintext = 'ABCDEFGHIJKLMNOP';
$envelope = TotpSecret::encryptForUser(41, $plaintext);
totpSecretAssert(TotpSecret::isEncrypted($envelope), 'new TOTP seeds use a versioned encrypted envelope');
totpSecretAssert($envelope !== $plaintext && strpos($envelope, $plaintext) === false, 'envelope does not expose the seed');
totpSecretAssert(TotpSecret::decryptForUser(41, $envelope) === $plaintext, 'owner can decrypt an intact envelope');
totpSecretAssert(TotpSecret::decryptForUser(42, $envelope) === null, 'ciphertext is bound to its owning user');

$tampered = $envelope;
$tamperOffset = strlen($tampered) - 2;
$tampered[$tamperOffset] = $tampered[$tamperOffset] === 'A' ? 'B' : 'A';
totpSecretAssert(TotpSecret::decryptForUser(41, $tampered) === null, 'ciphertext tampering fails authentication');
totpSecretAssert(TotpSecret::decryptForUser(41, strtolower($plaintext)) === null, 'runtime rejects plaintext database seeds');
totpSecretAssert(
    TotpSecret::legacyPlaintextForMigration(strtolower($plaintext)) === $plaintext,
    'CLI migration can explicitly decode a legacy Base32 seed'
);
totpSecretAssert(
    TotpSecret::legacyPlaintextForMigration('not-a-seed') === null,
    'CLI migration rejects invalid legacy seeds'
);
totpSecretAssert(TotpSecret::decryptForUser(41, 'not-a-seed') === null, 'invalid stored seed fails closed');

putenv('PM_TOTP_ENCRYPTION_KEY');
$missingKeyFailedClosed = false;
try {
    TotpSecret::decryptForUser(41, $envelope);
} catch (RuntimeException $error) {
    $missingKeyFailedClosed = true;
}
totpSecretAssert($missingKeyFailedClosed, 'missing runtime key fails closed');

echo "TOTP secret encryption tests passed.\n";
