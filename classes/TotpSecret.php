<?php

declare(strict_types=1);

/**
 * Versioned authenticated encryption for TOTP seeds stored in the database.
 *
 * The envelope is bound to the owning user ID, so ciphertext copied between
 * account rows cannot be decrypted. Runtime reads accept only authenticated
 * envelopes; the one-time migration has an explicitly named legacy decoder.
 */
final class TotpSecret
{
    private const PREFIX = 'E1$';
    private const KEY_ENVIRONMENT_VARIABLE = 'PM_TOTP_ENCRYPTION_KEY';

    public static function encryptForUser(int $userId, string $secret): string
    {
        $normalized = self::normalizePlaintext($secret);
        if ($userId < 1 || $normalized === null ||
            !function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
            throw new RuntimeException('TOTP encryption is unavailable');
        }

        $key = self::encryptionKey();
        try {
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $normalized,
                self::associatedData($userId),
                $nonce,
                $key
            );
            return self::PREFIX . base64_encode($nonce . $ciphertext);
        } finally {
            if (function_exists('sodium_memzero')) {
                sodium_memzero($key);
            }
        }
    }

    public static function decryptForUser(int $userId, ?string $storedSecret): ?string
    {
        if ($userId < 1 || !is_string($storedSecret) || $storedSecret === '') {
            return null;
        }

        if (!str_starts_with($storedSecret, self::PREFIX) ||
            !function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt')) {
            return null;
        }
        $payload = substr($storedSecret, strlen(self::PREFIX));
        if ($payload === '' || preg_match('/\A[A-Za-z0-9+\/]+={0,2}\z/D', $payload) !== 1) {
            return null;
        }
        $decoded = base64_decode($payload, true);
        $minimumLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES +
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES + 16;
        $maximumLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES +
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES + 64;
        if (!is_string($decoded) || strlen($decoded) < $minimumLength ||
            strlen($decoded) > $maximumLength ||
            !hash_equals(rtrim($payload, '='), rtrim(base64_encode($decoded), '='))) {
            return null;
        }

        $nonceLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        $nonce = substr($decoded, 0, $nonceLength);
        $ciphertext = substr($decoded, $nonceLength);
        $key = self::encryptionKey();
        try {
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext,
                self::associatedData($userId),
                $nonce,
                $key
            );
        } finally {
            if (function_exists('sodium_memzero')) {
                sodium_memzero($key);
            }
        }

        return is_string($plaintext) ? self::normalizePlaintext($plaintext) : null;
    }

    public static function isEncrypted(string $storedSecret): bool
    {
        return str_starts_with($storedSecret, self::PREFIX);
    }

    /**
     * Decode only the pre-envelope storage format for the CLI migration.
     * Application authentication must use decryptForUser(), which intentionally
     * rejects plaintext database values after migration.
     */
    public static function legacyPlaintextForMigration(?string $storedSecret): ?string
    {
        return is_string($storedSecret) ? self::normalizePlaintext($storedSecret) : null;
    }

    private static function normalizePlaintext(string $secret): ?string
    {
        $normalized = strtoupper(trim($secret));
        return preg_match('/\A[A-Z2-7]{16,64}\z/D', $normalized) === 1
            ? $normalized
            : null;
    }

    private static function associatedData(int $userId): string
    {
        return "pm-totp-user\0" . $userId;
    }

    private static function encryptionKey(): string
    {
        $encoded = getenv(self::KEY_ENVIRONMENT_VARIABLE);
        if (!is_string($encoded) || strlen($encoded) < 43 || strlen($encoded) > 44 ||
            preg_match('/\A[A-Za-z0-9+\/]+={0,2}\z/D', $encoded) !== 1) {
            throw new RuntimeException('Runtime TOTP encryption key is unavailable');
        }
        $key = base64_decode($encoded, true);
        if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES ||
            !hash_equals(rtrim($encoded, '='), rtrim(base64_encode($key), '='))) {
            throw new RuntimeException('Runtime TOTP encryption key is unavailable');
        }
        return $key;
    }
}
