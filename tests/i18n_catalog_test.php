<?php

declare(strict_types=1);

function i18nCatalogAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

/** @return array<string, string> */
function i18nFlattenMessages(array $messages, string $prefix = ''): array
{
    $flat = [];
    foreach ($messages as $key => $value) {
        if (!is_string($key) || $key === '') {
            throw new RuntimeException('catalog keys must be non-empty strings');
        }
        $segments = explode('.', $key);
        foreach ($segments as $segment) {
            if (in_array(strtolower($segment), ['__proto__', 'prototype', 'constructor'], true)) {
                throw new RuntimeException("catalog key {$key} cannot traverse an object prototype");
            }
        }

        $path = $prefix === '' ? $key : $prefix . '.' . $key;
        if (is_array($value)) {
            if ($value === []) {
                throw new RuntimeException("catalog branch {$path} must not be empty");
            }
            $flat += i18nFlattenMessages($value, $path);
            continue;
        }

        if (!is_string($value) || trim($value) === '') {
            throw new RuntimeException("catalog leaf {$path} must be a non-blank string");
        }
        $flat[$path] = $value;
    }
    return $flat;
}

/** @return list<string> */
function i18nPlaceholders(string $message): array
{
    preg_match_all('/\{\{([A-Za-z][A-Za-z0-9_]*)\}\}/', $message, $matches);
    $placeholders = array_values(array_unique($matches[1] ?? []));
    sort($placeholders, SORT_STRING);
    return $placeholders;
}

function i18nNormalizedSource(string $value): string
{
    // Match the browser runtime: translatedWhitespace preserves every
    // internal character and removes only edge whitespace around a text node.
    $normalized = preg_replace(
        '/(?:\A[\x{0009}-\x{000D}\x{0020}\x{00A0}]+|' .
            '[\x{0009}-\x{000D}\x{0020}\x{00A0}]+\z)/u',
        '',
        $value
    );
    return is_string($normalized) ? $normalized : $value;
}

function i18nSourcePattern(string $template): ?string
{
    $template = i18nNormalizedSource($template);
    if (!str_contains($template, '{{')) {
        return null;
    }
    $pattern = '\A';
    $cursor = 0;
    preg_match_all('/\{\{[A-Za-z][A-Za-z0-9_]*\}\}/', $template, $matches, PREG_OFFSET_CAPTURE);
    foreach ($matches[0] ?? [] as [$token, $offset]) {
        $pattern .= preg_quote(substr($template, $cursor, $offset - $cursor), '~') . '(.+?)';
        $cursor = $offset + strlen($token);
    }
    $pattern .= preg_quote(substr($template, $cursor), '~') . '\z';
    return '~' . $pattern . '~usD';
}

function i18nDecodePhpLiteral(string $literal): string
{
    $quote = $literal[0] ?? '';
    $body = substr($literal, 1, -1);
    if ($quote === "'") {
        return str_replace(["\\\\", "\\'"], ["\\", "'"], $body);
    }
    return stripcslashes($body);
}

/** @return list<string> */
function i18nPhpLiteralMatches(string $source, string $pattern): array
{
    $count = preg_match_all($pattern, $source, $matches, PREG_SET_ORDER);
    if ($count === false) {
        throw new RuntimeException('public API source extraction pattern is invalid');
    }

    $values = [];
    foreach ($matches as $match) {
        if (isset($match['literal']) && is_string($match['literal'])) {
            $values[] = i18nNormalizedSource(i18nDecodePhpLiteral($match['literal']));
        }
    }
    return $values;
}

/**
 * Conservatively identify literal strings that can be emitted through the
 * public API envelope. The explicit audited fixture below remains the oracle
 * for indirect flows; this scanner makes common future additions fail closed.
 *
 * @param list<string> $files
 * @param list<string> $apiFiles
 * @return list<string>
 */
function i18nExtractBackendEnvelopeSources(array $files, array $apiFiles): array
{
    $literal = <<<'REGEX'
(?<literal>'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")
REGEX;
    $keyedValue = <<<'REGEX'
~['"](?:message|error)['"]\s*=>\s*
REGEX;
    $keyedValue .= $literal . '~s';
    $assignedValue = <<<'REGEX'
~\[\s*['"](?:message|error)['"]\s*\]\s*=\s*
REGEX;
    $assignedValue .= $literal . '~s';
    $failureResponse = <<<'REGEX'
~\bsendFailureResponse\s*\(\s*[^,]+,\s*[^,]+,\s*
REGEX;
    $failureResponse .= $literal . '~s';
    $exception = <<<'REGEX'
~\bnew\s+(?<class>[A-Za-z_\\][A-Za-z0-9_\\]*)\s*\(\s*
REGEX;
    $exception .= $literal . '~s';

    $sources = [];
    foreach ($files as $path) {
        $source = file_get_contents($path);
        i18nCatalogAssert(is_string($source), basename($path) . ' public API source is readable');
        foreach ([$keyedValue, $assignedValue, $failureResponse] as $pattern) {
            foreach (i18nPhpLiteralMatches($source, $pattern) as $value) {
                $sources[$value] = true;
            }
        }

        if (!in_array($path, $apiFiles, true)) {
            continue;
        }
        $count = preg_match_all($exception, $source, $matches, PREG_SET_ORDER);
        if ($count === false) {
            throw new RuntimeException('public API exception extraction pattern is invalid');
        }
        foreach ($matches as $match) {
            $class = $match['class'] ?? '';
            if (!is_string($class) ||
                (!str_ends_with($class, 'Exception') && !str_ends_with($class, 'Error'))) {
                continue;
            }
            $value = i18nNormalizedSource(i18nDecodePhpLiteral($match['literal']));
            $sources[$value] = true;
        }
    }

    $values = array_keys($sources);
    sort($values, SORT_STRING);
    return $values;
}

function i18nDecodeJavaScriptLiteral(string $literal): string
{
    $body = substr($literal, 1, -1);
    return stripcslashes($body);
}

/** @return list<string> */
function i18nJavaScriptLiteralMatches(string $source, string $pattern): array
{
    $count = preg_match_all($pattern, $source, $matches, PREG_SET_ORDER);
    if ($count === false) {
        throw new RuntimeException('JavaScript UI source extraction pattern is invalid');
    }

    $values = [];
    foreach ($matches as $match) {
        if (isset($match['literal']) && is_string($match['literal'])) {
            $values[] = i18nNormalizedSource(i18nDecodeJavaScriptLiteral($match['literal']));
        }
    }
    return $values;
}

/** @param array<string, true> $exact @param list<string> $templates */
function i18nCatalogCoversSource(string $source, array $exact, array $templates): bool
{
    if (isset($exact[$source])) {
        return true;
    }
    foreach ($templates as $pattern) {
        if (preg_match($pattern, $source) === 1) {
            return true;
        }
    }
    return false;
}

/** @return list<string> */
function i18nIndexSources(DOMDocument $document, bool $report = true): array
{
    $xpath = new DOMXPath($document);
    $sources = [];

    $textNodes = $xpath->query(
        '//body//*[not(self::script) and not(self::style) and not(self::template) and ' .
        'not(ancestor-or-self::*[@data-i18n-ignore])]/text()[normalize-space()]'
    );
    if ($textNodes === false) {
        throw new RuntimeException('visible document text cannot be inspected');
    }
    if ($report) {
        i18nCatalogAssert(true, 'visible document text can be inspected');
    }
    foreach ($textNodes as $node) {
        $value = i18nNormalizedSource((string)$node->nodeValue);
        if ($value !== '') {
            $sources[] = $value;
        }
    }

    $localizableAttributes = [
        'title', 'placeholder', 'aria-label', 'aria-description', 'alt',
        'data-mobile-label', 'data-drop-label',
    ];
    $attributePredicates = array_map(
        static fn(string $attribute): string => '@' . $attribute,
        $localizableAttributes
    );
    $attributeNodes = $xpath->query(
        '//*[' . implode(' or ', $attributePredicates) . '][not(ancestor-or-self::*[@data-i18n-ignore])]'
    );
    if ($attributeNodes === false) {
        throw new RuntimeException('localizable document attributes cannot be inspected');
    }
    if ($report) {
        i18nCatalogAssert(true, 'localizable document attributes can be inspected');
    }
    foreach ($attributeNodes as $node) {
        if (!$node instanceof DOMElement) {
            continue;
        }
        foreach ($localizableAttributes as $attribute) {
            if (!$node->hasAttribute($attribute)) {
                continue;
            }
            $value = i18nNormalizedSource($node->getAttribute($attribute));
            if ($value !== '') {
                $sources[] = $value;
            }
        }
    }

    $description = $xpath->query('//meta[translate(@name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="description"]/@content');
    if ($description !== false) {
        foreach ($description as $attribute) {
            $value = i18nNormalizedSource((string)$attribute->nodeValue);
            if ($value !== '') {
                $sources[] = $value;
            }
        }
    }

    $title = $xpath->query('//head/title/text()[normalize-space()]');
    if ($title !== false) {
        foreach ($title as $node) {
            $value = i18nNormalizedSource((string)$node->nodeValue);
            if ($value !== '') {
                $sources[] = $value;
            }
        }
    }

    return array_values(array_unique($sources));
}

$root = dirname(__DIR__);
$locales = ['en', 'es', 'zh-Hans', 'zh-Hant', 'ar'];
$catalogs = [];
$flattened = [];
$pluralCategories = ['few', 'many', 'one', 'other', 'two', 'zero'];

foreach ($locales as $locale) {
    $path = $root . '/locales/' . $locale . '.json';
    $source = file_get_contents($path);
    i18nCatalogAssert(is_string($source), "{$locale} catalog is readable");
    try {
        $catalog = json_decode($source, true, 128, JSON_THROW_ON_ERROR);
    } catch (JsonException $error) {
        throw new RuntimeException("{$locale} catalog is valid JSON: " . $error->getMessage());
    }

    i18nCatalogAssert(is_array($catalog), "{$locale} catalog has an object root");
    i18nCatalogAssert(
        array_key_exists('meta', $catalog) && is_array($catalog['meta']) &&
            array_key_exists('messages', $catalog) && is_array($catalog['messages']),
        "{$locale} catalog has meta and messages objects"
    );
    i18nCatalogAssert(
        ($catalog['meta']['locale'] ?? null) === $locale,
        "{$locale} catalog declares its canonical locale"
    );
    i18nCatalogAssert(
        is_string($catalog['meta']['name'] ?? null) && trim($catalog['meta']['name']) !== '' &&
            is_string($catalog['meta']['nativeName'] ?? null) && trim($catalog['meta']['nativeName']) !== '',
        "{$locale} catalog provides language names"
    );
    i18nCatalogAssert(
        ($catalog['meta']['dir'] ?? null) === ($locale === 'ar' ? 'rtl' : 'ltr'),
        "{$locale} catalog declares the correct text direction"
    );
    $invalidKeys = [];
    $invalidPluralKeys = [];
    foreach ($catalog['messages'] as $key => $message) {
        if (!is_string($key) || preg_match('/\A[a-z0-9][a-z0-9._-]*\z/D', $key) !== 1) {
            $invalidKeys[] = (string)$key;
        }
        if (is_array($message)) {
            $forms = array_keys($message);
            sort($forms, SORT_STRING);
            if ($forms !== $pluralCategories) {
                $invalidPluralKeys[] = (string)$key;
            }
        }
    }
    i18nCatalogAssert(
        $invalidKeys === [],
        "{$locale} message keys use the engine's stable safe-key grammar" .
            ($invalidKeys === [] ? '' : ': ' . implode(', ', $invalidKeys))
    );
    i18nCatalogAssert(
        $invalidPluralKeys === [],
        "{$locale} plural messages provide every supported category" .
            ($invalidPluralKeys === [] ? '' : ': ' . implode(', ', $invalidPluralKeys))
    );

    $catalogs[$locale] = $catalog;
    $flattened[$locale] = i18nFlattenMessages($catalog['messages']);
    i18nCatalogAssert(count($flattened[$locale]) >= 100, "{$locale} catalog covers the complete application surface");
}

$englishKeys = array_keys($flattened['en']);
sort($englishKeys, SORT_STRING);
foreach ($locales as $locale) {
    $localeKeys = array_keys($flattened[$locale]);
    sort($localeKeys, SORT_STRING);
    i18nCatalogAssert($localeKeys === $englishKeys, "{$locale} catalog has exact English key parity");

    $placeholderMismatches = [];
    $markupMessages = [];
    foreach ($englishKeys as $key) {
        if (i18nPlaceholders($flattened[$locale][$key]) !== i18nPlaceholders($flattened['en'][$key])) {
            $placeholderMismatches[] = $key;
        }
        if (preg_match('/<\s*\/?\s*[A-Za-z][^>]*>/', $flattened[$locale][$key]) === 1) {
            $markupMessages[] = $key;
        }
    }
    i18nCatalogAssert(
        $placeholderMismatches === [],
        "{$locale} placeholders have exact English parity" .
            ($placeholderMismatches === [] ? '' : ': ' . implode(', ', $placeholderMismatches))
    );
    i18nCatalogAssert(
        $markupMessages === [],
        "{$locale} translations contain no HTML markup" .
            ($markupMessages === [] ? '' : ': ' . implode(', ', $markupMessages))
    );
}

$englishSources = [];
$englishSourcePatterns = [];
foreach ($flattened['en'] as $message) {
    $englishSources[i18nNormalizedSource($message)] = true;
    $pattern = i18nSourcePattern($message);
    if ($pattern !== null) {
        $englishSourcePatterns[] = $pattern;
    }
}

$requiredApiEnvelopeSources = preg_split('/\\R/u', trim(<<<'PM_API_ENVELOPE_SOURCES'
2FA disabled. Please sign in again.
2FA disabled successfully
2FA enabled. Please sign in again.
2FA enabled successfully
2FA is already enabled. Disable it before replacing the authenticator.
2FA is not enabled for this account
2FA setup expired. Start again.
2FA verification expired. Please login again.
2FA verification failed
2FA verification is required. Please login again.
2FA verification required
2FA verification successful
Access denied
Action not available
A fresh 2FA code or backup code is required
An attachment is required for this message type
Another message is still being processed. Please retry shortly
Attachment security scanning is temporarily unavailable
Attachments must be no larger than 50 MB
Attachments must use the upload endpoint
Attachment storage is temporarily unavailable
Authentication required
Authentication state changed. Please login again.
Authentication state changed. Please sign in again.
Avatar security scanning is temporarily unavailable
Avatar updated successfully
Avatar upload failed
Cache cleared successfully
Cannot edit messages older than 48 hours
Chat ID and after message ID are required
Chat ID and content are required
Chat ID and message ID are required
Chat ID and message IDs are required
Chat ID and search query are required
Chat ID and typing status are required
Chat ID is required
client_message_id was already used for a different message
Content-Type must be application/json
Content-Type must be multipart/form-data
Cross-origin request denied
Current and new passwords are required
Current password and a fresh 2FA code are required
Current password is incorrect
Current password is required
Empty attachments cannot be sent
Failed to add reaction
Failed to change password
Failed to create chat
Failed to delete message
Failed to disable 2FA
Failed to edit message
Failed to enable 2FA
Failed to generate backup codes
Failed to load message context
Failed to load messages
Failed to load new messages
Failed to setup 2FA
Failed to update avatar
Failed to update profile
Failed to update read status
Failed to update settings
Failed to update typing status
First name and last name are required
First name and last name contain invalid characters
Hourly upload attempt limit reached
Invalid 2FA code
Invalid 2FA code or backup code
Invalid action
Invalid action or missing action parameter
Invalid chat
Invalid chat background setting
Invalid chat participant
Invalid Content-Length
Invalid credentials
Invalid email address
Invalid font size setting
Invalid message
Invalid message context request
Invalid message cursor
Invalid message type
Invalid messaging privacy setting
Invalid or expired session
Invalid reaction
Invalid read receipt request
Invalid reply target
Invalid request
Invalid request format
Invalid setting value
Invalid theme setting
Invalid upload request
Invalid verification code
Invalid verification code. Please try again.
Invalid verification code or backup code
Limit cannot exceed 100
Logged out successfully
Login completion failed
Login failed. Please try again.
Logout failed
Message context limits cannot exceed 50
Message deleted
Message delivery could not be confirmed
Message edited
Message ID and emoji are required
Message ID and new content are required
Message ID is required
Message not found
Message not found or access denied
Message rate limit reached. Please slow down
Message retry identifier is invalid
Message retry protection is temporarily unavailable
Messaging is temporarily unavailable
Method not allowed
Missing required fields
New backup codes generated successfully
New password must be between 12 and 72 characters
New password must be different from current password
No active session
No attachment was uploaded
No file uploaded
No pending 2FA verification
No pending 2FA verification. Please login again.
No valid settings to update
Password changed. Please sign in again.
Password changed successfully
Password changes must use account settings
Password must be between 12 and 72 characters
Phone number is invalid
Phone number is too long
Profile data is too long
Profile fields are invalid
Profile updated successfully
Profile update failed
Reaction added
Registration failed
Registration successful
Request body is too large
Request failed. Please try again.
Request is too large
Search query is required
Secret and verification code are required
Session expired
Session validation failed
Settings data is required
Settings request failed
Settings updated successfully
Sign-in is temporarily unavailable. Please try again.
Status updated
The attachment changed during security scanning
The attachment changed during validation
The attachment changed while being saved
The attachment could not be inspected
The attachment could not be saved
The attachment could not be secured
The attachment type could not be inspected
The attachment upload changed during inspection
The attachment upload changed during processing
The attachment upload is invalid
The attachment upload was incomplete
The avatar changed during security scanning
The image dimensions or animation are not supported
The message is empty, invalid, or too long
The message you are replying to is no longer available
The request could not be completed
The request is invalid
This attachment type is not supported
This attachment was rejected by security scanning
This avatar was rejected by security scanning
This user is not accepting new chats
Too many 2FA attempts. Try again later.
Too many 2FA setup attempts. Try again later.
Too many avatar uploads. Try again later.
Too many login attempts. Try again later.
Too many password attempts. Try again later.
Too many registration attempts. Try again later.
Too many requests. Try again shortly.
Too many verification attempts. Please login again later.
Too many verification attempts. Start 2FA setup again later.
Too many verification attempts. Try again later.
Typing status must be a boolean
Typing status updated
Unsupported Content-Type
User account not found
User ID is required
Username and password are required
Username and password cannot be empty
Username is already taken
Username must be 3-50 letters, numbers, dots, dashes, or underscores
Username or email already exists
User not found
User settings not found
Verification code is required
Verification failed
Verification is temporarily unavailable. Please try again.
You no longer have access to this chat
Your attachment storage quota has been reached
Your hourly attachment limit has been reached
PM_API_ENVELOPE_SOURCES
));
i18nCatalogAssert(
    is_array($requiredApiEnvelopeSources) &&
        count($requiredApiEnvelopeSources) === 196 &&
        count(array_unique($requiredApiEnvelopeSources)) === 196,
    'the audited public API envelope source fixture is complete and duplicate-free'
);
$missingApiEnvelopeSources = [];
foreach ($requiredApiEnvelopeSources as $source) {
    if (!isset($englishSources[i18nNormalizedSource($source)])) {
        $missingApiEnvelopeSources[] = $source;
    }
}
i18nCatalogAssert(
    $missingApiEnvelopeSources === [],
    'every audited public API envelope source remains represented in the English catalog' .
        ($missingApiEnvelopeSources === [] ? '' : ': ' . implode(' | ', $missingApiEnvelopeSources))
);

$requiredInfrastructureSources = ['Response encoding failed'];
$missingInfrastructureSources = array_values(array_filter(
    $requiredInfrastructureSources,
    static fn(string $source): bool => !isset($englishSources[$source])
));
i18nCatalogAssert(
    $missingInfrastructureSources === [],
    'minimal infrastructure failure envelopes remain localizable' .
        ($missingInfrastructureSources === [] ? '' : ': ' . implode(' | ', $missingInfrastructureSources))
);

$apiSourceFiles = [
    $root . '/api/auth.php',
    $root . '/api/chat.php',
    $root . '/api/settings.php',
    $root . '/api/profile.php',
];
$backendEnvelopeSources = i18nExtractBackendEnvelopeSources(
    array_merge($apiSourceFiles, [$root . '/classes/Auth.php', $root . '/classes/Chat.php']),
    $apiSourceFiles
);
// These exceptions are caught and replaced with a different public message.
$internalBackendMessages = array_fill_keys([
    'Invalid client message identifier',
    'Unable to lock avatar state',
], true);
$missingExtractedBackendSources = [];
foreach ($backendEnvelopeSources as $source) {
    if (!isset($internalBackendMessages[$source]) && !isset($englishSources[$source])) {
        $missingExtractedBackendSources[] = $source;
    }
}
i18nCatalogAssert(
    $missingExtractedBackendSources === [],
    'new literal public API envelope sources must be added to the English catalog' .
        ($missingExtractedBackendSources === []
            ? ''
            : ': ' . implode(' | ', $missingExtractedBackendSources))
);

$indexSource = file_get_contents($root . '/index.html');
$engineSource = file_get_contents($root . '/assets/js/i18n.js');
$styleSource = file_get_contents($root . '/assets/css/style.css');
$htaccessSource = file_get_contents($root . '/.htaccess');
i18nCatalogAssert(
    is_string($indexSource) && is_string($engineSource) &&
        is_string($styleSource) && is_string($htaccessSource),
    'i18n integration sources are readable'
);

$applicationJavaScriptFiles = [
    $root . '/assets/js/script-ori_2025-06-07_02.js',
    $root . '/assets/js/security-hardening.js',
    $root . '/assets/js/ui-enhancements.js',
    $root . '/assets/js/csp-events.js',
    $root . '/assets/js/chat-ux.js',
];
$applicationJavaScript = [];
foreach ($applicationJavaScriptFiles as $path) {
    $source = file_get_contents($path);
    i18nCatalogAssert(is_string($source), basename($path) . ' dynamic UI source is readable');
    $applicationJavaScript[$path] = $source;
}

$databaseSource = file_get_contents($root . '/config/database.php');
$chatClassSource = file_get_contents($root . '/classes/Chat.php');
$settingsApiSource = file_get_contents($root . '/api/settings.php');
$phpI18nSource = file_get_contents($root . '/classes/I18n.php');
i18nCatalogAssert(
    is_string($databaseSource) && is_string($chatClassSource) &&
        is_string($settingsApiSource) && is_string($phpI18nSource),
    'locale-sensitive backend sources are readable'
);
i18nCatalogAssert(
    ($charsetPosition = strpos($databaseSource, "set_charset('utf8mb4')")) !== false &&
        ($timeZonePosition = strpos($databaseSource, "query(\"SET time_zone = '+00:00'\")")) !== false &&
        $timeZonePosition > $charsetPosition &&
        $timeZonePosition - $charsetPosition < 160,
    'database sessions establish UTC immediately after UTF-8 charset setup'
);
i18nCatalogAssert(
    substr_count(strtolower($chatClassSource), 'rm.is_deleted as reply_is_deleted') === 3 &&
        str_contains($chatClassSource, "array_key_exists('reply_is_deleted', \$message)") &&
        str_contains($chatClassSource, "\$message['reply_content'] = null") &&
        preg_match('/SET\s+is_deleted\s*=\s*TRUE,\s*content\s*=\s*[\'"][\'"]/i', $chatClassSource) === 1 &&
        !str_contains($chatClassSource, "content = 'This message was deleted'"),
    'deleted replies use language-neutral metadata and never persist an English UI sentinel'
);
$storageByteFields = [
    "'messages_bytes' => \$messageBytes",
    "'media_bytes' => \$mediaBytes",
    "'documents_bytes' => \$documentBytes",
    "'total_bytes' => \$totalBytes",
];
i18nCatalogAssert(
    count(array_filter(
        $storageByteFields,
        static fn(string $mapping): bool => str_contains($settingsApiSource, $mapping)
    )) === count($storageByteFields) &&
        preg_match('/\$messageCount\s*=\s*max\(0,\s*\(int\)/', $settingsApiSource) === 1 &&
        preg_match('/\$mediaBytes\s*=\s*max\(0,\s*\(int\)/', $settingsApiSource) === 1,
    'storage API exposes validated nonnegative raw byte counts for locale-aware clients'
);
i18nCatalogAssert(
    str_contains($phpI18nSource, "self::translate('Response encoding failed', \$locale)") &&
        str_contains($phpI18nSource, 'JSON_INVALID_UTF8_SUBSTITUTE'),
    'response encoding failures use a fresh localized minimal envelope before the hardcoded last resort'
);

$jsLiteralAtom = <<<'REGEX'
(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|\x60(?:\\.|[^\x60\\$]|\$(?!\{))*\x60)
REGEX;
$jsLiteral = '(?<literal>' . $jsLiteralAtom . ')';
$terminalJsLiteral = $jsLiteral . '(?!\s*\+)';
$directUiSourcePatterns = [
    '~\b(?:window\.)?(?:showToast|toast|showLoading|alert|confirm)\s*\(\s*' .
        $terminalJsLiteral . '~s',
    '~\b(?:window\.)?showToast\s*\(\s*[^,\r\n]*?\|\|\s*' . $terminalJsLiteral . '~s',
    '~\bshowConfirmDialog\s*\(\s*' . $terminalJsLiteral . '~s',
    '~\bshowConfirmDialog\s*\(\s*' . $jsLiteralAtom . '\s*,\s*' . $terminalJsLiteral . '~s',
    '~\bshowConfirmDialog\s*\(\s*' . $jsLiteralAtom . '\s*,\s*' . $jsLiteralAtom .
        '\s*,\s*' . $terminalJsLiteral . '~s',
    '~\b(?:localizedLiteral|translateUiText)\s*\(\s*' . $terminalJsLiteral . '~s',
    '~\.setCustomValidity\s*\(\s*' . $terminalJsLiteral . '~s',
    '~\.(?:textContent|innerText|placeholder|title)\s*=\s*' . $terminalJsLiteral . '~s',
    '~\.(?:textContent|innerText|placeholder|title)\s*=\s*[^;\r\n]*?\|\|\s*' .
        $terminalJsLiteral . '~s',
    '~\.setAttribute\s*\(\s*[\'"](?:placeholder|title|aria-label|aria-description|alt|' .
        'data-mobile-label|data-drop-label)[\'"]\s*,\s*' . $terminalJsLiteral . '~s',
    '~\bsetTextIfChanged\s*\(\s*[^,\r\n]+,\s*' . $terminalJsLiteral . '~s',
    '~\bappendTextElement\s*\(\s*[^,\r\n]+,\s*' . $jsLiteralAtom . '\s*,\s*' .
        $jsLiteralAtom . '\s*,\s*' . $terminalJsLiteral . '~s',
    '~\b(?:document\.)?createTextNode\s*\(\s*' . $terminalJsLiteral . '~s',
];
$ignoredDynamicUiSources = array_fill_keys(['', 'U', 'C', 'M', 'J', 'username'], true);
$missingDynamicUiSources = [];
$quotedHtmlFragmentCount = 0;
$ignoredQuotedHtmlSources = array_fill_keys([
    // This transient placeholder is synchronously replaced before the
    // mutation observer runs; only the final semantic labels are visible.
    'Nothing found',
    // A dynamic query splits this source across concatenated operands. The
    // complete source template is asserted explicitly below.
    'No users found matching "',
], true);
foreach ($applicationJavaScript as $path => $source) {
    foreach ($directUiSourcePatterns as $pattern) {
        foreach (i18nJavaScriptLiteralMatches($source, $pattern) as $value) {
            if (isset($ignoredDynamicUiSources[$value]) ||
                preg_match('/\A[\p{N}\p{P}\p{S}\p{Z}]+\z/u', $value) === 1 ||
                i18nCatalogCoversSource($value, $englishSources, $englishSourcePatterns)) {
                continue;
            }
            $missingDynamicUiSources[basename($path) . ': ' . $value] = true;
        }
    }
}

// Template literals are handled below. Cover the other common dynamic-markup
// form separately: one or more quoted HTML fragments concatenated into an
// innerHTML assignment. Inspecting each fragment independently is deliberate;
// it finds user-facing text without trying to evaluate surrounding JavaScript.
foreach ($applicationJavaScript as $path => $source) {
    $assignmentCount = preg_match_all(
        '~\.innerHTML\s*=\s*(?<expression>[^;]+);~s',
        $source,
        $assignments,
        PREG_SET_ORDER
    );
    if ($assignmentCount === false) {
        throw new RuntimeException('concatenated dynamic HTML extraction pattern is invalid');
    }
    foreach ($assignments as $assignment) {
        $fragmentCount = preg_match_all(
            '~(?<literal>' . $jsLiteralAtom . ')~s',
            $assignment['expression'],
            $fragments,
            PREG_SET_ORDER
        );
        if ($fragmentCount === false) {
            throw new RuntimeException('dynamic HTML fragment extraction pattern is invalid');
        }
        foreach ($fragments as $fragmentMatch) {
            $fragment = i18nDecodeJavaScriptLiteral($fragmentMatch['literal']);
            if (!str_contains($fragment, '<')) {
                continue;
            }
            $quotedHtmlFragmentCount += 1;
            $fragmentDocument = new DOMDocument();
            $previousFragmentErrors = libxml_use_internal_errors(true);
            $fragmentLoaded = $fragmentDocument->loadHTML(
                '<!doctype html><html><head><meta charset="utf-8"></head><body>' .
                    $fragment . '</body></html>',
                LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING
            );
            libxml_clear_errors();
            libxml_use_internal_errors($previousFragmentErrors);
            if (!$fragmentLoaded) {
                throw new RuntimeException(basename($path) . ' quoted HTML fragment cannot be inspected');
            }
            foreach (i18nIndexSources($fragmentDocument, false) as $value) {
                if (isset($ignoredDynamicUiSources[$value]) || isset($ignoredQuotedHtmlSources[$value]) ||
                    preg_match('/\A[\p{N}\p{P}\p{S}\p{Z}]+\z/u', $value) === 1 ||
                    i18nCatalogCoversSource($value, $englishSources, $englishSourcePatterns)) {
                    continue;
                }
                $missingDynamicUiSources[basename($path) . ' quoted HTML: ' . $value] = true;
            }
        }
    }
}
i18nCatalogAssert(
    $quotedHtmlFragmentCount >= 50,
    'quoted and concatenated dynamic HTML remains under catalog coverage'
);
$ignoredDynamicTemplateSources = array_fill_keys([
    '@loading',
    'Messenger',
    '• Google Authenticator',
    '• Microsoft Authenticator',
    '• Authy',
    '• 1Password',
    '• Bitwarden',
], true);
$dynamicTemplateCount = 0;
foreach ($applicationJavaScript as $path => $source) {
    $templateScanSource = preg_replace(
        '~\$\{[^{}]*\x60(?:\\.|[^\x60])*\x60[^{}]*\}~s',
        '000000',
        $source
    );
    if (!is_string($templateScanSource)) {
        throw new RuntimeException('nested dynamic HTML template interpolation could not be bounded');
    }
    $count = preg_match_all(
        '~\x60(?<template>\s*<[\s\S]*?)\x60~',
        $templateScanSource,
        $templateMatches,
        PREG_SET_ORDER
    );
    if ($count === false) {
        throw new RuntimeException('dynamic HTML template extraction pattern is invalid');
    }
    $dynamicTemplateCount += $count;
    foreach ($templateMatches as $templateMatch) {
        $template = preg_replace('/\$\{.*?\}/s', '000000', $templateMatch['template']);
        if (!is_string($template)) {
            throw new RuntimeException('dynamic HTML interpolation could not be bounded');
        }
        $templateDocument = new DOMDocument();
        $previousTemplateErrors = libxml_use_internal_errors(true);
        $templateLoaded = $templateDocument->loadHTML(
            '<!doctype html><html><head><meta charset="utf-8"></head><body>' . $template . '</body></html>',
            LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING
        );
        libxml_clear_errors();
        libxml_use_internal_errors($previousTemplateErrors);
        i18nCatalogAssert($templateLoaded, basename($path) . ' dynamic HTML template can be inspected');
        foreach (i18nIndexSources($templateDocument) as $value) {
            if (isset($ignoredDynamicTemplateSources[$value]) || str_contains($value, '$' . '{') ||
                preg_match('/\A[\p{N}\p{P}\p{S}\p{Z}]+\z/u', $value) === 1 ||
                i18nCatalogCoversSource($value, $englishSources, $englishSourcePatterns)) {
                continue;
            }
            $missingDynamicUiSources[basename($path) . ' template: ' . $value] = true;
        }
    }
}
i18nCatalogAssert($dynamicTemplateCount >= 10, 'active dynamic HTML templates remain under catalog coverage');
$requiredCompositeUiSources = [
    'Conversation pinned on this device',
    'Conversation unpinned on this device',
    'Conversation de-emphasized on this device',
    'Conversation prominence restored on this device',
    'Select a conversation first',
    '☀️ Light mode enabled',
    '🌙 Dark mode enabled',
    'No matching settings',
    'No matching conversations',
    'Secure message identifiers are unavailable in this browser',
    'Edit outcome could not be confirmed. Reload the conversation before retrying.',
    'Message could not be edited',
    'Try another search or filter.',
    'Could not load conversations',
    'Type at least 2 characters to search',
    'No users found matching "{{query}}"',
    'Type to search messages',
];
foreach ($requiredCompositeUiSources as $value) {
    if (!i18nCatalogCoversSource($value, $englishSources, $englishSourcePatterns)) {
        $missingDynamicUiSources['required composed/surfaced UI: ' . $value] = true;
    }
}
i18nCatalogAssert(
    $missingDynamicUiSources === [],
    'dynamic UI literals, templates, and localizable attributes are represented in the English catalog' .
        ($missingDynamicUiSources === [] ? '' : ': ' . implode(' | ', array_keys($missingDynamicUiSources)))
);

$literalTranslationKeyPattern =
    '~\b(?:localized|localizedCount|translateUi|PmI18n\.(?:t|tc))\s*\(\s*' .
    '(?<quote>[\'"])(?<key>[a-z0-9](?:[a-z0-9._-]*[a-z0-9_-])?)\k<quote>(?!\s*\+)~';
$missingJavaScriptKeys = [];
foreach ($applicationJavaScript as $path => $source) {
    $count = preg_match_all($literalTranslationKeyPattern, $source, $matches, PREG_SET_ORDER);
    if ($count === false) {
        throw new RuntimeException('JavaScript semantic translation key pattern is invalid');
    }
    foreach ($matches as $match) {
        $key = $match['key'];
        if (!array_key_exists($key, $catalogs['en']['messages'])) {
            $missingJavaScriptKeys[basename($path) . ': ' . $key] = true;
        }
    }
}
i18nCatalogAssert(
    $missingJavaScriptKeys === [],
    'every literal JavaScript semantic translation key exists in the catalog' .
        ($missingJavaScriptKeys === [] ? '' : ': ' . implode(' | ', array_keys($missingJavaScriptKeys)))
);

$mainJavaScriptPath = $root . '/assets/js/script-ori_2025-06-07_02.js';
$failureMapFound = preg_match(
    '/\bconst\s+CHAT_SEND_FAILURE_MESSAGES\s*=\s*Object\.freeze\s*\(\s*\{(?<body>.*?)\}\s*\);/s',
    $applicationJavaScript[$mainJavaScriptPath],
    $failureMapMatch
);
i18nCatalogAssert($failureMapFound === 1, 'the client send-failure allowlist can be inspected');
$failureSourcePattern = '~:\s*' . $terminalJsLiteral . '\s*(?:,|\z)~s';
$chatFailureSources = i18nJavaScriptLiteralMatches($failureMapMatch['body'], $failureSourcePattern);
i18nCatalogAssert(
    count($chatFailureSources) >= 29 && count(array_unique($chatFailureSources)) >= 28,
    'the complete client send-failure message surface is covered'
);
$failureEntryPattern =
    '~(?<code>[a-z][a-z0-9_]*)\s*:\s*' . $terminalJsLiteral . '\s*(?:,|\z)~s';
$failureEntryCount = preg_match_all(
    $failureEntryPattern,
    $failureMapMatch['body'],
    $failureEntries,
    PREG_SET_ORDER
);
i18nCatalogAssert(
    is_int($failureEntryCount) && $failureEntryCount === count($chatFailureSources),
    'every client send-failure source has a stable error code'
);
$missingChatFailureKeys = [];
foreach ($failureEntries as $entry) {
    $key = 'send.error.' . $entry['code'];
    if (!array_key_exists($key, $catalogs['en']['messages'])) {
        $missingChatFailureKeys[] = $key;
    }
}
i18nCatalogAssert(
    $missingChatFailureKeys === [],
    'every dynamic send-failure error code resolves to a semantic catalog key' .
        ($missingChatFailureKeys === [] ? '' : ': ' . implode(' | ', $missingChatFailureKeys))
);
$missingChatFailureSources = [];
foreach ($chatFailureSources as $source) {
    if (!i18nCatalogCoversSource($source, $englishSources, $englishSourcePatterns)) {
        $missingChatFailureSources[] = $source;
    }
}
i18nCatalogAssert(
    $missingChatFailureSources === [],
    'every allowlisted client send failure is represented in the English catalog' .
        ($missingChatFailureSources === [] ? '' : ': ' . implode(' | ', $missingChatFailureSources))
);

$securityJavaScript = $applicationJavaScript[$root . '/assets/js/security-hardening.js'];
$uiJavaScript = $applicationJavaScript[$root . '/assets/js/ui-enhancements.js'];
$chatUxJavaScript = $applicationJavaScript[$root . '/assets/js/chat-ux.js'];
$allApplicationJavaScript = implode("\n", $applicationJavaScript);
i18nCatalogAssert(
    substr_count($securityJavaScript, "localized('chat.online'") >= 2 &&
        substr_count($securityJavaScript, "localized('chat.last_seen'") >= 2 &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], "translateUi('chat.online'") &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], "translateUi('chat.last_seen'") &&
        !str_contains($allApplicationJavaScript, "translateUiText('online')") &&
        preg_match(
            '/\.textContent\s*=\s*(?:online|isReallyOnline)\s*\?\s*[\'"](?:online|Online)[\'"]/',
            $allApplicationJavaScript
        ) !== 1,
    'online and last-seen status chrome always uses semantic localized keys'
);
i18nCatalogAssert(
    str_contains($securityJavaScript, "localized('chat.no_messages'") &&
        str_contains($chatUxJavaScript, "localized('chat.no_messages'") &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], "translateUi('chat.no_messages'") &&
        preg_match(
            '/(?:last_message|serverPreview)\s*\|\|\s*[\'"]No messages yet[\'"]/',
            $allApplicationJavaScript
        ) !== 1,
    'empty conversation previews are localized explicitly outside the user-text exclusion boundary'
);
i18nCatalogAssert(
    str_contains($securityJavaScript, 'message.reply_is_deleted') &&
        str_contains($securityJavaScript, "localized('chat.deleted'") &&
        str_contains($securityJavaScript, "dataset.i18nReplyDeleted = 'true'") &&
        str_contains($securityJavaScript, '[data-i18n-reply-deleted="true"]'),
    'deleted reply chrome is rendered and refreshed from language-neutral metadata'
);
i18nCatalogAssert(
    str_contains($uiJavaScript, "edited.dataset.i18n = 'chat.edited'") &&
        str_contains($uiJavaScript, "edited.textContent = localized('chat.edited'"),
    'persistent edited-message chrome carries a semantic marker for live locale changes'
);
i18nCatalogAssert(
    str_contains($chatUxJavaScript, 'completedSearchCount: null') &&
        str_contains(
            $chatUxJavaScript,
            'uxState.completedSearchCount = uxState.searchResults.length'
        ) &&
        preg_match(
            '/else if \(Number\.isSafeInteger\(uxState\.completedSearchCount\)\)\s*\{\s*' .
                'refreshSearchCountOutput\(uxState\.completedSearchCount\);/s',
            $chatUxJavaScript
        ) === 1,
    'completed zero-result searches are reformatted when the locale changes'
);
i18nCatalogAssert(
    str_contains($applicationJavaScript[$mainJavaScriptPath], 'lastStorageUsage = storage') &&
        str_contains(
            $applicationJavaScript[$mainJavaScriptPath],
            "const byteKeys = ['messages_bytes', 'media_bytes', 'documents_bytes', 'total_bytes']"
        ) &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], 'return formatFileSize(bytes)') &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], 'refreshLocalizedStorageUsage();') &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], 'window.PmI18n.formatBytes(bytes)'),
    'storage UI prefers raw byte fields and reformats cached values after locale changes'
);
i18nCatalogAssert(
    str_contains(
        $applicationJavaScript[$mainJavaScriptPath],
        "const localization = option[0] === 'auto' ? ' data-i18n=\"settings.system_default\"' : ''"
    ),
    'the generated automatic-language option remains semantic across live locale changes'
);
$appearanceOptionMappings = [
    'value="small" data-i18n="settings.small"',
    'value="medium" data-i18n="settings.medium"',
    'value="large" data-i18n="settings.large"',
    'value="extra-large" data-i18n="settings.extra_large"',
    'value="default" data-i18n="settings.default"',
    'value="gradient1" data-i18n="settings.blue_gradient"',
    'value="gradient2" data-i18n="settings.purple_gradient"',
    'value="solid" data-i18n="settings.solid_color"',
];
i18nCatalogAssert(
    count(array_filter(
        $appearanceOptionMappings,
        static fn(string $mapping): bool => str_contains(
            $applicationJavaScript[$mainJavaScriptPath],
            $mapping
        )
    )) === count($appearanceOptionMappings) &&
        str_contains($uiJavaScript, "const semanticLabel = option.dataset.i18n || ''") &&
        str_contains($uiJavaScript, 'button.dataset.i18nAppearanceLabel = semanticLabel') &&
        str_contains(
            $uiJavaScript,
            'button.dataset.i18nAppearanceLabel || option.dataset.i18n'
        ) &&
        str_contains($uiJavaScript, 'localized(semanticLabel, {}, option.textContent)') &&
        str_contains($uiJavaScript, 'refreshVisualChoiceLabels();'),
    'persistent visual-choice labels and aria text refresh from semantic option keys'
);
i18nCatalogAssert(
    str_contains(
        $applicationJavaScript[$mainJavaScriptPath],
        "window.addEventListener('pm:localechange', refreshLocalizedApplicationChrome)"
    ) &&
        str_contains(
            $applicationJavaScript[$mainJavaScriptPath],
            'window.PmI18n.ready.then(function () {'
        ) &&
        str_contains(
            $applicationJavaScript[$mainJavaScriptPath],
            'window.setTimeout(refreshLocalizedApplicationChrome, 0)'
        ) &&
        str_contains(
            $applicationJavaScript[$mainJavaScriptPath],
            'window.refreshLocalizedSecurityChrome'
        ) &&
        str_contains(
            $applicationJavaScript[$mainJavaScriptPath],
            'window.refreshLocalizedChatUx'
        ) &&
        str_contains(
            $applicationJavaScript[$mainJavaScriptPath],
            'window.refreshLocalizedAccessibility'
        ),
    'initial catalog readiness and later locale changes refresh every dynamic chrome layer'
);
i18nCatalogAssert(
    preg_match(
        '/const fileName = appendTextElement\(.*?file\.name\);\s*' .
            'fileName\.dir\s*=\s*[\'"]auto[\'"];\s*fileName\.dataset\.i18nIgnore\s*=\s*[\'"][\'"];/s',
        $securityJavaScript
    ) === 1,
    'attachment preview filenames are explicitly excluded from automatic translation'
);
i18nCatalogAssert(
    str_contains($securityJavaScript, "alt: localized('profile.sender_avatar'") &&
        str_contains($securityJavaScript, "avatar.dataset.i18nAlt = 'profile.sender_avatar'") &&
        str_contains(
            $securityJavaScript,
            "querySelectorAll('img[data-i18n-alt=\"profile.sender_avatar\"]')"
        ) &&
        str_contains($securityJavaScript, "image.alt = localized('profile.sender_avatar'"),
    'sender-avatar alternative text is semantic at creation and on live locale changes'
);
i18nCatalogAssert(
    substr_count($uiJavaScript, "title.dataset.i18n = 'files.photo_unavailable'") === 2 &&
        str_contains($uiJavaScript, "description.dataset.i18n = 'files.photo_removed'"),
    'detached image-failure chrome carries semantic markers before insertion'
);
i18nCatalogAssert(
    str_contains($securityJavaScript, "dataset.i18nFallback = 'common.unknown'") &&
        str_contains($securityJavaScript, "dataset.i18nFallback = 'common.user'") &&
        str_contains($securityJavaScript, "dataset.i18nFallback = 'files.attachment_name'") &&
        str_contains($securityJavaScript, "querySelectorAll('[data-i18n-fallback]')") &&
        str_contains($uiJavaScript, "dataset.i18nImageFallback = 'files.photo_failed'") &&
        str_contains($uiJavaScript, "dataset.i18nImageFallback = 'files.photo'") &&
        str_contains($uiJavaScript, "querySelectorAll('[data-i18n-image-fallback]')"),
    'ignored user-text surfaces carry semantic metadata for localizable chrome fallbacks'
);
i18nCatalogAssert(
    !str_contains($engineSource, "'.profile-additional-info'") &&
        !str_contains($engineSource, "'.user-profile-bio'") &&
        str_contains($engineSource, "'.bio-content'"),
    'profile wrapper chrome remains localizable while only profile values are excluded'
);

$messageTimeFunctionFound = preg_match(
    '/function getMessageTimeMinutes\(message\)\s*\{(?<body>.*?)\n\s*\}\n\n\s*' .
        'function mutationTouchesMessage/s',
    $uiJavaScript,
    $messageTimeFunctionMatch
);
$messageTimeBody = $messageTimeFunctionFound === 1 ? $messageTimeFunctionMatch['body'] : '';
$canonicalTimestampPosition = strpos($messageTimeBody, 'window.parsePmTimestamp(message.dataset.createdAt)');
$localizedDisplayPosition = strpos($messageTimeBody, "message.querySelector('.message-time')");
i18nCatalogAssert(
    $messageTimeFunctionFound === 1 &&
        $canonicalTimestampPosition !== false &&
        $localizedDisplayPosition !== false &&
        $canonicalTimestampPosition < $localizedDisplayPosition &&
        str_contains($messageTimeBody, 'createdAt instanceof Date'),
    'message grouping parses canonical UTC metadata before localized display text'
);

i18nCatalogAssert(
    str_contains($uiJavaScript, "content.querySelector(':scope > .message-text')") &&
        str_contains($uiJavaScript, "content.querySelector(':scope > .message-caption')") &&
        str_contains($uiJavaScript, "image.dataset.i18nFileNameFallback !== 'true'") &&
        !str_contains($uiJavaScript, 'const preview = content.textContent') &&
        str_contains($uiJavaScript, "'chat.message_action_label'") &&
        str_contains($uiJavaScript, '{preview: preview}') &&
        str_contains($uiJavaScript, "'chat.message_action_label_empty'") &&
        str_contains(
            $uiJavaScript,
            'messagesList.querySelectorAll(\'.message-content[data-message-actions-ready="true"]\')'
        ) &&
        str_contains($uiJavaScript, "content.setAttribute('aria-label', createMessageActionLabel(content))"),
    'message action labels localize semantic chrome while preserving raw user previews across locale changes'
);

$cspEventsSource = $applicationJavaScript[$root . '/assets/js/csp-events.js'];
i18nCatalogAssert(
    str_contains($cspEventsSource, 'const message = translated === key ? fallback : translated;') &&
        str_contains($cspEventsSource, "'about.support_soon': 'Support feature coming soon!'") &&
        str_contains($cspEventsSource, "'about.help_soon': 'Help center coming soon!'") &&
        str_contains($cspEventsSource, "'about.legal_soon': 'Terms & Privacy coming soon!'"),
    'early and offline About actions fall back to readable English instead of semantic keys'
);
i18nCatalogAssert(
    !str_contains($applicationJavaScript[$mainJavaScriptPath], "showToast('❌ ' + (error.message") &&
        !str_contains($applicationJavaScript[$mainJavaScriptPath], "showToast('❌ ' + (data.message") &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], 'translateUiText(error.message)') &&
        substr_count($applicationJavaScript[$mainJavaScriptPath], 'translateUiText(data.message)') >= 2 &&
        str_contains(
            $applicationJavaScript[$mainJavaScriptPath],
            "translateUi('api.settings_update_failed', {}, 'Failed to update settings')"
        ) &&
        substr_count(
            $applicationJavaScript[$mainJavaScriptPath],
            "translateUi('api.invalid_verification', {}, 'Invalid verification code')"
        ) >= 2,
    'dynamic settings and two-factor failures localize their message before adding decorative icons'
);
i18nCatalogAssert(
    !str_contains($applicationJavaScript[$mainJavaScriptPath], "isOwnMessage ? 'You'") &&
        !str_contains($applicationJavaScript[$mainJavaScriptPath], "return 'User';") &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], "return {kind: 'self', name: ''};") &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], "? {kind: 'name', name: rawName}") &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], ": {kind: 'fallback', name: ''}") &&
        str_contains(
            $applicationJavaScript[$mainJavaScriptPath],
            'showReplyPreview(selectedMessageId, sender.name, text, sender.kind)'
        ) &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], "translateUi('common.you', {}, 'You')") &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], "translateUi('common.user', {}, 'User')") &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], 'input.dataset.replySenderKind = kind;') &&
        str_contains($applicationJavaScript[$mainJavaScriptPath], 'refreshReplyComposerSender();') &&
        str_contains($securityJavaScript, 'function replyPreviewSenderName(senderKind, senderName)') &&
        str_contains($securityJavaScript, "if (senderKind === 'self') return localized('common.you'") &&
        str_contains($securityJavaScript, "if (senderKind === 'fallback') return localized('common.user'") &&
        str_contains($securityJavaScript, 'return asString(senderName);') &&
        str_contains($securityJavaScript, 'replySender.dataset.i18nReplySenderKind = kind;') &&
        str_contains($securityJavaScript, "if (kind === 'name') replySender.dataset.i18nReplySenderName = rawName;") &&
        str_contains($securityJavaScript, "querySelectorAll('[data-i18n-reply-sender-kind]')") &&
        str_contains($securityJavaScript, 'const displayName = replyPreviewSenderName(kind, rawName);'),
    'reply previews model self, fallback, and genuine sender names for initial and live localization'
);

$directionSensitiveSelectors = [
    '\.settings-overview-card',
    '\.theme-choice',
    '\.visual-choice',
    '\.chat-side-search-results\s+\.search-result-item',
    '\.chat-row-menu-item',
    'button\.search-result-item',
];
$physicalLeftAlignment = [];
foreach ($directionSensitiveSelectors as $selector) {
    if (preg_match(
        '/(?:\A|\})[^{}]*' . $selector . '[^{}]*\{[^{}]*text-align\s*:\s*left\b/mi',
        $styleSource
    ) === 1) {
        $physicalLeftAlignment[] = $selector;
    }
}
i18nCatalogAssert(
    $physicalLeftAlignment === [],
    'direction-sensitive interactive controls never hard-code left text alignment' .
        ($physicalLeftAlignment === [] ? '' : ': ' . implode(', ', $physicalLeftAlignment))
);
i18nCatalogAssert(
    preg_match(
        '/html\[dir="rtl"\]\s+\.chat-side-search-field\s*>\s*i\s*\{[^}]*' .
            'right\s*:\s*14px[^}]*left\s*:\s*auto/s',
        $styleSource
    ) === 1 &&
        preg_match(
            '/html\[dir="rtl"\]\s+\.chat-side-search-field\s+input\s*\{[^}]*' .
                'padding-right\s*:\s*39px[^}]*padding-left\s*:\s*48px/s',
            $styleSource
        ) === 1 &&
        preg_match(
            '/html\[dir="rtl"\]\s+\.chat-side-search-field\s+button\s*\{[^}]*' .
                'right\s*:\s*auto[^}]*left\s*:\s*0/s',
            $styleSource
        ) === 1 &&
        preg_match(
            '/html\[dir="rtl"\]\s+\.chat-item\s+\.chat-avatar\s*\{[^}]*' .
                'margin-right\s*:\s*0[^}]*margin-left\s*:\s*9px/s',
            $styleSource
        ) === 1 &&
        preg_match(
            '/html\[dir="rtl"\]\s+\.settings-icon\s*\{[^}]*' .
                'margin-right\s*:\s*0[^}]*margin-left\s*:\s*12px/s',
            $styleSource
        ) === 1 &&
        preg_match(
            '/html\[dir="rtl"\]\s+\.chat-item:hover,\s*' .
                'html\[dir="rtl"\]\s+\.settings-item:hover\s*\{[^}]*translateX\(-2px\)/s',
            $styleSource
        ) === 1 &&
        preg_match(
            '/html\[dir="rtl"\]\s+\.chat-item\.active,\s*' .
                'html\[dir="rtl"\]\s+\.settings-item\.active\s*\{[^}]*inset\s+-3px\s+0/s',
            $styleSource
        ) === 1,
    'late RTL refinements mirror chat search controls, row spacing, motion, and active accents'
);
i18nCatalogAssert(
    preg_match(
        '/\.message-time,\s*\.message-status\s*\{[^}]*float\s*:\s*inline-end[^}]*' .
            'margin-inline-start\s*:\s*8px/s',
        $styleSource
    ) === 1 &&
        preg_match('/\.message-status\s*\{[^}]*margin-inline-start\s*:\s*5px/s', $styleSource) === 1 &&
        preg_match('/\.reply-preview\s*\{[^}]*border-inline-start\s*:/s', $styleSource) === 1 &&
        preg_match('/\.reply-preview\s+\.reply-close\s*\{[^}]*inset-inline-end\s*:\s*8px/s', $styleSource) === 1 &&
        preg_match('/\.reply-to\s*\{[^}]*border-inline-start\s*:\s*2px/s', $styleSource) === 1 &&
        preg_match('/\.message-edited\s*\{[^}]*margin-inline-start\s*:\s*6px/s', $styleSource) === 1 &&
        preg_match('/html\[dir="rtl"\]\s+\.ms-auto\s*\{[^}]*margin-right\s*:\s*auto/s', $styleSource) === 1 &&
        preg_match('/html\[dir="rtl"\]\s+\.fa-arrow-right\s*\{[^}]*scaleX\(-1\)/s', $styleSource) === 1 &&
        preg_match('/html\[dir="rtl"\]\s+\[data-pm-action="back-to-login"\]\s+\.fa-arrow-left\s*\{[^}]*scaleX\(-1\)/s', $styleSource) === 1 &&
        preg_match('/\.toast-container\s*\{[^}]*inset-inline-end\s*:\s*16px/s', $styleSource) === 1 &&
        preg_match('/\.emoji-picker\s*\{[^}]*inset-inline-start\s*:/s', $styleSource) === 1 &&
        preg_match('/html\[dir="rtl"\]\s+\.sidebar\s*\{[^}]*translateX\(100%\)/s', $styleSource) === 1 &&
        preg_match('/html\[dir="rtl"\]\s+\.sidebar\.show\s*\{[^}]*translateX\(0\)/s', $styleSource) === 1,
    'logical message chrome and overlays mirror cleanly while the RTL mobile rail enters from inline start'
);

$document = new DOMDocument();
$previous = libxml_use_internal_errors(true);
$loaded = $document->loadHTML($indexSource, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
libxml_clear_errors();
libxml_use_internal_errors($previous);
i18nCatalogAssert($loaded, 'application HTML can be parsed without network access');

// These are brand fragments, glyphs, fixture data, or numeric input examples,
// not natural-language UI copy. Keep this list deliberately small and exact.
$ignoredIndexSources = array_fill_keys([
    'pm', 'Messenger', 'M', 'J', 'Test User', '@testuser', '⌘K', '000000',
], true);
$missingSources = [];
foreach (i18nIndexSources($document) as $source) {
    if (isset($ignoredIndexSources[$source]) || isset($englishSources[$source])) {
        continue;
    }
    $templateMatch = false;
    foreach ($englishSourcePatterns as $pattern) {
        if (preg_match($pattern, $source) === 1) {
            $templateMatch = true;
            break;
        }
    }
    if ($templateMatch) {
        continue;
    }
    if (preg_match('/\A[\p{N}\p{P}\p{S}\p{Z}]+\z/u', $source) === 1) {
        continue;
    }
    $missingSources[] = $source;
}
i18nCatalogAssert(
    $missingSources === [],
    'every visible English HTML source and localizable attribute exists in the English catalog' .
        ($missingSources === [] ? '' : ': ' . implode(' | ', $missingSources))
);

$ignoreXPath = new DOMXPath($document);
$ignoredNodes = $ignoreXPath->query('//*[@data-i18n-ignore]');
i18nCatalogAssert($ignoredNodes !== false, 'explicit non-translatable surfaces can be inspected');
$ignoredNodeText = [];
foreach ($ignoredNodes as $node) {
    if (!$node instanceof DOMElement) {
        continue;
    }
    $ignoredNodeText[] = i18nNormalizedSource($node->textContent);
}
$allowedIgnoredNodeText = [
    '', 'Test User', '@testuser', 'Chat Name',
    'English', 'Español', '简体中文', '繁體中文', 'العربية',
];
sort($ignoredNodeText, SORT_STRING);
sort($allowedIgnoredNodeText, SORT_STRING);
i18nCatalogAssert(
    $ignoredNodeText === $allowedIgnoredNodeText,
    'the HTML translation-ignore boundary contains only user defaults and native language names'
);

$xpath = new DOMXPath($document);
$scriptNodes = $xpath->query('//script');
i18nCatalogAssert($scriptNodes !== false, 'script loading order can be inspected');
$scriptSources = [];
foreach ($scriptNodes as $script) {
    if (!$script instanceof DOMElement) {
        continue;
    }
    i18nCatalogAssert($script->hasAttribute('src'), 'CSP forbids inline script blocks');
    $scriptSources[] = $script->getAttribute('src');
}
$i18nPosition = null;
$applicationPosition = null;
foreach ($scriptSources as $index => $source) {
    if (str_starts_with($source, 'assets/js/i18n.js?')) {
        $i18nPosition = $index;
    }
    if (str_starts_with($source, 'assets/js/script-ori_2025-06-07_02.js?')) {
        $applicationPosition = $index;
    }
}
i18nCatalogAssert(
    is_int($i18nPosition) && is_int($applicationPosition) && $i18nPosition < $applicationPosition,
    'the external i18n engine loads before every application layer'
);

$allNodes = $xpath->query('//*');
i18nCatalogAssert($allNodes !== false, 'HTML attributes can be inspected for CSP regressions');
foreach ($allNodes as $node) {
    if (!$node instanceof DOMElement) {
        continue;
    }
    foreach ($node->attributes as $attribute) {
        $name = strtolower($attribute->name);
        if (str_starts_with($name, 'on') || $name === 'style') {
            throw new RuntimeException("CSP-forbidden inline {$name} attribute is present");
        }
    }
}
i18nCatalogAssert(true, 'inline event and style attributes remain absent');

i18nCatalogAssert(
    str_contains($htaccessSource, "script-src-attr 'none'") &&
        str_contains($htaccessSource, "style-src-attr 'none'") &&
        !preg_match('/\beval\s*\(|\bnew\s+Function\s*\(/', $engineSource) &&
        !str_contains($engineSource, '.innerHTML'),
    'the translation engine preserves the no-inline/no-eval/text-only CSP architecture'
);

require_once $root . '/classes/I18n.php';

/** Reset only request-scoped I18n state between negotiation fixtures. */
function i18nResetRequestState(): void
{
    $reflection = new ReflectionClass(I18n::class);
    foreach (['requestLocale' => null, 'headersApplied' => false] as $name => $value) {
        $property = $reflection->getProperty($name);
        $property->setAccessible(true);
        $property->setValue(null, $value);
    }
}

$_COOKIE = ['pm_locale' => 'ar'];
$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'es-MX;q=1';
i18nResetRequestState();
i18nCatalogAssert(I18n::locale() === 'ar', 'a supported locale cookie has negotiation precedence');

$_COOKIE = ['pm_locale' => 'es-MX'];
$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'zh-TW;q=0.7, es-MX;q=0.9, en;q=0.4';
i18nResetRequestState();
i18nCatalogAssert(
    I18n::locale() === 'es',
    'a regional cookie is rejected while weighted Accept-Language safely resolves to a supported base locale'
);

$_COOKIE = [];
$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'zh-Hans-TW';
i18nResetRequestState();
i18nCatalogAssert(
    I18n::locale() === 'zh-Hans',
    'PHP locale negotiation gives an explicit Simplified script precedence over a conflicting region'
);

$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'zh-Hant-CN';
i18nResetRequestState();
i18nCatalogAssert(
    I18n::locale() === 'zh-Hant',
    'PHP locale negotiation gives an explicit Traditional script precedence over a conflicting region'
);

$_COOKIE = ['pm_locale' => '../ar'];
$_SERVER['HTTP_ACCEPT_LANGUAGE'] = "invalid;q=1, ar;q=0\n";
i18nResetRequestState();
i18nCatalogAssert(I18n::locale() === 'en', 'malformed locale inputs fall back to English');

$_COOKIE = ['pm_locale' => 'es'];
unset($_SERVER['HTTP_ACCEPT_LANGUAGE']);
i18nResetRequestState();
$encoded = json_decode(I18n::encodeResponse([
    'success' => false,
    'message' => $flattened['en']['common.cancel'],
    'error' => $flattened['en']['common.close'],
    'nested' => ['message' => $flattened['en']['common.cancel']],
]), true, 32, JSON_THROW_ON_ERROR);
i18nCatalogAssert(
    $encoded['message'] === $flattened['es']['common.cancel'] &&
        $encoded['error'] === $flattened['es']['common.close'] &&
        $encoded['nested']['message'] === $flattened['en']['common.cancel'],
    'PHP localizes only top-level API envelope text and never user/application payload data'
);

$_COOKIE = [];
unset($_SERVER['HTTP_ACCEPT_LANGUAGE']);
i18nResetRequestState();

echo "Internationalization catalog tests passed.\n";
