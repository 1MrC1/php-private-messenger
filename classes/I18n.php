<?php
declare(strict_types=1);

/**
 * Small, request-scoped localization boundary for JSON API responses.
 *
 * Application data remains language-neutral. Only the top-level `message`
 * and `error` strings of a response are translated, after the endpoint has
 * already selected its HTTP status and behavioral flags.
 */
final class I18n
{
    private const DEFAULT_LOCALE = 'en';
    private const COOKIE_NAME = 'pm_locale';
    private const MAX_ACCEPT_LANGUAGE_BYTES = 4096;
    private const MAX_LANGUAGE_RANGES = 32;
    private const MAX_CATALOG_BYTES = 1048576;

    /** @var array<string, string> */
    private const CATALOG_FILES = [
        'en' => 'en.json',
        'es' => 'es.json',
        'zh-Hans' => 'zh-Hans.json',
        'zh-Hant' => 'zh-Hant.json',
        'ar' => 'ar.json',
    ];

    private static ?string $requestLocale = null;
    private static bool $headersApplied = false;

    /** @var array<string, array<string, mixed>> */
    private static array $catalogs = [];

    /** @var array<string, array<int, string>>|null */
    private static ?array $englishMessagePaths = null;

    private function __construct()
    {
    }

    public static function locale(): string
    {
        if (self::$requestLocale !== null) {
            return self::$requestLocale;
        }

        $cookieLocale = $_COOKIE[self::COOKIE_NAME] ?? null;
        if (is_string($cookieLocale)) {
            $normalized = self::normalizeLocale($cookieLocale, false);
            if ($normalized !== null) {
                return self::$requestLocale = $normalized;
            }
        }

        $acceptLanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null;
        if (is_string($acceptLanguage)) {
            $negotiated = self::negotiateAcceptLanguage($acceptLanguage);
            if ($negotiated !== null) {
                return self::$requestLocale = $negotiated;
            }
        }

        return self::$requestLocale = self::DEFAULT_LOCALE;
    }

    /**
     * Translate only API envelope text. Nested chat, profile, and user data is
     * deliberately left untouched.
     */
    public static function encodeResponse(array $response, int $options = 0): string
    {
        $locale = self::locale();
        self::setResponseHeaders($locale);

        foreach (['message', 'error'] as $field) {
            if (isset($response[$field]) && is_string($response[$field])) {
                $response[$field] = self::translate($response[$field], $locale);
            }
        }

        $encoded = json_encode($response, $options);
        if (is_string($encoded)) {
            return $encoded;
        }

        // Encode a fresh, minimal envelope so encoder diagnostics and partial
        // private response data are never exposed. The literal fallback is
        // retained only for the practically unreachable second failure.
        $fallback = json_encode([
            'success' => false,
            'message' => self::translate('Response encoding failed', $locale),
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        return is_string($fallback)
            ? $fallback
            : '{"success":false,"message":"Response encoding failed"}';
    }

    /** Apply locale headers to bodyless responses such as successful OPTIONS. */
    public static function applyResponseHeaders(): void
    {
        self::setResponseHeaders(self::locale());
    }

    private static function setResponseHeaders(string $locale): void
    {
        if (self::$headersApplied || headers_sent()) {
            return;
        }

        header('Content-Language: ' . $locale);
        // Preserve Vary fields already emitted by the authentication layer.
        header('Vary: Cookie, Accept-Language', false);
        self::$headersApplied = true;
    }

    private static function negotiateAcceptLanguage(string $header): ?string
    {
        if ($header === '' || strlen($header) > self::MAX_ACCEPT_LANGUAGE_BYTES ||
            preg_match('/[^\x20-\x7E]/D', $header) === 1) {
            return null;
        }

        $parts = explode(',', $header, self::MAX_LANGUAGE_RANGES + 1);
        if (count($parts) > self::MAX_LANGUAGE_RANGES) {
            return null;
        }

        $candidates = [];
        foreach ($parts as $position => $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            $segments = array_map('trim', explode(';', $part));
            if (count($segments) > 2 || $segments[0] === '') {
                continue;
            }

            $quality = 1.0;
            if (isset($segments[1])) {
                if (preg_match('/\Aq=(0(?:\.\d{0,3})?|1(?:\.0{0,3})?)\z/iD', $segments[1], $matches) !== 1) {
                    continue;
                }
                $quality = (float)$matches[1];
            }
            if ($quality <= 0.0) {
                continue;
            }

            $candidates[] = [
                'range' => $segments[0],
                'quality' => $quality,
                'position' => $position,
            ];
        }

        usort($candidates, static function (array $left, array $right): int {
            $qualityOrder = $right['quality'] <=> $left['quality'];
            return $qualityOrder !== 0
                ? $qualityOrder
                : ($left['position'] <=> $right['position']);
        });

        foreach ($candidates as $candidate) {
            if ($candidate['range'] === '*') {
                return self::DEFAULT_LOCALE;
            }
            $locale = self::normalizeLocale($candidate['range'], true);
            if ($locale !== null) {
                return $locale;
            }
        }

        return null;
    }

    private static function normalizeLocale(string $candidate, bool $allowRegionalFallback): ?string
    {
        $candidate = trim($candidate);
        if ($candidate === '' || strlen($candidate) > 35 ||
            preg_match('/\A[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*\z/D', $candidate) !== 1) {
            return null;
        }

        $lower = strtolower($candidate);
        $exact = [
            'en' => 'en',
            'es' => 'es',
            'zh-hans' => 'zh-Hans',
            'zh-hant' => 'zh-Hant',
            'ar' => 'ar',
        ];
        if (isset($exact[$lower])) {
            return $exact[$lower];
        }
        if (!$allowRegionalFallback) {
            return null;
        }

        if (preg_match('/\Aen(?:-|\z)/D', $lower) === 1) {
            return 'en';
        }
        if (preg_match('/\Aes(?:-|\z)/D', $lower) === 1) {
            return 'es';
        }
        if (preg_match('/\Aar(?:-|\z)/D', $lower) === 1) {
            return 'ar';
        }
        if ($lower === 'zh' || preg_match('/\Azh-(?:cn|sg)(?:-|\z)/D', $lower) === 1 ||
            str_starts_with($lower, 'zh-hans-')) {
            return 'zh-Hans';
        }
        if (preg_match('/\Azh-(?:tw|hk|mo)(?:-|\z)/D', $lower) === 1 ||
            str_starts_with($lower, 'zh-hant-')) {
            return 'zh-Hant';
        }

        return null;
    }

    private static function translate(string $message, string $locale): string
    {
        if ($message === '' || $locale === self::DEFAULT_LOCALE) {
            return $message;
        }

        $catalog = self::catalog($locale);
        if ($catalog === []) {
            return $message;
        }

        // Support source-keyed catalogs without allowing a message to select
        // a file or traverse an arbitrary nested structure.
        $direct = self::directTranslation($catalog, $message);
        if ($direct !== null) {
            return $direct;
        }

        // Shared UI catalogs commonly use stable nested keys. Find the path of
        // the exact English source string, then read that same path from the
        // requested locale. No fuzzy matching or interpolation is performed.
        $path = self::englishMessagePaths()[$message] ?? null;
        if (!is_array($path)) {
            return $message;
        }
        $translated = self::valueAtPath($catalog, $path);

        return is_string($translated) && $translated !== '' ? $translated : $message;
    }

    private static function directTranslation(array $catalog, string $message): ?string
    {
        if (isset($catalog[$message]) && is_string($catalog[$message]) && $catalog[$message] !== '') {
            return $catalog[$message];
        }

        foreach (['messages', 'api', 'errors'] as $section) {
            if (isset($catalog[$section]) && is_array($catalog[$section]) &&
                isset($catalog[$section][$message]) && is_string($catalog[$section][$message]) &&
                $catalog[$section][$message] !== '') {
                return $catalog[$section][$message];
            }
        }

        return null;
    }

    /** @return array<string, array<int, string>> */
    private static function englishMessagePaths(): array
    {
        if (self::$englishMessagePaths !== null) {
            return self::$englishMessagePaths;
        }

        self::$englishMessagePaths = [];
        $catalog = self::catalog(self::DEFAULT_LOCALE);
        $hasMessageRoot = isset($catalog['messages']) && is_array($catalog['messages']);
        $messages = $hasMessageRoot
            ? $catalog['messages']
            : $catalog;
        self::indexEnglishMessages($messages, $hasMessageRoot ? ['messages'] : []);
        return self::$englishMessagePaths;
    }

    /** @param array<int, string> $path */
    private static function indexEnglishMessages(array $node, array $path): void
    {
        foreach ($node as $key => $value) {
            if (!is_string($key)) {
                continue;
            }
            $nextPath = [...$path, $key];
            if (is_string($value)) {
                $isApiMessage = false;
                foreach ($nextPath as $segment) {
                    if ($segment === 'api' || str_starts_with($segment, 'api.')) {
                        $isApiMessage = true;
                        break;
                    }
                }
                if ($value !== '' &&
                    (!isset(self::$englishMessagePaths[$value]) || $isApiMessage)) {
                    self::$englishMessagePaths[$value] = $nextPath;
                }
            } elseif (is_array($value)) {
                self::indexEnglishMessages($value, $nextPath);
            }
        }
    }

    /** @param array<int, string> $path */
    private static function valueAtPath(array $catalog, array $path)
    {
        $value = $catalog;
        foreach ($path as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return null;
            }
            $value = $value[$key];
        }
        return $value;
    }

    /** @return array<string, mixed> */
    private static function catalog(string $locale): array
    {
        if (isset(self::$catalogs[$locale])) {
            return self::$catalogs[$locale];
        }
        if (!isset(self::CATALOG_FILES[$locale])) {
            return self::$catalogs[$locale] = [];
        }

        $applicationRoot = realpath(__DIR__ . '/..');
        $catalogPath = __DIR__ . '/../locales';
        $catalogDirectory = realpath($catalogPath);
        if ($applicationRoot === false || $catalogDirectory === false ||
            dirname($catalogDirectory) !== $applicationRoot || is_link($catalogPath) ||
            !is_dir($catalogDirectory)) {
            return self::$catalogs[$locale] = [];
        }

        $path = $catalogDirectory . DIRECTORY_SEPARATOR . self::CATALOG_FILES[$locale];
        $resolved = realpath($path);
        $stat = $resolved !== false ? @lstat($resolved) : false;
        if ($resolved === false || dirname($resolved) !== $catalogDirectory || !is_array($stat) ||
            ($stat['mode'] & 0170000) !== 0100000 || is_link($path) ||
            !isset($stat['size']) || (int)$stat['size'] < 2 ||
            (int)$stat['size'] > self::MAX_CATALOG_BYTES) {
            return self::$catalogs[$locale] = [];
        }

        $json = @file_get_contents($resolved, false, null, 0, self::MAX_CATALOG_BYTES + 1);
        if (!is_string($json) || strlen($json) > self::MAX_CATALOG_BYTES) {
            return self::$catalogs[$locale] = [];
        }

        try {
            $decoded = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            error_log('Unable to load i18n catalog: ' . $locale);
            return self::$catalogs[$locale] = [];
        }

        if (!is_array($decoded) || !isset($decoded['meta'], $decoded['messages']) ||
            !is_array($decoded['meta']) || !is_array($decoded['messages']) ||
            ($decoded['meta']['locale'] ?? null) !== $locale) {
            error_log('Invalid i18n catalog structure: ' . $locale);
            return self::$catalogs[$locale] = [];
        }

        return self::$catalogs[$locale] = $decoded;
    }
}
