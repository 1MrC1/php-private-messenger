(function () {
    'use strict';

    const STORAGE_KEY = 'pm_locale';
    const COOKIE_KEY = 'pm_locale';
    const DEFAULT_LOCALE = 'en';
    const CATALOG_ROOT = 'locales/';
    const CATALOG_VERSION = '20260809.7';
    const CATALOG_TIMEOUT_MS = 15000;
    const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
    const PLURAL_CATEGORIES = ['zero', 'one', 'two', 'few', 'many', 'other'];
    const LOCALIZED_ATTRIBUTES = [
        'placeholder', 'title', 'aria-label', 'aria-description', 'alt',
        'data-mobile-label', 'data-drop-label'
    ];
    const ATTRIBUTE_KEY_MAP = Object.freeze({
        'data-i18n-placeholder': 'placeholder',
        'data-i18n-title': 'title',
        'data-i18n-aria-label': 'aria-label',
        'data-i18n-aria-description': 'aria-description',
        'data-i18n-alt': 'alt',
        'data-i18n-content': 'content',
        'data-i18n-mobile-label': 'data-mobile-label',
        'data-i18n-drop-label': 'data-drop-label'
    });
    const HARD_EXCLUDE_SELECTOR = [
        '[data-i18n-ignore]', '[translate="no"]', 'script', 'style', 'code', 'pre',
        'kbd', 'samp', 'var', '[contenteditable]'
    ].join(',');
    const USER_TEXT_SELECTOR = [
        '.message-text', '.message-caption', '.reply-content', '.reply-sender-user', '.file-name',
        '.chat-last-message', '.chat-name', '.sender-name', '.bio-content',
        '.user-profile-name', '.user-profile-username',
        '.forward-message-preview', '.search-result-message',
        '.search-result-user', '.image-message img', '.image-message-unavailable-name',
        '.image-preview-unavailable-name',
        '#userName', '#userStatus', '#chatTitle', '#profileNameLarge',
        '#profileUsernameLarge', '#typingUsers'
    ].join(',');
    const SUPPORTED = Object.freeze({
        en: Object.freeze({locale: 'en', name: 'English', nativeName: 'English', dir: 'ltr', file: 'en.json'}),
        es: Object.freeze({locale: 'es', name: 'Spanish', nativeName: 'Espa\u00f1ol', dir: 'ltr', file: 'es.json'}),
        'zh-Hans': Object.freeze({locale: 'zh-Hans', name: 'Chinese (Simplified)', nativeName: '\u7b80\u4f53\u4e2d\u6587', dir: 'ltr', file: 'zh-Hans.json'}),
        'zh-Hant': Object.freeze({locale: 'zh-Hant', name: 'Chinese (Traditional)', nativeName: '\u7e41\u9ad4\u4e2d\u6587', dir: 'ltr', file: 'zh-Hant.json'}),
        ar: Object.freeze({locale: 'ar', name: 'Arabic', nativeName: '\u0627\u0644\u0639\u0631\u0628\u064a\u0629', dir: 'rtl', file: 'ar.json'})
    });

    const catalogs = new Map();
    const catalogPromises = new Map();
    const textSources = new WeakMap();
    const textRendered = new WeakMap();
    const attributeSources = new WeakMap();
    const attributeRendered = new WeakMap();
    const exactSourceIndex = new Map();
    let sourceTemplates = [];
    let activeLocale = DEFAULT_LOCALE;
    let preference = 'auto';
    let observer = null;
    let initPromise = null;
    let changeHandlerInstalled = false;
    let activationSequence = 0;
    let latestActivationPromise = null;

    function isPlainObject(value) {
        if (!value || Object.prototype.toString.call(value) !== '[object Object]') return false;
        const prototype = Object.getPrototypeOf(value);
        return prototype === Object.prototype || prototype === null;
    }

    function own(object, key) {
        return Boolean(object) && !FORBIDDEN_KEYS.has(key) &&
            Object.prototype.hasOwnProperty.call(object, key);
    }

    function normalizeLocale(value) {
        if (typeof value !== 'string') return null;
        let candidate = value.trim().replace(/_/g, '-');
        if (!candidate || candidate.length > 35) return null;
        if (candidate.toLowerCase() === 'auto') return 'auto';
        candidate = candidate.split(/-(?:u|x)-/i, 1)[0];
        if (!/^[A-Za-z]{2,3}(?:-[A-Za-z]{4})?(?:-(?:[A-Za-z]{2}|[0-9]{3}))?$/.test(candidate)) {
            return null;
        }

        const parts = candidate.split('-');
        const language = parts[0].toLowerCase();
        if (language === 'en') return 'en';
        if (language === 'es') return 'es';
        if (language === 'ar') return 'ar';
        if (language !== 'zh') return null;

        const normalizedParts = parts.slice(1).map(function (part) { return part.toLowerCase(); });
        if (normalizedParts.includes('hant')) return 'zh-Hant';
        if (normalizedParts.includes('hans')) return 'zh-Hans';
        if (normalizedParts.some(function (part) {
            return ['tw', 'hk', 'mo'].includes(part);
        })) return 'zh-Hant';
        return 'zh-Hans';
    }

    function readStoredPreference() {
        try {
            return normalizeLocale(window.localStorage.getItem(STORAGE_KEY));
        } catch (error) {
            return null;
        }
    }

    function readCookiePreference() {
        const cookies = String(document.cookie || '').split(';');
        for (let index = 0; index < cookies.length; index += 1) {
            const pair = cookies[index].trim();
            if (!pair.startsWith(COOKIE_KEY + '=')) continue;
            try {
                return normalizeLocale(decodeURIComponent(pair.slice(COOKIE_KEY.length + 1)));
            } catch (error) {
                return null;
            }
        }
        return null;
    }

    function detectPreference() {
        return readStoredPreference() || readCookiePreference() || 'auto';
    }

    function navigatorLocales() {
        const values = [];
        if (Array.isArray(navigator.languages)) values.push.apply(values, navigator.languages);
        if (navigator.language) values.push(navigator.language);
        return values;
    }

    function detectLocale(requestedPreference) {
        const normalized = normalizeLocale(requestedPreference);
        if (normalized && normalized !== 'auto') return normalized;
        const candidates = navigatorLocales();
        for (let index = 0; index < candidates.length; index += 1) {
            const locale = normalizeLocale(candidates[index]);
            if (locale && locale !== 'auto') return locale;
        }
        return DEFAULT_LOCALE;
    }

    function persistPreference(value) {
        try {
            window.localStorage.setItem(STORAGE_KEY, value);
        } catch (error) {
            // Cookie persistence still provides a durable fallback.
        }
        const secure = window.location && window.location.protocol === 'https:' ? '; Secure' : '';
        if (value === 'auto') {
            document.cookie = COOKIE_KEY + '=; Path=/; Max-Age=0; SameSite=Lax' + secure;
            return;
        }
        document.cookie = COOKIE_KEY + '=' + encodeURIComponent(value) +
            '; Path=/; Max-Age=31536000; SameSite=Lax' + secure;
    }

    function safeCatalogUrl(locale) {
        const metadata = SUPPORTED[locale];
        if (!metadata) throw new RangeError('Unsupported locale');
        const url = new URL(CATALOG_ROOT + metadata.file, document.baseURI);
        if (url.origin !== window.location.origin) throw new Error('Cross-origin locale catalogs are not allowed');
        url.searchParams.set('v', CATALOG_VERSION);
        return url.href;
    }

    function copyMessageValue(value) {
        if (typeof value === 'string') return value;
        if (!isPlainObject(value)) throw new TypeError('Invalid catalog message');
        const result = Object.create(null);
        const keys = Object.keys(value);
        if (!keys.length || keys.some(function (key) {
            return FORBIDDEN_KEYS.has(key) || !PLURAL_CATEGORIES.includes(key) || typeof value[key] !== 'string';
        })) throw new TypeError('Invalid plural message');
        keys.forEach(function (key) { result[key] = value[key]; });
        if (!own(result, 'other')) throw new TypeError('Plural message requires an other form');
        return Object.freeze(result);
    }

    function sanitizeCatalog(data, expectedLocale) {
        if (!isPlainObject(data) || !isPlainObject(data.meta) || !isPlainObject(data.messages)) {
            throw new TypeError('Invalid locale catalog');
        }
        if (data.meta.locale !== expectedLocale || !SUPPORTED[expectedLocale] ||
            data.meta.dir !== SUPPORTED[expectedLocale].dir) {
            throw new TypeError('Locale catalog metadata mismatch');
        }
        const messages = Object.create(null);
        Object.keys(data.messages).forEach(function (key) {
            if (FORBIDDEN_KEYS.has(key) || !/^[a-z0-9][a-z0-9._-]*$/.test(key)) {
                throw new TypeError('Invalid message key');
            }
            messages[key] = copyMessageValue(data.messages[key]);
        });
        return Object.freeze({
            meta: Object.freeze({
                locale: expectedLocale,
                name: String(data.meta.name || SUPPORTED[expectedLocale].name),
                nativeName: String(data.meta.nativeName || SUPPORTED[expectedLocale].nativeName),
                dir: SUPPORTED[expectedLocale].dir
            }),
            messages: Object.freeze(messages)
        });
    }

    function placeholders(value) {
        const result = [];
        const pattern = /\{\{([A-Za-z][A-Za-z0-9_]*)\}\}/g;
        let match;
        while ((match = pattern.exec(value)) !== null) {
            if (!result.includes(match[1])) result.push(match[1]);
        }
        return result.sort();
    }

    function validateCatalogParity(catalog, english) {
        const englishKeys = Object.keys(english.messages).sort();
        const catalogKeys = Object.keys(catalog.messages).sort();
        if (englishKeys.length !== catalogKeys.length || englishKeys.some(function (key, index) {
            return key !== catalogKeys[index];
        })) throw new TypeError('Locale catalog key mismatch');

        englishKeys.forEach(function (key) {
            const source = english.messages[key];
            const target = catalog.messages[key];
            if (typeof source !== typeof target) throw new TypeError('Locale catalog value mismatch');
            if (typeof source === 'string') {
                if (placeholders(source).join('|') !== placeholders(target).join('|')) {
                    throw new TypeError('Locale catalog placeholder mismatch');
                }
                return;
            }
            const sourceForms = Object.keys(source).sort();
            const targetForms = Object.keys(target).sort();
            if (sourceForms.length !== targetForms.length || sourceForms.some(function (form, index) {
                return form !== targetForms[index];
            })) throw new TypeError('Locale catalog plural mismatch');
            sourceForms.forEach(function (form) {
                if (placeholders(source[form]).join('|') !== placeholders(target[form]).join('|')) {
                    throw new TypeError('Locale catalog plural placeholder mismatch');
                }
            });
        });
    }

    function loadCatalog(locale) {
        if (catalogs.has(locale)) return Promise.resolve(catalogs.get(locale));
        if (catalogPromises.has(locale)) return catalogPromises.get(locale);
        if (typeof window.fetch !== 'function') return Promise.reject(new Error('Catalog fetch is unavailable'));
        const controller = typeof window.AbortController === 'function' ? new AbortController() : null;
        let timeoutId = 0;
        const timeout = new Promise(function (resolve, reject) {
            timeoutId = window.setTimeout(function () {
                if (controller) controller.abort();
                const error = new Error('Locale catalog request timed out');
                error.name = 'TimeoutError';
                reject(error);
            }, CATALOG_TIMEOUT_MS);
        });
        const request = window.fetch(safeCatalogUrl(locale), {
            method: 'GET',
            credentials: 'same-origin',
            headers: {'Accept': 'application/json'},
            signal: controller ? controller.signal : undefined
        }).then(function (response) {
            if (!response.ok) throw new Error('Locale catalog request failed');
            return response.json();
        });
        const promise = Promise.race([request, timeout]).then(function (data) {
            const catalog = sanitizeCatalog(data, locale);
            if (locale !== DEFAULT_LOCALE && catalogs.has(DEFAULT_LOCALE)) {
                validateCatalogParity(catalog, catalogs.get(DEFAULT_LOCALE));
            }
            catalogs.set(locale, catalog);
            return catalog;
        }).finally(function () {
            window.clearTimeout(timeoutId);
            catalogPromises.delete(locale);
        });
        catalogPromises.set(locale, promise);
        return promise;
    }

    function safeVariables(variables) {
        const result = Object.create(null);
        if (!isPlainObject(variables)) return result;
        Object.keys(variables).forEach(function (key) {
            if (FORBIDDEN_KEYS.has(key)) return;
            const descriptor = Object.getOwnPropertyDescriptor(variables, key);
            if (!descriptor || !own(descriptor, 'value')) return;
            try {
                result[key] = String(descriptor.value === null || descriptor.value === undefined ? '' : descriptor.value);
            } catch (error) {
                result[key] = '';
            }
        });
        return result;
    }

    function interpolate(template, variables) {
        const values = safeVariables(variables);
        return String(template).replace(/\{\{([A-Za-z][A-Za-z0-9_]*)\}\}/g, function (token, name) {
            return own(values, name) ? values[name] : token;
        });
    }

    function catalogMessage(locale, key) {
        const catalog = catalogs.get(locale);
        return catalog && own(catalog.messages, key) ? catalog.messages[key] : undefined;
    }

    function messageWithFallback(key) {
        const localized = catalogMessage(activeLocale, key);
        if (localized !== undefined) return localized;
        return catalogMessage(DEFAULT_LOCALE, key);
    }

    function t(key, variables, fallback) {
        const message = messageWithFallback(String(key || ''));
        if (typeof message === 'string') return interpolate(message, variables);
        if (message && own(message, 'other')) return interpolate(message.other, variables);
        return interpolate(typeof fallback === 'string' ? fallback : String(key || ''), variables);
    }

    function countVariables(count, variables) {
        const result = Object.create(null);
        const source = safeVariables(variables);
        Object.keys(source).forEach(function (key) { result[key] = source[key]; });
        result.count = formatNumber(count);
        return result;
    }

    function tc(key, count, variables, fallback) {
        const numericCount = Number(count);
        const message = messageWithFallback(String(key || ''));
        if (typeof message === 'string') return interpolate(message, countVariables(numericCount, variables));
        if (message) {
            let category = 'other';
            try {
                category = new Intl.PluralRules(activeLocale).select(numericCount);
            } catch (error) {
                category = numericCount === 1 ? 'one' : 'other';
            }
            const template = own(message, category) ? message[category] : message.other;
            return interpolate(template, countVariables(numericCount, variables));
        }
        return interpolate(typeof fallback === 'string' ? fallback : String(key || ''),
            countVariables(numericCount, variables));
    }

    function escapeRegExp(value) {
        return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function compileSourceTemplate(source, key, plural) {
        const names = [];
        let cursor = 0;
        let pattern = '^';
        const placeholder = /\{\{([A-Za-z][A-Za-z0-9_]*)\}\}/g;
        let match;
        while ((match = placeholder.exec(source)) !== null) {
            pattern += escapeRegExp(source.slice(cursor, match.index)) + '([\\s\\S]*?)';
            names.push(match[1]);
            cursor = match.index + match[0].length;
        }
        pattern += escapeRegExp(source.slice(cursor)) + '$';
        return {key: key, plural: plural, names: names, pattern: new RegExp(pattern)};
    }

    function buildSourceIndex() {
        exactSourceIndex.clear();
        sourceTemplates = [];
        const english = catalogs.get(DEFAULT_LOCALE);
        if (!english) return;
        const seenTemplates = new Set();
        Object.keys(english.messages).forEach(function (key) {
            const message = english.messages[key];
            const values = typeof message === 'string' ? [message] : Object.keys(message).map(function (form) {
                return message[form];
            });
            values.forEach(function (value) {
                if (!value.includes('{{')) {
                    if (!exactSourceIndex.has(value)) exactSourceIndex.set(value, {key: key, plural: false});
                    return;
                }
                const signature = value + '\u0000' + key;
                if (seenTemplates.has(signature)) return;
                seenTemplates.add(signature);
                sourceTemplates.push(compileSourceTemplate(value, key, typeof message !== 'string'));
            });
        });
        sourceTemplates.sort(function (first, second) {
            return second.pattern.source.length - first.pattern.source.length;
        });
    }

    function translateSource(source, variables) {
        if (typeof source !== 'string' || !source) return source;
        const exact = exactSourceIndex.get(source);
        if (exact) return exact.plural ? tc(exact.key, Number(variables && variables.count), variables) : t(exact.key, variables, source);
        for (let index = 0; index < sourceTemplates.length; index += 1) {
            const entry = sourceTemplates[index];
            const match = entry.pattern.exec(source);
            if (!match) continue;
            const values = Object.create(null);
            entry.names.forEach(function (name, captureIndex) { values[name] = match[captureIndex + 1]; });
            if (variables && isPlainObject(variables)) {
                const supplied = safeVariables(variables);
                Object.keys(supplied).forEach(function (key) { values[key] = supplied[key]; });
            }
            return entry.plural ? tc(entry.key, Number(values.count), values, source) : t(entry.key, values, source);
        }
        return source;
    }

    function formatter(method, value, options, fallback) {
        try {
            return new Intl[method](activeLocale, isPlainObject(options) ? options : undefined).format(value);
        } catch (error) {
            return fallback;
        }
    }

    function formatNumber(value, options) {
        const number = Number(value);
        return formatter('NumberFormat', Number.isFinite(number) ? number : value, options, String(value));
    }

    function validDate(value) {
        const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
        return Number.isNaN(date.getTime()) ? null : date;
    }

    function formatDate(value, options) {
        const date = validDate(value);
        if (!date) return '';
        return formatter('DateTimeFormat', date, options || {year: 'numeric', month: 'short', day: 'numeric'}, '');
    }

    function formatTime(value, options) {
        const date = validDate(value);
        if (!date) return '';
        return formatter('DateTimeFormat', date, options || {hour: '2-digit', minute: '2-digit'}, '');
    }

    function formatRelativeTime(value, unit, options) {
        const number = Number(value);
        try {
            return new Intl.RelativeTimeFormat(activeLocale, isPlainObject(options) ? options : {numeric: 'auto'})
                .format(Number.isFinite(number) ? number : 0, unit || 'second');
        } catch (error) {
            return String(value) + ' ' + String(unit || 'second');
        }
    }

    function formatBytes(value, options) {
        const bytes = Number(value);
        if (!Number.isFinite(bytes)) return '';
        const absolute = Math.abs(bytes);
        if (absolute < 1024) return tc('files.size.bytes', bytes, null, '{{count}} bytes');
        const units = ['kb', 'mb', 'gb', 'tb'];
        const power = Math.min(Math.floor(Math.log(absolute) / Math.log(1024)), units.length);
        const amount = bytes / Math.pow(1024, power);
        const formatted = formatNumber(amount, Object.assign({maximumFractionDigits: 1}, isPlainObject(options) ? options : {}));
        return t('files.size.' + units[power - 1], {count: formatted}, formatted + ' ' + units[power - 1].toUpperCase());
    }

    function isHardExcluded(element) {
        return Boolean(element && element.closest && element.closest(HARD_EXCLUDE_SELECTOR));
    }

    function isUserText(element) {
        return Boolean(element && element.closest && element.closest(USER_TEXT_SELECTOR));
    }

    function translatedWhitespace(source) {
        const match = /^(\s*)([\s\S]*?)(\s*)$/.exec(source);
        if (!match || !match[2]) return source;
        return match[1] + translateSource(match[2]) + match[3];
    }

    function localizeTextNode(node) {
        const parent = node && node.parentElement;
        if (!parent || isHardExcluded(parent) || isUserText(parent)) return;
        const current = node.nodeValue;
        const last = textRendered.get(node);
        let source = textSources.get(node);
        if (source === undefined || (last !== undefined && current !== last && current !== source)) {
            source = current;
            textSources.set(node, source);
        }
        const translated = translatedWhitespace(source);
        textRendered.set(node, translated);
        if (current !== translated) node.nodeValue = translated;
    }

    function attributeState(map, element) {
        let state = map.get(element);
        if (!state) {
            state = new Map();
            map.set(element, state);
        }
        return state;
    }

    function localizeSourceAttribute(element, name) {
        if (!element.hasAttribute(name) || isHardExcluded(element) || isUserText(element)) return;
        if (name === 'content' && element.tagName !== 'META') return;
        const current = element.getAttribute(name);
        const sources = attributeState(attributeSources, element);
        const rendered = attributeState(attributeRendered, element);
        const last = rendered.get(name);
        let source = sources.get(name);
        if (source === undefined || (last !== undefined && current !== last && current !== source)) {
            source = current;
            sources.set(name, source);
        }
        const translated = translateSource(source);
        rendered.set(name, translated);
        if (current !== translated) element.setAttribute(name, translated);
    }

    function localizeSemanticElement(element) {
        const key = element.getAttribute('data-i18n');
        if (key && !isHardExcluded(element) && !isUserText(element)) {
            const translated = t(key, null, element.textContent);
            if (element.textContent !== translated) element.textContent = translated;
        }
        Object.keys(ATTRIBUTE_KEY_MAP).forEach(function (keyAttribute) {
            if (!element.hasAttribute(keyAttribute)) return;
            const target = ATTRIBUTE_KEY_MAP[keyAttribute];
            const fallback = element.getAttribute(target) || '';
            const translated = t(element.getAttribute(keyAttribute), null, fallback);
            if (element.getAttribute(target) !== translated) element.setAttribute(target, translated);
        });
    }

    function localizeElement(element) {
        if (!element || element.nodeType !== 1) return;
        localizeSemanticElement(element);
        LOCALIZED_ATTRIBUTES.forEach(function (name) { localizeSourceAttribute(element, name); });
        if (element.tagName === 'META' && (element.name === 'description' || element.getAttribute('property'))) {
            localizeSourceAttribute(element, 'content');
        }
    }

    function syncLocaleControls(root) {
        const scope = root && root.querySelectorAll ? root : document;
        const controls = [];
        if (scope.nodeType === 1 && scope.matches('select[data-pm-action="change-locale"]')) controls.push(scope);
        scope.querySelectorAll('select[data-pm-action="change-locale"]').forEach(function (select) { controls.push(select); });
        controls.forEach(function (select) {
            if (Array.from(select.options).some(function (option) { return option.value === preference; })) {
                select.value = preference;
            }
        });
    }

    function localize(root) {
        const scope = root || document;
        if (scope.nodeType === 1) localizeElement(scope);
        if (scope.querySelectorAll) scope.querySelectorAll('*').forEach(localizeElement);
        const walkerRoot = scope.nodeType === 9 ? scope.documentElement : scope;
        if (walkerRoot && document.createTreeWalker) {
            const showText = window.NodeFilter ? window.NodeFilter.SHOW_TEXT : 4;
            const walker = document.createTreeWalker(walkerRoot, showText);
            let node = walker.nextNode();
            while (node) {
                localizeTextNode(node);
                node = walker.nextNode();
            }
        }
        syncLocaleControls(scope);
        return scope;
    }

    function startObserver() {
        if (observer || typeof window.MutationObserver !== 'function' || !document.documentElement) return observer;
        observer = new MutationObserver(function (mutations) {
            mutations.forEach(function (mutation) {
                if (mutation.type === 'characterData') {
                    localizeTextNode(mutation.target);
                    return;
                }
                if (mutation.type === 'attributes') {
                    localizeElement(mutation.target);
                    syncLocaleControls(mutation.target);
                    return;
                }
                mutation.addedNodes.forEach(function (node) {
                    if (node.nodeType === 3) localizeTextNode(node);
                    if (node.nodeType === 1) localize(node);
                });
            });
        });
        observer.observe(document.documentElement, {
            subtree: true,
            childList: true,
            characterData: true,
            attributes: true,
            attributeFilter: LOCALIZED_ATTRIBUTES.concat(Object.keys(ATTRIBUTE_KEY_MAP), ['data-i18n', 'content'])
        });
        return observer;
    }

    function stopObserver() {
        if (observer) observer.disconnect();
        observer = null;
    }

    function applyDocumentLocale(locale) {
        const metadata = SUPPORTED[locale] || SUPPORTED[DEFAULT_LOCALE];
        document.documentElement.setAttribute('lang', metadata.locale);
        document.documentElement.setAttribute('dir', metadata.dir);
        document.documentElement.setAttribute('data-pm-locale', metadata.locale);
    }

    function dispatchLocaleChange(previousLocale, previousPreference) {
        const detail = Object.freeze({
            locale: activeLocale,
            previousLocale: previousLocale,
            preference: preference,
            previousPreference: previousPreference,
            dir: SUPPORTED[activeLocale].dir
        });
        ['localechange', 'pm:localechange'].forEach(function (name) {
            try {
                window.dispatchEvent(new CustomEvent(name, {detail: detail}));
            } catch (error) {
                const event = document.createEvent('CustomEvent');
                event.initCustomEvent(name, false, false, detail);
                window.dispatchEvent(event);
            }
        });
    }

    function activateLocale(nextPreference, persist, announce, allowFallback) {
        const normalized = normalizeLocale(nextPreference);
        if (!normalized) return Promise.reject(new RangeError('Unsupported locale preference'));
        const requestedLocale = detectLocale(normalized);
        const sequence = ++activationSequence;
        const previousLocale = activeLocale;
        const previousPreference = preference;

        const activation = loadCatalog(DEFAULT_LOCALE).then(function (english) {
            buildSourceIndex();
            if (requestedLocale === DEFAULT_LOCALE) return english;
            return loadCatalog(requestedLocale).catch(function (error) {
                if (allowFallback) return english;
                throw error;
            });
        }).then(function (catalog) {
            if (sequence !== activationSequence) return activeLocale;
            preference = normalized;
            if (persist) persistPreference(preference);
            activeLocale = catalog.meta.locale;
            applyDocumentLocale(activeLocale);
            localize(document);
            syncLocaleControls(document);
            if (announce && (previousLocale !== activeLocale || previousPreference !== preference)) {
                dispatchLocaleChange(previousLocale, previousPreference);
            }
            return activeLocale;
        }).catch(function (error) {
            // A newer selection owns the UI now; an obsolete request must not
            // reset its controls or announce a failure.
            if (sequence !== activationSequence) return activeLocale;
            throw error;
        });
        latestActivationPromise = activation;
        return activation;
    }

    function settleLatestActivation(candidate) {
        return Promise.resolve(candidate).then(function (locale) {
            return candidate === latestActivationPromise
                ? locale
                : settleLatestActivation(latestActivationPromise);
        }, function (error) {
            if (candidate !== latestActivationPromise) {
                return settleLatestActivation(latestActivationPromise);
            }
            throw error;
        });
    }

    function setLocale(locale, options) {
        const settings = isPlainObject(options) ? options : {};
        return activateLocale(locale, settings.persist !== false, settings.announce !== false, false);
    }

    function installLocaleChangeHandler() {
        if (changeHandlerInstalled) return;
        changeHandlerInstalled = true;
        document.addEventListener('change', function (event) {
            const select = event.target && event.target.closest &&
                event.target.closest('select[data-pm-action="change-locale"]');
            if (!select) return;
            if (typeof select.setCustomValidity === 'function') select.setCustomValidity('');
            select.removeAttribute('aria-invalid');
            setLocale(select.value).catch(function () {
                syncLocaleControls(document);
                const message = t(
                    'settings.language.failed',
                    null,
                    'Language could not be changed'
                );
                if (typeof window.showToast === 'function') {
                    window.showToast(message, 'error');
                    return;
                }
                if (typeof select.setCustomValidity === 'function' &&
                    typeof select.reportValidity === 'function') {
                    select.setAttribute('aria-invalid', 'true');
                    select.setCustomValidity(message);
                    select.reportValidity();
                    window.setTimeout(function () {
                        if (!select.isConnected) return;
                        select.setCustomValidity('');
                        select.removeAttribute('aria-invalid');
                    }, 5000);
                }
            });
        });
        window.addEventListener('storage', function (event) {
            if (event.key !== STORAGE_KEY) return;
            const nextPreference = event.newValue === null ? 'auto' : normalizeLocale(event.newValue);
            if (!nextPreference || nextPreference === preference) return;
            activateLocale(nextPreference, false, true, false).catch(function () {
                syncLocaleControls(document);
            });
        });
    }

    function init() {
        if (initPromise) return initPromise;
        // Register the visible language control before any network work so a
        // first selection is never lost on a slow or offline connection.
        installLocaleChangeHandler();
        const detectedPreference = detectPreference();
        const initialActivation = activateLocale(detectedPreference, false, false, true);
        initPromise = settleLatestActivation(initialActivation).catch(function () {
            activeLocale = DEFAULT_LOCALE;
            applyDocumentLocale(activeLocale);
            return activeLocale;
        }).then(function (locale) {
            localize(document);
            startObserver();
            syncLocaleControls(document);
            return locale;
        });
        return initPromise;
    }

    function getLanguages() {
        return Object.keys(SUPPORTED).map(function (locale) {
            return Object.freeze(Object.assign({}, SUPPORTED[locale]));
        });
    }

    const api = {
        init: init,
        t: t,
        tc: tc,
        translate: translateSource,
        translateSource: translateSource,
        number: formatNumber,
        date: formatDate,
        time: formatTime,
        relative: formatRelativeTime,
        bytes: formatBytes,
        formatNumber: formatNumber,
        formatDate: formatDate,
        formatTime: formatTime,
        formatRelativeTime: formatRelativeTime,
        formatBytes: formatBytes,
        normalizeLocale: normalizeLocale,
        detectLocale: detectLocale,
        setLocale: setLocale,
        getLocale: function () { return activeLocale; },
        getPreference: function () { return preference; },
        getLanguages: getLanguages,
        localize: localize,
        startObserver: startObserver,
        stopObserver: stopObserver
    };
    Object.defineProperty(api, 'ready', {enumerable: true, get: init});
    Object.freeze(api);

    window.PmI18n = api;
    window.pmT = t;
    init();
}());
