'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class FakeEventTarget {
    constructor() {
        this.listeners = Object.create(null);
    }

    addEventListener(type, listener) {
        if (!this.listeners[type]) this.listeners[type] = [];
        this.listeners[type].push(listener);
    }

    removeEventListener(type, listener) {
        this.listeners[type] = (this.listeners[type] || []).filter((candidate) => candidate !== listener);
    }

    dispatchEvent(event) {
        event.target = event.target || this;
        (this.listeners[event.type] || []).slice().forEach((listener) => listener.call(this, event));
        return !event.defaultPrevented;
    }
}

class FakeText {
    constructor(value) {
        this.nodeType = 3;
        this.nodeValue = String(value);
        this.parentNode = null;
        this.parentElement = null;
    }

    get textContent() { return this.nodeValue; }
    set textContent(value) { this.nodeValue = String(value); }
}

class FakeElement extends FakeEventTarget {
    constructor(tagName = 'div') {
        super();
        this.nodeType = 1;
        this.tagName = String(tagName).toUpperCase();
        this.attributes = Object.create(null);
        this.childNodes = [];
        this.parentNode = null;
        this.parentElement = null;
        this.dataset = Object.create(null);
        this.className = '';
        this.id = '';
        this.value = '';
        this.options = [];
        this.scrollTop = 0;
    }

    appendChild(child) {
        this.childNodes.push(child);
        child.parentNode = this;
        child.parentElement = this;
        return child;
    }

    append(...children) {
        children.forEach((child) => this.appendChild(
            typeof child === 'string' ? new FakeText(child) : child
        ));
    }

    replaceChildren(...children) {
        this.childNodes = [];
        this.append(...children);
    }

    get textContent() {
        return this.childNodes.map((child) => child.textContent).join('');
    }

    set textContent(value) {
        this.replaceChildren(new FakeText(value));
    }

    setAttribute(name, value) {
        const normalized = String(name);
        this.attributes[normalized] = String(value);
        if (normalized === 'lang' || normalized === 'dir') this[normalized] = String(value);
        if (normalized.startsWith('data-')) {
            const key = normalized.slice(5).replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
            this.dataset[key] = String(value);
        }
    }

    getAttribute(name) {
        return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
    }

    hasAttribute(name) {
        return Object.prototype.hasOwnProperty.call(this.attributes, name);
    }

    removeAttribute(name) {
        delete this.attributes[name];
    }

    matches(selector) {
        return String(selector).split(',').some((part) => this.matchesOne(part.trim()));
    }

    matchesOne(selector) {
        if (selector === '*') return true;
        if (/^\.[a-z0-9_-]+$/i.test(selector)) {
            return String(this.className).split(/\s+/).includes(selector.slice(1));
        }
        if (/^#[a-z0-9_-]+$/i.test(selector)) return this.id === selector.slice(1);
        if (/^[a-z][a-z0-9-]*$/i.test(selector)) return this.tagName === selector.toUpperCase();
        const attribute = selector.match(/^\[([a-z0-9_-]+)(?:=["']?([^"'\]]+)["']?)?\]$/i);
        if (attribute) {
            if (!this.hasAttribute(attribute[1])) return false;
            return attribute[2] === undefined || this.getAttribute(attribute[1]) === attribute[2];
        }
        const tagAttribute = selector.match(/^([a-z0-9-]+)\[([a-z0-9_-]+)(?:=["']?([^"'\]]+)["']?)?\]$/i);
        if (tagAttribute) {
            return this.tagName === tagAttribute[1].toUpperCase() &&
                this.hasAttribute(tagAttribute[2]) &&
                (tagAttribute[3] === undefined || this.getAttribute(tagAttribute[2]) === tagAttribute[3]);
        }
        return false;
    }

    closest(selector) {
        let current = this;
        while (current) {
            if (current.matches && current.matches(selector)) return current;
            current = current.parentElement;
        }
        return null;
    }

    querySelectorAll(selector) {
        const results = [];
        const visit = (node) => {
            if (!(node instanceof FakeElement)) return;
            if (node !== this && node.matches(selector)) results.push(node);
            node.childNodes.forEach(visit);
        };
        this.childNodes.forEach(visit);
        return results;
    }

    querySelector(selector) {
        return this.querySelectorAll(selector)[0] || null;
    }
}

class FakeDocument extends FakeEventTarget {
    constructor() {
        super();
        this.nodeType = 9;
        this.readyState = 'complete';
        this.baseURI = 'https://messenger.example/';
        this.documentElement = new FakeElement('html');
        this.head = new FakeElement('head');
        this.body = new FakeElement('body');
        this.documentElement.append(this.head, this.body);
        this.activeElement = null;
        this.title = 'Messenger - Instant Messaging';
        const description = new FakeElement('meta');
        description.setAttribute('name', 'description');
        description.setAttribute('content', 'Messenger — calm, fast messaging for the people who matter.');
        this.head.appendChild(description);
    }

    createElement(tagName) { return new FakeElement(tagName); }
    createTextNode(value) { return new FakeText(value); }
    querySelectorAll(selector) { return this.documentElement.querySelectorAll(selector); }
    querySelector(selector) {
        if (selector === 'meta[name="description"]' || selector === "meta[name='description']") {
            return this.head.querySelector('meta[name="description"]');
        }
        return this.documentElement.querySelector(selector);
    }

    createTreeWalker(root, _whatToShow, filter) {
        const nodes = [];
        const visit = (node) => {
            if (node instanceof FakeText) {
                const result = filter && typeof filter.acceptNode === 'function'
                    ? filter.acceptNode(node)
                    : 1;
                if (result === 1) nodes.push(node);
                return;
            }
            (node.childNodes || []).forEach(visit);
        };
        visit(root);
        let index = 0;
        return {
            nextNode() { return nodes[index++] || null; }
        };
    }
}

class FakeCustomEvent {
    constructor(type, options = {}) {
        this.type = type;
        this.detail = options.detail;
        this.defaultPrevented = false;
        this.target = null;
    }
    preventDefault() { this.defaultPrevented = true; }
}

class FakeMutationObserver {
    constructor(callback) { this.callback = callback; }
    observe() {}
    disconnect() {}
}

function makeStorage(initial = {}, throws = false) {
    const values = new Map(Object.entries(initial));
    return {
        values,
        getItem(key) {
            if (throws) throw new Error('storage unavailable');
            return values.has(key) ? values.get(key) : null;
        },
        setItem(key, value) {
            if (throws) throw new Error('storage unavailable');
            values.set(String(key), String(value));
        },
        removeItem(key) {
            if (throws) throw new Error('storage unavailable');
            values.delete(String(key));
        }
    };
}

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

async function flushPromises() {
    await Promise.resolve();
    await new Promise((resolve) => setImmediate(resolve));
    await Promise.resolve();
}

function addRuntimeMessages(catalog) {
    const locale = catalog.meta.locale;
    const greetings = {
        en: 'Hello, {{name}}. {{name}} has {{count}}.',
        es: 'Hola, {{name}}. {{name}} tiene {{count}}.',
        'zh-Hans': '你好，{{name}}。{{name}}有 {{count}}。',
        'zh-Hant': '你好，{{name}}。{{name}}有 {{count}}。',
        ar: 'مرحبًا، {{name}}. لدى {{name}} {{count}}.'
    };
    const categoryNames = {
        en: ['zero', 'one', 'two', 'few', 'many', 'other'],
        es: ['cero', 'uno', 'dos', 'pocos', 'muchos', 'otros'],
        'zh-Hans': ['零', '一', '二', '少', '多', '其他'],
        'zh-Hant': ['零', '一', '二', '少', '多', '其他'],
        ar: ['صفر', 'واحد', 'اثنان', 'قليل', 'كثير', 'آخر']
    }[locale];
    catalog.messages['test.runtime.interpolation'] = greetings[locale];
    catalog.messages['test.runtime.fallback'] = locale === 'en' ? 'English fallback' : `${locale} fallback`;
    catalog.messages['test.runtime.plural'] = {
        zero: `${categoryNames[0]} {{count}}`,
        one: `${categoryNames[1]} {{count}}`,
        two: `${categoryNames[2]} {{count}}`,
        few: `${categoryNames[3]} {{count}}`,
        many: `${categoryNames[4]} {{count}}`,
        other: `${categoryNames[5]} {{count}}`
    };
    return catalog;
}

async function boot(options = {}) {
    const root = path.resolve(__dirname, '..');
    const catalogs = Object.create(null);
    const fixtureMeta = {
        en: {locale: 'en', name: 'English', nativeName: 'English', dir: 'ltr'},
        es: {locale: 'es', name: 'Spanish', nativeName: 'Español', dir: 'ltr'},
        'zh-Hans': {locale: 'zh-Hans', name: 'Chinese (Simplified)', nativeName: '简体中文', dir: 'ltr'},
        'zh-Hant': {locale: 'zh-Hant', name: 'Chinese (Traditional)', nativeName: '繁體中文', dir: 'ltr'},
        ar: {locale: 'ar', name: 'Arabic', nativeName: 'العربية', dir: 'rtl'}
    };
    const englishFixture = JSON.parse(fs.readFileSync(path.join(root, 'locales', 'en.json'), 'utf8'));
    ['en', 'es', 'zh-Hans', 'zh-Hant', 'ar'].forEach((locale) => {
        const catalogPath = path.join(root, 'locales', `${locale}.json`);
        const catalog = fs.existsSync(catalogPath)
            ? JSON.parse(fs.readFileSync(catalogPath, 'utf8'))
            : clone(englishFixture);
        catalog.meta = clone(fixtureMeta[locale]);
        catalogs[locale] = addRuntimeMessages(catalog);
    });
    if (typeof options.catalogTransform === 'function') options.catalogTransform(catalogs);

    const document = new FakeDocument();
    if (typeof options.setupDocument === 'function') options.setupDocument(document);
    const windowEvents = new FakeEventTarget();
    const fetches = [];
    const context = {
        AbortController,
        CustomEvent: FakeCustomEvent,
        DOMException,
        Element: FakeElement,
        MutationObserver: FakeMutationObserver,
        Node: {ELEMENT_NODE: 1, TEXT_NODE: 3, DOCUMENT_NODE: 9},
        NodeFilter: {FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3, SHOW_TEXT: 4},
        URL,
        clearTimeout,
        console: {debug() {}, error() {}, info() {}, log() {}, warn() {}},
        document,
        fetch: async (resource) => {
            const url = new URL(String(resource), document.baseURI);
            fetches.push(url.pathname);
            const match = url.pathname.match(/^\/locales\/(en|es|zh-Hans|zh-Hant|ar)\.json$/);
            if (!match || !catalogs[match[1]]) {
                return {ok: false, status: 404, json: async () => ({})};
            }
            return {
                ok: true,
                status: 200,
                json: async () => {
                    if (typeof options.catalogDelay === 'function') {
                        await options.catalogDelay(match[1], fetches.slice());
                    }
                    context.__catalogJson = JSON.stringify(catalogs[match[1]]);
                    return vm.runInContext('JSON.parse(__catalogJson)', context);
                }
            };
        },
        localStorage: options.storage || makeStorage(),
        location: {origin: 'https://messenger.example', href: 'https://messenger.example/'},
        navigator: {
            language: (options.languages || ['es-MX'])[0],
            languages: options.languages || ['es-MX', 'en-US']
        },
        queueMicrotask,
        setTimeout
    };
    context.window = context;
    context.self = context;
    if (typeof options.showToast === 'function') context.showToast = options.showToast;
    context.addEventListener = windowEvents.addEventListener.bind(windowEvents);
    context.removeEventListener = windowEvents.removeEventListener.bind(windowEvents);
    context.dispatchEvent = windowEvents.dispatchEvent.bind(windowEvents);

    vm.createContext(context);
    const source = fs.readFileSync(path.join(root, 'assets/js/i18n.js'), 'utf8');
    vm.runInContext(source, context, {filename: 'i18n.js'});
    assert.ok(context.PmI18n, 'the engine exports window.PmI18n');
    assert.ok(context.PmI18n.ready && typeof context.PmI18n.ready.then === 'function', 'ready is a Promise');
    if (typeof options.beforeReady === 'function') {
        await options.beforeReady({api: context.PmI18n, context, document, fetches});
    }
    await context.PmI18n.ready;
    return {api: context.PmI18n, catalogs, context, document, fetches, storage: context.localStorage};
}

function formatter(api, longName, shortName) {
    assert.equal(typeof api[longName], 'function', `${longName} is part of the public API`);
    assert.equal(typeof api[shortName], 'function', `${shortName} formatter alias is part of the public API`);
    return api[longName].bind(api);
}

function realmValue(context, value) {
    context.__runtimeJson = JSON.stringify(value);
    return vm.runInContext('JSON.parse(__runtimeJson)', context);
}

async function main() {
    let releaseEnglishCatalog;
    const delayedEnglishCatalog = new Promise((resolve) => { releaseEnglishCatalog = resolve; });
    let earlyLocaleControl;
    const earlySelection = await boot({
        languages: ['en-US'],
        catalogTransform(catalogs) {
            catalogs.ar.messages = clone(catalogs.en.messages);
        },
        setupDocument(document) {
            earlyLocaleControl = new FakeElement('select');
            earlyLocaleControl.setAttribute('data-pm-action', 'change-locale');
            earlyLocaleControl.options = ['auto', 'en', 'ar'].map((value) => ({value}));
            earlyLocaleControl.value = 'ar';
            document.body.appendChild(earlyLocaleControl);
        },
        catalogDelay(locale) {
            return locale === 'en' ? delayedEnglishCatalog : undefined;
        },
        beforeReady({document}) {
            document.dispatchEvent({type: 'change', target: earlyLocaleControl});
            releaseEnglishCatalog();
        }
    });
    assert.equal(
        earlySelection.api.getLocale(),
        'ar',
        'a language selection made while the initial catalog is pending is honored'
    );
    assert.equal(earlySelection.api.getPreference(), 'ar');
    assert.equal(earlySelection.document.documentElement.dir, 'rtl');

    const racingSwitches = await boot({
        languages: ['en-US'],
        catalogTransform(catalogs) {
            catalogs['zh-Hant'].messages = clone(catalogs.en.messages);
            delete catalogs.ar.messages['test.runtime.fallback'];
        }
    });
    const staleFailure = racingSwitches.api.setLocale(
        'ar',
        realmValue(racingSwitches.context, {persist: false})
    );
    const winningSwitch = racingSwitches.api.setLocale(
        'zh-Hant',
        realmValue(racingSwitches.context, {persist: false})
    );
    await assert.doesNotReject(staleFailure, 'an obsolete failed request is suppressed');
    await assert.doesNotReject(winningSwitch);
    assert.equal(
        racingSwitches.api.getLocale(),
        'zh-Hant',
        'an obsolete failed request cannot reset a newer successful selection'
    );

    let failedLocaleControl;
    const localeFailureToasts = [];
    const currentFailure = await boot({
        languages: ['en-US'],
        setupDocument(document) {
            failedLocaleControl = new FakeElement('select');
            failedLocaleControl.setAttribute('data-pm-action', 'change-locale');
            failedLocaleControl.options = ['auto', 'en', 'ar'].map((value) => ({value}));
            document.body.appendChild(failedLocaleControl);
        },
        catalogTransform(catalogs) {
            delete catalogs.ar.messages['test.runtime.fallback'];
        },
        showToast(message, type) {
            localeFailureToasts.push({message, type});
        }
    });
    failedLocaleControl.value = 'ar';
    currentFailure.document.dispatchEvent({type: 'change', target: failedLocaleControl});
    await flushPromises();
    await flushPromises();
    assert.equal(currentFailure.api.getLocale(), 'en');
    assert.equal(currentFailure.api.getPreference(), 'auto');
    assert.equal(failedLocaleControl.value, 'auto', 'a failed current selection resets the control');
    assert.deepEqual(
        localeFailureToasts,
        [{message: currentFailure.api.t('settings.language.failed'), type: 'error'}],
        'a failed current selection reports a localized visible error'
    );

    const storedPreference = await boot({
        storage: makeStorage({pm_locale: 'zh-Hant'}),
        languages: ['en-US']
    });
    assert.equal(storedPreference.api.getPreference(), 'zh-Hant');
    assert.equal(storedPreference.api.getLocale(), 'zh-Hant', 'a valid saved preference wins over navigator locale');
    assert.equal(storedPreference.document.documentElement.lang, 'zh-Hant');

    const invalidPreference = await boot({
        storage: makeStorage({pm_locale: '../ar'}),
        languages: ['zh-CN', 'en-US']
    });
    assert.equal(invalidPreference.api.getPreference(), 'auto');
    assert.equal(invalidPreference.api.getLocale(), 'zh-Hans', 'invalid saved data falls back to safe locale detection');

    const storageSync = await boot({languages: ['en-US']});
    storageSync.storage.values.set('pm_locale', 'ar');
    storageSync.context.dispatchEvent({type: 'storage', key: 'pm_locale', newValue: 'ar'});
    await flushPromises();
    assert.equal(storageSync.api.getPreference(), 'ar');
    assert.equal(storageSync.api.getLocale(), 'ar', 'a valid cross-tab preference change updates the live locale');
    assert.equal(storageSync.document.documentElement.dir, 'rtl');
    storageSync.context.dispatchEvent({type: 'storage', key: 'pm_locale', newValue: '../en'});
    await flushPromises();
    assert.equal(storageSync.api.getLocale(), 'ar', 'an invalid cross-tab locale is ignored');

    const automaticPreference = await boot({languages: ['es-MX', 'en-US']});
    await automaticPreference.api.setLocale('ar');
    await automaticPreference.api.setLocale('auto');
    assert.equal(automaticPreference.api.getPreference(), 'auto');
    assert.equal(automaticPreference.api.getLocale(), 'es', 'automatic preference re-runs safe navigator detection');
    assert.match(
        automaticPreference.document.cookie,
        /^pm_locale=; Path=\/; Max-Age=0;/,
        'automatic preference removes the explicit server locale cookie'
    );

    const initial = await boot();
    const {api, document} = initial;
    [
        'init', 't', 'tc', 'translate', 'translateSource', 'setLocale', 'getLocale',
        'getPreference', 'getLanguages', 'normalizeLocale', 'detectLocale',
        'localize', 'startObserver', 'stopObserver'
    ].forEach((name) => assert.equal(typeof api[name], 'function', `${name} is part of the public API`));
    assert.equal(initial.context.pmT, api.t, 'the lightweight global translation alias uses the safe engine');
    assert.deepEqual(
        Array.from(api.getLanguages(), (language) => language.locale),
        ['en', 'es', 'zh-Hans', 'zh-Hant', 'ar'],
        'the public language list exposes only the same-origin catalog allowlist'
    );

    assert.equal(api.normalizeLocale('AR-eg'), 'ar');
    assert.equal(api.normalizeLocale('es-MX'), 'es');
    assert.equal(api.normalizeLocale('zh-cn'), 'zh-Hans');
    assert.equal(api.normalizeLocale('zh-TW'), 'zh-Hant');
    assert.equal(api.normalizeLocale('zh-Hans-TW'), 'zh-Hans', 'an explicit Simplified script beats region');
    assert.equal(api.normalizeLocale('zh-Hant-CN'), 'zh-Hant', 'an explicit Traditional script beats region');
    assert.equal(api.normalizeLocale('../ar'), null);
    assert.equal(api.normalizeLocale('__proto__'), null);
    assert.equal(api.normalizeLocale('a'.repeat(200)), null);
    assert.equal(api.getLocale(), 'es', 'navigator regional locale resolves to a supported base locale');
    assert.equal(document.documentElement.lang, 'es');
    assert.equal(document.documentElement.dir, 'ltr');

    const malicious = '$&<img src=x onerror=alert(1)>';
    const maliciousVariables = realmValue(initial.context, {name: malicious, count: 0});
    assert.equal(
        api.t('test.runtime.interpolation', maliciousVariables),
        `Hola, ${malicious}. ${malicious} tiene 0.`,
        'interpolation replaces every token literally without replacement-pattern or HTML execution semantics'
    );
    const inherited = vm.runInContext("Object.assign(Object.create({name: 'polluted'}), {count: 2})", initial.context);
    assert.ok(
        api.t('test.runtime.interpolation', inherited).includes('{{name}}'),
        'interpolation never reads inherited parameter values'
    );
    assert.equal(api.t('constructor.prototype', undefined, 'Safe fallback'), 'Safe fallback');
    assert.equal(api.t('missing.key', undefined, 'Safe fallback'), 'Safe fallback');
    assert.equal(api.t('missing.key'), 'missing.key', 'unknown keys have a deterministic non-HTML fallback');

    const fallback = await boot({
        languages: ['ar'],
        catalogTransform(catalogs) {
            delete catalogs.ar.messages['test.runtime.fallback'];
        }
    });
    assert.equal(
        fallback.api.t('test.runtime.fallback'),
        'English fallback',
        'an initial selected catalog that fails parity falls back safely to the complete English catalog'
    );
    assert.equal(fallback.api.getLocale(), 'en');
    await assert.rejects(fallback.api.setLocale('ar', realmValue(fallback.context, {persist: false})));
    assert.equal(fallback.api.getLocale(), 'en', 'a failed explicit switch preserves the active locale');

    await api.setLocale('en', realmValue(initial.context, {persist: false}));
    assert.equal(api.tc('test.runtime.plural', 1), 'one 1');
    assert.equal(api.tc('test.runtime.plural', 2), 'other 2');
    await api.setLocale('ar', realmValue(initial.context, {persist: false}));
    const arabicCases = new Map([[0, 'صفر'], [1, 'واحد'], [2, 'اثنان'], [3, 'قليل'], [11, 'كثير'], [100, 'آخر']]);
    for (const [count, category] of arabicCases) {
        const localizedCount = new Intl.NumberFormat('ar').format(count);
        assert.equal(api.tc('test.runtime.plural', count), `${category} ${localizedCount}`, `Arabic plural category for ${count}`);
    }

    const formatNumber = formatter(api, 'formatNumber', 'number');
    const formatDate = formatter(api, 'formatDate', 'date');
    const formatTime = formatter(api, 'formatTime', 'time');
    const formatRelativeTime = formatter(api, 'formatRelativeTime', 'relative');
    const formatBytes = formatter(api, 'formatBytes', 'bytes');
    const numberOptions = {maximumFractionDigits: 2};
    const realmNumberOptions = realmValue(initial.context, numberOptions);
    assert.equal(
        formatNumber(1234567.89, realmNumberOptions),
        new Intl.NumberFormat('ar', numberOptions).format(1234567.89),
        'number formatting follows the active locale rather than the browser startup locale'
    );
    const instant = new Date('2026-08-09T14:05:06.000Z');
    const dateOptions = {year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC'};
    const timeOptions = {hour: '2-digit', minute: '2-digit', timeZone: 'UTC'};
    assert.equal(
        formatDate(instant.toISOString(), realmValue(initial.context, dateOptions)),
        new Intl.DateTimeFormat('ar', dateOptions).format(instant)
    );
    assert.equal(
        formatTime(instant.toISOString(), realmValue(initial.context, timeOptions)),
        new Intl.DateTimeFormat('ar', timeOptions).format(instant)
    );
    assert.equal(formatRelativeTime(-1, 'day'), new Intl.RelativeTimeFormat('ar', {numeric: 'auto'}).format(-1, 'day'));
    const externalUnit = api.t('files.size.kb', realmValue(initial.context, {count: 'X'}));
    assert.ok(
        externalUnit.includes('X') && !externalUnit.includes('{{count}}'),
        'format placeholders accept own scalar values'
    );
    const sameRealmUnit = vm.runInContext("PmI18n.t('files.size.kb', {count: 'Y'})", initial.context);
    assert.ok(
        sameRealmUnit.includes('Y') && !sameRealmUnit.includes('{{count}}'),
        'same-realm interpolation accepts plain parameter objects'
    );
    const formattedBytes = formatBytes(1536);
    assert.equal(typeof formattedBytes, 'string');
    assert.ok(
        formattedBytes.includes(new Intl.NumberFormat('ar', {maximumFractionDigits: 1}).format(1.5)),
        `byte formatting localizes its numeric component (received ${JSON.stringify(formattedBytes)})`
    );
    assert.doesNotThrow(() => formatDate('not-a-date'));
    assert.doesNotThrow(() => formatNumber(Number.NaN));

    const events = [];
    const applicationEvents = [];
    await api.setLocale('en', realmValue(initial.context, {persist: false, announce: false}));
    initial.context.addEventListener('localechange', (event) => events.push(event.detail));
    initial.context.addEventListener('pm:localechange', (event) => applicationEvents.push(event.detail));
    const input = new FakeElement('textarea');
    input.value = 'untranslated user draft';
    input.scrollTop = 42;
    document.activeElement = input;
    await api.setLocale('ar');
    assert.equal(document.documentElement.lang, 'ar');
    assert.equal(document.documentElement.dir, 'rtl');
    assert.equal(api.getPreference(), 'ar');
    assert.match(document.cookie, /(?:^|;\s*)pm_locale=ar(?:;|$)/);
    assert.equal(input.value, 'untranslated user draft');
    assert.equal(input.scrollTop, 42);
    assert.equal(document.activeElement, input, 'switching locale preserves focus and transient user input');
    assert.equal(events.length, 1, 'one localechange event is emitted after a real locale change');
    assert.equal(applicationEvents.length, 1, 'one application locale event is emitted after a real locale change');
    await api.setLocale('en');
    assert.equal(document.documentElement.lang, 'en');
    assert.equal(document.documentElement.dir, 'ltr', 'switching back removes RTL state');

    await api.setLocale('es', realmValue(initial.context, {persist: false}));
    const rawReplySender = 'You';
    assert.equal(
        api.t('chat.replying_to', realmValue(initial.context, {name: rawReplySender})),
        'Respondiendo a You',
        'a genuine sender name that matches English chrome remains raw inside a localized reply label'
    );
    assert.equal(
        api.t('chat.reply_to', realmValue(initial.context, {name: api.t('common.you')})),
        'Responder a Tú...',
        'the semantic self sender localizes inside the reply composer placeholder'
    );
    assert.equal(
        api.t('chat.replying_to', realmValue(initial.context, {name: api.t('common.user')})),
        'Respondiendo a Usuario',
        'the unknown-sender fallback localizes inside reply chrome'
    );
    await api.setLocale('en', realmValue(initial.context, {persist: false}));
    assert.equal(api.t('common.you'), 'You');
    assert.equal(
        api.t('chat.replying_to', realmValue(initial.context, {name: rawReplySender})),
        'Replying to You'
    );
    await api.setLocale('es', realmValue(initial.context, {persist: false}));
    assert.equal(api.t('common.you'), 'Tú', 'the semantic self sender updates on a live locale switch');
    const root = new FakeElement('section');
    const chrome = new FakeElement('button');
    chrome.textContent = 'Cancel';
    chrome.setAttribute('aria-label', 'Close');
    const userContent = new FakeElement('div');
    userContent.className = 'message-text';
    userContent.setAttribute('dir', 'auto');
    userContent.textContent = 'Cancel';
    const ignoredContent = new FakeElement('div');
    ignoredContent.setAttribute('data-i18n-ignore', '');
    ignoredContent.textContent = 'Close';
    const attachmentFilename = new FakeElement('bdi');
    attachmentFilename.className = 'file-name';
    attachmentFilename.setAttribute('dir', 'auto');
    attachmentFilename.textContent = 'Settings';
    const twoFactorInstruction = new FakeElement('p');
    const twoFactorInstructionSource =
        'Enter the 6-digit code from your authenticator app or use a backup code.';
    twoFactorInstruction.textContent = twoFactorInstructionSource;
    const profileInfo = new FakeElement('div');
    profileInfo.className = 'profile-additional-info';
    const profileLabel = new FakeElement('span');
    profileLabel.textContent = 'Email:';
    const profileValue = new FakeElement('bdi');
    profileValue.setAttribute('data-i18n-ignore', '');
    profileValue.textContent = 'Settings';
    profileInfo.append(profileLabel, profileValue);
    const profileBio = new FakeElement('div');
    profileBio.className = 'user-profile-bio';
    const profileBioHeading = new FakeElement('h6');
    profileBioHeading.textContent = 'About';
    const profileBioValue = new FakeElement('div');
    profileBioValue.className = 'bio-content';
    profileBioValue.textContent = 'Settings';
    profileBio.append(profileBioHeading, profileBioValue);
    root.append(
        chrome, userContent, ignoredContent, attachmentFilename, twoFactorInstruction,
        profileInfo, profileBio
    );
    await Promise.resolve(api.localize(root));
    assert.equal(chrome.textContent, api.translate('Cancel'));
    assert.equal(chrome.getAttribute('aria-label'), api.translate('Close'));
    assert.equal(userContent.textContent, 'Cancel', 'known user-content surfaces are never translated');
    assert.equal(userContent.getAttribute('dir'), 'auto');
    assert.equal(ignoredContent.textContent, 'Close', 'explicitly ignored dynamic content is never translated');
    assert.equal(
        attachmentFilename.textContent,
        'Settings',
        'attachment filenames that happen to equal catalog copy remain user-controlled text'
    );
    assert.equal(
        twoFactorInstruction.textContent,
        api.translate(twoFactorInstructionSource),
        'the exact 2FA instruction source localizes without whitespace normalization'
    );
    assert.equal(profileLabel.textContent, api.translate('Email:'), 'profile chrome labels localize');
    assert.equal(profileValue.textContent, 'Settings', 'profile values remain user-controlled text');
    assert.equal(profileBioHeading.textContent, api.translate('About'), 'bio section chrome localizes');
    assert.equal(profileBioValue.textContent, 'Settings', 'bio content remains user-controlled text');

    const unavailableStorage = await boot({storage: makeStorage({}, true), languages: ['en-US']});
    await assert.doesNotReject(unavailableStorage.api.setLocale('ar'));
    assert.equal(unavailableStorage.api.getLocale(), 'ar', 'storage failure cannot block a live language switch');
    assert.equal(unavailableStorage.document.documentElement.dir, 'rtl');

    console.log('Internationalization runtime tests passed.');
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
