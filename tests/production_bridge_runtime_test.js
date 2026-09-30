'use strict';

// Does the protected layer actually reach the real application?
//
// Five rounds of review passed with a green suite while the answer was no. The
// legacy bundle declares `let currentChatId` and `let currentUser` at the top
// level of a classic script: those are bindings in the global lexical scope, not
// properties of `window`. The protected layer read `window.currentChatId`, which
// is permanently `undefined`, so every "protected" send fell through to the
// legacy plaintext sender — in production, never in a test, because every test
// injected its own globals and none of them loaded the real files together.
//
// This test loads the real scripts, in the real order, in one shared context —
// the only way to see whether the layers are connected at all.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

function browserish() {
    const listeners = new Map();
    const elements = new Map();

    const element = (id) => {
        if (!elements.has(id)) {
            elements.set(id, {
                id,
                value: '',
                textContent: '',
                hidden: false,
                dataset: {},
                files: [],
                classList: { add() {}, remove() {}, contains: () => false },
                style: {},
                appendChild() {},
                removeChild() {},
                addEventListener() {},
                removeAttribute() {},
                setAttribute() {},
                querySelector: () => null,
                querySelectorAll: () => [],
            });
        }
        return elements.get(id);
    };

    const doc = {
        readyState: 'complete',
        body: { appendChild() {}, removeChild() {} },
        documentElement: { classList: { add() {}, remove() {} }, style: {}, setAttribute() {} },
        getElementById: (id) => element(id),
        querySelector: () => null,
        querySelectorAll: () => [],
        createElement: () => element('created-' + Math.random()),
        addEventListener: (name, handler) => {
            listeners.set(name, (listeners.get(name) || []).concat(handler));
        },
        removeEventListener() {},
        cookie: '',
    };

    const context = {
        console,
        document: doc,
        navigator: { userAgent: 'node', language: 'en' },
        location: { href: 'https://example.test/', origin: 'https://example.test' },
        localStorage: (() => {
            const values = new Map();
            return {
                getItem: (key) => (values.has(key) ? values.get(key) : null),
                setItem: (key, value) => values.set(key, String(value)),
                removeItem: (key) => values.delete(key),
            };
        })(),
        sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
        fetch: async () => ({ ok: true, json: async () => ({ success: true }) }),
        setTimeout,
        clearTimeout,
        setInterval: () => 0,
        clearInterval,
        requestAnimationFrame: (fn) => setTimeout(fn, 0),
        addEventListener: (name, handler) => {
            listeners.set(name, (listeners.get(name) || []).concat(handler));
        },
        removeEventListener() {},
        matchMedia: () => ({ matches: false, addEventListener() {}, addListener() {} }),
        crypto: require('node:crypto').webcrypto,
        indexedDB: { open: () => ({}) },
        bootstrap: { Modal: { getOrCreateInstance: () => ({ show() {}, hide() {} }) } },
        IntersectionObserver: class { observe() {} disconnect() {} },
        MutationObserver: class { observe() {} disconnect() {} },
        Notification: { permission: 'default' },
        URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} },
        Blob: class {},
    };
    context.window = context;
    context.self = context;
    context.globalThis = context;
    return { context, listeners };
}

// The i18n runtime fetches its catalogue on a timer; in this harness that
// request never resolves. It is not what is under test, and its rejection must
// not fail the run.
process.on('unhandledRejection', () => {});
process.on('uncaughtException', (error) => {
    if (error && /Locale catalog|catalog request/.test(String(error.message))) {
        return;
    }
    throw error;
});

const { context } = browserish();
vm.createContext(context);

// The real files, in the order index.html loads them. Each is a classic script,
// so they share one global lexical scope — which is the whole point here.
for (const file of [
    'assets/js/i18n.js',
    'assets/js/script-ori_2025-06-07_02.js',
    'assets/js/security-hardening.js',
    'assets/js/ui-enhancements.js',
    'assets/js/csp-events.js',
    'assets/js/chat-ux.js',
    'assets/js/protected-chat.js',
    'assets/js/protected-ui.js',
]) {
    try {
        vm.runInContext(read(file), context, { filename: file });
    } catch (error) {
        // A missing browser API is fine; a syntax error is not.
        if (error instanceof SyntaxError) {
            throw error;
        }
    }
}

console.log('PASS: every production script parses and runs in one shared context');

// The bundle's own globals exist as lexical bindings, not window properties.
// This is the fact the bridge has to respect.
assert.equal(
    vm.runInContext('typeof currentChatId', context),
    'object',
    "the legacy bundle's currentChatId exists as a lexical binding"
);
assert.equal(
    vm.runInContext('typeof window.currentChatId', context),
    'undefined',
    'and is NOT a window property — reading window.currentChatId is always undefined'
);
console.log('PASS: the bundle keeps its state in lexical bindings, not on window');

// The protected layer must not depend on the window properties that do not exist.
const protectedUi = read('assets/js/protected-ui.js');
assert.equal(
    /window\.currentChatId/.test(protectedUi.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, '')),
    false,
    'the protected layer does not read window.currentChatId outside comments'
);
assert.equal(
    /window\.currentUserId/.test(protectedUi.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, '')),
    false,
    'nor window.currentUserId'
);
console.log('PASS: the protected layer reads no global that does not exist');

// And the bridge resolves the real binding. Set the chat the way the bundle does
// and ask the layer what it sees.
vm.runInContext('currentChatId = 42; currentUser = { id: 7 };', context);
// Compared as primitives: an object created inside the VM has a different
// prototype, which deepStrictEqual would object to for the wrong reason.
assert.equal(
    vm.runInContext('typeof currentChatId === "undefined" ? null : currentChatId', context),
    42,
    'the selected chat is readable by name'
);
assert.equal(
    vm.runInContext('typeof currentUser === "undefined" || !currentUser ? null : currentUser.id', context),
    7,
    'and so is the signed-in account'
);

// The installed wrapper has to be the protected one, not the legacy function.
const wrapperInstalled = vm.runInContext(
    'typeof window.sendMessage === "function" && /protectedAwareSend/.test(window.sendMessage.name + window.sendMessage.toString())',
    context
);
assert.equal(wrapperInstalled, true, 'the protected send wrapper is installed over the legacy sender');
const fileWrapperInstalled = vm.runInContext(
    'typeof window.handleFileSelect === "function" && /protectedAwareFileSelect/.test(window.handleFileSelect.toString())',
    context
);
assert.equal(fileWrapperInstalled, true, 'and the protected attachment wrapper too');
console.log('PASS: the protected wrappers are installed and read the real selection');

console.log('Production bridge tests passed.');
// Nothing here waits on a timer; exit before the i18n loader's does.
process.exit(0);
