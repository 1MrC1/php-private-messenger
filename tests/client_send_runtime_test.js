'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class FakeElement {
    constructor(id = '') {
        this.id = id;
        this.tagName = String(id).toUpperCase();
        this.attributes = Object.create(null);
        this.childNodes = [];
        this.dataset = Object.create(null);
        this.disabled = false;
        this.files = [];
        this.isConnected = true;
        this.parentNode = null;
        this.style = Object.create(null);
        this.value = '';
        this.textContent = '';
        this.innerHTML = '';
        this.className = '';
        this.listeners = Object.create(null);
        const classes = new Set();
        this.classList = {
            add: (...names) => names.forEach((name) => classes.add(name)),
            remove: (...names) => names.forEach((name) => classes.delete(name)),
            contains: (name) => classes.has(name),
            toggle: (name, force) => {
                const enabled = force === undefined ? !classes.has(name) : Boolean(force);
                if (enabled) classes.add(name); else classes.delete(name);
                return enabled;
            }
        };
    }

    get children() { return this.childNodes.filter((child) => child instanceof FakeElement); }
    addEventListener(type, listener) {
        if (!this.listeners[type]) this.listeners[type] = [];
        this.listeners[type].push(listener);
    }
    appendChild(child) {
        if (child instanceof FakeElement && child.parentNode) {
            child.parentNode.childNodes = child.parentNode.childNodes.filter((node) => node !== child);
        }
        this.childNodes.push(child);
        if (child instanceof FakeElement) child.parentNode = this;
        return child;
    }
    append(...children) { children.forEach((child) => this.appendChild(child)); }
    click() {
        (this.listeners.click || []).forEach((listener) => listener({
            currentTarget: this,
            preventDefault() {}
        }));
    }
    cloneNode() { return new FakeElement(this.id); }
    focus() {}
    getAttribute(name) { return this.attributes[name] ?? null; }
    insertBefore(child) { this.childNodes.unshift(child); return child; }
    querySelector() { return null; }
    remove() {
        if (this.parentNode) {
            this.parentNode.childNodes = this.parentNode.childNodes.filter((node) => node !== this);
            this.parentNode = null;
        }
        this.isConnected = false;
    }
    removeAttribute(name) { delete this.attributes[name]; }
    replaceChildren(...children) {
        this.childNodes.forEach((child) => {
            if (child instanceof FakeElement) child.parentNode = null;
        });
        this.childNodes = [];
        children.forEach((child) => this.appendChild(child));
    }
    setAttribute(name, value) { this.attributes[name] = String(value); }
}

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
    });
    return {promise, resolve, reject};
}

function jsonResponse(data, status = 200) {
    const body = JSON.stringify(data);
    return {
        ok: status >= 200 && status < 300,
        status,
        json: async () => data,
        text: async () => body
    };
}

async function flushPromises() {
    await Promise.resolve();
    await new Promise((resolve) => setImmediate(resolve));
    await Promise.resolve();
}

function createBrowserContext() {
    const elements = new Map();
    let profileVisible = true;
    const profileIds = new Set([
        'profileFirstName', 'profileLastName', 'profileUsername', 'profileBio',
        'profilePhone', 'profileNameLarge', 'profileUsernameLarge', 'profileAvatarLarge'
    ]);
    const elementFor = (id) => {
        if (!profileVisible && profileIds.has(id)) return null;
        if (!elements.has(id)) elements.set(id, new FakeElement(id));
        return elements.get(id);
    };
    const sendButton = elementFor('sendMessageBtn');
    sendButton.childNodes = [new FakeElement('sendIcon')];
    const messageInput = elementFor('messageInput');

    const document = {
        activeElement: messageInput,
        baseURI: 'https://messenger.example/',
        body: elementFor('body'),
        documentElement: elementFor('documentElement'),
        addEventListener() {},
        createElement: (tagName) => new FakeElement(tagName),
        createTextNode: (text) => ({textContent: String(text), cloneNode() { return this; }}),
        getElementById: elementFor,
        querySelector: (selector) => selector === '.send-btn' ? sendButton : null,
        querySelectorAll: () => []
    };

    class BrowserURL extends URL {
        static createObjectURL() { return 'blob:pm-test'; }
        static revokeObjectURL() {}
    }

    class FakeFormData {
        constructor() { this.entries = []; }
        append(name, value) { this.entries.push([name, value]); }
    }

    const context = {
        Array,
        Blob,
        Boolean,
        Date,
        Element: FakeElement,
        Error,
        FormData: FakeFormData,
        HTMLButtonElement: FakeElement,
        JSON,
        Map,
        Math,
        Number,
        Object,
        Promise,
        RegExp,
        Set,
        String,
        Symbol,
        TypeError,
        URL: BrowserURL,
        Uint8Array,
        clearInterval,
        clearTimeout,
        console: {debug() {}, error() {}, log() {}, warn() {}},
        crypto: require('node:crypto').webcrypto,
        document,
        fetch: async () => { throw new Error('Unexpected fetch'); },
        localStorage: {getItem() { return null; }, setItem() {}, removeItem() {}},
        navigator: {},
        setImmediate,
        setInterval: () => 0,
        setTimeout,
        bootstrap: {
            Modal: class {
                hide() {}
                show() {}
                static getInstance() { return {hide() {}}; }
            }
        },
        addEventListener() {}
    };
    context.window = context;
    context.location = {origin: 'https://messenger.example'};
    context.innerWidth = 1024;
    context.$ = function () {
        return {
            ready() {},
            modal() {}
        };
    };
    context.__elements = elements;
    context.__messageInput = messageInput;
    context.__sendButton = sendButton;
    context.__setProfileVisible = (visible) => { profileVisible = visible; };
    return vm.createContext(context);
}

async function main() {
    const root = path.resolve(__dirname, '..');
    const applicationSource = fs.readFileSync(
        path.join(root, 'assets/js/script-ori_2025-06-07_02.js'),
        'utf8'
    );
    const hardeningSource = fs.readFileSync(
        path.join(root, 'assets/js/security-hardening.js'),
        'utf8'
    );
    const context = createBrowserContext();
    vm.runInContext(applicationSource, context, {filename: 'script-ori_2025-06-07_02.js'});
    vm.runInContext('showToast = function () {}; renderChats = function () {};', context);

    context.fetch = async () => jsonResponse({
        success: true,
        chats: [],
        message_idempotency_ready: true
    });
    await vm.runInContext('loadChats()', context);
    assert.equal(vm.runInContext('messageIdempotencyReady', context), true);

    context.fetch = async () => jsonResponse({success: true, chats: []});
    await vm.runInContext('loadChats()', context);
    assert.equal(
        vm.runInContext('messageIdempotencyReady', context),
        false,
        'a legacy response without capability proof must disable retries'
    );

    const oldPoll = deferred();
    const latestPoll = deferred();
    const polls = [oldPoll, latestPoll];
    context.fetch = () => polls.shift().promise;
    const oldPromise = vm.runInContext('loadChats()', context);
    const latestPromise = vm.runInContext('loadChats()', context);
    latestPoll.resolve(jsonResponse({
        success: true,
        chats: [],
        message_idempotency_ready: false
    }));
    await latestPromise;
    oldPoll.resolve(jsonResponse({
        success: true,
        chats: [],
        message_idempotency_ready: true
    }));
    await oldPromise;
    assert.equal(
        vm.runInContext('messageIdempotencyReady', context),
        false,
        'an older poll must not overwrite the latest fleet capability'
    );

    context.fetch = async () => { throw new Error('offline'); };
    await vm.runInContext('loadChats()', context);
    assert.equal(
        vm.runInContext('messageIdempotencyReady', context),
        false,
        'a latest failed capability poll must fail closed'
    );

    context.__ambiguousSendResponse = jsonResponse({
        success: false,
        error_code: 'request_failed'
    }, 503);
    const ambiguousSend = await vm.runInContext(
        'readChatSendResponse(__ambiguousSendResponse, false)',
        context
    );
    assert.equal(ambiguousSend.status, 503);
    assert.equal(ambiguousSend.error_code, 'request_failed');
    assert.equal(ambiguousSend.delivery_unconfirmed, true);

    context.__malformedSendResponse = {
        ok: true,
        status: 200,
        text: async () => ''
    };
    const malformedSend = await vm.runInContext(
        'readChatSendResponse(__malformedSendResponse, false)',
        context
    );
    assert.equal(
        malformedSend.delivery_unconfirmed,
        true,
        'an empty successful HTTP response must not be treated as a deterministic rejection'
    );

    context.fetch = async () => ({
        ok: true,
        status: 200,
        json: () => new Promise(() => {})
    });
    await assert.rejects(
        vm.runInContext(
            "fetchWithTimeout('api/auth.php', {}, 10, function (response) { return response.json(); })",
            context
        ),
        (error) => error && error.name === 'TimeoutError',
        'authentication must time out while a response body is stalled'
    );

    context.fetch = async () => ({
        ok: true,
        status: 200,
        text: () => new Promise(() => {})
    });
    await assert.rejects(
        vm.runInContext('fetchChatAttempt({}, 10, false)', context),
        (error) => error && error.name === 'TimeoutError',
        'message sends must time out while a response body is stalled'
    );

    context.__rejectedSendResponse = jsonResponse({
        success: false,
        error_code: 'invalid_message'
    }, 400);
    const rejectedSend = await vm.runInContext(
        'readChatSendResponse(__rejectedSendResponse, false)',
        context
    );
    assert.equal(rejectedSend.delivery_unconfirmed, false);
    assert.equal(
        vm.runInContext("isSupportedChatAttachment({type: 'application/zip'})", context),
        true,
        'the shared picker allowlist must include server-supported archives'
    );
    assert.equal(
        vm.runInContext("isSupportedChatAttachment({type: 'text/html'})", context),
        false,
        'the shared picker allowlist must reject unsupported active content'
    );
    assert.equal(
        vm.runInContext("isSupportedChatAttachment({type: 'audio/x-m4a'})", context),
        false,
        'the shared picker allowlist must not claim unsupported server MIME aliases'
    );

    const sendResponse = deferred();
    let sendFetches = 0;
    context.fetch = () => {
        sendFetches += 1;
        return sendResponse.promise;
    };
    context.__messageInput.value = 'one logical message';
    context.__messageInput.dataset = Object.create(null);
    context.__sendButton.disabled = false;
    vm.runInContext(
        'currentChatId = 17; currentAttachment = null; messageIdempotencyReady = false;' +
        'chatSendInFlight = false; sendMessage(); sendMessage();',
        context
    );
    await flushPromises();
    assert.equal(sendFetches, 1, 'rapid keyboard submissions must start only one request');
    assert.equal(vm.runInContext('chatSendInFlight', context), true);
    sendResponse.resolve(jsonResponse({
        success: false,
        error_code: 'invalid_message'
    }, 400));
    await flushPromises();
    assert.equal(vm.runInContext('chatSendInFlight', context), false);
    assert.equal(context.__sendButton.disabled, false);

    context.fetch = async () => {
        sendFetches += 1;
        return jsonResponse({success: false, error_code: 'invalid_message'}, 400);
    };
    vm.runInContext('sendMessage()', context);
    await flushPromises();
    assert.equal(sendFetches, 2, 'the guard must release after the request settles');

    vm.runInContext(hardeningSource, context, {filename: 'security-hardening.js'});
    vm.runInContext('loadMessages = function () {};', context);

    const firstChatSnapshot = [{
        chat_id: 2,
        title: 'Second chat',
        chat_avatar: '/api/avatar.php?file=avatar_2_1_deadbeef.png',
        last_message: 'First preview',
        last_message_time: '2026-08-08 19:00:00',
        unread_count: 1
    }];
    context.__firstChatSnapshot = firstChatSnapshot;
    vm.runInContext('renderChats(__firstChatSnapshot);', context);
    const chatList = context.__elements.get('chatList');
    const firstChatRow = chatList.children[0];
    const firstAvatarNode = firstChatRow.__pmChatRefs.avatar.childNodes[0];

    context.__secondChatSnapshot = [{
        ...firstChatSnapshot[0],
        last_message: 'Updated preview',
        unread_count: 3
    }];
    vm.runInContext('renderChats(__secondChatSnapshot);', context);
    assert.strictEqual(chatList.children[0], firstChatRow, 'polling must reuse the chat row');
    assert.strictEqual(
        chatList.children[0].__pmChatRefs.avatar.childNodes[0],
        firstAvatarNode,
        'polling must preserve an unchanged avatar image node'
    );
    assert.equal(chatList.children[0].__pmChatRefs.lastMessage.textContent, 'Updated preview');
    assert.equal(chatList.children[0].__pmChatRefs.unread.textContent, '3');
    assert.equal(chatList.children[0].__pmChatRefs.unread.hidden, false);
    assert.equal(firstChatRow.dataset.keyboardReady, 'true');
    assert.equal(firstChatRow.listeners.keydown.length, 1, 'a hardened row must own one keyboard handler');

    context.__reorderedChats = [{chat_id: 'invalid'}, {
        chat_id: 3,
        title: 'Third chat',
        chat_avatar: null,
        last_message: 'New row',
        unread_count: 0
    }, context.__secondChatSnapshot[0], {
        chat_id: 3,
        title: 'Duplicate third chat',
        chat_avatar: '/api/avatar.php?file=avatar_3_9_deadbeef.png'
    }];
    vm.runInContext('currentChatId = 2; renderChats(__reorderedChats);', context);
    assert.deepEqual(
        chatList.children.map((row) => row.dataset.chatId),
        ['3', '2'],
        'reconciliation must preserve the server order'
    );
    assert.strictEqual(chatList.children[1], firstChatRow);
    assert.equal(
        chatList.children[0].__pmChatRefs.unread.hidden,
        true,
        'a zero-unread chat must keep its reconciled badge hidden'
    );
    assert.equal(firstChatRow.classList.contains('active'), true);
    assert.strictEqual(firstChatRow.__pmChatData, context.__secondChatSnapshot[0]);

    const hardenedSelectChat = context.selectChat;
    context.__clickedChat = null;
    let keyboardSelections = 0;
    context.selectChat = (chatId, chat) => {
        keyboardSelections += 1;
        context.__clickedChat = {chatId, chat};
    };
    firstChatRow.click();
    assert.equal(context.__clickedChat.chatId, 2);
    assert.strictEqual(
        context.__clickedChat.chat,
        context.__secondChatSnapshot[0],
        'a reused row click must use the newest chat snapshot'
    );
    const keyboardEvent = (key) => ({key, preventDefault() {}});
    firstChatRow.listeners.keydown[0](keyboardEvent('Enter'));
    assert.equal(keyboardSelections, 2, 'Enter must select exactly once');
    firstChatRow.listeners.keydown[0](keyboardEvent(' '));
    assert.equal(keyboardSelections, 3, 'Space must select exactly once');
    context.selectChat = hardenedSelectChat;

    context.__changedAvatarSnapshot = [{
        ...context.__secondChatSnapshot[0],
        chat_avatar: '/api/avatar.php?file=avatar_2_2_cafebabe.png'
    }];
    vm.runInContext('renderChats(__changedAvatarSnapshot);', context);
    assert.equal(chatList.children.length, 1, 'stale chat rows must be removed');
    assert.strictEqual(chatList.children[0], firstChatRow, 'the retained chat row must stay stable');
    assert.notStrictEqual(
        firstChatRow.__pmChatRefs.avatar.childNodes[0],
        firstAvatarNode,
        'a changed authorized avatar URL must replace the image node'
    );

    vm.runInContext(
        'currentChatId = 1; clientSendSemanticEpoch = 4;' +
        'pendingClientMessage = {id: "pending", chatId: "1"};' +
        'selectChat(2, {title: "Second chat"}, null);',
        context
    );
    assert.equal(vm.runInContext('clientSendSemanticEpoch', context), 5);
    assert.equal(vm.runInContext('pendingClientMessage', context), null);
    vm.runInContext('selectChat(2, {title: "Second chat"}, null);', context);
    assert.equal(
        vm.runInContext('clientSendSemanticEpoch', context),
        5,
        'reselecting the same chat must not invalidate an unchanged send'
    );

    vm.runInContext(
        'avatarSelectionEpoch = 8;' +
        'pendingAvatarUpload = {selectionToken: 7};' +
        'handleAvatarUpload({target: {files: [], value: ""}});',
        context
    );
    assert.equal(vm.runInContext('avatarSelectionEpoch', context), 8);
    assert.equal(vm.runInContext('pendingAvatarUpload.selectionToken', context), 7);

    const invalidInput = {files: [{type: 'text/plain', size: 20}], value: 'chosen'};
    context.__invalidAvatarInput = invalidInput;
    vm.runInContext('handleAvatarUpload({target: __invalidAvatarInput});', context);
    assert.equal(vm.runInContext('avatarSelectionEpoch', context), 8);
    assert.equal(invalidInput.value, '');

    const validFile = {name: 'avatar.png', type: 'image/png', size: 20};
    const validInput = {files: [validFile], value: 'chosen'};
    context.__validAvatarInput = validInput;
    vm.runInContext(
        'avatarUploadInFlight = true; handleAvatarUpload({target: __validAvatarInput});',
        context
    );
    assert.equal(validInput.value, '');
    assert.equal(vm.runInContext('avatarSelectionEpoch', context), 9);
    assert.equal(vm.runInContext('pendingAvatarUpload.file === __validAvatarInput.files[0]', context), true);

    context.__setProfileVisible(false);
    vm.runInContext(
        'currentUser = {first_name: "A", last_name: "User", username: "a", bio: ""};',
        context
    );
    assert.doesNotThrow(() => vm.runInContext('loadUserProfile()', context));
    context.__setProfileVisible(true);

    const refreshResponse = deferred();
    let refreshStarted = false;
    context.fetch = (url) => {
        if (url === 'api/profile.php') {
            return Promise.resolve(jsonResponse({success: false, message: 'Unavailable'}, 503));
        }
        if (url === 'api/auth.php') {
            refreshStarted = true;
            return refreshResponse.promise;
        }
        throw new Error('Unexpected avatar URL');
    };
    let avatarSettled = false;
    const avatarPromise = vm.runInContext(
        'avatarUploadInFlight = false; pendingAvatarUpload = null;' +
        'uploadAvatar({name: "avatar.png", type: "image/png", size: 20}, 9)',
        context
    ).then(() => { avatarSettled = true; });
    await flushPromises();
    assert.equal(refreshStarted, true);
    assert.equal(avatarSettled, false, 'the serial queue must await authoritative reconciliation');
    refreshResponse.resolve(jsonResponse({
        success: true,
        user: {
            id: 1,
            first_name: 'Authoritative',
            last_name: 'User',
            username: 'authoritative',
            bio: '',
            avatar: '/api/avatar.php?file=avatar_1_1_deadbeef.png'
        }
    }));
    await avatarPromise;
    assert.equal(
        vm.runInContext('currentUser.username', context),
        'authoritative',
        'a failed/ambiguous avatar response must reconcile from authenticated server state'
    );

    console.log('Client send runtime tests passed.');
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
