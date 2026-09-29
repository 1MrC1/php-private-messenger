'use strict';

// Exercises the interface layer for protected conversations against a stubbed
// DOM and a stubbed client: starting one, routing a send, and filling decrypted
// text into rows the existing renderer drew.

const assert = require('node:assert/strict');
const { createProtectedUi } = require('../assets/js/protected-ui.js');

/** The smallest DOM these functions actually touch. */
function fakeDocument(rows) {
    const nodes = new Map();
    for (const row of rows) {
        const body = {
            textContent: '',
            dataset: {},
            classList: { classes: new Set(), add(name) { this.classes.add(name); } },
        };
        nodes.set('.message-row[data-message-id="' + row.id + '"]', {
            querySelector: (selector) => (selector === '.message-text' ? body : null),
            body,
        });
    }
    return {
        rows: nodes,
        chats: new Map(),
        querySelector(selector) {
            if (nodes.has(selector)) return nodes.get(selector);
            if (this.chats.has(selector)) return this.chats.get(selector);
            return null;
        },
        markChatProtected(chatId, isProtected) {
            this.chats.set('.chat-item[data-chat-id="' + chatId + '"]',
                { dataset: { protected: isProtected ? 'true' : 'false' } });
        },
    };
}

/** The interface under test, wired to a fake document and client. */
function makeUi(doc, client, notify) {
    return createProtectedUi({
        document: doc,
        post: async () => ({ success: true }),
        clientFactory: async () => client,
        prompt: async () => null,
        notify: notify || (() => {}),
    });
}

function fakeClient(options) {
    const state = {
        enrolled: options.enrolled === true,
        sent: [],
        joined: options.joined !== false,
        // How many times the interface asked for revoked devices to be removed.
        revocationChecks: 0,
    };
    return {
        state,
        resume: async () => state.enrolled,
        enroll: async (details) => { state.enrolled = true; state.enrollment = details; return { deviceId: 1 }; },
        startConversation: async (chatId) => ({ groupId: 'group-for-' + chatId }),
        syncGroup: async () => (state.joined ? { groupId: 'group-for-42', lastSequence: 1 } : { groupId: null, lastSequence: 0 }),
        send: async (chatId, groupId, text) => { state.sent.push({ chatId, groupId, text }); return { messageId: 7 }; },
        receive: async () => options.messages || [],
        enforceRevocations: async () => {
            state.revocationChecks++;
            if (options.revocationFails === true) {
                throw new Error('the directory could not be read');
            }
            return { removed: [] };
        },
        sendingBlocked: () => options.sendingBlocked || null,
        verifyDirectory: async () => {
            state.directoryChecks = (state.directoryChecks || 0) + 1;
            if (options.directoryFails === true) {
                throw new Error('the directory does not continue from what this device saw');
            }
            return { verified: 1, head: 1 };
        },
        recallConversation: async (chatId) => (options.recalled
            ? Object.assign({ groupId: 'group-for-' + chatId, lastSequence: 3, lastMessageId: 9 }, options.recalled)
            : null),
    };
}

(async () => {
    // ---- enrollment is asked for once, and only when needed ----------------
    {
        let prompted = 0;
        const client = fakeClient({ enrolled: false });
        const ui = createProtectedUi({
            document: fakeDocument([]),
            post: async () => ({ success: true, chat_id: 42 }),
            clientFactory: async () => client,
            prompt: async () => { prompted++; return { identity: 'ada', currentPassword: 'p', secondFactorCode: '123456' }; },
        });

        assert.equal(await ui.ensureDevice(), true, 'a device can be set up');
        assert.equal(prompted, 1, 'the credentials are asked for once');
        assert.equal(client.state.enrollment.currentPassword, 'p', 'the password reaches enrollment');
        assert.equal(client.state.enrollment.secondFactorCode, '123456', 'the second factor reaches enrollment');

        await ui.ensureDevice();
        assert.equal(prompted, 1, 'an enrolled device is not asked again');
        console.log('PASS: enrollment is requested once, with both credentials');
    }

    // ---- declining leaves nothing behind -----------------------------------
    {
        const client = fakeClient({ enrolled: false });
        const ui = createProtectedUi({
            document: fakeDocument([]),
            post: async () => { throw new Error('the server must not be called'); },
            clientFactory: async () => client,
            prompt: async () => null,
        });
        assert.equal(await ui.ensureDevice(), false, 'declining is not an error');
        assert.equal(await ui.startProtectedConversation(2), null,
            'declining does not create a conversation');
        console.log('PASS: declining enrollment creates nothing');
    }

    // ---- starting a protected conversation ---------------------------------
    {
        const calls = [];
        const client = fakeClient({ enrolled: true });
        const ui = createProtectedUi({
            document: fakeDocument([]),
            post: async (url, body) => { calls.push(body.action); return { success: true, chat_id: 42 }; },
            clientFactory: async () => client,
            prompt: async () => null,
        });

        const started = await ui.startProtectedConversation(2);
        assert.equal(started.chatId, 42);
        assert.equal(started.groupId, 'group-for-42');
        assert.deepEqual(calls, ['create_private_chat'], 'the chat is created, then protected by the client');
        console.log('PASS: a protected conversation is created and protected');
    }

    // ---- sending is routed, and refused when this device has not joined -----
    {
        const doc = fakeDocument([]);
        doc.markChatProtected(42, true);
        doc.markChatProtected(43, false);
        const client = fakeClient({ enrolled: true });
        const ui = createProtectedUi({
            document: doc,
            post: async () => ({ success: true }),
            clientFactory: async () => client,
            prompt: async () => null,
        });

        assert.equal(ui.isProtected(42), true, 'a marked conversation is recognised');
        assert.equal(ui.isProtected(43), false, 'an ordinary conversation is not');
        assert.equal(ui.isProtected(99), false, 'an unknown conversation is not assumed protected');

        await ui.send(42, 'the studio is free from six');
        assert.equal(client.state.sent.length, 1, 'the message goes through the encrypting client');
        assert.equal(client.state.sent[0].text, 'the studio is free from six');
        console.log('PASS: sending in a protected conversation is routed through the client');

        const notJoined = createProtectedUi({
            document: doc,
            post: async () => ({ success: true }),
            clientFactory: async () => fakeClient({ enrolled: true, joined: false }),
            prompt: async () => null,
        });
        await assert.rejects(() => notJoined.send(42, 'hello'), /has not joined/,
            'a device that has not joined refuses to send rather than sending plaintext');
        console.log('PASS: a device that has not joined refuses to send');
    }

    // ---- decrypted text is written into the rendered rows -------------------
    {
        const doc = fakeDocument([{ id: 11 }, { id: 12 }]);
        doc.markChatProtected(42, true);
        const ui = createProtectedUi({
            document: doc,
            post: async () => ({ success: true }),
            clientFactory: async () => fakeClient({
                enrolled: true,
                messages: [
                    { messageId: 11, readable: true, text: 'first' },
                    { messageId: 12, readable: false, text: null },
                ],
            }),
            prompt: async () => null,
            translate: (key, fallback) => fallback,
        });

        const filled = await ui.decorateMessages(42);
        assert.equal(filled, 2, 'both rows are filled');

        const readable = doc.rows.get('.message-row[data-message-id="11"]').body;
        assert.equal(readable.textContent, 'first', 'a readable message shows its text');
        assert.equal(readable.dataset.protectedFilled, 'true', 'a filled row is marked so it is not refilled');

        const unreadable = doc.rows.get('.message-row[data-message-id="12"]').body;
        assert.match(unreadable.textContent, /cannot be read/,
            'a message this device cannot open says so rather than vanishing');
        assert.ok(unreadable.classList.classes.has('message-unreadable'),
            'an unreadable message is marked for styling');
        console.log('PASS: decrypted text is written into the existing rows, unreadable ones say so');

        // Rendering again must not rewrite what is already there.
        readable.textContent = 'left alone';
        await ui.decorateMessages(42);
        assert.equal(readable.textContent, 'left alone', 'an already-filled row is not rewritten');
        console.log('PASS: re-rendering does not rewrite filled rows');
    }

    // ---- revocation is re-checked, and sending fails closed ----------------
    // A review found the boolean that used to guard this: a device revoked after
    // the first open stayed a member for the life of the page.

    {
        const doc = fakeDocument([]);
        doc.markChatProtected(42, true);
        const client = fakeClient({ enrolled: true });
        const ui = makeUi(doc, client);

        await ui.adoptConversation(42);
        await ui.adoptConversation(42);
        await ui.adoptConversation(42);
        assert.equal(client.state.revocationChecks, 3,
            'every open re-checks for revoked devices, rather than once per page');
        console.log('PASS: revoked devices are looked for on every open, not once');
    }

    {
        const notices = [];
        const doc = fakeDocument([]);
        doc.markChatProtected(42, true);
        const client = fakeClient({ enrolled: true, revocationFails: true });
        const ui = makeUi(doc, client, (message) => notices.push(message));

        await ui.adoptConversation(42);
        await assert.rejects(() => ui.send(42, 'while a removal may be pending'),
            /revoked device/,
            'sending is refused while the revocation check is failing');
        assert.equal(client.state.sent.length, 0, 'nothing was sent');
        assert.ok(notices.some((line) => /revoked device/.test(line)),
            'and the person is told why');
        console.log('PASS: a failed revocation check blocks sending instead of being swallowed');
    }

    {
        const notices = [];
        const doc = fakeDocument([]);
        doc.markChatProtected(42, true);
        const client = fakeClient({
            enrolled: true,
            sendingBlocked: 'this conversation has diverged from the rest of the group',
        });
        const ui = makeUi(doc, client, (message) => notices.push(message));

        await ui.adoptConversation(42);
        await assert.rejects(() => ui.send(42, 'on a branch nobody else took'), /diverged/,
            'sending is refused after a fork');
        assert.equal(client.state.sent.length, 0, 'nothing was sent');
        console.log('PASS: a forked conversation refuses to send');
    }

    // ---- a fresh page finds a conversation it is already in ----------------

    {
        const doc = fakeDocument([]);
        doc.markChatProtected(42, true);
        // `joined: false` means the server has no welcome left to replay, which
        // is exactly the situation after a reload.
        const client = fakeClient({ enrolled: true, joined: false, recalled: {} });
        const ui = makeUi(doc, client);

        const groupId = await ui.adoptConversation(42);
        assert.equal(groupId, 'group-for-42',
            'a reloaded page recovers the group from the sealed local record');
        console.log('PASS: a reload rejoins a conversation whose welcome is long gone');
    }

    {
        const notices = [];
        const doc = fakeDocument([]);
        doc.markChatProtected(42, true);
        const client = fakeClient({ enrolled: true, directoryFails: true });
        const ui = makeUi(doc, client, (message) => notices.push(message));

        await ui.adoptConversation(42);
        assert.ok(client.state.directoryChecks >= 1, 'the directory chain is checked when a conversation opens');
        await assert.rejects(() => ui.send(42, 'while the directory disagrees'), /directory/,
            'sending is refused while the directory does not match what this device saw');
        assert.ok(notices.some((line) => /safety numbers/.test(line)),
            'and the person is told to compare safety numbers');
        console.log('PASS: a rewritten directory blocks sending and says why');
    }

    console.log('Protected interface runtime tests passed.');
})().catch((error) => {
    console.error(error);
    process.exit(1);
});
