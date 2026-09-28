// Protected conversations: the interface.
//
// Deliberately a layer on top rather than an edit to the legacy bundle. It adds
// its own entry point, routes sending for protected conversations through the
// encrypting client, and fills in decrypted text on rows the existing renderer
// has already drawn -- so the message rendering, which is the part that has been
// hardened, stays exactly as it is.
//
// None of this makes the application end-to-end encrypted. See
// docs/security/e2ee-readiness.md.
(function () {
    'use strict';

    function createProtectedUi(adapters) {
        const doc = adapters.document;
        const post = adapters.post;
        const clientFactory = adapters.clientFactory;
        const prompt = adapters.prompt;
        const notify = adapters.notify || function () {};
        const translate = adapters.translate || ((key, fallback) => fallback);

        let client = null;
        // chatId -> {groupId, lastMessageId, opened: Map(messageId -> text)}
        const conversations = new Map();

        async function ensureClient() {
            if (!client) {
                client = await clientFactory();
            }
            return client;
        }

        /**
         * Make sure this device can take part, asking for the credentials the
         * server requires only when there is no device yet.
         */
        async function ensureDevice() {
            const active = await ensureClient();
            if (await active.resume()) {
                return true;
            }

            const credentials = await prompt();
            if (!credentials) {
                return false;
            }

            await active.enroll({
                identity: credentials.identity,
                label: credentials.label,
                currentPassword: credentials.currentPassword,
                secondFactorCode: credentials.secondFactorCode,
                keyPackageCount: 10,
            });
            return true;
        }

        /**
         * Create a conversation and protect it in one step.
         *
         * Protection is decided at creation and cannot be added later, so this
         * is the only moment it can be chosen. If protecting fails the chat has
         * already been created as an ordinary one; that is reported rather than
         * hidden, because silently handing back a plaintext conversation the
         * person asked to protect is the worst outcome available.
         */
        async function startProtectedConversation(otherUserId) {
            if (!(await ensureDevice())) {
                return null;
            }

            const created = await post('api/chat.php', {
                action: 'create_private_chat',
                user_id: otherUserId,
            });
            if (!created || created.success !== true || !created.chat_id) {
                throw new Error((created && created.message) ||
                    translate('protected.start_failed', 'Could not start the conversation'));
            }

            try {
                const started = await (await ensureClient()).startConversation(created.chat_id, otherUserId);
                conversations.set(created.chat_id, {
                    groupId: started.groupId,
                    lastMessageId: 0,
                    opened: new Map(),
                });
                return { chatId: created.chat_id, groupId: started.groupId };
            } catch (error) {
                notify(translate('protected.start_failed', 'Could not start the conversation') +
                    ' ' + error.message);
                throw error;
            }
        }

        /** Join a conversation this device was invited to. */
        async function adoptConversation(chatId) {
            const active = await ensureClient();
            if (!(await active.resume())) {
                return null;
            }
            const known = conversations.get(chatId);
            const sync = await active.syncGroup(chatId, known ? known.lastSequence || 0 : 0);
            if (!sync.groupId && !known) {
                return null;
            }
            const record = known || { lastMessageId: 0, opened: new Map() };
            record.groupId = sync.groupId || record.groupId;
            record.lastSequence = sync.lastSequence;
            conversations.set(chatId, record);

            // A device revoked in settings keeps the keys it already holds, so
            // somebody still in the conversation has to publish a removal. Done
            // here rather than silently skipped, and reported if it fails: a
            // security control that fails quietly is worse than one that is
            // absent, because nobody looks for it.
            if (record.groupId && !record.revocationsChecked) {
                record.revocationsChecked = true;
                try {
                    await active.enforceRevocations(chatId, record.groupId);
                } catch (error) {
                    record.revocationsChecked = false;
                    notify(translate('protected.revocation_check_failed',
                        'Could not check whether a revoked device is still in this conversation.'));
                }
            }
            return record.groupId;
        }

        function isProtected(chatId) {
            const row = doc.querySelector('.chat-item[data-chat-id="' + chatId + '"]');
            return !!row && row.dataset.protected === 'true';
        }

        /** Send through the encrypting client instead of the plaintext path. */
        async function send(chatId, text) {
            const groupId = await adoptConversation(chatId);
            if (!groupId) {
                throw new Error(translate('protected.not_joined',
                    'This device has not joined that protected conversation yet'));
            }
            return (await ensureClient()).send(chatId, groupId, text);
        }

        /** Show the safety number for the open conversation. */
        async function showSafetyNumber(chatId) {
            const holder = doc.getElementById ? doc.getElementById('protectedSafety') : null;
            const target = doc.getElementById ? doc.getElementById('protectedSafetyNumber') : null;
            if (!holder || !target) {
                return null;
            }
            const groupId = await adoptConversation(chatId);
            if (!groupId) {
                holder.hidden = true;
                return null;
            }
            const number = await (await ensureClient()).safetyNumber(groupId);
            target.textContent = number;
            holder.hidden = false;
            return number;
        }

        /**
         * Fill in the text of messages the renderer drew as empty.
         *
         * The server stores an empty content column for a protected message, so
         * the existing renderer produces a row with no text. Rather than
         * duplicating that renderer, this decrypts and writes into the row it
         * already made, using textContent so nothing is ever parsed as markup.
         */
        async function decorateMessages(chatId) {
            const groupId = await adoptConversation(chatId);
            if (!groupId) {
                return 0;
            }
            const record = conversations.get(chatId);
            const messages = await (await ensureClient()).receive(chatId, groupId, 0);

            let filled = 0;
            for (const message of messages) {
                record.opened.set(message.messageId, message.readable ? message.text : null);
            }
            for (const [messageId, text] of record.opened) {
                const row = doc.querySelector('.message-row[data-message-id="' + messageId + '"]');
                if (!row) {
                    continue;
                }
                const body = row.querySelector('.message-text');
                if (!body || body.dataset.protectedFilled === 'true') {
                    continue;
                }
                body.textContent = text === null
                    ? translate('protected.unreadable', 'This message cannot be read on this device')
                    : text;
                body.dataset.protectedFilled = 'true';
                if (text === null) {
                    body.classList.add('message-unreadable');
                }
                filled++;
            }
            return filled;
        }

        return {
            ensureDevice,
            startProtectedConversation,
            adoptConversation,
            isProtected,
            send,
            showSafetyNumber,
            decorateMessages,
            conversations,
        };
    }

    // ---- browser wiring ----------------------------------------------------

    function browserPrompt() {
        return new Promise(function (resolve) {
            const dialog = document.getElementById('protectedEnrollModal');
            if (!dialog || typeof bootstrap === 'undefined') {
                resolve(null);
                return;
            }
            const modal = bootstrap.Modal.getOrCreateInstance(dialog);
            const form = document.getElementById('protectedEnrollForm');
            const password = document.getElementById('protectedEnrollPassword');
            const code = document.getElementById('protectedEnrollCode');
            const label = document.getElementById('protectedEnrollLabel');

            function cleanup(result) {
                form.removeEventListener('submit', onSubmit);
                dialog.removeEventListener('hidden.bs.modal', onHide);
                password.value = '';
                code.value = '';
                resolve(result);
            }
            function onSubmit(event) {
                event.preventDefault();
                const credentials = {
                    identity: (window.currentUser && window.currentUser.username) || 'device',
                    label: label.value || null,
                    currentPassword: password.value,
                    secondFactorCode: code.value,
                };
                modal.hide();
                cleanup(credentials);
            }
            function onHide() { cleanup(null); }

            form.addEventListener('submit', onSubmit);
            dialog.addEventListener('hidden.bs.modal', onHide);
            modal.show();
        });
    }

    async function install() {
        if (!window.PmProtected) {
            return null;
        }
        const ui = createProtectedUi({
            document,
            post: async function (url, body) {
                const response = await fetch(url, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                    body: JSON.stringify(body),
                });
                try { return await response.json(); } catch (error) { return null; }
            },
            clientFactory: () => window.PmProtected.browserClient(),
            prompt: browserPrompt,
            notify: (message) => { if (typeof window.showToast === 'function') window.showToast(message, 'error'); },
            translate: (key, fallback) => (window.HiI18n && typeof window.HiI18n.t === 'function'
                ? window.HiI18n.t(key, {}) : fallback) || fallback,
        });

        // The option in the new-conversation dialog has to actually do
        // something, or it is worse than absent: it would look like it
        // protected a conversation that it did not.
        const legacyStart = window.startChatWithUser;
        if (typeof legacyStart === 'function') {
            window.startChatWithUser = function protectedAwareStart(userId) {
                const option = document.getElementById('newChatProtected');
                if (!option || !option.checked) {
                    return legacyStart.apply(this, arguments);
                }
                return ui.startProtectedConversation(userId)
                    .then(function (started) {
                        option.checked = false;
                        if (!started) {
                            return;   // enrollment was declined; nothing was created
                        }
                        const dialog = document.getElementById('newChatModal');
                        if (dialog && typeof bootstrap !== 'undefined') {
                            const modal = bootstrap.Modal.getInstance(dialog);
                            if (modal) modal.hide();
                        }
                        if (typeof window.loadChats === 'function') window.loadChats();
                    })
                    .catch(function (error) {
                        if (typeof window.showToast === 'function') {
                            window.showToast(error.message, 'error');
                        }
                    });
            };
        }

        // Route sending for protected conversations through the encrypting
        // client. Everything else keeps the path it already had.
        const legacySend = window.sendMessage;
        if (typeof legacySend === 'function') {
            window.sendMessage = function protectedAwareSend() {
                const chatId = window.currentChatId;
                if (!chatId || !ui.isProtected(chatId)) {
                    return legacySend.apply(this, arguments);
                }
                const input = document.getElementById('messageInput');
                const text = input ? input.value.trim() : '';
                if (!text) {
                    return undefined;
                }
                input.value = '';
                return ui.send(chatId, text)
                    .then(() => { if (typeof window.loadMessages === 'function') window.loadMessages(chatId); })
                    .catch((error) => {
                        if (typeof window.showToast === 'function') window.showToast(error.message, 'error');
                    });
            };
        }

        // Fill in decrypted text after the renderer has drawn the rows.
        const legacyRender = window.renderMessages;
        if (typeof legacyRender === 'function') {
            window.renderMessages = function protectedAwareRender() {
                const result = legacyRender.apply(this, arguments);
                const chatId = window.currentChatId;
                if (chatId && ui.isProtected(chatId)) {
                    ui.decorateMessages(chatId).catch(() => {});
                    ui.showSafetyNumber(chatId).catch(() => {});
                }
                return result;
            };
        }

        window.PmProtectedUi = ui;
        return ui;
    }

    const api = { createProtectedUi, install };
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window === 'object') {
        window.PmProtectedUiFactory = api;
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => { install(); }, { once: true });
        } else {
            install();
        }
    }
})();
