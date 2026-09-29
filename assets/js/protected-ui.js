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
            await refreshProtectionPins(chatId);
            if (!(await active.resume())) {
                return null;
            }
            // After a reload the page-local map is empty, but the client kept
            // what it needs sealed on the device: which group this conversation
            // uses and how far it had read. Without this the interface could not
            // rejoin a conversation it was already in, because the welcome that
            // carried the group id has long since been consumed.
            let known = conversations.get(chatId);
            if (!known) {
                const recalled = await active.recallConversation(chatId);
                if (recalled) {
                    known = {
                        groupId: recalled.groupId,
                        lastSequence: recalled.lastSequence || 0,
                        lastMessageId: recalled.lastMessageId || 0,
                        opened: new Map(),
                    };
                    conversations.set(chatId, known);
                }
            }

            const sync = await active.syncGroup(chatId, known ? known.lastSequence || 0 : 0);
            if (!sync.groupId && !known) {
                return null;
            }
            const record = known || { lastMessageId: 0, opened: new Map() };
            record.groupId = sync.groupId || record.groupId;
            record.lastSequence = sync.lastSequence;
            conversations.set(chatId, record);

            // A device revoked in settings keeps the keys it already holds, so
            // somebody still in the conversation has to publish a removal.
            //
            // This runs on every open, not once per record: a review found the
            // boolean that used to guard it, which meant a device revoked after
            // the first open stayed a member for the life of the page. A failed
            // check also blocks sending, because a pending removal is exactly
            // when one should not keep talking.
            if (record.groupId) {
                try {
                    // The directory's own hash chain, checked against what this
                    // device last saw. A server that rewrites history it has
                    // already shown is caught here; one that has always lied to
                    // this device is not, which is why the safety number exists.
                    await active.verifyDirectory();
                    record.directoryCheckFailed = false;
                } catch (error) {
                    record.directoryCheckFailed = true;
                    notify(translate('protected.directory_changed',
                        'The device directory does not match what this device saw before. Compare safety numbers before continuing.'));
                }

                // A device the other account enrolled after this conversation
                // started has to be admitted or that person reads on one device
                // and not another.
                try {
                    const mine = Number(currentAccountId());
                    const others = (await active.participants(chatId))
                        .filter((userId) => userId !== mine);
                    if (others.length > 0) {
                        await admitNewDevices(chatId, record.groupId, others);
                    }
                } catch (error) {
                    notify(translate('protected.admit_failed',
                        'A device of the other account could not be added to this conversation.'));
                }

                try {
                    await active.enforceRevocations(chatId, record.groupId);
                    record.revocationCheckFailed = false;
                } catch (error) {
                    record.revocationCheckFailed = true;
                    notify(translate('protected.revocation_check_failed',
                        'Could not check whether a revoked device is still in this conversation.'));
                }
            }
            return record.groupId;
        }

        function currentAccountId() {
            return adapters.accountId !== undefined
                ? adapters.accountId
                : (typeof window === 'object' && window ? window.currentUserId : null);
        }

        /**
         * Whether a conversation is protected.
         *
         * The row's flag comes from the server, and a review pointed out what that
         * means for the stated adversary: answering `is_protected: false` routed
         * the next message to the plaintext client. Protection is irreversible, so
         * anything this device has already established outranks what the server
         * says now. The page-local record is consulted first because this runs on
         * every keystroke path; `refreshProtectionPins()` fills it from the sealed
         * store when a conversation is opened.
         */
        function isProtected(chatId) {
            const known = conversations.get(chatId);
            if (known && (known.protected === true || known.groupId)) {
                return true;
            }
            if (pinnedProtected.has(Number(chatId))) {
                return true;
            }
            const row = doc.querySelector('.chat-item[data-chat-id="' + chatId + '"]');
            return !!row && row.dataset.protected === 'true';
        }

        /** Conversations this device has itself established as protected. */
        const pinnedProtected = new Set();

        async function refreshProtectionPins(chatId) {
            try {
                const client = await ensureClient();
                if (await client.knownProtected(chatId)) {
                    pinnedProtected.add(Number(chatId));
                }
            } catch (error) {
                // A device with no session has nothing pinned yet.
            }
        }

        /** Send through the encrypting client instead of the plaintext path. */
        async function send(chatId, text) {
            const groupId = await adoptConversation(chatId);
            if (!groupId) {
                throw new Error(translate('protected.not_joined',
                    'This device has not joined that protected conversation yet'));
            }
            const client = await ensureClient();

            // Fail closed rather than send into a membership we are unsure of:
            // a revocation we could not check, a change we could not publish, or
            // a fork the engine reported.
            const record = conversations.get(chatId);
            if (record && record.revocationCheckFailed === true) {
                throw new Error(translate('protected.revocation_check_failed',
                    'Could not check whether a revoked device is still in this conversation.'));
            }
            if (record && record.directoryCheckFailed === true) {
                throw new Error(translate('protected.directory_changed',
                    'The device directory does not match what this device saw before. Compare safety numbers before continuing.'));
            }
            const blocked = client.sendingBlocked(chatId, groupId);
            if (blocked) {
                notify(translate('protected.rejoin_required',
                    'This conversation has to be rejoined before anything else is sent.'));
                throw new Error(blocked);
            }
            return client.send(chatId, groupId, text);
        }

        /**
         * Send a file into a protected conversation.
         *
         * The bytes are encrypted here and the server stores ciphertext it
         * cannot scan, which is why the banner says so in every language.
         */
        async function sendAttachment(chatId, file) {
            const groupId = await adoptConversation(chatId);
            if (!groupId) {
                throw new Error(translate('protected.not_joined',
                    'This device has not joined that protected conversation yet'));
            }
            const client = await ensureClient();
            const blocked = client.sendingBlocked(chatId, groupId);
            if (blocked) {
                throw new Error(blocked);
            }
            const bytes = new Uint8Array(await file.arrayBuffer());
            return client.sendAttachment(chatId, groupId, file.name, bytes);
        }

        /** Decrypt an attachment and hand it to the person as a download. */
        async function openAttachment(descriptor) {
            const client = await ensureClient();
            const opened = await client.openAttachment(descriptor);
            if (typeof doc.createElement !== 'function' || typeof URL === 'undefined') {
                return opened;
            }
            const url = URL.createObjectURL(new Blob([opened.bytes], { type: 'application/octet-stream' }));
            const link = doc.createElement('a');
            link.href = url;
            link.download = opened.name || 'attachment';
            link.rel = 'noopener';
            if (doc.body && typeof doc.body.appendChild === 'function') {
                doc.body.appendChild(link);
                link.click();
                doc.body.removeChild(link);
            }
            // Revoked on the next turn: the click has to have happened first.
            setTimeout(() => URL.revokeObjectURL(url), 0);
            return opened;
        }

        /**
         * Admit any device of the other participants that is not in the group.
         *
         * A device enrolled after a conversation started would otherwise never
         * be able to read it, and `admitDevices()` had no caller at all. Run when
         * a conversation opens, and quiet when there is nothing to do.
         */
        async function admitNewDevices(chatId, groupId, otherUserIds) {
            const client = await ensureClient();
            let admitted = 0;
            for (const userId of otherUserIds) {
                try {
                    const result = await client.admitDevices(chatId, groupId, userId);
                    admitted += result.admitted || 0;
                } catch (error) {
                    // A device with no key packages left, or a key that does not
                    // match its enrolment, must be visible rather than silently
                    // excluded: the other person would simply never see messages.
                    notify(translate('protected.admit_failed',
                        'A device of the other account could not be added to this conversation.'));
                }
            }
            return admitted;
        }

        /** Produce a recovery file and hand it to the person with its passphrase. */
        async function downloadRecoveryFile() {
            const client = await ensureClient();
            if (!(await client.resume())) {
                throw new Error(translate('protected.not_enrolled',
                    'This device is not set up for protected conversations yet'));
            }
            const recovery = await client.createRecoveryFile();
            if (typeof doc.createElement === 'function' && typeof URL !== 'undefined') {
                const url = URL.createObjectURL(new Blob(
                    [JSON.stringify(recovery.file, null, 2)],
                    { type: 'application/json' }
                ));
                const link = doc.createElement('a');
                link.href = url;
                link.download = 'protected-conversations-recovery.json';
                link.rel = 'noopener';
                if (doc.body && typeof doc.body.appendChild === 'function') {
                    doc.body.appendChild(link);
                    link.click();
                    doc.body.removeChild(link);
                }
                setTimeout(() => URL.revokeObjectURL(url), 0);
            }
            return recovery;
        }

        /** Restore this device from a recovery file the person chose. */
        async function restoreFromFile(file, passphrase) {
            const client = await ensureClient();
            const text = await file.text();
            let parsed;
            try {
                parsed = JSON.parse(text);
            } catch (error) {
                throw new Error(translate('protected.recovery_unreadable',
                    'That file is not a recovery file this version understands'));
            }
            return client.restoreFromRecoveryFile(parsed, passphrase.trim());
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
                record.opened.set(message.messageId, {
                    attachment: message.attachment || null,
                    text: message.readable ? message.text : null,
                    // MLS's answer about authorship, kept so the row can say so
                    // when it disagrees with what the server claimed.
                    authorship: message.authorship,
                });
            }
            for (const [messageId, opened] of record.opened) {
                const row = doc.querySelector('.message-row[data-message-id="' + messageId + '"]');
                if (!row) {
                    continue;
                }
                const body = row.querySelector('.message-text');
                if (!body || body.dataset.protectedFilled === 'true') {
                    continue;
                }
                body.textContent = opened.text === null
                    ? translate('protected.unreadable', 'This message cannot be read on this device')
                    : opened.text;
                body.dataset.protectedFilled = 'true';
                if (opened.text === null) {
                    body.classList.add('message-unreadable');
                }

                // An attachment: the row has no text, so it gets a button that
                // decrypts and downloads. Without this a protected attachment
                // arrived and could not be opened at all.
                if (opened.attachment && body.dataset.protectedAttachment !== 'true') {
                    body.dataset.protectedAttachment = 'true';
                    body.textContent = '';
                    const button = doc.createElement('button');
                    button.type = 'button';
                    button.className = 'protected-attachment';
                    button.textContent = opened.attachment.name ||
                        translate('protected.attachment', 'Encrypted file');
                    button.addEventListener('click', () => {
                        openAttachment(opened.attachment).catch((error) => notify(error.message));
                    });
                    body.appendChild(button);
                }

                // A message whose signature does not belong to the account the
                // server named is displayed with that said plainly. Hiding the
                // text would lose information; presenting it as authentic would
                // be a lie.
                if (opened.authorship === 'mismatched' || opened.authorship === 'unverified') {
                    const warning = doc.createElement('span');
                    warning.className = 'message-authorship-warning';
                    warning.textContent = opened.authorship === 'mismatched'
                        ? translate('protected.author_mismatch',
                            'This message was signed by a different account than the one shown.')
                        : translate('protected.author_unverified',
                            'The sender of this message could not be verified.');
                    body.appendChild(warning);
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
            sendAttachment,
            openAttachment,
            admitNewDevices,
            downloadRecoveryFile,
            restoreFromFile,
            showSafetyNumber,
            decorateMessages,
            refreshProtectionPins,
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
            clientFactory: () => window.PmProtected.browserClient(window.currentUserId || null),
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

        // The recovery file needs somewhere to be asked for. Two globals, bound
        // externally by csp-events.js because the policy denies inline handlers.
        window.pmShowRecoveryDialog = function pmShowRecoveryDialog() {
            const modal = document.getElementById('protectedRecoveryModal');
            if (!modal || typeof window.bootstrap !== 'object' || !window.bootstrap.Modal) {
                return;
            }
            // The passphrase from a previous visit must not still be on screen.
            const holder = document.getElementById('protectedRecoveryResult');
            const passphrase = document.getElementById('protectedRecoveryPassphrase');
            if (holder && passphrase) {
                passphrase.textContent = '';
                holder.hidden = true;
            }
            window.bootstrap.Modal.getOrCreateInstance(modal).show();
        };

        window.pmDownloadRecoveryFile = function pmDownloadRecoveryFile() {
            return ui.downloadRecoveryFile()
                .then((recovery) => {
                    const passphrase = document.getElementById('protectedRecoveryPassphrase');
                    const holder = document.getElementById('protectedRecoveryResult');
                    if (passphrase && holder) {
                        // Shown once, never stored: the file is useless without it
                        // and the server never sees either.
                        passphrase.textContent = recovery.passphrase;
                        holder.hidden = false;
                    }
                    return recovery;
                })
                .catch((error) => {
                    if (typeof window.showToast === 'function') window.showToast(error.message, 'error');
                });
        };

        window.pmRestoreFromRecoveryFile = function pmRestoreFromRecoveryFile() {
            const input = document.getElementById('protectedRecoveryFile');
            const passphrase = document.getElementById('protectedRestorePassphrase');
            const file = input && input.files && input.files[0];
            if (!file || !passphrase || !passphrase.value.trim()) {
                if (typeof window.showToast === 'function') {
                    window.showToast(
                        (window.PmI18n && window.PmI18n.t
                            ? window.PmI18n.t('protected.recovery_needs_both')
                            : null) || 'Choose the recovery file and type its passphrase.',
                        'error'
                    );
                }
                return undefined;
            }
            return ui.restoreFromFile(file, passphrase.value)
                .then(() => {
                    passphrase.value = '';
                    input.value = '';
                    if (typeof window.showToast === 'function') {
                        window.showToast(
                            (window.PmI18n && window.PmI18n.t
                                ? window.PmI18n.t('protected.recovery_restored')
                                : null) || 'This device was restored from the recovery file.',
                            'success'
                        );
                    }
                })
                .catch((error) => {
                    if (typeof window.showToast === 'function') window.showToast(error.message, 'error');
                });
        };

        // Attachments in a protected conversation go through the encrypting
        // client. Until now `sendAttachment()` existed with nothing calling it,
        // so picking a file in a protected chat took the legacy upload path —
        // which the server now refuses outright, leaving the person with an
        // error and no way to send a file at all.
        const legacyFileSelect = window.handleFileSelect;
        if (typeof legacyFileSelect === 'function') {
            window.handleFileSelect = function protectedAwareFileSelect(event) {
                const chatId = window.currentChatId;
                if (!chatId || !ui.isProtected(chatId)) {
                    return legacyFileSelect.apply(this, arguments);
                }
                const input = event && event.target;
                const file = input && input.files && input.files[0];
                if (!file) {
                    return undefined;
                }
                if (input) {
                    input.value = '';
                }
                return ui.sendAttachment(chatId, file)
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
