// Protected conversations: the browser half.
//
// This ties three things together: the MLS engine in assets/vendor/mls/, the
// key transport in api/chat.php, and local storage of the device's own state.
//
// WHAT THIS IS NOT. It is not finished and it has not been independently
// reviewed. Nothing here entitles the interface to claim end-to-end encryption;
// see docs/security/e2ee-readiness.md for what is still required.
//
// THREAT MODEL, PLAINLY. Device state is written to IndexedDB wrapped with a
// non-extractable AES-GCM key, so at rest it is inert without that key and
// cannot be read out by a script that only reaches storage. While the tab is
// open the material is live in WebAssembly memory, so a cross-site scripting
// bug defeats this. The content security policy and the no-markup renderer are
// what stand in the way of that; the boundary this design can honestly defend
// is the server operator's database and backups, not a compromised browser.
(function () {
    'use strict';

    const DB_NAME = 'pm-protected';
    const DB_VERSION = 1;
    const STORE = 'device';
    const WRAP_KEY_ID = 'wrapping-key';
    const STATE_ID = 'session-state';
    // PBKDF2 is what a browser offers without more WebAssembly; the generated
    // passphrase is what actually carries the strength here.
    const RECOVERY_ITERATIONS = 600000;

    /**
     * Everything the client touches is injected, so the whole flow can be
     * driven in a test without a browser: storage, crypto, transport and the
     * MLS module.
     */
    function createProtectedClient(adapters) {
        // Which account this device state belongs to.
        //
        // A review switched accounts in one browser and watched the second
        // account resume the first one's signer, because the store used one
        // fixed key per origin. The account is now part of every identifier and
        // is sealed inside the record, so a mismatch cannot silently pass.
        const accountId = adapters.accountId === undefined || adapters.accountId === null
            ? null
            : String(adapters.accountId);
        const scope = accountId === null ? '' : ':' + accountId;
        const wrapKeyId = WRAP_KEY_ID + scope;
        const stateId = STATE_ID + scope;

        const storage = adapters.storage;
        const subtle = adapters.crypto.subtle;
        const randomBytes = adapters.randomBytes;
        const post = adapters.post;
        const mls = adapters.mls;

        let session = null;
        let identity = null;
        let signaturePublicKey = null;

        const encoder = new TextEncoder();
        const decoder = new TextDecoder();

        // ---- local key storage ---------------------------------------------

        async function wrappingKey() {
            const existing = await storage.get(wrapKeyId);
            if (existing) {
                return existing;
            }
            // Non-extractable: the key object can encrypt and decrypt but its
            // bytes cannot be read back out, so a script that reaches IndexedDB
            // still cannot lift the session state off the device.
            const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
                'encrypt',
                'decrypt',
            ]);
            await storage.put(wrapKeyId, key);
            return key;
        }

        /**
         * A small sealed store beside the session, for two things a reload
         * otherwise destroys.
         *
         * A review found both. The chat-to-group mapping lived only in a page
         * `Map`, so after a reload the interface could not tell which MLS group
         * a conversation used — and the welcome that would have told it has
         * already been consumed. And an MLS application message decrypts exactly
         * once, so every message read before the reload became permanently
         * unreadable: a protected conversation showed no history at all.
         *
         * Plaintext at rest is a real cost, so it is sealed with the same
         * non-extractable key as the session and bounded per conversation. The
         * alternative is a messenger that forgets every conversation when the tab
         * closes, which nobody would use and which would push people back to the
         * plaintext path.
         */
        const HISTORY_LIMIT = 500;

        async function readSealed(id, fallback) {
            const record = await storage.get(id);
            if (!record) {
                return fallback;
            }
            if ((record.accountId ?? null) !== accountId) {
                return fallback;
            }
            try {
                const key = await wrappingKey();
                const plain = await subtle.decrypt({ name: 'AES-GCM', iv: record.iv }, key, record.sealed);
                return JSON.parse(decoder.decode(new Uint8Array(plain)));
            } catch (error) {
                // A record we cannot open is a record we cannot trust.
                return fallback;
            }
        }

        async function writeSealed(id, value) {
            const key = await wrappingKey();
            const iv = randomBytes(12);
            const sealed = await subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                encoder.encode(JSON.stringify(value))
            );
            await storage.put(id, { iv, sealed: new Uint8Array(sealed), accountId });
        }

        const conversationsId = 'conversations' + scope;
        const directoryHeadId = 'directory-head' + scope;
        const historyId = (chatId) => 'history' + scope + ':' + chatId;

        /** Which MLS group each conversation uses, and how far we have read. */
        async function rememberConversation(chatId, groupIdBase64, cursors) {
            const known = await readSealed(conversationsId, {});
            const existing = known[String(chatId)] || {};
            known[String(chatId)] = {
                groupId: groupIdBase64 || existing.groupId || null,
                lastSequence: (cursors && cursors.lastSequence !== undefined)
                    ? cursors.lastSequence
                    : (existing.lastSequence || 0),
                lastMessageId: (cursors && cursors.lastMessageId !== undefined)
                    ? cursors.lastMessageId
                    : (existing.lastMessageId || 0),
            };
            await writeSealed(conversationsId, known);
            return known[String(chatId)];
        }

        /** What we knew about a conversation before the page reloaded. */
        async function recallConversation(chatId) {
            const known = await readSealed(conversationsId, {});
            return known[String(chatId)] || null;
        }

        async function rememberOpened(chatId, entries) {
            if (entries.length === 0) {
                return;
            }
            const id = historyId(chatId);
            const history = await readSealed(id, {});
            for (const entry of entries) {
                history[String(entry.messageId)] = {
                    text: entry.text,
                    authorship: entry.authorship,
                    senderId: entry.senderId,
                    claimedSenderId: entry.claimedSenderId,
                    attachment: entry.attachment || null,
                    contentType: entry.contentType,
                    createdAt: entry.createdAt,
                };
            }
            // Bounded: keep the most recent by message id.
            const ids = Object.keys(history).map(Number).sort((left, right) => left - right);
            while (ids.length > HISTORY_LIMIT) {
                delete history[String(ids.shift())];
            }
            await writeSealed(id, history);
        }

        /** Messages this device has already opened, by message id. */
        async function recallOpened(chatId) {
            return readSealed(historyId(chatId), {});
        }

        async function saveSession() {
            if (!session) {
                return;
            }
            const key = await wrappingKey();
            const iv = randomBytes(12);
            const sealed = await subtle.encrypt({ name: 'AES-GCM', iv }, key, session.export_state());
            await storage.put(stateId, {
                iv,
                sealed: new Uint8Array(sealed),
                identity,
                signaturePublicKey,
                accountId,
            });
        }

        async function loadSession() {
            const record = await storage.get(stateId);
            if (!record) {
                return null;
            }
            // Belt as well as braces: the key is scoped, and the record says
            // whose it is. Refusing here means an account switch cannot inherit
            // another account's device, even if the store were keyed wrongly.
            if ((record.accountId ?? null) !== accountId) {
                return null;
            }
            const key = await wrappingKey();
            const plain = await subtle.decrypt({ name: 'AES-GCM', iv: record.iv }, key, record.sealed);
            identity = record.identity;
            signaturePublicKey = record.signaturePublicKey;
            return mls.MlsSession.restore(
                new Uint8Array(plain),
                record.signaturePublicKey,
                record.identity
            );
        }

        // ---- device lifecycle ----------------------------------------------

        /** Restore this device's session, or report that there is not one yet. */
        async function resume() {
            if (session) {
                return true;
            }
            session = await loadSession();
            return session !== null;
        }

        /**
         * Create this device's identity and register it with the server.
         *
         * The caller supplies the current password and a second factor because
         * the server demands both: enrolling a device adds a key that can read
         * future messages, so it is held to the same bar as disabling 2FA.
         */
        async function enroll(options) {
            if (await resume()) {
                throw new Error('This device is already enrolled');
            }

            session = new mls.MlsSession();
            identity = encoder.encode(options.identity);
            signaturePublicKey = session.create_identity(options.identity);

            const keyPackages = [];
            for (let index = 0; index < (options.keyPackageCount || 10); index++) {
                keyPackages.push(toBase64(session.create_key_package()));
            }

            const response = await post('api/settings.php', {
                action: 'enroll_device',
                current_password: options.currentPassword,
                second_factor_code: options.secondFactorCode,
                label: options.label || null,
                public_id: toBase64(randomBytes(32)),
                signature_public_key: toBase64(signaturePublicKey),
                credential: toBase64(identity),
                cipher_suite: mls.ciphersuite(),
                key_packages: keyPackages,
            });

            if (!response || response.success !== true) {
                // Do not keep half-enrolled state around: a session whose device
                // the server does not know cannot participate, and keeping it
                // would make the next attempt look like a duplicate.
                session = null;
                identity = null;
                signaturePublicKey = null;
                throw new Error((response && response.message) || 'Enrollment failed');
            }

            await saveSession();
            return { deviceId: response.device_id, keyPackagesStored: response.key_packages_stored };
        }

        // ---- conversations --------------------------------------------------

        /**
         * Turn a conversation protected and admit another account's devices.
         *
         * Every live device of the other account must be admitted, or that
         * person reads the conversation on one device and not another. If any
         * of them is out of key packages the server says so, and this refuses
         * rather than forming a group that silently excludes it.
         */
        async function startConversation(chatId, otherUserId) {
            await requireSession();

            const claim = await post('api/chat.php', {
                action: 'claim_key_packages',
                user_id: otherUserId,
                chat_id: chatId,
            });
            if (!claim || claim.success !== true) {
                throw new Error((claim && claim.message) || 'Could not claim key packages');
            }
            const exhausted = claim.key_packages.filter((entry) => entry.exhausted);
            if (exhausted.length > 0) {
                throw new Error('A device of that account has no key packages left; it could not be added');
            }

            const groupId = session.create_group();
            const protect = await post('api/chat.php', {
                action: 'protect_chat',
                chat_id: chatId,
                group_id: toBase64(groupId),
                cipher_suite: mls.ciphersuite(),
            });
            if (!protect || protect.success !== true) {
                throw new Error((protect && protect.message) || 'Could not protect the conversation');
            }

            await admit(chatId, groupId, claim.key_packages);
            await saveSession();
            return { groupId: toBase64(groupId) };
        }

        /**
         * Admit another account's devices to a conversation that is already
         * protected — a device enrolled after the conversation started, which
         * would otherwise never be able to read it.
         *
         * Existing members pick the commit up through `syncGroup`; without that
         * they would stay in the old epoch and stop being able to read.
         */
        async function admitDevices(chatId, groupIdBase64, otherUserId) {
            await requireSession();

            const claim = await post('api/chat.php', {
                action: 'claim_key_packages',
                user_id: otherUserId,
                chat_id: chatId,
            });
            if (!claim || claim.success !== true) {
                throw new Error((claim && claim.message) || 'Could not claim key packages');
            }
            const exhausted = claim.key_packages.filter((entry) => entry.exhausted);
            if (exhausted.length > 0) {
                throw new Error('A device of that account has no key packages left; it could not be added');
            }

            const result = await admit(chatId, fromBase64(groupIdBase64), claim.key_packages);
            await saveSession();
            return result;
        }

        /**
         * Add each claimed key package and publish what the others need.
         *
         * A device already in the group is skipped rather than added again: the
         * directory hands out a package for every live device of an account,
         * including ones already here, and adding one twice would give it two
         * leaves.
         */
        async function admit(chatId, groupId, keyPackages) {
            let admitted = 0;
            let skipped = 0;
            for (const entry of keyPackages) {
                const material = fromBase64(entry.key_package);
                const key = mls.MlsSession.key_package_signature_key(material);

                // The directory says this device signs with one key; the key
                // package it published is signed with another. Admitting it
                // would create a member that revocation can never find, because
                // revocation looks the device up by the advertised key. Refuse.
                if (toBase64(key) !== entry.signature_public_key) {
                    throw new Error(
                        'A device published a key package that does not match its enrolled key, ' +
                        'so it was not added'
                    );
                }
                if (session.has_member(groupId, key)) {
                    skipped++;
                    continue;
                }
                const added = session.add_member(groupId, material);
                // The epoch the group is in once this commit has been applied,
                // not a placeholder: the server orders handshakes by it.
                const epoch = Number(session.epoch(groupId));

                // Our own state already moved to the new epoch when the commit
                // was created, so an unpublished commit leaves everybody else
                // behind. A review found both posts going unchecked while the
                // caller was told the device had been admitted. Publication
                // failure is now an error, and the conversation is marked as
                // needing republication so nothing is sent from a state the
                // others never saw.
                const publishedCommit = await post('api/chat.php', {
                    action: 'post_handshake',
                    chat_id: chatId,
                    kind: 2,
                    epoch,
                    payload: toBase64(added.commit),
                });
                if (!publishedCommit || publishedCommit.success !== true) {
                    unpublished.add(chatId);
                    throw new Error(
                        (publishedCommit && publishedCommit.message) ||
                        'The group change could not be published, so this conversation needs to be rejoined'
                    );
                }
                const publishedWelcome = await post('api/chat.php', {
                    action: 'post_handshake',
                    chat_id: chatId,
                    kind: 3,
                    epoch,
                    payload: toBase64(concat(lengthPrefixed(added.welcome), added.ratchet_tree)),
                });
                if (!publishedWelcome || publishedWelcome.success !== true) {
                    unpublished.add(chatId);
                    throw new Error(
                        (publishedWelcome && publishedWelcome.message) ||
                        'The invitation could not be published, so the new device cannot join yet'
                    );
                }
                admitted++;
            }
            return { admitted, skipped };
        }

        /** Apply any group changes the server is holding for this conversation. */
        async function syncGroup(chatId, afterSequence) {
            await requireSession();
            const response = await post('api/chat.php', {
                action: 'get_handshakes',
                chat_id: chatId,
                after_sequence: afterSequence || 0,
            });
            if (!response || response.success !== true) {
                throw new Error((response && response.message) || 'Could not fetch group updates');
            }

            let joinedGroupId = null;
            let applied = 0;
            let lastSequence = afterSequence || 0;
            for (const entry of response.handshakes) {
                lastSequence = entry.sequence;
                const payload = fromBase64(entry.payload);
                if (entry.kind === 3) {
                    // A welcome, carrying the ratchet tree the joiner needs.
                    const split = readLengthPrefixed(payload);
                    try {
                        joinedGroupId = session.join_group(split.head, split.tail);
                    } catch (error) {
                        // A welcome addressed to another device is not an error
                        // for this one; it simply cannot open it.
                    }
                    continue;
                }

                // Commits and proposals. Applying these is not optional: when
                // somebody else changes the membership they move to a new
                // epoch, and a device that skips the commit stays behind and
                // can no longer read anything. The queue is in order, so a
                // commit that arrives before our own welcome is simply for a
                // group we are not in yet.
                if (session.apply_handshake(payload) === 'applied') {
                    applied++;
                }
            }

            await saveSession();

            // Remember which group this conversation uses. The welcome that
            // carried it is consumed, so a reload cannot learn it again.
            const recalled = await recallConversation(chatId);
            const groupIdBase64 = joinedGroupId
                ? toBase64(joinedGroupId)
                : (recalled ? recalled.groupId : null);
            await rememberConversation(chatId, groupIdBase64, { lastSequence });

            return {
                lastSequence,
                applied,
                groupId: groupIdBase64,
            };
        }

        /**
         * Conversations this device must not send into.
         *
         * Two ways in: a group change we could not publish, so the others are
         * behind a state we have already left; and a fork the engine reported,
         * where we cannot say who is still a member. Both mean the same thing
         * for sending — stop, and say why.
         */
        const unpublished = new Set();

        function assertSendable(chatId, groupIdBase64) {
            if (unpublished.has(chatId)) {
                throw new Error(
                    'A group change in this conversation was never published, so it must be rejoined ' +
                    'before anything else is sent'
                );
            }
            if (groupIdBase64 && session.has_diverged(fromBase64(groupIdBase64))) {
                throw new Error(
                    'This conversation has diverged from the rest of the group, so it must be rejoined ' +
                    'before anything else is sent'
                );
            }
        }

        /** Why this device may not send, or null when it may. */
        function sendingBlocked(chatId, groupIdBase64) {
            try {
                assertSendable(chatId, groupIdBase64);
                return null;
            } catch (error) {
                return error.message;
            }
        }

        /**
         * Where in the group a message was produced.
         *
         * The server keeps this to order handshakes and to refuse an epoch that
         * has gone backwards, so sending a constant would quietly turn that
         * check off. `epoch()` crosses from WebAssembly as a BigInt, which
         * JSON.stringify refuses outright, hence the conversion.
         */
        function position(groupId) {
            return {
                epoch: Number(session.epoch(groupId)),
                sender_leaf: session.own_leaf(groupId),
            };
        }

        async function send(chatId, groupIdBase64, text) {
            await requireSession();
            assertSendable(chatId, groupIdBase64);
            const groupId = fromBase64(groupIdBase64);
            const sealed = session.seal(groupId, encoder.encode(text));
            const where = position(groupId);
            await saveSession();

            const response = await post('api/chat.php', {
                action: 'send_protected_message',
                chat_id: chatId,
                envelope: {
                    envelope_version: 1,
                    content_type: 1,
                    epoch: where.epoch,
                    sender_leaf: where.sender_leaf,
                    group_id: groupIdBase64,
                    aad_digest: toBase64(new Uint8Array(32)),
                    ciphertext: toBase64(sealed),
                },
            });
            if (!response || response.success !== true) {
                throw new Error((response && response.message) || 'Could not send');
            }
            return { messageId: response.message_id };
        }

        /**
         * Fetch and open messages. A message that cannot be opened is reported
         * as such rather than dropped: silently showing a shorter conversation
         * than the one that exists is worse than saying a message is unreadable.
         */
        async function receive(chatId, groupIdBase64, afterMessageId) {
            await requireSession();
            const response = await post('api/chat.php', {
                action: 'get_protected_envelopes',
                chat_id: chatId,
                after_message_id: afterMessageId || 0,
            });
            if (!response || response.success !== true) {
                throw new Error((response && response.message) || 'Could not fetch messages');
            }

            const groupId = fromBase64(groupIdBase64);
            // Who each signature key belongs to, so authorship can come from the
            // protocol rather than from a column the server controls.
            const directory = await participantKeyIndex(chatId);
            // What this device has opened before. An MLS application message
            // decrypts once, so without this a reload loses the conversation.
            const remembered = await recallOpened(chatId);
            const messages = [];
            const toRemember = [];
            for (const envelope of response.envelopes) {
                const previously = remembered[String(envelope.message_id)];
                if (previously) {
                    messages.push({
                        messageId: envelope.message_id,
                        senderId: previously.senderId,
                        claimedSenderId: previously.claimedSenderId,
                        senderDeviceId: null,
                        senderKey: null,
                        authorship: previously.authorship,
                        createdAt: previously.createdAt || envelope.created_at,
                        contentType: previously.contentType,
                        readable: previously.text !== null || previously.attachment !== null,
                        text: previously.text,
                        attachment: previously.attachment,
                        fromHistory: true,
                    });
                    continue;
                }

                let text = null;
                let readable = true;
                let senderKey = null;
                try {
                    const opened = session.open(groupId, fromBase64(envelope.ciphertext));
                    text = decoder.decode(opened.plaintext);
                    senderKey = opened.sender_key ? toBase64(opened.sender_key) : null;
                } catch (error) {
                    readable = false;
                }

                // MLS says who wrote it. The row also says who wrote it. If they
                // disagree, the row is wrong — and a review showed that changing
                // that one field was enough to re-attribute authenticated
                // content, so the disagreement has to be visible rather than
                // resolved in the server's favour.
                const authenticated = senderKey ? directory.get(senderKey) : undefined;
                const claimedSenderId = Number(envelope.sender_id);
                const authorship = !readable
                    ? 'unknown'
                    : (authenticated === undefined
                        ? 'unverified'
                        : (authenticated.userId === claimedSenderId ? 'verified' : 'mismatched'));
                let attachment = null;
                if (readable && envelope.content_type === 2) {
                    try {
                        const descriptor = JSON.parse(text);
                        if (descriptor && descriptor.kind === 'attachment') {
                            attachment = descriptor;
                            text = null;
                        }
                    } catch (error) {
                        readable = false;
                        text = null;
                    }
                }
                const message = {
                    messageId: envelope.message_id,
                    // The authenticated author where there is one; the claim is
                    // kept separately so a caller cannot confuse them.
                    senderId: authenticated ? authenticated.userId : null,
                    claimedSenderId,
                    senderDeviceId: authenticated ? authenticated.deviceId : null,
                    senderKey,
                    authorship,
                    createdAt: envelope.created_at,
                    contentType: envelope.content_type,
                    readable,
                    text,
                    attachment,
                    fromHistory: false,
                };
                messages.push(message);
                if (readable) {
                    toRemember.push(message);
                }
            }

            await rememberOpened(chatId, toRemember);
            const highest = messages.reduce(
                (top, message) => Math.max(top, Number(message.messageId) || 0),
                0
            );
            if (highest > 0) {
                await rememberConversation(chatId, groupIdBase64, { lastMessageId: highest });
            }
            await saveSession();
            return messages;
        }

        /**
         * Walk the directory's hash chain and check it against what we last saw.
         *
         * The chain existed from the start and **no client verified it**, which a
         * review pointed out and the documentation had glossed. Verified here it
         * does what it was built for: it catches a server that rewrites history
         * it has already shown us. It is still not key transparency — a server
         * that lies consistently to a client which has never seen the truth is
         * not caught by any amount of chain walking — and the code says so rather
         * than implying otherwise.
         *
         * `entryDigest = SHA-256(uint64 seq || previous || uint16 type || payload)`,
         * matching `DeviceDirectory::entryDigest()`.
         */
        async function verifyDirectory() {
            const head = await readSealed(directoryHeadId, { seq: 0, digest: null });
            let previous = head.digest === null ? new Uint8Array(32) : fromBase64(head.digest);
            let seq = head.seq;
            let checked = 0;

            for (let page = 0; page < 50; page++) {
                const response = await post('api/chat.php', {
                    action: 'get_directory_log',
                    after_seq: seq,
                    limit: 200,
                });
                if (!response || response.success !== true) {
                    throw new Error((response && response.message) || 'Could not read the device directory log');
                }
                const entries = response.entries || [];
                if (entries.length === 0) {
                    break;
                }

                for (const entry of entries) {
                    if (Number(entry.seq) !== seq + 1) {
                        throw new Error('The device directory has a gap at entry ' + entry.seq);
                    }
                    const claimedPrevious = fromBase64(entry.previous_digest);
                    if (toBase64(claimedPrevious) !== toBase64(previous)) {
                        throw new Error(
                            'The device directory does not continue from what this device already saw: ' +
                            'entry ' + entry.seq + ' names a different history'
                        );
                    }

                    const expected = await directoryEntryDigest(
                        Number(entry.seq),
                        claimedPrevious,
                        Number(entry.entry_type),
                        fromBase64(entry.payload_digest)
                    );
                    if (toBase64(expected) !== entry.entry_digest) {
                        throw new Error('The device directory entry ' + entry.seq + ' does not match its digest');
                    }

                    previous = expected;
                    seq = Number(entry.seq);
                    checked++;
                }
            }

            await writeSealed(directoryHeadId, { seq, digest: toBase64(previous) });
            return { verified: checked, head: seq };
        }

        async function directoryEntryDigest(seq, previous, entryType, payloadDigest) {
            const input = new Uint8Array(8 + previous.length + 2 + payloadDigest.length);
            // uint64 big-endian, the way PHP's pack('J') writes it.
            const view = new DataView(input.buffer);
            view.setUint32(0, Math.floor(seq / 0x100000000));
            view.setUint32(4, seq >>> 0);
            input.set(previous, 8);
            view.setUint16(8 + previous.length, entryType);
            input.set(payloadDigest, 8 + previous.length + 2);
            return new Uint8Array(await subtle.digest('SHA-256', input));
        }

        /**
         * signature key (base64) -> { userId, deviceId, revoked } for everyone in
         * this conversation.
         *
         * Cached per call chain rather than for the session: a device revoked a
         * moment ago must not keep its place in this map.
         */
        async function participantKeyIndex(chatId) {
            const response = await post('api/chat.php', {
                action: 'list_participant_devices',
                chat_id: chatId,
            });
            if (!response || response.success !== true) {
                throw new Error((response && response.message) || 'Could not read the device directory');
            }
            const index = new Map();
            for (const device of response.devices) {
                index.set(device.signature_public_key, {
                    userId: Number(device.user_id),
                    deviceId: Number(device.device_id),
                    revoked: device.revoked === true,
                });
            }
            return index;
        }

        // ---- attachments ----------------------------------------------------

        /**
         * Encrypt a file, upload the ciphertext, and send the key inside the
         * sealed message.
         *
         * The content key lives in the envelope, which is itself encrypted to
         * the group, so the server holds bytes it cannot decrypt and a key it
         * never sees. It also cannot scan those bytes for malware, which is why
         * the interface says so.
         */
        async function sendAttachment(chatId, groupIdBase64, fileName, bytes) {
            await requireSession();
            assertSendable(chatId, groupIdBase64);

            const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
                'encrypt',
                'decrypt',
            ]);
            const iv = randomBytes(12);
            const ciphertext = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));

            const upload = await post('api/chat.php', {
                action: 'put_encrypted_blob',
                chat_id: chatId,
                ciphertext: toBase64(ciphertext),
            });
            if (!upload || upload.success !== true) {
                throw new Error((upload && upload.message) || 'Could not upload the attachment');
            }

            const descriptor = {
                kind: 'attachment',
                blob_id: upload.blob_id,
                name: fileName,
                size: bytes.length,
                key: toBase64(new Uint8Array(await subtle.exportKey('raw', key))),
                iv: toBase64(iv),
                sha256: upload.sha256,
            };

            const groupId = fromBase64(groupIdBase64);
            const sealed = session.seal(groupId, encoder.encode(JSON.stringify(descriptor)));
            const where = position(groupId);
            await saveSession();

            const response = await post('api/chat.php', {
                action: 'send_protected_message',
                chat_id: chatId,
                envelope: {
                    envelope_version: 1,
                    content_type: 2,
                    epoch: where.epoch,
                    sender_leaf: where.sender_leaf,
                    group_id: groupIdBase64,
                    aad_digest: toBase64(new Uint8Array(32)),
                    ciphertext: toBase64(sealed),
                },
            });
            if (!response || response.success !== true) {
                throw new Error((response && response.message) || 'Could not send the attachment');
            }
            return { messageId: response.message_id, blobId: upload.blob_id };
        }

        /**
         * Fetch and decrypt an attachment previously described by a message.
         *
         * What actually protects this is AES-GCM: the key travels inside the
         * sealed envelope, so a server that substitutes the blob cannot produce
         * bytes that authenticate. The digest comparison below is a cheap check
         * against accidental corruption and a mismatched reference -- it is NOT
         * a defence against a malicious server, because the same server supplies
         * it and could return a matching one for whatever it served.
         */
        async function openAttachment(descriptor) {
            const response = await post('api/chat.php', {
                action: 'get_encrypted_blob',
                blob_id: descriptor.blob_id,
            });
            if (!response || response.success !== true) {
                throw new Error((response && response.message) || 'Could not fetch the attachment');
            }
            if (response.sha256 !== descriptor.sha256) {
                throw new Error('That attachment is not the one the message described');
            }

            const key = await subtle.importKey(
                'raw',
                fromBase64(descriptor.key),
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );
            const plain = await subtle.decrypt(
                { name: 'AES-GCM', iv: fromBase64(descriptor.iv) },
                key,
                fromBase64(response.ciphertext)
            );
            return { name: descriptor.name, bytes: new Uint8Array(plain) };
        }

        // ---- recovery --------------------------------------------------------

        /**
         * Produce a recovery file for this device's state.
         *
         * The passphrase is generated for the person rather than chosen by
         * them, because the key derivation available in a browser without
         * WebAssembly is PBKDF2, which is materially weaker against a GPU than
         * Argon2id. A ~128-bit generated passphrase does not depend on the
         * derivation being strong.
         *
         * Download-only by design: the server never receives this. Handing it
         * an encrypted blob would make the passphrase the only barrier for
         * whoever holds the database.
         */
        async function createRecoveryFile() {
            await requireSession();

            // 24 characters from a 31-symbol unambiguous alphabet: 118.9 bits.
            //
            // Rejection sampling, not `% 31`: a byte modulo 31 makes eight
            // symbols likelier than the other twenty-three, which a review
            // measured as costing three bits of min-entropy. Cheap to avoid, and
            // a biased generator is the kind of thing nobody notices later.
            const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
            const limit = 256 - (256 % alphabet.length);   // 248: a whole number of alphabets
            let passphrase = '';
            let taken = 0;
            while (taken < 24) {
                for (const byte of randomBytes(32)) {
                    if (byte >= limit) {
                        continue;   // would bias the result; draw again
                    }
                    passphrase += alphabet[byte % alphabet.length];
                    taken++;
                    if (taken % 6 === 0 && taken !== 24) {
                        passphrase += '-';
                    }
                    if (taken === 24) {
                        break;
                    }
                }
            }

            const salt = randomBytes(16);
            const iv = randomBytes(12);
            const key = await deriveRecoveryKey(passphrase, salt);

            // The header travels as authenticated data, not merely alongside the
            // ciphertext. A review pointed out that the identity, the public key
            // and the KDF parameters sat outside the AEAD, so they could be
            // rewritten without the file failing to open.
            const header = {
                format: 'pm-recovery-v2',
                kdf: 'PBKDF2-SHA512',
                iterations: RECOVERY_ITERATIONS,
                salt: toBase64(salt),
                iv: toBase64(iv),
                identity: toBase64(identity),
                signature_public_key: toBase64(signaturePublicKey),
                account_id: accountId,
            };
            const sealed = new Uint8Array(
                await subtle.encrypt(
                    { name: 'AES-GCM', iv, additionalData: encoder.encode(canonicalHeader(header)) },
                    key,
                    session.export_state()
                )
            );

            return {
                passphrase,
                file: Object.assign({}, header, { state: toBase64(sealed) }),
            };
        }

        /** Restore a device from a recovery file and its passphrase. */
        async function restoreFromRecoveryFile(file, passphrase) {
            if (!file || file.format !== 'pm-recovery-v2') {
                throw new Error('That is not a recovery file this version understands');
            }
            if (file.kdf !== 'PBKDF2-SHA512') {
                throw new Error('That recovery file uses a key derivation this version does not support');
            }
            // An attacker-chosen iteration count is a way to make a browser sit
            // still for an hour. Bound it, and require at least what we write.
            const iterations = Number(file.iterations);
            if (!Number.isInteger(iterations) ||
                iterations < RECOVERY_ITERATIONS ||
                iterations > RECOVERY_ITERATIONS * 10) {
                throw new Error('That recovery file declares an unusable key derivation cost');
            }
            if ((file.account_id ?? null) !== accountId) {
                throw new Error('That recovery file belongs to a different account');
            }

            const header = {
                format: file.format,
                kdf: file.kdf,
                iterations,
                salt: file.salt,
                iv: file.iv,
                identity: file.identity,
                signature_public_key: file.signature_public_key,
                account_id: file.account_id ?? null,
            };
            const key = await deriveRecoveryKey(passphrase, fromBase64(file.salt), iterations);
            let plain;
            try {
                plain = await subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: fromBase64(file.iv),
                        additionalData: encoder.encode(canonicalHeader(header)),
                    },
                    key,
                    fromBase64(file.state)
                );
            } catch (error) {
                throw new Error('That passphrase does not open this recovery file');
            }

            identity = fromBase64(file.identity);
            signaturePublicKey = fromBase64(file.signature_public_key);
            session = mls.MlsSession.restore(new Uint8Array(plain), signaturePublicKey, identity);
            await saveSession();
            return true;
        }

        async function deriveRecoveryKey(passphrase, salt, iterations) {
            const material = await subtle.importKey(
                'raw',
                encoder.encode(passphrase),
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );
            return subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt,
                    iterations: iterations || RECOVERY_ITERATIONS,
                    hash: 'SHA-512',
                },
                material,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        }

        /**
         * The number two people can compare out of band to check nobody has
         * been substituted. Only meaningful if someone actually compares it.
         */
        async function safetyNumber(groupIdBase64) {
            await requireSession();
            return session.safety_number(fromBase64(groupIdBase64));
        }

        async function requireSession() {
            if (!(await resume())) {
                throw new Error('This device is not enrolled for protected conversations');
            }
        }

        /**
         * Remove any member of this conversation that belongs to a revoked
         * device, and publish the removals.
         *
         * Revoking a device in settings stops it being offered new key packages.
         * It does **not** stop a device that is already inside a group from
         * reading: it holds those keys, and no server action can take them back,
         * because the server has none. Somebody still in the conversation has to
         * publish a removal, which is what this does — best effort, since only a
         * current member can do it.
         */
        async function enforceRevocations(chatId, groupIdBase64) {
            await requireSession();
            const response = await post('api/chat.php', {
                action: 'list_participant_devices',
                chat_id: chatId,
            });
            if (!response || response.success !== true) {
                throw new Error((response && response.message) || 'Could not check device revocations');
            }

            const groupId = fromBase64(groupIdBase64);
            const mine = toBase64(session.identity_key());
            const removed = [];
            for (const device of response.devices) {
                if (!device.revoked || device.signature_public_key === mine) {
                    continue;
                }
                if (!session.has_member(groupId, fromBase64(device.signature_public_key))) {
                    continue;
                }
                await removeMember(chatId, groupIdBase64, device.signature_public_key);
                removed.push(device.device_id);
            }
            return { removed };
        }

        /**
         * Remove a device from a protected conversation and publish the commit
         * the remaining members need.
         *
         * The removed device can still read what it already received — that is
         * inherent, it holds those keys — but not what is sent afterwards.
         */
        async function removeMember(chatId, groupIdBase64, signatureKeyBase64) {
            await requireSession();
            const groupId = fromBase64(groupIdBase64);
            const commit = session.remove_member(groupId, fromBase64(signatureKeyBase64));
            const where = position(groupId);
            await saveSession();

            const response = await post('api/chat.php', {
                action: 'post_handshake',
                chat_id: chatId,
                kind: 2,
                epoch: where.epoch,
                payload: toBase64(commit),
            });
            if (!response || response.success !== true) {
                // The removal took effect locally the moment it was created, so
                // an unpublished one leaves us alone on a branch where the device
                // is gone while everyone else still has it.
                unpublished.add(chatId);
                throw new Error((response && response.message) || 'Could not publish the removal');
            }
            return { epoch: where.epoch };
        }

        return { resume, enroll, startConversation, admitDevices, syncGroup, send, receive, sendAttachment, openAttachment, safetyNumber, createRecoveryFile, restoreFromRecoveryFile, removeMember, enforceRevocations, sendingBlocked, recallConversation, rememberConversation, verifyDirectory };
    }

    /**
     * The header exactly as it is authenticated: fixed field order, so the two
     * sides cannot disagree about what was covered.
     */
    function canonicalHeader(header) {
        return [
            header.format,
            header.kdf,
            String(header.iterations),
            header.salt,
            header.iv,
            header.identity,
            header.signature_public_key,
            header.account_id === null || header.account_id === undefined ? '' : String(header.account_id),
        ].join('\n');
    }

    // ---- small helpers -----------------------------------------------------

    function toBase64(bytes) {
        let binary = '';
        const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        for (let index = 0; index < view.length; index++) {
            binary += String.fromCharCode(view[index]);
        }
        return btoa(binary);
    }

    function fromBase64(value) {
        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index++) {
            bytes[index] = binary.charCodeAt(index);
        }
        return bytes;
    }

    function concat(first, second) {
        const out = new Uint8Array(first.length + second.length);
        out.set(first, 0);
        out.set(second, first.length);
        return out;
    }

    /** Four-byte big-endian length, then the payload. */
    function lengthPrefixed(bytes) {
        const out = new Uint8Array(4 + bytes.length);
        new DataView(out.buffer).setUint32(0, bytes.length, false);
        out.set(bytes, 4);
        return out;
    }

    function readLengthPrefixed(bytes) {
        const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
        return {
            head: bytes.slice(4, 4 + length),
            tail: bytes.slice(4 + length),
        };
    }

    // ---- browser wiring ----------------------------------------------------

    function indexedDbStorage() {
        function open() {
            return new Promise(function (resolve, reject) {
                const request = indexedDB.open(DB_NAME, DB_VERSION);
                request.onupgradeneeded = function () {
                    request.result.createObjectStore(STORE);
                };
                request.onsuccess = function () { resolve(request.result); };
                request.onerror = function () { reject(request.error); };
            });
        }

        function transact(mode, run) {
            return open().then(function (db) {
                return new Promise(function (resolve, reject) {
                    const tx = db.transaction(STORE, mode);
                    const request = run(tx.objectStore(STORE));
                    request.onsuccess = function () { resolve(request.result); };
                    request.onerror = function () { reject(request.error); };
                });
            });
        }

        return {
            get: (key) => transact('readonly', (store) => store.get(key)),
            put: (key, value) => transact('readwrite', (store) => store.put(value, key)),
        };
    }

    async function browserClient(accountId) {
        const mls = await import('../vendor/mls/pm_mls.js');
        await mls.default();
        return createProtectedClient({
            // Whose device this is. Without it, two accounts sharing a browser
            // share a signer.
            accountId: accountId === undefined ? (window.currentUserId || null) : accountId,
            storage: indexedDbStorage(),
            crypto: window.crypto,
            randomBytes: (length) => window.crypto.getRandomValues(new Uint8Array(length)),
            post: async function (url, body) {
                const response = await fetch(url, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                    body: JSON.stringify(body),
                });
                try {
                    return await response.json();
                } catch (error) {
                    return null;
                }
            },
            mls,
        });
    }

    const api = { createProtectedClient, browserClient };
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window === 'object') {
        window.PmProtected = api;
    }
})();
