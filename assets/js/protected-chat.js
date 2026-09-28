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
            const existing = await storage.get(WRAP_KEY_ID);
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
            await storage.put(WRAP_KEY_ID, key);
            return key;
        }

        async function saveSession() {
            if (!session) {
                return;
            }
            const key = await wrappingKey();
            const iv = randomBytes(12);
            const sealed = await subtle.encrypt({ name: 'AES-GCM', iv }, key, session.export_state());
            await storage.put(STATE_ID, {
                iv,
                sealed: new Uint8Array(sealed),
                identity,
                signaturePublicKey,
            });
        }

        async function loadSession() {
            const record = await storage.get(STATE_ID);
            if (!record) {
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

            for (const entry of claim.key_packages) {
                const added = session.add_member(groupId, fromBase64(entry.key_package));
                await post('api/chat.php', {
                    action: 'post_handshake',
                    chat_id: chatId,
                    kind: 2,
                    epoch: 0,
                    payload: toBase64(added.commit),
                });
                await post('api/chat.php', {
                    action: 'post_handshake',
                    chat_id: chatId,
                    kind: 3,
                    epoch: 0,
                    payload: toBase64(concat(lengthPrefixed(added.welcome), added.ratchet_tree)),
                });
            }

            await saveSession();
            return { groupId: toBase64(groupId) };
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
                }
            }

            await saveSession();
            return {
                lastSequence,
                groupId: joinedGroupId ? toBase64(joinedGroupId) : null,
            };
        }

        async function send(chatId, groupIdBase64, text) {
            await requireSession();
            const groupId = fromBase64(groupIdBase64);
            const sealed = session.seal(groupId, encoder.encode(text));
            await saveSession();

            const response = await post('api/chat.php', {
                action: 'send_protected_message',
                chat_id: chatId,
                envelope: {
                    envelope_version: 1,
                    content_type: 1,
                    epoch: 0,
                    sender_leaf: 0,
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
            const messages = [];
            for (const envelope of response.envelopes) {
                let text = null;
                let readable = true;
                try {
                    const opened = session.open(groupId, fromBase64(envelope.ciphertext));
                    text = decoder.decode(opened);
                } catch (error) {
                    readable = false;
                }
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
                messages.push({
                    messageId: envelope.message_id,
                    senderId: envelope.sender_id,
                    createdAt: envelope.created_at,
                    contentType: envelope.content_type,
                    readable,
                    text,
                    attachment,
                });
            }

            await saveSession();
            return messages;
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
            await saveSession();

            const response = await post('api/chat.php', {
                action: 'send_protected_message',
                chat_id: chatId,
                envelope: {
                    envelope_version: 1,
                    content_type: 2,
                    epoch: 0,
                    sender_leaf: 0,
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

            // 24 characters from an unambiguous alphabet, ~124 bits.
            const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
            const picks = randomBytes(24);
            let passphrase = '';
            for (let index = 0; index < picks.length; index++) {
                passphrase += alphabet[picks[index] % alphabet.length];
                if (index % 6 === 5 && index !== picks.length - 1) {
                    passphrase += '-';
                }
            }

            const salt = randomBytes(16);
            const iv = randomBytes(12);
            const key = await deriveRecoveryKey(passphrase, salt);
            const sealed = new Uint8Array(
                await subtle.encrypt({ name: 'AES-GCM', iv }, key, session.export_state())
            );

            return {
                passphrase,
                file: {
                    format: 'pm-recovery-v1',
                    kdf: 'PBKDF2-SHA512',
                    iterations: RECOVERY_ITERATIONS,
                    salt: toBase64(salt),
                    iv: toBase64(iv),
                    identity: toBase64(identity),
                    signature_public_key: toBase64(signaturePublicKey),
                    state: toBase64(sealed),
                },
            };
        }

        /** Restore a device from a recovery file and its passphrase. */
        async function restoreFromRecoveryFile(file, passphrase) {
            if (!file || file.format !== 'pm-recovery-v1') {
                throw new Error('That is not a recovery file this version understands');
            }
            const key = await deriveRecoveryKey(passphrase, fromBase64(file.salt), file.iterations);
            let plain;
            try {
                plain = await subtle.decrypt(
                    { name: 'AES-GCM', iv: fromBase64(file.iv) },
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

        return { resume, enroll, startConversation, syncGroup, send, receive, sendAttachment, openAttachment, safetyNumber, createRecoveryFile, restoreFromRecoveryFile };
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

    async function browserClient() {
        const mls = await import('../vendor/mls/pm_mls.js');
        await mls.default();
        return createProtectedClient({
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
