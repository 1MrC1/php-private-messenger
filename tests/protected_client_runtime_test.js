'use strict';

// Drives the protected-conversation client end to end with the real MLS build
// and a simulated server, so the whole path is exercised without a browser:
// enroll two devices, protect a conversation, admit the other device, send,
// receive, and survive a reload.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');

global.btoa = (binary) => Buffer.from(binary, 'binary').toString('base64');
global.atob = (value) => Buffer.from(value, 'base64').toString('binary');

const { createProtectedClient } = require('../assets/js/protected-chat.js');

/** Storage that behaves like IndexedDB for our purposes and nothing more. */
function memoryStorage() {
    const values = new Map();
    return {
        get: async (key) => values.get(key),
        put: async (key, value) => { values.set(key, value); },
        size: () => values.size,
        raw: values,
    };
}

/**
 * A stand-in for the server: it keeps the same things the real one does and,
 * crucially, only ever sees what the real one would.
 */
function fakeServer() {
    const devices = new Map();          // userId -> [{deviceId, keyPackages: []}]
    const handshakes = new Map();       // chatId -> [{sequence, kind, payload}]
    const envelopes = new Map();        // chatId -> [{message_id, ciphertext, ...}]
    const protectedChats = new Set();
    const blobs = [];
    const digests = new Map();
    let nextDeviceId = 1;
    let nextMessageId = 1;
    const seen = [];

    async function post(url, body) {
        seen.push({ url, action: body.action });
        switch (body.action) {
            case 'enroll_device': {
                const userId = body.__userId;
                const list = devices.get(userId) || [];
                const device = { deviceId: nextDeviceId++, keyPackages: body.key_packages.slice() };
                list.push(device);
                devices.set(userId, list);
                return { success: true, device_id: device.deviceId, key_packages_stored: device.keyPackages.length };
            }
            case 'claim_key_packages': {
                const list = devices.get(body.user_id) || [];
                return {
                    success: true,
                    key_packages: list.map((device) => {
                        const next = device.keyPackages.shift();
                        return next
                            ? { device_id: device.deviceId, key_package: next, exhausted: false }
                            : { device_id: device.deviceId, key_package: null, exhausted: true };
                    }),
                };
            }
            case 'protect_chat':
                protectedChats.add(body.chat_id);
                return { success: true, chat_id: body.chat_id };
            case 'post_handshake': {
                const list = handshakes.get(body.chat_id) || [];
                list.push({ sequence: list.length + 1, kind: body.kind, epoch: body.epoch, payload: body.payload });
                handshakes.set(body.chat_id, list);
                return { success: true, sequence: list.length };
            }
            case 'get_handshakes': {
                const list = handshakes.get(body.chat_id) || [];
                return { success: true, handshakes: list.filter((e) => e.sequence > (body.after_sequence || 0)) };
            }
            case 'send_protected_message': {
                if (!protectedChats.has(body.chat_id)) {
                    return { success: false, error_code: 'chat_not_protected', message: 'not protected' };
                }
                const list = envelopes.get(body.chat_id) || [];
                const row = {
                    message_id: nextMessageId++,
                    sender_id: body.__userId,
                    created_at: '2026-09-28 12:00:00',
                    ciphertext: body.envelope.ciphertext,
                    content_type: body.envelope.content_type,
                };
                list.push(row);
                envelopes.set(body.chat_id, list);
                return { success: true, message_id: row.message_id };
            }
            case 'put_encrypted_blob': {
                const id = blobs.length + 1;
                blobs.push({ id, chat_id: body.chat_id, ciphertext: body.ciphertext });
                const digest = require('node:crypto').createHash('sha256')
                    .update(Buffer.from(body.ciphertext, 'base64')).digest('base64');
                digests.set(id, digest);
                return { success: true, blob_id: id, byte_size: Buffer.from(body.ciphertext, 'base64').length, sha256: digest };
            }
            case 'get_encrypted_blob': {
                const blob = blobs.find((entry) => entry.id === body.blob_id);
                if (!blob) return { success: false, error_code: 'unknown_blob', message: 'unknown' };
                return { success: true, blob_id: blob.id, ciphertext: blob.ciphertext, sha256: digests.get(blob.id) };
            }
            case 'get_protected_envelopes': {
                const list = envelopes.get(body.chat_id) || [];
                return { success: true, envelopes: list.filter((e) => e.message_id > (body.after_message_id || 0)) };
            }
            default:
                return { success: false, message: 'unknown action ' + body.action };
        }
    }

    return { post, devices, envelopes, handshakes, seen, blobs };
}

(async () => {
    const mls = await import(path.join(__dirname, '..', 'assets', 'vendor', 'mls', 'pm_mls.js'));
    await mls.default({ module_or_path: fs.readFileSync(path.join(__dirname, '..', 'assets', 'vendor', 'mls', 'pm_mls_bg.wasm')) });

    const server = fakeServer();
    const build = (userId, storage) => createProtectedClient({
        storage,
        crypto: webcrypto,
        randomBytes: (length) => webcrypto.getRandomValues(new Uint8Array(length)),
        post: (url, body) => server.post(url, Object.assign({ __userId: userId }, body)),
        mls,
    });

    const adaStorage = memoryStorage();
    const miraStorage = memoryStorage();
    const ada = build(1, adaStorage);
    const mira = build(2, miraStorage);

    // ---- enrollment --------------------------------------------------------

    assert.equal(await ada.resume(), false, 'a fresh device has no session');
    const adaEnrolled = await ada.enroll({
        identity: 'ada@example', label: 'Laptop',
        currentPassword: 'secret', secondFactorCode: '123456', keyPackageCount: 3,
    });
    assert.ok(adaEnrolled.deviceId > 0, 'enrollment returns a device id');
    await mira.enroll({
        identity: 'mira@example', label: 'Phone',
        currentPassword: 'secret', secondFactorCode: '654321', keyPackageCount: 3,
    });
    console.log('PASS: two devices enroll and publish key packages');

    assert.ok(server.seen.some((call) => call.url === 'api/settings.php' && call.action === 'enroll_device'),
        'enrollment goes to the settings endpoint, which is the one behind the credential gate');
    console.log('PASS: enrollment uses the credential-gated endpoint');

    // The wrapping key must not be extractable, or storing state gains nothing.
    const wrapping = await adaStorage.get('wrapping-key');
    assert.equal(wrapping.extractable, false, 'the wrapping key is non-extractable');
    await assert.rejects(() => webcrypto.subtle.exportKey('raw', wrapping),
        'the wrapping key cannot be exported');
    console.log('PASS: session state is wrapped with a non-extractable key');

    const stored = await adaStorage.get('session-state');
    assert.ok(stored.sealed.length > 0 && stored.iv.length === 12, 'state is stored sealed with an IV');
    assert.ok(!Buffer.from(stored.sealed).includes(Buffer.from('ada@example')),
        'the stored state does not expose the identity in the clear');
    console.log('PASS: stored state is ciphertext, not the session');

    // ---- a protected conversation -----------------------------------------

    const started = await ada.startConversation(42, 2);
    assert.ok(started.groupId, 'protecting a conversation yields a group');
    console.log('PASS: a conversation is protected and the other device admitted');

    const sync = await mira.syncGroup(42, 0);
    assert.ok(sync.groupId, 'the invited device joins from the welcome the server relayed');
    console.log('PASS: the invited device joins from the relayed welcome');

    const secret = 'the studio is free from six';
    await ada.send(42, started.groupId, secret);

    // What the server holds must not be the message.
    const storedEnvelopes = server.envelopes.get(42);
    assert.equal(storedEnvelopes.length, 1, 'the server stored one envelope');
    assert.ok(!Buffer.from(storedEnvelopes[0].ciphertext, 'base64').includes(Buffer.from(secret)),
        'the server holds ciphertext that does not contain the message');
    console.log('PASS: the server stores ciphertext, not the message');

    const received = await mira.receive(42, sync.groupId, 0);
    assert.equal(received.length, 1);
    assert.equal(received[0].readable, true);
    assert.equal(received[0].text, secret, 'the recipient reads the message');
    console.log('PASS: the recipient opens it');

    // ---- a reload ----------------------------------------------------------

    const miraAgain = build(2, miraStorage);
    assert.equal(await miraAgain.resume(), true, 'a new client resumes from stored state');
    await ada.send(42, started.groupId, 'and bring the cello');
    const afterReload = await miraAgain.receive(42, sync.groupId, received[0].messageId);
    assert.equal(afterReload[0].text, 'and bring the cello',
        'the resumed device keeps decrypting');
    console.log('PASS: a device resumes after a reload and keeps decrypting');

    // ---- an outsider -------------------------------------------------------

    const outsider = build(3, memoryStorage());
    await outsider.enroll({
        identity: 'mallory@example', currentPassword: 'secret', secondFactorCode: '111111', keyPackageCount: 1,
    });
    const outsiderView = await outsider.receive(42, started.groupId, 0);
    assert.ok(outsiderView.every((message) => message.readable === false && message.text === null),
        'an account outside the group cannot read the conversation');
    console.log('PASS: an outsider fetching the same envelopes reads nothing');

    // ---- refusing to leave a device behind ---------------------------------

    // The outsider published exactly one key package. Spend it, then try again:
    // the second attempt must refuse rather than form a group without them.
    await ada.startConversation(44, 3);
    await assert.rejects(
        () => ada.startConversation(45, 3),
        /no key packages left/,
        'a conversation is refused rather than formed without a device that cannot be admitted'
    );
    console.log('PASS: exhausted key packages refuse the conversation instead of excluding a device');

    // ---- encrypted attachments --------------------------------------------

    const fileBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const sentAttachment = await ada.sendAttachment(42, started.groupId, 'score.pdf', fileBytes);
    assert.ok(sentAttachment.blobId > 0, 'the attachment is uploaded');

    const storedBlob = Buffer.from(server.blobs[0].ciphertext, 'base64');
    assert.ok(!storedBlob.includes(Buffer.from(fileBytes)),
        'the stored blob does not contain the file');
    assert.ok(!Buffer.from(server.envelopes.get(42).slice(-1)[0].ciphertext, 'base64')
        .includes(Buffer.from('score.pdf')),
        'the file name is inside the sealed envelope, not visible to the server');
    console.log('PASS: the server stores an encrypted blob and cannot see the file or its name');

    const withAttachment = await miraAgain.receive(42, sync.groupId, sentAttachment.messageId - 1);
    const descriptor = withAttachment.find((message) => message.attachment);
    assert.ok(descriptor, 'the recipient sees an attachment message');
    assert.equal(descriptor.attachment.name, 'score.pdf', 'the file name travels inside the envelope');
    assert.equal(descriptor.text, null, 'an attachment is not presented as text');

    const opened = await miraAgain.openAttachment(descriptor.attachment);
    assert.deepEqual(Array.from(opened.bytes), Array.from(fileBytes),
        'the recipient recovers the exact file');
    console.log('PASS: the recipient decrypts the attachment back to the original bytes');

    // A server that swaps the blob must not be able to produce something that
    // decrypts. Note it also controls the digest it reports, so the digest is
    // not what saves us here -- AES-GCM authentication is, because the key came
    // through the sealed envelope rather than from the server.
    server.blobs[0].ciphertext = Buffer.from('tampered payload that is the wrong thing').toString('base64');
    await assert.rejects(() => miraAgain.openAttachment(descriptor.attachment),
        (error) => error instanceof Error || error instanceof DOMException,
        'a swapped blob fails to decrypt rather than yielding plausible bytes');
    console.log('PASS: a substituted attachment fails authentication');

    console.log('Protected client runtime tests passed.');
})().catch((error) => {
    console.error(error);
    process.exit(1);
});
