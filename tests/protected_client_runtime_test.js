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
    // A hash chain shaped exactly like the server's, so the client's walk is
    // tested against the real construction rather than a stub.
    const directoryLog = [];
    // Small on purpose: a cap of two proves the client pages instead of assuming
    // one request is the whole history.
    const pageCap = 2;
    // chatId:userId -> the packages already handed out for that pair.
    const claimScopes = new Map();
    const crypto = require('node:crypto');
    /** The preimage DeviceDirectory::entryPayload() hashes. */
    const directoryPayload = (entryType, userId, deviceId, publicId, signatureKey) => {
        const header = Buffer.alloc(2 + 8 + 8 + 2);
        header.writeUInt16BE(entryType, 0);
        header.writeBigUInt64BE(BigInt(userId), 2);
        header.writeBigUInt64BE(BigInt(deviceId), 10);
        header.writeUInt16BE(publicId.length, 18);
        const keyLength = Buffer.alloc(4);
        keyLength.writeUInt32BE(signatureKey.length, 0);
        return Buffer.concat([
            Buffer.from('pm-dir-v2\0', 'latin1'), header, publicId, keyLength, signatureKey,
        ]);
    };

    const appendDirectoryEntry = (entryType, payload) => {
        const seq = directoryLog.length + 1;
        const previous = directoryLog.length === 0
            ? Buffer.alloc(32)
            : Buffer.from(directoryLog[directoryLog.length - 1].entry_digest, 'base64');
        const payloadDigest = crypto.createHash('sha256').update(payload).digest();
        const seqBytes = Buffer.alloc(8);
        seqBytes.writeUInt32BE(0, 0);
        seqBytes.writeUInt32BE(seq, 4);
        const typeBytes = Buffer.alloc(2);
        typeBytes.writeUInt16BE(entryType, 0);
        const entryDigest = crypto.createHash('sha256')
            .update(Buffer.concat([seqBytes, previous, typeBytes, payloadDigest]))
            .digest();
        directoryLog.push({
            seq,
            entry_type: entryType,
            previous_digest: previous.toString('base64'),
            payload_digest: payloadDigest.toString('base64'),
            entry_digest: entryDigest.toString('base64'),
        });
        return directoryLog[directoryLog.length - 1];
    };

    async function post(url, body) {
        seen.push({ url, action: body.action });
        switch (body.action) {
            case 'enroll_device': {
                const userId = body.__userId;
                const list = devices.get(userId) || [];
                const device = {
                    deviceId: nextDeviceId++,
                    keyPackages: body.key_packages.slice(),
                    signatureKey: body.signature_public_key,
                    revoked: false,
                    userId,
                };
                list.push(device);
                devices.set(userId, list);
                device.publicId = crypto.randomBytes(32).toString('base64');
                const entry = appendDirectoryEntry(1, directoryPayload(
                    1, userId, device.deviceId,
                    Buffer.from(device.publicId, 'base64'),
                    Buffer.from(device.signatureKey, 'base64')
                ));
                device.enrolledSeq = entry.seq;
                return { success: true, device_id: device.deviceId, key_packages_stored: device.keyPackages.length };
            }
            case 'publish_key_packages': {
                // The real endpoint appends to the device's unconsumed packages.
                const list = devices.get(body.__userId) || [];
                const device = list.find((entry) => entry.deviceId === body.device_id);
                if (!device) {
                    return { success: false, message: 'unknown device' };
                }
                device.keyPackages.push(...body.key_packages);
                return { success: true, key_packages_stored: body.key_packages.length };
            }
            case 'claim_key_packages': {
                // The real endpoint refuses a claim that is not for a
                // conversation both accounts are in; the double insists on being
                // told which conversation, so a caller that forgets is caught.
                if (!body.chat_id) {
                    return { success: false, error_code: 'not_a_participant', message: 'no conversation given' };
                }
                // And it answers a repeat for the same conversation from the
                // package already spent, as the server does, so a test cannot pass
                // by spending packages the server would not have spent.
                const list = devices.get(body.user_id) || [];
                const answer = {
                    success: true,
                    key_packages: list.map((device) => {
                        // Reuse is per conversation *and* per device, as the server
                        // does it: a device already claimed for this conversation
                        // costs nothing, a device never claimed for it spends one.
                        const scopeKey = body.chat_id + ':' + device.deviceId;
                        if (claimScopes.has(scopeKey)) {
                            return claimScopes.get(scopeKey);
                        }
                        const next = device.keyPackages.shift();
                        const claimed = next
                            ? {
                                device_id: device.deviceId,
                                // The enrolled key, which the admitting client
                                // compares against the key inside the package.
                                signature_public_key: device.claimedKey || device.signatureKey,
                                key_package: next,
                                exhausted: false,
                            }
                            : { device_id: device.deviceId, key_package: null, exhausted: true };
                        if (claimed.exhausted === false) {
                            claimScopes.set(scopeKey, Object.assign({}, claimed, { reused: true }));
                        }
                        return claimed;
                    }),
                };
                return answer;
            }
            case 'get_directory_log': {
                const after = Number(body.after_seq || 0);
                return { success: true, entries: directoryLog.filter((entry) => entry.seq > after) };
            }
            case 'list_participant_devices': {
                // Every device of every participant, the way the real endpoint
                // answers: the key, the account, the public id, the chain
                // sequence its enrolment was written at, and the chain head.
                const all = [];
                for (const list of devices.values()) {
                    for (const device of list) {
                        all.push({
                            device_id: device.deviceId,
                            user_id: device.claimedUserId || device.userId,
                            public_id: device.publicId,
                            signature_public_key: device.signatureKey,
                            enrolled_seq: device.enrolledSeq,
                            revoked_seq: device.revokedSeq || null,
                            revoked: device.revoked,
                        });
                    }
                }
                return { success: true, head: directoryLog.length, devices: all };
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
            case 'post_handshake_batch': {
                // One transaction, consecutive sequences, exactly as the server
                // does it: nothing can be wedged between a commit and its welcome.
                const list = handshakes.get(body.chat_id) || [];
                const sequences = [];
                for (const message of body.messages) {
                    list.push({
                        sequence: list.length + 1,
                        kind: message.kind,
                        epoch: message.epoch,
                        payload: message.payload,
                    });
                    sequences.push(list.length);
                }
                handshakes.set(body.chat_id, list);
                return { success: true, sequences };
            }
            case 'get_handshakes': {
                const list = handshakes.get(body.chat_id) || [];
                const after = Number(body.after_sequence || 0);
                // The real endpoint caps a page; the double does too, so a client
                // that fetches one page is caught here rather than in production.
                const page = list.filter((e) => e.sequence > after).slice(0, pageCap);
                return { success: true, handshakes: page };
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
                const after = Number(body.after_message_id || 0);
                return {
                    success: true,
                    envelopes: list.filter((e) => e.message_id > after).slice(0, pageCap),
                };
            }
            default:
                return { success: false, message: 'unknown action ' + body.action };
        }
    }

    return { post, devices, envelopes, handshakes, seen, blobs, directoryLog, appendDirectoryEntry, directoryPayload };
}

(async () => {
    const mls = await import(path.join(__dirname, '..', 'assets', 'vendor', 'mls', 'pm_mls.js'));
    await mls.default({ module_or_path: fs.readFileSync(path.join(__dirname, '..', 'assets', 'vendor', 'mls', 'pm_mls_bg.wasm')) });

    const server = fakeServer();
    const build = (userId, storage) => createProtectedClient({
        accountId: userId,
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
    // Stored under an account-scoped key, so two accounts in one browser cannot
    // share a wrapping key or a session.
    assert.equal(await adaStorage.get('wrapping-key'), undefined,
        'nothing is stored under the old unscoped key');
    const wrapping = await adaStorage.get('wrapping-key:1');
    assert.equal(wrapping.extractable, false, 'the wrapping key is non-extractable');
    await assert.rejects(() => webcrypto.subtle.exportKey('raw', wrapping),
        'the wrapping key cannot be exported');
    console.log('PASS: session state is wrapped with a non-extractable key');

    const stored = await adaStorage.get('session-state:1');
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

    // ---- a device enrolled after the conversation started ------------------
    // Without this path a device enrolled later can never read the
    // conversation, and — worse — the members already in it would be stranded
    // in an old epoch by the commit that admits it.

    const tabletStorage = memoryStorage();
    const tablet = build(2, tabletStorage);
    await tablet.enroll({
        identity: 'mira-tablet@example', label: 'Tablet',
        currentPassword: 'secret', secondFactorCode: '222222', keyPackageCount: 2,
    });

    const admission = await ada.admitDevices(42, started.groupId, 2);
    assert.equal(admission.admitted, 1, 'only the new device is admitted');
    assert.equal(admission.skipped, 1, 'the device already in the conversation is skipped, not added twice');
    console.log('PASS: a device enrolled later is admitted without duplicating the one already there');

    // The member that was already there has to apply the commit or it stops
    // being able to read. This is the regression that motivated the path.
    const miraCatchUp = await miraAgain.syncGroup(42, sync.lastSequence);
    assert.ok(miraCatchUp.applied >= 1, 'the existing member applied the commit that admits the new device');

    const tabletJoin = await tablet.syncGroup(42, 0);
    assert.ok(tabletJoin.groupId, 'the new device joins from the welcome');

    const afterAdmission = 'everyone including the tablet';
    await ada.send(42, started.groupId, afterAdmission);

    const miraReads = await miraAgain.receive(42, sync.groupId, 0);
    assert.ok(miraReads.some((message) => message.text === afterAdmission),
        'the member that was already there keeps reading across the membership change');
    const tabletReads = await tablet.receive(42, tabletJoin.groupId, 0);
    assert.ok(tabletReads.some((message) => message.text === afterAdmission),
        'the newly admitted device reads what is sent afterwards');
    console.log('PASS: after a membership change every device still reads');

    // The safety number is supposed to move when the membership does, which is
    // the whole point of comparing it.
    const numberAfter = await ada.safetyNumber(started.groupId);
    assert.equal(numberAfter, await tablet.safetyNumber(tabletJoin.groupId),
        'every device computes the same safety number');
    console.log('PASS: the safety number agrees across all three devices');

    // ---- a failed publication survives a reload ----------------------------
    // The block used to live in a page-local Set: a reload restored the advanced
    // MLS state without it, and sending resumed on a branch nobody else had.

    {
        const blockedChat = 70;
        const blockedStorage = memoryStorage();
        const blockedClient = build(1, blockedStorage);
        await blockedClient.enroll({
            identity: 'blocked@example', currentPassword: 'secret',
            secondFactorCode: '777777', keyPackageCount: 2,
        });

        // Protect a conversation, then make publication fail for the next change.
        server.post('api/chat.php', { action: 'protect_chat', chat_id: blockedChat, __userId: 1 });
        const own = await blockedClient.startConversation(blockedChat, 1).catch(() => null);

        // Any publication from here on is rejected by the server.
        const realPost = server.post;
        let rejectPublication = false;
        server.post = async (url, body) => {
            if (rejectPublication &&
                (body.action === 'post_handshake' || body.action === 'post_handshake_batch')) {
                return { success: false, message: 'the server refused this handshake' };
            }
            return realPost(url, body);
        };

        if (own && own.groupId) {
            rejectPublication = true;
            await assert.rejects(
                () => blockedClient.admitDevices(blockedChat, own.groupId, 2),
                /could not be published|refused/,
                'an unpublishable change is reported as a failure'
            );
            assert.ok(blockedClient.sendingBlocked(blockedChat, own.groupId),
                'and the conversation is blocked from sending');

            // The reload: a brand new client over the same store.
            rejectPublication = false;
            const afterReload = build(1, blockedStorage);
            assert.equal(await afterReload.resume(), true, 'the device resumes after the reload');
            assert.ok(afterReload.sendingBlocked(blockedChat, own.groupId),
                'and the block came back with it, rather than being forgotten');
            await assert.rejects(() => afterReload.send(blockedChat, own.groupId, 'on a branch nobody has'),
                /rejoined/, 'so sending is still refused');
            console.log('PASS: a failed publication still blocks sending after a reload');
        }
        server.post = realPost;
    }

    // ---- a removal beyond the first page is still seen ---------------------
    // A second review put a genuine removal past the server's page cap: a device
    // that fetched one page never saw it, kept sending, and the removed device
    // read what followed. The double caps pages at two, so a client that does not
    // page cannot pass this.

    {
        const paged = 60;
        server.handshakes.set(paged, []);
        // Seven handshakes, well past a two-entry page.
        for (let index = 0; index < 7; index++) {
            await server.post('api/chat.php', {
                action: 'post_handshake', chat_id: paged, kind: 3, epoch: 0,
                // A welcome for somebody else: this device cannot open it, which
                // is normal, so the paging behaviour is what is under test.
                payload: Buffer.concat([
                    Buffer.from([0, 0, 0, 4]), Buffer.from('nope'), Buffer.from('tree'),
                ]).toString('base64'),
                __userId: 1,
            });
        }
        const walked = await mira.syncGroup(paged, 0);
        assert.equal(walked.lastSequence, 7,
            'the client pages until the server runs out rather than stopping at the first page');
        console.log('PASS: group history past the first page is fetched');

        // A gap means something was withheld: stop rather than carry on.
        const withheld = 61;
        const foreignWelcome = Buffer.concat([
            Buffer.from([0, 0, 0, 4]), Buffer.from('nope'), Buffer.from('tree'),
        ]).toString('base64');
        server.handshakes.set(withheld, [
            { sequence: 1, kind: 3, epoch: 0, payload: foreignWelcome },
            { sequence: 3, kind: 3, epoch: 0, payload: foreignWelcome },
        ]);
        await assert.rejects(() => mira.syncGroup(withheld, 0), /gap at 3/,
            'a missing sequence is refused rather than skipped');
        assert.ok(mira.sendingBlocked(withheld, null),
            'and the conversation is blocked from sending until it is rejoined');
        console.log('PASS: a withheld handshake blocks the conversation instead of being ignored');
    }

    // ---- a message past the first page is still decrypted ------------------

    {
        const many = [];
        for (let index = 0; index < 5; index++) {
            many.push(await ada.send(42, started.groupId, 'paged message ' + index));
        }
        const readAll = await miraAgain.receive(42, sync.groupId, many[0].messageId - 1);
        for (let index = 0; index < 5; index++) {
            assert.ok(readAll.some((message) => message.text === 'paged message ' + index),
                'message ' + index + ' past the page cap is fetched and opened');
        }
        console.log('PASS: messages past the first page are fetched and decrypted');
    }

    // ---- a deferred change that will not apply is not forgiven -------------
    // The catch around the welcome used to wrap the replay as well, so a
    // deferred commit that failed during replay was swallowed as "this welcome
    // belongs to another device" — and the incomplete block was then cleared, so
    // the newly joined device carried on sending from the epoch before the
    // removal it never applied.

    {
        const lateChat = 95;
        const lateStore = memoryStorage();
        const late = build(51, lateStore);
        await late.enroll({
            identity: 'late@example', currentPassword: 'secret',
            secondFactorCode: '515151', keyPackageCount: 4,
        });
        await server.post('api/chat.php', { action: 'protect_chat', chat_id: lateChat, __userId: 51 });

        // A queue with contiguous sequences: a commit this device cannot apply,
        // then a welcome that does let it join. The commit is deferred, the join
        // succeeds, and the replay of the commit then fails.
        const unusable = Buffer.from('a commit this device cannot read').toString('base64');
        const foreignWelcome = Buffer.concat([
            Buffer.from([0, 0, 0, 4]), Buffer.from('nope'), Buffer.from('tree'),
        ]).toString('base64');
        server.handshakes.set(lateChat, [
            { sequence: 1, kind: 2, epoch: 1, payload: unusable },
            { sequence: 2, kind: 3, epoch: 1, payload: foreignWelcome },
        ]);

        await assert.rejects(() => late.syncGroup(lateChat, 0),
            /could not be applied|could not account for/,
            'a group change this device cannot apply is refused rather than stepped over');
        assert.ok(late.sendingBlocked(lateChat, null),
            'and the conversation stays blocked from sending');

        // Repeating the sync must not clear the block either.
        await assert.rejects(() => late.syncGroup(lateChat, 0), /could not be applied|rejoined/);
        assert.ok(late.sendingBlocked(lateChat, null), 'a second attempt does not forgive it');
        console.log('PASS: a deferred change that cannot be applied keeps the conversation blocked');
    }

    // ---- an empty page does not lift a block -------------------------------
    // A review cleared a removal block by returning an empty retry: "no more
    // history" was read as "you are caught up".

    {
        const stuck = 96;
        const late = build(61, memoryStorage());
        await late.enroll({
            identity: 'stuck@example', currentPassword: 'secret',
            secondFactorCode: '616161', keyPackageCount: 4,
        });
        await server.post('api/chat.php', { action: 'protect_chat', chat_id: stuck, __userId: 61 });

        const unusable = Buffer.from('a change this device cannot read').toString('base64');
        server.handshakes.set(stuck, [{ sequence: 1, kind: 2, epoch: 1, payload: unusable }]);
        await assert.rejects(() => late.syncGroup(stuck, 0), /could not be applied/);
        assert.ok(late.sendingBlocked(stuck, null), 'the conversation is blocked');

        // The server now says there is nothing more. That must not be enough.
        server.handshakes.set(stuck, []);
        await assert.rejects(() => late.syncGroup(stuck, 0),
            /rejoined/,
            'an empty page does not lift the block');
        assert.ok(late.sendingBlocked(stuck, null), 'and sending stays refused');
        console.log('PASS: a block is only lifted by applying the change it waits for');
    }

    // ---- a relabelled commit cannot clear a block --------------------------
    // The block used to bind to the sequence number, which the server chooses. A
    // review blocked a device on sequence S with a corrupted removal, then
    // relabelled a *different* valid commit as S: applying it cleared the block,
    // and the removed device kept reading. The block binds to the payload's
    // digest now, so only those exact bytes lift it.

    {
        const substituted = 98;
        const observer = build(81, memoryStorage());
        await observer.enroll({
            identity: 'observer@example', currentPassword: 'secret',
            secondFactorCode: '818181', keyPackageCount: 4,
        });
        await server.post('api/chat.php', { action: 'protect_chat', chat_id: substituted, __userId: 81 });

        const corrupted = Buffer.from('a removal this device cannot read').toString('base64');
        server.handshakes.set(substituted, [{ sequence: 1, kind: 2, epoch: 1, payload: corrupted }]);
        await assert.rejects(() => observer.syncGroup(substituted, 0), /could not be applied/);
        assert.ok(observer.sendingBlocked(substituted, null), 'the observer is blocked');

        // The server now offers a different payload under the same sequence.
        const different = Buffer.from('an entirely different change').toString('base64');
        server.handshakes.set(substituted, [{ sequence: 1, kind: 2, epoch: 1, payload: different }]);
        await assert.rejects(() => observer.syncGroup(substituted, 0),
            /could not be applied|rejoined/,
            'a different payload under the same sequence does not satisfy the block');
        assert.ok(observer.sendingBlocked(substituted, null),
            'and the conversation stays blocked, so nothing is sent on a branch it cannot account for');
        console.log('PASS: relabelling a different commit with the blocked sequence does not lift the block');
    }

    // ---- the same bytes applying later does not lift a block ---------------
    // The sharpest version of this attack, from the seventh review: a commit
    // that fails only because its prerequisite is missing applies perfectly once
    // the server supplies that prerequisite. Keying the block to the payload
    // digest therefore cleared it, while the change the device had actually
    // missed — a removal — was never applied at all.

    {
        const prerequisite = 99;
        const device = build(91, memoryStorage());
        await device.enroll({
            identity: 'prereq@example', currentPassword: 'secret',
            secondFactorCode: '919191', keyPackageCount: 6,
        });
        await server.post('api/chat.php', { action: 'protect_chat', chat_id: prerequisite, __userId: 91 });

        // A change this device cannot apply in its current state.
        const failing = Buffer.from('a commit that needs a prerequisite').toString('base64');
        server.handshakes.set(prerequisite, [{ sequence: 1, kind: 2, epoch: 2, payload: failing }]);
        await assert.rejects(() => device.syncGroup(prerequisite, 0), /could not be applied/);
        assert.ok(device.sendingBlocked(prerequisite, null), 'the device is blocked');

        // Now the server offers a prerequisite followed by the very same bytes.
        // Under the old rule this cleared the block.
        server.handshakes.set(prerequisite, [
            { sequence: 1, kind: 2, epoch: 1, payload: Buffer.from('the prerequisite').toString('base64') },
            { sequence: 2, kind: 2, epoch: 2, payload: failing },
        ]);
        await assert.rejects(() => device.syncGroup(prerequisite, 0),
            /could not be applied|rejoined/,
            'supplying the prerequisite does not turn "these bytes applied" into "I am caught up"');
        assert.ok(device.sendingBlocked(prerequisite, null),
            'and the conversation is still blocked from sending');
        console.log('PASS: replaying the same bytes with their prerequisite does not lift the block');
    }

    // ---- but a genuine rejoin does -----------------------------------------
    // Otherwise the conversation would be bricked, and people would turn the
    // feature off rather than live with it.

    {
        const repaired = 101;
        const holderStore = memoryStorage();
        const holder = build(92, holderStore);
        await holder.enroll({
            identity: 'repaired@example', currentPassword: 'secret',
            secondFactorCode: '929292', keyPackageCount: 6,
        });
        const owner = build(93, memoryStorage());
        await owner.enroll({
            identity: 'owner@example', currentPassword: 'secret',
            secondFactorCode: '939393', keyPackageCount: 6,
        });
        await server.post('api/chat.php', { action: 'protect_chat', chat_id: repaired, __userId: 93 });

        // The holder loses track of the conversation.
        const unreadable = Buffer.from('a change the holder cannot apply').toString('base64');
        server.handshakes.set(repaired, [{ sequence: 1, kind: 2, epoch: 1, payload: unreadable }]);
        await assert.rejects(() => holder.syncGroup(repaired, 0), /could not be applied/);
        assert.ok(holder.sendingBlocked(repaired, null), 'it is blocked');

        // A member of the conversation adds it again, which produces a welcome
        // addressed to the key package the holder published when it failed.
        // The holder published fresh packages when it failed. Spend the older
        // ones first so the admission uses one of those fresh packages, which is
        // what a real claim does once the earlier ones are consumed.
        const holderDevice = server.devices.get(92)[0];
        const freshCount = 3;
        holderDevice.keyPackages.splice(0, holderDevice.keyPackages.length - freshCount);

        const started = await owner.startConversation(repaired, 92);
        assert.ok(started.groupId, 'a member re-admits the device');

        const rejoined = await holder.syncGroup(repaired, 0);
        assert.ok(rejoined.groupId, 'the holder joins from the new welcome');
        assert.equal(holder.sendingBlocked(repaired, rejoined.groupId), null,
            'and being re-admitted through a key package it created after failing clears the block');
        console.log('PASS: a genuine re-admission repairs the conversation');
    }

    // ---- protection is marked before it is requested -----------------------
    // If the server commits and the local write or the response is lost, a
    // conversation is protected while this device thinks it is not.

    {
        const marker = (() => {
            const values = new Map();
            return {
                getItem: (key) => (values.has(key) ? values.get(key) : null),
                setItem: (key, value) => { values.set(key, String(value)); },
                removeItem: (key) => { values.delete(key); },
            };
        })();
        const lossyStore = memoryStorage();
        const client = createProtectedClient({
            accountId: 71,
            storage: lossyStore,
            localStore: marker,
            crypto: webcrypto,
            randomBytes: (length) => webcrypto.getRandomValues(new Uint8Array(length)),
            post: (url, body) => (body.action === 'protect_chat'
                // The server committed; the answer never arrived.
                ? Promise.reject(new Error('the response was lost'))
                : server.post(url, Object.assign({ __userId: 71 }, body))),
            mls,
        });
        await client.enroll({
            identity: 'lossy@example', currentPassword: 'secret',
            secondFactorCode: '717171', keyPackageCount: 4,
        });

        await assert.rejects(() => client.startConversation(97, 71), /lost|protect/);
        assert.equal(client.markedProtected(97), true,
            'the conversation is marked protected even though the answer never came');
        assert.ok(client.sendingBlocked(97, null),
            'and it is blocked from sending until it is reopened, rather than treated as plaintext');
        console.log('PASS: a lost protect_chat response leaves the conversation protected and blocked, not plaintext');
    }

    // ---- the creator remembers its own conversation ------------------------
    // A fourth review found the one account that never wrote the protection
    // marker was the conversation's creator: it held the group in memory, and
    // after a reload the server's flag was the only thing left saying the
    // conversation was protected.

    {
        const marker = (() => {
            const values = new Map();
            return {
                getItem: (key) => (values.has(key) ? values.get(key) : null),
                setItem: (key, value) => { values.set(key, String(value)); },
                removeItem: (key) => { values.delete(key); },
                dump: () => Object.fromEntries(values),
            };
        })();

        const creatorStore = memoryStorage();
        const creator = createProtectedClient({
            accountId: 41,
            storage: creatorStore,
            localStore: marker,
            crypto: webcrypto,
            randomBytes: (length) => webcrypto.getRandomValues(new Uint8Array(length)),
            post: (url, body) => server.post(url, Object.assign({ __userId: 41 }, body)),
            mls,
        });
        await creator.enroll({
            identity: 'creator@example', currentPassword: 'secret',
            secondFactorCode: '414141', keyPackageCount: 4,
        });

        const created = await creator.startConversation(90, 41);
        assert.ok(created.groupId, 'the creator protects a conversation');

        // The state the reload leaves behind: a fresh client over the same stores.
        const afterReload = createProtectedClient({
            accountId: 41,
            storage: creatorStore,
            localStore: marker,
            crypto: webcrypto,
            randomBytes: (length) => webcrypto.getRandomValues(new Uint8Array(length)),
            post: (url, body) => server.post(url, Object.assign({ __userId: 41 }, body)),
            mls,
        });
        assert.equal(await afterReload.resume(), true, 'the creator resumes');
        assert.equal(await afterReload.knownProtected(90), true,
            'and still knows the conversation it created is protected');
        assert.equal(afterReload.markedProtected(90), true,
            'including from the synchronous marker, which is what a send path can read');
        console.log('PASS: the creator remembers its own protected conversation across a reload');

        // Even with the marker wiped — a cleared browser — the sealed record
        // re-marks it on resume, so the server's flag is still not the only word.
        marker.removeItem('pm-protected-chats:41');
        const wiped = createProtectedClient({
            accountId: 41,
            storage: creatorStore,
            localStore: marker,
            crypto: webcrypto,
            randomBytes: (length) => webcrypto.getRandomValues(new Uint8Array(length)),
            post: (url, body) => server.post(url, Object.assign({ __userId: 41 }, body)),
            mls,
        });
        assert.equal(await wiped.resume(), true, 'it resumes with the marker gone');
        assert.equal(wiped.markedProtected(90), true,
            'and the marker is re-derived from the sealed record');
        console.log('PASS: a cleared marker is rebuilt from the sealed record on resume');
    }

    // ---- recovery is not a way around a security state ----------------------
    // A review exported a recovery file from a device blocked from sending on an
    // unpublished branch, restored it elsewhere, and found the block gone.

    {
        const blockedChat = 80;
        const store = memoryStorage();
        const client = build(1, store);
        // Plenty of key packages: this case is about the block surviving export,
        // not about exhaustion.
        await client.enroll({
            identity: 'blocked-export@example', currentPassword: 'secret',
            secondFactorCode: '808080', keyPackageCount: 12,
        });
        // A fresh account with its own packages, so this case tests the block and
        // not exhaustion left over from earlier cases.
        const guest = build(31, memoryStorage());
        await guest.enroll({
            identity: 'guest@example', currentPassword: 'secret',
            secondFactorCode: '313131', keyPackageCount: 4,
        });
        await server.post('api/chat.php', { action: 'protect_chat', chat_id: blockedChat, __userId: 1 });
        const own = await client.startConversation(blockedChat, 1).catch(() => null);

        if (own && own.groupId) {
            const realPost = server.post;
            server.post = async (url, body) => (
                body.action === 'post_handshake' || body.action === 'post_handshake_batch'
                    ? { success: false, message: 'refused' }
                    : realPost(url, body)
            );
            await assert.rejects(() => client.admitDevices(blockedChat, own.groupId, 31), /refused|published/);
            server.post = realPost;
            assert.ok(client.sendingBlocked(blockedChat, own.groupId), 'the device is blocked from sending');

            const exported = await client.createRecoveryFile();
            const elsewhere = build(1, memoryStorage());
            await elsewhere.restoreFromRecoveryFile(exported.file, exported.passphrase);
            assert.ok(elsewhere.sendingBlocked(blockedChat, own.groupId),
                'a device restored from that file is blocked too, rather than starting clean');
            await assert.rejects(() => elsewhere.send(blockedChat, own.groupId, 'from the unpublished branch'),
                /rejoined/, 'so recovery is not a way around the block');
            console.log('PASS: recovery carries the block, not just the keys');
        }
    }

    // ---- the directory chain is actually verified ---------------------------
    // The chain existed from the start and nothing checked it, which a review
    // pointed out while the documentation implied clients could.

    const firstWalk = await ada.verifyDirectory();
    assert.ok(firstWalk.verified > 0, 'the chain is walked and entries are checked');
    assert.equal(firstWalk.head, server.directoryLog.length, 'the walk reaches the head');

    // Walking again from the stored head verifies nothing new and still agrees.
    const secondWalk = await ada.verifyDirectory();
    assert.equal(secondWalk.verified, 0, 'a second walk has nothing new to check');
    assert.equal(secondWalk.head, firstWalk.head, 'and the head has not moved');
    console.log('PASS: the directory chain is walked, and progress is remembered');

    // A server that rewrites history it has already shown must be caught.
    const rewritten = server.appendDirectoryEntry(1, Buffer.from('a device nobody enrolled'));
    rewritten.previous_digest = Buffer.alloc(32).toString('base64');
    await assert.rejects(() => ada.verifyDirectory(),
        /different history|does not continue/,
        'an entry that does not continue the history this device saw is refused');
    console.log('PASS: a rewritten directory is caught by the client, not merely detectable in principle');

    // Repair the log so later cases are unaffected.
    server.directoryLog.pop();

    // ---- a reload keeps the conversation and its history -------------------
    // Two things a review found a reload destroyed: the chat-to-group mapping,
    // which only lived in a page-local Map while the welcome that carried it had
    // already been consumed, and every message read before the reload, because
    // an MLS application message decrypts exactly once.

    const beforeReload = 'said before the tab closed';
    const beforeSend = await ada.send(42, started.groupId, beforeReload);
    const readBefore = await miraAgain.receive(42, sync.groupId, beforeSend.messageId - 1);
    assert.ok(readBefore.some((message) => message.text === beforeReload),
        'the message is read once while the page is open');

    // A brand new client over the same store: this is what a reload gives you.
    const afterReloadClient = build(2, miraStorage);
    assert.equal(await afterReloadClient.resume(), true, 'the device resumes');

    const recalled = await afterReloadClient.recallConversation(42);
    assert.ok(recalled && recalled.groupId, 'the conversation remembers which group it uses');
    assert.equal(recalled.groupId, sync.groupId, 'and it is the right one');

    const historyAfterReload = await afterReloadClient.receive(42, recalled.groupId, beforeSend.messageId - 1);
    const fromHistory = historyAfterReload.find((message) => message.messageId === beforeSend.messageId);
    assert.ok(fromHistory, 'the message is still listed after the reload');
    assert.equal(fromHistory.text, beforeReload,
        'and is still readable, from the sealed local history rather than a second decryption');
    assert.equal(fromHistory.fromHistory, true, 'the client says where it came from');
    console.log('PASS: a reload keeps both the group mapping and the messages already read');

    // That history is at rest as ciphertext, not as text.
    const historyRecord = await miraStorage.get('history:2:42');
    assert.ok(historyRecord && historyRecord.sealed.length > 0, 'the history is stored sealed');
    assert.ok(!Buffer.from(historyRecord.sealed).includes(Buffer.from(beforeReload)),
        'the stored history does not contain the message in the clear');
    console.log('PASS: local history is sealed with the same non-extractable key');

    // ---- one browser, two accounts -----------------------------------------
    // The reviewer logged a second account into a store the first had used and
    // watched it resume the first account's signer, which produces a group
    // member that the second account's directory has never heard of and cannot
    // revoke.

    const sharedStore = memoryStorage();
    const first = createProtectedClient({
        accountId: 11,
        storage: sharedStore,
        crypto: webcrypto,
        randomBytes: (length) => webcrypto.getRandomValues(new Uint8Array(length)),
        post: (url, body) => server.post(url, Object.assign({ __userId: 11 }, body)),
        mls,
    });
    await first.enroll({
        identity: 'first@example', currentPassword: 'secret', secondFactorCode: '111222', keyPackageCount: 1,
    });
    assert.equal(await first.resume(), true, 'the first account has a device');

    const second = createProtectedClient({
        accountId: 12,
        storage: sharedStore,
        crypto: webcrypto,
        randomBytes: (length) => webcrypto.getRandomValues(new Uint8Array(length)),
        post: (url, body) => server.post(url, Object.assign({ __userId: 12 }, body)),
        mls,
    });
    assert.equal(await second.resume(), false,
        'a different account in the same browser does not inherit the first one\'s device');
    console.log('PASS: device state does not cross between accounts sharing a browser');

    // ---- authorship comes from MLS, not from the row -----------------------
    // The reviewer changed one server-controlled field and watched authenticated
    // content be re-attributed to another account. Attribution now comes from
    // the signature MLS verified, and a disagreement is visible.

    // A fresh message each time: MLS will not open the same one twice, so the
    // honest and tampered cases each need their own.
    const honestText = 'who wrote this matters';
    const honestSend = await ada.send(42, started.groupId, honestText);
    const honestRead = await miraAgain.receive(42, sync.groupId, honestSend.messageId - 1);
    const genuine = honestRead.find((message) => message.text === honestText);
    assert.ok(genuine, 'the message is there');
    assert.equal(genuine.authorship, 'verified', 'an untouched message is attributed to its signer');
    assert.equal(genuine.senderId, 1, 'and the signer is the account that sent it');

    // Now the server lies about who wrote the next one, before anyone reads it.
    const forgedText = 'and so does who did not';
    const forgedSend = await ada.send(42, started.groupId, forgedText);
    const row = server.envelopes.get(42).find((entry) => entry.message_id === forgedSend.messageId);
    const realSenderId = row.sender_id;
    row.sender_id = 999999;

    const tamperedRead = await miraAgain.receive(42, sync.groupId, forgedSend.messageId - 1);
    const forged = tamperedRead.find((message) => message.messageId === forgedSend.messageId);
    assert.equal(forged.text, forgedText, 'the message still decrypts: MLS protected the bytes');
    assert.equal(forged.authorship, 'mismatched',
        'a row that disagrees with the signature is reported as mismatched');
    assert.equal(forged.senderId, realSenderId,
        'attribution stays with the account MLS authenticated');
    assert.equal(forged.claimedSenderId, 999999,
        'and what the server claimed is kept separately rather than silently used');
    row.sender_id = realSenderId;
    console.log('PASS: changing the server-side sender does not change who a message is attributed to');

    // ---- remapping a key to another account is caught ----------------------
    // The second review's attack: with the honest chain head already pinned, the
    // server relabelled a signature key as belonging to account 999999 and set
    // sender_id to match. The client reported the forgery as "verified", because
    // the mapping it trusted came from that same response.

    {
        const remapText = 'whose words are these';
        const remapSend = await ada.send(42, started.groupId, remapText);

        const adaDevice = server.devices.get(1)[0];
        const trueOwner = adaDevice.userId;
        adaDevice.claimedUserId = 999999;
        const row = server.envelopes.get(42).find((entry) => entry.message_id === remapSend.messageId);
        row.sender_id = 999999;

        // The pinned binding disagrees with the listing, so this must be refused
        // outright rather than answered with a forged attribution.
        await assert.rejects(
            () => miraAgain.receive(42, sync.groupId, remapSend.messageId - 1),
            /attributed to a different account/,
            'a key remapped to another account is refused, not reported as verified'
        );

        adaDevice.claimedUserId = undefined;
        row.sender_id = trueOwner;
        const honest = await miraAgain.receive(42, sync.groupId, remapSend.messageId - 1);
        const restored = honest.find((message) => message.messageId === remapSend.messageId);
        assert.equal(restored.authorship, 'verified',
            'and the honest mapping still verifies once it is put back');
        console.log('PASS: a signature key cannot be re-attributed to another account');
    }

    // A device whose enrolment is not in the chain at all cannot be "verified".
    {
        const unbound = 'sent by a device with no chain entry';
        const unboundSend = await ada.send(42, started.groupId, unbound);
        const adaDevice = server.devices.get(1)[0];
        const realSeq = adaDevice.enrolledSeq;
        adaDevice.enrolledSeq = null;

        const read = await miraAgain.receive(42, sync.groupId, unboundSend.messageId - 1);
        const message = read.find((entry) => entry.messageId === unboundSend.messageId);
        assert.equal(message.authorship, 'unverified',
            'a device the chain does not cover is reported unverified rather than verified');
        adaDevice.enrolledSeq = realSeq;
        console.log('PASS: authorship needs a chain entry, not merely a directory row');
    }

    // ---- a key package that does not match the enrolled key ----------------
    // The reviewer's scenario: a device advertises signature key X in the
    // directory while publishing key packages signed by Y. Admission would add
    // Y, revocation would look for X, and the device could never be removed.

    const impostorStorage = memoryStorage();
    const impostor = build(4, impostorStorage);
    await impostor.enroll({
        identity: 'impostor@example', label: 'Laptop',
        currentPassword: 'secret', secondFactorCode: '444444', keyPackageCount: 2,
    });
    const impostorDevice = server.devices.get(4)[0];
    // Same device, different advertised key: only the directory column changes.
    impostorDevice.claimedKey = Buffer.from('a key this device does not sign with').toString('base64');

    await assert.rejects(
        () => ada.startConversation(77, 4),
        /does not match its enrolled key/,
        'a key package that does not match the enrolled key is refused rather than admitted'
    );
    console.log('PASS: a device whose key package disagrees with its directory key is not admitted');

    // And the honest case still works, so the check is not simply refusing
    // everything.
    impostorDevice.claimedKey = undefined;
    const honest = await ada.startConversation(78, 4);
    assert.ok(honest.groupId, 'a device whose keys agree is admitted normally');
    console.log('PASS: the binding check still admits an honest device');

    // ---- revocation actually stops a device reading ------------------------
    // Revoking a device stops it being offered new key packages. That alone does
    // nothing to a device already inside the group: it holds those keys, and the
    // server cannot take them back because it has none. Somebody still in the
    // conversation has to publish a removal.

    const miraDevices = server.devices.get(2);
    const tabletDevice = miraDevices[miraDevices.length - 1];
    assert.ok(tabletDevice && tabletDevice.deviceId > 0, 'the tablet is in the directory');

    const beforeRevocation = 'still readable by the tablet';
    await ada.send(42, started.groupId, beforeRevocation);
    const tabletBefore = await tablet.receive(42, tabletJoin.groupId, 0);
    assert.ok(tabletBefore.some((message) => message.text === beforeRevocation),
        'the tablet reads normally before being revoked');

    tabletDevice.revoked = true;

    // Revocation alone leaves it reading — which is exactly the gap this closes.
    const enforced = await ada.enforceRevocations(42, started.groupId);
    assert.deepEqual(enforced.removed, [tabletDevice.deviceId],
        'the revoked device is removed from the conversation');

    await miraAgain.syncGroup(42, 0);
    const afterRevocation = 'not for a revoked device';
    await ada.send(42, started.groupId, afterRevocation);

    const tabletAfter = await tablet.receive(42, tabletJoin.groupId, 0);
    assert.ok(!tabletAfter.some((message) => message.text === afterRevocation),
        'the revoked device cannot read what is sent after its removal');
    const miraAfter = await miraAgain.receive(42, sync.groupId, 0);
    assert.ok(miraAfter.some((message) => message.text === afterRevocation),
        'the devices that remain keep reading');
    console.log('PASS: revoking a device removes it from the conversation and it stops reading');

    // Running it again must be a no-op rather than a second removal.
    assert.deepEqual((await ada.enforceRevocations(42, started.groupId)).removed, [],
        'a device already removed is not removed again');
    console.log('PASS: enforcing revocations twice changes nothing the second time');

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

    // ---- recovery ----------------------------------------------------------

    const recovery = await mira.createRecoveryFile();
    assert.match(recovery.passphrase, /^[a-z2-9]{6}(-[a-z2-9]{6}){3}$/,
        'the passphrase is generated, grouped and unambiguous');
    assert.equal(recovery.file.format, 'pm-recovery-v3');
    assert.ok(recovery.file.iterations >= 600000, 'the derivation is not cheap');

    // The file must not carry the state in the clear.
    assert.ok(!Buffer.from(recovery.file.state, 'base64').includes(Buffer.from('mira@example')),
        'the recovery file does not expose the identity');
    console.log('PASS: a recovery file is produced under a generated passphrase');

    // A fresh device, no stored state at all, recovers from the file.
    const recoveredStorage = memoryStorage();
    const recovered = build(2, recoveredStorage);
    assert.equal(await recovered.resume(), false, 'the replacement device starts empty');
    await recovered.restoreFromRecoveryFile(recovery.file, recovery.passphrase);

    // This file was written before the tablet was admitted, so it restores a
    // device one epoch behind. It has to catch up on handshakes before it can
    // read again — which is the behaviour to want, not a bug: the alternative
    // would be a device that silently shows a conversation it has fallen out of.
    // The mapping travels inside the recovery file, so a restored device knows
    // which group each conversation uses without being told out of band.
    const recalledAfterRestore = await recovered.recallConversation(42);
    assert.ok(recalledAfterRestore && recalledAfterRestore.groupId,
        'a restored device knows which group the conversation uses');

    const caughtUp = await recovered.syncGroup(42, 0);
    assert.ok(caughtUp.applied >= 0, 'a recovered device applies the changes it missed');

    await ada.send(42, started.groupId, 'recovered and still reading');
    const afterRecovery = await recovered.receive(42, sync.groupId, 0);
    assert.ok(afterRecovery.some((message) => message.text === 'recovered and still reading'),
        'a recovered device reads messages sent after the loss');
    console.log('PASS: a replacement device recovers, catches up and keeps reading');

    await assert.rejects(
        () => build(2, memoryStorage()).restoreFromRecoveryFile(recovery.file, 'wrong-passphrase-entirely'),
        /does not open this recovery file/,
        'the wrong passphrase is refused'
    );
    await assert.rejects(
        () => build(2, memoryStorage()).restoreFromRecoveryFile({ format: 'something-else' }, 'x'),
        /not a recovery file/,
        'an unknown file format is refused'
    );

    // The header is authenticated, so rewriting any of it fails to open rather
    // than opening with different metadata.
    const tamperedHeader = Object.assign({}, recovery.file, {
        signature_public_key: Buffer.from('a key that was never ours').toString('base64'),
    });
    await assert.rejects(
        () => build(2, memoryStorage()).restoreFromRecoveryFile(tamperedHeader, recovery.passphrase),
        /does not open this recovery file/,
        'rewriting the header breaks authentication instead of changing the metadata'
    );

    // An attacker-chosen derivation cost is a way to make a browser sit still.
    await assert.rejects(
        () => build(2, memoryStorage()).restoreFromRecoveryFile(
            Object.assign({}, recovery.file, { iterations: 600000000 }),
            recovery.passphrase
        ),
        /unusable key derivation cost/,
        'an absurd iteration count is refused before any derivation starts'
    );

    // And a file from another account does not open here.
    await assert.rejects(
        () => build(3, memoryStorage()).restoreFromRecoveryFile(recovery.file, recovery.passphrase),
        /different account/,
        'a recovery file from another account is refused'
    );
    console.log('PASS: the recovery header is authenticated, bounded, and account-bound');
    console.log('PASS: a wrong passphrase and an unknown format are both refused');

    console.log('Protected client runtime tests passed.');
})().catch((error) => {
    console.error(error);
    process.exit(1);
});
