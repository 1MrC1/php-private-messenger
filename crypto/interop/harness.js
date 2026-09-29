// The harness's module, kept out of the page because the application's content
// security policy denies inline script and the fixture is held to the same rule.
import init, { MlsSession, version, ciphersuite } from '../../assets/vendor/mls/pm_mls.js';

const log = (line) => {
    document.getElementById('log').textContent += '\n' + line;
};

const sessions = new Map();
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const toBase64 = (bytes) => {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
};

const fromBase64 = (value) => {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
};

await init();
document.getElementById('log').textContent = version() + ', cipher suite ' + ciphersuite();

// The surface the runner drives. Everything crosses as base64 or plain values so
// nothing depends on how a particular engine marshals typed arrays.
window.pm = {
    ready: true,
    version: () => version(),
    ciphersuite: () => ciphersuite(),

    createIdentity(key, name) {
        const session = new MlsSession();
        const publicKey = session.create_identity(name);
        sessions.set(key, session);
        return toBase64(publicKey);
    },
    createKeyPackage(key) {
        return toBase64(sessions.get(key).create_key_package());
    },
    createGroup(key) {
        return toBase64(sessions.get(key).create_group());
    },
    addMember(key, groupId, keyPackage) {
        const added = sessions.get(key).add_member(fromBase64(groupId), fromBase64(keyPackage));
        return {
            commit: toBase64(added.commit),
            welcome: toBase64(added.welcome),
            ratchetTree: toBase64(added.ratchet_tree),
        };
    },
    joinGroup(key, welcome, ratchetTree) {
        return toBase64(sessions.get(key).join_group(fromBase64(welcome), fromBase64(ratchetTree)));
    },
    seal(key, groupId, text) {
        return toBase64(sessions.get(key).seal(fromBase64(groupId), encoder.encode(text)));
    },
    open(key, groupId, sealed) {
        const opened = sessions.get(key).open(fromBase64(groupId), fromBase64(sealed));
        return decoder.decode(opened.plaintext);
    },
    /** The sender MLS authenticated, so the runner can check it crosses engines. */
    openAuthenticated(key, groupId, sealed) {
        const opened = sessions.get(key).open(fromBase64(groupId), fromBase64(sealed));
        return {
            text: decoder.decode(opened.plaintext),
            senderKey: opened.sender_key ? toBase64(opened.sender_key) : null,
            senderLeaf: opened.sender_leaf,
        };
    },
    hasDiverged(key, groupId) {
        return sessions.get(key).has_diverged(fromBase64(groupId));
    },
    applyHandshake(key, handshake) {
        return sessions.get(key).apply_handshake(fromBase64(handshake));
    },
    removeMember(key, groupId, signatureKey) {
        return toBase64(sessions.get(key).remove_member(fromBase64(groupId), fromBase64(signatureKey)));
    },
    identityKey(key) {
        return toBase64(sessions.get(key).identity_key());
    },
    safetyNumber(key, groupId) {
        return sessions.get(key).safety_number(fromBase64(groupId));
    },
    epoch(key, groupId) {
        return Number(sessions.get(key).epoch(fromBase64(groupId)));
    },
    exportState(key) {
        return toBase64(sessions.get(key).export_state());
    },
    restore(key, state, publicKey, name) {
        sessions.set(key, MlsSession.restore(fromBase64(state), fromBase64(publicKey), encoder.encode(name)));
        return true;
    },
    /**
     * What the client needs from the browser besides WebAssembly.
     *
     * The MLS build carries its own cryptography, so nothing here touches
     * signatures or the group — WebCrypto's uneven Ed25519 support never enters
     * the picture. What the client does depend on is a non-extractable AES-GCM
     * key it can keep in IndexedDB, and PBKDF2-SHA512 for the recovery file. An
     * engine missing either of those cannot run protected conversations, so the
     * matrix should say so rather than only testing the parts that work.
     */
    async probe() {
        const report = { aesGcm: false, nonExtractable: false, indexedDbCryptoKey: false, pbkdf2Sha512: false, pbkdf2Ms: null };

        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        report.nonExtractable = key.extractable === false;
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode('probe'));
        report.aesGcm = decoder.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, sealed)) === 'probe';

        // A CryptoKey has to survive a round trip through IndexedDB, which is
        // how the client keeps state wrapped without ever holding raw key bytes.
        report.indexedDbCryptoKey = await new Promise((resolve) => {
            const request = indexedDB.open('pm-interop-probe', 1);
            request.onupgradeneeded = () => request.result.createObjectStore('keys');
            request.onerror = () => resolve(false);
            request.onsuccess = () => {
                const db = request.result;
                const write = db.transaction('keys', 'readwrite');
                write.objectStore('keys').put(key, 'k');
                write.oncomplete = () => {
                    const read = db.transaction('keys', 'readonly').objectStore('keys').get('k');
                    read.onsuccess = () => {
                        const back = read.result;
                        resolve(!!back && back.type === 'secret' && back.extractable === false);
                        db.close();
                        indexedDB.deleteDatabase('pm-interop-probe');
                    };
                    read.onerror = () => resolve(false);
                };
                write.onerror = () => resolve(false);
            };
        });

        const started = performance.now();
        const material = await crypto.subtle.importKey('raw', encoder.encode('passphrase'), { name: 'PBKDF2' }, false, ['deriveKey']);
        const derived = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: crypto.getRandomValues(new Uint8Array(16)), iterations: 600000, hash: 'SHA-512' },
            material,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
        report.pbkdf2Ms = Math.round(performance.now() - started);
        report.pbkdf2Sha512 = derived instanceof CryptoKey;

        return report;
    },

    // Opening what was not sealed for you must fail, in every engine.
    expectRefusal(key, groupId, sealed) {
        try {
            sessions.get(key).open(fromBase64(groupId), fromBase64(sealed));
            return false;
        } catch (error) {
            return true;
        }
    },
};

// A self-test, so the page is useful opened by hand as well.
try {
    window.pm.createIdentity('a', 'a@example');
    window.pm.createIdentity('b', 'b@example');
    const keyPackage = window.pm.createKeyPackage('b');
    const groupId = window.pm.createGroup('a');
    const added = window.pm.addMember('a', groupId, keyPackage);
    const joined = window.pm.joinGroup('b', added.welcome, added.ratchetTree);
    const sealed = window.pm.seal('a', groupId, 'it works in this browser');
    const opened = window.pm.open('b', joined, sealed);
    log(opened === 'it works in this browser'
        ? 'self-test: a round trip in this engine works'
        : 'self-test: FAILED, opened ' + JSON.stringify(opened));
    sessions.clear();
} catch (error) {
    log('self-test: FAILED, ' + error);
}
