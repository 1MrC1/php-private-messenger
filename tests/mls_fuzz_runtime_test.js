'use strict';

// Adversarial input for the MLS layer.
//
// The property under test is narrow and absolute: for any mutation of a sealed
// message, opening it must either fail or return something that is not the
// original plaintext. It must never return the plaintext for bytes that were
// not the ones sealed, and it must never crash the module in a way that leaves
// the session unusable afterwards.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const dir = path.join(__dirname, '..', 'assets', 'vendor', 'mls');
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Deterministic, so a failure can be reproduced from the seed alone. */
function seededRandom(seed) {
    let state = seed >>> 0;
    return function next() {
        state = (state * 1664525 + 1013904223) >>> 0;
        return state / 4294967296;
    };
}

(async () => {
    const mls = await import(path.join(dir, 'pm_mls.js'));
    await mls.default({ module_or_path: fs.readFileSync(path.join(dir, 'pm_mls_bg.wasm')) });

    const alice = new mls.MlsSession();
    alice.create_identity('alice@example');
    const bob = new mls.MlsSession();
    bob.create_identity('bob@example');

    const keyPackage = bob.create_key_package();
    const groupId = alice.create_group();
    const added = alice.add_member(groupId, keyPackage);
    const bobGroupId = bob.join_group(added.welcome, added.ratchet_tree);

    const secret = 'the studio is free from six';
    const sealed = alice.seal(groupId, encoder.encode(secret));

    // Sanity: the honest path works before we start breaking things.
    assert.equal(decoder.decode(bob.open(bobGroupId, sealed).plaintext), secret,
        'the untouched message opens');
    console.log('PASS: the untouched message opens');

    const random = seededRandom(20260928);
    let refused = 0;
    let openedSomethingElse = 0;
    const iterations = 400;

    for (let attempt = 0; attempt < iterations; attempt++) {
        const mutated = Uint8Array.from(sealed);
        const choice = random();

        if (choice < 0.4) {
            // Flip bits.
            const flips = 1 + Math.floor(random() * 4);
            for (let index = 0; index < flips; index++) {
                const at = Math.floor(random() * mutated.length);
                mutated[at] = mutated[at] ^ (1 << Math.floor(random() * 8));
            }
        } else if (choice < 0.6) {
            // Truncate.
            const keep = Math.floor(random() * mutated.length);
            var candidate = mutated.slice(0, keep);
        } else if (choice < 0.8) {
            // Extend with rubbish.
            const extra = new Uint8Array(1 + Math.floor(random() * 32));
            for (let index = 0; index < extra.length; index++) {
                extra[index] = Math.floor(random() * 256);
            }
            var candidate = new Uint8Array(mutated.length + extra.length);
            candidate.set(mutated, 0);
            candidate.set(extra, mutated.length);
        } else {
            // Splice a block out of the middle.
            const at = Math.floor(random() * Math.max(1, mutated.length - 8));
            var candidate = new Uint8Array(mutated.length - 4);
            candidate.set(mutated.slice(0, at), 0);
            candidate.set(mutated.slice(at + 4), at);
        }

        const input = typeof candidate === 'undefined' ? mutated : candidate;
        candidate = undefined;

        if (input.length === sealed.length && Buffer.from(input).equals(Buffer.from(sealed))) {
            continue;   // the mutation happened to be a no-op
        }

        let result = null;
        try {
            result = bob.open(bobGroupId, input).plaintext;
        } catch (error) {
            refused++;
            continue;
        }
        const text = decoder.decode(result);
        assert.notEqual(text, secret,
            'a mutated message must never open as the original plaintext (attempt ' + attempt + ')');
        openedSomethingElse++;
    }

    console.log('PASS: ' + iterations + ' mutations, ' + refused + ' refused, ' +
        openedSomethingElse + ' accepted without yielding the plaintext');
    assert.ok(refused > iterations * 0.8,
        'the overwhelming majority of mutations are refused outright');
    console.log('PASS: mutated messages are refused rather than misread');

    // The session must still work after all that.
    const after = alice.seal(groupId, encoder.encode('and bring the cello'));
    assert.equal(decoder.decode(bob.open(bobGroupId, after).plaintext), 'and bring the cello',
        'the session still works after being fed hundreds of malformed messages');
    console.log('PASS: the session survives the fuzzing and keeps working');

    // Replay: the same sealed message a second time must not be accepted as new.
    let replayRefused = false;
    try {
        bob.open(bobGroupId, sealed);
    } catch (error) {
        replayRefused = true;
    }
    assert.ok(replayRefused, 'a replayed message is refused');
    console.log('PASS: a replayed message is refused');

    // Empty and absurd inputs.
    for (const nonsense of [new Uint8Array(0), new Uint8Array(1), new Uint8Array(100000)]) {
        assert.throws(() => bob.open(bobGroupId, nonsense), 'degenerate input is refused');
    }
    console.log('PASS: empty and oversized inputs are refused');

    // ---- handshakes ---------------------------------------------------------
    // A commit is more dangerous than a message: applying a bad one moves the
    // group somewhere it should not be. The property is that no mutation of a
    // commit is ever *applied*, and that the group's epoch does not move.

    const carol = new mls.MlsSession();
    carol.create_identity('carol@example');
    const commit = alice.add_member(groupId, carol.create_key_package()).commit;

    const epochBefore = Number(bob.epoch(bobGroupId));
    let handshakesRefused = 0;
    let handshakesReported = 0;

    for (let attempt = 0; attempt < 200; attempt++) {
        const mutated = Uint8Array.from(commit);
        const flips = 1 + Math.floor(random() * 3);
        for (let index = 0; index < flips; index++) {
            const at = Math.floor(random() * mutated.length);
            mutated[at] = mutated[at] ^ (1 << Math.floor(random() * 8));
        }
        if (Buffer.from(mutated).equals(Buffer.from(commit))) {
            continue;
        }

        let outcome;
        try {
            outcome = bob.apply_handshake(mutated);
        } catch (error) {
            handshakesRefused++;
            continue;
        }
        assert.notEqual(outcome, 'applied',
            'a mutated commit must never be applied (attempt ' + attempt + ')');
        handshakesReported++;
    }

    console.log('PASS: 200 mutated commits, ' + handshakesRefused + ' refused, ' +
        handshakesReported + ' reported without being applied');
    assert.equal(Number(bob.epoch(bobGroupId)), epochBefore,
        'no mutated commit moved the group to another epoch');
    console.log('PASS: the group stayed in its epoch throughout');

    // The genuine commit still applies afterwards, so the fuzzing did not leave
    // the session in a state where honest traffic fails.
    assert.equal(bob.apply_handshake(commit), 'applied',
        'the genuine commit still applies after the mutated ones were refused');
    assert.equal(Number(bob.epoch(bobGroupId)), epochBefore + 1,
        'applying the genuine commit does move the epoch');
    console.log('PASS: the genuine commit still applies afterwards');

    console.log('MLS fuzz runtime tests passed.');
})().catch((error) => {
    console.error(error);
    process.exit(1);
});
