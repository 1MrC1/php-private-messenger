'use strict';

// Exercises the committed MLS build the way a client will: two devices, a group,
// a sealed message, and a session exported and restored the way a page reload
// forces. It loads the same artifacts that ship, so a broken or stale build
// fails here rather than in someone's browser.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const dir = path.join(__dirname, '..', 'assets', 'vendor', 'mls');
const encoder = new TextEncoder();
const decoder = new TextDecoder();

(async () => {
    const wasm = fs.readFileSync(path.join(dir, 'pm_mls_bg.wasm'));
    const module = await import(path.join(dir, 'pm_mls.js'));
    // Pass the bytes directly: the shipped loader would otherwise fetch them
    // relative to the document, which does not exist here.
    await module.default({ module_or_path: wasm });

    // The exact version, not just the name: the known-answer tests in
    // crypto/tests/ run against this library, and that only means something if
    // the artifact embeds the same one.
    assert.match(module.version(), /openmls 0\.9\.0/,
        'the module reports the exact OpenMLS version the vectors ran against');
    assert.equal(typeof module.ciphersuite(), 'number', 'a cipher suite is pinned');
    console.log('PASS: the committed WebAssembly build loads');

    // Two devices, each with independent state, as two browsers would be.
    const alice = new module.MlsSession();
    alice.create_identity('alice@example');
    const bob = new module.MlsSession();
    const bobPublicKey = bob.create_identity('bob@example');
    assert.ok(bobPublicKey.length > 0, 'an identity yields a public key');
    console.log('PASS: two independent device identities');

    const bobKeyPackage = bob.create_key_package();
    assert.ok(bobKeyPackage.length > 0, 'a key package is produced for publication');

    const groupId = alice.create_group();
    assert.ok(groupId.length > 0, 'a group is created');

    const added = alice.add_member(groupId, bobKeyPackage);
    assert.ok(added.welcome.length > 0 && added.commit.length > 0,
        'adding a member yields a welcome and a commit');
    console.log('PASS: a group is formed and a member added from a published key package');

    const joinedId = bob.join_group(added.welcome, added.ratchet_tree);
    assert.deepEqual(Array.from(joinedId), Array.from(groupId),
        'the joiner lands in the same group');
    console.log('PASS: the welcome carries the joiner into the same group');

    const secret = 'the studio is free from six';
    const sealed = alice.seal(groupId, encoder.encode(secret));

    // The point of the exercise: what the server would store must not contain
    // the message.
    assert.ok(!decoder.decode(sealed).includes(secret),
        'the sealed bytes do not contain the plaintext');
    assert.ok(!Buffer.from(sealed).includes(Buffer.from(secret, 'utf8')),
        'the plaintext is absent from the sealed bytes at the byte level');
    console.log('PASS: the sealed message does not contain the plaintext');

    assert.equal(decoder.decode(bob.open(joinedId, sealed)), secret,
        'the recipient recovers the message');
    console.log('PASS: the recipient opens it');

    // A page reload throws the session object away. State must survive it.
    const state = bob.export_state();
    assert.ok(state.length > 0, 'session state exports to bytes');

    const restored = module.MlsSession.restore(state, bobPublicKey, encoder.encode('bob@example'));
    const second = alice.seal(groupId, encoder.encode('and bring the cello'));
    assert.equal(decoder.decode(restored.open(joinedId, second)), 'and bring the cello',
        'a restored session keeps decrypting');
    console.log('PASS: exported state restores and keeps working across sessions');

    // A stranger holding neither the group nor the keys gets nothing.
    const outsider = new module.MlsSession();
    outsider.create_identity('mallory@example');
    assert.throws(() => outsider.open(groupId, sealed), /no such group|loading the group failed/,
        'a session that is not in the group cannot open its messages');
    console.log('PASS: a session outside the group cannot open its messages');

    // Truncated input must be refused rather than misread.
    assert.throws(() => bob.open(joinedId, sealed.slice(0, 10)), /reading the message failed|processing failed/,
        'a truncated message is refused');
    console.log('PASS: malformed input is refused');

    // ---- safety numbers ----------------------------------------------------

    const aliceNumber = alice.safety_number(groupId);
    const bobNumber = bob.safety_number(joinedId);
    assert.equal(aliceNumber, bobNumber, 'both sides compute the same safety number');
    assert.match(aliceNumber, /^\d{5}( \d{5}){3}\n\d{5}( \d{5}){3}$/,
        'the safety number is grouped for reading aloud');
    console.log('PASS: both sides compute the same safety number');

    const other = new module.MlsSession();
    other.create_identity('carol@example');
    const otherGroup = other.create_group();
    assert.notEqual(other.safety_number(otherGroup), aliceNumber,
        'a different conversation has a different safety number');
    console.log('PASS: a different conversation has a different safety number');

    // ---- staying in step across a membership change --------------------------
    // The property that used to be missing: when one member changes the
    // membership, everyone else has to apply that commit or they are left in a
    // dead epoch, unable to read anything further.

    const carol = new module.MlsSession();
    carol.create_identity('carol@example');
    const addCarol = alice.add_member(groupId, carol.create_key_package());

    assert.equal(bob.apply_handshake(addCarol.commit), 'applied',
        'a member already in the group applies the commit that admits another');
    const carolGroupId = carol.join_group(addCarol.welcome, addCarol.ratchet_tree);

    assert.equal(Number(alice.epoch(groupId)), Number(bob.epoch(joinedId)),
        'the committer and the existing member are in the same epoch');
    assert.equal(Number(carol.epoch(carolGroupId)), Number(alice.epoch(groupId)),
        'the joiner lands in that same epoch');
    assert.deepEqual(
        [alice.own_leaf(groupId), bob.own_leaf(joinedId), carol.own_leaf(carolGroupId)],
        [0, 1, 2],
        'each device knows its own distinct leaf');

    const toThree = alice.seal(groupId, encoder.encode('three in the room'));
    assert.equal(decoder.decode(bob.open(joinedId, toThree)), 'three in the room',
        'the member who applied the commit keeps reading');
    assert.equal(decoder.decode(carol.open(carolGroupId, toThree)), 'three in the room',
        'so does the one who just joined');
    console.log('PASS: a membership change keeps every member in step');

    // Applying the same commit again, or one's own commit, must be harmless
    // rather than an error: a client re-fetching a queue will do both.
    assert.equal(bob.apply_handshake(addCarol.commit), 'already-applied',
        'a commit already applied is recognised, not reprocessed');
    assert.equal(alice.apply_handshake(addCarol.commit), 'already-applied',
        'the committer recognises its own commit');

    // A handshake for a conversation this device is not in is not an error
    // either; a shared queue can contain one.
    const stranger = new module.MlsSession();
    stranger.create_identity('dave@example');
    const strangerGroup = stranger.create_group();
    const strangerCommit = stranger.add_member(
        strangerGroup,
        (() => { const s = new module.MlsSession(); s.create_identity('erin@example'); return s.create_key_package(); })()
    ).commit;
    assert.equal(bob.apply_handshake(strangerCommit), 'unknown-group',
        'a handshake for another conversation is reported, not thrown');
    // A fresh application message, because an already-opened one would be
    // refused for reuse before its kind could be reported.
    assert.equal(bob.apply_handshake(alice.seal(groupId, encoder.encode('not a handshake'))),
        'not-a-handshake', 'an application message is not mistaken for a handshake');
    assert.throws(() => bob.apply_handshake(new Uint8Array([1, 2, 3])),
        /reading the handshake failed/, 'rubbish is refused');
    console.log('PASS: handshakes that are not ours are reported rather than thrown or misapplied');

    // ---- out of order --------------------------------------------------------
    // Messages arrive out of order on real networks. Within an epoch MLS
    // tolerates that; what it must not tolerate is the same message twice.

    const ordered1 = alice.seal(groupId, encoder.encode('first'));
    const ordered2 = alice.seal(groupId, encoder.encode('second'));
    const ordered3 = alice.seal(groupId, encoder.encode('third'));
    assert.equal(decoder.decode(bob.open(joinedId, ordered3)), 'third',
        'a later message opens before an earlier one');
    assert.equal(decoder.decode(bob.open(joinedId, ordered1)), 'first',
        'the earlier one still opens afterwards');
    assert.equal(decoder.decode(bob.open(joinedId, ordered2)), 'second',
        'and so does the one between them');
    assert.throws(() => bob.open(joinedId, ordered2), /processing failed/,
        'the same message a second time is refused');
    console.log('PASS: out-of-order delivery is tolerated, replay is not');

    // ---- removal -------------------------------------------------------------
    // The property that matters for a lost or stolen device: after removal it
    // must not be able to read what is sent next, while everyone else must.

    const before = alice.seal(groupId, encoder.encode('before the removal'));
    assert.equal(decoder.decode(bob.open(joinedId, before)), 'before the removal',
        'the member reads normally before being removed');

    const removal = alice.remove_member(groupId, bob.identity_key());
    assert.ok(removal.length > 0, 'removing a member yields a commit for the others');
    assert.equal(carol.apply_handshake(removal), 'applied',
        'the remaining member applies the removal');

    const afterRemoval = alice.seal(groupId, encoder.encode('after the removal'));
    assert.equal(decoder.decode(carol.open(carolGroupId, afterRemoval)), 'after the removal',
        'the remaining member keeps reading across the removal');

    let removedCouldRead = false;
    try {
        removedCouldRead = decoder.decode(bob.open(joinedId, afterRemoval)) === 'after the removal';
    } catch (error) {
        removedCouldRead = false;
    }
    assert.equal(removedCouldRead, false,
        'a removed device cannot read what is sent after its removal');

    // Even after being told about its own eviction, and even if it tries again.
    bob.apply_handshake(removal);
    assert.throws(() => bob.open(joinedId, afterRemoval), /UseAfterEviction|processing failed/,
        'a removed device stays evicted');
    console.log('PASS: a removed device cannot read later messages, and the others can');

    console.log('MLS session runtime tests passed.');
})().catch((error) => {
    console.error(error);
    process.exit(1);
});
