'use strict';

// Forks, and the state format that has to survive them.
//
// An independent review (2026-09-29) showed that recognising a duplicate commit
// by "its epoch is behind ours" also swallowed a *different* commit from that
// epoch. Two members can commit from the same point, the delivery service picks
// the order, and the genuine removal was reported as `already-applied` — after
// which the nominally removed device kept reading on the branch the client had
// silently taken. This proves the new behaviour: a retry is recognised by its
// exact bytes, anything else from an abandoned epoch is a fork, and a forked
// session stops sending.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const dir = path.join(__dirname, '..', 'assets', 'vendor', 'mls');
const encoder = new TextEncoder();
const decoder = new TextDecoder();

(async () => {
    const mls = await import(path.join(dir, 'pm_mls.js'));
    await mls.default({ module_or_path: fs.readFileSync(path.join(dir, 'pm_mls_bg.wasm')) });

    const session = (name) => {
        const one = new mls.MlsSession();
        one.create_identity(name);
        return one;
    };

    // ---- the reviewer's scenario, verbatim in shape -------------------------

    const a = session('a@example');
    const b = session('b@example');
    const removed = session('removed@example');

    const groupId = a.create_group();
    const addB = a.add_member(groupId, b.create_key_package());
    b.join_group(addB.welcome, addB.ratchet_tree);

    const addRemoved = a.add_member(groupId, removed.create_key_package());
    assert.equal(b.apply_handshake(addRemoved.commit), 'applied');
    removed.join_group(addRemoved.welcome, addRemoved.ratchet_tree);

    // A removes the compromised device. B, from the same epoch, commits
    // something else. Both are valid; whoever delivers them chooses the order.
    const removal = a.remove_member(groupId, removed.identity_key());
    const competing = b.remove_member(groupId, a.identity_key());

    assert.equal(removed.apply_handshake(competing), 'applied',
        'the competing commit applies on the branch it belongs to');

    // The genuine removal now arrives at a session that has left that epoch. It
    // must be called a fork, not a duplicate.
    assert.equal(b.apply_handshake(removal), 'diverged',
        'a different commit from an abandoned epoch is reported as a fork');
    assert.equal(removed.apply_handshake(removal), 'diverged',
        'and is reported as a fork to the other device on that branch too');
    console.log('PASS: a competing same-epoch commit is a fork, not an already-applied duplicate');

    assert.equal(b.has_diverged(groupId), true, 'the fork is remembered');
    assert.throws(() => b.seal(groupId, encoder.encode('post-removal secret')),
        /diverged/,
        'a forked session refuses to seal, so there is nothing for the removed device to read');
    console.log('PASS: a forked session stops sending rather than talking on a branch it cannot vouch for');

    // ---- an exact retry is still a retry -----------------------------------

    const c = session('c@example');
    const d = session('d@example');
    const cleanGroup = c.create_group();
    const addD = c.add_member(cleanGroup, d.create_key_package());
    d.join_group(addD.welcome, addD.ratchet_tree);

    // The joiner never applied this commit — its welcome carried the result —
    // so it is history from before the device existed in the group, not a fork.
    // Getting this wrong would have made every ordinary join look like one.
    assert.equal(d.apply_handshake(addD.commit), 'before-our-time',
        'the commit that admitted a device is recognised as predating it');
    assert.equal(c.apply_handshake(addD.commit), 'already-applied',
        'the committer recognises its own commit by its exact bytes');
    assert.equal(d.has_diverged(cleanGroup), false, 'neither is mistaken for a fork');
    assert.equal(c.has_diverged(cleanGroup), false, 'and the committer is unaffected');

    const message = c.seal(cleanGroup, encoder.encode('still talking'));
    assert.equal(decoder.decode(d.open(cleanGroup, message).plaintext), 'still talking',
        'an honest conversation is unaffected');
    console.log('PASS: an exact retry is still a retry, and honest traffic is unaffected');

    // The fork memory has to survive a reload, or the next page load starts
    // calling forks retries again.
    const state = b.export_state();
    const restored = mls.MlsSession.restore(state, b.identity_key(), encoder.encode('b@example'));
    assert.equal(restored.has_diverged(groupId), true, 'the fork survives an export and restore');
    assert.throws(() => restored.seal(groupId, encoder.encode('after a reload')), /diverged/,
        'and still refuses to send');
    console.log('PASS: divergence survives a reload');

    // ---- the state format ---------------------------------------------------
    // The same review found the old framing accepted trailing bytes, silently
    // collapsed duplicate keys, and truncated a u64 length to zero on wasm32.

    const good = d.export_state();
    const identity = encoder.encode('d@example');
    const key = d.identity_key();

    assert.doesNotThrow(() => mls.MlsSession.restore(good, key, identity),
        'a genuine state restores');

    const trailing = new Uint8Array(good.length + 2);
    trailing.set(good, 0);
    trailing.set([0xde, 0xad], good.length);
    assert.throws(() => mls.MlsSession.restore(trailing, key, identity), /trailing bytes/,
        'trailing bytes are refused rather than ignored');

    const wrongMagic = Uint8Array.from(good);
    wrongMagic[0] = wrongMagic[0] ^ 0xff;
    assert.throws(() => mls.MlsSession.restore(wrongMagic, key, identity), /not a session state/,
        'a state that is not ours is refused by its header');

    assert.throws(() => mls.MlsSession.restore(good.slice(0, good.length - 4), key, identity),
        /truncated/, 'a truncated state is refused');

    // A declared length far beyond the blob must be refused as implausible
    // rather than attempted: bytes 16..20 are the entry count.
    const absurd = Uint8Array.from(good);
    absurd[16] = 0xff; absurd[17] = 0xff; absurd[18] = 0xff; absurd[19] = 0xff;
    assert.throws(() => mls.MlsSession.restore(absurd, key, identity), /implausible|truncated/,
        'an implausible entry count is refused');
    console.log('PASS: the state format refuses trailing bytes, a foreign header, truncation and absurd lengths');

    // ---- the safety number binds the conversation, not just the members ----
    // The review's scenario: two separately keyed groups accepted by the same
    // two devices used to display the same number, so a welcome cross-routed
    // between them was invisible.

    const e = session('e@example');
    const f = session('f@example');

    const firstGroup = e.create_group();
    const joinFirst = e.add_member(firstGroup, f.create_key_package());
    const fFirst = f.join_group(joinFirst.welcome, joinFirst.ratchet_tree);

    const secondGroup = e.create_group();
    const joinSecond = e.add_member(secondGroup, f.create_key_package());
    const fSecond = f.join_group(joinSecond.welcome, joinSecond.ratchet_tree);

    assert.equal(e.safety_number(firstGroup), f.safety_number(fFirst),
        'both devices see the same number for one conversation');
    assert.notEqual(e.safety_number(firstGroup), e.safety_number(secondGroup),
        'two conversations with identical membership have different numbers');
    assert.notEqual(f.safety_number(fFirst), f.safety_number(fSecond),
        'and the other device sees them as different too');
    console.log('PASS: the safety number distinguishes two groups with the same members');

    console.log('MLS fork and state-format tests passed.');
})().catch((error) => {
    console.error(error);
    process.exit(1);
});
