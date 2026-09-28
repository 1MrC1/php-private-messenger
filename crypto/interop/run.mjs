#!/usr/bin/env node
'use strict';

/**
 * The browser interoperability matrix for the MLS build.
 *
 * For every ordered pair of engines it puts one device in each browser and runs
 * a real conversation between them: identity, key package, group, welcome,
 * sealed message, safety number, a membership change and a removal. A build
 * that works in one engine and not another — or worse, one that produces bytes
 * another engine cannot read — fails here.
 *
 * This is not part of the test suite. The application needs no browser
 * automation, and the suite must run for someone with only PHP and Node. Run it
 * yourself with:
 *
 *     node crypto/interop/run.mjs
 *
 * It needs Playwright's browsers. If `playwright` is not resolvable, point
 * PLAYWRIGHT_MODULE at an installation, or install it:
 *
 *     npm i -D playwright && npx playwright install chromium firefox webkit
 *
 * Results, with versions and dates, are recorded in
 * docs/security/browser-interop.md — a claim about browsers is worth nothing
 * without saying which ones and when.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..');

const TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.wasm': 'application/wasm',
    '.json': 'application/json',
};

async function loadPlaywright() {
    const candidates = [process.env.PLAYWRIGHT_MODULE, 'playwright'].filter(Boolean);
    for (const candidate of candidates) {
        try {
            const module = await import(candidate);
            // Playwright is CommonJS, so a dynamic import puts it behind
            // `default` unless Node managed to detect the named exports.
            return module.chromium ? module : (module.default || module);
        } catch (error) {
            // try the next one
        }
    }
    console.error(
        'Playwright is not available.\n' +
        '  npm i -D playwright && npx playwright install chromium firefox webkit\n' +
        '  or: PLAYWRIGHT_MODULE=/path/to/node_modules/playwright node crypto/interop/run.mjs'
    );
    process.exit(2);
}

function serve() {
    const server = http.createServer((request, response) => {
        // Everything is served read-only from the repository, and the path is
        // confined to it: this is a test fixture, but a directory traversal in a
        // fixture is still a directory traversal.
        const requested = decodeURIComponent((request.url || '/').split('?')[0]);
        const target = path.join(root, path.normalize(requested).replace(/^(\.\.[/\\])+/, ''));
        if (!target.startsWith(root + path.sep)) {
            response.writeHead(403).end('no');
            return;
        }
        fs.readFile(target, (error, bytes) => {
            if (error) {
                response.writeHead(404).end('not found');
                return;
            }
            response.writeHead(200, {
                'content-type': TYPES[path.extname(target)] || 'application/octet-stream',
                // WebAssembly needs this policy in the real application too.
                'content-security-policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'",
            }).end(bytes);
        });
    });
    return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
    });
}

/** One device, living in one browser page. */
function device(page, key) {
    const call = (method, ...args) =>
        page.evaluate(({ method, args, key }) => window.pm[method](key, ...args), { method, args, key });
    return {
        key,
        createIdentity: (name) => call('createIdentity', name),
        createKeyPackage: () => call('createKeyPackage'),
        createGroup: () => call('createGroup'),
        addMember: (groupId, keyPackage) => call('addMember', groupId, keyPackage),
        joinGroup: (welcome, tree) => call('joinGroup', welcome, tree),
        seal: (groupId, text) => call('seal', groupId, text),
        open: (groupId, sealed) => call('open', groupId, sealed),
        applyHandshake: (handshake) => call('applyHandshake', handshake),
        removeMember: (groupId, signatureKey) => call('removeMember', groupId, signatureKey),
        identityKey: () => call('identityKey'),
        safetyNumber: (groupId) => call('safetyNumber', groupId),
        epoch: (groupId) => call('epoch', groupId),
        exportState: () => call('exportState'),
        restore: (state, publicKey, name) => call('restore', state, publicKey, name),
        expectRefusal: (groupId, sealed) => call('expectRefusal', groupId, sealed),
    };
}

/**
 * A conversation with one device in each of two engines. Returns nothing and
 * throws on the first thing that does not hold.
 */
async function conversation(alicePage, bobPage, label) {
    const alice = device(alicePage, 'alice-' + label);
    const bob = device(bobPage, 'bob-' + label);

    await alice.createIdentity('alice@' + label);
    const bobKey = await bob.createIdentity('bob@' + label);

    const keyPackage = await bob.createKeyPackage();
    const groupId = await alice.createGroup();
    const added = await alice.addMember(groupId, keyPackage);
    const joined = await bob.joinGroup(added.welcome, added.ratchetTree);

    if (joined !== groupId) {
        throw new Error(label + ': the joiner landed in a different group');
    }

    const secret = 'sealed in one engine, opened in another';
    const sealed = await alice.seal(groupId, secret);
    const opened = await bob.open(joined, sealed);
    if (opened !== secret) {
        throw new Error(label + ': the message did not survive the crossing: ' + JSON.stringify(opened));
    }

    // Both directions, because a one-way check would miss an engine that can
    // read but not write.
    const back = 'and back the other way';
    const reply = await bob.seal(joined, back);
    if (await alice.open(groupId, reply) !== back) {
        throw new Error(label + ': the reply did not survive the crossing');
    }

    // The safety number is what people compare out of band; it must not depend
    // on the engine that computed it.
    const aliceNumber = await alice.safetyNumber(groupId);
    const bobNumber = await bob.safetyNumber(joined);
    if (aliceNumber !== bobNumber) {
        throw new Error(label + ': the safety numbers differ across engines');
    }

    // A membership change, applied across the pair.
    const carol = device(bobPage, 'carol-' + label);
    await carol.createIdentity('carol@' + label);
    const addCarol = await alice.addMember(groupId, await carol.createKeyPackage());
    if (await bob.applyHandshake(addCarol.commit) !== 'applied') {
        throw new Error(label + ': the existing member could not apply the commit');
    }
    const carolGroup = await carol.joinGroup(addCarol.welcome, addCarol.ratchetTree);
    const toThree = await alice.seal(groupId, 'three engines in the room');
    if (await bob.open(joined, toThree) !== 'three engines in the room' ||
        await carol.open(carolGroup, toThree) !== 'three engines in the room') {
        throw new Error(label + ': a member stopped reading after the membership change');
    }
    if (await alice.epoch(groupId) !== await bob.epoch(joined)) {
        throw new Error(label + ': the epochs diverged across engines');
    }

    // A removal, and the removed device must not read what follows.
    const removal = await alice.removeMember(groupId, await bob.identityKey());
    await carol.applyHandshake(removal);
    const afterRemoval = await alice.seal(groupId, 'after the removal');
    if (await carol.open(carolGroup, afterRemoval) !== 'after the removal') {
        throw new Error(label + ': the remaining member stopped reading after a removal');
    }
    if (!(await bob.expectRefusal(joined, afterRemoval))) {
        throw new Error(label + ': a removed device could still read');
    }

    // State written by one engine must be readable by that engine after a
    // reload; this is what a page refresh does.
    const state = await carol.exportState();
    const restored = device(bobPage, 'carol-restored-' + label);
    await restored.restore(state, await carol.identityKey(), 'carol@' + label);
    const afterReload = await alice.seal(groupId, 'after a reload');
    if (await restored.open(carolGroup, afterReload) !== 'after a reload') {
        throw new Error(label + ': exported state did not survive a reload');
    }
}

const { server, port } = await serve();
const playwright = await loadPlaywright();
const url = `http://127.0.0.1:${port}/crypto/interop/harness.html`;

const engines = ['chromium', 'firefox', 'webkit'];
const open = new Map();
const versions = new Map();
const failures = [];
const unavailable = [];
const probes = new Map();

try {
    for (const name of engines) {
        // An engine that is not installed is reported as not run rather than
        // crashing the matrix: a partial result honestly labelled is worth more
        // than no result, and pretending otherwise is how interop claims rot.
        let browser;
        try {
            browser = await playwright[name].launch();
        } catch (error) {
            unavailable.push(`${name}: ${error.message.split('\n')[0]}`);
            console.log(`SKIP: ${name} is not available here`);
            continue;
        }
        const page = await browser.newPage();
        page.on('pageerror', (error) => failures.push(`${name}: page error: ${error.message}`));
        await page.goto(url);
        await page.waitForFunction(() => window.pm && window.pm.ready === true, null, { timeout: 60000 });
        open.set(name, { browser, page });
        versions.set(name, `${name} ${browser.version()}`);
        console.log(`loaded in ${versions.get(name)}`);

        // The build loading is not enough: the client also needs a
        // non-extractable AES-GCM key it can keep in IndexedDB, and
        // PBKDF2-SHA512 for recovery files.
        const report = await page.evaluate(() => window.pm.probe());
        probes.set(name, report);
        const missing = ['aesGcm', 'nonExtractable', 'indexedDbCryptoKey', 'pbkdf2Sha512']
            .filter((capability) => report[capability] !== true);
        if (missing.length > 0) {
            failures.push(`${name}: missing ${missing.join(', ')}`);
            console.log(`FAIL: ${name} is missing ${missing.join(', ')}`);
        } else {
            console.log(`PASS: ${name} has what the client needs (PBKDF2 600k took ${report.pbkdf2Ms} ms)`);
        }
    }

    for (const from of open.keys()) {
        for (const to of open.keys()) {
            const label = `${from}-to-${to}`;
            try {
                await conversation(open.get(from).page, open.get(to).page, label);
                console.log(`PASS: ${from} → ${to}`);
            } catch (error) {
                failures.push(`${label}: ${error.message}`);
                console.log(`FAIL: ${from} → ${to}: ${error.message}`);
            }
        }
    }
} finally {
    for (const { browser } of open.values()) {
        await browser.close().catch(() => {});
    }
    server.close();
}

console.log('\nEngines:');
for (const name of engines) {
    console.log('  ' + (versions.get(name) || `${name} — not run here`));
}
console.log('\nBrowser features the client depends on:');
for (const [name, report] of probes) {
    console.log(`  ${name}: AES-GCM ${report.aesGcm}, non-extractable ${report.nonExtractable}, ` +
        `CryptoKey in IndexedDB ${report.indexedDbCryptoKey}, PBKDF2-SHA512 ${report.pbkdf2Sha512} ` +
        `(600k iterations in ${report.pbkdf2Ms} ms)`);
}

if (unavailable.length > 0) {
    console.log('\nNot run:');
    for (const entry of unavailable) {
        console.log('  ' + entry);
    }
}

if (failures.length > 0) {
    console.error('\n' + failures.length + ' failure(s):');
    for (const failure of failures) {
        console.error('  ' + failure);
    }
    process.exit(1);
}

const ran = open.size;
if (ran < 2) {
    console.error('\nOnly ' + ran + ' engine(s) ran, so nothing was shown to interoperate.');
    process.exit(1);
}
console.log('\nAll ' + ran * ran + ' pairs of the ' + ran + ' engines present interoperate.');
