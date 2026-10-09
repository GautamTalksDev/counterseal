import { test } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { verifyBundle, verifyExtends, hashLabel, sha256hex, shareableBundle, signerProof } from '../../sdk/receipts.mjs';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, symlinkSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SDK = fileURLToPath(new URL('../../sdk/receipts.mjs', import.meta.url));

test('the zero-dependency SDK verifies real bundles offline and rejects tampering', async () => {
  const w = await World.create();
  const u = await w.user();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const vk = (await w.req('GET', '/v1/log/key', { origin: null, xw: false })).body.verifier_key;
  const r = await w.req('POST', '/v1/receipts', { bearer: key, origin: null, xw: false, body: { receipts: [{ agent: 'a', action: 'one' }, { agent: 'a', action: 'two' }, { agent: 'a', action: 'three' }] } });
  for (const b of r.body.receipts) assert.equal((await verifyBundle(b, vk)).ok, true);
  const b = structuredClone(r.body.receipts[1]);
  b.entry.receipt.action = 'something else';
  await assert.rejects(verifyBundle(b, vk), /leaf hash/);
  const b2 = structuredClone(r.body.receipts[1]);
  b2.inclusion_proof.reverse();
  await assert.rejects(verifyBundle(b2, vk), /inclusion/);
  // a forged log with its own key cannot pass when the real verifier key is pinned
  const other = await World.create();
  const ou = await other.user();
  const okey = (await other.req('POST', '/v1/keys', { cookie: ou.cookie, body: {} })).body.key;
  const forged = (await other.req('POST', '/v1/receipts', { bearer: okey, origin: null, xw: false, body: { receipt: { agent: 'a', action: 'one' } } })).body.receipts[0];
  await assert.rejects(verifyBundle(forged, vk), /different log key/);
  const { log, ...noHint } = forged; void log;
  await assert.rejects(verifyBundle(noHint, vk), /signature/);
  // history only grows
  const old = (await w.req('GET', '/v1/log/checkpoint', { origin: null, xw: false })).body;
  await w.req('POST', '/v1/receipts', { bearer: key, origin: null, xw: false, body: { receipt: { agent: 'a', action: 'four' } } });
  const neu = (await w.req('GET', '/v1/log/checkpoint', { origin: null, xw: false })).body;
  const p = (await w.req('GET', '/v1/log/proof/consistency?first=3&second=4', { origin: null, xw: false })).body.consistency_proof;
  assert.equal(await verifyExtends(old, neu, p, vk), true);
});

test('the CLI runs through an npm-style bin symlink, and never exits 0 without verifying', async () => {
  const w = await World.create();
  const u = await w.user();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const vk = (await w.req('GET', '/v1/log/key', { origin: null, xw: false })).body.verifier_key;
  const b = (await w.req('POST', '/v1/receipts', { bearer: key, origin: null, xw: false, body: { receipt: { agent: 'a', action: 'cli' } } })).body.receipts[0];
  const dir = mkdtempSync(join(tmpdir(), 'receipts-cli-'));
  try {
    const bin = join(dir, 'witness'); // like node_modules/.bin/witness: no extension, a symlink
    symlinkSync(SDK, bin);
    const good = join(dir, 'good.json'), bad = join(dir, 'bad.json'), junk = join(dir, 'junk.json');
    writeFileSync(good, JSON.stringify(b));
    const t = structuredClone(b); t.entry.receipt.action = 'edited'; writeFileSync(bad, JSON.stringify(t));
    writeFileSync(junk, '{ not json');
    const run = (...a) => spawnSync(process.execPath, [bin, ...a], { encoding: 'utf8' });
    let r = run('verify', good, '--key', vk);
    assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /^VERIFIED/);
    r = run('verify', bad, '--key', vk);
    assert.equal(r.status, 1); assert.match(r.stderr, /NOT VERIFIED/);
    for (const args of [[], ['verify'], ['verify', good, '--key'], ['frobnicate'], ['verify', good, 'extra']]) {
      r = run(...args);
      assert.equal(r.status, 2, `usage error for: ${args.join(' ')}`); assert.equal(r.stdout, '');
    }
    for (const f of [junk, join(dir, 'missing.json')]) { r = run('verify', f, '--key', vk); assert.equal(r.status, 1); assert.match(r.stderr, /NOT VERIFIED/); }
    // the wrong pinned key fails
    const other = await World.create();
    const ovk = (await other.req('GET', '/v1/log/key', { origin: null, xw: false })).body.verifier_key;
    assert.equal(run('verify', good, '--key', ovk).status, 1);
    // also when run directly by path
    assert.equal(spawnSync(process.execPath, [SDK, 'verify', good, '--key', vk]).status, 0);
    r = run('hash', 'customer 42', '--salt', 's');
    assert.equal(r.status, 0); assert.equal(r.stdout.trim(), await hashLabel('customer 42', 's'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('hashLabel gives a publishable label that fits the action field', async () => {
  const h = await hashLabel('refund for jane@example.com');
  assert.equal(h, 'sha256:' + (await sha256hex('refund for jane@example.com')));
  assert.ok(h.length <= 80);
  assert.notEqual(await hashLabel('x', 'salt1'), await hashLabel('x', 'salt2'));
});
test('shareable bundles drop the owner opening unless keepOpening is set; signerProof matches the server format', async () => {
  const w = await World.create();
  const u = await w.user();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const vk = (await w.req('GET', '/v1/log/key', { origin: null, xw: false })).body.verifier_key;
  const raw = (await w.req('POST', '/v1/receipts', { bearer: key, origin: null, xw: false, body: { receipt: { agent: 'a', action: 'b' } } })).body.receipts[0];
  assert.ok(raw.opening, 'the API response carries the opening for the owner');
  const shared = shareableBundle(raw);
  assert.equal(shared.opening, undefined);
  assert.equal((await verifyBundle(shared, vk)).ownerProved, false);
  assert.equal((await verifyBundle(shareableBundle(raw, { keepOpening: true }), vk)).ownerProved, true);
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = Buffer.from(await crypto.subtle.exportKey('raw', kp.publicKey)).toString('base64url');
  const ch = (await w.req('POST', '/v1/keys/signer/begin', { cookie: u.cookie, body: { signerPublicKey: pub } })).body;
  const r = await w.req('POST', '/v1/keys', { cookie: u.cookie, body: { signerPublicKey: pub, signerChallengeId: ch.challengeId, signerProof: await signerProof(kp.privateKey, ch.challenge, pub, { origin: ch.origin, account: ch.account }) } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
});
