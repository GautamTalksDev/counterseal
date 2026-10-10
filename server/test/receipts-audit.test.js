// Regression tests for the 9 Oct 2026 launch audit. Each test is named after its finding and encodes the audit's PoC.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World, signedKey } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';

const anon = { origin: null, xw: false };
beforeEach(() => _resetMemoryBuckets());

async function victimAndMallory() {
  const w = await World.create();
  const victim = await w.user('Victim', '203.0.113.1');
  const mallory = await w.user('Mallory', '198.51.100.7');
  const signer = await signedKey(w, victim.cookie, 'v');
  const mkey = (await w.req('POST', '/v1/keys', { cookie: mallory.cookie, body: { label: 'm' } })).body.key;
  return { w, victim, mallory, signer, mkey };
}

// ---- H1
test('H1: a signed receipt copied from the public log cannot be re-logged through an unsigned API key', async () => {
  const { w, signer, mkey } = await victimAndMallory();
  const signed = await signer.sign({ agent: 'billing-bot', action: 'stripe.refund', decision: 'approved', ts: Date.now() });
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: signer.key, ...anon, body: { receipt: signed } })).status, 200);
  const captured = (await w.req('GET', '/v1/log/entries?start=0&count=1', anon)).body.entries[0].entry.receipt;
  for (let i = 0; i < 3; i++) {
    const r = await w.req('POST', '/v1/receipts', { bearer: mkey, ...anon, body: { receipt: captured } });
    assert.equal(r.status, 400, `try ${i}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error, 'sig_requires_signer_key');
  }
  assert.equal(w.core.size(), 1, 'only the original is in the log');
});

test('H1: a sig without ts is refused on an unsigned API key, and a batch with one such receipt records nothing', async () => {
  const { w, signer, mkey } = await victimAndMallory();
  const { sig } = await signer.sign({ agent: 'billing-bot', action: 'stripe.refund', decision: 'approved' });
  const r = await w.req('POST', '/v1/receipts', { bearer: mkey, ...anon, body: { receipt: { agent: 'billing-bot', action: 'stripe.refund', decision: 'approved', sig } } });
  assert.equal(r.status, 400); assert.equal(r.body.error, 'sig_requires_signer_key');
  const b = await w.req('POST', '/v1/receipts', { bearer: mkey, ...anon, body: { receipts: [{ agent: 'a', action: 'ok' }, { agent: 'a', action: 'b', sig }] } });
  assert.equal(b.body.error, 'sig_requires_signer_key');
  assert.equal(w.core.size(), 0);
});

// ---- shared: a real bundle from a World, and a forged one under the same origin name signed with an attacker key
const te = new TextEncoder();
async function realBundle(w) {
  const u = await w.user('Owner', '203.0.113.20');
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const b = (await w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt: { agent: 'billing-bot', action: 'stripe.refund', decision: 'approved' } } })).body.receipts[0];
  const vk = (await w.req('GET', '/v1/log/key', anon)).body.verifier_key;
  const { opening, ...share } = b; void opening;
  return { b: share, vk, key, u };
}
async function forgedBundle(name) {
  const { canonical } = await import('../src/receipts.js');
  const fk = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const fpub = new Uint8Array(await crypto.subtle.exportKey('raw', fk.publicKey));
  const id = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...te.encode(name + '\n'), 1, ...fpub]))).slice(0, 4);
  const entry = { v: 2, submitter: 'f'.repeat(64), received_at: Date.parse('2026-01-01'), receipt: { agent: 'billing-bot', action: 'stripe.refund ALL', decision: 'approved' } };
  const leaf = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([0, ...te.encode(canonical(entry))])));
  const std = (x) => Buffer.from(x).toString('base64');
  const body = `${name}\n1\n${std(leaf)}\n`;
  const fsig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, fk.privateKey, te.encode(body)));
  return { index: 0, leaf_hash: std(leaf), tree_size: 1, inclusion_proof: [], checkpoint: `${body}\n— ${name} ${std(new Uint8Array([...id, ...fsig]))}\n`, entry, log: `${name}+${Buffer.from(id).toString('hex')}+${std(new Uint8Array([1, ...fpub]))}` };
}
const sdk = await import('../../sdk/receipts.mjs');
const SDK_PATH = new URL('../../sdk/receipts.mjs', import.meta.url).pathname;
const { spawnSync } = await import('node:child_process');
const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
const { tmpdir } = await import('node:os');
const { join } = await import('node:path');
function cliRun(files, ...args) {
  const dir = mkdtempSync(join(tmpdir(), 'receipts-audit-'));
  try {
    const paths = Object.fromEntries(Object.entries(files).map(([n, v]) => { const p = join(dir, n); writeFileSync(p, typeof v === 'string' ? v : JSON.stringify(v)); return [n, p]; }));
    return spawnSync(process.execPath, [SDK_PATH, ...args.map((a) => paths[a] ?? a)], { encoding: 'utf8' });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ---- M1
test('M1: the in-browser verifier checks a pasted bundle against the log\'s own key, never the key inside the bundle', async () => {
  const { checkPasted } = await import('../../site/public/check.js');
  const w = await World.create();
  const { b, vk } = await realBundle(w);
  const forged = await forgedBundle('leash.test/log');
  assert.equal((await sdk.verifyBundle(forged, forged.log)).ok, true, 'the forged bundle is self-consistent (the PoC)');
  const bad = await checkPasted(JSON.stringify(forged), { logKey: vk }, sdk);
  assert.equal(bad.ok, false); assert.match(bad.text, /^NOT VERIFIED/);
  const good = await checkPasted(JSON.stringify(b), { logKey: vk }, sdk);
  assert.equal(good.ok, true, good.text); assert.match(good.text, /^VERIFIED\n/); assert.ok(good.text.includes(vk), 'says which key it checked against');
  const noLog = structuredClone(forged); delete noLog.log;
  assert.equal((await checkPasted(JSON.stringify(noLog), { logKey: vk }, sdk)).ok, false, 'removing the log hint does not help');
  assert.equal((await checkPasted(JSON.stringify(b), { logKey: null }, sdk)).ok, false, 'no key, no verdict');
  // the sample: a throwaway key made in the browser, and the result says so
  const demo = await checkPasted(JSON.stringify(forged), { logKey: vk, demoKey: forged.log }, sdk);
  assert.equal(demo.ok, true); assert.match(demo.text, /^VERIFIED \(DEMO KEY\)/); assert.match(demo.text, /not this log/);
  assert.equal((await checkPasted('{ nope', { logKey: vk }, sdk)).ok, false);
});

test('M1: verifyBundle needs the key you pin; a bundle that names another log key is refused', async () => {
  const w = await World.create();
  const { b, vk } = await realBundle(w);
  await assert.rejects(sdk.verifyBundle(b), /verifier key/);
  const forged = await forgedBundle('leash.test/log');
  await assert.rejects(sdk.verifyBundle(forged, vk), /different log key/);
  assert.equal((await sdk.verifyBundle(b, vk)).ok, true);
});

test('M1: the CLI without --key prints VERIFIED (UNPINNED KEY) and does not exit 0', async () => {
  const w = await World.create();
  const { b, vk } = await realBundle(w);
  let r = cliRun({ 'b.json': b }, 'verify', 'b.json');
  assert.equal(r.status, 3, r.stdout + r.stderr); assert.match(r.stdout, /^VERIFIED \(UNPINNED KEY\)/);
  r = cliRun({ 'f.json': await forgedBundle('leash.test/log') }, 'verify', 'f.json');
  assert.notEqual(r.status, 0, 'a forged bundle never exits 0 without a pinned key');
  r = cliRun({ 'b.json': b }, 'verify', 'b.json', '--key', vk);
  assert.equal(r.status, 0); assert.match(r.stdout, /^VERIFIED  entry/);
});

// ---- M2
const { b64u } = await import('../src/util.js');
const P = 2n ** 255n - 19n, L = 2n ** 252n + 27742317777372353535851937790883648493n;
const leBytes = (n, len = 32) => Uint8Array.from({ length: len }, (_, i) => Number((n >> (8n * BigInt(i))) & 255n));
test('M2: small-order and non-canonical Ed25519 public keys cannot be bound as signers', async () => {
  const w = await World.create();
  const u = await w.user();
  const y8 = 2707385501144840649318225287225658788936804267575313519463743609750303402022n; // an order-8 point's y
  assert.equal(y8 + 55188659117513257062467267217118295137698188065244968500265048394206261417927n, P, 'the two order-8 y values are y and -y');
  const weak = [];
  for (const y of [0n, 1n, P - 1n, y8, P - y8, P, P + 1n, P + 2n, 2n ** 255n - 1n]) for (const sign of [0, 1]) {
    const k = leBytes(y); if (sign) k[31] |= 0x80; weak.push(b64u(k));
  }
  assert.ok(weak.includes('AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), 'includes the PoC identity point');
  for (const pub of weak) {
    const r = await w.req('POST', '/v1/keys/signer/begin', { cookie: u.cookie, body: { signerPublicKey: pub } });
    assert.equal(r.status, 400, pub); assert.equal(r.body.error, 'bad_signerPublicKey', pub);
  }
  // the PoC: with the identity key, R = identity and s = 0 "verifies" over any message in WebCrypto on Node 22 (OpenSSL
  // 3.0); Node 24 refuses it (or the key) itself. The server must refuse the key either way, so the platform's answer is
  // not asserted, only that the server never relies on it.
  const ident = leBytes(1n);
  try {
    const ik = await crypto.subtle.importKey('raw', ident, { name: 'Ed25519' }, false, ['verify']);
    await crypto.subtle.verify({ name: 'Ed25519' }, ik, new Uint8Array([...ident, ...new Uint8Array(32)]), te.encode('anything'));
  } catch { /* a platform that refuses the identity key outright */ }
  const r = await w.req('POST', '/v1/keys', { cookie: u.cookie, body: { label: 'weak', signerPublicKey: b64u(ident), signerChallengeId: 'ab'.repeat(12), signerProof: b64u(new Uint8Array([...ident, ...new Uint8Array(32)])) } });
  assert.equal(r.body.error, 'bad_signerPublicKey', 'refused before any challenge is looked at');
  assert.equal((await signedKey(w, u.cookie)).key.startsWith('lsr_'), true, 'a normal key still binds');
});

test('M2: a signature whose s is not reduced (s >= L) is refused as a non-canonical encoding', async () => {
  const { w, s } = await signedSetup();
  const good = await s.sign({ agent: 'a', action: 'b', ts: Date.now() });
  const raw = Uint8Array.from(Buffer.from(good.sig.value, 'base64url'));
  const sv = raw.slice(32).reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);
  const bad = new Uint8Array([...raw.slice(0, 32), ...leBytes(sv + L)]);
  const r = await w.req('POST', '/v1/receipts', { bearer: s.key, ...anon, body: { receipt: { ...good, sig: { alg: 'ed25519', value: b64u(bad) } } } });
  assert.equal(r.status, 400); assert.equal(r.body.error, 'bad_sig');
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: s.key, ...anon, body: { receipt: good } })).status, 200);
});

// ---- L1
const UNSAFE = { DEL: '\u007f', 'C1 CSI': '\u009b', ESC: '\u001b', RLO: '‮', LRI: '⁦', ZWSP: '​', BOM: '﻿', LS: ' ', 'lone surrogate': '\ud800' };
test('L1: labels with control, bidi and invisible characters are refused in every free-text field', async () => {
  const w = await World.create();
  const u = await w.user();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const send = (receipt) => w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt } });
  for (const [name, ch] of Object.entries(UNSAFE)) {
    for (const [field, rc, code] of [['agent', { agent: 'a' + ch, action: 'x' }, 'bad_agent'], ['action', { agent: 'a', action: 'refund' + ch + 'txt.exe' }, 'bad_action'],
      ['subject', { agent: 'a', action: 'x', subject: ch }, 'bad_subject'], ['run', { agent: 'a', action: 'x', run: 'r' + ch }, 'bad_run'], ['meta', { agent: 'a', action: 'x', meta: { k: 'v' + ch } }, 'bad_meta']]) {
      const r = await send(rc);
      assert.equal(r.status, 400, `${name} in ${field}`); assert.equal(r.body.error, code, `${name} in ${field}`);
    }
  }
  assert.equal((await send({ agent: 'Café 日本 🚀', action: 'naïve ñ', subject: 'Ünïcödé', meta: { k: 'ok é' } })).status, 200, 'ordinary Unicode is fine');
  assert.equal(w.core.size(), 1);
});

test('L1: the CLI and the website escape control and bidi characters from a verified bundle instead of printing them', async () => {
  const w = await World.create();
  const { canonical } = await import('../src/receipts.js');
  const { b64std } = await import('../src/note.js');
  const vk = (await w.req('GET', '/v1/log/key', anon)).body.verifier_key;
  // an entry that bypassed validation (an old or hostile log): labels with ESC, CSI, RLO and BOM
  const entry = canonical({ v: 2, submitter: 'e'.repeat(64), received_at: Date.now(), receipt: { agent: 'evil‮bot', action: '\u001b[31mred\u009b1m', decision: 'approved﻿' } });
  const res = await w.core.append([{ tenant: 't', entry }], Date.now());
  const e = res.entries[0];
  const b = { index: e.index, leaf_hash: b64std(e.leaf), tree_size: res.size, inclusion_proof: e.proof.map(b64std), checkpoint: res.note, entry: JSON.parse(entry), log: vk };
  const r = cliRun({ 'b.json': b }, 'verify', 'b.json', '--key', vk);
  assert.equal(r.status, 0, r.stderr);
  for (const ch of ['‮', '\u001b', '\u009b', '﻿']) assert.ok(!r.stdout.includes(ch), 'raw ' + JSON.stringify(ch) + ' printed');
  assert.match(r.stdout, /evil\\u\{202e\}bot/);
  const { checkPasted } = await import('../../site/public/check.js');
  const web = await checkPasted(JSON.stringify(b), { logKey: vk }, sdk);
  assert.equal(web.ok, true);
  for (const ch of ['‮', '\u001b', '\u009b', '﻿']) assert.ok(!web.text.includes(ch), 'web shows raw ' + JSON.stringify(ch));
});

// ---- L2
test('L2: verifyBundle refuses an index or tree size that is not a non-negative safe integer', async () => {
  const w = await World.create();
  const { b, vk } = await realBundle(w);
  assert.equal((await sdk.verifyBundle(b, vk)).index, 0);
  for (const index of [-1, 0.5, '0', null, NaN, 2 ** 53, -0.5]) await assert.rejects(sdk.verifyBundle({ ...b, index }, vk), Error, `index ${JSON.stringify(index)}`);
  for (const tree_size of ['1', 1.5, -1]) await assert.rejects(sdk.verifyBundle({ ...b, tree_size }, vk), Error, `tree_size ${JSON.stringify(tree_size)}`);
  await assert.rejects(sdk.verifyBundle({ ...b, inclusion_proof: [123] }, vk), Error);
});

test('L2: verifyInclusion and verifyConsistency (SDK and server) return false for bad indexes and sizes', async () => {
  const merkle = await import('../src/merkle.js');
  const leaf = new Uint8Array(32), root = leaf;
  for (const v of [sdk.verifyInclusion, merkle.verifyInclusion]) {
    assert.equal(await v(0, 1, leaf, [], root), true, 'a one-leaf tree is its leaf');
    for (const [i, n] of [[-1, 1], [0.5, 1], ['0', 1], [0, 1.5], [0, '1'], [NaN, 1], [-1, 0]]) assert.equal(await v(i, n, leaf, [], root), false, `${v === sdk.verifyInclusion ? 'sdk' : 'server'} ${JSON.stringify([i, n])}`);
  }
  for (const v of [sdk.verifyConsistency, merkle.verifyConsistency]) {
    for (const [m, n] of [[0.5, 1], ['1', '1'], [-1, 1], [1, 2.5]]) assert.equal(await v(m, n, root, root, [leaf]), false, JSON.stringify([m, n]));
  }
});

test('L2: a checkpoint whose size line is not a plain decimal is refused, even when signed', async () => {
  const w = await World.create();
  const { signCheckpoint } = await import('../src/note.js');
  const vk = (await w.req('GET', '/v1/log/key', anon)).body.verifier_key;
  const root = new Uint8Array(32);
  assert.equal((await sdk.verifyCheckpoint(await signCheckpoint(w.env, 1, root), vk)).size, 1);
  for (const size of ['1e0', '01', '-1', ' 1', '0x1', '1.0', '9007199254740993']) await assert.rejects(sdk.verifyCheckpoint(await signCheckpoint(w.env, size, root), vk), /checkpoint/, size);
  await assert.rejects(sdk.verifyCheckpoint((await signCheckpoint(w.env, 1, new Uint8Array(31))), vk), /checkpoint/, 'a root must be 32 bytes');
});

// ---- L3
test('L3: an inclusion proof needs an explicit index, and numeric query parameters are plain decimals', async () => {
  const w = await World.create();
  const { u } = await realBundle(w);
  const get = (p) => w.req('GET', p, anon);
  assert.equal((await get('/v1/log/proof/inclusion?index=0')).status, 200);
  const r = await get('/v1/log/proof/inclusion');
  assert.equal(r.status, 400, JSON.stringify(r.body)); assert.equal(r.body.error, 'bad_index');
  for (const q of ['index=', 'index=0x0', 'index=0e0', 'index=%200', 'index=-0', 'index=00']) assert.equal((await get('/v1/log/proof/inclusion?' + q)).body.error, 'bad_index', q);
  assert.equal((await get('/v1/log/proof/inclusion?index=0&size=')).body.error, 'bad_size');
  assert.equal((await get('/v1/log/entries?start=')).body.error, 'bad_start');
  assert.equal((await get('/v1/log/entries?count=1e1')).body.error, 'bad_count');
  assert.equal((await get('/v1/log/proof/consistency?first=1&second=0x1')).body.error, 'bad_second');
  assert.equal((await w.req('GET', '/v1/my/receipts?before=', { cookie: u.cookie })).body.error, 'bad_before');
  assert.equal((await get('/v1/log/entries')).status, 200, 'optional parameters may still be left out');
});

// ---- M4
const { handle } = await import('../src/index.js');
/** a POST whose body is a stream of 1 KB chunks; counts how many chunks the server pulled */
function streamingPost(w, path, { chunks = 1024, contentLength } = {}) {
  const st = { pulled: 0 };
  const body = new ReadableStream({ pull(c) { if (st.pulled >= chunks) return c.close(); st.pulled++; c.enqueue(new TextEncoder().encode(st.pulled === 1 ? '{"name":"' + 'x'.repeat(1015) : 'x'.repeat(1024))); } }, { highWaterMark: 0 });
  const headers = { 'content-type': 'application/json', origin: 'https://leash.test', 'cf-connecting-ip': '203.0.113.50' };
  if (contentLength !== undefined) headers['content-length'] = String(contentLength);
  const req = new Request('https://leash.test' + path, { method: 'POST', body, duplex: 'half', headers });
  return { st, res: handle(req, w.env, { log: w.log }) };
}
test('M4: an unauthenticated body that declares more than 16 KB is refused before any of it is read', async () => {
  const w = await World.create();
  const { st, res } = streamingPost(w, '/v1/auth/register/begin', { contentLength: 10_000_000 });
  const r = await res;
  assert.equal(r.status, 413); assert.equal((await r.json()).error, 'too_large');
  assert.equal(st.pulled, 0, 'nothing was read');
});

test('M4: a chunked body without content-length is read only up to the cap, then refused', async () => {
  const w = await World.create();
  const { st, res } = streamingPost(w, '/v1/auth/register/begin', { chunks: 1024 });
  const r = await res;
  assert.equal(r.status, 413);
  assert.ok(st.pulled <= 18, `pulled ${st.pulled} KB of a 1 MB body for a 16 KB cap`);
  const ok = await w.req('POST', '/v1/auth/register/begin', { body: { name: 'Still works' } });
  assert.equal(ok.status, 200, 'normal bodies are unaffected');
});

// ---- M5
test('M5: a storage failure in the middle of an append leaves the log as it was, and the next append works', async () => {
  const merkle = await import('../src/merkle.js');
  const refMth = async (l) => { if (l.length === 1) return l[0]; let k = 1; while (k * 2 < l.length) k *= 2; return merkle.nodeHash(await refMth(l.slice(0, k)), await refMth(l.slice(k))); };
  const w = await World.create();
  const u = await w.user();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const vk = (await w.req('GET', '/v1/log/key', anon)).body.verifier_key;
  const post = (n, p) => w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipts: Array.from({ length: n }, (_, i) => ({ agent: 'a', action: p + i })) } });
  const rows = (t) => w.sql.raw.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n;
  assert.equal((await post(3, 'a')).status, 200);
  const before = { leaves: rows('leaves'), nodes: rows('nodes'), head: JSON.stringify(w.core.head()) };
  for (const where of [/INSERT INTO head/, /INSERT INTO nodes/]) {
    w.sql.failOn = where; // the next matching statement throws, once
    assert.equal((await post(2, 'b')).status, 500, String(where));
    assert.deepEqual({ leaves: rows('leaves'), nodes: rows('nodes'), head: JSON.stringify(w.core.head()) }, before, 'nothing half-written after ' + where);
  }
  const r = await post(3, 'c');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(w.core.size(), 6);
  const leaves = w.sql.raw.prepare('SELECT hash FROM leaves ORDER BY idx').all().map((x) => new Uint8Array(x.hash));
  assert.deepEqual(new Uint8Array(w.core.head().root), await refMth(leaves), 'root matches an RFC 6962 reference');
  for (const b of r.body.receipts) assert.equal((await sdk.verifyBundle(b, vk)).ok, true);
});

// ---- M3
const MIN = 60_000;
/** run fn with Date.now() shifted by ms (the server reads the clock through Date.now) */
async function at(ms, fn) { const real = Date.now; const t0 = real(); Date.now = () => t0 + ms + (real() - t0); try { return await fn(); } finally { Date.now = real; } }
test('M3: a signed receipt must carry a ts within 10 minutes of the server clock', async () => {
  const { w, s } = await signedSetup();
  const send = async (dt) => w.req('POST', '/v1/receipts', { bearer: s.key, ...anon, body: { receipt: await s.sign({ agent: 'a', action: 'dt ' + dt, ts: Date.now() + dt }) } });
  for (const dt of [-11 * MIN, 11 * MIN, -365 * 24 * 60 * MIN]) { const r = await send(dt); assert.equal(r.status, 400, String(dt)); assert.equal(r.body.error, 'stale_ts'); }
  for (const dt of [-9 * MIN, 9 * MIN, 0]) assert.equal((await send(dt)).status, 200, String(dt));
  assert.equal(w.core.size(), 3);
});

test('M3: replay records are pruned once their receipts are past the window, by cron and opportunistically, and stay unreplayable', async () => {
  const { w, s, count } = await signedSetup();
  const worker = (await import('../src/index.js')).default;
  const old = await s.sign({ agent: 'a', action: 'old', ts: Date.now() });
  const send = (receipt) => w.req('POST', '/v1/receipts', { bearer: s.key, ...anon, body: { receipt } });
  assert.equal((await send(old)).status, 200);
  assert.equal(count('signed_receipts'), 1);
  await at(31 * MIN, async () => {
    await worker.scheduled({}, w.env);
    assert.equal(count('signed_receipts'), 0, 'cron pruned the record');
    const r = await send(old);
    assert.equal(r.status, 400, 'the old receipt is outside the window, so it still cannot be replayed'); assert.equal(r.body.error, 'stale_ts');
  });
  // opportunistic: with no cron at all, a later signed request prunes old records
  assert.equal((await send(await s.sign({ agent: 'a', action: 'second', ts: Date.now() }))).status, 200);
  await at(62 * MIN, async () => {
    assert.equal((await send(await s.sign({ agent: 'a', action: 'third', ts: Date.now() }))).status, 200);
    assert.equal(count('signed_receipts'), 1, 'only the fresh record is left');
  });
});

// ---- L7
test('L7: the signer proof names the log origin and the account, and the CLI prints both before it signs', async () => {
  const w = await World.create();
  const u = await w.user();
  const accountId = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body.account.id;
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const pub = jwk.x;
  const begin = async () => (await w.req('POST', '/v1/keys/signer/begin', { cookie: u.cookie, body: { signerPublicKey: pub } })).body;
  let ch = await begin();
  assert.equal(ch.origin, 'leash.test/log'); assert.equal(ch.account, accountId);
  assert.equal(ch.sign, `witness/signer-proof/v2\nleash.test/log\n${accountId}\n${ch.challenge}\n${pub}`);
  const bind = (c, signerProof) => w.req('POST', '/v1/keys', { cookie: u.cookie, body: { label: 'cli', signerPublicKey: pub, signerChallengeId: c.challengeId, signerProof } });
  // a proof over the old text, without origin and account, is refused
  const v1 = b64u(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, te.encode(`witness/signer-proof/v1\n${ch.challenge}\n${pub}`)));
  assert.equal((await bind(ch, v1)).body.error, 'bad_signerProof');
  // the CLI shows what it is about to authorize, then signs
  ch = await begin();
  const r = cliRun({ 'k.jwk': jwk }, 'prove-signer', ch.challenge, '--origin', ch.origin, '--account', ch.account, '--jwk', 'k.jwk');
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stderr.includes('leash.test/log') && r.stderr.includes(accountId), r.stderr);
  assert.equal((await bind(ch, r.stdout.trim())).status, 200);
  for (const args of [['prove-signer', 'abc', '--jwk', 'k.jwk'], ['prove-signer', 'abc', '--origin', 'o', '--jwk', 'k.jwk'], ['prove-signer', 'abc', '--origin', 'bad origin', '--account', accountId, '--jwk', 'k.jwk']]) {
    assert.equal(cliRun({ 'k.jwk': jwk }, ...args).status, 2, args.join(' '));
  }
  await assert.rejects(sdk.signerProof(kp.privateKey, ch.challenge, pub), /origin/);
  ch = await begin();
  assert.equal((await bind(ch, await sdk.signerProof(kp.privateKey, ch.challenge, pub, { origin: ch.origin, account: ch.account }))).status, 200);
});

// ---- L8
test('L8: a signed batch imports the signer public key once per request, not once per receipt', async () => {
  const { batch, post } = await signedSetup();
  const rs = await batch(SIGNED_MAX);
  const real = crypto.subtle.importKey;
  let imports = 0;
  crypto.subtle.importKey = function (format, data, alg, ...rest) { if (format === 'raw' && alg?.name === 'Ed25519') imports++; return real.call(this, format, data, alg, ...rest); };
  try {
    assert.equal((await post(rs)).status, 200);
  } finally { crypto.subtle.importKey = real; }
  assert.equal(imports, 1, `${imports} imports of the signer key for ${SIGNED_MAX} receipts`);
});

test('L8: batches are capped where the measured CPU keeps a margin under the Free plan 10 ms: 25 unsigned, 12 signed', async () => {
  const { w, u, batch, post } = await signedSetup();
  const plain = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  const unsigned = (n) => w.req('POST', '/v1/receipts', { bearer: plain, ...anon, body: { receipts: Array.from({ length: n }, (_, i) => ({ agent: 'a', action: 'u' + i })) } });
  assert.deepEqual([LIMITS.MAX_BATCH, LIMITS.MAX_SIGNED_BATCH], [25, 12]);
  assert.equal((await unsigned(26)).body.error, 'bad_batch');
  assert.equal((await unsigned(25)).status, 200);
  assert.equal((await post(await batch(13))).body.error, 'bad_batch');
  assert.equal((await post(await batch(12, Date.now() + 1000))).status, 200);
});

// ---- L4
async function captureLogs(fn) {
  const lines = [], orig = { error: console.error, warn: console.warn };
  console.error = (...a) => lines.push(['error', a.join(' ')]); console.warn = (...a) => lines.push(['warn', a.join(' ')]);
  try { await fn(); } finally { Object.assign(console, orig); }
  return lines;
}
test('L4: 500s and security events (auth, CSRF, replay, 429) are logged, without IPs, keys, cookies or account ids', async () => {
  const { w, u, s, batch, post } = await signedSetup();
  const accountId = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body.account.id;
  const plain = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body;
  const rs = await batch(1);
  const lines = await captureLogs(async () => {
    const real = w.log.append;
    w.log.append = async () => { throw new Error('storage down'); };
    const r = await w.req('POST', '/v1/receipts', { bearer: plain.key, ...anon, body: { receipt: { agent: 'a', action: 'b' } } });
    assert.equal(r.status, 500); assert.deepEqual(r.body, { error: 'internal', message: 'Something went wrong.' }, 'nothing internal leaks to the client');
    w.log.append = real;
    await w.req('POST', '/v1/receipts', { bearer: 'lsr_' + 'A'.repeat(43), ...anon, body: { receipt: { agent: 'a', action: 'b' } } });
    await w.req('DELETE', `/v1/keys/${plain.id}`, { cookie: u.cookie, xw: false });
    await post(rs); await post(rs);
    w.env.PUB_RPM = '1';
    await w.req('GET', '/v1/stats', anon); await w.req('GET', '/v1/stats', anon);
  });
  const text = lines.map((l) => l[1]).join('\n');
  const has = (level, re) => lines.some(([lv, t]) => lv === level && re.test(t));
  assert.ok(has('error', /"event":"internal_error".*storage down/), text);
  assert.ok(has('error', /"path":"\/v1\/receipts"/), text);
  for (const code of ['api_key_invalid', 'csrf', 'replay', 'slow_down']) assert.ok(has('warn', new RegExp(`"code":"${code}"`)), code + '\n' + text);
  assert.ok(text.includes('/v1/keys/:id'), 'ids in paths are redacted');
  for (const secret of ['203.0.113', plain.key, s.key, u.cookie.split('=')[1], accountId, plain.id]) assert.ok(!text.includes(secret), 'logged ' + secret);
});

// ---- L5
async function deleteAccount(w, u) {
  const b = (await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} })).body;
  const d = await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: b.challengeId, credential: await u.auth.get(b.options) } });
  assert.equal(d.status, 200, JSON.stringify(d.body));
}
test('L5: deleting an account also deletes the replay records of its signers', async () => {
  const { w, u, s, batch, post, count } = await signedSetup();
  assert.equal((await post(await batch(3))).status, 200);
  assert.equal(count('signed_receipts'), 3);
  void s;
  await deleteAccount(w, u);
  assert.equal(count('signed_receipts'), 0);
});

test('L5: a receipt authenticated before its account is deleted, but written after, is unlinked and leaves no usage row', async () => {
  const w = await World.create();
  const u = await w.user();
  const accountId = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body.account.id;
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  // the race: the account is deleted after this request passed the API key check, just before it reserves usage
  const realPrepare = w.env.DB.prepare;
  let fired = false;
  w.env.DB.prepare = (sql) => {
    const st = realPrepare(sql);
    if (fired || !/^INSERT INTO usage/.test(sql)) return st;
    fired = true;
    return { bind: (...a) => { const b = st.bind(...a); return { first: async () => { await deleteAccount(w, u); return b.first(); } }; } };
  };
  const r = await w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt: { agent: 'a', action: 'in flight' } } });
  w.env.DB.prepare = realPrepare;
  assert.equal(fired, true); assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(w.core.size(), 1);
  assert.equal(w.sql.raw.prepare('SELECT COUNT(*) AS n FROM leaves WHERE tenant = ? OR opening IS NOT NULL').get(accountId).n, 0, 'the late entry is unlinked');
  assert.equal(w.env.DB.raw.prepare('SELECT COUNT(*) AS n FROM usage WHERE account_id = ?').get(accountId).n, 0, 'no usage row for a deleted account');
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt: { agent: 'a', action: 'after' } } })).body.error, 'api_key_invalid');
});

// ---- L6
test('L6: expired sessions, challenges, rate-limit rows and replay records are cleaned up on sign-in and registration, with no cron', async () => {
  const w = await World.create();
  const u = await w.user();
  const db = w.env.DB.raw;
  const plant = () => {
    const past = Date.now() - 1;
    db.prepare('INSERT INTO sessions (hash, account_id, kind, created_at, expires_at) SELECT ?, id, ?, ?, ? FROM accounts LIMIT 1').run('old-session-' + Math.random(), 'web', past - 1, past);
    db.prepare('INSERT INTO challenges (id, kind, challenge, expires_at) VALUES (?, ?, ?, ?)').run('old' + Math.random(), 'login', 'x', past);
    db.prepare('INSERT INTO ratelimits (bucket, count, reset_at) VALUES (?, 1, ?)').run('old:' + Math.random(), past);
    db.prepare('INSERT INTO signed_receipts (signer, sig, at) VALUES (?, ?, ?)').run('s', 'old' + Math.random(), past - 31 * MIN);
  };
  const expired = () => ['sessions WHERE expires_at', 'challenges WHERE expires_at', 'ratelimits WHERE reset_at'].reduce((n, t) => n + db.prepare(`SELECT COUNT(*) AS n FROM ${t} < ?`).get(Date.now()).n, 0)
    + db.prepare('SELECT COUNT(*) AS n FROM signed_receipts WHERE at < ?').get(Date.now() - 30 * MIN).n;
  await at(11 * MIN, async () => {
    plant(); assert.ok(expired() >= 4);
    const lb = (await w.req('POST', '/v1/auth/login/begin', { body: {} })).body;
    assert.equal((await w.req('POST', '/v1/auth/login/finish', { body: { challengeId: lb.challengeId, credential: await u.auth.get(lb.options) } })).status, 200);
    assert.equal(expired(), 0, 'a sign-in cleaned up');
  });
  await at(22 * MIN, async () => {
    plant(); assert.ok(expired() >= 4);
    assert.ok((await w.user('New')).cookie);
    assert.equal(expired(), 0, 'a registration cleaned up');
  });
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).status, 200, 'live sessions are kept');
});

// ---- H3: Workers Free: 100k Worker and 100k Durable Object requests a day; D1 and DO SQLite: 100k rows written a day
test('H3: the landing page reads the log with one API request, and that response verifies on its own', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../site/public/verify/verify.js', import.meta.url), 'utf8');
  const apis = [...new Set([...src.matchAll(/['"`](\/v1\/[^'"`?]*)/g)].map((m) => m[1]))];
  assert.deepEqual(apis, ['/v1/stats'], 'the verify page calls only /v1/stats');
  assert.ok(!/fetch\([^)]*no-store/.test(src), 'and lets the browser cache it briefly');
  const w = await World.create();
  await realBundle(w);
  const r = await w.req('GET', '/v1/stats', anon);
  assert.equal(r.status, 200);
  const vk = (await w.req('GET', '/v1/log/key', anon)).body.verifier_key;
  assert.equal(r.body.verifier_key, vk); assert.equal(r.body.origin, 'leash.test/log');
  const cp = await sdk.verifyCheckpoint(r.body.checkpoint, r.body.verifier_key);
  assert.equal(cp.size, r.body.tree_size); assert.equal(Buffer.from(cp.root).toString('base64'), r.body.root);
  const cc = r.headers.get('cache-control');
  assert.match(cc, /^public, max-age=(\d+)$/); assert.ok(Number(cc.match(/\d+/)[0]) <= 30, cc);
  assert.equal(r.headers.get('access-control-allow-origin'), '*');
  const empty = await (await World.create()).req('GET', '/v1/stats', anon);
  assert.equal(empty.body.tree_size, 0); assert.equal(empty.body.checkpoint, null); assert.match(empty.body.verifier_key, /^leash\.test\/log\+/);
});

test('H3: reads of the log head within a few seconds reuse one Durable Object call, and an append refreshes it', async () => {
  const w = await World.create();
  const { key } = await realBundle(w);
  const real = w.log.head; let calls = 0;
  w.log.head = () => { calls++; return real(); };
  for (let i = 0; i < 5; i++) { await w.req('GET', '/v1/stats', anon); await w.req('GET', '/v1/log/checkpoint', anon); }
  assert.ok(calls <= 1, `${calls} Durable Object head() calls for 10 reads`);
  await w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt: { agent: 'a', action: 'second' } } });
  assert.equal((await w.req('GET', '/v1/stats', anon)).body.tree_size, 2, 'this isolate\'s own append is visible at once');
});

test('H3: the default GLOBAL_DAILY_CAP is 10,000 receipts a day, in code and in wrangler.jsonc', async () => {
  const { readFileSync } = await import('node:fs');
  const wr = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
  assert.match(wr, /"GLOBAL_DAILY_CAP": "10000"/);
  const w = await World.create();
  const { key } = await realBundle(w);
  const today = new Date().toISOString().slice(0, 10);
  w.env.DB.raw.prepare('UPDATE global_usage SET receipts = 9999 WHERE day = ?').run(today);
  const send = () => w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipt: { agent: 'a', action: 'x' } } });
  assert.equal((await send()).status, 200, 'the 10,000th fits');
  const r = await send();
  assert.equal(r.status, 503); assert.equal(r.body.error, 'log_at_capacity');
});

test('H3: receipt requests write no rate-limit row, and requests that will be refused (capacity, used-up quota) write nothing', async () => {
  const w = await World.create();
  const { key } = await realBundle(w);
  const send = (n = 1) => w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipts: Array.from({ length: n }, (_, i) => ({ agent: 'a', action: 'x' + i })) } });
  const ok = await send();
  assert.equal(ok.status, 200);
  assert.equal(w.env.DB.raw.prepare("SELECT COUNT(*) AS n FROM ratelimits WHERE bucket LIKE 'key:%'").get().n, 0, 'the per-key limit costs no D1 row');
  assert.ok(ok.writes <= 3, `${ok.writes} D1 writes for one unsigned receipt`);
  // capacity: once the day is full, later requests in this isolate are refused before any D1 write
  w.env.GLOBAL_DAILY_CAP = String(w.env.DB.raw.prepare('SELECT receipts FROM global_usage').get().receipts);
  assert.equal((await send()).status, 503);
  for (let i = 0; i < 3; i++) { const r = await send(); assert.equal(r.status, 503); assert.equal(r.writes, 0, 'refused at capacity without writing'); }
  delete w.env.GLOBAL_DAILY_CAP;
  // quota: an account that used all of it is refused without writes; a batch that only would not fit still sees the real numbers
  const v = await World.create();
  Object.assign(v.env, { FREE_LIMIT: '2' });
  const vb = await realBundle(v);
  const vsend = (n) => v.req('POST', '/v1/receipts', { bearer: vb.key, ...anon, body: { receipts: Array.from({ length: n }, (_, i) => ({ agent: 'a', action: 'q' + i })) } });
  const big = await vsend(2);
  assert.equal(big.status, 402); assert.equal(big.body.remaining, 1);
  assert.equal((await vsend(1)).status, 200, 'the last unit is still usable');
  assert.equal((await vsend(1)).status, 402);
  for (let i = 0; i < 3; i++) { const r = await vsend(1); assert.equal(r.status, 402); assert.equal(r.body.remaining, 0); assert.equal(r.writes, 0); }
});

test('H3: a client over a D1-backed rate limit is refused without another D1 write until the window resets', async () => {
  const w = await World.create();
  const begin = () => w.req('POST', '/v1/auth/login/begin', { body: {}, ip: '192.0.2.77' });
  for (let i = 0; i < 60; i++) assert.equal((await begin()).status, 200);
  assert.equal((await begin()).status, 429);
  for (let i = 0; i < 5; i++) { const r = await begin(); assert.equal(r.status, 429); assert.equal(r.writes, 0, 'no limiter write once over the limit'); }
});

// ---- H2: Workers Free allows 50 D1 queries per invocation
async function signedSetup(env = {}) {
  const w = await World.create();
  Object.assign(w.env, env);
  const u = await w.user('V', '203.0.113.1');
  const s = await signedKey(w, u.cookie);
  const batch = (n, t0 = Date.now()) => Promise.all(Array.from({ length: n }, (_, i) => s.sign({ agent: 'a', action: 'x' + i, ts: t0 + i })));
  const post = (receipts) => w.req('POST', '/v1/receipts', { bearer: s.key, ...anon, body: { receipts } });
  const count = (t) => w.env.DB.raw.prepare(`SELECT COALESCE(${t === 'signed_receipts' ? 'COUNT(*)' : 'SUM(receipts)'}, 0) AS n FROM ${t}`).get().n;
  return { w, u, s, batch, post, count };
}
const { LIMITS } = await import('../src/receipts.js');
const SIGNED_MAX = LIMITS.MAX_SIGNED_BATCH || LIMITS.MAX_BATCH;

test('H2: the largest signed batch stays well under 50 D1 queries per invocation, and is recorded in full', async () => {
  const { w, batch, post, count } = await signedSetup();
  w.env.DB.cap = 50;
  const r = await post(await batch(SIGNED_MAX));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.queries <= 10, `${r.queries} D1 queries for a signed batch of ${SIGNED_MAX}`);
  assert.equal(w.core.size(), SIGNED_MAX); assert.equal(count('usage'), SIGNED_MAX); assert.equal(count('signed_receipts'), SIGNED_MAX);
});

test('H2: a signed batch refused for quota is a 402 within the query limit, and its signatures stay usable', async () => {
  const { w, batch, post, count } = await signedSetup({ FREE_LIMIT: '5' });
  w.env.DB.cap = 50;
  const rs = await batch(Math.min(30, SIGNED_MAX));
  const r = await post(rs);
  assert.equal(r.status, 402, JSON.stringify(r.body)); assert.equal(r.body.error, 'quota');
  assert.equal(count('signed_receipts'), 0, 'nothing stays claimed'); assert.equal(count('usage'), 0);
  w.env.FREE_LIMIT = '1000';
  assert.equal((await post(rs)).status, 200, 'the same signed receipts are accepted once the quota allows them');
});

test('H2: if anything after the replay claim fails, usage, global usage and the claims are all released', async () => {
  const { w, batch, post, count } = await signedSetup();
  const rs = await batch(SIGNED_MAX);
  w.env.DB.failOn = /global_usage/;
  const r = await post(rs);
  assert.equal(r.status, 500);
  w.env.DB.failOn = null;
  assert.equal(count('usage'), 0); assert.equal(count('global_usage'), 0); assert.equal(count('signed_receipts'), 0);
  assert.equal(w.core.size(), 0);
  assert.equal((await post(rs)).status, 200, 'a retry of the same receipts is not a replay');
});

test('H2: a failure updating last_used after the append does not turn a recorded batch into a 500', async () => {
  const { w, batch, post } = await signedSetup();
  w.env.DB.failOn = /last_used/;
  const r = await post(await batch(3));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.receipts.length, 3); assert.equal(w.core.size(), 3);
});
