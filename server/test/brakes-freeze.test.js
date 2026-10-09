// Brakes, Freeze: one tap stops every token of the account (423, before anything else is read or written), from any
// signed-in surface; only a passkey ceremony in the app starts them again. A frozen account costs the database almost
// nothing, nothing already approved fires after it, and approvals wait until it ends.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { World, serve } from './helpers.js';
import { isFrozen, _resetBrakeMemory } from '../src/brakes.js';
import { EXPONENTS } from '../src/money.js';
import { anon, stripeWorld, account, mint, stripe, posts, approve, cliSession, withVapid, subscribe, db, auditRows, publicEntries, FCM } from './brakes-helpers.js';

const get = (w, tok) => w.req('GET', '/p/stripe/v1/customers', { bearer: tok, ...anon });
const cust = (w, tok, n = 0) => stripe(w, tok, '/v1/customers', `email=user${n}%40example.com`);
const frozen = (w, u) => w.req('GET', '/v1/me', { cookie: u.cookie }).then((r) => r.body.account.frozen_at);
async function unfreeze(w, u, o = {}) {
  const b = await w.req('POST', '/v1/me/unfreeze/begin', { cookie: u.cookie, body: {}, ...o });
  if (b.status !== 200) return b;
  return w.req('POST', '/v1/me/unfreeze/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) }, ...o });
}

test('freeze from the command line stops every call of every token at once, reads included; the agent is told to stop; nothing reaches the provider', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const a = await mint(w, u, {}, 'a'), b = await mint(w, u, {}, 'b');
  assert.equal((await cust(w, a.token)).status, 200);
  const cli = await cliSession(w, u);
  const f = await w.req('POST', '/v1/me/freeze', { bearer: cli, ...anon, body: {} });
  assert.equal(f.status, 200, JSON.stringify(f.body));
  assert.equal(f.body.frozen, true); assert.ok(f.body.frozen_at > 0);
  assert.ok(await frozen(w, u));
  const before = w.upstream.length;
  for (const tok of [a.token, b.token]) {
    for (const r of [await get(w, tok), await cust(w, tok, 5), await w.req('DELETE', '/p/stripe/v1/customers/cus_1', { bearer: tok, ...anon }), await w.req('HEAD', '/p/stripe/v1/customers', { bearer: tok, ...anon })]) {
      assert.equal(r.status, 423);
      if (r.body.error) { assert.equal(r.body.error, 'account_frozen'); assert.match(r.body.message, /frozen: every agent token is stopped/); }
    }
  }
  assert.equal(w.upstream.length, before, 'nothing reached the provider');
  // a wrong token still gets a plain 401: a frozen account does not confirm that a token exists
  assert.equal((await get(w, 'lsh_' + 'A'.repeat(43))).body.error, 'token_invalid');
  // a revoked token is revoked
  await w.req('DELETE', `/v1/tokens/${b.id}`, { cookie: u.cookie });
  assert.equal((await get(w, b.token)).body.error, 'token_invalid');
  // another account is not touched
  const v = await account(w, { name: 'Other', ip: '198.51.100.5' });
  const vt = await mint(w, v, {});
  assert.equal((await cust(w, vt.token)).status, 200);
  assert.equal(await frozen(w, v), null);
  // the owner can still see everything and mint, revoke and deny while frozen
  assert.equal((await w.req('GET', '/v1/tokens', { cookie: u.cookie })).status, 200);
  assert.equal((await mint(w, u, {}, 'c')).token.startsWith('lsh_'), true);
  assert.equal(await isFrozen(w.env, v.id), false);
  assert.equal(await isFrozen(w.env, u.id), true);
});

test('freezing again changes nothing and logs nothing new; it is on the record with who did it', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const cli = await cliSession(w, u);
  const first = await w.req('POST', '/v1/me/freeze', { cookie: u.cookie, body: {} });
  const second = await w.req('POST', '/v1/me/freeze', { bearer: cli, ...anon, body: {} });
  assert.equal(second.body.already, true); assert.equal(second.body.frozen_at, first.body.frozen_at);
  const rows = auditRows(w, u.id).filter((a) => a.action === 'freeze');
  assert.equal(rows.length, 1); assert.equal(rows[0].actor, 'web'); assert.equal(rows[0].detail.by, 'web');
  const cli2 = await w.req('POST', '/v1/me/freeze', { bearer: cli, ...anon, body: {} });
  assert.equal(cli2.body.already, true);
  // only a signed-in session can freeze; a CSRF-less browser request cannot; a token cannot
  assert.equal((await w.req('POST', '/v1/me/freeze', { body: {} })).status, 401);
  const t = await mint(w, u, {});
  assert.equal((await w.req('POST', '/v1/me/freeze', { bearer: t.token, ...anon, body: {} })).status, 401);
  assert.equal((await w.req('POST', '/v1/me/freeze', { cookie: u.cookie, body: {}, xleash: false })).body.error, 'csrf');
  const v = await account(w, { name: 'Other', ip: '198.51.100.5' });
  assert.equal((await w.req('POST', '/v1/me/freeze', { cookie: v.cookie, body: {}, origin: 'https://evil.example' })).body.error, 'csrf');
  assert.equal(await frozen(w, v), null);
});

test('unfreezing needs a passkey ceremony in a web session: not a command line session, not the app without the ceremony, not a spent or foreign challenge', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const eve = await account(w, { name: 'Eve', ip: '198.51.100.9' });
  const t = await mint(w, u, {});
  const cli = await cliSession(w, u);
  assert.equal((await w.req('POST', '/v1/me/unfreeze/begin', { cookie: u.cookie, body: {} })).body.error, 'not_frozen');
  await w.req('POST', '/v1/me/freeze', { bearer: cli, ...anon, body: {} });
  assert.equal((await get(w, t.token)).status, 423);
  // a command line session
  assert.equal((await w.req('POST', '/v1/me/unfreeze/begin', { bearer: cli, ...anon, body: {} })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', '/v1/me/unfreeze/finish', { bearer: cli, ...anon, body: {} })).body.error, 'passkey_required');
  // the app without the ceremony; without a signed-in session; without CSRF
  assert.equal((await w.req('POST', '/v1/me/unfreeze/finish', { cookie: u.cookie, body: {} })).status, 400);
  assert.equal((await w.req('POST', '/v1/me/unfreeze/begin', { body: {} })).status, 401);
  assert.equal((await w.req('POST', '/v1/me/unfreeze/begin', { cookie: u.cookie, body: {}, xleash: false })).body.error, 'csrf');
  // someone else's passkey, someone else's challenge
  const b = await w.req('POST', '/v1/me/unfreeze/begin', { cookie: u.cookie, body: {} });
  const foreign = await w.req('POST', '/v1/me/unfreeze/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await eve.auth.get(b.body.options) } });
  assert.equal(foreign.status, 401); assert.equal(foreign.body.error, 'unknown_passkey');
  const eb = await w.req('POST', '/v1/me/unfreeze/begin', { cookie: eve.cookie, body: {} });
  assert.equal(eb.body.error, 'not_frozen', 'her account is not frozen');
  // the challenge of an unfreeze is for unfreezing only
  const b2 = await w.req('POST', '/v1/me/unfreeze/begin', { cookie: u.cookie, body: {} });
  const asMint = await w.req('POST', '/v1/tokens/passkey/finish', { cookie: u.cookie, body: { credentialId: u.cred, challengeId: b2.body.challengeId, credential: await u.auth.get(b2.body.options) } });
  assert.equal(asMint.status, 400);
  const stolen = await w.req('POST', '/v1/me/unfreeze/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(stolen.status, 400, 'a challenge is single use, and the failed attempt spent it');
  const h = await w.req('DELETE', '/p/stripe/v1/customers/cus_1', { bearer: t.token, ...anon });
  assert.equal(h.status, 423);
  assert.ok(await frozen(w, u), 'still frozen after all of that');
  // the right ceremony
  const ok = await unfreeze(w, u);
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(ok.body.frozen, false);
  assert.equal(await frozen(w, u), null);
  assert.equal((await get(w, t.token)).status, 200);
  const log = auditRows(w, u.id).filter((a) => a.action === 'unfreeze');
  assert.equal(log.length, 1); assert.match(log[0].detail.passkey, /^[0-9a-f]{16}$/); assert.equal(log[0].actor, 'web');
  assert.equal((await unfreeze(w, u)).body.error, 'not_frozen');
});

test('a frozen account costs the database almost nothing: no body read, no signature check, no token rate limit, no last_used; one note a while in the log', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mint(w, u, {});
  await get(w, t.token);
  const lastUsed = db(w).prepare('SELECT last_used FROM tokens WHERE id = ?').get(t.id).last_used;
  await w.req('POST', '/v1/me/freeze', { cookie: u.cookie, body: {} });
  const first = await get(w, t.token);
  assert.equal(first.status, 423);
  let rows = 0, queries = 0;
  for (let i = 0; i < 25; i++) { const r = await cust(w, t.token, i); assert.equal(r.status, 423); rows += r.writes; queries += r.queries; }
  assert.equal(rows, 25, 'one write each: the per-network limit every proxied call already pays');
  assert.ok(queries <= 25 * 2, `${queries} queries for 25 refused calls`);
  assert.equal(db(w).prepare('SELECT last_used FROM tokens WHERE id = ?').get(t.id).last_used, lastUsed);
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM ratelimits WHERE bucket LIKE 'tok:%'").get().n, 1, 'the token\'s own rate limit row was written before the freeze only');
  const notes = auditRows(w, u.id).filter((a) => a.action === 'frozen_block');
  assert.equal(notes.length, 1, 'the first refused call is noted, the other 25 are not');
  assert.deepEqual(notes[0].detail, { method: 'GET', host: 'api.stripe.com' });
  assert.equal((await publicEntries(w)).filter((e) => e.entry.receipt.meta.rule === 'brake.frozen').length, 0);
  assert.equal(posts(w).length, 0);
});

test('freezing voids approvals nobody used yet; approving waits until the freeze ends; deny still works', async () => {
  const w = stripeWorld();
  const u = await account(w);
  const t = await mint(w, u, {});
  const del = (n) => w.req('DELETE', `/p/stripe/v1/customers/cus_${n}`, { bearer: t.token, ...anon });
  const h1 = await del(1), h2 = await del(2), h3 = await del(3);
  assert.equal((await approve(w, u, h1.body.hold_id)).status, 200);
  // a ceremony begun before the freeze and finished after it
  const begun = await w.req('POST', `/v1/holds/${h2.body.hold_id}/approve/begin`, { cookie: u.cookie, body: {} });
  assert.equal(begun.status, 200);
  const f = await w.req('POST', '/v1/me/freeze', { cookie: u.cookie, body: {} });
  assert.equal(f.body.voided_approvals, 1);
  assert.equal(auditRows(w, u.id).find((a) => a.action === 'freeze').detail.voided_approvals, 1);
  const late = await w.req('POST', `/v1/holds/${h2.body.hold_id}/approve/finish`, { cookie: u.cookie, body: { challengeId: begun.body.challengeId, credential: await u.auth.get(begun.body.options) } });
  assert.equal(late.status, 423); assert.equal(late.body.error, 'account_frozen');
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(h2.body.hold_id).status, 'pending', 'still waiting for a human');
  const fresh = await w.req('POST', `/v1/holds/${h3.body.hold_id}/approve/begin`, { cookie: u.cookie, body: {} });
  assert.equal(fresh.status, 423); assert.match(fresh.body.message, /Unfreeze it with your passkey first/);
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(h1.body.hold_id).status, 'expired', 'the approval nobody used is void');
  // deny is always safe
  assert.equal((await w.req('POST', `/v1/holds/${h3.body.hold_id}/deny`, { cookie: u.cookie, body: {} })).status, 200);
  assert.equal((await unfreeze(w, u)).status, 200);
  assert.equal(posts(w).length + w.upstream.filter((x) => x.method === 'DELETE').length, 0, 'the voided approval did not fire');
  assert.equal((await del(1)).status, 428, 'a new hold, as if it had never been approved');
  // approving works again, and the pending one can be decided
  assert.equal((await approve(w, u, h2.body.hold_id)).status, 200);
  assert.equal((await del(2)).status, 200);
});

test('the phone sees it: devices are woken once when the account is frozen, alerts and /v1/me say so', async () => {
  const w = stripeWorld();
  await withVapid(w);
  const u = await account(w);
  await subscribe(w, u);
  assert.equal((await w.req('GET', '/v1/alerts', { cookie: u.cookie })).body.frozen_at, null);
  const cli = await cliSession(w, u);
  w.pushes.length = 0;
  const f = await w.req('POST', '/v1/me/freeze', { bearer: cli, ...anon, body: {} });
  assert.equal(w.pushes.length, 1); assert.equal(w.pushes[0].url, FCM); assert.equal(w.pushes[0].init.body, '', 'the push carries nothing');
  await w.req('POST', '/v1/me/freeze', { bearer: cli, ...anon, body: {} });
  assert.equal(w.pushes.length, 1, 'freezing again wakes nobody');
  const al = await w.req('GET', '/v1/alerts', { cookie: u.cookie });
  assert.equal(al.body.frozen_at, f.body.frozen_at);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.account.frozen_at, f.body.frozen_at);
  assert.equal((await w.req('GET', '/v1/alerts', { bearer: cli, ...anon })).body.frozen_at, f.body.frozen_at, 'a command line session sees it too');
});

// ---------------------------------------------------------------- the surfaces: command line, service worker, page
test('leashcli freeze: stops the account, says only the app can start it again, and cannot unfreeze', async () => {
  const w = new World();
  const srv = await serve(w);
  const dir = mkdtempSync(join(tmpdir(), 'freeze-'));
  const CLI = fileURLToPath(new URL('../../cli/leash.mjs', import.meta.url));
  const run = (args) => new Promise((done) => {
    const p = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, LEASH_URL: w.base, XDG_CONFIG_HOME: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    p.on('exit', (code) => done({ code, out, err }));
  });
  try {
    const u = await w.user('Ada');
    const c = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'F'.repeat(36) } });
    const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: c.body.id } })).body.token;
    const cli = await cliSession(w, u);
    assert.match((await run(['freeze'])).err, /Not signed in/);
    mkdirSync(join(dir, 'leash'), { recursive: true });
    writeFileSync(join(dir, 'leash', 'config.json'), JSON.stringify({ token: cli }));
    const r = await run(['freeze']);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /^Frozen: every agent token on this account is stopped \(HTTP 423\) until you unfreeze it with your passkey at http:\/\/127\.0\.0\.1:\d+\/app\. This command line cannot unfreeze\.\n$/);
    assert.equal((await w.req('GET', '/p/github/repos/a/b', { bearer: tok, ...anon })).status, 423);
    assert.match((await run(['freeze'])).out, /^Already frozen/);
    assert.match((await run(['unfreeze'])).out, /login \| logout/, 'there is no command to unfreeze');
    assert.match((await run([])).out, /\bfreeze\b/);
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});

/** run the service worker with a fake browser around it: events in, notifications and fetches out */
function serviceWorker(responses) {
  const listeners = {}, shown = [], fetched = [], opened = [];
  const self = {
    addEventListener: (type, fn) => { listeners[type] = fn; },
    skipWaiting() {}, clients: { claim() {}, matchAll: async () => [], openWindow: async (u) => { opened.push(u); } },
    location: { origin: 'https://counterseal.example' },
    registration: { showNotification: async (title, o) => { shown.push(JSON.parse(JSON.stringify({ title, ...o }))); } },
  };
  const ctx = vm.createContext({ self, URL, Promise, JSON, Array, Object, String, console, fetch: async (url, init = {}) => { fetched.push(JSON.parse(JSON.stringify({ url, init }))); return responses(url, init); } });
  vm.runInContext(readFileSync(new URL('../../site/public/sw.js', import.meta.url), 'utf8'), ctx);
  const fire = async (type, ev) => { let p; listeners[type]({ ...ev, waitUntil: (x) => { p = x; } }); await p; };
  return { fire, shown, fetched, opened };
}
const jsonRes = (o, status = 200) => ({ ok: status < 400, status, json: async () => o });

test('the phone alert: a frozen account says so; a held refund shows its amount; every alert has a Freeze button that freezes with one tap and says what it did', async () => {
  const hold = { id: 'a'.repeat(24), token_label: 'support agent', method: 'POST', host: 'api.stripe.com', path: '/v1/refunds', why: 'Refund of 1,240.00 USD is over this token\'s cap of 50.00 USD a call.', headline: 'Refund 1,240.00 USD', created_at: 5, approve_url: 'https://counterseal.example/app#hold=' + 'a'.repeat(24) };
  let alerts = { holds: [hold], signins: [], frozen_at: null };
  const sw = serviceWorker((url, init) => (url === '/v1/alerts' ? jsonRes(alerts) : url === '/v1/me/freeze' ? jsonRes({ ok: true, frozen: true }) : jsonRes({}, 404)));
  await sw.fire('push', {});
  let n = sw.shown.at(-1);
  assert.equal(n.title, 'support agent wants to POST api.stripe.com');
  assert.match(n.body, /^Refund 1,240\.00 USD\n\/v1\/refunds\nRefund of 1,240\.00 USD is over/);
  assert.deepEqual(n.actions, [{ action: 'freeze', title: 'Freeze everything' }]);
  assert.equal(n.data.url, hold.approve_url);
  // nothing to freeze in the "alerts are working" test message, and nothing once frozen
  alerts = { holds: [], signins: [], frozen_at: null };
  await sw.fire('push', {});
  assert.equal(sw.shown.at(-1).title, 'Counterseal alerts are working'); assert.equal(sw.shown.at(-1).actions, undefined);
  alerts = { holds: [hold], signins: [], frozen_at: 1 };
  await sw.fire('push', {});
  n = sw.shown.at(-1);
  assert.equal(n.title, 'Counterseal is frozen'); assert.match(n.body, /Every agent token is stopped\. Unfreeze it with your passkey in the app\./); assert.equal(n.actions, undefined);
  assert.equal(n.data.url, '/app');
  // a command line sign-in alert also has the button
  alerts = { holds: [], signins: [{ id: 'b'.repeat(24), created_at: 9, country: 'DE', network: 'Hetzner' }], frozen_at: null };
  await sw.fire('push', {});
  assert.deepEqual(sw.shown.at(-1).actions, [{ action: 'freeze', title: 'Freeze everything' }]);
  // the tap: one POST with the CSRF header, then a notification that says it is done
  await sw.fire('notificationclick', { action: 'freeze', notification: { close() {}, data: { url: '/app' } } });
  const post = sw.fetched.find((f) => f.url === '/v1/me/freeze');
  assert.equal(post.init.method, 'POST'); assert.equal(post.init.headers['x-leash'], '1'); assert.equal(post.init.credentials, 'same-origin');
  assert.equal(sw.shown.at(-1).title, 'Counterseal froze every agent token');
  assert.match(sw.shown.at(-1).body, /Unfreeze needs your passkey/);
  assert.deepEqual(sw.opened, []);
  // when the tap cannot freeze (signed out), the app opens instead, and nothing claims success
  const out = serviceWorker(() => jsonRes({ error: 'signed_out' }, 401));
  await out.fire('notificationclick', { action: 'freeze', notification: { close() {}, data: { url: '/app' } } });
  assert.deepEqual(out.opened, ['https://counterseal.example/app#freeze']);
  assert.ok(!out.shown.some((s) => /froze/.test(s.title)));
  // an ordinary tap on the body still opens the request
  const plain = serviceWorker(() => jsonRes({}));
  await plain.fire('notificationclick', { action: '', notification: { close() {}, data: { url: hold.approve_url } } });
  assert.deepEqual(plain.opened, [hold.approve_url]);
  assert.equal(plain.fetched.length, 0, 'a tap on the body freezes nothing');
});

test('the page: a Freeze button that cannot be missed, an unfreeze that asks for the passkey, no innerHTML, and the same decimals as the server', () => {
  const html = readFileSync(new URL('../../site/public/app/index.html', import.meta.url), 'utf8');
  const js = readFileSync(new URL('../../site/public/app/app.js', import.meta.url), 'utf8');
  const css = readFileSync(new URL('../../site/public/styles.css', import.meta.url), 'utf8');
  assert.match(html, /<div id="freezeBar" class="freezebar"[^>]*>[\s\S]*<button id="freezeBtn" class="btn freeze"/);
  assert.match(html, /id="unfreezeBtn"/);
  assert.match(css, /\.freezebar\{[^}]*position:sticky[^}]*\}/);
  assert.match(css, /\.freezebar\.on\{[^}]*background:/);
  assert.match(js, /api\('POST', '\/v1\/me\/freeze'/);
  assert.match(js, /ceremony\('\/v1\/me\/unfreeze\/begin', '\/v1\/me\/unfreeze\/finish'\)/);
  assert.match(js, /`\/v1\/tokens\/\$\{x\.id\}\/reset\/begin`, `\/v1\/tokens\/\$\{x\.id\}\/reset\/finish`/);
  assert.ok(!/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(/.test(js), 'Trusted Types: no innerHTML');
  // a link never freezes: the one call that does is the button's click
  assert.equal(js.split("'/v1/me/freeze'").length - 1, 1);
  assert.match(js, /\$\('freezeBtn'\)\.onclick = async \(\) => \{[^]*?'\/v1\/me\/freeze'/);
  // the page converts a typed amount with the same decimals as the server shows
  const zero = /const ZERO = new Set\('([^']+)'\.split\(' '\)\)/.exec(js)?.[1].split(' ');
  const three = /const THREE = new Set\('([^']+)'\.split\(' '\)\)/.exec(js)?.[1].split(' ');
  assert.deepEqual(zero, EXPONENTS.zero); assert.deepEqual(three, EXPONENTS.three);
});
