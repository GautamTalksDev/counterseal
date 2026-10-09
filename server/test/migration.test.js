// Live data survives the merge. The code deployed before the merge (test/fixtures/live-src) writes real rows into a
// database with migrations 0001 to 0003; then 0004 is applied, as `wrangler d1 migrations apply` will do on the live
// database, and the merged code must keep every account, passkey, session, CLI session, token, hold, push device and
// audit chain working.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { makeDb, World, Authenticator, ORIGIN, RP_ID } from './helpers.js';
import { handle as liveHandle } from './fixtures/live-src/index.js';

const GH = 'ghp_' + 'L'.repeat(36);
const MIG = new URL('../migrations/', import.meta.url);

// every migration after the live schema (0001 to 0003), in the order wrangler applies them
const AFTER_LIVE = readdirSync(MIG).sort().filter((f) => f >= '0004');

test('migrations are additive only: no DROP, no RENAME, no rewrite of existing rows', () => {
  const files = readdirSync(MIG).sort();
  assert.deepEqual(files.slice(0, 5), ['0001_init.sql', '0002_hold_preview.sql', '0003_push.sql', '0004_record_and_prove.sql', '0005_cli_signin.sql']);
  for (const f of AFTER_LIVE) {
    const sql = readFileSync(new URL(f, MIG), 'utf8').replace(/--.*$/gm, '').replace(/ON DELETE CASCADE/g, '');
    assert.ok(!/\b(DROP|RENAME|DELETE|UPDATE|REPLACE)\b/i.test(sql), f + ' only adds');
    for (const stmt of sql.split(';').map((s) => s.trim()).filter(Boolean)) {
      assert.match(stmt, /^(CREATE TABLE|CREATE INDEX|ALTER TABLE \w+ ADD COLUMN)/, stmt.slice(0, 60));
      if (/^ALTER/.test(stmt)) assert.ok(!/NOT NULL/.test(stmt) || /DEFAULT/.test(stmt), 'a NOT NULL column needs a default: ' + stmt);
    }
  }
});

test('live-shaped data written by the deployed code keeps working after 0004 and the merged code', async () => {
  // ---- before: the live schema (0001 to 0003) and the live code
  const db = makeDb({ migrations: (f) => f < '0004' });
  const w = new World({ db });
  const env = w.env;
  const upstream = [];
  const fetcher = async (url, init) => { upstream.push({ url, method: init.method, auth: new Headers(init.headers).get('authorization') }); return new Response('{}', { status: 200 }); };
  const live = async (method, path, { body, cookie, bearer, origin = ORIGIN, x = true } = {}) => {
    const h = { 'cf-connecting-ip': '203.0.113.7' };
    if (body !== undefined) h['content-type'] = 'application/json';
    if (cookie) h.cookie = cookie; if (bearer) h.authorization = 'Bearer ' + bearer; if (origin) h.origin = origin; if (x) h['x-leash'] = '1';
    const r = await liveHandle(new Request('https://leash.test' + path, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined }), env, { fetcher });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j, headers: r.headers };
  };
  const auth = new Authenticator(ORIGIN, RP_ID);
  const rb = await live('POST', '/v1/auth/register/begin', { body: { name: 'Live User' } });
  const rf = await live('POST', '/v1/auth/register/finish', { body: { challengeId: rb.body.challengeId, credential: await auth.create(rb.body.options) } });
  assert.equal(rf.status, 200);
  const cookie = rf.headers.get('set-cookie').split(';')[0];
  const cred = (await live('POST', '/v1/credentials', { cookie, body: { provider: 'github', secret: GH, label: 'prod' } })).body;
  const tok = (await live('POST', '/v1/tokens', { cookie, body: { credentialId: cred.id, label: 'old agent', policy: { hold: [{ method: 'POST', path: '/repos/*/*/releases' }] } } })).body;
  const proxy = (h, method, path, body) => h(new Request('https://leash.test/p/github' + path, { method, headers: { authorization: 'Bearer ' + tok.token, 'cf-connecting-ip': '203.0.113.7', ...(body ? { 'content-type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined }), env, { fetcher });
  const pending = await (await proxy(liveHandle, 'DELETE', '/repos/acme/pending')).json();
  const approved = await (await proxy(liveHandle, 'DELETE', '/repos/acme/approved')).json();
  const denied = await (await proxy(liveHandle, 'DELETE', '/repos/acme/denied')).json();
  const ab = await live('POST', `/v1/holds/${approved.hold_id}/approve/begin`, { cookie, body: {} });
  assert.equal((await live('POST', `/v1/holds/${approved.hold_id}/approve/finish`, { cookie, body: { challengeId: ab.body.challengeId, credential: await auth.get(ab.body.options) } })).status, 200);
  assert.equal((await live('POST', `/v1/holds/${denied.hold_id}/deny`, { cookie, body: {} })).status, 200);
  env.VAPID_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])).privateKey));
  const pushes = []; // never the real push services
  env.__pushFetch = async (u) => { pushes.push(u); return new Response(null, { status: 201 }); };
  assert.equal((await live('POST', '/v1/push/subscribe', { cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/live-device' } })).status, 200);
  const d = await live('POST', '/v1/device/start', { body: {}, origin: null, x: false });
  const db1 = await live('POST', '/v1/device/approve/begin', { cookie, body: { user_code: d.body.user_code } });
  await live('POST', '/v1/device/approve/finish', { cookie, body: { user_code: d.body.user_code, challengeId: db1.body.challengeId, credential: await auth.get(db1.body.options) } });
  const cli = (await live('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, origin: null, x: false })).body.access_token;
  assert.match(cli, /^lsc_/);
  const auditBefore = db.raw.prepare('SELECT seq, hash FROM audit ORDER BY seq').all();
  const counts = Object.fromEntries(['accounts', 'passkeys', 'sessions', 'credentials', 'tokens', 'holds', 'audit', 'push_subs'].map((t) => [t, db.raw.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n]));

  // ---- the deploy: apply 0004 and every later migration to the same database
  for (const f of AFTER_LIVE) db.raw.exec(readFileSync(new URL(f, MIG), 'utf8'));
  for (const [t, n] of Object.entries(counts)) assert.equal(db.raw.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n, n, t + ' rows unchanged');
  assert.deepEqual(db.raw.prepare('SELECT seq, hash FROM audit ORDER BY seq').all(), auditBefore, 'audit rows untouched');
  assert.equal(db.raw.prepare('SELECT receipts FROM accounts').get().receipts, 0, 'an existing account has receipts off');
  assert.equal(db.raw.prepare('SELECT agent_key_id FROM tokens').get().agent_key_id, null, 'existing tokens stay unbound');

  // ---- after: the merged code on the migrated database
  const now = (m, p, o = {}) => w.req(m, p, o);
  assert.equal((await now('GET', '/v1/me', { cookie })).status, 200, 'the live web session still works');
  assert.equal((await now('GET', '/v1/tokens', { bearer: cli, origin: null, xleash: false })).status, 200, 'the live CLI session still works');
  const lb = await now('POST', '/v1/auth/login/begin', { body: {} });
  assert.equal((await now('POST', '/v1/auth/login/finish', { body: { challengeId: lb.body.challengeId, credential: await auth.get(lb.body.options) } })).status, 200, 'the passkey still signs in (counter continues)');
  const get = await w.req('GET', '/p/github/repos/acme/app', { bearer: tok.token, origin: null, xleash: false });
  assert.equal(get.status, 200, 'the live token still works, unsigned');
  assert.equal(w.upstream.at(-1).headers.authorization, 'Bearer ' + GH, 'the vaulted key still decrypts');
  assert.equal((await w.req('POST', '/p/github/repos/acme/app/releases', { bearer: tok.token, origin: null, xleash: false, body: {} })).status, 428, 'its policy still applies');
  // the hold approved before the deploy is still good for its one retry; the pending one can be approved now
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/approved', { bearer: tok.token, origin: null, xleash: false })).status, 200);
  const holds = (await now('GET', '/v1/holds', { cookie })).body.holds.map((h) => h.id);
  assert.ok(holds.includes(pending.hold_id));
  const pb = await now('POST', `/v1/holds/${pending.hold_id}/approve/begin`, { cookie, body: {} });
  assert.equal((await now('POST', `/v1/holds/${pending.hold_id}/approve/finish`, { cookie, body: { challengeId: pb.body.challengeId, credential: await auth.get(pb.body.options) } })).status, 200);
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/pending', { bearer: tok.token, origin: null, xleash: false })).status, 200);
  // the audit chain spans the deploy and still verifies; old entries read the same
  const v = await now('GET', '/v1/audit/verify', { cookie });
  assert.equal(v.body.ok, true); assert.ok(v.body.entries > auditBefore.length);
  // receipts stay off for this account: nothing public was written
  assert.equal((await now('GET', '/v1/log/entries', { origin: null, xleash: false })).body.entries.length, 0);
  const me = (await now('GET', '/v1/me', { cookie })).body;
  assert.equal(me.receipts.on, false); assert.equal(me.account.name, 'Live User');
  // push devices registered before the deploy still get alerts
  pushes.length = 0;
  const pt = await now('POST', '/v1/push/test', { cookie, body: {} });
  assert.equal(pt.body.sent, 1, JSON.stringify(pt.body));
  assert.deepEqual(pushes, ['https://fcm.googleapis.com/fcm/send/live-device']);
  // and the old code's API answers the same shapes the published CLI (leashcli 0.1.1) reads
  const t2 = await now('POST', '/v1/tokens', { bearer: cli, origin: null, xleash: false, body: { credentialId: cred.id, label: 'cli' } });
  for (const k of ['id', 'token', 'provider', 'baseUrl', 'expiresAt', 'note']) assert.ok(k in t2.body, k);
  for (const k of ['id', 'method', 'host', 'path', 'rule', 'why']) assert.ok(k in (await now('GET', '/v1/holds?status=used', { bearer: cli, origin: null, xleash: false })).body.holds[0], k);

  // 0006 (approvals): every hold the live code wrote reads as a proxied API call, with no agent and no deny reason
  assert.deepEqual(db.raw.prepare('SELECT DISTINCT kind FROM holds').all().map((r) => r.kind), ['proxy']);
  const deniedLive = (await now('GET', '/v1/holds?status=denied', { cookie })).body.holds.find((h) => h.id === denied.hold_id);
  assert.equal(deniedLive.kind, 'proxy'); assert.equal(deniedLive.agent, null); assert.equal(deniedLive.deny_reason, null); assert.equal(deniedLive.context, null);
  // and the live CLI session and passkey drive the new approvals end to end
  const gk = await now('POST', '/v1/guard/keys', { bearer: cli, origin: null, xleash: false, body: { label: 'live laptop' } });
  assert.equal(gk.status, 200, JSON.stringify(gk.body));
  const ask = await now('POST', '/v1/approvals', { bearer: gk.body.key, origin: null, xleash: false, body: { kind: 'shell', agent: 'codex', rule: 'sh.git-force', why: 'Rewrites the remote history.', summary: 'git push --force', detail: 'git push --force origin main' } });
  assert.equal(ask.status, 202, JSON.stringify(ask.body));
  const gb = await now('POST', `/v1/holds/${ask.body.id}/approve/begin`, { cookie, body: {} });
  assert.equal((await now('POST', `/v1/holds/${ask.body.id}/approve/finish`, { cookie, body: { challengeId: gb.body.challengeId, credential: await auth.get(gb.body.options) } })).status, 200);
  assert.equal((await now('POST', `/v1/approvals/${ask.body.id}/use`, { bearer: gk.body.key, origin: null, xleash: false, body: { hash: ask.body.hash } })).status, 200);
  assert.equal((await now('GET', '/v1/audit/verify', { cookie })).body.ok, true);
});
