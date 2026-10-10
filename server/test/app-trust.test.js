// The app, the first run and the privacy center (branch feat/app-trust): the demo hold, the launch funnel, the data
// export, the evidence pack (verified with the same code the browser runs), retention, account deletion end to end, and
// the WebAuthn options Safari needs.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World, ORIGIN } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { _resetMarks, HOLD_DAYS_DEFAULT } from '../src/trust.js';
import { sweep } from '../src/index.js';
import { sha256hex, b64u } from '../src/util.js';
import { verifyChain, decisionsCsv, MAPPING } from '../../site/public/app/evidence.js';
import { verifyCheckpoint } from '../../sdk/receipts.mjs';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); _resetMarks(); });
const anon = { origin: null, xleash: false };
const GH = 'ghp_' + 'S'.repeat(36);
const logSize = async (w) => (await w.log.head())?.size || 0;
/** the first hold's request hash (never exported: it stands for the exact request) */
const db0 = (w) => w.env.DB.raw.prepare('SELECT req_hash FROM holds LIMIT 1').get().req_hash;

async function approve(w, u, id) {
  const b = await w.req('POST', `/v1/holds/${id}/approve/begin`, { cookie: u.cookie, body: {} });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  return w.req('POST', `/v1/holds/${id}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
async function ceremony(w, u, begin, finish, body = {}) {
  const b = await w.req('POST', begin, { cookie: u.cookie, body });
  if (b.status !== 200) return b;
  return w.req('POST', finish, { cookie: u.cookie, body: { ...body, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
/** a CLI session for the user, through the real device-code sign-in */
async function cli(w, u) {
  const s = await w.req('POST', '/v1/device/start', { ...anon, body: {} });
  await w.req('POST', '/v1/device/lookup', { cookie: u.cookie, body: { user_code: s.body.user_code } });
  await ceremony(w, u, '/v1/device/approve/begin', '/v1/device/approve/finish', { user_code: s.body.user_code });
  return (await w.req('POST', '/v1/device/poll', { ...anon, body: { device_code: s.body.device_code } })).body.access_token;
}
/** a second person on the account with the given role, signed in on the web (rows written as the team code writes them) */
async function member(w, u, role) {
  const acct = await w.accountId(u.cookie);
  const mid = [...crypto.getRandomValues(new Uint8Array(12))].map((x) => x.toString(16).padStart(2, '0')).join('');
  const tok = b64u(crypto.getRandomValues(new Uint8Array(32)));
  w.env.DB.raw.prepare('INSERT INTO members (id, account_id, name, role, created_at) VALUES (?, ?, ?, ?, ?)').run(acct, acct, 'Founder', 'owner', Date.now());
  w.env.DB.raw.prepare('INSERT INTO members (id, account_id, name, role, created_at) VALUES (?, ?, ?, ?, ?)').run(mid, acct, 'Asha', role, Date.now());
  w.env.DB.raw.prepare("INSERT INTO sessions (hash, account_id, kind, created_at, expires_at, member_id) VALUES (?, ?, 'web', ?, ?, ?)").run(await sha256hex(tok), acct, Date.now(), Date.now() + 3600_000, mid);
  return { cookie: '__Host-leash=' + tok, memberId: mid };
}

test('Try a held call: a demo hold, approved with the real passkey ceremony, used once; never proxied, never public', async () => {
  const w = new World();
  const u = await w.user();
  const before = await logSize(w);
  const d = await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: {} });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  assert.equal(d.body.demo, true); assert.equal(d.body.created, true); assert.match(d.body.approve_url, /\/app#hold=[0-9a-f]{24}$/);
  // asking again while it waits returns the same hold (no second alert)
  const again = await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: {} });
  assert.equal(again.body.hold_id, d.body.hold_id); assert.equal(again.body.created, false);
  // it shows in the list like any hold, labelled as the demo
  const h = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds.find((x) => x.id === d.body.hold_id);
  assert.equal(h.kind, 'demo'); assert.match(h.preview, /^DEMO\./); assert.match(h.why, /^Demo:/);
  // retrying before approval: not approved
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: { hold: d.body.hold_id } })).body.error, 'not_approved');
  const a = await approve(w, u, d.body.hold_id);
  assert.equal(a.status, 200, JSON.stringify(a.body)); assert.equal(a.body.approved, true); assert.match(a.body.note, /No public receipt/);
  const r = await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: { hold: d.body.hold_id } });
  assert.equal(r.status, 200); assert.equal(r.body.status, 'executed'); assert.equal(r.body.response.provider, 'demo');
  // an approval works once
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: { hold: d.body.hold_id } })).body.error, 'already_used');
  // nothing went upstream, nothing was sealed in the public log, and the audit log says demo, not approve
  assert.equal(w.upstream.length, 0);
  assert.equal(await logSize(w), before, 'no public receipt for the demo');
  const acts = w.env.DB.raw.prepare('SELECT action FROM audit ORDER BY seq').all().map((x) => x.action);
  for (const x of ['demo_hold', 'demo_approved', 'demo_executed']) assert.ok(acts.includes(x), x);
  for (const x of ['hold', 'approve', 'proxy_approved']) assert.ok(!acts.includes(x), x);
  // the funnel: it tried the demo, which is not a protected call
  const me = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body;
  assert.ok(me.progress.demo > 0); assert.equal(me.progress.call, null);
});

test('the demo: denying it is private too; browser only; frozen accounts refuse; 10 an hour; only your own; strict body', async () => {
  const w = new World();
  const u = await w.user(), v = await w.user('Other', '198.51.100.9');
  const d = await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', `/v1/holds/${d.body.hold_id}/deny`, { cookie: u.cookie, body: { reason: 'just looking' } })).status, 200);
  assert.equal(await logSize(w), 0);
  assert.ok(w.env.DB.raw.prepare("SELECT 1 FROM audit WHERE action = 'demo_denied'").get());
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: { hold: d.body.hold_id } })).body.error, 'denied');
  // someone else's demo hold is not yours to retry
  const e = await w.req('POST', '/v1/demo/call', { cookie: v.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: { hold: e.body.hold_id } })).status, 404);
  // a command line session cannot (it is a dashboard lesson), and neither can a cross-site request
  const lsc = await cli(w, u);
  assert.equal((await w.req('POST', '/v1/demo/call', { ...anon, bearer: lsc, body: {} })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: u.cookie, origin: 'https://evil.test', body: {} })).body.error, 'csrf');
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: u.cookie, xleash: false, body: {} })).body.error, 'csrf');
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: { hold: d.body.hold_id, x: 1 } })).status, 400);
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: { x: 1 } })).body.error, 'bad_field');
  // the demo hold is not a guard approval: a guard key cannot read or use it
  const gk = (await w.req('POST', '/v1/guard/keys', { cookie: u.cookie, body: { label: 'g' } })).body.key;
  assert.equal((await w.req('GET', `/v1/approvals/${d.body.hold_id}`, { ...anon, bearer: gk })).status, 404);
  // frozen: nothing new is held
  await w.req('POST', '/v1/me/freeze', { cookie: v.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: v.cookie, body: { hold: e.body.hold_id } })).status, 409, 'a retry of a pending hold still answers');
  await w.req('POST', `/v1/holds/${e.body.hold_id}/deny`, { cookie: v.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/demo/call', { cookie: v.cookie, body: {} })).status, 423);
  // ten new demo holds an hour per account
  let last;
  for (let i = 0; i < 11; i++) {
    const x = await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: {} });
    last = x;
    if (x.status === 200) await w.req('POST', `/v1/holds/${x.body.hold_id}/deny`, { cookie: u.cookie, body: {} });
  }
  assert.equal(last.status, 429);
});

test('launch funnel markers: written once each, never by a poll; the first protected call is a real one', async () => {
  const w = new World();
  const u = await w.user();
  const acct = await w.accountId(u.cookie);
  const row = () => w.env.DB.raw.prepare('SELECT first_token_at, first_call_at, installed_at, alerts_at, demo_at FROM accounts WHERE id = ?').get(acct);
  assert.deepEqual(Object.values(row()), [null, null, null, null, null]);
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } })).body.token;
  const t1 = row().first_token_at;
  assert.ok(t1 > 0);
  await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } });
  assert.equal(row().first_token_at, t1, 'the first time stays');
  const p1 = await w.req('GET', '/p/github/user', { ...anon, bearer: tok });
  assert.equal(p1.status, 200);
  assert.ok(row().first_call_at > 0);
  // a second call writes no marker (memory gate), and the app's poll writes nothing at all
  const p2 = await w.req('GET', '/p/github/user', { ...anon, bearer: tok });
  const p1Writes = p1.writes, p2Writes = p2.writes;
  assert.ok(p2Writes < p1Writes, `${p2Writes} < ${p1Writes}`);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).writes, 0);
  // installed: once
  assert.equal((await w.req('POST', '/v1/me/installed', { cookie: u.cookie, body: {} })).status, 200);
  const i1 = row().installed_at; assert.ok(i1 > 0);
  await w.req('POST', '/v1/me/installed', { cookie: u.cookie, body: {} });
  assert.equal(row().installed_at, i1);
  assert.equal((await w.req('POST', '/v1/me/installed', { cookie: u.cookie, origin: 'https://evil.test', body: {} })).body.error, 'csrf');
  // alerts on
  assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/abc' } })).status, 200);
  assert.ok(row().alerts_at > 0);
  const me = (await w.req('GET', '/v1/me', { cookie: u.cookie })).body;
  assert.ok(me.progress.token && me.progress.call && me.progress.installed && me.progress.alerts);
  // a guard approval request is a protected call too
  const v = await w.user('Guard user', '198.51.100.20');
  const gk = (await w.req('POST', '/v1/guard/keys', { cookie: v.cookie, body: { label: 'g' } })).body.key;
  const g = await w.req('POST', '/v1/approvals', { ...anon, bearer: gk, body: { kind: 'shell', agent: 'claude-code', rule: 'sh.terraform-destroy', why: 'Destroys.', summary: 'terraform destroy', detail: 'terraform destroy' } });
  assert.equal(g.status, 202);
  assert.ok((await w.req('GET', '/v1/me', { cookie: v.cookie })).body.progress.call > 0);
});

test('GET /v1/admin/stats: the launch funnel, aggregate counts by day, within the query budget, no ids', async () => {
  const w = new World();
  w.env.STATS_TOKEN = 'st_' + 'k'.repeat(40);
  const u = await w.user('Jane Example'), v = await w.user('Other', '198.51.100.40'), x = await w.user('Third', '198.51.100.41');
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } })).body.token;
  await w.req('GET', '/p/github/user', { ...anon, bearer: tok });
  await w.req('POST', '/v1/me/installed', { cookie: v.cookie, body: {} });
  await w.req('POST', '/v1/push/subscribe', { cookie: x.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/xyz' } });
  await w.req('POST', '/v1/demo/call', { cookie: x.cookie, body: {} });
  const r = await w.req('GET', '/v1/admin/stats', { ...anon, bearer: w.env.STATS_TOKEN });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.queries <= 12, `${r.queries} queries`);
  assert.equal(r.writes, 0);
  const f = r.body.funnel;
  assert.deepEqual([f.accountsWithToken, f.accountsWithFirstProtectedCall, f.accountsTriedDemo, f.accountsWithAppInstalled, f.accountsWithAlertsOn, f.accountsWithAppInstalledOrAlertsOn], [1, 1, 1, 1, 1, 2]);
  assert.equal(f.byDay30d.length, 1);
  const day = f.byDay30d[0];
  assert.match(day.day, /^\d{4}-\d{2}-\d{2}$/);
  assert.deepEqual({ ...day, day: undefined }, { day: undefined, token: 1, firstProtectedCall: 1, demo: 1, installed: 1, alertsOn: 1 });
  // accounts from before the markers: a used token still counts as a first protected call, a device as alerts on
  w.env.DB.raw.prepare('UPDATE accounts SET first_call_at = NULL, alerts_at = NULL').run();
  const r2 = (await w.req('GET', '/v1/admin/stats', { ...anon, bearer: w.env.STATS_TOKEN })).body.funnel;
  assert.equal(r2.accountsWithFirstProtectedCall, 1); assert.equal(r2.accountsWithAlertsOn, 1);
  const text = JSON.stringify(r.body);
  for (const s of ['Jane', 'Other', 'Third', tok, cred, await w.accountId(u.cookie), 'fcm.googleapis']) assert.ok(!text.includes(s), s);
  // the D1 cap of 50 queries per invocation is never near
  w.env.DB.cap = 50;
  assert.equal((await w.req('GET', '/v1/admin/stats', { ...anon, bearer: w.env.STATS_TOKEN })).status, 200);
});

test('download all my data: owner only, fresh passkey, 3 an hour, audited, and never a secret', async () => {
  const w = new World();
  const u = await w.user('Data Owner');
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH, label: 'prod key' } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, label: 'laptop agent' } })).body.token;
  await w.req('DELETE', '/p/github/repos/acme/app', { ...anon, bearer: tok });
  const gk = (await w.req('POST', '/v1/guard/keys', { cookie: u.cookie, body: { label: 'guard one' } })).body.key;
  await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/SECRETPUSHTOKEN' } });
  // a command line session cannot, a cross-site request cannot, and the passkey must be fresh
  const lsc = await cli(w, u);
  assert.equal((await w.req('POST', '/v1/me/export/begin', { ...anon, bearer: lsc, body: {} })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', '/v1/me/export/begin', { cookie: u.cookie, origin: 'https://evil.test', body: {} })).body.error, 'csrf');
  const b = await w.req('POST', '/v1/me/export/begin', { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/me/export/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId } })).status, 400);
  const r = await ceremony(w, u, '/v1/me/export/begin', '/v1/me/export/finish');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.queries <= 40, `${r.queries} queries`);
  const x = r.body;
  assert.equal(x.format, 'counterseal-data-export/1');
  assert.equal(x.account.name, 'Data Owner'); assert.equal(x.account.hold_days, HOLD_DAYS_DEFAULT);
  assert.equal(x.credentials[0].label, 'prod key'); assert.equal(x.tokens[0].label, 'laptop agent');
  assert.equal(x.holds.pages_from, '/v1/export/holds');
  const hp = await w.req('GET', '/v1/export/holds', { cookie: u.cookie });
  assert.equal(hp.status, 200); assert.equal(hp.body.done, true);
  assert.equal(hp.body.entries.length, 1); assert.equal(hp.body.entries[0].path, '/repos/acme/app');
  assert.ok(!JSON.stringify(hp.body).includes(db0(w)), 'no hold request hash');
  assert.equal((await w.req('GET', '/v1/export/holds', { ...anon, bearer: lsc })).body.error, 'passkey_required');
  assert.equal(x.alert_devices[0].service, 'fcm.googleapis.com');
  assert.equal(x.audit.pages_from, '/v1/export/evidence', 'the app adds the audit log page by page');
  // no secret, no part of one, no hash that stands for one
  const text = JSON.stringify(x);
  const db = w.env.DB.raw;
  const secrets = [GH, GH.slice(-4), tok, gk, lsc, 'SECRETPUSHTOKEN', ...db.prepare('SELECT hash FROM tokens').all().map((y) => y.hash), ...db.prepare('SELECT hash FROM guard_keys').all().map((y) => y.hash),
    ...db.prepare('SELECT hash FROM sessions').all().map((y) => y.hash), ...db.prepare('SELECT ct, iv, wrapped_dek, dek_iv FROM credentials').all().flatMap(Object.values),
    ...db.prepare('SELECT jwk FROM passkeys').all().map((y) => JSON.parse(y.jwk).x), ...db.prepare('SELECT cred_id FROM passkeys').all().map((y) => y.cred_id)];
  for (const s of secrets) assert.ok(!text.includes(s), 'leaked: ' + String(s).slice(0, 12));
  assert.ok(db.prepare("SELECT 1 FROM audit WHERE action = 'data_export'").get(), 'on the record');
  // 3 an hour (the first begin above without a finish counts too)
  assert.equal((await w.req('POST', '/v1/me/export/begin', { cookie: u.cookie, body: {} })).status, 200);
  assert.equal((await w.req('POST', '/v1/me/export/begin', { cookie: u.cookie, body: {} })).status, 429);
  // on a team, only an owner
  const w2 = new World();
  const o = await w2.user('Team owner');
  const a = await member(w2, o, 'approver');
  assert.equal((await w2.req('POST', '/v1/me/export/begin', { cookie: a.cookie, body: {} })).body.error, 'role_required');
  assert.equal((await w2.req('POST', '/v1/me/retention', { cookie: a.cookie, body: { holdDays: 30 } })).body.error, 'role_required');
  assert.equal((await w2.req('GET', '/v1/export/holds', { cookie: a.cookie })).body.error, 'role_required');
  // but anyone on it may try the demo and read the evidence pack, as they read the audit log
  assert.equal((await w2.req('POST', '/v1/demo/call', { cookie: a.cookie, body: {} })).status, 200);
  assert.equal((await w2.req('GET', '/v1/export/evidence', { cookie: a.cookie })).status, 200);
});

test('the evidence pack: pages of the audit chain the browser verifies, a signed checkpoint, a CSV, no writes', async () => {
  const w = new World();
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } })).body.token;
  const h = await w.req('DELETE', '/p/github/repos/acme/app', { ...anon, bearer: tok });
  await approve(w, u, h.body.hold_id);
  await w.req('DELETE', '/p/github/repos/acme/app', { ...anon, bearer: tok });
  // more than a page of entries
  const { audit } = await import('../src/audit.js');
  const acct = await w.accountId(u.cookie);
  for (let i = 0; i < 520; i++) await audit(w.env, acct, 'web', 'note', { i, text: 'a "quoted" =formula' });
  let after = null, entries = [], first;
  for (;;) {
    const r = await w.req('GET', '/v1/export/evidence' + (after ? `?after=${after}` : ''), { cookie: u.cookie });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.writes, 0);
    assert.ok(r.queries <= 3, `${r.queries} queries`);
    if (!after) first = r.body;
    entries = entries.concat(r.body.entries);
    if (r.body.done) break;
    after = r.body.next_after;
  }
  assert.equal(entries.length, w.env.DB.raw.prepare('SELECT COUNT(*) AS n FROM audit WHERE account_id = ?').get(acct).n);
  assert.equal(first.from_start, true);
  const v = await verifyChain(entries, first.account_id, { fromStart: true });
  assert.equal(v.ok, true, JSON.stringify(v));
  // the checkpoint verifies under the log's key (the same SDK the browser loads)
  assert.ok(first.log.checkpoint);
  assert.ok(await verifyCheckpoint(first.log.checkpoint, first.log.verifier_key));
  // the browser catches an edit, a removal and a reorder
  const edited = entries.map((e, i) => (i === 7 ? { ...e, detail: e.detail.replace('"i":', '"j":') } : e));
  assert.equal((await verifyChain(edited, first.account_id, { fromStart: true })).ok, false);
  assert.equal((await verifyChain(entries.filter((_, i) => i !== 9), first.account_id, { fromStart: true })).ok, false);
  assert.equal((await verifyChain(entries.slice(1), first.account_id, { fromStart: true })).ok, false, 'a pack that claims to start at the beginning must');
  assert.equal((await verifyChain(entries.slice(1), first.account_id, { fromStart: false })).ok, true, 'a range verifies between its ends');
  // a date range
  const mid = entries[200].at;
  const ranged = await w.req('GET', `/v1/export/evidence?from=${mid}`, { cookie: u.cookie });
  assert.ok(ranged.body.entries.every((e) => e.at >= mid));
  assert.equal((await w.req('GET', '/v1/export/evidence?from=5&to=1', { cookie: u.cookie })).status, 400);
  assert.equal((await w.req('GET', '/v1/export/evidence?after=abc', { cookie: u.cookie })).status, 400);
  // the CSV: decisions only, formulas defused, quotes escaped
  const csv = decisionsCsv(entries);
  const lines = csv.trim().split('\r\n');
  assert.equal(lines[0].split(',')[0], 'seq');
  assert.equal(lines.length - 1, entries.filter((e) => ['hold', 'approve', 'deny', 'proxy', 'proxy_approved', 'run_approved'].includes(e.action)).length);
  assert.ok(lines.some((l) => l.includes('"approved"')) && lines.some((l) => l.includes('"held"')) && lines.some((l) => l.includes('"executed"')));
  assert.ok(!/(^|,)"[=+@-]/.test(csv.replace(/"-?\d/g, '')), 'no cell starts as a formula');
  assert.match(decisionsCsv([{ seq: 1, at: 0, actor: 'web', action: 'deny', detail: JSON.stringify({ path: '=HYPERLINK("x")' }), hash: 'h' }]), /"'=HYPERLINK\(""x""\)"/);
  // the mapping note is marked as our interpretation
  assert.match(MAPPING.note, /Our interpretation/); assert.ok(MAPPING.items.some((i) => /26\(6\)/.test(i.ref)) && MAPPING.items.some((i) => i.ref.startsWith('CC6.3')));
  // other accounts' entries never appear
  const other = await w.user('Other', '198.51.100.2');
  const o = await w.req('GET', '/v1/export/evidence', { cookie: other.cookie });
  assert.ok(o.body.entries.every((e) => !entries.some((x) => x.seq === e.seq)));
  assert.equal((await w.req('GET', '/v1/export/evidence', anon)).status, 401);
});

test('retention: an owner picks 30, 90 or 365 days for closed holds; the cleanup honours it; open holds stay', async () => {
  const w = new World();
  const u = await w.user(), v = await w.user('Default keeper', '198.51.100.3');
  const acct = await w.accountId(u.cookie), acct2 = await w.accountId(v.cookie);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.retention.holdDays, 365);
  for (const bad of [0, 31, '30', null, 3650]) assert.equal((await w.req('POST', '/v1/me/retention', { cookie: u.cookie, body: { holdDays: bad } })).status, 400, String(bad));
  const lsc = await cli(w, u);
  assert.equal((await w.req('POST', '/v1/me/retention', { ...anon, bearer: lsc, body: { holdDays: 30 } })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', '/v1/me/retention', { cookie: u.cookie, body: { holdDays: 30 } })).status, 200);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.retention.holdDays, 30);
  assert.ok(w.env.DB.raw.prepare("SELECT 1 FROM audit WHERE action = 'retention_changed'").get());
  const DAY = 86_400_000, t = Date.now();
  const ins = w.env.DB.raw.prepare("INSERT INTO holds (id, account_id, token_id, req_hash, method, host, path, rule, why, status, created_at, expires_at) VALUES (?, ?, 't', 'h', 'DELETE', 'api.github.com', '/x', 'r', 'w', ?, ?, ?)");
  const mk = (id, a, status, ageDays) => ins.run(id, a, status, t - ageDays * DAY, t - ageDays * DAY);
  mk('a'.repeat(24), acct, 'denied', 31); mk('b'.repeat(24), acct, 'used', 29); mk('c'.repeat(24), acct, 'pending', -0.01);
  mk('d'.repeat(24), acct2, 'denied', 364); mk('e'.repeat(24), acct2, 'expired', 366);
  await sweep(w.env, t);
  const left = w.env.DB.raw.prepare('SELECT id, status FROM holds ORDER BY id').all().map((r) => r.id[0] + ':' + r.status);
  assert.deepEqual(left, ['b:used', 'c:pending', 'd:denied']);
});

test('deleting the account leaves no row anywhere that names it, rate limit counters included', async () => {
  const w = new World();
  const u = await w.user('Leaving');
  const acct = await w.accountId(u.cookie);
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred } })).body.token;
  await w.req('DELETE', '/p/github/repos/acme/app', { ...anon, bearer: tok });
  await w.req('POST', '/v1/guard/keys', { cookie: u.cookie, body: { label: 'g' } });
  await w.req('POST', '/v1/demo/call', { cookie: u.cookie, body: {} });
  await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/abc' } });
  await w.req('POST', '/v1/keys', { cookie: u.cookie, body: { label: 'r' } });
  await w.req('POST', '/v1/me/installed', { cookie: u.cookie, body: {} });
  await cli(w, u);
  await ceremony(w, u, '/v1/me/export/begin', '/v1/me/export/finish');
  const d = await ceremony(w, u, '/v1/me/delete/begin', '/v1/me/delete/finish', { confirm: 'delete' });
  assert.equal(d.status, 200, JSON.stringify(d.body)); assert.equal(d.body.deleted, true);
  const db = w.env.DB.raw, found = [];
  for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all()) {
    const cols = db.prepare(`PRAGMA table_info(${name})`).all().map((c) => c.name);
    for (const c of cols) if (db.prepare(`SELECT 1 FROM ${name} WHERE CAST(${c} AS TEXT) LIKE ? LIMIT 1`).get('%' + acct + '%')) found.push(`${name}.${c}`);
  }
  assert.deepEqual(found, []);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).status, 401);
});

test('passkey sign-up options work in Safari: ES256 first, a discoverable credential in both spellings, user verification, no attestation', async () => {
  const w = new World();
  const b = await w.req('POST', '/v1/auth/register/begin', { body: { name: 'Ada Lovelace' } });
  const o = b.body.options;
  assert.equal(o.pubKeyCredParams[0].alg, -7);
  assert.deepEqual(o.authenticatorSelection, { residentKey: 'required', requireResidentKey: true, userVerification: 'required' });
  assert.equal(o.attestation, 'none');
  assert.equal(o.rp.id, 'leash.test'); assert.equal(new URL(ORIGIN).hostname, o.rp.id, 'the RP ID is the page\'s own host');
  assert.equal(Buffer.from(o.user.id, 'base64url').length, 16, 'a random user handle, never the name');
  assert.ok(Buffer.from(o.challenge, 'base64url').length >= 16);
  assert.ok(o.timeout >= 60_000);
  // the login options carry no allowCredentials, so Safari offers every passkey for the site
  const l = await w.req('POST', '/v1/auth/login/begin', { body: {} });
  assert.equal(l.body.options.allowCredentials, undefined); assert.equal(l.body.options.userVerification, 'required');
});

test('a web session ends after an hour without an action of yours; background reads do not count; command lines are unaffected', async () => {
  const w = new World();
  const u = await w.user();
  const db = w.env.DB.raw;
  const set = (ms) => db.prepare("UPDATE sessions SET seen_at = ? WHERE kind = 'web'").run(Date.now() - ms);
  const seen = () => db.prepare("SELECT seen_at FROM sessions WHERE kind = 'web'").get().seen_at;
  assert.ok(seen() > 0, 'a new web session starts active');
  // the app's background refresh: no header, so nothing is written and the clock keeps running
  set(30 * 60_000);
  const before = seen();
  const r = await w.req('GET', '/v1/me', { cookie: u.cookie });
  assert.equal(r.status, 200); assert.equal(seen(), before);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).writes, 0, 'a background read writes nothing');
  // a read you made (the app marks it) or any write keeps it alive
  await w.req('GET', '/v1/holds', { cookie: u.cookie, headers: { 'x-leash-active': '1' } });
  assert.ok(seen() > before);
  set(30 * 60_000);
  await w.req('POST', '/v1/me/installed', { cookie: u.cookie, body: {} });
  assert.ok(seen() > Date.now() - 5000);
  // at most one write a minute
  const again = await w.req('GET', '/v1/me', { cookie: u.cookie, headers: { 'x-leash-active': '1' } });
  assert.equal(again.writes, 0);
  // an hour without an action: signed out, and the reason says so
  const lsc = await cli(w, u);
  set(61 * 60_000);
  const out = await w.req('GET', '/v1/me', { cookie: u.cookie });
  assert.equal(out.status, 401); assert.equal(out.body.reason, 'idle');
  // a session made before the migration (no seen_at) counts from its creation
  db.prepare("UPDATE sessions SET seen_at = NULL, created_at = ? WHERE kind = 'web'").run(Date.now() - 2 * 3600_000);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).status, 401);
  // the command line session keeps working (it has its own 7-day life)
  assert.equal((await w.req('GET', '/v1/me', { ...anon, bearer: lsc })).status, 200);
});
