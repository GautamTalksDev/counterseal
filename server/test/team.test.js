// The two-person seal (feature 2a): team members, invites, roles, removal, quorum votes, and the 24-hour rule for anything
// that lowers protection. Abuse cases: invite reuse, expiry and revocation; the same person counted twice (a second
// passkey, a second browser, two confirmations at once); a viewer, a member, a removed or a demoted member sealing; the
// requester sealing with self-approval off; a race between two approvers; lowering the quorum early; CSRF on both hosts;
// pre-approvals and money caps as a way around two seals; Freeze; receipt privacy; the D1 budgets.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { World, Authenticator, ORIGIN, RP_ID } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { b64u, sha256hex } from '../src/util.js';
import { MAX_MEMBERS, INVITES_PER_HOUR, plan, effective } from '../src/team.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });
const anon = { origin: null, xleash: false };
const GH = 'ghp_' + 'T'.repeat(36);
const HOUR = 3600_000, DAY = 24 * HOUR;
const count = (w, sql, ...a) => w.env.DB.raw.prepare(sql).get(...a).n;
const actions = (w) => w.env.DB.raw.prepare('SELECT action FROM audit ORDER BY seq').all().map((r) => r.action);

async function timeShift(ms, fn) { const real = Date.now; const t0 = real(); Date.now = () => t0 + ms + (real() - t0); try { return await fn(); } finally { Date.now = real; } }
async function withVapid(w) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  w.env.VAPID_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
  w.pushes = [];
  w.env.__pushFetch = async (url) => { w.pushes.push(url); return new Response(null, { status: 201 }); };
}
const device = (w, u, name) => w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/' + name } });

/** the account's founder: their member id is the account id */
async function founder(w, name = 'Gautam') {
  const u = await w.user(name);
  u.id = await w.accountId(u.cookie);
  u.member = u.id;
  return u;
}
async function invite(w, owner, { role = 'approver', label = 'teammate', hours } = {}, o = {}) {
  const b = await w.req('POST', '/v1/team/invites/begin', { cookie: owner.cookie, body: { role, label, ...(hours === undefined ? {} : { hours }) }, ...o });
  if (b.status !== 200) return b;
  return w.req('POST', '/v1/team/invites/finish', { cookie: owner.cookie, body: { challengeId: b.body.challengeId, credential: await owner.auth.get(b.body.options) }, ...o });
}
const tokenOf = (r) => r.body.url.split('#invite=')[1];
/** the invite page: begin (name), a new passkey, finish; returns the new member's cookie, authenticator and id */
async function join(w, token, name, o = {}) {
  const auth = new Authenticator(o.origin || ORIGIN, o.rpId || RP_ID);
  const url = (p) => (o.host || '') + p;
  const b = await w.req('POST', url('/v1/invites/begin'), { body: { token, name }, ...(o.origin ? { origin: o.origin } : {}), ...(o.cookie ? { cookie: o.cookie } : {}) });
  if (b.status !== 200) return b;
  const f = await w.req('POST', url('/v1/invites/finish'), { body: { token, challengeId: b.body.challengeId, credential: await auth.create(b.body.options) }, ...(o.origin ? { origin: o.origin } : {}) });
  if (f.status !== 200) return f;
  const cookie = f.headers.get('set-cookie').split(';')[0];
  const me = (await w.req('GET', url('/v1/me'), { cookie, ...(o.origin ? { origin: o.origin } : {}) })).body;
  return { status: 200, cookie, auth, member: me.member.id, role: me.member.role, name };
}
/** a person on the team with a role, through a real invite */
async function add(w, owner, name, role = 'approver') {
  const r = await invite(w, owner, { role, label: name + ' (label)' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const m = await join(w, tokenOf(r), name);
  assert.equal(m.status, 200, JSON.stringify(m.body));
  return m;
}
/** approve = seal: begin, the person's passkey, finish */
async function seal(w, u, id, auth = u.auth) {
  const b = await w.req('POST', `/v1/holds/${id}/approve/begin`, { cookie: u.cookie, body: {} });
  if (b.status !== 200) return b;
  return w.req('POST', `/v1/holds/${id}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await auth.get(b.body.options) } });
}
async function ceremony(w, u, path, body = {}) {
  const b = await w.req('POST', path + '/begin', { cookie: u.cookie, body });
  if (b.status !== 200) return b;
  return w.req('POST', path + '/finish', { cookie: u.cookie, body: { ...body, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
const setQuorum = (w, u, quorum, selfApprove) => ceremony(w, u, '/v1/team/quorum', { quorum, selfApprove });
const setRole = (w, u, m, role) => ceremony(w, u, `/v1/team/members/${m.member || m}/role`, { role });
const remove = (w, u, m) => ceremony(w, u, `/v1/team/members/${m.member || m}/remove`);
async function vault(w, u) {
  const r = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body.id;
}
/** a token made by u, and its DELETE held */
async function heldCall(w, u, cred, path = '/repos/acme/app') {
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, label: 'agent of ' + (u.name || 'founder') } });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  const r = await w.req('DELETE', '/p/github' + path, { bearer: t.body.token, ...anon });
  assert.equal(r.status, 428, JSON.stringify(r.body));
  return { token: t.body.token, tokenId: t.body.id, hold: r.body.hold_id, body: r.body };
}
/** a second passkey for a member, stored as a real registration would store it */
async function extraPasskey(w, accountId, memberId) {
  const a = new Authenticator(ORIGIN, RP_ID);
  await a.create({ challenge: 'AAAA' });
  const j = await crypto.subtle.exportKey('jwk', a.kp.publicKey);
  w.env.DB.raw.prepare('INSERT INTO passkeys (cred_id, account_id, alg, jwk, sign_count, created_at, rp_id, member_id) VALUES (?, ?, -7, ?, 0, ?, ?, ?)')
    .run(b64u(a.credId), accountId, JSON.stringify({ kty: 'EC', crv: 'P-256', x: j.x, y: j.y, ext: true }), Date.now(), RP_ID, memberId);
  return a;
}
async function login(w, auth) {
  const b = await w.req('POST', '/v1/auth/login/begin', { body: {} });
  const f = await w.req('POST', '/v1/auth/login/finish', { body: { challengeId: b.body.challengeId, credential: await auth.get(b.body.options) } });
  return f.status === 200 ? { cookie: f.headers.get('set-cookie').split(';')[0], auth } : f;
}
/** the same person signed in again (web sessions last 12 hours; tests that move the clock a day sign in again) */
const relog = async (w, x) => ({ ...x, cookie: (await login(w, x.auth)).cookie });
async function cliSession(w, u) {
  const d = await w.req('POST', '/v1/device/start', { body: {}, ...anon, ip: '198.51.100.' + Math.floor(Math.random() * 200) });
  const ab = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.body.user_code } });
  await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.body.user_code, challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } });
  const p = await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, ...anon });
  assert.equal(p.status, 200, JSON.stringify(p.body));
  return p.body.access_token;
}

test('an account without a team works as before: its founder is the owner, one seal approves, the record keeps its shape', async () => {
  const w = new World();
  const u = await founder(w);
  assert.deepEqual((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.member, { id: u.id, role: 'owner', name: 'Gautam', founder: true });
  const t = (await w.req('GET', '/v1/team', { cookie: u.cookie })).body;
  assert.equal(t.quorum, 1); assert.equal(t.selfApprove, true); assert.equal(t.pending, null); assert.equal(t.voters, 1);
  assert.deepEqual(t.members.map((m) => [m.id, m.role, m.founder, m.passkeys, m.you]), [[u.id, 'owner', true, 1, true]]);
  assert.equal(count(w, 'SELECT COUNT(*) n FROM members'), 0, 'nothing is written for an account without a team');
  const cred = await vault(w, u);
  const h = await heldCall(w, u, cred);
  assert.equal(h.body.seals_needed, 1); assert.doesNotMatch(h.body.message, /different approvers/);
  const a = await seal(w, u, h.hold);
  assert.equal(a.status, 200, JSON.stringify(a.body));
  assert.equal(a.body.approved, true); assert.equal(a.body.seals, 1); assert.equal(a.body.needs, 1);
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/app', { bearer: h.token, ...anon })).status, 200);
  const ap = JSON.parse(w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'approve'").get().detail);
  for (const k of ['member', 'quorum', 'votes']) assert.ok(!(k in ap), k);
  assert.ok(!actions(w).includes('approve_vote'));
  const rc = (await w.req('GET', '/v1/log/entries?start=0&count=50', anon)).body.entries.map((e) => e.entry.receipt).find((r) => r.decision === 'approved');
  assert.deepEqual(Object.keys(rc.meta).sort(), ['map', 'passkey', 'rule'], 'no quorum fields on a one-seal approval');
});

test('invites: an owner with a passkey makes one; single use, stored hashed, in the URL fragment, 2 hours by default, revocable; the token is never stored or logged', async () => {
  const w = new World();
  const u = await founder(w);
  const r = await invite(w, u, { role: 'approver', label: 'Asha (platform)' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.match(r.body.url, /^https:\/\/leash\.test\/app#invite=[A-Za-z0-9_-]{43}$/);
  const token = tokenOf(r);
  assert.ok(Math.abs(r.body.expiresAt - (Date.now() + 2 * HOUR)) < 60_000, '2 hours by default');
  const row = w.env.DB.raw.prepare('SELECT * FROM invites').get();
  assert.equal(row.hash, await sha256hex(token)); assert.equal(row.created_by, u.id); assert.equal(row.role, 'approver'); assert.equal(row.account_id, u.id);
  const everywhere = JSON.stringify(['invites', 'audit', 'challenges', 'members', 'sessions'].map((t) => w.env.DB.raw.prepare(`SELECT * FROM ${t}`).all()));
  assert.ok(!everywhere.includes(token), 'the token is stored nowhere');
  assert.ok(!JSON.stringify(w.env.DB.raw.prepare('SELECT detail FROM audit').all()).includes(row.hash), 'the audit log names the invite, not its hash');
  // the invite page shows who invites, to which account and for which role, before anything is made
  const look = await w.req('POST', '/v1/invites/lookup', { body: { token } });
  assert.equal(look.status, 200, JSON.stringify(look.body));
  assert.deepEqual({ ...look.body, expires_at: 0 }, { account: 'Gautam', inviter: 'Gautam', role: 'approver', label: 'Asha (platform)', expires_at: 0 });
  // the parameters are checked, and what the passkey approved is exactly what is made
  for (const [body, code] of [[{ role: 'owner', label: 'x' }, 'bad_role'], [{ role: 'admin', label: 'x' }, 'bad_role'], [{ role: 'viewer', label: '<b>' }, 'bad_label'], [{ role: 'viewer' }, 'bad_label'],
    [{ role: 'viewer', label: 'x', hours: 25 }, 'bad_hours'], [{ role: 'viewer', label: 'x', hours: 0 }, 'bad_hours'], [{ role: 'viewer', label: 'x', hours: 1.5 }, 'bad_hours']]) {
    assert.equal((await w.req('POST', '/v1/team/invites/begin', { cookie: u.cookie, body })).body.error, code, JSON.stringify(body));
  }
  const b = await w.req('POST', '/v1/team/invites/begin', { cookie: u.cookie, body: { role: 'viewer', label: 'viewer one', hours: 24 } });
  const f = await w.req('POST', '/v1/team/invites/finish', { cookie: u.cookie, body: { role: 'approver', label: 'changed', hours: 1, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(f.body.role, 'viewer'); assert.equal(f.body.label, 'viewer one'); assert.ok(f.body.expiresAt > Date.now() + 23 * HOUR);
  // joining uses it once; a second use is refused at every step
  const a = await join(w, token, 'Asha');
  assert.equal(a.status, 200, JSON.stringify(a.body)); assert.equal(a.role, 'approver'); assert.notEqual(a.member, u.id);
  assert.equal((await w.req('POST', '/v1/invites/lookup', { body: { token } })).body.error, 'invite_invalid');
  assert.equal((await join(w, token, 'Mallory')).body.error, 'invite_invalid');
  // the passkey made by joining is the new member's own, and signs them in as themselves
  assert.equal(count(w, 'SELECT COUNT(*) n FROM passkeys WHERE member_id = ?', a.member), 1);
  const again = await login(w, a.auth);
  assert.deepEqual((await w.req('GET', '/v1/me', { cookie: again.cookie })).body.member, { id: a.member, role: 'approver', name: 'Asha', founder: false });
  // an invite expires (2 hours by default)
  const r2 = await invite(w, u, { role: 'member', label: 'late' });
  await timeShift(2 * HOUR + 60_000, async () => assert.equal((await join(w, tokenOf(r2), 'Late')).body.error, 'invite_invalid'));
  // revoked: dead at once; revoking twice is not found
  const r3 = await invite(w, u, { role: 'member', label: 'revoked' });
  assert.equal((await w.req('DELETE', `/v1/team/invites/${r3.body.id}`, { cookie: u.cookie })).status, 200);
  assert.equal((await join(w, tokenOf(r3), 'Revoked')).body.error, 'invite_invalid');
  assert.equal((await w.req('DELETE', `/v1/team/invites/${r3.body.id}`, { cookie: u.cookie })).status, 404);
  for (const bad of ['', 'x', token + 'A', 'A'.repeat(43), 42]) assert.ok(['bad_token', 'invite_invalid'].includes((await w.req('POST', '/v1/invites/lookup', { body: { token: bad } })).body.error), String(bad));
  // only an owner, only in the app with a passkey
  assert.equal((await w.req('POST', '/v1/team/invites/begin', { cookie: a.cookie, body: { role: 'viewer', label: 'x' } })).body.error, 'role_required');
  assert.equal((await w.req('DELETE', `/v1/team/invites/${f.body.id}`, { cookie: a.cookie })).body.error, 'role_required');
  const cli = await cliSession(w, u);
  assert.equal((await w.req('POST', '/v1/team/invites/begin', { bearer: cli, ...anon, body: { role: 'viewer', label: 'x' } })).body.error, 'passkey_required');
  assert.deepEqual([...new Set(actions(w).filter((x) => /^invite_|^member_joined$/.test(x)))].sort(), ['invite_created', 'invite_revoked', 'member_joined']);
});

test('an invite token never reaches a log line, an audit entry or an error message, even when it is refused', async () => {
  const w = new World();
  const u = await founder(w);
  const lines = [];
  const keep = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(keep)) console[k] = (...a) => { lines.push(a.map(String).join(' ')); };
  let token;
  try {
    const r = await invite(w, u, { role: 'approver', label: 'logged (yes)' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    token = tokenOf(r);
    const outs = [await w.req('POST', '/v1/invites/lookup', { body: { token } }), await w.req('POST', '/v1/invites/lookup', { body: { token }, origin: 'https://evil.test' }),
      await w.req('POST', '/v1/invites/begin', { body: { token, name: '<bad>' } })];
    const m = await join(w, token, 'Asha');
    outs.push(await w.req('POST', '/v1/invites/lookup', { body: { token } }), await w.req('POST', '/v1/invites/begin', { body: { token, name: 'Again' } }));
    for (const o of outs) assert.ok(!JSON.stringify(o.body).includes(token), 'not echoed in an answer');
    assert.equal(m.status, 200);
  } finally { Object.assign(console, keep); }
  assert.ok(lines.length > 0, 'refusals were logged as security events');
  assert.ok(!lines.join('\n').includes(token), 'no log line carries the token');
  assert.ok(!JSON.stringify(w.env.DB.raw.prepare('SELECT * FROM audit').all()).includes(token));
});

test('invites are limited: 10 people a team counting open invites, and 10 invites an hour per account', async () => {
  assert.equal(MAX_MEMBERS, 10); assert.equal(INVITES_PER_HOUR, 10);
  const w = new World();
  const u = await founder(w);
  for (let i = 0; i < MAX_MEMBERS - 1; i++) assert.equal((await invite(w, u, { role: 'viewer', label: 'v' + i })).status, 200);
  assert.equal((await invite(w, u, { role: 'viewer', label: 'one more' })).body.error, 'team_full', 'the founder and 9 open invites');
  const list = (await w.req('GET', '/v1/team', { cookie: u.cookie })).body.invites;
  assert.equal(list.length, 9);
  assert.ok(list.every((i) => !('hash' in i) && !('token' in i)));
  await w.req('DELETE', `/v1/team/invites/${list[0].id}`, { cookie: u.cookie });
  assert.equal((await invite(w, u, { role: 'viewer', label: 'tenth' })).status, 200);
  await w.req('DELETE', `/v1/team/invites/${list[1].id}`, { cookie: u.cookie });
  const over = await invite(w, u, { role: 'viewer', label: 'eleventh' });
  assert.equal(over.status, 429); assert.equal(over.body.error, 'slow_down');
});

test('joining: a new passkey that the same authenticator cannot make twice; a browser already in the account is refused; names are unique; the whole team is alerted', async () => {
  const w = new World();
  await withVapid(w);
  const u = await founder(w);
  assert.equal((await device(w, u, 'owner-phone')).status, 200);
  const r = await invite(w, u, { role: 'approver', label: 'Ben' });
  const token = tokenOf(r);
  const b = await w.req('POST', '/v1/invites/begin', { body: { token, name: 'Ben' } });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  assert.deepEqual(b.body.options.excludeCredentials, [{ type: 'public-key', id: b64u(u.auth.credId) }], 'an authenticator that holds one of the account\'s passkeys refuses to make another');
  assert.equal(b.body.options.authenticatorSelection.userVerification, 'required'); assert.equal(b.body.options.rp.id, RP_ID);
  assert.deepEqual([b.body.account, b.body.inviter, b.body.role], ['Gautam', 'Gautam', 'approver']);
  // a browser signed in to the account is a member already
  assert.equal((await w.req('POST', '/v1/invites/begin', { body: { token, name: 'Ben' }, cookie: u.cookie })).body.error, 'already_member');
  assert.equal((await w.req('POST', '/v1/invites/lookup', { body: { token }, cookie: u.cookie })).body.error, 'already_member');
  // names are unique in a team (the founder's too), whatever the case; and they are plain names
  assert.equal((await w.req('POST', '/v1/invites/begin', { body: { token, name: 'gautam' } })).body.error, 'name_taken');
  for (const bad of ['', 'x'.repeat(61), '<script>', 'a‮b', 'a\nb']) assert.equal((await w.req('POST', '/v1/invites/begin', { body: { token, name: bad } })).body.error, 'bad_name', JSON.stringify(bad));
  // joining wakes every device already on the team (never the joiner's: they have none yet)
  w.pushes.length = 0;
  const m = await join(w, token, 'Ben');
  assert.equal(m.status, 200, JSON.stringify(m.body));
  assert.deepEqual(w.pushes, ['https://fcm.googleapis.com/fcm/send/owner-phone']);
  const ev = (await w.req('GET', '/v1/alerts', { cookie: u.cookie })).body.team;
  assert.deepEqual({ ...ev[0], at: 0 }, { kind: 'member_joined', at: 0, name: 'Ben', role: 'approver' });
  assert.equal(JSON.parse(w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'member_joined'").get().detail).invited_by, u.id);
  // the joiner's name is taken now too, and a finished join cannot be finished again
  const r2 = await invite(w, u, { role: 'viewer', label: 'Ben again' });
  assert.equal((await w.req('POST', '/v1/invites/begin', { body: { token: tokenOf(r2), name: 'BEN' } })).body.error, 'name_taken');
  const t = (await w.req('GET', '/v1/team', { cookie: m.cookie })).body;
  assert.deepEqual(t.members.map((x) => [x.name, x.role, x.label]), [['Gautam', 'owner', null], ['Ben', 'approver', 'Ben']]);
  assert.equal(t.me.id, m.member); assert.equal(t.members.find((x) => x.you).id, m.member);
});

test('two seals: two different approvers each seal with their own passkey; one person counts once (second passkey, second browser); viewers and members cannot seal; any denial ends it', async () => {
  const w = new World();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha', 'approver');
  const vic = await add(w, u, 'Vic', 'viewer');
  const mel = await add(w, u, 'Mel', 'member');
  assert.equal((await setQuorum(w, u, 2, true)).status, 200);
  const cred = await vault(w, u);
  const h = await heldCall(w, u, cred);
  assert.equal(h.body.seals_needed, 2); assert.match(h.body.message, /2 different approvers/);
  // a viewer or a member is refused before any passkey prompt
  assert.equal((await seal(w, vic, h.hold)).body.error, 'role_required');
  assert.equal((await seal(w, mel, h.hold)).body.error, 'role_required');
  // the first seal is private and approves nothing
  const s1 = await seal(w, u, h.hold);
  assert.equal(s1.status, 200, JSON.stringify(s1.body));
  assert.deepEqual([s1.body.approved, s1.body.seals, s1.body.needs], [false, 1, 2]);
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/app', { bearer: h.token, ...anon })).status, 428, 'one seal is not enough');
  // the same person again: from the same browser, from a second browser, with a second passkey of their own
  assert.equal((await seal(w, u, h.hold)).body.error, 'already_sealed');
  const second = await login(w, u.auth);
  assert.equal((await seal(w, second, h.hold)).body.error, 'already_sealed');
  const pk2 = await extraPasskey(w, u.id, u.id);
  assert.equal((await seal(w, u, h.hold, pk2)).body.error, 'already_sealed');
  // a passkey that belongs to someone else cannot seal in your session
  const b = await w.req('POST', `/v1/holds/${h.hold}/approve/begin`, { cookie: asha.cookie, body: {} });
  const wrong = await w.req('POST', `/v1/holds/${h.hold}/approve/finish`, { cookie: asha.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(wrong.status, 401); assert.equal(wrong.body.error, 'unknown_passkey');
  // the card: 1 of 2, by whom, with which passkey (every member sees it)
  const card = (await w.req('GET', '/v1/holds', { cookie: vic.cookie })).body.holds.find((x) => x.id === h.hold);
  assert.equal(card.needs, 2); assert.equal(card.votes.length, 1);
  assert.deepEqual([card.votes[0].member, card.votes[0].name, card.votes[0].passkey], [u.id, 'Gautam', (await sha256hex(b64u(u.auth.credId))).slice(0, 16)]);
  assert.ok(!('req_hash' in card));
  // a second, different approver completes it: the agent may retry once
  const s2 = await seal(w, asha, h.hold);
  assert.equal(s2.status, 200, JSON.stringify(s2.body)); assert.deepEqual([s2.body.approved, s2.body.seals], [true, 2]);
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/app', { bearer: h.token, ...anon })).status, 200);
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/app', { bearer: h.token, ...anon })).status, 428, 'once');
  assert.deepEqual(w.env.DB.raw.prepare('SELECT member_id FROM hold_votes WHERE hold_id = ? ORDER BY at').all(h.hold).map((x) => x.member_id), [u.id, asha.member]);
  const ap = JSON.parse(w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'approve'").get().detail);
  assert.equal(ap.quorum, 2); assert.equal(ap.member, asha.member); assert.deepEqual(ap.votes.map((x) => x.member), [u.id, asha.member]);
  assert.equal(count(w, "SELECT COUNT(*) n FROM audit WHERE action = 'approve_vote'"), 1);
  // a denial by anyone, a viewer too, ends a hold whatever seals it has
  const h2 = await heldCall(w, u, cred, '/repos/acme/two');
  assert.equal((await seal(w, asha, h2.hold)).body.seals, 1);
  assert.equal((await w.req('POST', `/v1/holds/${h2.hold}/deny`, { cookie: vic.cookie, body: { reason: 'not today' } })).status, 200);
  assert.equal((await seal(w, u, h2.hold)).status, 404);
  assert.equal(JSON.parse(w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'deny'").get().detail).member, vic.member);
  assert.equal((await w.req('GET', '/v1/audit/verify', { cookie: u.cookie })).body.ok, true);
});

test('two confirmations at once: one person in two browsers is counted once; two approvers at once approve exactly once', async () => {
  const w = new World();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha');
  const ben = await add(w, u, 'Ben');
  await setQuorum(w, u, 2, true);
  const cred = await vault(w, u);
  // Asha begins in two browsers (with two passkeys of hers), then confirms both at the same moment
  const h = await heldCall(w, u, cred);
  const pk2 = await extraPasskey(w, u.id, asha.member);
  const other = await login(w, pk2);
  const b1 = await w.req('POST', `/v1/holds/${h.hold}/approve/begin`, { cookie: asha.cookie, body: {} });
  const b2 = await w.req('POST', `/v1/holds/${h.hold}/approve/begin`, { cookie: other.cookie, body: {} });
  const [f1, f2] = await Promise.all([
    w.req('POST', `/v1/holds/${h.hold}/approve/finish`, { cookie: asha.cookie, body: { challengeId: b1.body.challengeId, credential: await asha.auth.get(b1.body.options) } }),
    w.req('POST', `/v1/holds/${h.hold}/approve/finish`, { cookie: other.cookie, body: { challengeId: b2.body.challengeId, credential: await pk2.get(b2.body.options) } }),
  ]);
  assert.deepEqual([f1.status, f2.status].sort(), [200, 409], JSON.stringify([f1.body, f2.body]));
  assert.equal([f1, f2].find((x) => x.status === 409).body.error, 'already_sealed');
  assert.equal(count(w, 'SELECT COUNT(*) n FROM hold_votes WHERE hold_id = ?', h.hold), 1);
  assert.equal(w.env.DB.raw.prepare('SELECT status FROM holds WHERE id = ?').get(h.hold).status, 'pending');
  // two different approvers confirm at the same moment: one approval, two seals, one receipt
  w.env.DB.raw.prepare('UPDATE accounts SET receipts = 1').run();
  const h2 = await heldCall(w, u, cred, '/repos/acme/race');
  const ba = await w.req('POST', `/v1/holds/${h2.hold}/approve/begin`, { cookie: asha.cookie, body: {} });
  const bb = await w.req('POST', `/v1/holds/${h2.hold}/approve/begin`, { cookie: ben.cookie, body: {} });
  const [x, y] = await Promise.all([
    w.req('POST', `/v1/holds/${h2.hold}/approve/finish`, { cookie: asha.cookie, body: { challengeId: ba.body.challengeId, credential: await asha.auth.get(ba.body.options) } }),
    w.req('POST', `/v1/holds/${h2.hold}/approve/finish`, { cookie: ben.cookie, body: { challengeId: bb.body.challengeId, credential: await ben.auth.get(bb.body.options) } }),
  ]);
  assert.equal(x.status, 200, JSON.stringify(x.body)); assert.equal(y.status, 200, JSON.stringify(y.body));
  assert.ok(x.body.approved || y.body.approved);
  assert.equal(w.env.DB.raw.prepare('SELECT status FROM holds WHERE id = ?').get(h2.hold).status, 'approved');
  assert.equal(count(w, 'SELECT COUNT(*) n FROM hold_votes WHERE hold_id = ?', h2.hold), 2);
  const approves = w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'approve'").all().map((r) => JSON.parse(r.detail)).filter((d) => d.hold === h2.hold);
  assert.equal(approves.length, 1, 'exactly one approval');
  const receipts = (await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries.map((e) => e.entry.receipt).filter((r) => r.decision === 'approved');
  assert.equal(receipts.length, 1); assert.equal(receipts[0].meta.quorum, 2); assert.equal(receipts[0].meta.votes, 2);
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/race', { bearer: h2.token, ...anon })).status, 200);
});

test('self-approval off: whoever made the token or guard key that asked cannot be one of the seals; turning it on waits 24 hours', async () => {
  const w = new World();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha');
  const ben = await add(w, u, 'Ben');
  const cred = await vault(w, u);
  assert.equal((await setQuorum(w, u, 2, false)).body.pending, null, 'turning self-approval off is immediate');
  // Asha's own agent token asks: Asha cannot seal it; the owner and Ben can
  const h = await heldCall(w, asha, cred);
  assert.equal(w.env.DB.raw.prepare('SELECT requested_by FROM holds WHERE id = ?').get(h.hold).requested_by, asha.member);
  const own = await seal(w, asha, h.hold);
  assert.equal(own.status, 403); assert.equal(own.body.error, 'own_request');
  assert.equal((await seal(w, u, h.hold)).body.approved, false);
  assert.equal((await seal(w, ben, h.hold)).body.approved, true);
  // a coding agent's guard key works the same way
  const gk = (await w.req('POST', '/v1/guard/keys', { cookie: asha.cookie, body: { label: 'asha laptop' } })).body.key;
  const ask = await w.req('POST', '/v1/approvals', { bearer: gk, ...anon, body: { kind: 'shell', agent: 'claude-code', rule: 'sh.terraform-destroy', why: 'Destroys everything.', summary: 'terraform destroy', detail: 'terraform destroy -auto-approve', context: { cwd: 'infra' } } });
  assert.equal(ask.status, 202, JSON.stringify(ask.body));
  assert.equal((await seal(w, asha, ask.body.id)).body.error, 'own_request');
  // with self-approval back on (after 24 hours), the maker may be one of the two
  assert.equal((await setQuorum(w, u, 2, true)).body.pending.selfApprove, true);
  const h2 = await heldCall(w, asha, cred, '/repos/acme/b');
  assert.equal((await seal(w, asha, h2.hold)).body.error, 'own_request', 'still off until the 24 hours are over');
  await timeShift(DAY + 60_000, async () => {
    const [a2, b2] = [await relog(w, asha), await relog(w, ben)];
    const h3 = await heldCall(w, a2, cred, '/repos/acme/c');
    const s = await seal(w, a2, h3.hold);
    assert.equal(s.status, 200, JSON.stringify(s.body)); assert.equal(s.body.approved, false);
    assert.equal((await seal(w, b2, h3.hold)).body.approved, true);
  });
});

test('removing a member revokes their sessions, passkeys, devices, tokens, guard keys and receipts keys, closes what they asked for and drops their seals, at once', async () => {
  const w = new World();
  await withVapid(w);
  const u = await founder(w);
  const asha = await add(w, u, 'Asha');
  const ben = await add(w, u, 'Ben');
  await setQuorum(w, u, 2, true);
  const cred = await vault(w, u);
  // everything Asha has: a CLI session, a device, a token with a waiting hold, a guard key, a receipts key, a seal
  const cli = await cliSession(w, asha);
  assert.equal((await device(w, asha, 'asha-phone')).status, 200);
  const mine = await heldCall(w, asha, cred, '/repos/acme/asha');
  const gk = (await w.req('POST', '/v1/guard/keys', { bearer: cli, ...anon, body: { label: 'asha cli guard' } })).body.key;
  const rk = (await w.req('POST', '/v1/keys', { cookie: asha.cookie, body: { label: 'asha receipts' } })).body.key;
  const other = await heldCall(w, u, cred, '/repos/acme/other');
  assert.equal((await seal(w, asha, other.hold)).body.seals, 1);
  w.env.DB.raw.prepare('INSERT INTO move_links (hash, account_id, created_at, expires_at, member_id) VALUES (?, ?, ?, ?, ?)').run('h'.repeat(64), u.id, Date.now(), Date.now() + 600_000, asha.member);
  // the rules: never the last owner, never the founder by someone else, never fewer approvers than the quorum
  assert.equal((await remove(w, u, u)).body.error, 'last_owner');
  assert.equal((await remove(w, asha, ben)).body.error, 'role_required', 'only an owner removes someone else');
  // quorum 2 with three approvers: removing Asha leaves two, which is enough
  const r = await remove(w, u, asha);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.revoked, { sessions: 2, passkeys: 1, devices: 1, seals: 1, holds: 1, tokens: 1, guardKeys: 1, receiptsKeys: 1, invites: 0 });
  // signed out everywhere, and cannot sign in again
  assert.equal((await w.req('GET', '/v1/me', { cookie: asha.cookie })).status, 401);
  assert.equal((await w.req('GET', '/v1/holds', { bearer: cli, ...anon })).status, 401);
  const relog = await login(w, asha.auth);
  assert.equal(relog.status, 401); assert.equal(relog.body.error, 'unknown_passkey');
  // what she made stops; what she asked for is closed; her seal no longer counts
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/asha', { bearer: mine.token, ...anon })).body.error, 'token_invalid');
  assert.equal((await w.req('POST', '/v1/approvals', { bearer: gk, ...anon, body: {} })).body.error, 'guard_key_invalid');
  assert.equal((await w.req('POST', '/v1/receipts', { bearer: rk, ...anon, body: { receipt: { agent: 'a', action: 'x' } } })).body.error, 'api_key_invalid');
  assert.equal(w.env.DB.raw.prepare('SELECT status FROM holds WHERE id = ?').get(mine.hold).status, 'expired');
  assert.equal(count(w, 'SELECT COUNT(*) n FROM push_subs WHERE member_id = ?', asha.member), 0);
  assert.ok(w.env.DB.raw.prepare('SELECT used_at FROM move_links WHERE member_id = ?').get(asha.member).used_at, 'an unused move link of hers is void');
  const card = (await w.req('GET', '/v1/holds', { cookie: u.cookie })).body.holds.find((x) => x.id === other.hold);
  assert.equal(card.votes.length, 0, 'her seal is dropped');
  assert.equal((await seal(w, ben, other.hold)).body.approved, false, 'so one more seal is still needed');
  assert.equal((await seal(w, u, other.hold)).body.approved, true);
  // with two approvers left and quorum 2, neither can be removed
  assert.equal((await remove(w, u, ben)).body.error, 'not_enough_approvers');
  // anyone may leave (the rules permitting): a viewer leaves and is signed out
  const vic = await add(w, u, 'Vic', 'viewer');
  const left = await remove(w, vic, vic);
  assert.equal(left.status, 200, JSON.stringify(left.body)); assert.match(left.headers.get('set-cookie'), /Max-Age=0/);
  assert.equal((await w.req('GET', '/v1/me', { cookie: vic.cookie })).status, 401);
  const team = (await w.req('GET', '/v1/team', { cookie: u.cookie })).body;
  assert.deepEqual(team.members.map((m) => m.name), ['Gautam', 'Ben']);
  assert.ok(actions(w).filter((a) => a === 'member_removed').length === 2);
  assert.equal((await w.req('GET', '/v1/audit/verify', { cookie: u.cookie })).body.ok, true);
});

test('roles: changed by an owner with a passkey; a demoted approver\'s seals are dropped; a new approver seals only 24 hours later while two seals are required; the account always keeps an owner', async () => {
  const w = new World();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha');
  const ben = await add(w, u, 'Ben');
  const mel = await add(w, u, 'Mel', 'member');
  await setQuorum(w, u, 2, true);
  const cred = await vault(w, u);
  for (const [role, code] of [['king', 'bad_role'], ['member', 'same_role']]) assert.equal((await setRole(w, u, mel, role)).body.error, code, role);
  assert.equal((await setRole(w, asha, mel, 'approver')).body.error, 'role_required');
  // a promotion while two seals are required: the new approver's seal counts from 24 hours later
  const p = await setRole(w, u, mel, 'approver');
  assert.equal(p.status, 200, JSON.stringify(p.body)); assert.ok(p.body.votesFrom > Date.now() + DAY - 60_000);
  const h = await heldCall(w, u, cred);
  const early = await seal(w, mel, h.hold);
  assert.equal(early.status, 403); assert.equal(early.body.error, 'seal_not_yet');
  await timeShift(DAY + 60_000, async () => {
    const [u2, mel2] = [await relog(w, u), await relog(w, mel)];
    const h2 = await heldCall(w, u2, cred, '/repos/acme/later');
    assert.equal((await seal(w, mel2, h2.hold)).body.seals, 1);
    // demoting her drops that seal, and she cannot seal again
    assert.equal((await setRole(w, u2, mel, 'viewer')).status, 200);
    assert.equal((await w.req('GET', '/v1/holds', { cookie: u2.cookie })).body.holds.find((x) => x.id === h2.hold).votes.length, 0);
    assert.equal((await seal(w, mel2, h2.hold)).body.error, 'role_required');
  });
  // an approver demoted between their passkey prompt and their confirmation does not count
  const h3 = await heldCall(w, u, cred, '/repos/acme/demoted');
  const b = await w.req('POST', `/v1/holds/${h3.hold}/approve/begin`, { cookie: ben.cookie, body: {} });
  assert.equal(b.status, 200);
  // (quorum 2 needs two approvers: Gautam and Asha remain)
  assert.equal((await setRole(w, u, ben, 'member')).status, 200);
  const late = await w.req('POST', `/v1/holds/${h3.hold}/approve/finish`, { cookie: ben.cookie, body: { challengeId: b.body.challengeId, credential: await ben.auth.get(b.body.options) } });
  assert.equal(late.status, 403); assert.equal(count(w, 'SELECT COUNT(*) n FROM hold_votes WHERE hold_id = ?', h3.hold), 0);
  // never fewer approvers than the quorum, never no owner (the last one can be neither demoted nor removed)
  assert.equal((await setRole(w, u, asha, 'viewer')).body.error, 'not_enough_approvers');
  assert.equal((await setRole(w, u, u, 'approver')).body.error, 'last_owner');
  assert.equal((await remove(w, u, u)).body.error, 'last_owner');
  // owners may change one another, the founder too, and everyone is told
  assert.equal((await setRole(w, u, asha, 'owner')).status, 200);
  const inv = await invite(w, u, { role: 'viewer', label: 'from gautam' });
  assert.equal(inv.status, 200, JSON.stringify(inv.body));
  assert.equal((await setRole(w, asha, u, 'approver')).status, 200);
  const ev = (await w.req('GET', '/v1/alerts', { cookie: ben.cookie })).body.team;
  assert.ok(ev.some((e) => e.kind === 'member_role_changed' && e.name === 'Gautam' && e.from === 'owner' && e.to === 'approver'), JSON.stringify(ev));
  // an owner's open invites die when they stop being an owner, and they can no longer make one
  assert.equal((await join(w, tokenOf(inv), 'Nobody')).body.error, 'invite_invalid');
  assert.equal((await w.req('POST', '/v1/team/invites/begin', { cookie: u.cookie, body: { role: 'viewer', label: 'x' } })).body.error, 'role_required');
  const changes = w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'member_role_changed'").all().map((r) => JSON.parse(r.detail));
  assert.deepEqual(changes.map((c) => `${c.from}>${c.to}`), ['member>approver', 'approver>viewer', 'approver>member', 'approver>owner', 'owner>approver']);
});

test('the quorum: raising is immediate (waiting holds too), lowering waits 24 hours, alerts every member and can be cancelled by an approver', async () => {
  const w = new World();
  await withVapid(w);
  const u = await founder(w);
  const asha = await add(w, u, 'Asha');
  const vic = await add(w, u, 'Vic', 'viewer');
  for (const x of [u, asha, vic]) assert.equal((await device(w, x, 'phone-' + (x.name || 'owner'))).status, 200);
  const cred = await vault(w, u);
  for (const [body, code] of [[{ quorum: 3, selfApprove: true }, 'bad_quorum'], [{ quorum: 0, selfApprove: true }, 'bad_quorum'], [{ quorum: 2 }, 'bad_selfApprove'], [{ quorum: '2', selfApprove: true }, 'bad_quorum'], [{ quorum: 1, selfApprove: true }, 'same_quorum']]) {
    assert.equal((await w.req('POST', '/v1/team/quorum/begin', { cookie: u.cookie, body })).body.error, code, JSON.stringify(body));
  }
  assert.equal((await w.req('POST', '/v1/team/quorum/begin', { cookie: asha.cookie, body: { quorum: 2, selfApprove: true } })).body.error, 'role_required');
  // a hold made at quorum 1 needs 2 seals once the quorum is raised
  const early = await heldCall(w, u, cred, '/repos/acme/early');
  const up = await setQuorum(w, u, 2, true);
  assert.equal(up.status, 200, JSON.stringify(up.body)); assert.equal(up.body.quorum, 2); assert.equal(up.body.pending, null);
  assert.equal((await seal(w, u, early.hold)).body.approved, false, 'raising applies to waiting holds at once');
  // lowering: scheduled for 24 hours later, every member's devices are woken, the alert says when
  w.pushes.length = 0;
  const down = await setQuorum(w, u, 1, true);
  assert.equal(down.status, 200); assert.equal(down.body.quorum, 2); assert.equal(down.body.pending.quorum, 1);
  assert.ok(Math.abs(down.body.pending.effectiveAt - (Date.now() + DAY)) < 60_000);
  assert.deepEqual(w.pushes.sort(), ['phone-Asha', 'phone-Vic', 'phone-owner'].map((x) => 'https://fcm.googleapis.com/fcm/send/' + x).sort());
  const ev = (await w.req('GET', '/v1/alerts', { cookie: vic.cookie })).body.team.find((e) => e.kind === 'quorum_lowering');
  assert.equal(ev.to.quorum, 1); assert.equal(ev.from.quorum, 2); assert.equal(ev.effective_at, down.body.pending.effectiveAt);
  const t1 = (await w.req('GET', '/v1/team', { cookie: vic.cookie })).body;
  assert.equal(t1.quorum, 2); assert.equal(t1.pending.quorum, 1);
  // a minute before: still two seals; at 24 hours: one, read lazily (no write, no cron)
  await timeShift(DAY - 60_000, async () => {
    const u2 = await relog(w, u);
    const h = await heldCall(w, u2, cred, '/repos/acme/before');
    assert.equal(h.body.seals_needed, 2);
    assert.equal((await seal(w, u2, h.hold)).body.approved, false);
  });
  await timeShift(DAY + 60_000, async () => {
    const u2 = await relog(w, u);
    const h = await heldCall(w, u2, cred, '/repos/acme/after');
    assert.equal(h.body.seals_needed, 1);
    assert.equal((await seal(w, u2, h.hold)).body.approved, true);
    assert.equal((await w.req('GET', '/v1/team', { cookie: u2.cookie })).body.quorum, 1);
    assert.equal(w.env.DB.raw.prepare('SELECT quorum FROM accounts').get().quorum, 2, 'the stored row is unchanged: applied when read');
  });
  // a new lowering can be cancelled by an approver with a passkey, never by a viewer or a command line
  assert.equal((await setQuorum(w, u, 2, false)).status, 200, 'turning self-approval off clears the waiting change (it tightens)');
  assert.equal((await w.req('GET', '/v1/team', { cookie: u.cookie })).body.pending, null);
  const again = await setQuorum(w, u, 1, false);
  assert.equal(again.body.pending.quorum, 1);
  assert.equal((await w.req('POST', '/v1/team/quorum/cancel/begin', { cookie: vic.cookie, body: {} })).body.error, 'role_required');
  const cli = await cliSession(w, asha);
  assert.equal((await w.req('POST', '/v1/team/quorum/cancel/begin', { bearer: cli, ...anon, body: {} })).body.error, 'passkey_required');
  const c = await ceremony(w, asha, '/v1/team/quorum/cancel');
  assert.equal(c.status, 200, JSON.stringify(c.body)); assert.equal(c.body.quorum, 2);
  await timeShift(DAY + 60_000, async () => assert.equal((await w.req('GET', '/v1/team', { cookie: (await relog(w, u)).cookie })).body.quorum, 2, 'cancelled: nothing changes later'));
  assert.equal((await ceremony(w, asha, '/v1/team/quorum/cancel')).body.error, 'no_pending');
  // a quorum the team cannot meet is refused
  const w2 = new World();
  const solo = await founder(w2);
  assert.equal((await w2.req('POST', '/v1/team/quorum/begin', { cookie: solo.cookie, body: { quorum: 2, selfApprove: true } })).body.error, 'not_enough_approvers');
  const log = actions(w);
  assert.ok(log.includes('quorum_changed') && log.includes('quorum_change_cancelled'));
});

test('the quorum change is what the passkey approved, and a concurrent change is never silently overwritten', async () => {
  const w = new World();
  const u = await founder(w);
  await add(w, u, 'Asha');
  const b = await w.req('POST', '/v1/team/quorum/begin', { cookie: u.cookie, body: { quorum: 2, selfApprove: true } });
  const f = await w.req('POST', '/v1/team/quorum/finish', { cookie: u.cookie, body: { quorum: 1, selfApprove: true, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(f.body.quorum, 2, 'the body of the finish step cannot change it');
  // another owner tightens between this owner's passkey prompt and confirmation: the tightening stays in force now, and
  // what this owner asked for (quorum 1, self-approval on) only waits its 24 hours
  const b2 = await w.req('POST', '/v1/team/quorum/begin', { cookie: u.cookie, body: { quorum: 1, selfApprove: true } });
  w.env.DB.raw.prepare('UPDATE accounts SET self_approve = 0').run();
  const f2 = await w.req('POST', '/v1/team/quorum/finish', { cookie: u.cookie, body: { challengeId: b2.body.challengeId, credential: await u.auth.get(b2.body.options) } });
  assert.equal(f2.status, 200, JSON.stringify(f2.body));
  assert.deepEqual([f2.body.quorum, f2.body.selfApprove, f2.body.pending.quorum, f2.body.pending.selfApprove], [2, false, 1, true]);
  // and a change that lands between the read and the write of the same confirmation is never overwritten
  const b3 = await w.req('POST', '/v1/team/quorum/begin', { cookie: u.cookie, body: { quorum: 2, selfApprove: true } });
  const prepare = w.env.DB.prepare;
  w.env.DB.prepare = (sql) => { if (/^UPDATE accounts SET quorum = \?1/.test(sql)) w.env.DB.raw.prepare('UPDATE accounts SET quorum_pending = NULL, self_approve_pending = NULL, quorum_effective_at = NULL').run(); return prepare(sql); };
  const f3 = await w.req('POST', '/v1/team/quorum/finish', { cookie: u.cookie, body: { challengeId: b3.body.challengeId, credential: await u.auth.get(b3.body.options) } });
  w.env.DB.prepare = prepare;
  assert.equal(f3.status, 409); assert.equal(f3.body.error, 'try_again');
  // the planner: tightening parts now, loosening parts in 24 hours
  const t = 1000;
  assert.deepEqual(plan({ quorum: 1, selfApprove: true }, { quorum: 2, selfApprove: false }, t), { now: { quorum: 2, selfApprove: false }, pending: null });
  assert.deepEqual(plan({ quorum: 2, selfApprove: true }, { quorum: 1, selfApprove: false }, t), { now: { quorum: 2, selfApprove: false }, pending: { quorum: 1, selfApprove: false, effectiveAt: t + DAY } });
  assert.deepEqual(plan({ quorum: 2, selfApprove: false }, { quorum: 2, selfApprove: true }, t), { now: { quorum: 2, selfApprove: false }, pending: { quorum: 2, selfApprove: true, effectiveAt: t + DAY } });
  assert.deepEqual(effective({ quorum: 2, self_approve: 0, quorum_pending: 1, self_approve_pending: 1, quorum_effective_at: 5000 }, 4999), { quorum: 2, selfApprove: false, pending: { quorum: 1, selfApprove: true, effectiveAt: 5000 } });
  assert.deepEqual(effective({ quorum: 2, self_approve: 0, quorum_pending: 1, self_approve_pending: 1, quorum_effective_at: 5000 }, 5000), { quorum: 1, selfApprove: true, pending: null });
  assert.deepEqual(effective(null), { quorum: 1, selfApprove: true, pending: null });
});

test('no one person can get around two seals: pre-approvals and money caps are paused while two are required, and cannot be made', async () => {
  const w = new World();
  const u = await founder(w);
  const cred = await vault(w, u);
  const stripe = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'stripe', secret: 'sk_test_' + 'q'.repeat(24) } })).body.id;
  const mintPre = (credentialId, policy) => ceremony(w, u, '/v1/tokens/passkey', { credentialId, label: 'pre', policy });
  // at quorum 1, a pre-approved token passes its pre-approved call unattended (as before)
  const pre = await mintPre(cred, { unattendedIrreversible: [{ method: 'DELETE', path: '/repos/acme/*' }] });
  assert.equal(pre.status, 200, JSON.stringify(pre.body));
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/one', { bearer: pre.body.token, ...anon })).status, 200);
  await add(w, u, 'Asha');
  await setQuorum(w, u, 2, true);
  // now the same call is held like any other, and needs two seals
  const held = await w.req('DELETE', '/p/github/repos/acme/two', { bearer: pre.body.token, ...anon });
  assert.equal(held.status, 428); assert.equal(held.body.rule, 'gh.delete'); assert.equal(held.body.seals_needed, 2);
  // and nobody can make a pre-approved token or set money caps alone
  const no = await mintPre(cred, { unattendedIrreversible: [{ method: 'DELETE', path: '/repos/acme/*' }] });
  assert.equal(no.status, 409); assert.equal(no.body.error, 'quorum_blocks_preapproval');
  const caps = await mintPre(stripe, { money: { currency: 'usd', perCall: 5000, perDay: 20000 } });
  assert.equal(caps.status, 409); assert.equal(caps.body.error, 'quorum_blocks_preapproval');
  // a command line session never could, and an ordinary token is still fine
  assert.equal((await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, label: 'plain' } })).status, 200);
});

test('money caps made at quorum 1 stop letting refunds through once two seals are required', async () => {
  const w = new World();
  const u = await founder(w);
  const stripe = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'stripe', secret: 'sk_test_' + 'q'.repeat(24) } })).body.id;
  const capped = await ceremony(w, u, '/v1/tokens/passkey', { credentialId: stripe, label: 'support', policy: { money: { currency: 'usd', perCall: 5000, perDay: 20000 } } });
  assert.equal(capped.status, 200, JSON.stringify(capped.body));
  w.reply = (url, init) => (init.method === 'GET'
    ? new Response(JSON.stringify({ id: 'ch_3NabcdefGHIJKLMNOP01', object: 'charge', amount: 8000, amount_captured: 8000, amount_refunded: 0, captured: true, currency: 'usd' }), { status: 200, headers: { 'content-type': 'application/json' } })
    : new Response(JSON.stringify({ id: 're_1', object: 'refund' }), { status: 200, headers: { 'content-type': 'application/json' } }));
  const refund = (amount) => w.req('POST', '/p/stripe/v1/refunds', { bearer: capped.body.token, ...anon, raw: `charge=ch_3NabcdefGHIJKLMNOP01&amount=${amount}`, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  assert.equal((await refund(1000)).status, 200, 'under the cap: passes unattended at quorum 1');
  await add(w, u, 'Asha');
  await setQuorum(w, u, 2, true);
  const r = await refund(1001);
  assert.equal(r.status, 428, JSON.stringify(r.body)); assert.equal(r.body.seals_needed, 2);
  assert.equal(count(w, 'SELECT COALESCE(SUM(amount), 0) n FROM spend'), 1000, 'nothing was reserved for the held refund');
});

test('a coding agent\'s guard hold needs two seals too, and the guard can read "1 of 2"', async () => {
  const w = new World();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha');
  await setQuorum(w, u, 2, true);
  const gk = (await w.req('POST', '/v1/guard/keys', { cookie: u.cookie, body: { label: 'laptop' } })).body.key;
  const ask = await w.req('POST', '/v1/approvals', { bearer: gk, ...anon, body: { kind: 'shell', agent: 'codex', rule: 'sh.git-force', why: 'Rewrites history.', summary: 'git push --force', detail: 'git push --force origin main' } });
  assert.equal(ask.status, 202, JSON.stringify(ask.body));
  const st = (await w.req('GET', `/v1/approvals/${ask.body.id}`, { bearer: gk, ...anon })).body;
  assert.deepEqual([st.status, st.seals, st.needs], ['pending', 0, 2]);
  assert.equal((await seal(w, u, ask.body.id)).body.approved, false);
  const st1 = (await w.req('GET', `/v1/approvals/${ask.body.id}`, { bearer: gk, ...anon })).body;
  assert.deepEqual([st1.status, st1.seals, st1.needs], ['pending', 1, 2]);
  assert.equal((await w.req('POST', `/v1/approvals/${ask.body.id}/use`, { bearer: gk, ...anon, body: { hash: ask.body.hash } })).body.error, 'not_approved');
  assert.equal((await seal(w, asha, ask.body.id)).body.approved, true);
  assert.equal((await w.req('POST', `/v1/approvals/${ask.body.id}/use`, { bearer: gk, ...anon, body: { hash: ask.body.hash } })).status, 200);
  assert.equal(w.env.DB.raw.prepare('SELECT needs FROM holds WHERE id = ?').get(ask.body.id).needs, 2);
});

test('Freeze: nothing is sealed while frozen, a freeze drops seals already cast, and only an approver with a passkey unfreezes', async () => {
  const w = new World();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha');
  const vic = await add(w, u, 'Vic', 'viewer');
  await setQuorum(w, u, 2, true);
  const cred = await vault(w, u);
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, label: 'agent' } });
  const h = await w.req('DELETE', '/p/github/repos/acme/app', { bearer: t.body.token, ...anon });
  assert.equal((await seal(w, u, h.body.hold_id)).body.seals, 1);
  // Asha begins sealing; a viewer freezes (stopping is always safe); her confirmation is refused, and the seal already
  // cast is dropped
  const b = await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/begin`, { cookie: asha.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/me/freeze', { cookie: vic.cookie, body: {} })).status, 200);
  const f = await w.req('POST', `/v1/holds/${h.body.hold_id}/approve/finish`, { cookie: asha.cookie, body: { challengeId: b.body.challengeId, credential: await asha.auth.get(b.body.options) } });
  assert.equal(f.status, 423); assert.equal(f.body.error, 'account_frozen');
  assert.equal(count(w, 'SELECT COUNT(*) n FROM hold_votes'), 0);
  assert.equal(JSON.parse(w.env.DB.raw.prepare("SELECT detail FROM audit WHERE action = 'freeze'").get().detail).dropped_seals, 1);
  assert.equal((await seal(w, u, h.body.hold_id)).status, 423);
  // a viewer or a member cannot unfreeze; an approver can, with a passkey
  assert.equal((await w.req('POST', '/v1/me/unfreeze/begin', { cookie: vic.cookie, body: {} })).body.error, 'role_required');
  assert.equal((await ceremony(w, asha, '/v1/me/unfreeze')).status, 200);
  // sealing starts again from nothing
  assert.equal((await seal(w, u, h.body.hold_id)).body.seals, 1);
  assert.equal((await seal(w, asha, h.body.hold_id)).body.approved, true);
});

test('receipts: the public log gets the quorum and the number of seals, never who, which passkey, a name, a label or a member id; a partial seal is private', async () => {
  const w = new World();
  const u = await founder(w, 'Gautam Founder');
  const asha = await add(w, u, 'Asha Secretname', 'approver');
  await setQuorum(w, u, 2, true);
  const cred = await vault(w, u);
  const h = await heldCall(w, u, cred, '/repos/acme-secret/app');
  assert.equal((await seal(w, u, h.hold)).body.approved, false);
  let entries = (await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries;
  assert.deepEqual(entries.map((e) => e.entry.receipt.decision), ['held'], 'a partial seal is not a receipt');
  assert.equal((await seal(w, asha, h.hold)).body.approved, true);
  entries = (await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries;
  const ap = entries.map((e) => e.entry.receipt).find((r) => r.decision === 'approved');
  assert.deepEqual(ap.meta, { map: ap.meta.map, rule: 'gh.delete', passkey: true, quorum: 2, votes: 2 });
  const pub = JSON.stringify(entries);
  const tables = w.sql.raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((t) => t.name);
  const stored = JSON.stringify(tables.map((t) => w.sql.raw.prepare(`SELECT * FROM ${t}`).all()), (k, v) => (v instanceof Uint8Array ? '' : v));
  const fp = (await sha256hex(b64u(asha.auth.credId))).slice(0, 16);
  for (const s of ['Secretname', 'Asha', 'Gautam', 'Founder', '(label)', asha.member, fp, 'acme-secret']) {
    assert.ok(!pub.includes(s), 'public log has ' + s);
    assert.ok(!stored.includes(s), 'log storage has ' + s);
  }
});

test('roles on every route: a viewer reads and denies; a member makes keys but cannot seal; only owners delete the account, delete vault keys or switch receipts; passkeys and command lines are each person\'s own', async () => {
  const w = new World();
  const u = await founder(w);
  const vic = await add(w, u, 'Vic', 'viewer');
  const mel = await add(w, u, 'Mel', 'member');
  const asha = await add(w, u, 'Asha', 'approver');
  const cred = await vault(w, u);
  // a viewer: reads, denies, freezes; nothing else
  for (const p of ['/v1/holds', '/v1/tokens', '/v1/credentials', '/v1/audit', '/v1/team', '/v1/guard/keys', '/v1/me']) assert.equal((await w.req('GET', p, { cookie: vic.cookie })).status, 200, p);
  for (const [m, p, body] of [['POST', '/v1/tokens', { credentialId: cred }], ['POST', '/v1/credentials', { provider: 'github', secret: GH }], ['POST', '/v1/guard/keys', { label: 'x' }], ['POST', '/v1/keys', { label: 'x' }], ['POST', '/v1/agent-keys/begin', { publicKey: 'x' }]]) {
    assert.equal((await w.req(m, p, { cookie: vic.cookie, body })).body.error, 'role_required', p);
  }
  // a member: makes tokens, guard keys and receipts keys; cannot seal, pre-approve, delete vault keys, switch receipts or
  // delete the account
  const melTok = await w.req('POST', '/v1/tokens', { cookie: mel.cookie, body: { credentialId: cred, label: 'mel agent' } });
  assert.equal(melTok.status, 200);
  assert.equal((await w.req('POST', '/v1/guard/keys', { cookie: mel.cookie, body: { label: 'mel' } })).status, 200);
  const h = await w.req('DELETE', '/p/github/repos/acme/app', { bearer: melTok.body.token, ...anon });
  assert.equal((await seal(w, mel, h.body.hold_id)).body.error, 'role_required');
  for (const [m, p] of [['POST', '/v1/tokens/passkey/begin'], ['DELETE', `/v1/credentials/${cred}`], ['POST', '/v1/me/receipts/on'], ['POST', '/v1/me/receipts/off/begin'], ['POST', '/v1/me/delete/begin'], ['POST', '/v1/me/unfreeze/begin']]) {
    assert.equal((await w.req(m, p, { cookie: mel.cookie, body: m === 'POST' ? {} : undefined })).body.error, 'role_required', p);
  }
  // an approver seals and may pre-approve at quorum 1, but owner-only actions stay closed
  assert.equal((await seal(w, asha, h.body.hold_id)).body.approved, true);
  for (const [m, p] of [['DELETE', `/v1/credentials/${cred}`], ['POST', '/v1/me/delete/begin'], ['POST', '/v1/me/receipts/on']]) assert.equal((await w.req(m, p, { cookie: asha.cookie, body: m === 'POST' ? {} : undefined })).body.error, 'role_required', p);
  assert.equal((await w.req('DELETE', `/v1/credentials/${cred}`, { cookie: u.cookie })).status, 200);
  // the deny of a viewer works from a command line too: their command line carries their role
  const vicCli = await cliSession(w, vic);
  assert.equal((await w.req('POST', '/v1/tokens', { bearer: vicCli, ...anon, body: { credentialId: cred } })).body.error, 'role_required');
  const cred2 = await vault(w, u);
  const h2 = await heldCall(w, u, cred2, '/repos/acme/b');
  assert.equal((await w.req('POST', `/v1/holds/${h2.hold}/deny`, { bearer: vicCli, ...anon, body: {} })).status, 200);
  // passkeys: each person sees and removes only their own
  const own = (await w.req('GET', '/v1/passkeys', { cookie: mel.cookie })).body.passkeys;
  assert.equal(own.length, 1);
  const ownersPk = (await w.req('GET', '/v1/passkeys', { cookie: u.cookie })).body.passkeys[0].id;
  assert.ok(!own.some((p) => p.id === ownersPk));
  assert.equal((await w.req('POST', `/v1/passkeys/${ownersPk}/remove/begin`, { cookie: mel.cookie, body: {} })).status, 404);
  // command line sign-ins: yours, or anyone's for an owner
  const sid = (await w.req('GET', '/v1/sessions', { cookie: u.cookie })).body.sessions.find((s) => s.member === vic.member).id;
  assert.equal((await w.req('DELETE', `/v1/sessions/${sid}`, { cookie: mel.cookie })).body.error, 'role_required');
  assert.equal((await w.req('DELETE', `/v1/sessions/${sid}`, { cookie: u.cookie })).status, 200);
  assert.equal((await w.req('GET', '/v1/holds', { bearer: vicCli, ...anon })).status, 401);
  // a passkey ceremony needs the signed-in person's own passkey everywhere (here: the owner's receipts switch)
  const rb = await w.req('POST', '/v1/me/receipts/off/begin', { cookie: u.cookie, body: {} });
  const rf = await w.req('POST', '/v1/me/receipts/off/finish', { cookie: u.cookie, body: { challengeId: rb.body.challengeId, credential: await asha.auth.get(rb.body.options) } });
  assert.equal(rf.status, 401); assert.equal(rf.body.error, 'unknown_passkey');
});

test('CSRF and hosts: team changes need the host\'s own Origin and the x-leash header, on both hosts; invites are opened and joined on the product\'s host only', async () => {
  const NEW = 'https://counterseal.test', OLD = 'https://leash.test';
  const w = new World();
  Object.assign(w.env, { ORIGIN: NEW, RP_ID: 'counterseal.test', LEGACY_ORIGIN: OLD, LEGACY_RP_ID: 'leash.test' });
  const auth = new Authenticator(NEW, 'counterseal.test');
  const rb = await w.req('POST', NEW + '/v1/auth/register/begin', { origin: NEW, body: { name: 'Owner' } });
  const rf = await w.req('POST', NEW + '/v1/auth/register/finish', { origin: NEW, body: { challengeId: rb.body.challengeId, credential: await auth.create(rb.body.options) } });
  const u = { cookie: rf.headers.get('set-cookie').split(';')[0], auth };
  const routes = [['/v1/team/invites/begin', { role: 'viewer', label: 'x' }], ['/v1/team/quorum/begin', { quorum: 2, selfApprove: true }], ['/v1/team/quorum/cancel/begin', {}], ['/v1/holds/' + 'a'.repeat(24) + '/approve/begin', {}], ['/v1/me/freeze', {}]];
  for (const [p, body] of routes) {
    for (const [url, o] of [[NEW + p, { origin: OLD }], [OLD + p, { origin: NEW }], [NEW + p, { origin: 'https://evil.test' }], [NEW + p, { origin: NEW, xleash: false }], [NEW + p, { origin: null }]]) {
      const r = await w.req('POST', url, { cookie: u.cookie, body, ...o });
      assert.equal(r.status, 403, `${url} ${JSON.stringify(o)}`); assert.equal(r.body.error, 'csrf', `${url} ${JSON.stringify(o)}`);
    }
  }
  const b = await w.req('POST', NEW + '/v1/team/invites/begin', { origin: NEW, cookie: u.cookie, body: { role: 'approver', label: 'Ben' } });
  const f = await w.req('POST', NEW + '/v1/team/invites/finish', { origin: NEW, cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await auth.get(b.body.options) } });
  assert.equal(f.status, 200, JSON.stringify(f.body));
  assert.ok(f.body.url.startsWith(NEW + '/app#invite='), 'the link is always on the product\'s host');
  const token = tokenOf(f);
  // the public join routes check the Origin too, and refuse the old host
  assert.equal((await w.req('POST', NEW + '/v1/invites/lookup', { origin: OLD, body: { token } })).body.error, 'csrf');
  assert.equal((await w.req('POST', OLD + '/v1/invites/lookup', { origin: OLD, body: { token } })).body.error, 'invite_on_new_host');
  assert.equal((await w.req('POST', OLD + '/v1/invites/begin', { origin: OLD, body: { token, name: 'Ben' } })).body.error, 'invite_on_new_host');
  const m = await join(w, token, 'Ben', { host: NEW, origin: NEW, rpId: 'counterseal.test' });
  assert.equal(m.status, 200, JSON.stringify(m.body)); assert.equal(m.role, 'approver');
  assert.equal(w.env.DB.raw.prepare('SELECT rp_id FROM passkeys WHERE member_id = ?').get(m.member).rp_id, 'counterseal.test');
});

test('budgets: sealing, joining, removing and reading the team stay well under 50 D1 queries; the proxy costs no extra query on a team', async () => {
  const w = new World();
  await withVapid(w);
  const u = await founder(w);
  w.env.DB.raw.prepare('UPDATE accounts SET receipts = 1').run();
  for (let i = 0; i < 4; i++) await device(w, u, 'owner-' + i);
  const asha = await add(w, u, 'Asha');
  for (let i = 0; i < 4; i++) await device(w, asha, 'asha-' + i);
  await setQuorum(w, u, 2, true);
  const cred = await vault(w, u);
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, label: 'agent' } })).body.token;
  w.env.DB.cap = 50;
  const get = await w.req('GET', '/p/github/repos/acme/app', { bearer: tok, ...anon });
  assert.equal(get.status, 200);
  const held = await w.req('DELETE', '/p/github/repos/acme/app', { bearer: tok, ...anon });
  assert.equal(held.status, 428);
  assert.ok(held.queries <= 35, `${held.queries} queries to hold`);
  const id = held.body.hold_id;
  const b1 = await w.req('POST', `/v1/holds/${id}/approve/begin`, { cookie: u.cookie, body: {} });
  const s1 = await w.req('POST', `/v1/holds/${id}/approve/finish`, { cookie: u.cookie, body: { challengeId: b1.body.challengeId, credential: await u.auth.get(b1.body.options) } });
  assert.equal(s1.status, 200, JSON.stringify(s1.body)); assert.ok(s1.queries <= 30, `${s1.queries} queries for a first seal (and the nudge to 4 devices)`);
  const b2 = await w.req('POST', `/v1/holds/${id}/approve/begin`, { cookie: asha.cookie, body: {} });
  const s2 = await w.req('POST', `/v1/holds/${id}/approve/finish`, { cookie: asha.cookie, body: { challengeId: b2.body.challengeId, credential: await asha.auth.get(b2.body.options) } });
  assert.equal(s2.body.approved, true); assert.ok(s2.queries <= 25, `${s2.queries} queries for the final seal (sealed)`);
  const team = await w.req('GET', '/v1/team', { cookie: u.cookie });
  assert.ok(team.queries <= 8, `${team.queries} queries to read the team`);
  const r = await invite(w, u, { role: 'viewer', label: 'v' });
  assert.ok(r.queries <= 20, `${r.queries} queries to make an invite`);
  const auth = new Authenticator(ORIGIN, RP_ID);
  const jb = await w.req('POST', '/v1/invites/begin', { body: { token: tokenOf(r), name: 'Vic' } });
  const jf = await w.req('POST', '/v1/invites/finish', { body: { token: tokenOf(r), challengeId: jb.body.challengeId, credential: await auth.create(jb.body.options) } });
  assert.equal(jf.status, 200); assert.ok(jf.queries <= 35, `${jf.queries} queries to join (and alert 8 devices)`);
  const vic = { member: (await w.req('GET', '/v1/me', { cookie: jf.headers.get('set-cookie').split(';')[0] })).body.member.id };
  const rm = await remove(w, u, vic);
  assert.equal(rm.status, 200); assert.ok(rm.queries <= 30, `${rm.queries} queries to remove someone`);
  w.env.DB.cap = 0;
  // the proxy's query count is the same for a team as for one person
  const w2 = new World();
  const solo = await founder(w2);
  const c2 = await vault(w2, solo);
  const t2 = (await w2.req('POST', '/v1/tokens', { cookie: solo.cookie, body: { credentialId: c2 } })).body.token;
  await w2.req('GET', '/p/github/repos/acme/app', { bearer: t2, ...anon }); // first call writes last_seen
  const soloGet = await w2.req('GET', '/p/github/repos/acme/app', { bearer: t2, ...anon });
  const teamGet = await w.req('GET', '/p/github/repos/acme/app', { bearer: tok, ...anon });
  assert.equal(teamGet.queries, soloGet.queries);
});

test('the app: a Team view, seals on hold cards, the invite page and team alerts, without innerHTML; the invite token leaves the address bar at once', () => {
  const read = (p) => readFileSync(new URL('../../site/public/' + p, import.meta.url), 'utf8');
  const app = read('app/app.js'), html = read('app/index.html'), sw = read('sw.js');
  for (const s of ['/v1/team', '/v1/team/quorum/begin', '/v1/team/quorum/cancel/begin', '/v1/team/invites/begin', '/v1/invites/lookup', '/v1/invites/finish', '/role/begin', '/remove/begin', 'excludeCredentials', 'Add your seal with passkey']) assert.ok(app.includes(s), s);
  assert.match(app, /#invite=\(\[A-Za-z0-9_-\]\{43\}\)\$\/\); if \(iv\) \{ inviteToken = iv\[1\]; history\.replaceState\(null, '', '\/app'\)/, 'read once, then removed from the address bar');
  assert.ok(!/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(/.test(app));
  for (const id of ['inviteIn', 'members', 'invitePanel', 'qForm', 'qBanner', 'sealCount']) assert.match(html, new RegExp(`id="${id}"`), id);
  for (const k of ['member_joined', 'member_role_changed', 'member_removed', 'quorum_lowering', 'seals']) assert.ok(sw.includes(k), k);
});

test('deleting the account removes the whole team: members, invites and seals', async () => {
  const w = new World();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha');
  await invite(w, u, { role: 'viewer', label: 'open' });
  await setQuorum(w, u, 2, true);
  const cred = await vault(w, u);
  const h = await heldCall(w, u, cred);
  await seal(w, asha, h.hold);
  assert.equal((await w.req('POST', '/v1/me/delete/begin', { cookie: asha.cookie, body: {} })).body.error, 'role_required');
  const d = await ceremony(w, u, '/v1/me/delete', { confirm: 'delete' });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  for (const t of ['members', 'invites', 'hold_votes', 'passkeys', 'sessions', 'holds']) assert.equal(count(w, `SELECT COUNT(*) n FROM ${t}`), 0, t);
  assert.equal((await w.req('GET', '/v1/me', { cookie: asha.cookie })).status, 401);
});
