// Shared by the break-glass and alert-channel tests (two-person seal, part 2b): a team through real invites, ceremonies,
// held calls from tokens and guard keys, and the window's own routes.
import assert from 'node:assert/strict';
import { Authenticator, ORIGIN, RP_ID } from './helpers.js';

export const anon = { origin: null, xleash: false };
export const GH = 'ghp_' + 'T'.repeat(36);
export const db = (w) => w.env.DB.raw;
export const HOUR = 3600_000, DAY = 24 * HOUR;

export async function timeShift(ms, fn) { const real = Date.now; const t0 = real(); Date.now = () => t0 + ms + (real() - t0); try { return await fn(); } finally { Date.now = real; } }
export async function withVapid(w) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  w.env.VAPID_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
  w.pushes = [];
  w.env.__pushFetch = async (url) => { w.pushes.push(url); return new Response(null, { status: 201 }); };
}
export const device = (w, u, name) => w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/' + name } });

/** the account's founder: their member id is the account id */
export async function founder(w, name = 'Gautam') {
  const u = await w.user(name);
  u.id = await w.accountId(u.cookie);
  u.member = u.id;
  u.name = name;
  return u;
}
/** a person on the team with a role, through a real invite. `seasoned`: their seal counts at once (the 24 hour rule is tested in team.test.js) */
export async function add(w, owner, name, role = 'approver', { seasoned = true } = {}) {
  const b = await w.req('POST', '/v1/team/invites/begin', { cookie: owner.cookie, body: { role, label: name + ' (label)' } });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  const f = await w.req('POST', '/v1/team/invites/finish', { cookie: owner.cookie, body: { challengeId: b.body.challengeId, credential: await owner.auth.get(b.body.options) } });
  assert.equal(f.status, 200, JSON.stringify(f.body));
  const token = f.body.url.split('#invite=')[1];
  const auth = new Authenticator(ORIGIN, RP_ID);
  const jb = await w.req('POST', '/v1/invites/begin', { body: { token, name } });
  const jf = await w.req('POST', '/v1/invites/finish', { body: { token, challengeId: jb.body.challengeId, credential: await auth.create(jb.body.options) } });
  assert.equal(jf.status, 200, JSON.stringify(jf.body));
  const cookie = jf.headers.get('set-cookie').split(';')[0];
  const me = (await w.req('GET', '/v1/me', { cookie })).body;
  if (seasoned) db(w).prepare('UPDATE members SET votes_from = 0 WHERE id = ?').run(me.member.id);
  return { cookie, auth, member: me.member.id, role: me.member.role, name };
}
export async function ceremony(w, u, path, body = {}) {
  const b = await w.req('POST', path + '/begin', { cookie: u.cookie, body });
  if (b.status !== 200) return b;
  return w.req('POST', path + '/finish', { cookie: u.cookie, body: { ...body, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
export async function setQuorum(w, u, quorum, selfApprove) { const r = await ceremony(w, u, '/v1/team/quorum', { quorum, selfApprove }); assert.equal(r.status, 200, JSON.stringify(r.body)); return r; }
export async function seal(w, u, id) {
  const b = await w.req('POST', `/v1/holds/${id}/approve/begin`, { cookie: u.cookie, body: {} });
  if (b.status !== 200) return b;
  return w.req('POST', `/v1/holds/${id}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
export async function vault(w, u) {
  const r = await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: GH } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body.id;
}
/** a token made by u (labelled), not yet used */
export async function makeToken(w, u, cred, label) {
  const t = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, label } });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  return t.body;
}
export const del = (w, token, path = '/repos/acme/app') => w.req('DELETE', '/p/github' + path, { bearer: token, ...anon });
/** a token made by u, and its DELETE held */
export async function heldCall(w, u, cred, path = '/repos/acme/app', label = 'agent of ' + (u.name || 'founder')) {
  const t = await makeToken(w, u, cred, label);
  const r = await del(w, t.token, path);
  assert.equal(r.status, 428, JSON.stringify(r.body));
  return { token: t.token, tokenId: t.id, hold: r.body.hold_id, body: r.body };
}
export const openWindow = (w, u, body = {}, over = {}) => ceremony(w, u, '/v1/team/breakglass', { minutes: 30, reason: 'prod is down, second approver asleep', ...body, ...over });

// guard keys
export const CMD = 'terraform destroy -auto-approve';
export const ask = (over = {}) => ({ kind: 'shell', agent: 'claude-code', rule: 'sh.terraform-destroy', why: 'Destroys every resource in the state. This cannot be undone.', summary: CMD, detail: CMD, context: { cwd: 'infra', session: 'sess-1' }, map: '2026-10-10.1', ...over });
export async function guardKey(w, u, label = 'laptop guard') {
  const r = await w.req('POST', '/v1/guard/keys', { cookie: u.cookie, body: { label } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body;
}
export const create = (w, key, body = ask()) => w.req('POST', '/v1/approvals', { bearer: key, ...anon, body });
export const use = (w, key, id, hash) => w.req('POST', `/v1/approvals/${id}/use`, { bearer: key, ...anon, body: { hash } });
export const receipts = async (w) => (await w.req('GET', '/v1/log/entries?start=0&count=200', anon)).body.entries.map((e) => e.entry.receipt);
