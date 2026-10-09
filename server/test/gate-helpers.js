// Shared by the Deploy Gate tests: a world with a stand-in for GitHub's issuer, gates made with a passkey, runs that ask
// with a signed token, polls, approvals and a few conveniences.
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { makeGithub } from './gh.js';
import { audienceFor } from '../src/gates.js';
import { _resetOidc } from '../src/oidc.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
export { audienceFor };

export const anon = { origin: null, xleash: false };

export async function timeShift(ms, fn) { const real = Date.now; const t0 = real(); Date.now = () => t0 + ms + (real() - t0); try { return await fn(); } finally { Date.now = real; } }
export async function withVapid(w) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  w.env.VAPID_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
  w.pushes = [];
  w.env.__pushFetch = async (url) => { w.pushes.push(url); return new Response(null, { status: 201 }); };
}
/** a world with a stand-in for GitHub's issuer wired in */
export async function world() {
  // one issuer per world: this isolate's cache of GitHub's key set belongs to the previous one
  _resetOidc(); _resetMemoryBuckets();
  const w = new World(), gh = await makeGithub();
  w.env.__oidcFetch = gh.fetch;
  return { w, gh };
}
/** a gate made with a passkey ceremony, as the app does it */
export async function makeGate(w, u, over = {}) {
  const b = await w.req('POST', '/v1/gates/passkey/begin', { cookie: u.cookie, body: {} });
  assert.equal(b.status, 200, JSON.stringify(b.body));
  return w.req('POST', '/v1/gates/passkey/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options), label: 'prod deploy', repository: 'acme/app', workflows: ['.github/workflows/deploy.yml'], refs: ['refs/heads/main'], ...over } });
}
export const gateId = async (w, u, over) => { const r = await makeGate(w, u, over); assert.equal(r.status, 200, JSON.stringify(r.body)); return r.body.id; };
/** a run asks: a token signed by the stand-in GitHub for this gate's audience, with the claims changed by `over` */
export async function ask(w, gh, gate, over = {}, o = {}) {
  const jwt = o.token ?? await gh.token(gh.claims({ aud: audienceFor(w.env, gate), ...over }), o.sign);
  return w.req('POST', '/v1/gate/request', { bearer: jwt, ...anon, body: o.body ?? { gate, ...(o.summary ? { summary: o.summary } : {}), ...(o.minutes ? { timeout_minutes: o.minutes } : {}) } });
}
export const poll = (w, secret, id, wait) => w.req('GET', `/v1/gate/status/${id}${wait === undefined ? '' : '?wait=' + wait}`, { bearer: secret, ...anon });
export async function approve(w, u, id) {
  const b = await w.req('POST', `/v1/holds/${id}/approve/begin`, { cookie: u.cookie, body: {} });
  if (b.status !== 200) return b;
  return w.req('POST', `/v1/holds/${id}/approve/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
export const holds = async (w, u, status = '') => (await w.req('GET', '/v1/holds' + (status ? '?status=' + status : ''), { cookie: u.cookie })).body.holds;
export async function cliSession(w, u) {
  const d = await w.req('POST', '/v1/device/start', { body: {}, ...anon, ip: '198.51.100.' + Math.floor(Math.random() * 200) });
  const ab = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.body.user_code } });
  await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.body.user_code, challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } });
  return (await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, ...anon })).body.access_token;
}
export const db = (w) => w.env.DB.raw;
