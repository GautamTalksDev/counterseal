// The dashboard's side of the first run, the demo held call and the privacy center: the page's own code (app.js) on the
// small fake DOM, against answers from the real Worker.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { _resetMarks } from '../src/trust.js';
import { page } from './app-fake.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); _resetMarks(); });

/** routes that forward to a real World as the signed-in user u */
function live(w, u, over = {}) {
  const fwd = (method, path) => async (body) => { const r = await w.req(method, path, { cookie: u.cookie, ...(body !== undefined ? { body } : {}) }); return [r.status, r.body]; };
  const r = {};
  for (const p of ['/v1/me', '/v1/credentials', '/v1/tokens', '/v1/holds', '/v1/audit', '/v1/agent-keys', '/v1/team', '/v1/guard/keys', '/v1/push/key', '/v1/gates']) r['GET ' + p] = fwd('GET', p);
  r['GET /v1/meta'] = async () => [200, { providers: [], app: 'https://leash.test', legacyApp: null }];
  r['POST /v1/demo/call'] = fwd('POST', '/v1/demo/call');
  return { ...r, ...over };
}
/** wait for the page's own async work (a real Worker answers behind it; the full suite can be slow) */
const until = async (p, ok) => { for (let i = 0; i < 300 && !ok(); i++) await new Promise((r) => setTimeout(r, 10)); await p.settle(); };
const find = (root, text) => root.all((c) => c.tag === 'button' && c.textContent === text)[0];

test('first run: the checklist counts what the account has done; Try a held call makes a demo hold; approving it lets the demo agent retry once', async () => {
  const w = new World();
  const u = await w.user('Ada');
  const auth = u.auth;
  const routes = live(w, u);
  let challenge = null;
  const p0 = await page(routes);
  await until(p0, () => p0.byId('frCount').textContent);
  assert.equal(p0.byId('firstRun').hidden, false);
  assert.equal(p0.byId('frCount').textContent, '1 of 6 done');
  p0.byId('demoBtn').click();
  for (let i = 0; i < 50 && !p0.byId('holds').children.length; i++) await new Promise((r) => setTimeout(r, 20));
  await p0.settle();
  assert.ok(p0.calls.some((c) => c.method === 'POST' && c.path === '/v1/demo/call'));
  const card = p0.byId('holds').children[0];
  assert.ok(card && card.className.includes('hold-demo'), 'the demo card is on the list');
  assert.ok(card.textContent.includes('The demo agent wants to DELETE /repos/you/practice-repo'));
  assert.ok(card.textContent.includes('Demo'));
  // approve: begin and finish go to the real server; the fake browser's passkey answer is replaced by a real one
  const id = card.id.slice(5);
  const p = await page({
    ...live(w, u),
    [`POST /v1/holds/${id}/approve/begin`]: async () => { const r = await w.req('POST', `/v1/holds/${id}/approve/begin`, { cookie: u.cookie, body: {} }); challenge = r.body; return [r.status, r.body]; },
    [`POST /v1/holds/${id}/approve/finish`]: async (body) => { const r = await w.req('POST', `/v1/holds/${id}/approve/finish`, { cookie: u.cookie, body: { challengeId: body.challengeId, credential: await auth.get(challenge.options) } }); return [r.status, r.body]; },
  });
  await until(p, () => p.byId('holds').children.length);
  find(p.byId('holds'), 'Approve with passkey').click();
  for (let i = 0; i < 20 && !p.calls.some((c) => c.body && c.body.hold === id); i++) await new Promise((r) => setTimeout(r, 20));
  await p.settle();
  const retry = p.calls.find((c) => c.method === 'POST' && c.path === '/v1/demo/call' && c.body && c.body.hold === id);
  assert.ok(retry, 'the app played the agent and retried once: ' + p.toast() + ' ' + JSON.stringify(p.calls.filter((c) => c.method === 'POST')));
  assert.match(p.byId('demoResult').textContent, /demo provider answered 204/);
  assert.equal(p.byId('frCount').textContent, '2 of 6 done');
});

test('signed out after an hour without activity: the app says so and offers the passkey sign-in again', async () => {
  const w = new World();
  const u = await w.user('Ada');
  let idle = false;
  const routes = live(w, u);
  const me = routes['GET /v1/me'];
  routes['GET /v1/me'] = async (b) => (idle ? [401, { error: 'signed_out', reason: 'idle', message: 'Signed out after an hour without activity.' }] : me(b));
  const p = await page(routes);
  await until(p, () => p.calls.some((c) => c.path === '/v1/holds'));
  assert.equal(p.byId('signedIn').hidden, false);
  idle = true;
  // the next call that comes back 401 while signed in
  routes['POST /v1/demo/call'] = async () => [401, { error: 'signed_out', reason: 'idle' }];
  p.byId('demoBtn').click(); await p.settle();
  assert.equal(p.byId('signedIn').hidden, true);
  assert.equal(p.byId('signedOut').hidden, false);
  assert.match(p.byId('authErr').textContent, /after an hour without activity/);
});

test('the privacy view shows the retention rules from the server and saves a new choice', async () => {
  const w = new World();
  const u = await w.user('Ada');
  const routes = live(w, u, { 'POST /v1/me/retention': async (body) => { const r = await w.req('POST', '/v1/me/retention', { cookie: u.cookie, body }); return [r.status, r.body]; } });
  const p = await page(routes);
  await until(p, () => p.calls.some((c) => c.path === '/v1/holds'));
  p.byId('retDays').value = '30';
  p.byId('retSave').click();
  await until(p, () => p.toast());
  assert.match(p.toast(), /deleted 30 days after they close/);
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.retention.holdDays, 30);
});
