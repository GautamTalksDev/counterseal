// Brakes' Freeze reaches deploy gates: while an account is frozen nothing new is asked (423 account_frozen, before anything
// is written and before the run's token is spent), a wait ends at once, no approval is spent and no key is handed out, an
// approval nobody used yet is void, and only a passkey ceremony in the app starts it again. Same answer as every other
// frozen path (src/brakes.js, test/brakes-freeze.test.js).
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { isFrozen } from '../src/brakes.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetOidc } from '../src/oidc.js';
import { anon, withVapid, world, gateId, ask, poll, approve, cliSession, db } from './gate-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetOidc(); });

const freeze = (w, who) => w.req('POST', '/v1/me/freeze', who.bearer ? { bearer: who.bearer, ...anon, body: {} } : { cookie: who.cookie, body: {} });
async function unfreeze(w, u) {
  const b = await w.req('POST', '/v1/me/unfreeze/begin', { cookie: u.cookie, body: {} });
  if (b.status !== 200) return b;
  return w.req('POST', '/v1/me/unfreeze/finish', { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
const cancel = (w, secret, id) => w.req('POST', `/v1/gate/cancel/${id}`, { bearer: secret, ...anon, body: {} });

test('a frozen account answers 423 to a run that asks, writes nothing, keeps the token unspent, and alerts no one', async () => {
  const { w, gh } = await world();
  await withVapid(w);
  const u = await w.user();
  await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/phone' } });
  const acct = await w.accountId(u.cookie);
  const cli = await cliSession(w, u);
  const g = await gateId(w, u);
  const pending = await ask(w, gh, g, { run_id: '1' });
  const approved = await ask(w, gh, g, { run_id: '2' });
  assert.equal((await approve(w, u, approved.body.id)).status, 200);
  const entriesBefore = (await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries.length;
  w.pushes.length = 0;

  const f = await freeze(w, { bearer: cli });
  assert.equal(f.status, 200, JSON.stringify(f.body));
  assert.equal(f.body.voided_approvals, 1, 'the approval nobody used yet is void');
  assert.equal(await isFrozen(w.env, acct), true);
  w.pushes.length = 0;
  const holdsBefore = db(w).prepare('SELECT COUNT(*) n FROM holds').get().n, pollsBefore = db(w).prepare('SELECT COUNT(*) n FROM gate_polls').get().n;
  const noncesBefore = db(w).prepare("SELECT COUNT(*) n FROM nonces WHERE k LIKE 'oidc:%'").get().n;

  // a run asks (the right repository): 423, nothing written, its token not spent, nobody alerted
  const jwt = await gh.token(gh.claims({ aud: `https://leash.test/gate/${g}`, run_id: '3' }));
  const r = await ask(w, gh, g, {}, { token: jwt });
  assert.equal(r.status, 423, JSON.stringify(r.body)); assert.equal(r.body.error, 'account_frozen'); assert.match(r.body.message, /frozen/);
  assert.equal(r.writes, 0, 'a frozen account costs no writes'); assert.ok(r.queries <= 3, `${r.queries} queries`);
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM holds').get().n, holdsBefore); assert.equal(db(w).prepare('SELECT COUNT(*) n FROM gate_polls').get().n, pollsBefore);
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM nonces WHERE k LIKE 'oidc:%'").get().n, noncesBefore, 'the token was not spent');
  assert.equal(w.pushes.length, 0);
  // the same token works after the freeze ends (it was never used), within its five minutes
  // a run from another repository still learns only that it is not this gate's
  const stranger = await ask(w, gh, g, { repository: 'evil/app', repository_id: '666', repository_owner: 'evil', repository_owner_id: '6', workflow_ref: 'evil/app/.github/workflows/deploy.yml@refs/heads/main', job_workflow_ref: 'evil/app/.github/workflows/deploy.yml@refs/heads/main' });
  assert.equal(stranger.status, 403); assert.equal(stranger.body.reason, 'repository');

  // waiting: any poll answers 423 with the reason, the pending hold and the voided approval alike, and writes nothing
  for (const [id, secret] of [[pending.body.id, pending.body.poll], [approved.body.id, approved.body.poll]]) {
    const p = await poll(w, secret, id);
    assert.equal(p.status, 423, JSON.stringify(p.body)); assert.equal(p.body.error, 'account_frozen'); assert.equal(p.writes, 0);
    const wait = await poll(w, secret, id, 20);
    assert.equal(wait.status, 423); assert.equal(wait.writes, 0);
  }
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(approved.body.id).status, 'expired');
  // the human cannot approve while frozen (nothing is released), but denying and a job giving up still work
  assert.equal((await approve(w, u, pending.body.id)).status, 423);
  assert.equal((await w.req('GET', '/v1/alerts', { cookie: u.cookie })).body.frozen_at, f.body.frozen_at);
  assert.deepEqual((await cancel(w, pending.body.poll, pending.body.id)).body, { ok: true, cancelled: true });
  // nothing was sealed in the public log by any of that
  assert.equal((await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries.length, entriesBefore + 0);
  assert.ok(!db(w).prepare("SELECT action FROM audit").all().some((a) => a.action === 'gate_passed'));

  // unfreeze needs a passkey; a command line cannot
  assert.equal((await w.req('POST', '/v1/me/unfreeze/begin', { bearer: cli, ...anon, body: {} })).body.error, 'passkey_required');
  assert.equal((await unfreeze(w, u)).status, 200);
  // the old approval does not come back; the run asks again, is approved and goes on
  assert.equal((await poll(w, approved.body.poll, approved.body.id)).body.status, 'expired');
  const again = await ask(w, gh, g, { run_id: '2' });
  assert.equal(again.status, 202, JSON.stringify(again.body)); assert.notEqual(again.body.id, approved.body.id);
  assert.equal((await approve(w, u, again.body.id)).status, 200);
  assert.equal((await poll(w, again.body.poll, again.body.id)).body.status, 'approved');
});

test('a freeze ends a wait in progress at the next read, and an approval is not spent in the instant of a freeze', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const acct = await w.accountId(u.cookie);
  const g = await gateId(w, u);
  const a = await ask(w, gh, g, { run_id: '1' });
  // the owner freezes while the job is in a long poll
  let sleeps = 0;
  w.env.__sleep = async () => { if (++sleeps === 2) db(w).prepare('UPDATE accounts SET frozen_at = ? WHERE id = ?').run(Date.now(), acct); };
  const p = await poll(w, a.body.poll, a.body.id, 20);
  assert.equal(p.status, 423); assert.equal(p.body.error, 'account_frozen'); assert.equal(sleeps, 2, 'it ended two seconds in, not at 20'); assert.equal(p.writes, 0);
  delete w.env.__sleep;
  db(w).prepare('UPDATE accounts SET frozen_at = NULL WHERE id = ?').run(acct);

  // approved, read as approved, and then frozen before the statement that spends it: not spent
  assert.equal((await approve(w, u, a.body.id)).status, 200);
  const real = w.env.DB.prepare;
  w.env.DB.prepare = (sql) => { if (/^UPDATE holds SET status = 'used'/.test(sql.trim()) && /kind = 'deploy'/.test(sql)) db(w).prepare('UPDATE accounts SET frozen_at = ? WHERE id = ?').run(Date.now(), acct); return real(sql); };
  const raced = await poll(w, a.body.poll, a.body.id);
  w.env.DB.prepare = real;
  assert.equal(raced.status, 423, JSON.stringify(raced.body)); assert.equal(raced.body.error, 'account_frozen');
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(a.body.id).status, 'approved', 'the approval was not spent');
  assert.equal(db(w).prepare('SELECT repository_id FROM gates').get().repository_id, null, 'and the gate was not bound');
  // once the freeze ends the same approval is still good (it was never void: this freeze was not made through the API)
  db(w).prepare('UPDATE accounts SET frozen_at = NULL WHERE id = ?').run(acct);
  assert.equal((await poll(w, a.body.poll, a.body.id)).body.status, 'approved');
});

test('phase 2 under a freeze: no key is handed out, and the tokens a gate already handed out stop with every other token', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'D'.repeat(36) } })).body.id;
  const g = await gateId(w, u, { credentialId: cred });
  const first = await ask(w, gh, g, { run_id: '1' });
  assert.equal((await approve(w, u, first.body.id)).status, 200);
  const live = (await poll(w, first.body.poll, first.body.id)).body.token;
  assert.match(live, /^lsh_/);
  assert.equal((await w.req('GET', '/p/github/repos/acme/app/pulls', { bearer: live, ...anon })).status, 200);
  const second = await ask(w, gh, g, { run_id: '2' });
  assert.equal((await approve(w, u, second.body.id)).status, 200);
  const tokens = db(w).prepare('SELECT COUNT(*) n FROM tokens').get().n;
  assert.equal((await freeze(w, u)).status, 200);
  const p = await poll(w, second.body.poll, second.body.id);
  assert.equal(p.status, 423); assert.ok(!('token' in p.body));
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM tokens').get().n, tokens, 'no token was made');
  const stopped = await w.req('GET', '/p/github/repos/acme/app/pulls', { bearer: live, ...anon });
  assert.equal(stopped.status, 423); assert.equal(stopped.body.error, 'account_frozen');
  assert.equal(w.upstream.filter((x) => x.url.includes('/pulls')).length, 1, 'nothing reached the provider while frozen');
});
