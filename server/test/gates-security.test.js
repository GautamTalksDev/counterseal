// Deploy Gate: what a gate accepts (every filter), binding to the repository's ids, public receipts and their privacy,
// phase 2 (a short-lived token only after approval), the Workers Free budgets, and the data around it (migration, sweep,
// account deletion).
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { makeDb, World } from './helpers.js';
import { makeGithub } from './gh.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetOidc } from '../src/oidc.js';
import { sweep } from '../src/index.js';
import { anon, timeShift, withVapid, world, makeGate, gateId, ask, poll, approve, holds, cliSession, db, audienceFor } from './gate-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetOidc(); });
const run = async (w, gh, g, over, u) => { const r = await ask(w, gh, g, over); if (u && r.status === 202) await approve(w, u, r.body.id); return r; };

test('every filter: repository, workflow files (the top one and the job\'s), refs, environments and events; a refused run writes nothing and alerts no one', async () => {
  const { w, gh } = await world();
  await withVapid(w);
  const u = await w.user();
  await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/phone' } });
  const g = await gateId(w, u, {
    workflows: ['.github/workflows/deploy.yml', '.github/workflows/release.yml'], refs: ['refs/heads/main', 'refs/heads/release/*', 'refs/tags/v*'],
    environments: ['production'], events: ['push', 'workflow_dispatch'],
  });
  const wf = (name, ref = 'refs/heads/main', repo = 'acme/app') => `${repo}/.github/workflows/${name}@${ref}`;
  const refused = async (over, reason) => {
    const holdsBefore = db(w).prepare('SELECT COUNT(*) n FROM holds').get().n, pushes = w.pushes.length;
    const r = await ask(w, gh, g, over);
    assert.equal(r.status, 403, JSON.stringify(over) + JSON.stringify(r.body));
    assert.equal(r.body.error, 'gate_refused'); assert.equal(r.body.reason, reason, JSON.stringify(over));
    assert.equal(r.writes, 0, 'a refused run writes nothing: ' + JSON.stringify(over));
    assert.equal(db(w).prepare('SELECT COUNT(*) n FROM holds').get().n, holdsBefore);
    assert.equal(w.pushes.length, pushes, 'and alerts no one');
    assert.equal(db(w).prepare("SELECT COUNT(*) n FROM nonces WHERE k LIKE 'oidc:%'").get().n, 0, 'the token was not spent');
    return r.body.message;
  };
  // repository: another name, another owner, a lookalike
  for (const [repo, owner] of [['acme/other', 'acme'], ['evil/app', 'evil'], ['acme/app2', 'acme'], ['acme/ap', 'acme'], ['acme-evil/app', 'acme-evil']]) {
    await refused({ repository: repo, repository_owner: owner, workflow_ref: wf('deploy.yml', 'refs/heads/main', repo), job_workflow_ref: wf('deploy.yml', 'refs/heads/main', repo) }, 'repository');
  }
  // workflow: a file the gate does not list, the job's workflow not listed, a workflow of another repository (reusable), a path trick
  assert.match(await refused({ workflow_ref: wf('other.yml'), job_workflow_ref: wf('other.yml') }, 'workflow'), /other\.yml/);
  await refused({ job_workflow_ref: wf('other.yml') }, 'workflow');
  await refused({ workflow_ref: wf('other.yml') }, 'workflow');
  assert.match(await refused({ job_workflow_ref: wf('deploy.yml', 'refs/heads/main', 'acme/shared') }, 'workflow'), /Reusable workflows from other repositories are not supported/);
  await refused({ workflow_ref: wf('deploy.yml', 'refs/heads/main', 'acme/shared') }, 'workflow');
  await refused({ workflow_ref: wf('deploy.yaml'), job_workflow_ref: wf('deploy.yaml') }, 'workflow');
  // ref: a branch not listed, a prefix that is not the pattern, a tag not listed, a pull request ref
  await refused({ ref: 'refs/heads/feature' }, 'ref'); await refused({ ref: 'refs/heads/release' }, 'ref'); await refused({ ref: 'refs/heads/main2' }, 'ref'); await refused({ ref: 'refs/heads/xmain' }, 'ref');
  await refused({ ref: 'refs/tags/1.0' }, 'ref'); await refused({ ref: 'refs/tags/' + 'x' }, 'ref'); await refused({ ref: 'refs/pull/7/merge', event_name: 'pull_request' }, 'ref');
  // environment: another one, or none (this gate lists one)
  await refused({ environment: 'staging' }, 'environment'); await refused({ environment: 'Production' }, 'environment'); await refused({ environment: undefined }, 'environment'); await refused({ environment: 'production ' }, 'environment');
  // event: not on the list (pull_request, schedule, release, workflow_run are not this gate's)
  for (const ev of ['pull_request', 'pull_request_target', 'schedule', 'release', 'workflow_run', 'issue_comment', 'repository_dispatch']) await refused({ event_name: ev }, 'event');
  // and what it does accept
  let n = 0;
  for (const over of [{}, { ref: 'refs/heads/release/1.2' }, { ref: 'refs/heads/release/a/b' }, { ref: 'refs/tags/v1.2.3' }, { event_name: 'workflow_dispatch' }, { workflow_ref: wf('release.yml'), job_workflow_ref: wf('release.yml') },
    { repository: 'ACME/App', workflow_ref: wf('deploy.yml', 'refs/heads/main', 'ACME/App'), job_workflow_ref: wf('deploy.yml', 'refs/heads/main', 'ACME/App') }]) {
    const r = await ask(w, gh, g, { run_id: String(100 + n++), ...over });
    assert.equal(r.status, 202, JSON.stringify(over) + JSON.stringify(r.body));
    await w.req('POST', `/v1/holds/${r.body.id}/deny`, { cookie: u.cookie, body: {} });
  }
  // a gate without environments takes a job with or without one
  const open = await gateId(w, u, { label: 'any environment' });
  assert.equal((await ask(w, gh, open, { environment: undefined })).status, 202);
  assert.equal((await ask(w, gh, open, { environment: 'whatever', run_id: '2' })).status, 202);
});

test('the first approved run binds the gate to GitHub\'s ids; after that a renamed repository works and a re-created one does not', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const first = await ask(w, gh, g);
  assert.equal(first.body.rule, 'gate.bind');
  // unbound: asking again is still the first run; nothing is bound until a human approves AND the job spends it
  assert.equal(db(w).prepare('SELECT repository_id FROM gates').get().repository_id, null);
  assert.equal((await approve(w, u, first.body.id)).status, 200);
  assert.equal(db(w).prepare('SELECT repository_id FROM gates').get().repository_id, null, 'approved is not yet bound');
  assert.equal((await poll(w, first.body.poll, first.body.id)).body.status, 'approved');
  const bound = db(w).prepare('SELECT * FROM gates').get();
  assert.deepEqual([bound.repository_id, bound.repository_owner_id, bound.repository], ['1001', '77', 'acme/app']);
  // bound: the same repository again is an ordinary deploy
  const again = await ask(w, gh, g, { run_id: '2' });
  assert.equal(again.body.rule, 'gate.deploy');
  assert.match((await holds(w, u))[0].preview, /^Repository: acme\/app/);
  assert.ok(!/First run/.test((await holds(w, u))[0].preview));
  // a repository with the same name but other ids (deleted and re-created, or transferred): refused, and says nothing of the old ids
  for (const [rid, oid] of [['2002', '77'], ['1001', '88'], ['2002', '88']]) {
    const r = await ask(w, gh, g, { repository_id: rid, repository_owner_id: oid, run_id: '3' });
    assert.equal(r.status, 403, rid + oid); assert.equal(r.body.reason, 'repository'); assert.equal(r.writes, 0);
    assert.ok(!JSON.stringify(r.body).includes('1001'));
  }
  // the repository was renamed (same ids): GitHub's ids are what the gate is bound to; its workflows must still be the gate's
  const renamed = await ask(w, gh, g, { repository: 'acme/app-renamed', workflow_ref: 'acme/app-renamed/.github/workflows/deploy.yml@refs/heads/main', job_workflow_ref: 'acme/app-renamed/.github/workflows/deploy.yml@refs/heads/main', run_id: '4' });
  assert.equal(renamed.status, 202, JSON.stringify(renamed.body));
  assert.match((await holds(w, u))[0].preview, /^Repository: acme\/app-renamed/);
});

test('two unbound runs from different repositories that share the name: whichever is spent first binds, the other is not spent', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const a = await ask(w, gh, g), b = await ask(w, gh, g, { repository_id: '2002', repository_owner_id: '88' });
  assert.equal(a.status, 202); assert.equal(b.status, 202); assert.notEqual(a.body.id, b.body.id);
  assert.equal((await approve(w, u, a.body.id)).status, 200); assert.equal((await approve(w, u, b.body.id)).status, 200);
  assert.equal((await poll(w, a.body.poll, a.body.id)).body.status, 'approved');
  const late = await poll(w, b.body.poll, b.body.id);
  assert.equal(late.status, 409); assert.equal(late.body.error, 'gate_bound_elsewhere');
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(b.body.id).status, 'approved', 'its approval was not spent');
  assert.equal(db(w).prepare('SELECT repository_id FROM gates').get().repository_id, '1001');
});

test('public receipts say DEPLOY, the decision and the rule; the repository only if the owner opted in, and never a commit, person, label or text', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const acct = await w.accountId(u.cookie);
  const secret = { label: 'Acme Secret Label', summary: 'ship the acme billing hotfix', sha: 'deadbeefcafe0718293a4b5c6d7e8f9012345678' };
  // ids that cannot turn up in a hash or a timestamp by chance
  const ids = { repository_id: '7741001', run_id: '90817265' };
  const g = await gateId(w, u, { label: secret.label });
  const r = await ask(w, gh, g, { sha: secret.sha, ...ids }, { summary: secret.summary });
  await approve(w, u, r.body.id);
  await poll(w, r.body.poll, r.body.id);
  const r2 = await ask(w, gh, g, { ...ids, run_id: '90817266', sha: secret.sha });
  await w.req('POST', `/v1/holds/${r2.body.id}/deny`, { cookie: u.cookie, body: { reason: 'Not the acme billing hotfix on a Friday.' } });
  const entries = (await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries.map((e) => e.entry);
  const rc = entries.map((e) => e.receipt);
  assert.deepEqual(rc.map((x) => `${x.action} ${x.decision} ${x.meta.rule}`), ['DEPLOY github.com held gate.bind', 'DEPLOY github.com approved gate.bind', 'DEPLOY github.com executed gate.bind', 'DEPLOY github.com held gate.deploy', 'DEPLOY github.com denied gate.deploy']);
  for (const x of rc) assert.deepEqual(Object.keys(x.meta).sort().filter((k) => !['map', 'rule', 'passkey'].includes(k)), [], 'fixed words only');
  assert.equal(rc[1].meta.passkey, true);
  const secrets = ['acme', 'Acme', 'acme/app', 'octocat', secret.label, 'billing', 'hotfix', 'deadbeef', 'a1b2c3', '90817265', '7741001', '.github', 'deploy.yml', 'production', 'Friday', 'Deploy', acct, 'Gautam'];
  const pub = JSON.stringify(entries);
  for (const s of secrets) assert.ok(!pub.includes(s), 'the public log has ' + s);
  const tables = w.sql.raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((t) => t.name);
  const stored = JSON.stringify(tables.map((t) => w.sql.raw.prepare(`SELECT * FROM ${t}`).all()), (k, v) => (v instanceof Uint8Array ? '' : v));
  for (const s of secrets.filter((x) => x !== acct)) assert.ok(!stored.includes(s), 'the log storage has ' + s);
  // each receipt opens to the owner's private audit entry
  const audit = db(w).prepare('SELECT hash, receipt, action FROM audit WHERE receipt IS NOT NULL ORDER BY seq').all();
  assert.deepEqual(audit.map((a) => a.action), ['hold', 'approve', 'gate_passed', 'hold', 'deny']);
  assert.deepEqual(rc.map((x) => x.parent), audit.map((a) => a.hash));

  // opted in for this gate: the repository name is public, nothing else new
  const { w: w2, gh: gh2 } = await world();
  const u2 = await w2.user();
  const g2 = await gateId(w2, u2, { publishRepo: true });
  assert.equal((await w2.req('GET', '/v1/gates', { cookie: u2.cookie })).body.gates[0].publish_repo, true);
  const q = await ask(w2, gh2, g2, { sha: secret.sha, ...ids }, { summary: secret.summary });
  await approve(w2, u2, q.body.id);
  await poll(w2, q.body.poll, q.body.id);
  const q2 = await ask(w2, gh2, g2, { ...ids, run_id: '90817266' });
  await w2.req('POST', `/v1/holds/${q2.body.id}/deny`, { cookie: u2.cookie, body: {} });
  const rc2 = (await w2.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries.map((e) => e.entry.receipt);
  assert.equal(rc2.length, 5);
  for (const x of rc2) { assert.equal(x.meta.repo, 'acme/app'); assert.deepEqual(Object.keys(x.meta).sort().filter((k) => !['map', 'rule', 'passkey', 'repo'].includes(k)), []); }
  const pub2 = JSON.stringify(rc2);
  for (const s of ['octocat', 'deadbeef', 'billing', 'deploy.yml', 'production', '90817265', '7741001', 'prod deploy']) assert.ok(!pub2.includes(s), 'opted in, but the public log has ' + s);
  // receipts off: nothing public, the decisions still in the private audit log
  const { w: w3, gh: gh3 } = await world();
  const u3 = await w3.user();
  const off = await w3.req('POST', '/v1/me/receipts/off/begin', { cookie: u3.cookie, body: {} });
  await w3.req('POST', '/v1/me/receipts/off/finish', { cookie: u3.cookie, body: { challengeId: off.body.challengeId, credential: await u3.auth.get(off.body.options) } });
  const g3 = await gateId(w3, u3);
  const o = await ask(w3, gh3, g3);
  await approve(w3, u3, o.body.id); await poll(w3, o.body.poll, o.body.id);
  assert.equal((await w3.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries.length, 0);
  assert.deepEqual(db(w3).prepare("SELECT action FROM audit WHERE action IN ('hold','approve','gate_passed') ORDER BY seq").all().map((a) => a.action), ['hold', 'approve', 'gate_passed']);
});

test('phase 2, no approval and no key: a run gets a 15 minute token for the vaulted key only after a passkey approval, once, under the gate\'s policy', async () => {
  const { w, gh } = await world();
  const u = await w.user(), v = await w.user('Eve', '192.0.2.9');
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'D'.repeat(36), label: 'deploy key' } })).body.id;
  const policy = { allow: [{ method: 'GET', path: '/repos/acme/**' }, { method: 'POST', path: '/repos/acme/app/deployments' }, { method: 'DELETE', path: '/repos/acme/app/releases/*' }], unattendedIrreversible: [{ method: 'DELETE', path: '/repos/acme/app/releases/*' }], perMinute: 60 };
  // making such a gate needs the passkey ceremony (the same route), a key of this account, and a valid policy
  assert.equal((await makeGate(w, u, { credentialId: '0'.repeat(24) })).status, 404);
  const foreign = (await w.req('POST', '/v1/credentials', { cookie: v.cookie, body: { provider: 'github', secret: 'ghp_' + 'E'.repeat(36) } })).body.id;
  assert.equal((await makeGate(w, u, { credentialId: foreign })).status, 404, 'never another account\'s key');
  assert.equal((await makeGate(w, u, { credentialId: cred, policy: { allow: 'x' } })).body.error, 'bad_policy');
  const cli = await cliSession(w, u);
  assert.equal((await w.req('POST', '/v1/gates/passkey/begin', { bearer: cli, ...anon, body: {} })).body.error, 'passkey_required');
  const made = await makeGate(w, u, { credentialId: cred, policy });
  assert.equal(made.status, 200, JSON.stringify(made.body));
  assert.deepEqual(made.body.credential, { id: cred, provider: 'github', label: 'deploy key', preapproved: 1 });
  const g = made.body.id;
  const tokensBefore = db(w).prepare('SELECT COUNT(*) n FROM tokens').get().n;

  const r = await ask(w, gh, g);
  assert.ok(!JSON.stringify(r.body).includes('lsh_'), 'no key in the answer to the request');
  const pending = await poll(w, r.body.poll, r.body.id);
  assert.equal(pending.body.status, 'pending'); assert.ok(!('token' in pending.body), 'nothing before approval');
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM tokens').get().n, tokensBefore, 'no token exists for a run that is waiting');
  assert.equal((await approve(w, u, r.body.id)).status, 200);
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM tokens').get().n, tokensBefore, 'approving mints nothing by itself: the poll that spends the approval does');
  const t0 = Date.now();
  const p = await poll(w, r.body.poll, r.body.id);
  assert.equal(p.body.status, 'approved');
  assert.match(p.body.token, /^lsh_[A-Za-z0-9_-]{43}$/); assert.equal(p.body.provider, 'github'); assert.equal(p.body.base_url, 'https://leash.test/p/github');
  assert.ok(Math.abs(p.body.token_expires_at - (t0 + 15 * 60_000)) < 5_000, '15 minutes');
  // once: the same secret again, and a second secret for the same hold, get no token
  const dup = await poll(w, r.body.poll, r.body.id);
  assert.equal(dup.body.status, 'used'); assert.ok(!('token' in dup.body));
  // the token is an ordinary Counterseal token under the gate's policy: the real key is injected, nothing outside the policy passes
  const tok = p.body.token;
  const call = (method, path, body) => w.req(method, `/p/github${path}`, { bearer: tok, ...anon, body });
  assert.equal((await call('GET', '/repos/acme/app/pulls')).status, 200);
  assert.equal(w.upstream.at(-1).headers.authorization, 'Bearer ghp_' + 'D'.repeat(36), 'the real key went upstream, not to the job');
  assert.equal((await call('POST', '/repos/acme/app/deployments', { ref: 'main' })).status, 200);
  assert.equal((await call('PUT', '/user/starred/acme/app')).body.error, 'leash_denied', 'outside the policy');
  assert.equal((await call('DELETE', '/repos/acme/app')).body.error, 'held_for_approval', 'irreversible and not pre-approved: it waits for a human like any other');
  assert.equal((await call('DELETE', '/repos/acme/app/releases/5')).status, 200, 'pre-approved by the passkey ceremony that made the gate');
  // what the owner sees
  const listed = (await w.req('GET', '/v1/tokens', { cookie: u.cookie })).body.tokens.find((x) => x.label === 'gate: prod deploy');
  assert.equal(listed.minted_by, 'gate'); assert.ok(listed.expires_at <= t0 + 15 * 60_000 + 5_000);
  assert.equal(db(w).prepare('SELECT gate_id, hold_id FROM gate_runs').get().hold_id, r.body.id);
  const audit = JSON.stringify(db(w).prepare('SELECT detail FROM audit').all());
  assert.ok(!audit.includes('lsh_'), 'the token is never in the audit log');
  const passed = JSON.parse(db(w).prepare("SELECT detail FROM audit WHERE action = 'gate_passed'").get().detail);
  assert.deepEqual([passed.credential, passed.provider], [cred, 'github']);
  // 15 minutes later it is gone
  await timeShift(16 * 60_000, async () => assert.equal((await call('GET', '/repos/acme/app/pulls')).body.error, 'token_invalid'));
  // a denied or expired run never gets one
  const d = await ask(w, gh, g, { run_id: '2' });
  await w.req('POST', `/v1/holds/${d.body.id}/deny`, { cookie: u.cookie, body: {} });
  const dp = await poll(w, d.body.poll, d.body.id);
  assert.equal(dp.body.status, 'denied'); assert.ok(!('token' in dp.body));
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM tokens').get().n, tokensBefore + 1);
  // revoking the gate stops what it handed out, and closes what is waiting
  const l = await ask(w, gh, g, { run_id: '3' });
  await approve(w, u, l.body.id);
  const live = (await poll(w, l.body.poll, l.body.id)).body.token;
  assert.equal((await w.req('GET', '/p/github/repos/acme/app/pulls', { bearer: live, ...anon })).status, 200);
  const waiting = await ask(w, gh, g, { run_id: '4' });
  const rv = await w.req('DELETE', `/v1/gates/${g}`, { cookie: u.cookie });
  assert.deepEqual(rv.body, { ok: true, closed: 1, tokens: 2 }, 'both tokens this gate handed out, including the one whose 15 minutes were up');
  assert.equal((await w.req('GET', '/p/github/repos/acme/app/pulls', { bearer: live, ...anon })).body.error, 'token_invalid');
  assert.equal((await poll(w, waiting.body.poll, waiting.body.id)).body.status, 'expired');
});

test('phase 2 does not spend an approval it cannot honour: the key was deleted, or the account has too many live tokens', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'D'.repeat(36) } })).body.id;
  const g = await gateId(w, u, { credentialId: cred });
  const r = await ask(w, gh, g);
  await approve(w, u, r.body.id);
  assert.equal((await w.req('DELETE', `/v1/credentials/${cred}`, { cookie: u.cookie })).status, 200);
  const gone = await poll(w, r.body.poll, r.body.id);
  assert.equal(gone.status, 409); assert.equal(gone.body.error, 'credential_gone');
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(r.body.id).status, 'approved');
  // too many live tokens
  const cred2 = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'F'.repeat(36) } })).body.id;
  const g2 = await gateId(w, u, { label: 'second', credentialId: cred2 });
  const acct = await w.accountId(u.cookie);
  for (let i = 0; i < 200; i++) db(w).prepare('INSERT INTO tokens (id, account_id, credential_id, hash, label, policy, minted_by, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run('t' + i, acct, cred2, 'h' + i, 'x', '{}', 'cli', Date.now() + 1e7, Date.now());
  const r2 = await ask(w, gh, g2);
  await approve(w, u, r2.body.id);
  const full = await poll(w, r2.body.poll, r2.body.id);
  assert.equal(full.status, 409); assert.equal(full.body.error, 'too_many_tokens');
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(r2.body.id).status, 'approved', 'the approval is still good');
  db(w).prepare("DELETE FROM tokens WHERE id LIKE 't%'").run();
  assert.equal((await poll(w, r2.body.poll, r2.body.id)).status, 200);
});

test('Workers Free budgets: asking, polling and passing stay far under 50 D1 queries; polling writes nothing', async () => {
  const { w, gh } = await world();
  await withVapid(w);
  const u = await w.user();
  for (let i = 0; i < 10; i++) await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/d' + i } });
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'D'.repeat(36) } })).body.id;
  const g = await gateId(w, u, { credentialId: cred, publishRepo: true });
  w.env.DB.cap = 50;
  const r = await ask(w, gh, g);
  assert.equal(r.status, 202);
  assert.ok(r.queries <= 35, `${r.queries} queries to ask (gate, token, hold, audit, receipt, 10 devices)`);
  assert.ok(r.writes <= 20, `${r.writes} writes to ask`);
  const dup = await ask(w, gh, g);
  assert.ok(dup.queries <= 8 && dup.writes <= 3, `${dup.queries} queries, ${dup.writes} writes to ask again (a token spent, a poll secret)`);
  const wait = await poll(w, r.body.poll, r.body.id, 20);
  assert.equal(wait.writes, 0); assert.ok(wait.queries <= 12, `${wait.queries} queries to wait 20 seconds`);
  const a = await approve(w, u, r.body.id);
  assert.ok(a.queries <= 20, `${a.queries} queries to approve`);
  const p = await poll(w, r.body.poll, r.body.id);
  assert.equal(p.body.status, 'approved'); assert.ok(p.queries <= 25, `${p.queries} queries to spend the approval and mint a token`);
  w.env.DB.cap = 0;
  // deleting the account removes gates, poll secrets and run records
  const del = await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: del.body.challengeId, credential: await u.auth.get(del.body.options) } })).status, 200);
  for (const t of ['gates', 'gate_polls', 'gate_runs', 'holds', 'tokens']) assert.equal(db(w).prepare(`SELECT COUNT(*) n FROM ${t}`).get().n, 0, t);
});

test('the sweep drops what is no longer needed a day after a deploy hold closes: the preview and the person\'s name; poll secrets when they end', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const a = await ask(w, gh, g), b = await ask(w, gh, g, { run_id: '2' });
  await approve(w, u, a.body.id); await poll(w, a.body.poll, a.body.id);
  await w.req('POST', `/v1/holds/${b.body.id}/deny`, { cookie: u.cookie, body: {} });
  const c = await ask(w, gh, g, { run_id: '3' });
  const t = Date.now();
  await sweep(w.env, t + 3600_000);
  assert.ok(db(w).prepare('SELECT context FROM holds WHERE id = ?').get(a.body.id).context, 'within a day it stays');
  await sweep(w.env, t + 2 * 86400_000);
  const rows = db(w).prepare('SELECT id, status, context, preview FROM holds').all();
  for (const x of rows) { if (x.id === c.body.id) continue; assert.equal(x.context, null, x.status); assert.equal(x.preview, null); }
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM gate_polls').get().n, 0, 'every poll secret has ended by then');
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM nonces WHERE k LIKE 'oidc:%'").get().n, 0);
  assert.ok(!JSON.stringify(db(w).prepare('SELECT * FROM holds').all()).includes('octocat'));
  // the owner's audit log keeps the repository, commit and run, never the person
  assert.ok(db(w).prepare("SELECT detail FROM audit WHERE action = 'hold'").all().every((x) => JSON.parse(x.detail).repository === 'acme/app' && !x.detail.includes('octocat')));
});

test('migration 0007 on live-shaped data: holds, guard keys and approvals written before it keep working, and gates work on the same database', async () => {
  const MIG = new URL('../migrations/', import.meta.url);
  // every migration except this one: the rows below are written by the code as it runs without gates, then 0007 is applied
  // to the same database, as `wrangler d1 migrations apply` will do on the live one before the new code is deployed
  const db0 = makeDb({ migrations: (f) => !f.startsWith('0007') });
  const w = new World({ db: db0 });
  const gh = await makeGithub(); _resetOidc(); w.env.__oidcFetch = gh.fetch;
  const u = await w.user();
  const gk = (await w.req('POST', '/v1/guard/keys', { cookie: u.cookie, body: { label: 'laptop' } })).body;
  const h = await w.req('POST', '/v1/approvals', { bearer: gk.key, ...anon, body: { kind: 'shell', agent: 'claude-code', rule: 'sh.x', why: 'w', summary: 's', detail: 'terraform destroy' } });
  assert.equal(h.status, 202, JSON.stringify(h.body));
  assert.equal((await approve(w, u, h.body.id)).status, 200);
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'L'.repeat(36) } })).body.id;
  const tok = (await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, label: 'old agent' } })).body.token;
  const brokered = await w.req('DELETE', '/p/github/repos/acme/old', { bearer: tok, ...anon });
  assert.equal(brokered.status, 428);
  const counts = Object.fromEntries(['accounts', 'passkeys', 'holds', 'guard_keys', 'tokens', 'credentials', 'audit'].map((t) => [t, db0.raw.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n]));
  const auditBefore = db0.raw.prepare('SELECT seq, hash FROM audit ORDER BY seq').all();
  const holdsBefore = db0.raw.prepare('SELECT * FROM holds ORDER BY id').all();
  for (const f of readdirSync(MIG).sort().filter((f) => f.startsWith('0007'))) db0.raw.exec(readFileSync(new URL(f, MIG), 'utf8'));
  for (const [t, n] of Object.entries(counts)) assert.equal(db0.raw.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n, n, t + ' rows unchanged');
  assert.deepEqual(db0.raw.prepare('SELECT seq, hash FROM audit ORDER BY seq').all(), auditBefore, 'the audit chain is untouched');
  assert.deepEqual(db0.raw.prepare('SELECT * FROM holds ORDER BY id').all(), holdsBefore, 'so are the holds');
  // the approval written before still works, and the brokered hold lists as it did; a gate is made and used on the migrated database
  assert.equal((await w.req('POST', `/v1/approvals/${h.body.id}/use`, { bearer: gk.key, ...anon, body: { hash: h.body.hash } })).status, 200);
  const listed = (await holds(w, u)).find((x) => x.id === brokered.body.hold_id);
  assert.equal(listed.kind, 'proxy'); assert.equal(listed.token_label, 'old agent'); assert.equal(listed.context, null);
  const g = await gateId(w, u);
  const r = await ask(w, gh, g);
  assert.equal(r.status, 202, JSON.stringify(r.body));
  assert.equal((await approve(w, u, r.body.id)).status, 200);
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'approved');
  assert.equal((await approve(w, u, brokered.body.hold_id)).status, 200);
  assert.equal((await w.req('DELETE', '/p/github/repos/acme/old', { bearer: tok, ...anon })).status, 200, 'the brokered call goes through once approved');
  assert.equal((await w.req('GET', '/v1/audit/verify', { cookie: u.cookie })).body.ok, true);
  const kinds = db0.raw.prepare('SELECT kind, COUNT(*) n FROM holds GROUP BY kind ORDER BY kind').all().map((x) => `${x.kind}:${x.n}`);
  assert.deepEqual(kinds, ['deploy:1', 'proxy:1', 'shell:1']);
});

test('a gate\'s runs never mix with guard approvals or brokered holds: the same id spaces, the same routes, different doors', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const gk = (await w.req('POST', '/v1/guard/keys', { cookie: u.cookie, body: { label: 'laptop' } })).body;
  const r = await ask(w, gh, g);
  // a guard key cannot read or use a deploy hold, and a poll secret cannot read a guard hold
  assert.equal((await w.req('GET', `/v1/approvals/${r.body.id}`, { bearer: gk.key, ...anon })).status, 404);
  assert.equal((await w.req('POST', `/v1/approvals/${r.body.id}/use`, { bearer: gk.key, ...anon, body: { hash: 'a'.repeat(64) } })).status, 404);
  const h = await w.req('POST', '/v1/approvals', { bearer: gk.key, ...anon, body: { kind: 'shell', agent: 'claude-code', rule: 'sh.x', why: 'w', summary: 's', detail: 'rm -rf /' } });
  assert.equal((await poll(w, r.body.poll, h.body.id)).status, 404);
  // approving the guard hold does not release the deploy hold, nor the other way
  await approve(w, u, h.body.id);
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'pending');
  await approve(w, u, r.body.id);
  assert.equal((await w.req('GET', `/v1/approvals/${h.body.id}`, { bearer: gk.key, ...anon })).body.status, 'approved');
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'approved');
  assert.equal((await w.req('GET', `/v1/approvals/${h.body.id}`, { bearer: gk.key, ...anon })).body.status, 'approved', 'still its own');
  // the list shows both kinds with their own labels
  const kinds = (await holds(w, u, 'approved')).map((x) => [x.kind, x.token_label]).sort();
  assert.deepEqual(kinds, [['shell', 'laptop']]);
  void audienceFor;
});

test('the operator\'s private numbers count gates, deploys that passed and holds by kind, and never name a repository, run or person', async () => {
  const { w, gh } = await world();
  w.env.STATS_TOKEN = 'S'.repeat(40);
  const u = await w.user();
  const cred = (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'D'.repeat(36) } })).body.id;
  const g = await gateId(w, u, { label: 'Acme Secret Label' });
  await gateId(w, u, { label: 'with a key', repository: 'acme/web', credentialId: cred });
  const r = await ask(w, gh, g, { run_id: '7654321' }, { summary: 'ship it' });
  await approve(w, u, r.body.id); await poll(w, r.body.poll, r.body.id);
  await ask(w, gh, g, { run_id: '7654322' });
  const s = await w.req('GET', '/v1/admin/stats', { bearer: w.env.STATS_TOKEN, ...anon });
  assert.equal(s.status, 200, JSON.stringify(s.body));
  assert.ok(s.queries <= 12, `${s.queries} queries`); assert.equal(s.writes, 0);
  assert.deepEqual(s.body.gates, { made: 2, madeLast7d: 2, active: 2, bound: 1, handingOutAKey: 1 });
  assert.deepEqual(s.body.decisions.deploysPassedAfterApproval, { total: 1, last7d: 1 });
  assert.equal(s.body.guard.holdsLast7dByKind.deploy, 2);
  const text = JSON.stringify(s.body);
  for (const secret of ['acme', 'Acme', 'octocat', '7654321', 'ship it', 'a1b2c3', g]) assert.ok(!text.includes(secret), secret);
});
