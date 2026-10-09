// Deploy Gate (feature 3): gates made with a passkey, the run's OIDC token verified, what it says checked against the gate,
// the hold that results, the poll that waits (writing nothing), the approval spent once, binding on the first approved run,
// public receipts, and phase 2 (a short-lived token only after approval).
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetOidc } from '../src/oidc.js';
import { PENDING_PER_GATE, HOLDS_PER_HOUR } from '../src/gates.js';
import { gateHash, factsOf } from '../src/gatefacts.js';
import { anon, timeShift, withVapid, world, makeGate, gateId, ask, poll, approve, holds, cliSession, db, audienceFor } from './gate-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetOidc(); });

test('a gate is made with a passkey, listed, and revoked by any session; nothing is accepted by default', async () => {
  const { w } = await world();
  const u = await w.user(), v = await w.user('Eve', '192.0.2.9');
  const cli = await cliSession(w, u);
  // no passkey ceremony, no gate: a web session alone, a command line sign-in and a wrong or reused challenge all fail
  const b = await w.req('POST', '/v1/gates/passkey/begin', { cookie: u.cookie, body: {} });
  const base = { label: 'prod', repository: 'acme/app', workflows: ['.github/workflows/deploy.yml'], refs: ['refs/heads/main'] };
  assert.equal((await w.req('POST', '/v1/gates/passkey/begin', { bearer: cli, ...anon, body: {} })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', '/v1/gates/passkey/finish', { bearer: cli, ...anon, body: { ...base, challengeId: b.body.challengeId, credential: {} } })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', '/v1/gates/passkey/begin', { cookie: u.cookie, body: {}, xleash: false })).body.error, 'csrf');
  assert.equal((await w.req('POST', '/v1/gates/passkey/finish', { cookie: u.cookie, body: { ...base, challengeId: '00'.repeat(12), credential: await u.auth.get(b.body.options) } })).body.error, 'challenge_expired');
  const ok = await w.req('POST', '/v1/gates/passkey/finish', { cookie: u.cookie, body: { ...base, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.match(ok.body.id, /^gate_[0-9a-f]{24}$/);
  assert.deepEqual(ok.body.events, ['push', 'workflow_dispatch', 'release', 'deployment', 'merge_group'], 'a fixed default list of events, never pull_request');
  assert.equal(ok.body.environments, null); assert.equal(ok.body.bound, null); assert.equal(ok.body.publish_repo, false); assert.equal(ok.body.credential, null);
  // the challenge is single use
  assert.equal((await w.req('POST', '/v1/gates/passkey/finish', { cookie: u.cookie, body: { ...base, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } })).body.error, 'challenge_expired');
  // another person's passkey cannot make a gate in this account
  const vb = await w.req('POST', '/v1/gates/passkey/begin', { cookie: v.cookie, body: {} });
  const cross = await w.req('POST', '/v1/gates/passkey/finish', { cookie: u.cookie, body: { ...base, challengeId: vb.body.challengeId, credential: await v.auth.get(vb.body.options) } });
  assert.equal(cross.status, 403);
  // list: any session; the other account sees none of it; revoking is 404 for another account and works from a CLI session
  const l = await w.req('GET', '/v1/gates', { bearer: cli, ...anon });
  assert.equal(l.status, 200); assert.equal(l.body.gates.length, 1); assert.equal(l.body.gates[0].repository, 'acme/app'); assert.equal(l.body.server, 'https://leash.test');
  assert.equal((await w.req('GET', '/v1/gates', { cookie: v.cookie })).body.gates.length, 0);
  assert.equal((await w.req('DELETE', `/v1/gates/${ok.body.id}`, { cookie: v.cookie })).status, 404);
  assert.equal((await w.req('DELETE', `/v1/gates/${ok.body.id}`, { cookie: u.cookie, xleash: false })).body.error, 'csrf');
  const rv = await w.req('DELETE', `/v1/gates/${ok.body.id}`, { bearer: cli, ...anon });
  assert.deepEqual(rv.body, { ok: true, closed: 0, tokens: 0 });
  assert.equal((await w.req('DELETE', `/v1/gates/${ok.body.id}`, { cookie: u.cookie })).status, 404, 'twice is not found');
  const acts = db(w).prepare("SELECT action FROM audit WHERE action LIKE 'gate_%'").all().map((r) => r.action);
  assert.deepEqual(acts, ['gate_created', 'gate_revoked']);
});

test('gate configuration is strict: a repository, workflows and refs are required, wildcards and risky events are not expressible', async () => {
  const { w } = await world();
  const u = await w.user();
  const bad = [
    [{ label: '' }, 'bad_label'], [{ label: '<b>' }, 'bad_label'], [{ label: 'x'.repeat(61) }, 'bad_label'],
    [{ repository: undefined }, 'bad_repository'], [{ repository: 'acme' }, 'bad_repository'], [{ repository: 'acme/*' }, 'bad_repository'], [{ repository: '*/app' }, 'bad_repository'],
    [{ repository: 'acme/app/extra' }, 'bad_repository'], [{ repository: 'acme/..' }, 'bad_repository'], [{ repository: 'ac me/app' }, 'bad_repository'], [{ repository: 'https://github.com/acme/app' }, 'bad_repository'],
    [{ workflows: undefined }, 'bad_workflows'], [{ workflows: [] }, 'bad_workflows'], [{ workflows: ['deploy.yml'] }, 'bad_workflows'], [{ workflows: ['.github/workflows/*.yml'] }, 'bad_workflows'],
    [{ workflows: ['.github/workflows/../x.yml'] }, 'bad_workflows'], [{ workflows: ['.github/workflows/sub/x.yml'] }, 'bad_workflows'], [{ workflows: 'deploy.yml' }, 'bad_workflows'],
    [{ workflows: Array.from({ length: 6 }, (_, i) => `.github/workflows/w${i}.yml`) }, 'bad_workflows'],
    [{ refs: undefined }, 'bad_refs'], [{ refs: [] }, 'bad_refs'], [{ refs: ['*'] }, 'bad_refs'], [{ refs: ['main'] }, 'bad_refs'], [{ refs: ['refs/heads/*'] }, 'bad_refs'], [{ refs: ['refs/tags/*'] }, 'bad_refs'],
    [{ refs: ['refs/heads/**'] }, 'bad_refs'], [{ refs: ['refs/heads/a*b'] }, 'bad_refs'], [{ refs: ['refs/heads/../x'] }, 'bad_refs'], [{ refs: ['refs/heads//x'] }, 'bad_refs'], [{ refs: ['refs/pull/1/merge'] }, 'bad_refs'],
    [{ environments: ['prod*'] }, 'bad_environments'], [{ environments: [''] }, 'bad_environments'], [{ environments: 'production' }, 'bad_environments'],
    [{ events: ['pull_request'] }, 'bad_events'], [{ events: ['pull_request_target'] }, 'bad_events'], [{ events: ['workflow_run'] }, 'bad_events'], [{ events: [] }, 'bad_events'], [{ events: ['*'] }, 'bad_events'],
    [{ publishRepo: 'yes' }, 'bad_publishRepo'], [{ extra: 1 }, 'bad_field'], [{ policy: { readOnly: true } }, 'policy_needs_credential'],
  ];
  for (const [over, code] of bad) {
    const r = await makeGate(w, u, over);
    assert.equal(r.status, 400, JSON.stringify(over) + ' ' + JSON.stringify(r.body));
    assert.equal(r.body.error, code, JSON.stringify(over));
  }
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM gates').get().n, 0, 'nothing was made');
  // good: prefix patterns with one trailing *, several workflows, environments, events from the vocabulary, a dotted repo name
  const good = await makeGate(w, u, { repository: 'acme/.github', workflows: ['.github/workflows/deploy.yml', '.github/workflows/release.yaml'], refs: ['refs/heads/main', 'refs/heads/release/*', 'refs/tags/v*'], environments: ['production', 'staging (eu)'], events: ['push', 'schedule', 'repository_dispatch'] });
  assert.equal(good.status, 200, JSON.stringify(good.body));
  assert.deepEqual(good.body.refs, ['refs/heads/main', 'refs/heads/release/*', 'refs/tags/v*']);
  // 20 active gates at most
  for (let i = 0; i < 19; i++) assert.equal((await makeGate(w, u, { label: 'g' + i })).status, 200);
  assert.equal((await makeGate(w, u, { label: 'one too many' })).body.error, 'too_many_gates');
});

test('the happy path: ask with GitHub\'s token, wait, approve with a passkey, pass once; the card shows only what GitHub signed', async () => {
  const { w, gh } = await world();
  await withVapid(w);
  const u = await w.user();
  assert.equal((await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/phone' } })).status, 200);
  const g = await gateId(w, u, { environments: ['production'] });
  const r = await ask(w, gh, g, {}, { summary: 'deploy a1b2c3d to production' });
  assert.equal(r.status, 202, JSON.stringify(r.body));
  assert.equal(r.body.status, 'pending'); assert.equal(r.body.created, true); assert.equal(r.body.rule, 'gate.bind');
  assert.match(r.body.poll, /^gps_[A-Za-z0-9_-]{43}$/);
  assert.equal(r.body.approve_url, `https://leash.test/app#hold=${r.body.id}`);
  assert.ok(Math.abs(r.body.expires_at - (Date.now() + 15 * 60_000)) < 60_000, 'the hold lasts as long as the job will wait (15 minutes by default)');
  assert.equal(w.pushes.length, 1, 'one alert, carrying nothing');
  assert.ok(!JSON.stringify(r.body).includes('acme'), 'the answer to the job says nothing about the repository');
  // what the owner's app shows: the facts GitHub signed, links built from them, the workflow's own text kept apart
  const h = (await holds(w, u))[0];
  assert.equal(h.id, r.body.id); assert.equal(h.kind, 'deploy'); assert.equal(h.agent, 'github-actions'); assert.equal(h.method, 'DEPLOY'); assert.equal(h.host, 'github.com');
  assert.equal(h.token_label, 'prod deploy'); assert.equal(h.path, 'acme/app@a1b2c3d production'); assert.equal(h.rule, 'gate.bind');
  assert.deepEqual(h.context.gate, {
    repository: 'acme/app', repository_id: '1001', ref: 'refs/heads/main', sha: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678', workflow_ref: 'acme/app/.github/workflows/deploy.yml@refs/heads/main',
    job_workflow_ref: 'acme/app/.github/workflows/deploy.yml@refs/heads/main', environment: 'production', event: 'push', actor: 'octocat', run_id: '812', run_attempt: '1',
    visibility: 'private', runner: 'github-hosted', bind: 1, summary: 'deploy a1b2c3d to production',
    run_url: 'https://github.com/acme/app/actions/runs/812/attempts/1', commit_url: 'https://github.com/acme/app/commit/a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
  });
  assert.ok(!('req_hash' in h));
  assert.match(h.preview, /First run of this gate: approving binds it to acme\/app \(GitHub id 1001\)/);
  assert.match(h.preview, /Commit: a1b2c3d4e5f60718293a4b5c6d7e8f9012345678/);
  assert.match(h.preview, /The lines above are from the token GitHub signed for this job\.\nText from the workflow \(not verified\): deploy a1b2c3d to production$/);
  // not approved: the job waits
  const p0 = await poll(w, r.body.poll, r.body.id);
  assert.equal(p0.status, 200); assert.equal(p0.body.status, 'pending');
  // approve with a passkey (the same route as every other hold)
  const a = await approve(w, u, r.body.id);
  assert.equal(a.status, 200, JSON.stringify(a.body));
  assert.match(a.body.note, /The job can now go on, once, within 10 minutes/);
  // the next poll spends it
  const p1 = await poll(w, r.body.poll, r.body.id);
  assert.equal(p1.body.status, 'approved'); assert.ok(!('token' in p1.body), 'phase 1 hands out nothing');
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(r.body.id).status, 'used');
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'used', 'once');
  // the first approved run bound the gate to GitHub's ids
  const gate = db(w).prepare('SELECT * FROM gates WHERE id = ?').get(g);
  assert.equal(gate.repository_id, '1001'); assert.equal(gate.repository_owner_id, '77'); assert.ok(gate.bound_at > 0); assert.ok(gate.last_used > 0);
  assert.equal((await w.req('GET', '/v1/gates', { cookie: u.cookie })).body.gates[0].bound.repository_id, '1001');
  // the audit log has the run, never the person
  const acts = db(w).prepare('SELECT action, detail FROM audit ORDER BY seq').all().filter((x) => ['hold', 'approve', 'gate_passed'].includes(x.action));
  assert.deepEqual(acts.map((x) => x.action), ['hold', 'approve', 'gate_passed']);
  const hold = JSON.parse(acts[0].detail);
  assert.equal(hold.repository, 'acme/app'); assert.equal(hold.sha, 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678'); assert.equal(hold.run_id, '812'); assert.equal(hold.gate, g);
  assert.ok(!JSON.stringify(acts).includes('octocat') && !JSON.stringify(acts).includes('deploy a1b2c3d'), 'no actor and no workflow text in the audit log');
  assert.equal((await w.req('GET', '/v1/audit/verify', { cookie: u.cookie })).body.ok, true);
  // the second run of the same gate is an ordinary deploy, not a binding
  const r2 = await ask(w, gh, g, { run_id: '813' });
  assert.equal(r2.body.rule, 'gate.deploy');
  assert.match((await holds(w, u))[0].preview, /^Repository: acme\/app \(private\)/);
});

test('a run that is asked again is the same hold (no second alert), with its own poll secret; a retry after a lost answer works', async () => {
  const { w, gh } = await world();
  await withVapid(w);
  const u = await w.user();
  await w.req('POST', '/v1/push/subscribe', { cookie: u.cookie, body: { endpoint: 'https://fcm.googleapis.com/fcm/send/phone' } });
  const g = await gateId(w, u);
  const a = await ask(w, gh, g), b = await ask(w, gh, g);
  assert.equal(b.status, 202); assert.equal(b.body.id, a.body.id); assert.equal(b.body.created, false); assert.notEqual(b.body.poll, a.body.poll);
  assert.equal(w.pushes.length, 1);
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM holds').get().n, 1);
  assert.equal((await approve(w, u, a.body.id)).status, 200);
  // asking after the approval, before it was spent: it comes back approved, and either secret may spend it, once
  const c = await ask(w, gh, g);
  assert.equal(c.body.status, 'approved'); assert.equal(c.body.id, a.body.id);
  assert.equal((await poll(w, b.body.poll, a.body.id)).body.status, 'approved');
  assert.equal((await poll(w, a.body.poll, a.body.id)).body.status, 'used');
  assert.equal((await poll(w, c.body.poll, a.body.id)).body.status, 'used');
  // after it was spent, the same claims need a new approval
  const d = await ask(w, gh, g);
  assert.equal(d.body.created, true); assert.notEqual(d.body.id, a.body.id);
});

test('the approval is bound to the repository, run, attempt, commit, workflow, ref, environment and job; a different one is a different hold', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u, { refs: ['refs/heads/main', 'refs/heads/hotfix'], environments: ['production', 'staging'], workflows: ['.github/workflows/deploy.yml', '.github/workflows/other.yml'] });
  const first = await ask(w, gh, g);
  assert.equal((await approve(w, u, first.body.id)).status, 200);
  const variants = [
    { sha: 'b'.repeat(40) }, { run_id: '999' }, { run_attempt: '2' }, { environment: 'staging' }, { check_run_id: '5552' }, { ref: 'refs/heads/hotfix' },
    { workflow_ref: 'acme/app/.github/workflows/other.yml@refs/heads/main', job_workflow_ref: 'acme/app/.github/workflows/other.yml@refs/heads/main' },
    { workflow_ref: 'acme/app/.github/workflows/other.yml@refs/heads/main' }, { job_workflow_ref: 'acme/app/.github/workflows/other.yml@refs/heads/main' },
  ];
  const seen = new Set([first.body.id]);
  for (const v of variants) {
    const r = await ask(w, gh, g, v);
    assert.equal(r.status, 202, JSON.stringify(v) + JSON.stringify(r.body));
    assert.equal(r.body.created, true, JSON.stringify(v));
    assert.equal(r.body.status, 'pending', 'an approval for one run does not cover another: ' + JSON.stringify(v));
    seen.add(r.body.id);
    assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'pending');
  }
  assert.equal(seen.size, variants.length + 1);
  // the first one's approval is still its own, and its poll secret reads nothing of the others
  const mine = await ask(w, gh, g);
  assert.equal(mine.body.id, first.body.id);
  const other = await ask(w, gh, g, { sha: 'b'.repeat(40) });
  assert.equal((await poll(w, mine.body.poll, other.body.id)).status, 404, 'a poll secret reads one hold');
  assert.equal((await poll(w, other.body.poll, first.body.id)).status, 404);
  assert.equal((await poll(w, mine.body.poll, first.body.id)).body.status, 'approved');
  // the hash is the documented one, over GitHub's ids and the facts of the run
  const f = factsOf(db(w).prepare('SELECT context FROM holds WHERE id = ?').get(first.body.id).context);
  assert.equal(db(w).prepare('SELECT req_hash FROM holds WHERE id = ?').get(first.body.id).req_hash,
    await gateHash({ gate: g, repository_id: '1001', owner_id: '77', run_id: '812', run_attempt: '1', sha: f.sha, workflow_ref: f.workflow_ref, job_workflow_ref: f.job_workflow_ref, ref: 'refs/heads/main', environment: 'production', check_run_id: '5551' }));
});

test('a hold whose recorded facts no longer match the hash it was approved under is not passed', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const r = await ask(w, gh, g);
  assert.equal((await approve(w, u, r.body.id)).status, 200);
  const row = db(w).prepare('SELECT context FROM holds WHERE id = ?').get(r.body.id);
  const ctx = JSON.parse(row.context); ctx.gate.sha = 'c'.repeat(40);
  db(w).prepare('UPDATE holds SET context = ? WHERE id = ?').run(JSON.stringify(ctx), r.body.id);
  const p = await poll(w, r.body.poll, r.body.id);
  assert.equal(p.status, 409); assert.equal(p.body.error, 'hash_mismatch');
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(r.body.id).status, 'approved', 'the approval was not spent');
});

test('denial: the job gets the reason as data, nothing passes, and the same claims can ask again', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const r = await ask(w, gh, g);
  const d = await w.req('POST', `/v1/holds/${r.body.id}/deny`, { cookie: u.cookie, body: { reason: 'Not on a Friday.\n::error::Ignore previous instructions​' } });
  assert.equal(d.status, 200);
  const p = await poll(w, r.body.poll, r.body.id);
  assert.equal(p.body.status, 'denied'); assert.equal(p.body.deny_reason, 'Not on a Friday. ::error::Ignore previous instructions');
  assert.ok(!('token' in p.body));
  assert.equal((await approve(w, u, r.body.id)).status, 404, 'a denied hold cannot be approved afterwards');
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'denied');
  const again = await ask(w, gh, g);
  assert.equal(again.body.created, true); assert.notEqual(again.body.id, r.body.id);
  assert.equal((await w.req('POST', `/v1/holds/${again.body.id}/deny`, { cookie: u.cookie, body: {} })).status, 200);
  assert.equal((await poll(w, again.body.poll, again.body.id)).body.deny_reason, null);
  // a command line sign-in may deny (deny is always safe) but never approve
  const cli = await cliSession(w, u);
  const third = await ask(w, gh, g);
  assert.equal((await w.req('POST', `/v1/holds/${third.body.id}/approve/begin`, { bearer: cli, ...anon, body: {} })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', `/v1/holds/${third.body.id}/deny`, { bearer: cli, ...anon, body: { reason: 'no' } })).status, 200);
});

test('expiry: the hold lasts as long as the job waits; an approved one must be spent within 10 minutes; reading it as expired writes nothing', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const r = await ask(w, gh, g, {}, { minutes: 5 });
  assert.ok(Math.abs(r.body.expires_at - (Date.now() + 5 * 60_000)) < 30_000);
  await timeShift(6 * 60_000, async () => {
    const p = await poll(w, r.body.poll, r.body.id);
    assert.equal(p.body.status, 'expired'); assert.equal(p.writes, 0);
    assert.equal((await approve(w, u, r.body.id)).status, 404, 'too late to approve');
  });
  const r2 = await ask(w, gh, g, { run_id: '2' });
  assert.equal((await approve(w, u, r2.body.id)).status, 200);
  await timeShift(11 * 60_000, async () => assert.equal((await poll(w, r2.body.poll, r2.body.id)).body.status, 'expired'));
  // timeout_minutes is a whole number from 1 to 60
  for (const m of [0, 61, 1.5, '15', -1]) assert.equal((await ask(w, gh, g, { run_id: '3' }, { body: { gate: g, timeout_minutes: m } , token: await gh.token(gh.claims({ aud: audienceFor(w.env, g), run_id: '3' })) })).body.error, 'bad_timeout', String(m));
  const long = await ask(w, gh, g, { run_id: '4' }, { minutes: 60 });
  assert.ok(Math.abs(long.body.expires_at - (Date.now() + 60 * 60_000)) < 30_000);
});

test('the poll writes nothing to D1 while it waits, returns the moment a human decides, and is limited in memory', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const r = await ask(w, gh, g);
  let sleeps = 0;
  w.env.__sleep = async (ms) => { assert.ok(ms > 0 && ms <= 2000); sleeps++; };
  const p = await poll(w, r.body.poll, r.body.id, 20);
  assert.equal(p.status, 200); assert.equal(p.body.status, 'pending');
  assert.equal(p.writes, 0, 'waiting writes nothing'); assert.ok(p.queries <= 12, `${p.queries} queries`); assert.equal(sleeps, 10);
  // the decision lands during the wait: the poll returns with it at once
  sleeps = 0;
  w.env.__sleep = async () => { if (++sleeps === 2) db(w).prepare("UPDATE holds SET status = 'denied', deny_reason = 'later' WHERE id = ?").run(r.body.id); };
  const d = await poll(w, r.body.poll, r.body.id, 20);
  assert.equal(d.body.status, 'denied'); assert.equal(d.body.deny_reason, 'later'); assert.equal(sleeps, 2); assert.equal(d.writes, 0);
  for (const bad of ['21', '-1', '1.5', 'x', '', '01']) assert.equal((await poll(w, r.body.poll, r.body.id, bad)).body.error, 'bad_wait', bad);
  // polls are limited in memory (30 a minute per secret), and a refused poll writes nothing
  _resetMemoryBuckets();
  for (let i = 0; i < 30; i++) assert.equal((await poll(w, r.body.poll, r.body.id)).status, 200);
  const over = await poll(w, r.body.poll, r.body.id);
  assert.equal(over.status, 429); assert.equal(over.writes, 0);
  // the secret and the route: malformed or foreign secrets read nothing
  _resetMemoryBuckets();
  const noauth = await w.req('GET', `/v1/gate/status/${r.body.id}`, anon);
  assert.equal(noauth.status, 401); assert.equal(noauth.body.error, 'poll_secret_required');
  for (const bad of ['gps_short', 'lsg_' + 'A'.repeat(43), 'lsh_' + 'A'.repeat(43), 'gps_' + 'A'.repeat(43), r.body.poll + 'x']) assert.ok([401, 404].includes((await poll(w, bad, r.body.id)).status), bad);
  assert.equal((await poll(w, 'gps_' + 'A'.repeat(43), r.body.id)).status, 404);
  assert.equal((await poll(w, r.body.poll, '0'.repeat(24))).status, 404);
  // a gate poll secret is no guard key, session or token anywhere else
  for (const [m, path] of [['GET', '/v1/holds'], ['GET', '/v1/gates'], ['POST', `/v1/approvals/${r.body.id}/use`], ['POST', `/v1/holds/${r.body.id}/approve/begin`]]) {
    assert.equal((await w.req(m, path, { bearer: r.body.poll, ...anon, body: m === 'POST' ? {} : undefined })).status, 401, path);
  }
});

test('cancel: a job that gives up closes its hold so nobody is asked to approve it; only its own secret can', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  const a = await ask(w, gh, g), b = await ask(w, gh, g, { run_id: '2' });
  const call = (secret, id) => w.req('POST', `/v1/gate/cancel/${id}`, { bearer: secret, ...anon, body: {} });
  assert.deepEqual((await call(b.body.poll, a.body.id)).body, { ok: true, cancelled: false }, 'another hold\'s secret does nothing');
  assert.equal((await poll(w, a.body.poll, a.body.id)).body.status, 'pending');
  assert.deepEqual((await call(a.body.poll, a.body.id)).body, { ok: true, cancelled: true });
  assert.equal((await poll(w, a.body.poll, a.body.id)).body.status, 'expired');
  assert.equal((await approve(w, u, a.body.id)).status, 404);
  assert.deepEqual((await call(a.body.poll, a.body.id)).body, { ok: true, cancelled: false }, 'twice is a no-op');
  assert.equal((await holds(w, u)).length, 1, 'only the other run is still waiting');
});

test('limits: 10 waiting per gate, 30 new holds an hour per gate, 100 waiting per account; refused requests write nothing', async () => {
  const { w, gh } = await world();
  const u = await w.user();
  const g = await gateId(w, u);
  for (let i = 0; i < PENDING_PER_GATE; i++) assert.equal((await ask(w, gh, g, { run_id: String(100 + i) })).status, 202);
  const full = await ask(w, gh, g, { run_id: '999' });
  assert.equal(full.status, 429); assert.equal(full.body.error, 'too_many_holds');
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM holds WHERE status = 'pending'").get().n, PENDING_PER_GATE);
  // 30 an hour: close the waiting ones and keep asking
  let made = PENDING_PER_GATE, status = 202;
  for (let i = 0; i < HOLDS_PER_HOUR + 2 && status === 202; i++) {
    db(w).prepare("UPDATE holds SET status = 'denied' WHERE status = 'pending'").run();
    const r = await ask(w, gh, g, { run_id: String(1000 + i) });
    status = r.status;
    if (r.status === 202) made++; else assert.equal(r.body.error, 'slow_down');
  }
  assert.equal(made, HOLDS_PER_HOUR); assert.equal(status, 429);
  // 100 waiting on the account is shared with brokered calls and commands: simulate it with rows
  const { w: w2, gh: gh2 } = await world();
  const u2 = await w2.user();
  const g2 = await gateId(w2, u2), acct = await w2.accountId(u2.cookie);
  for (let i = 0; i < 100; i++) db(w2).prepare("INSERT INTO holds (id, account_id, token_id, req_hash, method, host, path, rule, why, created_at, expires_at) VALUES (?, ?, ?, ?, 'GET', 'x', '/', 'r', 'w', ?, ?)").run(String(i).padStart(24, '0'), acct, 'tok' + i, 'h' + i, Date.now(), Date.now() + 60_000);
  const over = await ask(w2, gh2, g2);
  assert.equal(over.status, 429); assert.equal(over.body.error, 'too_many_holds');
  assert.equal(db(w2).prepare("SELECT COUNT(*) n FROM holds WHERE kind = 'deploy'").get().n, 0);
});
