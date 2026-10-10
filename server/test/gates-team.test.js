// Deploy Gate on a team (two-person seal): a deploy hold needs as many seals as the quorum, the gate's maker cannot seal
// what it asks for when self-approval is off, roles decide who makes and revokes a gate, a passkey must be the signed-in
// person's own, and removing or demoting the maker stops their gates (and what those handed out).
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { Authenticator, ORIGIN, RP_ID } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetOidc } from '../src/oidc.js';
import { anon, world, makeGate, gateId, ask, poll, approve, holds, db } from './gate-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetOidc(); });

async function founder(w, name = 'Gautam') {
  const u = await w.user(name);
  u.id = await w.accountId(u.cookie);
  u.member = u.id;
  return u;
}
async function add(w, owner, name, role = 'approver') {
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
  // a new approver's seal counts 24 hours after joining while one person cannot approve alone (tested in team.test.js)
  db(w).prepare('UPDATE members SET votes_from = 0 WHERE id = ?').run(me.member.id);
  return { cookie, auth, member: me.member.id, role: me.member.role, name };
}
async function ceremony(w, u, path, body = {}) {
  const b = await w.req('POST', path + '/begin', { cookie: u.cookie, body });
  if (b.status !== 200) return b;
  return w.req('POST', path + '/finish', { cookie: u.cookie, body: { ...body, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}
const setQuorum = async (w, u, quorum, selfApprove) => { const r = await ceremony(w, u, '/v1/team/quorum', { quorum, selfApprove }); assert.equal(r.status, 200, JSON.stringify(r.body)); return r; };
const POLICY = { allow: [{ method: 'GET', path: '/repos/acme/**' }, { method: 'DELETE', path: '/repos/acme/app/releases/*' }], unattendedIrreversible: [{ method: 'DELETE', path: '/repos/acme/app/releases/*' }], perMinute: 60 };
const vaultKey = async (w, u) => (await w.req('POST', '/v1/credentials', { cookie: u.cookie, body: { provider: 'github', secret: 'ghp_' + 'D'.repeat(36), label: 'deploy key' } })).body.id;
// the hold row: seals needed, and who "asked" (the gate's maker)
const holdRow = (w, id) => ({ ...db(w).prepare('SELECT needs, requested_by, status FROM holds WHERE id = ?').get(id) });

test('a deploy hold needs as many seals as the quorum: one seal is not enough, two let the job go on, once', async () => {
  const { w, gh } = await world();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben');
  await setQuorum(w, u, 2, true);
  const g = await gateId(w, u);
  const r = await ask(w, gh, g);
  assert.equal(r.status, 202, JSON.stringify(r.body));
  assert.deepEqual(holdRow(w, r.body.id), { needs: 2, requested_by: u.id, status: 'pending' });
  const h = (await holds(w, u))[0];
  assert.equal(h.needs, 2); assert.deepEqual(h.votes, []);
  const first = await approve(w, asha, r.body.id);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.approved, false); assert.equal(first.body.seals, 1); assert.equal(first.body.needs, 2);
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'pending', 'one seal does not let the job go on');
  assert.equal((await approve(w, asha, r.body.id)).body.error, 'already_sealed', 'the same person counts once');
  const second = await approve(w, ben, r.body.id);
  assert.equal(second.body.approved, true, JSON.stringify(second.body));
  const p = await poll(w, r.body.poll, r.body.id);
  assert.equal(p.body.status, 'approved');
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'used', 'once');
  // the audit and the receipts say the approval was reached by two different approvers, never who
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM hold_votes WHERE hold_id = ?").get(r.body.id).n, 2);
});

test('the quorum is read when the run asks: raising it afterwards also holds the waiting hold to the new number', async () => {
  const { w, gh } = await world();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben');
  const g = await gateId(w, u);
  const r = await ask(w, gh, g);
  assert.equal(holdRow(w, r.body.id).needs, 1);
  await setQuorum(w, u, 2, true);
  assert.equal((await approve(w, asha, r.body.id)).body.approved, false, 'the quorum in force now is two');
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'pending');
  assert.equal((await approve(w, ben, r.body.id)).body.approved, true);
});

test('with self-approval off, the person who made the gate cannot seal what it asks for; someone else can', async () => {
  const { w, gh } = await world();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben');
  const g = await gateId(w, asha);
  assert.equal(db(w).prepare('SELECT member_id FROM gates WHERE id = ?').get(g).member_id, asha.member);
  await setQuorum(w, u, 1, false);
  const r = await ask(w, gh, g);
  assert.equal(holdRow(w, r.body.id).requested_by, asha.member);
  assert.equal((await approve(w, asha, r.body.id)).body.error, 'own_request');
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'pending');
  assert.equal((await approve(w, ben, r.body.id)).body.approved, true);
  assert.equal((await poll(w, r.body.poll, r.body.id)).body.status, 'approved');
  // a gate the founder made has the founder as its maker (their member id is the account id)
  const gf = await gateId(w, u, { label: 'founder gate' });
  const r2 = await ask(w, gh, gf, { run_id: '900' });
  assert.equal(holdRow(w, r2.body.id).requested_by, u.id);
  assert.equal((await approve(w, u, r2.body.id)).body.error, 'own_request');
});

test('roles: a viewer makes nothing, a member makes a gate but cannot pre-approve, and a passkey must be the signed-in person\'s own', async () => {
  const { w } = await world();
  const u = await founder(w);
  const viewer = await add(w, u, 'Vera', 'viewer'), member = await add(w, u, 'Max', 'member'), asha = await add(w, u, 'Asha');
  const cred = await vaultKey(w, u);
  const vb = await w.req('POST', '/v1/gates/passkey/begin', { cookie: viewer.cookie, body: {} });
  assert.equal(vb.status, 403); assert.equal(vb.body.error, 'role_required');
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM gates').get().n, 0);
  assert.equal((await makeGate(w, member)).status, 200, 'a member may make a gate (it asks; it cannot approve itself)');
  // pre-approving irreversible calls is approving in advance: an owner or approver, as for a token
  const mb = await w.req('POST', '/v1/gates/passkey/begin', { cookie: member.cookie, body: {} });
  const mf = await w.req('POST', '/v1/gates/passkey/finish', { cookie: member.cookie, body: { challengeId: mb.body.challengeId, credential: await member.auth.get(mb.body.options), label: 'pre', repository: 'acme/app', workflows: ['.github/workflows/deploy.yml'], refs: ['refs/heads/main'], credentialId: cred, policy: POLICY } });
  assert.equal(mf.status, 403); assert.equal(mf.body.error, 'role_required');
  const okApprover = await makeGate(w, asha, { credentialId: cred, policy: POLICY });
  assert.equal(okApprover.status, 200, JSON.stringify(okApprover.body));
  assert.equal(okApprover.body.member_id, asha.member);
  // another person's passkey cannot make a gate in your name, even in your browser
  const b = await w.req('POST', '/v1/gates/passkey/begin', { cookie: asha.cookie, body: {} });
  const cross = await w.req('POST', '/v1/gates/passkey/finish', { cookie: asha.cookie, body: { challengeId: b.body.challengeId, credential: await member.auth.get(b.body.options), label: 'x', repository: 'acme/app', workflows: ['.github/workflows/deploy.yml'], refs: ['refs/heads/main'] } });
  assert.equal(cross.status, 401); assert.equal(cross.body.error, 'unknown_passkey');
  // with two seals required, nobody pre-approves alone
  await setQuorum(w, u, 2, true);
  const blocked = await makeGate(w, asha, { label: 'blocked', credentialId: cred, policy: POLICY });
  assert.equal(blocked.status, 409); assert.equal(blocked.body.error, 'quorum_blocks_preapproval');
  assert.equal((await makeGate(w, asha, { label: 'plain', credentialId: cred, policy: { allow: [{ method: 'GET', path: '/repos/acme/**' }], perMinute: 60 } })).status, 200, 'a key without pre-approvals is fine');
});

test('a pre-approval in a gate\'s policy pauses when the team needs two seals later: the token\'s irreversible call is held', async () => {
  const { w, gh } = await world();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben');
  const cred = await vaultKey(w, u);
  const g = await gateId(w, u, { credentialId: cred, policy: POLICY });
  const run = async (id, extra = {}) => {
    const r = await ask(w, gh, g, { run_id: id, ...extra });
    assert.equal((await approve(w, u, r.body.id)).body.approved, true);
    return (await poll(w, r.body.poll, r.body.id)).body.token;
  };
  const tok = await run('1');
  assert.equal(db(w).prepare('SELECT member_id FROM tokens WHERE minted_by = ?').get('gate').member_id, u.id);
  const del = (t) => w.req('DELETE', '/p/github/repos/acme/app/releases/5', { bearer: t, ...anon });
  assert.equal((await del(tok)).status, 200, 'pre-approved while one seal is enough');
  await setQuorum(w, u, 2, true);
  const held = await del(tok);
  assert.equal(held.status, 428, JSON.stringify(held.body));
  assert.equal(held.body.error, 'held_for_approval');
  void asha; void ben;
});

test('revoking a gate: its maker or an owner; another approver freezes instead; a viewer cannot', async () => {
  const { w } = await world();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben'), viewer = await add(w, u, 'Vera', 'viewer');
  const g1 = await gateId(w, asha), g2 = await gateId(w, asha, { label: 'second' });
  const del = (who, id) => w.req('DELETE', `/v1/gates/${id}`, { cookie: who.cookie });
  const no = await del(ben, g1);
  assert.equal(no.status, 403); assert.equal(no.body.error, 'role_required');
  assert.equal((await del(viewer, g1)).status, 403);
  assert.equal(db(w).prepare('SELECT revoked FROM gates WHERE id = ?').get(g1).revoked, 0);
  assert.equal((await del(asha, g1)).status, 200, 'its maker');
  assert.equal((await del(u, g2)).status, 200, 'an owner');
  assert.equal((await del(u, g2)).status, 404, 'twice is not found');
  const list = (await w.req('GET', '/v1/gates', { cookie: viewer.cookie })).body.gates;
  assert.equal(list.length, 2, 'everyone on the team reads the list');
  assert.ok(list.every((x) => x.member_id === asha.member));
});

test('removing the person who made a gate stops it: its waiting hold closes, the key it handed out is revoked, and new runs find nothing', async () => {
  const { w, gh } = await world();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben');
  const cred = await vaultKey(w, u);
  const g = await gateId(w, asha, { credentialId: cred, policy: { allow: [{ method: 'GET', path: '/repos/acme/**' }], perMinute: 60 } });
  const first = await ask(w, gh, g, { run_id: '1' });
  assert.equal((await approve(w, ben, first.body.id)).body.approved, true);
  const got = await poll(w, first.body.poll, first.body.id);
  assert.match(got.body.token, /^lsh_/);
  const waiting = await ask(w, gh, g, { run_id: '2' });
  assert.equal(waiting.body.status, 'pending');
  const rm = await ceremony(w, u, `/v1/team/members/${asha.member}/remove`);
  assert.equal(rm.status, 200, JSON.stringify(rm.body));
  assert.equal(rm.body.revoked.gates, 1);
  assert.equal(rm.body.revoked.tokens, 1, 'the token the gate handed out');
  assert.equal(rm.body.revoked.holds, 1, 'the run that was waiting');
  assert.equal(db(w).prepare('SELECT revoked FROM gates WHERE id = ?').get(g).revoked, 1);
  assert.equal((await poll(w, waiting.body.poll, waiting.body.id)).body.status, 'expired');
  assert.equal((await w.req('GET', '/p/github/repos/acme/app', { bearer: got.body.token, ...anon })).body.error, 'token_invalid');
  assert.equal((await ask(w, gh, g, { run_id: '3' })).body.error, 'gate_not_found');
});

test('demoting the person who made a gate to viewer stops it too; demoting to member does not', async () => {
  const { w, gh } = await world();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben');
  const g = await gateId(w, asha);
  const g2 = await gateId(w, ben);
  const waiting = await ask(w, gh, g, { run_id: '2' });
  const toMember = await ceremony(w, u, `/v1/team/members/${asha.member}/role`, { role: 'member' });
  assert.equal(toMember.status, 200, JSON.stringify(toMember.body));
  assert.equal(db(w).prepare('SELECT revoked FROM gates WHERE id = ?').get(g).revoked, 0, 'a member may still make gates');
  const toViewer = await ceremony(w, u, `/v1/team/members/${asha.member}/role`, { role: 'viewer' });
  assert.equal(toViewer.status, 200, JSON.stringify(toViewer.body));
  assert.equal(toViewer.body.revoked.gates, 1);
  assert.equal(db(w).prepare('SELECT revoked FROM gates WHERE id = ?').get(g).revoked, 1);
  assert.equal(db(w).prepare('SELECT revoked FROM gates WHERE id = ?').get(g2).revoked, 0, 'somebody else\'s gate is untouched');
  assert.equal((await poll(w, waiting.body.poll, waiting.body.id)).body.status, 'expired');
});

test('a viewer can deny a deploy but not seal it; the card shows the seals so far', async () => {
  const { w, gh } = await world();
  const u = await founder(w);
  const asha = await add(w, u, 'Asha'), viewer = await add(w, u, 'Vera', 'viewer');
  await add(w, u, 'Ben');
  await setQuorum(w, u, 2, true);
  const g = await gateId(w, u);
  const r = await ask(w, gh, g);
  assert.equal((await approve(w, viewer, r.body.id)).body.error, 'role_required');
  await approve(w, asha, r.body.id);
  const h = (await holds(w, viewer))[0];
  assert.equal(h.needs, 2); assert.equal(h.votes.length, 1); assert.equal(h.votes[0].name, 'Asha');
  const deny = await w.req('POST', `/v1/holds/${r.body.id}/deny`, { cookie: viewer.cookie, body: { reason: 'wrong week' } });
  assert.equal(deny.status, 200, JSON.stringify(deny.body));
  const p = await poll(w, r.body.poll, r.body.id);
  assert.equal(p.body.status, 'denied'); assert.equal(p.body.deny_reason, 'wrong week');
});
