// Break-glass windows (two-person seal, part 2b): who may open one and how, what it lets through and what it never does,
// how it ends, how the team is told, what the receipts say, and the D1 budget of the hot path.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { sweep } from '../src/index.js';
import { world, gateId, ask as ask2, poll as pollGate } from './gate-helpers.js';
import { anon, db, HOUR, DAY, timeShift, withVapid, device, founder, add, ceremony, setQuorum, seal, vault, makeToken, del, heldCall, openWindow, ask, guardKey, create, use, receipts, CMD } from './bg-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });
const closeWindow = (w, u, id) => w.req('DELETE', `/v1/team/breakglass/${id}`, { cookie: u.cookie });
const team = async (w, u) => (await w.req('GET', '/v1/team', { cookie: u.cookie })).body;
const open = async (w, u, body, over) => { const r = await openWindow(w, u, body, over); assert.equal(r.status, 200, JSON.stringify(r.body)); return r.body; };

test('an approver opens a window with a passkey: it lists who, why and until when, and wakes every other member', async () => {
  const w = new World();
  await withVapid(w);
  const u = await founder(w), asha = await add(w, u, 'Asha');
  await device(w, u, 'founder-phone'); await device(w, asha, 'asha-phone');
  w.pushes = [];
  const t0 = Date.now();
  const r = await openWindow(w, asha);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.match(r.body.id, /^[0-9a-f]{24}$/); assert.equal(r.body.scope, null);
  assert.ok(Math.abs(r.body.expires_at - (t0 + 30 * 60_000)) < 5_000);
  assert.deepEqual(w.pushes, ['https://fcm.googleapis.com/fcm/send/founder-phone'], 'everyone but the opener');
  const t = await team(w, u);
  assert.equal(t.windows.length, 1);
  assert.deepEqual([t.windows[0].opened_by_name, t.windows[0].reason, t.windows[0].scope], ['Asha', 'prod is down, second approver asleep', null]);
  assert.deepEqual(t.breakglass, { minMinutes: 5, maxMinutes: 60, perDay: 3 });
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.breakglass.length, 1, 'the banner reads it from /v1/me');
  const alerts = (await w.req('GET', '/v1/alerts', { cookie: u.cookie })).body.team;
  assert.deepEqual(alerts.filter((a) => a.kind.startsWith('breakglass')).map((a) => [a.kind, a.minutes]), [['breakglass_opened', 30]]);
  const a = JSON.parse(db(w).prepare("SELECT detail FROM audit WHERE action = 'breakglass_opened'").get().detail);
  assert.deepEqual([a.by, a.minutes, a.scope], [asha.member, 30, 'all']);
  // closing: any member in any session
  const viewer = await add(w, u, 'Vera', 'viewer');
  assert.equal((await closeWindow(w, viewer, r.body.id)).status, 200);
  assert.equal((await closeWindow(w, viewer, r.body.id)).status, 404);
  assert.equal((await team(w, u)).windows.length, 0);
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM audit WHERE action = 'breakglass_closed'").get().n, 1);
});

test('who may open one, and the shape of the request: owner or approver, web, fresh passkey, 5 to 60 minutes, a reason', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha'), max = await add(w, u, 'Max', 'member'), vera = await add(w, u, 'Vera', 'viewer');
  const cred = await vault(w, u);
  for (const who of [max, vera]) assert.equal((await w.req('POST', '/v1/team/breakglass/begin', { cookie: who.cookie, body: { minutes: 30, reason: 'x y z' } })).body.error, 'role_required');
  // a command line session never opens one
  const d = await w.req('POST', '/v1/device/start', { body: {}, ...anon, ip: '198.51.100.9' });
  const ab = await w.req('POST', '/v1/device/approve/begin', { cookie: u.cookie, body: { user_code: d.body.user_code } });
  await w.req('POST', '/v1/device/approve/finish', { cookie: u.cookie, body: { user_code: d.body.user_code, challengeId: ab.body.challengeId, credential: await u.auth.get(ab.body.options) } });
  const cli = (await w.req('POST', '/v1/device/poll', { body: { device_code: d.body.device_code }, ...anon })).body.access_token;
  assert.equal((await w.req('POST', '/v1/team/breakglass/begin', { bearer: cli, ...anon, body: { minutes: 30, reason: 'x y z' } })).body.error, 'passkey_required');
  const bad = [
    [{ minutes: 4 }, 'bad_minutes'], [{ minutes: 61 }, 'bad_minutes'], [{ minutes: 30.5 }, 'bad_minutes'], [{ minutes: '30' }, 'bad_minutes'], [{ minutes: undefined }, 'bad_minutes'],
    [{ reason: '' }, 'bad_reason'], [{ reason: 'ab' }, 'bad_reason'], [{ reason: 5 }, 'bad_reason'], [{ reason: undefined }, 'bad_reason'], [{ reason: 'x'.repeat(801) }, 'bad_reason'],
    [{ extend: true }, 'bad_field'], [{ tokenId: 'nope' }, 'bad_tokenId'], [{ tokenId: '0'.repeat(24) }, 'not_found'],
  ];
  for (const [over, code] of bad) {
    const r = await w.req('POST', '/v1/team/breakglass/begin', { cookie: asha.cookie, body: { minutes: 30, reason: 'prod is down', ...over } });
    assert.equal(r.body.error, code, JSON.stringify(over));
  }
  // a token of another account is no scope
  const v = await founder(w, 'Eve'); const vc = await vault(w, v); const theirs = await makeToken(w, v, vc, 'theirs');
  assert.equal((await w.req('POST', '/v1/team/breakglass/begin', { cookie: asha.cookie, body: { minutes: 30, reason: 'prod is down', tokenId: theirs.id } })).body.error, 'not_found');
  // 60 minutes is the most; 5 the least; the reason is cleaned and kept to 200 characters
  const ok = await open(w, asha, { minutes: 60, reason: '  line one\n\tline two  ' + 'y'.repeat(300) });
  assert.equal(db(w).prepare('SELECT reason FROM windows WHERE id = ?').get(ok.id).reason.length, 200);
  assert.ok(!/[\n\t]/.test(db(w).prepare('SELECT reason FROM windows WHERE id = ?').get(ok.id).reason));
  assert.ok(Math.abs(ok.expires_at - (Date.now() + 60 * 60_000)) < 5_000);
  // the passkey must be the opener's own, and it approves exactly what was asked
  await closeWindow(w, asha, ok.id);
  const b = await w.req('POST', '/v1/team/breakglass/begin', { cookie: asha.cookie, body: { minutes: 5, reason: 'short one' } });
  const other = await w.req('POST', '/v1/team/breakglass/finish', { cookie: asha.cookie, body: { minutes: 5, reason: 'short one', challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(other.body.error, 'unknown_passkey', "someone else's passkey is no consent");
  const b2 = await w.req('POST', '/v1/team/breakglass/begin', { cookie: asha.cookie, body: { minutes: 5, reason: 'short one' } });
  const bigger = await w.req('POST', '/v1/team/breakglass/finish', { cookie: asha.cookie, body: { minutes: 60, reason: 'a different reason', challengeId: b2.body.challengeId, credential: await asha.auth.get(b2.body.options) } });
  assert.equal(bigger.status, 200);
  assert.equal(db(w).prepare('SELECT reason FROM windows WHERE id = ?').get(bigger.body.id).reason, 'short one', 'what the passkey approved, not what finish says');
  assert.ok(bigger.body.expires_at < Date.now() + 6 * 60_000);
  void cred;
});

test('one at a time, three a day, never extended; a freeze stops it and a new one; a new approver cannot open one while two seals are required', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha');
  const first = await open(w, u);
  assert.equal((await openWindow(w, asha)).body.error, 'window_open', 'a window cannot be extended or doubled');
  await closeWindow(w, u, first.id);
  const second = await open(w, u); await closeWindow(w, u, second.id);
  const third = await open(w, asha); await closeWindow(w, asha, third.id);
  const fourth = await openWindow(w, u);
  assert.equal(fourth.status, 429); assert.equal(fourth.body.error, 'too_many_windows');
  // a day later there is room again
  db(w).prepare('UPDATE windows SET opened_at = opened_at - ?, expires_at = expires_at - ?').run(DAY + 1000, DAY + 1000);
  assert.equal((await openWindow(w, u)).status, 200);
  // a freeze: nothing opens, and an open one stops letting calls through (tested below)
  const w2 = new World();
  const a = await founder(w2);
  assert.equal((await w2.req('POST', '/v1/me/freeze', { cookie: a.cookie, body: {} })).status, 200);
  assert.equal((await openWindow(w2, a)).body.error, 'account_frozen');
  // while one person cannot approve alone, a new approver's seal does not count for 24 hours, and neither does their window
  const w3 = new World();
  const o = await founder(w3), n1 = await add(w3, o, 'Ann'), n2 = await add(w3, o, 'Bea');
  await setQuorum(w3, o, 2, true);
  const fresh = await add(w3, o, 'Fred', 'approver', { seasoned: false });
  const r = await openWindow(w3, fresh);
  assert.equal(r.status, 403); assert.equal(r.body.error, 'seal_not_yet');
  assert.equal((await openWindow(w3, n1)).status, 200, 'a seasoned approver may, with the whole team told');
  void n2;
});

test('what a window lets through: the held calls of the token it names (or all), flagged in the log and the receipt, until it ends', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha');
  db(w).prepare('UPDATE accounts SET receipts = 1').run();
  const cred = await vault(w, u);
  const a = await makeToken(w, u, cred, 'agent a'), b = await makeToken(w, u, cred, 'agent b');
  assert.equal((await del(w, a.token)).status, 428);
  assert.equal((await del(w, b.token)).status, 428);
  const held = db(w).prepare("SELECT COUNT(*) n FROM holds WHERE status = 'pending'").get().n;
  // a window for token a only
  const win = await open(w, asha, { tokenId: a.id });
  assert.deepEqual((await team(w, u)).windows[0].scope, { token_id: a.id, label: 'agent a' });
  const up = w.upstream.length;
  const through = await del(w, a.token, '/repos/acme/other');
  assert.equal(through.status, 200, JSON.stringify(through.body));
  assert.equal(w.upstream.length, up + 1, 'it reached the provider');
  assert.equal(w.upstream.at(-1).headers.authorization, 'Bearer ' + 'ghp_' + 'T'.repeat(36), 'with the real key, as any allowed call');
  assert.equal((await del(w, b.token, '/repos/acme/other')).status, 428, 'another token is not covered');
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM holds WHERE status = 'pending'").get().n, held + 1, 'only the other token held something new');
  const d = JSON.parse(db(w).prepare("SELECT detail FROM audit WHERE action = 'proxy' ORDER BY seq DESC LIMIT 1").get().detail);
  assert.equal(d.breakglass, win.id); assert.match(d.rule, /:breakglass$/);
  const rc = (await receipts(w)).filter((r) => r.decision === 'allowed' && r.meta.breakglass);
  assert.equal(rc.length, 1, 'the public receipt says breakglass');
  assert.deepEqual(Object.keys(rc[0].meta).sort(), ['breakglass', 'map', 'rule'].sort());
  assert.ok(!JSON.stringify(rc[0]).includes(win.id), 'and nothing else about the window');
  // closed: held again
  await closeWindow(w, u, win.id);
  assert.equal((await del(w, a.token, '/repos/acme/again')).status, 428);
  // for all tokens, until it expires
  const all = await open(w, u, { minutes: 10 });
  assert.equal((await del(w, b.token, '/repos/acme/b1')).status, 200);
  assert.equal((await del(w, a.token, '/repos/acme/a1')).status, 200);
  await timeShift(11 * 60_000, async () => assert.equal((await del(w, b.token, '/repos/acme/b2')).status, 428, 'exactly its expiry'));
  void all;
  // reads and ordinary writes are not affected: a window is only about what would be held
  assert.equal((await w.req('GET', '/p/github/user', { bearer: a.token, ...anon })).status, 200);
});

test('what a window never does: a freeze, a brake, the opener\'s own token with self-approval off, or a demoted opener', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben');
  const cred = await vault(w, u);
  const mine = await makeToken(w, asha, cred, 'asha agent'), theirs = await makeToken(w, ben, cred, 'ben agent');
  await open(w, asha);
  // self-approval on: her own token goes through
  assert.equal((await del(w, mine.token, '/repos/acme/x1')).status, 200);
  await setQuorum(w, u, 1, false);
  assert.equal((await del(w, mine.token, '/repos/acme/x2')).status, 428, 'with self-approval off, not what the opener\'s own token asks for');
  assert.equal((await del(w, theirs.token, '/repos/acme/x3')).status, 200, 'someone else\'s token is covered');
  // and she cannot name her own token as the scope
  const w2 = new World();
  const u2 = await founder(w2), a2 = await add(w2, u2, 'Asha'); await add(w2, u2, 'Ben');
  const c2 = await vault(w2, u2); const t2 = await makeToken(w2, a2, c2, 'asha agent');
  await setQuorum(w2, u2, 1, false);
  const own = await openWindow(w2, a2, { tokenId: t2.id });
  assert.equal(own.status, 403); assert.equal(own.body.error, 'own_request');
  // a tripped breaker is a brake: the window does not lift it
  const w3 = new World();
  const u3 = await founder(w3); const c3 = await vault(w3, u3); const t3 = await makeToken(w3, u3, c3, 'looping');
  await open(w3, u3);
  db(w3).prepare('UPDATE tokens SET tripped_at = ?, tripped_why = ? WHERE id = ?').run(Date.now(), 'too many writes', t3.id);
  const tr = await w3.req('POST', '/p/github/repos/acme/app/issues', { bearer: t3.token, ...anon, body: { title: 'x' } });
  assert.equal(tr.status, 428, JSON.stringify(tr.body)); assert.equal(tr.body.rule, 'brake.tripped');
  // a freeze stops everything whatever a window says
  const w4 = new World();
  const u4 = await founder(w4); const c4 = await vault(w4, u4); const t4 = await makeToken(w4, u4, c4, 'agent');
  await open(w4, u4);
  assert.equal((await del(w4, t4.token)).status, 200);
  await w4.req('POST', '/v1/me/freeze', { cookie: u4.cookie, body: {} });
  assert.equal((await del(w4, t4.token, '/repos/acme/z')).status, 423);
  // the opener demoted: the window no longer applies (it stops being one person's decision)
  const w5 = new World();
  const u5 = await founder(w5), a5 = await add(w5, u5, 'Asha'); await add(w5, u5, 'Ben');
  const c5 = await vault(w5, u5); const t5 = await makeToken(w5, u5, c5, 'agent');
  await open(w5, a5);
  assert.equal((await del(w5, t5.token, '/repos/acme/ok')).status, 200);
  assert.equal((await ceremony(w5, u5, `/v1/team/members/${a5.member}/role`, { role: 'member' })).status, 200);
  assert.equal((await del(w5, t5.token, '/repos/acme/after')).status, 428, 'her window ended with her role');
});

test('a guard key asks during a window: the answer is the approval, once, on the record', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha');
  db(w).prepare('UPDATE accounts SET receipts = 1').run();
  const k = await guardKey(w, u);
  const pending = await create(w, k.key, ask({ summary: 'terraform destroy a' , detail: 'terraform destroy a' }));
  assert.equal(pending.status, 202, 'before the window it waits');
  const win = await open(w, asha);
  const got = await create(w, k.key);
  assert.equal(got.status, 200, JSON.stringify(got.body));
  assert.equal(got.body.status, 'approved'); assert.equal(got.body.breakglass, true);
  assert.equal(db(w).prepare('SELECT status, needs FROM holds WHERE id = ?').get(got.body.id).status, 'approved');
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM hold_votes WHERE hold_id = ?').get(got.body.id).n, 0, 'no seal was needed, and none is claimed');
  assert.ok(Math.abs(got.body.expires_at - (Date.now() + 10 * 60_000)) < 5_000, 'used once within 10 minutes, like any approval');
  const used = await use(w, k.key, got.body.id, got.body.hash);
  assert.equal(used.status, 200);
  assert.equal((await use(w, k.key, got.body.id, got.body.hash)).body.error, 'already_used');
  const a = JSON.parse(db(w).prepare("SELECT detail FROM audit WHERE action = 'run_approved'").get().detail);
  assert.equal(a.breakglass, win.id);
  const rc = (await receipts(w)).filter((r) => r.meta.breakglass);
  assert.equal(rc.length, 1); assert.equal(rc[0].decision, 'executed');
  // the hold that was already waiting stays waiting: a window does not approve what asked before it
  assert.equal(db(w).prepare("SELECT status FROM holds WHERE id = ?").get(pending.body.id).status, 'pending');
  // closed: asking waits again
  await closeWindow(w, u, win.id);
  assert.equal((await create(w, k.key, ask({ summary: 'terraform destroy b', detail: 'terraform destroy b' }))).status, 202);
  // a window scoped to one guard key
  const k2 = await guardKey(w, u, 'second'); const k3 = await guardKey(w, u, 'third');
  await open(w, u, { tokenId: k2.id });
  assert.equal((await create(w, k2.key, ask({ summary: 'c', detail: 'c' }))).status, 200);
  assert.equal((await create(w, k3.key, ask({ summary: 'd', detail: 'd' }))).status, 202);
  void CMD;
});

test('a deploy gate is never opened by a window: the job waits for the approval as before', async () => {
  const { w, gh } = await world();
  const u = await founder(w);
  const g = await gateId(w, u);
  await open(w, u);
  const r = await ask2(w, gh, g);
  assert.equal(r.status, 202, JSON.stringify(r.body));
  assert.equal(r.body.status, 'pending');
  assert.equal((await pollGate(w, r.body.poll, r.body.id)).body.status, 'pending');
  assert.equal(db(w).prepare("SELECT status FROM holds WHERE id = ?").get(r.body.id).status, 'pending');
});

test('the D1 budget: a call no window concerns costs nothing more, and a held call one read at most', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha');
  const cred = await vault(w, u);
  const t = await makeToken(w, u, cred, 'agent');
  w.env.DB.cap = 50;
  const held = await del(w, t.token);
  const base = held.queries;
  assert.ok(base <= 35, `${base} queries for a held call`);
  const other = await del(w, t.token, '/repos/acme/same-again');
  const noWindow = other.queries;
  await open(w, asha, { minutes: 10 });
  const during = await del(w, t.token, '/repos/acme/third');
  assert.equal(during.status, 200);
  assert.ok(during.queries <= noWindow + 6, `${during.queries} queries for a call a window let through (a held one: ${noWindow})`);
  const ok = await w.req('GET', '/p/github/user', { bearer: t.token, ...anon });
  assert.ok(ok.queries <= 12, `${ok.queries} queries for an allowed read while a window is open`);
  const o = await w.req('POST', '/v1/team/breakglass/begin', { cookie: u.cookie, body: { minutes: 5, reason: 'budget' } });
  assert.equal(o.body.error, 'window_open');
  w.env.DB.cap = 0;
});

test('the sweep keeps a week of windows, and accounts delete with them', async () => {
  const w = new World();
  const u = await founder(w);
  const win = await open(w, u);
  db(w).prepare('UPDATE windows SET expires_at = ? WHERE id = ?').run(Date.now() - 8 * DAY, win.id);
  await sweep(w.env);
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM windows').get().n, 0);
  const win2 = await open(w, u);
  const del1 = await ceremony(w, u, '/v1/me/delete', { confirm: 'delete' });
  assert.equal(del1.status, 200, JSON.stringify(del1.body));
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM windows WHERE id = ?').get(win2.id).n, 0, 'gone with the account');
  void HOUR;
});

test('quorum 2: a window lets one approver\'s emergency through, announced to everyone; the seal rules are otherwise untouched', async () => {
  const w = new World();
  await withVapid(w);
  const u = await founder(w), asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben');
  await device(w, u, 'founder-phone'); await device(w, ben, 'ben-phone');
  await setQuorum(w, u, 2, true);
  const cred = await vault(w, u);
  const h = await heldCall(w, u, cred, '/repos/acme/one');
  assert.equal((await seal(w, asha, h.hold)).body.approved, false);
  w.pushes = [];
  await open(w, asha);
  assert.deepEqual(w.pushes.sort(), ['https://fcm.googleapis.com/fcm/send/ben-phone', 'https://fcm.googleapis.com/fcm/send/founder-phone'], 'both other members were woken');
  const t2 = await makeToken(w, u, cred, 'second');
  assert.equal((await del(w, t2.token, '/repos/acme/two')).status, 200, 'one approver let it through, and it says so');
  // the hold from before the window still needs its second seal
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(h.hold).status, 'pending');
  assert.equal((await seal(w, ben, h.hold)).body.approved, true);
});
