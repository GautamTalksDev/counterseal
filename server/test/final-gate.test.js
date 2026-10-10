// The final security gate before launch (9 Oct 2026): the joints between features built in parallel. Each test here
// failed before its fix.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { world, gateId, ask as askGate } from './gate-helpers.js';
import { anon, db, founder, add, ceremony, vault, makeToken, del, openWindow, guardKey, create } from './bg-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });

test('a freeze closes an open break-glass window: after the unfreeze, held calls are held again', async () => {
  const w = new World();
  const u = await founder(w);
  const cred = await vault(w, u);
  const t = await makeToken(w, u, cred, 'agent');
  const g = await guardKey(w, u);
  const win = await openWindow(w, u);
  assert.equal(win.status, 200, JSON.stringify(win.body));
  assert.equal((await del(w, t.token, '/repos/acme/before')).status, 200, 'the window lets it through');
  assert.equal((await w.req('POST', '/v1/me/freeze', { cookie: u.cookie, body: {} })).status, 200);
  const un = await ceremony(w, u, '/v1/me/unfreeze');
  assert.equal(un.status, 200, JSON.stringify(un.body));
  assert.equal((await del(w, t.token, '/repos/acme/after')).status, 428, 'the window ended with the freeze');
  const a = await create(w, g.key);
  assert.equal(a.status, 202, JSON.stringify(a.body)); assert.equal(a.body.status, 'pending', 'a guard ask waits for a person again');
  const row = db(w).prepare('SELECT closed_at, closed_by FROM windows WHERE id = ?').get(win.body.id);
  assert.ok(row.closed_at, 'closed'); assert.equal(row.closed_by, u.member);
  assert.equal((await w.req('GET', '/v1/team', { cookie: u.cookie })).body.windows.length, 0, 'no banner either');
  const fr = JSON.parse(db(w).prepare("SELECT detail FROM audit WHERE action = 'freeze'").get().detail);
  assert.equal(fr.closed_windows, 1, 'on the record');
});

test('break glass never lifts a token\'s own hold rules, default or allow list: only what the map holds', async () => {
  const w = new World();
  const u = await founder(w);
  const cred = await vault(w, u);
  const mint = async (label, policy) => { const r = await w.req('POST', '/v1/tokens', { cookie: u.cookie, body: { credentialId: cred, label, policy } }); assert.equal(r.status, 200, JSON.stringify(r.body)); return r.body; };
  // the owner's own rule: every issue comment waits for a person, whatever happens
  const ruled = await mint('ruled', { hold: [{ method: 'POST', path: '/repos/*/*/issues/*/comments' }] });
  // a token whose default is to hold anything off its allow list
  const listed = await mint('listed', { allow: [{ method: 'GET', path: '/**' }], default: 'hold' });
  // a token that may only read: a delete is not on its allow list (default allow: off the list is denied)
  const reader = await mint('reader', { allow: [{ method: 'GET', path: '/**' }] });
  const plain = await mint('plain', undefined);
  assert.equal((await openWindow(w, u)).status, 200);
  const c1 = await w.req('POST', '/p/github/repos/acme/app/issues/1/comments', { bearer: ruled.token, ...anon, body: { body: 'hi' } });
  assert.equal(c1.status, 428, JSON.stringify(c1.body)); assert.equal(c1.body.rule, 'policy.hold');
  const c2 = await w.req('POST', '/p/github/repos/acme/app/issues', { bearer: listed.token, ...anon, body: { title: 'x' } });
  assert.equal(c2.status, 428, JSON.stringify(c2.body)); assert.equal(c2.body.rule, 'policy.default');
  // the map holds these deletes; the window may only let one through when the token's own policy would allow it
  assert.equal((await del(w, listed.token, '/repos/acme/a')).status, 428, 'off the allow list, default hold');
  assert.equal((await del(w, reader.token, '/repos/acme/b')).status, 428, 'off the allow list of a read token');
  assert.equal((await del(w, plain.token, '/repos/acme/c')).status, 200, 'a token whose policy allows it: let through');
  assert.ok(!db(w).prepare("SELECT detail FROM audit WHERE action = 'proxy'").all().some((r) => /policy\.(hold|default|allowlist):breakglass/.test(r.detail)));
});

test('revoking a gate: only its maker or an owner, and someone else\'s refused revoke closes nothing', async () => {
  const { w, gh } = await world();
  const u = await founder(w);
  const mia = await add(w, u, 'Mia', 'member'), max = await add(w, u, 'Max', 'member');
  const gate = await gateId(w, mia);
  const r = await askGate(w, gh, gate);
  assert.equal(r.status, 202, JSON.stringify(r.body));
  const no = await w.req('DELETE', `/v1/gates/${gate}`, { cookie: max.cookie });
  assert.equal(no.status, 403, JSON.stringify(no.body));
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(r.body.id).status, 'pending', 'Mia\'s deploy still waits for a decision');
  const yes = await w.req('DELETE', `/v1/gates/${gate}`, { cookie: mia.cookie });
  assert.equal(yes.status, 200); assert.equal(yes.body.closed, 1);
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(r.body.id).status, 'expired');
});

// ---------------------------------------------------------------- denial of wallet (Workers Free budgets are shared by every tenant)
test('reported receipts can never use up what the broker\'s own decisions need: per account, and across accounts', async () => {
  const sealed = async (w) => (await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries.filter((e) => e.entry.source === 'broker').length;
  const send = (w, key, n) => w.req('POST', '/v1/receipts', { bearer: key, ...anon, body: { receipts: Array.from({ length: n }, (_, i) => ({ agent: 'junk', action: 'a' + i })) } });
  // an agent with a receipts key fills its own account's day: the account's decisions are still sealed (no "receipts off"
  // without a passkey)
  const w = new World();
  w.env.ACCOUNT_DAILY_CAP = '3';
  const u = await founder(w);
  db(w).prepare('UPDATE accounts SET receipts = 1').run();
  const key = (await w.req('POST', '/v1/keys', { cookie: u.cookie, body: {} })).body.key;
  assert.equal((await send(w, key, 3)).status, 200);
  assert.equal((await send(w, key, 1)).status, 402, 'reported receipts stop at the account\'s cap');
  const cred = await vault(w, u); const t = await makeToken(w, u, cred, 'agent');
  for (const p of ['/a', '/b']) assert.equal((await del(w, t.token, '/repos/acme' + p)).status, 428);
  assert.equal(await sealed(w), 2, 'both decisions are in the public log');
  assert.equal((await w.req('GET', '/v1/me', { cookie: u.cookie })).body.receipts.skipped, 0);
  // a few accounts fill the reported share of the whole log: everyone else's decisions are still sealed
  const v = new World();
  Object.assign(v.env, { GLOBAL_DAILY_CAP: '6', REPORTED_DAILY_CAP: '3' });
  const spam = await founder(v, 'Spam');
  const sk = (await v.req('POST', '/v1/keys', { cookie: spam.cookie, body: {} })).body.key;
  assert.equal((await send(v, sk, 3)).status, 200);
  const full = await send(v, sk, 1);
  assert.equal(full.status, 503); assert.equal(full.body.error, 'log_at_capacity');
  const victim = await founder(v, 'Victim');
  db(v).prepare('UPDATE accounts SET receipts = 1 WHERE id = ?').run(victim.id);
  const vc = await vault(v, victim); const vt = await makeToken(v, victim, vc, 'agent');
  for (const p of ['/x', '/y', '/z']) assert.equal((await del(v, vt.token, '/repos/acme' + p)).status, 428);
  assert.equal(await sealed(v), 3, 'the victim\'s decisions are sealed');
});

test('the evidence pack and the chain check read a bounded number of rows per request, however long the log is', async () => {
  const { audit } = await import('../src/audit.js');
  const { EVIDENCE_SCAN } = await import('../src/trust.js');
  const { VERIFY_PAGE } = await import('../src/audit.js');
  const w = new World();
  const u = await founder(w);
  for (let i = 0; i < 2 * EVIDENCE_SCAN + 10; i++) await audit(w.env, u.id, 'web', 'note', { i });
  const total = db(w).prepare('SELECT COUNT(*) n FROM audit WHERE account_id = ?').get(u.id).n;
  // a range after every entry: no page reads the whole log to find nothing
  const future = Date.now() + 86_400_000;
  let after = null, pages = 0, entries = 0;
  for (;;) {
    const r = await w.req('GET', `/v1/export/evidence?from=${future}${after ? `&after=${after}` : ''}`, { cookie: u.cookie });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    pages++; entries += r.body.entries.length;
    if (r.body.done) break;
    after = r.body.next_after;
    assert.ok(pages < 10);
  }
  assert.equal(entries, 0); assert.ok(pages >= 2, 'the look is cut into pages of at most ' + EVIDENCE_SCAN);
  // the whole log still comes out, page by page
  after = null; entries = 0;
  for (let i = 0; i < 50; i++) {
    const r = await w.req('GET', `/v1/export/evidence${after ? `?after=${after}` : ''}`, { cookie: u.cookie });
    entries += r.body.entries.length;
    if (r.body.done) break;
    after = r.body.next_after;
  }
  assert.equal(entries, total);
  // the chain check: a page at a time, linked page to page, and it still finds an edit
  let v = await w.req('GET', '/v1/audit/verify', { cookie: u.cookie });
  assert.equal(v.body.ok, true); assert.equal(v.body.entries, VERIFY_PAGE); assert.equal(v.body.done, false);
  let n = v.body.entries;
  while (!v.body.done) { v = await w.req('GET', `/v1/audit/verify?after=${v.body.next_after}`, { cookie: u.cookie }); assert.equal(v.body.ok, true); n += v.body.entries; }
  assert.equal(n, total);
  const mid = db(w).prepare('SELECT seq FROM audit WHERE account_id = ? ORDER BY seq LIMIT 1 OFFSET ?').get(u.id, VERIFY_PAGE + 5).seq;
  db(w).prepare("UPDATE audit SET detail = '{\"i\":-1}' WHERE seq = ?").run(mid);
  const first = await w.req('GET', '/v1/audit/verify', { cookie: u.cookie });
  const second = await w.req('GET', `/v1/audit/verify?after=${first.body.next_after}`, { cookie: u.cookie });
  assert.deepEqual([second.body.ok, second.body.brokenAt], [false, mid]);
});

test('the dashboard\'s background refresh: nothing while the page is hidden, one request a tick while shown', async () => {
  const { page } = await import('./app-fake.js');
  const w = new World();
  const u = await founder(w);
  const get = async (p) => (await w.req('GET', p, { cookie: u.cookie })).body;
  const me = await get('/v1/me'), alerts = await get('/v1/alerts');
  const p = await page({
    'GET /v1/me': async () => [200, me], 'GET /v1/meta': async () => [200, { providers: [], app: 'https://leash.test' }], 'GET /v1/credentials': async () => [200, { credentials: [] }],
    'GET /v1/tokens': async () => [200, { tokens: [] }], 'GET /v1/holds': async () => [200, { holds: [] }], 'GET /v1/audit': async () => [200, { entries: [] }], 'GET /v1/agent-keys': async () => [200, { agentKeys: [] }],
    'GET /v1/push/key': async () => [200, { enabled: false }], 'GET /v1/team': async () => [200, await get('/v1/team')], 'GET /v1/alerts': async () => [200, alerts],
  });
  const tick = p.intervals.at(-1);
  assert.equal(typeof tick, 'function', 'the refresh is set up');
  const before = p.calls.length;
  p.document.hidden = true;
  for (let i = 0; i < 10; i++) { tick(); await p.settle(); }
  assert.equal(p.calls.length, before, 'a hidden page asks nothing');
  p.document.hidden = false;
  for (let i = 0; i < 6; i++) { tick(); await p.settle(); }
  const shown = p.calls.slice(before);
  assert.ok(shown.length <= 6 + 6, `at most one request a tick while nothing changes, and a full load at most once (${shown.length})`);
  assert.ok(shown.filter((c) => c.path === '/v1/alerts').length >= 5);
});

// ---------------------------------------------------------------- what leaves the account
test('a token label that reads like a web address is never a link in a team channel', async () => {
  const { holdText } = await import('../src/channels.js');
  const t = holdText({ who: 'https://counterseal-login.example/approve', rule: 'gh.delete-repo', url: 'https://leash.test/app#hold=ab' });
  assert.match(t, /^Counterseal: `https:\/\/counterseal-login\.example[^`]*` needs approval/, 'in code formatting');
  assert.equal(holdText({ who: 'deploy agent', rule: 'r', url: 'u' }), 'Counterseal: deploy agent needs approval for r. Approve with your passkey: u', 'a plain label stays plain');
});

test('a guard key cannot write text of its own choosing into the permanent public log through the rule', async () => {
  const w = new World();
  const u = await founder(w);
  db(w).prepare('UPDATE accounts SET receipts = 1').run();
  const g = await guardKey(w, u);
  const r = await create(w, g.key, { kind: 'shell', agent: 'claude-code', rule: 'sh.db-host-10.0.4.12-pw-hunter2', why: 'x', summary: 'x', detail: 'x' });
  assert.equal(r.status, 202, JSON.stringify(r.body));
  const ok = await create(w, g.key, { kind: 'shell', agent: 'claude-code', rule: 'sh.rm', why: 'x', summary: 'y', detail: 'y' });
  assert.equal(ok.status, 202);
  const rs = (await w.req('GET', '/v1/log/entries?start=0&count=100', anon)).body.entries.map((e) => e.entry.receipt);
  assert.ok(!JSON.stringify(rs).includes('hunter2'), 'the made-up rule is not public');
  assert.ok(rs.some((x) => x.meta.rule === 'sh.rm'), 'a rule Counterseal ships still is');
  assert.equal(db(w).prepare("SELECT rule FROM holds WHERE rule LIKE 'sh.db-host%'").get().rule, 'sh.db-host-10.0.4.12-pw-hunter2', 'the owner still sees it on the card');
});

test('what a break-glass window tells the team is true: the calls it lets through are on the record (allowed reads are not)', async () => {
  const w = new World();
  const sent = [];
  w.env.__channelFetch = async (url, init) => { sent.push(JSON.parse(init.body)); return new Response('ok'); };
  const u = await founder(w);
  const ch = await ceremony(w, u, '/v1/team/channels', { kind: 'slack', url: 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678', label: 'ops room' });
  assert.equal(ch.status, 200, JSON.stringify(ch.body));
  assert.equal((await openWindow(w, u)).status, 200);
  const text = sent.map((b) => b.text).find((t) => /break glass is open/.test(t));
  assert.ok(text, JSON.stringify(sent));
  assert.match(text, /every call it lets through is on the record/);
  assert.ok(!/every call is on the record/.test(text));
});
