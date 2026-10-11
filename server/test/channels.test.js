// Team alert channels (two-person seal, part 2b): Slack, Discord and Google Chat are told, never asked. Adding one is an
// owner's passkey for exactly that address; the address is sealed at rest; the closed list of hosts and paths (SSRF); what a
// message carries and never carries; failures, redirects and the ten-failure stop; the limits.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { checkUrl, holdText, safeLabel, KINDS, MAX_FAILURES } from '../src/channels.js';
import { anon, db, withVapid, device, founder, add, ceremony, setQuorum, seal, vault, makeToken, del, heldCall, guardKey, create, ask } from './bg-helpers.js';
import { cliSession } from './brakes-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });

const SLACK = 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678';
const DISCORD = 'https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-aBcDeFgHiJk';
const GCHAT = 'https://chat.googleapis.com/v1/spaces/AAAAbbbbCCC/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=abcDEF123456-ghijKL_mnop%3D';

/** the stand-in for the three services: records every POST and answers as told */
function sink(w, answer = () => new Response('ok', { status: 200 })) {
  const calls = [];
  w.env.__channelFetch = async (url, init) => { calls.push({ url, init, body: JSON.parse(init.body) }); return answer(url, init, calls.length); };
  return calls;
}
const add1 = (w, u, kind, url, label = 'ops room') => ceremony(w, u, '/v1/team/channels', { kind, url, label });
const addOk = async (w, u, kind, url, label) => { const r = await add1(w, u, kind, url, label); assert.equal(r.status, 200, JSON.stringify(r.body)); return r.body; };
const list = async (w, u) => (await w.req('GET', '/v1/team', { cookie: u.cookie })).body.channels;
const flush = () => new Promise((r) => setTimeout(r, 5));

test('an owner adds a channel with a passkey for exactly that address; it is sealed at rest and never comes back', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha');
  const calls = sink(w);
  const ch = await addOk(w, u, 'slack', SLACK, 'ops room');
  assert.deepEqual([ch.kind, ch.name, ch.label, ch.host, ch.failures, ch.disabled], ['slack', 'Slack', 'ops room', 'hooks.slack.com', 0, false]);
  const stored = JSON.stringify(db(w).prepare('SELECT * FROM channels').all());
  assert.ok(!stored.includes('abcdEFGH1234') && !stored.includes('services/T0123'), 'the address is sealed');
  assert.ok(!JSON.stringify(await list(w, u)).includes('abcdEFGH1234'), 'and never listed');
  assert.ok(!JSON.stringify(db(w).prepare('SELECT detail FROM audit').all()).includes('abcdEFGH1234'), 'nor in the log');
  assert.deepEqual((await list(w, asha)).map((c) => c.label), ['ops room'], 'every member sees the label and host');
  // the passkey approves this address, this kind and this label
  const b = await w.req('POST', '/v1/team/channels/begin', { cookie: u.cookie, body: { kind: 'slack', url: SLACK, label: 'other room' } });
  const swapped = await w.req('POST', '/v1/team/channels/finish', { cookie: u.cookie, body: { kind: 'slack', url: SLACK.replace('abcdEFGH', 'zzzzEFGH'), label: 'other room', challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.equal(swapped.body.error, 'channel_changed');
  const b2 = await w.req('POST', '/v1/team/channels/begin', { cookie: u.cookie, body: { kind: 'slack', url: SLACK, label: 'other room' } });
  const wrongKey = await w.req('POST', '/v1/team/channels/finish', { cookie: u.cookie, body: { kind: 'slack', url: SLACK, label: 'other room', challengeId: b2.body.challengeId, credential: await asha.auth.get(b2.body.options) } });
  assert.equal(wrongKey.body.error, 'unknown_passkey', 'the owner\'s own passkey');
  assert.equal(calls.length, 0, 'adding sends nothing');
  // owners only, web only, 3 at most
  for (const who of [asha, await add(w, u, 'Max', 'member'), await add(w, u, 'Vera', 'viewer')]) assert.equal((await w.req('POST', '/v1/team/channels/begin', { cookie: who.cookie, body: { kind: 'slack', url: SLACK, label: 'x' } })).body.error, 'role_required');
  await addOk(w, u, 'discord', DISCORD, 'chat'); await addOk(w, u, 'gchat', GCHAT, 'google');
  const fourth = await add1(w, u, 'slack', SLACK.replace('B0456EFGH', 'B0456EFGX'), 'one too many');
  assert.equal(fourth.status, 409); assert.equal(fourth.body.error, 'too_many_channels');
  assert.equal((await list(w, u)).length, 3);
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM audit WHERE action = 'channel_added'").get().n, 3);
});

test('SSRF: only the exact hosts and path shapes of the three services, byte for byte; nothing else is ever stored or fetched', async () => {
  const w = new World();
  const u = await founder(w);
  const calls = sink(w);
  const bad = [
    ['slack', 'http://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'], // not https
    ['slack', 'https://hooks.slack.com:443/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'], // a port, even the default
    ['slack', 'https://hooks.slack.com:8443/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'],
    ['slack', 'https://user:pass@hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'], // userinfo
    ['slack', 'https://hooks.slack.com@evil.test/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'],
    ['slack', 'https://evil.test\\@hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'],
    ['slack', 'https://hooks.slack.com.evil.test/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'], // a longer host
    ['slack', 'https://evilhooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'],
    ['slack', 'https://hooks.slack.com./services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'], // trailing dot
    ['slack', 'https://HOOKS.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'], // not as the parser writes it
    ['slack', 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678?x=1'], // a query
    ['slack', 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678#frag'],
    ['slack', 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678/'],
    ['slack', 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcd%2eEFGH1234ijklMNOP'], // %2e
    ['slack', 'https://hooks.slack.com/services/../services/T0123ABCD/B0456EFGH/abcdEFGH1234'],
    ['slack', 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678\n'],
    ['slack', ' https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'],
    ['slack', 'https://hooks.slack.com/\tservices/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'],
    ['slack', 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH'],
    ['slack', 'https://127.0.0.1/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'], // IP literals
    ['slack', 'https://[::1]/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'],
    ['slack', 'https://2130706433/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'],
    ['slack', 'https://hooks.slaсk.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'], // a Cyrillic letter (punycode)
    ['slack', 'https://xn--hooks-slack-9g5g.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'],
    ['slack', 'https://slack-gov.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678'], // another service's host
    ['slack', DISCORD], ['discord', SLACK], ['gchat', DISCORD], ['discord', GCHAT],
    ['discord', 'https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789?wait=true'],
    ['discord', 'https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/slack'], // Discord's Slack-compatible endpoint
    ['discord', 'https://ptb.discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'],
    ['discord', 'https://discord.com/api/v10/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'],
    ['discord', 'https://cdn.discordapp.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'],
    ['gchat', 'https://chat.googleapis.com/v1/spaces/AAAAbbbbCCC/messages'], // no key and token
    ['gchat', 'https://chat.googleapis.com/v1/spaces/AAAAbbbbCCC/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=abcDEF123456&extra=1'],
    ['gchat', 'https://chat.googleapis.com/v1/spaces/AAAAbbbbCCC/messages?token=abcDEF123456&key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI'], // order
    ['gchat', 'https://chat.googleapis.com/v1/spaces/AAAAbbbbCCC/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=%2e%2e%2f'],
    ['gchat', 'https://chat.googleapis.com/v1/spaces/-/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=abcDEF123456'],
    ['gchat', 'https://www.googleapis.com/v1/spaces/AAAAbbbbCCC/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=abcDEF123456'],
    ['teams', SLACK], ['', SLACK], [undefined, SLACK], ['slack', ''], ['slack', undefined], ['slack', 5], ['slack', 'x'.repeat(601)],
  ];
  for (const [kind, url] of bad) {
    const r = await w.req('POST', '/v1/team/channels/begin', { cookie: u.cookie, body: { kind, url, label: 'x' } });
    assert.equal(r.status, 400, `${kind} ${String(url).slice(0, 70)}`);
    assert.ok(['bad_url', 'bad_kind'].includes(r.body.error), r.body.error);
    assert.throws(() => checkUrl(kind, url), /./);
  }
  // the good ones are exactly what the parser makes of them
  for (const [kind, url] of [['slack', SLACK], ['discord', DISCORD], ['discord', DISCORD.replace('discord.com', 'discordapp.com')], ['gchat', GCHAT]]) assert.equal(checkUrl(kind, url).href, url);
  assert.deepEqual(Object.keys(KINDS), ['slack', 'discord', 'gchat']);
  assert.equal(db(w).prepare('SELECT COUNT(*) n FROM channels').get().n, 0);
  assert.equal(calls.length, 0, 'nothing was fetched');
  assert.equal((await w.req('POST', '/v1/team/channels/begin', { cookie: u.cookie, body: { kind: 'slack', url: SLACK, label: '<b>x</b>' } })).body.error, 'bad_label');
  assert.equal((await w.req('POST', '/v1/team/channels/begin', { cookie: u.cookie, body: { kind: 'slack', url: SLACK, label: 'x', extra: 1 } })).body.error, 'bad_field');
  // a row that was stored badly (or tampered with) is checked again before anything is sent
  await addOk(w, u, 'slack', SLACK);
  const sealedAs = db(w).prepare('SELECT id FROM channels').get().id;
  db(w).prepare("UPDATE channels SET kind = 'discord' WHERE id = ?").run(sealedAs);
  const t = await w.req('POST', `/v1/team/channels/${sealedAs}/test`, { cookie: u.cookie, body: {} });
  assert.deepEqual(t.body, { ok: false, status: 0 }, 'a row whose kind was changed does not open, and nothing is posted');
  assert.equal(calls.length, 0);
});

test('a held call tells the channels: who, the rule, the seals and the link; never the path, command, body, amount or a name', async () => {
  const w = new World();
  await withVapid(w);
  const u = await founder(w);
  await device(w, u, 'phone');
  const calls = sink(w);
  await addOk(w, u, 'slack', SLACK, 'ops'); await addOk(w, u, 'discord', DISCORD, 'chat'); await addOk(w, u, 'gchat', GCHAT, 'google');
  const cred = await vault(w, u);
  const t = await makeToken(w, u, cred, 'deploy agent');
  const r = await w.req('DELETE', '/p/github/repos/acme/secret-project-name?token=sk_live_123', { bearer: t.token, ...anon, body: { note: 'wire 40000 USD' } });
  assert.equal(r.status, 428);
  assert.equal(calls.length, 3, 'one message to each channel');
  const by = (host) => calls.find((c) => c.url.includes(host));
  const slack = by('hooks.slack.com'), discord = by('discord.com'), gchat = by('chat.googleapis.com');
  const text = slack.body.text;
  assert.match(text, /^Counterseal: deploy agent needs approval for [A-Za-z0-9_.:-]+\. Approve with your passkey: https:\/\/leash\.test\/app#hold=[0-9a-f]{24}$/);
  assert.ok(text.includes(r.body.hold_id));
  for (const secret of ['secret-project-name', 'sk_live', '40000', 'acme', 'DELETE', 'Gautam']) assert.ok(!text.includes(secret), secret);
  assert.deepEqual(Object.keys(slack.body), ['text']);
  assert.deepEqual(discord.body, { content: text, allowed_mentions: { parse: [] } }, 'Discord: no mention can fire');
  assert.deepEqual(gchat.body, { text });
  for (const c of calls) {
    assert.equal(c.init.method, 'POST'); assert.equal(c.init.redirect, 'manual'); assert.ok(c.init.signal, 'a timeout');
    assert.match(c.init.headers['content-type'], /^application\/json/);
    assert.equal(Object.keys(c.init.headers).length, 1, 'no cookie, no authorization, nothing else');
  }
  // one alert a minute for held calls, shared with the phone: a second hold in the minute is quiet everywhere
  const r2 = await del(w, t.token, '/repos/acme/other');
  assert.equal(r2.status, 428); assert.equal(calls.length, 3);
  // a label with markup or a mention cannot reach a channel as one
  assert.equal(safeLabel('<!channel> @here [x](http://e.test) `y`'), 'channel here x(http://e.test) y');
  assert.equal(holdText({ who: '<!channel>', rule: 'a b<c>', needs: 2, seals: 1, url: 'https://leash.test/app#hold=ab' }), 'Counterseal: channel needs approval for abc (1 of 2 seals so far). Approve with your passkey: https://leash.test/app#hold=ab');
});

test('a guard key\'s hold and a partial seal tell the channels too', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha'), ben = await add(w, u, 'Ben');
  const calls = sink(w);
  await addOk(w, u, 'slack', SLACK, 'ops');
  await setQuorum(w, u, 2, true);
  calls.length = 0;
  const k = await guardKey(w, u);
  const g = await create(w, k.key);
  assert.equal(g.status, 202);
  assert.equal(calls.length, 1);
  assert.match(calls[0].body.text, /^Counterseal: claude-code needs approval for sh\.terraform-destroy \(0 of 2 seals so far\)\. Approve with your passkey: https:\/\/leash\.test\/app#hold=/);
  assert.ok(!calls[0].body.text.includes('terraform destroy -auto-approve'), 'never the command');
  // the first seal: "1 of 2" goes out once the minute's alert allows it
  _resetMemoryBuckets(); db(w).prepare("DELETE FROM ratelimits WHERE bucket LIKE 'pushhold:%'").run();
  calls.length = 0;
  assert.equal((await seal(w, asha, g.body.id)).body.approved, false);
  await flush();
  assert.equal(calls.length, 1);
  assert.match(calls[0].body.text, /^Counterseal: a held action has 1 of 2 seals and needs another approver\. Approve with your passkey: https:\/\/leash\.test\/app#hold=/);
  assert.equal((await seal(w, ben, g.body.id)).body.approved, true);
});

test('team changes tell the channels in words that carry no name, role, reason or count', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha');
  const calls = sink(w);
  await addOk(w, u, 'discord', DISCORD, 'chat');
  calls.length = 0;
  assert.equal((await ceremony(w, u, `/v1/team/members/${asha.member}/role`, { role: 'viewer' })).status, 200);
  await flush();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].body.content, 'Counterseal: the team or its approval rules changed. Review it in the app.');
  assert.ok(!/Asha|viewer|approver/.test(JSON.stringify(calls[0].body)));
});

test('failures: a thrown error, a 500 and a redirect count; ten in a row stop it; a test that works turns it back on; one test a minute', async () => {
  const w = new World();
  const u = await founder(w);
  let mode = 'fail';
  const calls = sink(w, () => (mode === 'throw' ? (() => { throw new Error('boom'); })() : mode === 'redirect' ? new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/' } }) : mode === 'fail' ? new Response('no', { status: 500 }) : new Response('ok')));
  const ch = await addOk(w, u, 'slack', SLACK, 'ops');
  const cred = await vault(w, u);
  const t = await makeToken(w, u, cred, 'agent');
  const failures = () => db(w).prepare('SELECT failures, last_ok_at FROM channels WHERE id = ?').get(ch.id);
  const hold = async (i) => { db(w).prepare("DELETE FROM ratelimits WHERE bucket LIKE 'pushhold:%'").run(); _resetMemoryBuckets(); const r = await del(w, t.token, '/repos/acme/r' + i); assert.equal(r.status, 428); await flush(); };
  await hold(1); assert.equal(failures().failures, 1);
  mode = 'throw'; await hold(2); assert.equal(failures().failures, 2);
  mode = 'redirect'; await hold(3); assert.equal(failures().failures, 3, 'a redirect is a failure and is not followed');
  assert.equal(calls.length, 3, 'never followed: one request each');
  mode = 'fail';
  for (let i = 4; i <= 10; i++) await hold(i);
  assert.equal(failures().failures, MAX_FAILURES);
  const before = calls.length;
  await hold(11);
  assert.equal(calls.length, before, 'ten in a row: it stops sending');
  assert.equal((await list(w, u))[0].disabled, true);
  // a test works whatever the state, and turns it back on
  mode = 'ok';
  const test1 = await w.req('POST', `/v1/team/channels/${ch.id}/test`, { cookie: u.cookie, body: {} });
  assert.deepEqual(test1.body, { ok: true, status: 200 });
  assert.match(calls.at(-1).body.text, /test message/);
  assert.equal(failures().failures, 0); assert.ok(failures().last_ok_at);
  assert.equal((await w.req('POST', `/v1/team/channels/${ch.id}/test`, { cookie: u.cookie, body: {} })).body.error, 'slow_down', 'one test a minute');
  await hold(12);
  assert.equal(calls.at(-1).body.text.startsWith('Counterseal: agent needs approval'), true, 'sending again');
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM audit WHERE detail LIKE '%hooks.slack%'").get().n, 1, 'only the host, once, when it was added');
});

test('what is stored is bound to its row: a sealed address copied to another channel does not open', async () => {
  const w = new World();
  const u = await founder(w);
  const calls = sink(w);
  const a = await addOk(w, u, 'slack', SLACK, 'a'), b = await addOk(w, u, 'discord', DISCORD, 'b');
  const rowA = db(w).prepare('SELECT ct, iv, wrapped_dek, dek_iv FROM channels WHERE id = ?').get(a.id);
  db(w).prepare('UPDATE channels SET ct = ?, iv = ?, wrapped_dek = ?, dek_iv = ? WHERE id = ?').run(rowA.ct, rowA.iv, rowA.wrapped_dek, rowA.dek_iv, b.id);
  await w.req('POST', `/v1/team/channels/${a.id}/test`, { cookie: u.cookie, body: {} });
  _resetMemoryBuckets(); db(w).prepare("DELETE FROM ratelimits WHERE bucket LIKE 'chtest:%'").run();
  const t = await w.req('POST', `/v1/team/channels/${b.id}/test`, { cookie: u.cookie, body: {} });
  assert.deepEqual(t.body, { ok: false, status: 0 }, 'the copied address does not open for the other channel');
  assert.equal(calls.length, 1, 'only the real one was posted to');
});

test('remove: an owner, at once; the channel hears nothing more; a stranger\'s id is not found', async () => {
  const w = new World();
  const u = await founder(w), asha = await add(w, u, 'Asha');
  const calls = sink(w);
  const ch = await addOk(w, u, 'gchat', GCHAT, 'g');
  assert.equal((await w.req('DELETE', `/v1/team/channels/${ch.id}`, { cookie: asha.cookie })).body.error, 'role_required');
  const v = await founder(w, 'Eve');
  assert.equal((await w.req('DELETE', `/v1/team/channels/${ch.id}`, { cookie: v.cookie })).status, 404);
  assert.equal((await w.req('POST', `/v1/team/channels/${ch.id}/test`, { cookie: v.cookie, body: {} })).status, 404);
  assert.equal((await w.req('DELETE', `/v1/team/channels/${ch.id}`, { cookie: u.cookie, xleash: false })).body.error, 'csrf');
  assert.equal((await w.req('DELETE', `/v1/team/channels/${ch.id}`, { cookie: u.cookie })).status, 200);
  const cred = await vault(w, u); const t = await makeToken(w, u, cred, 'agent');
  await del(w, t.token); await flush();
  assert.equal(calls.length, 0);
  assert.equal(db(w).prepare("SELECT COUNT(*) n FROM audit WHERE action = 'channel_removed'").get().n, 1);
  // 2 owners: the other owner may remove too (any owner may), and a heldCall helper still works with none
  void heldCall;
});

test('a deploy gate\'s hold tells the channels too: the gate\'s name, the rule and the link; never the repository, commit or run', async () => {
  const { world, gateId, ask: askGate } = await import('./gate-helpers.js');
  const { w, gh } = await world();
  const u = await founder(w);
  const calls = sink(w);
  await addOk(w, u, 'slack', SLACK, 'ops');
  const g = await gateId(w, u, { label: 'prod deploy' });
  const r = await askGate(w, gh, g, {}, { summary: 'deploy a1b2c3d to production' });
  assert.equal(r.status, 202, JSON.stringify(r.body));
  assert.equal(calls.length, 1);
  assert.match(calls[0].body.text, /^Counterseal: prod deploy needs approval for gate\.bind\. Approve with your passkey: https:\/\/leash\.test\/app#hold=[0-9a-f]{24}$/);
  for (const s of ['acme', 'a1b2c3d', 'octocat', '812', 'production', 'refs/heads']) assert.ok(!calls[0].body.text.includes(s), s);
});

test('gate M4: a command line session cannot remove an alert channel (monitoring is switched off only from the app)', async () => {
  const w = new World();
  const u = await founder(w);
  sink(w);
  const ch = await addOk(w, u, 'gchat', GCHAT, 'g');
  const cli = await cliSession(w, u);
  const r = await w.req('DELETE', `/v1/team/channels/${ch.id}`, { bearer: cli, ...anon });
  assert.equal(r.status, 403);
  assert.equal(r.body.error, 'passkey_required');
  assert.equal((await w.req('DELETE', `/v1/team/channels/${ch.id}`, { cookie: u.cookie })).status, 200, 'the app still can');
});
