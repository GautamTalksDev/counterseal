// Budget seal: metered spend on AI model calls, hard daily and monthly caps per agent, key and account, "ask me" mode,
// the runaway detector, the live view and the alerts. Includes concurrent calls near a cap and UTC day and month edges.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { World } from './helpers.js';
import { anon, account, mint, approve, cliSession, withVapid, subscribe, db, auditRows } from './brakes-helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetBrakeMemory } from '../src/brakes.js';
import * as Budget from '../src/budget.js';
import * as M from '../src/metered.js';
import { jsonView, providerOf, PROVIDERS, MAP_VERSION } from '../src/providers.js';

const OA = 'sk-proj-' + 'Q'.repeat(40), AN = 'sk-ant-api03-' + 'Z'.repeat(40);
const J = JSON.stringify;
const realNow = Date.now;
afterEach(() => { Date.now = realNow; });
const at = (t) => { Date.now = () => t; };

/** a world whose upstream is a fake OpenAI and Anthropic answering with the usage w.usage (or w.answer(url, init)) */
function aiWorld() {
  _resetMemoryBuckets(); _resetBrakeMemory(); Budget._resetBudgetMemory();
  const w = new World();
  w.usage = { prompt_tokens: 20, completion_tokens: 900 };
  w.status = 200;
  w.reply = (url, init) => {
    if (w.answer) return w.answer(url, init);
    const anthropic = new URL(url).host === 'api.anthropic.com';
    const usage = anthropic ? { input_tokens: w.usage.prompt_tokens, output_tokens: w.usage.completion_tokens } : w.usage;
    return new Response(J({ id: 'x', model: JSON.parse(init.body ? new TextDecoder().decode(init.body) : '{}').model, usage }), { status: w.status, headers: { 'content-type': 'application/json' } });
  };
  return w;
}
const chat = (model = 'gpt-4o', max = 1000) => J({ model, max_tokens: max, messages: [{ role: 'user', content: 'hi' }] });
const call = (w, tok, body = chat(), path = '/v1/chat/completions', provider = 'openai') =>
  w.req('POST', `/p/${provider}${path}`, { bearer: tok, ...anon, headers: { 'content-type': 'application/json' }, raw: body });
/** make calls until one is not 200; returns how many passed (at most 20) */
async function untilStopped(w, tok, body) {
  for (let i = 0; i < 20; i++) if ((await call(w, tok, body)).status !== 200) return i;
  return 20;
}
const forwarded = (w) => w.upstream.filter((x) => x.method === 'POST').length;
const est = (body, model = 'gpt-4o') => M.readRequest('openai', body, jsonView).estimate;
const totals = (w) => Object.fromEntries(db(w).prepare('SELECT scope, period, amount, over, extra FROM budget_spend').all().map((r) => [`${r.scope.split(':')[0]} ${r.period}`, r.amount + r.over]));

async function setup(w, provider = 'openai') {
  const u = await account(w, { provider, secret: provider === 'openai' ? OA : AN });
  const t = await mint(w, u, {});
  return { u, t };
}
/** set a budget with a passkey ceremony; returns the finish response */
async function setBudget(w, u, s) {
  const b = await w.req('POST', '/v1/budget/begin', { cookie: u.cookie, body: s });
  if (b.status !== 200) return b;
  return w.req('POST', '/v1/budget/finish', { cookie: u.cookie, body: { ...s, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
}

// ---------------------------------------------------------------- the pure half
test('prices: exact model names only (Anthropic dated snapshots too); anything else is unpriced, never guessed', () => {
  assert.deepEqual(M.priceOf('openai', 'gpt-4o'), [2.5, 10, 1.25]);
  assert.deepEqual(M.priceOf('openai', 'gpt-4o-2024-05-13'), [5, 15, null], 'a snapshot with its own price');
  assert.equal(M.priceOf('openai', 'gpt-4o-2024-08-06'), null, 'an OpenAI snapshot that is not listed is unpriced');
  assert.equal(M.priceOf('openai', 'gpt-4o-mini-new'), null);
  assert.equal(M.priceOf('openai', 'GPT-4O'), null);
  assert.equal(M.priceOf('openai', 'constructor'), null, 'no prototype keys');
  assert.equal(M.priceOf('openai', '__proto__'), null);
  assert.deepEqual(M.priceOf('anthropic', 'claude-sonnet-4-5-20250929'), [3, 15, 0.3]);
  assert.deepEqual(M.priceOf('anthropic', 'claude-opus-5-5'), [4, 20, 0.2]);
  assert.equal(M.priceOf('anthropic', 'claude-opus-4-9'), null, 'a new model is unpriced, not the nearest one');
  assert.equal(M.priceOf('anthropic', 'claude-opus-4-5-2025'), null);
  assert.equal(M.priceOf('anthropic', 'gpt-4o'), null);
  assert.equal(M.priceOf('openai', 'claude-opus-5-5'), null);
  assert.equal(M.priceOf('openai', 7), null);
  assert.equal(M.priceOf('stripe', 'gpt-4o'), null);
  assert.match(M.PRICES_DATE, /^\d{4}-\d{2}-\d{2}$/);
  for (const [p, t] of Object.entries(M.PRICES)) {
    assert.match(M.PRICE_SOURCES[p], /^https:\/\//);
    for (const [m, v] of Object.entries(t)) {
      assert.equal(v.length, 3, m);
      assert.ok(v[0] > 0 && v[1] > 0 && (v[2] === null || v[2] > 0), m);
    }
  }
});

test('cost: tokens times the price per million, rounded up, in micro dollars; cache writes at twice the input price', () => {
  assert.equal(M.costOf([2.5, 10, 1.25], { input: 1000, output: 1000, cacheRead: 0, cacheWrite: 0 }), 2500 + 10000);
  assert.equal(M.costOf([0.15, 0.6, null], { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 }), 2, 'each part rounds up');
  assert.equal(M.costOf([3, 15, 0.3], { input: 0, output: 0, cacheRead: 1_000_000, cacheWrite: 1_000_000 }), 300_000 + 6_000_000);
  assert.equal(M.costOf([3, 15, null], { input: 0, output: 0, cacheRead: 1_000_000, cacheWrite: 0 }), 3_000_000, 'no cache price: input price');
});

test('estimate: input bytes over three plus the full output limit; no limit means DEFAULT_OUTPUT_TOKENS (32,768); odd limits are ignored', () => {
  const r = M.readRequest('openai', chat('gpt-4o', 1000), jsonView);
  assert.equal(r.model, 'gpt-4o');
  assert.equal(r.estimate, Math.ceil(Math.ceil(chat().length / 3) * 2.5) + 10000);
  const none = J({ model: 'gpt-4o', messages: [] });
  assert.equal(M.readRequest('openai', none, jsonView).estimate, Math.ceil(Math.ceil(none.length / 3) * 2.5) + M.DEFAULT_OUTPUT_TOKENS * 10);
  for (const max of [-1, 0, 1.5, '100', 2e6]) assert.equal(M.readRequest('openai', J({ model: 'gpt-4o', max_tokens: max }), jsonView).estimate > 40000, true, String(max));
  assert.equal(M.readRequest('openai', J({ model: 'gpt-4o', max_completion_tokens: 10 }), jsonView).estimate < 1000, true);
  assert.equal(M.readRequest('openai', '{"model":"gpt-4o","model":"gpt-4o-mini"}', jsonView).model, null, 'a repeated key is unreadable');
  assert.equal(M.readRequest('openai', 'not json', jsonView).model, null);
  assert.equal(M.readRequest('openai', J({ model: 'mystery-1' }), jsonView).price, null);
});

test('usage: JSON and event streams, OpenAI chat and Responses, Anthropic with cache fields; unreadable is null', () => {
  assert.deepEqual(M.readUsage('openai', 'application/json', J({ model: 'gpt-4o', usage: { prompt_tokens: 5, completion_tokens: 7 } })), { usage: { input: 5, output: 7, cacheRead: 0, cacheWrite: 0 }, model: 'gpt-4o' });
  assert.deepEqual(M.readUsage('openai', 'application/json', J({ usage: { input_tokens: 3, output_tokens: 4 } })).usage, { input: 3, output: 4, cacheRead: 0, cacheWrite: 0 });
  assert.deepEqual(M.readUsage('anthropic', 'application/json', J({ usage: { input_tokens: 3, output_tokens: 4, cache_read_input_tokens: 10, cache_creation_input_tokens: 2 } })).usage, { input: 3, output: 4, cacheRead: 10, cacheWrite: 2 });
  const oaStream = ['data: {"choices":[{"delta":{"content":"hi"}}]}', 'data: {"model":"gpt-4o","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":22}}', 'data: [DONE]'].join('\n\n');
  assert.deepEqual(M.readUsage('openai', 'text/event-stream; charset=utf-8', oaStream).usage, { input: 11, output: 22, cacheRead: 0, cacheWrite: 0 });
  const resp = 'event: response.completed\ndata: {"type":"response.completed","response":{"model":"gpt-5","usage":{"input_tokens":8,"output_tokens":9}}}\n\n';
  assert.deepEqual(M.readUsage('openai', 'text/event-stream', resp), { usage: { input: 8, output: 9, cacheRead: 0, cacheWrite: 0 }, model: 'gpt-5' });
  const anStream = ['event: message_start', 'data: {"type":"message_start","message":{"model":"claude-opus-5-5","usage":{"input_tokens":40,"output_tokens":1,"cache_read_input_tokens":5}}}', '',
    'event: message_delta', 'data: {"type":"message_delta","usage":{"output_tokens":120}}', '', 'event: message_delta', 'data: {"type":"message_delta","usage":{"output_tokens":300}}'].join('\n');
  assert.deepEqual(M.readUsage('anthropic', 'text/event-stream', anStream), { usage: { input: 40, output: 300, cacheRead: 5, cacheWrite: 0 }, model: 'claude-opus-5-5' });
  assert.equal(M.readUsage('openai', 'text/event-stream', 'data: {"choices":[]}\n\ndata: [DONE]'), null, 'a stream without usage (no stream_options)');
  assert.equal(M.readUsage('openai', 'application/json', '{"usage":'), null);
  assert.equal(M.readUsage('openai', 'application/json', J({ ok: true })), null);
  assert.deepEqual(M.readUsage('openai', 'application/json', J({ usage: { prompt_tokens: -5, completion_tokens: 'x' } })).usage, { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 });
});

test('which calls are metered: model calls; free calls pass; every other write on those hosts is unpriced; other providers have no meter', () => {
  assert.equal(M.meterKind('openai', 'POST', '/v1/chat/completions'), 'metered');
  assert.equal(M.meterKind('openai', 'POST', '/v1/responses'), 'metered');
  assert.equal(M.meterKind('anthropic', 'POST', '/v1/messages'), 'metered');
  assert.equal(M.meterKind('anthropic', 'POST', '/v1/messages/count_tokens'), 'free');
  assert.equal(M.meterKind('openai', 'POST', '/v1/files'), 'free');
  assert.equal(M.meterKind('openai', 'GET', '/v1/models'), null);
  assert.equal(M.meterKind('openai', 'POST', '/v1/images/generations'), 'unpriced');
  assert.equal(M.meterKind('anthropic', 'POST', '/v1/messages/batches'), 'unpriced');
  assert.equal(M.meterKind('openai', 'PUT', '/v1/chat/completions'), 'unpriced');
  assert.equal(M.meterKind('github', 'POST', '/v1/chat/completions'), null);
  // the AI providers are proxied, but the public irreversible map and its claim are unchanged
  assert.equal(MAP_VERSION, '2026-10-10.1');
  assert.ok(!('openai' in PROVIDERS) && !('anthropic' in PROVIDERS));
  assert.equal(providerOf('openai').host, 'api.openai.com');
  assert.equal(providerOf('constructor'), null);
  assert.equal(providerOf('toString'), null);
});

// ---------------------------------------------------------------- metering through the proxy
test('a metered call: the real key is sent, never the token; the real cost is kept per agent, key and account, day and month', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  const r = await call(w, t.token);
  assert.equal(r.status, 200, J(r.body));
  assert.equal(w.upstream[0].headers.authorization, 'Bearer ' + OA);
  assert.ok(!J(w.upstream[0].headers).includes('lsh_'));
  const want = M.costOf([2.5, 10, 1.25], { input: 20, output: 900, cacheRead: 0, cacheWrite: 0 });
  assert.deepEqual(totals(w), { 'tok d:2026-10-10': want, 'tok m:2026-10': want, 'cred d:2026-10-10': want, 'cred m:2026-10': want, 'acct d:2026-10-10': want, 'acct m:2026-10': want });
  const v = (await w.req('GET', '/v1/budget', { cookie: u.cookie })).body;
  assert.equal(v.prices.date, M.PRICES_DATE);
  const ag = v.scopes.find((s) => s.scope === 'tok:' + t.id);
  assert.equal(ag.day.spent, want); assert.equal(ag.day.cap, null); assert.equal(ag.day.resetsAt, Date.UTC(2026, 9, 11));
  assert.equal(ag.month.resetsAt, Date.UTC(2026, 10, 1));
  assert.equal(v.scopes[0].scope, 'account');
  assert.ok(r.queries <= 25, `${r.queries} queries for a metered call`);
});

test('Anthropic: x-api-key and a fixed anthropic-version are set by Counterseal; usage is read from the answer', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { t } = await setup(w, 'anthropic');
  const r = await w.req('POST', '/p/anthropic/v1/messages', { bearer: t.token, ...anon, headers: { 'content-type': 'application/json', 'anthropic-version': '1999-01-01', 'x-api-key': 'agent-supplied' }, raw: J({ model: 'claude-sonnet-4-5', max_tokens: 1000, messages: [] }) });
  assert.equal(r.status, 200, J(r.body));
  assert.equal(w.upstream[0].headers['x-api-key'], AN);
  assert.equal(w.upstream[0].headers['anthropic-version'], '2023-06-01');
  assert.equal(totals(w)['tok d:2026-10-10'], M.costOf([3, 15, 0.3], { input: 20, output: 900, cacheRead: 0, cacheWrite: 0 }));
  // a key that is not an Anthropic key is refused when it is added
  const u2 = await w.user('Other');
  assert.equal((await w.req('POST', '/v1/credentials', { cookie: u2.cookie, body: { provider: 'anthropic', secret: OA } })).body.error, 'bad_secret');
});

test('the irreversible rules of the AI providers still hold: a DELETE and an organisation admin call wait for a passkey', async () => {
  const w = aiWorld();
  const { t } = await setup(w);
  const d = await w.req('DELETE', '/p/openai/v1/files/file-abc', { bearer: t.token, ...anon });
  assert.equal(d.status, 428); assert.equal(d.body.rule, 'oa.delete');
  const a = await call(w, t.token, J({ name: 'k' }), '/v1/organization/admin_api_keys');
  assert.equal(a.status, 428); assert.equal(a.body.rule, 'oa.admin');
  assert.equal(forwarded(w), 0);
});

// ---------------------------------------------------------------- hard caps
test('hard cap per agent: the call that would pass the daily cap gets 402 with what is left, and is never sent', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  const s = await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 5 });
  assert.equal(s.status, 200, J(s.body));
  const ok = [];
  for (let i = 0; i < 8; i++) ok.push((await call(w, t.token)).status);
  const each = M.costOf([2.5, 10, 1.25], { input: 20, output: 900, cacheRead: 0, cacheWrite: 0 });
  const fit = Math.floor((50_000 - est(chat())) / each) + 1; // calls whose reservation still fits
  assert.deepEqual(ok, [...Array(fit).fill(200), ...Array(8 - fit).fill(402)]);
  assert.equal(forwarded(w), fit, 'a refused call never reaches the provider');
  const r = await call(w, t.token);
  assert.equal(r.status, 402);
  assert.equal(r.body.error, 'budget_exhausted');
  assert.equal(r.body.budget.scope, 'tok:' + t.id);
  assert.equal(r.body.budget.period, 'day');
  assert.equal(r.body.budget.cap, 50_000);
  assert.equal(r.body.budget.remaining, 50_000 - fit * each);
  assert.equal(r.body.budget.resets_at, Date.UTC(2026, 9, 11));
  assert.match(r.body.message, /stopped this call before it was sent/);
  assert.ok(!/[–—]|--/.test(r.body.message), 'no dashes in the message');
  // the refusal is noted once in the owner's log, not once per call
  assert.equal(auditRows(w, u.id).filter((e) => e.action === 'budget_block').length, 1);
  // a token without a cap on the same key is not stopped (the key and account have no cap)
  const t2 = await mint(w, u, {}, 'other agent');
  assert.equal((await call(w, t2.token)).status, 200);
});

test('caps per key and per account stop every agent that uses them', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  const t2 = await mint(w, u, {}, 'second');
  assert.equal((await setBudget(w, u, { scope: 'cred:' + u.cred, dailyCents: 3 })).status, 200);
  const res = [];
  for (let i = 0; i < 3; i++) { res.push((await call(w, t.token)).status); res.push((await call(w, t2.token)).status); }
  assert.deepEqual(res, [200, 200, 200, 402, 402, 402], 'three calls of about $0.009 fit the key\'s $0.03, whichever agent makes them');
  const last = await call(w, t2.token);
  assert.equal(last.body.budget.scope, 'cred:' + u.cred);
  // account cap, monthly
  const w2 = aiWorld();
  const a = await setup(w2);
  assert.equal((await setBudget(w2, a.u, { scope: 'account', monthlyCents: 2 })).status, 200);
  assert.equal(await untilStopped(w2, a.t.token), 2, 'two calls of about $0.009 fit $0.02');
  const m = await call(w2, a.t.token);
  assert.equal(m.status, 402); assert.equal(m.body.budget.scope, 'account'); assert.equal(m.body.budget.period, 'month');
  assert.equal(m.body.budget.resets_at, Date.UTC(2026, 10, 1));
});

test('concurrent calls near the cap: 30 at once, never more through than the cap allows, and the total never passes it', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 5 })).status, 200);
  const e = est(chat());
  const rs = await Promise.all(Array.from({ length: 30 }, () => call(w, t.token)));
  const passed = rs.filter((r) => r.status === 200).length;
  assert.ok(passed >= 1 && passed <= Math.floor(50_000 / e) + 1, `${passed} passed`);
  assert.ok(rs.every((r) => [200, 402, 409].includes(r.status)), J(rs.map((r) => r.status)));
  assert.equal(forwarded(w), passed);
  const row = db(w).prepare("SELECT amount, over, cap FROM budget_spend WHERE scope = ? AND period LIKE 'd:%'").get('tok:' + t.id);
  assert.ok(row.amount + row.over <= 50_000, J(row));
});

test('the reservation is one atomic statement: 50 concurrent reservations fit the cap exactly, all six totals or none', async () => {
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'account', dailyCents: 10 })).status, 200);
  const tok = db(w).prepare('SELECT * FROM tokens WHERE id = ?').get(t.id);
  const env = { ...w.env };
  const body = chat();
  const e = est(body);
  const got = await Promise.allSettled(Array.from({ length: 50 }, () => Budget.before(env, { tok, provider: 'openai', method: 'POST', canon: '/v1/chat/completions', bodyText: body })));
  const ok = got.filter((g) => g.status === 'fulfilled' && g.value?.meter).length;
  assert.equal(ok, Math.floor(100_000 / e));
  assert.ok(got.filter((g) => g.status === 'rejected').every((g) => g.reason.status === 402));
  const rows = db(w).prepare('SELECT scope, period, amount FROM budget_spend').all();
  assert.equal(rows.length, 6);
  assert.ok(rows.every((r) => r.amount === ok * e), 'every total moved together: ' + J(rows));
});

test('a refusal (4xx) gives the reservation back; a 5xx keeps the estimate; an answer without usage is charged its ceiling', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { t } = await setup(w);
  w.status = 400;
  assert.equal((await call(w, t.token)).status, 400);
  assert.equal(totals(w)['tok d:2026-10-10'], 0);
  w.status = 503;
  assert.equal((await call(w, t.token)).status, 503);
  assert.equal(totals(w)['tok d:2026-10-10'], est(chat()));
  w.status = 200;
  w.answer = () => new Response('data: {"choices":[]}\n\ndata: [DONE]\n\n', { headers: { 'content-type': 'text/event-stream' } });
  const r = await call(w, t.token);
  assert.equal(r.status, 200);
  assert.match(r.body, /DONE/, 'the agent gets the stream unchanged');
  assert.equal(totals(w)['tok d:2026-10-10'], est(chat()) + M.readRequest('openai', chat(), jsonView).unread, 'unread usage: charged the largest output it could have had (gate M1)');
});

test('a streamed answer is metered from its usage, and a real cost above the estimate is kept past the cap (as over)', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 2 })).status, 200);
  // the provider ran far more output than the request allowed for (it should not; the meter keeps the truth anyway)
  w.answer = () => new Response('data: {"model":"gpt-4o","choices":[],"usage":{"prompt_tokens":100,"completion_tokens":5000}}\n\ndata: [DONE]\n\n', { headers: { 'content-type': 'text/event-stream' } });
  assert.equal((await call(w, t.token, chat('gpt-4o', 100))).status, 200);
  const row = db(w).prepare("SELECT amount, over, cap FROM budget_spend WHERE scope = ? AND period LIKE 'd:%'").get('tok:' + t.id);
  assert.equal(row.amount + row.over, M.costOf([2.5, 10, 1.25], { input: 100, output: 5000, cacheRead: 0, cacheWrite: 0 }));
  assert.equal(row.amount, 20_000, 'the reservable total stops at the cap');
  assert.equal((await call(w, t.token, chat('gpt-4o', 1))).status, 402, 'and nothing more goes');
});

// ---------------------------------------------------------------- clock edges (UTC)
test('day rollover at UTC midnight: 23:59:59.999 counts for the old day, 00:00:00.000 starts a new day, the month goes on', async () => {
  at(Date.UTC(2026, 9, 10, 23, 0));
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 2, monthlyCents: 3 })).status, 200);
  at(Date.UTC(2026, 9, 10, 23, 59, 59, 999));
  assert.equal(await untilStopped(w, t.token), 2);
  const full = await call(w, t.token);
  assert.equal(full.status, 402); assert.equal(full.body.budget.period, 'day', 'the day is full');
  assert.equal(full.body.budget.resets_at, Date.UTC(2026, 9, 11));
  at(Date.UTC(2026, 9, 11, 0, 0, 0, 0));
  assert.equal((await call(w, t.token)).status, 200, 'a new UTC day');
  const tt = totals(w);
  assert.ok(tt['tok d:2026-10-10'] > 0 && tt['tok d:2026-10-11'] > 0);
  assert.equal(tt['tok m:2026-10'], tt['tok d:2026-10-10'] + tt['tok d:2026-10-11']);
  // the month cap still binds across days: the day has room, the month does not
  const m = await call(w, t.token);
  assert.equal(m.status, 402); assert.equal(m.body.budget.period, 'month');
  assert.equal(m.body.budget.resets_at, Date.UTC(2026, 10, 1));
});

test('month rollover: 31 Oct 23:59:59.999 UTC is October, 1 Nov 00:00 UTC starts November; a local time zone never matters', async () => {
  at(Date.UTC(2026, 9, 31, 20));
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'account', monthlyCents: 2 })).status, 200);
  at(Date.UTC(2026, 9, 31, 23, 59, 59, 999));
  assert.equal(await untilStopped(w, t.token), 2);
  const full = await call(w, t.token);
  assert.equal(full.status, 402);
  assert.equal(full.body.budget.resets_at, Date.UTC(2026, 10, 1));
  at(Date.UTC(2026, 10, 1));
  assert.equal((await call(w, t.token)).status, 200);
  assert.ok(totals(w)['acct m:2026-11'] > 0 && totals(w)['acct d:2026-11-01'] > 0);
  // periods and resets are pure UTC arithmetic, also over a year end and a leap day
  assert.deepEqual(Budget.periodsOf(Date.UTC(2026, 11, 31, 23, 59, 59, 999)), { day: 'd:2026-12-31', month: 'm:2026-12' });
  assert.deepEqual(Budget.resetsOf(Date.UTC(2026, 11, 31, 23)), { day: Date.UTC(2027, 0, 1), month: Date.UTC(2027, 0, 1) });
  assert.deepEqual(Budget.resetsOf(Date.UTC(2028, 1, 28, 12)), { day: Date.UTC(2028, 1, 29), month: Date.UTC(2028, 2, 1) });
});

// ---------------------------------------------------------------- unpriced
test('an unknown model is unpriced: a few calls a day pass, then each waits for a passkey; approving lets that one through', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'account', dailyCents: 100, unpricedPerDay: 2 })).status, 200);
  const body = chat('gpt-99-preview');
  assert.equal((await call(w, t.token, body)).status, 200);
  assert.equal((await call(w, t.token, body)).status, 200);
  const h = await call(w, t.token, body);
  assert.equal(h.status, 428); assert.equal(h.body.rule, 'budget.unpriced');
  assert.match(h.body.message, /not in the price table/);
  assert.equal(forwarded(w), 2);
  assert.equal(totals(w)['acct d:2026-10-10'], undefined, 'an unpriced call is never given a guessed price');
  assert.equal((await approve(w, u, h.body.hold_id)).status, 200);
  assert.equal((await call(w, t.token, body)).status, 200, 'the approved exact request goes once');
  assert.equal((await call(w, t.token, body)).status, 428);
  // an unpriced path (images) counts the same way; a new UTC day starts the allowance again
  at(Date.UTC(2026, 9, 11, 0, 0, 1));
  assert.equal((await call(w, t.token, J({ prompt: 'x' }), '/v1/images/generations')).status, 200);
  // the default allowance is 10
  const w2 = aiWorld();
  const b = await setup(w2);
  const st = [];
  for (let i = 0; i < 11; i++) st.push((await call(w2, b.t.token, chat('mystery'))).status);
  assert.deepEqual(st, [...Array(M.UNPRICED_DEFAULT).fill(200), 428]);
});

// ---------------------------------------------------------------- "ask me" mode
test('"ask me" mode: past 80% the call waits; approving lets the period run to the cap; at the cap approving raises it once', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 5, ask: true })).status, 200);
  const st = [];
  let held;
  for (let i = 0; i < 6; i++) { const r = await call(w, t.token); st.push(r.status); if (r.status === 428) { held = r; break; } }
  assert.ok(held, J(st));
  assert.equal(held.body.rule, 'budget.ask');
  assert.match(held.body.message, /past 80%/);
  const before = totals(w)['tok d:2026-10-10'];
  assert.ok(before <= 40_000 + 1, 'the asked call reserved nothing');
  const a = await approve(w, u, held.body.hold_id);
  assert.equal(a.status, 200); assert.match(a.body.note, /run on to its cap/);
  assert.equal(db(w).prepare('SELECT status FROM holds WHERE id = ?').get(held.body.hold_id).status, 'used', 'the approval is used up by the budget');
  // now it runs to the cap, and at the cap it is held (not 402) because ask mode is on
  let cap;
  for (let i = 0; i < 6; i++) { const r = await call(w, t.token); if (r.status !== 200) { cap = r; break; } }
  assert.equal(cap.status, 428); assert.equal(cap.body.rule, 'budget.cap');
  assert.match(cap.body.message, /raise the cap once, to \$0\.10/);
  const n = forwarded(w);
  assert.equal((await approve(w, u, cap.body.hold_id)).status, 200);
  assert.equal(db(w).prepare("SELECT extra FROM budget_spend WHERE scope = ? AND period LIKE 'd:%'").get('tok:' + t.id).extra, 50_000);
  assert.equal((await call(w, t.token)).status, 200, 'past the old cap after one approval');
  assert.equal(forwarded(w), n + 1);
  const v = (await w.req('GET', '/v1/budget', { cookie: u.cookie })).body.scopes.find((s) => s.scope === 'tok:' + t.id);
  assert.equal(v.day.extra, 50_000); assert.equal(v.ask, true);
  assert.ok(auditRows(w, u.id).some((e) => e.action === 'budget_raised' && e.detail.rule === 'budget.cap'));
});

test('a denied budget question changes nothing; a frozen account answers 423 before any budget is read', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 1, ask: true })).status, 200);
  const h = await call(w, t.token, chat('gpt-4o', 900));
  assert.equal(h.status, 428);
  assert.equal((await w.req('POST', `/v1/holds/${h.body.hold_id}/deny`, { cookie: u.cookie, body: {} })).status, 200);
  assert.equal((await call(w, t.token, chat('gpt-4o', 900))).status, 428);
  assert.equal((await w.req('POST', '/v1/me/freeze', { cookie: u.cookie, body: {} })).status, 200);
  const f = await call(w, t.token);
  assert.equal(f.status, 423); assert.equal(f.body.error, 'account_frozen');
  assert.equal(db(w).prepare("SELECT COUNT(*) AS n FROM holds WHERE status = 'pending'").get().n, 1, 'nothing new is held while frozen');
});

// ---------------------------------------------------------------- the runaway detector
test('runaway: more calls in the window than allowed trips the token breaker; its writes wait until a passkey reset', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = await withVapid(aiWorld());
  const { u, t } = await setup(w);
  await subscribe(w, u);
  assert.equal((await setBudget(w, u, { scope: 'account', runaway: { calls: 3, minutes: 5 } })).status, 200);
  for (let i = 0; i < 3; i++) assert.equal((await call(w, t.token)).status, 200);
  const p0 = w.pushes.length;
  const r = await call(w, t.token);
  assert.equal(r.status, 428); assert.equal(r.body.rule, 'brake.tripped');
  assert.match(r.body.message, /runaway limit/);
  assert.equal(w.pushes.length, p0 + 1, 'the call that tripped it wakes the owner');
  assert.equal(db(w).prepare('SELECT tripped_why FROM tokens WHERE id = ?').get(t.id).tripped_why, 'runaway');
  assert.equal((await call(w, t.token)).status, 428, 'still tripped');
  assert.equal(forwarded(w), 3);
  // reset with a passkey: the runaway window goes too, so it does not trip again at once
  const b = await w.req('POST', `/v1/tokens/${t.id}/reset/begin`, { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', `/v1/tokens/${t.id}/reset/finish`, { cookie: u.cookie, body: { challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } })).status, 200);
  assert.equal((await call(w, t.token)).status, 200);
  // after the window, the count starts again
  at(Date.UTC(2026, 9, 10, 12, 30));
  for (let i = 0; i < 3; i++) assert.equal((await call(w, t.token)).status, 200);
});

test('runaway by spend: more estimated dollars in the window than allowed trips it too', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'account', runaway: { cents: 2, minutes: 10 } })).status, 200);
  const st = [];
  for (let i = 0; i < 4; i++) st.push((await call(w, t.token)).status);
  assert.deepEqual(st, [200, 428, 428, 428], 'two estimates of about $0.01 pass $0.02');
});

// ---------------------------------------------------------------- alerts
test('alerts: one empty push at each of 50%, 80% and 100% of a cap, and /v1/alerts shows the totals past 50%', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = await withVapid(aiWorld());
  const { u, t } = await setup(w);
  await subscribe(w, u);
  assert.equal((await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 4 })).status, 200);
  const seen = [];
  for (let i = 0; i < 5; i++) {
    at(Date.UTC(2026, 9, 10, 12, i * 2)); // a minute apart at least, so the once-a-minute limit does not hide one
    await call(w, t.token);
  }
  for (const e of auditRows(w, u.id).filter((x) => x.action === 'budget_alert')) seen.push(...e.detail.alerts.map((a) => a.pct));
  assert.deepEqual([...new Set(seen)].sort((a, b) => a - b), [50, 80, 100].filter((p) => seen.includes(p)));
  assert.ok(seen.includes(50) && seen.includes(80), J(seen));
  assert.equal(seen.filter((p) => p === 50).length, 1, 'each crossing is seen once');
  assert.ok(w.pushes.length >= 2);
  assert.ok(w.pushes.every((p) => !p.init.body || p.init.body.length === 0), 'the push carries nothing');
  const al = (await w.req('GET', '/v1/alerts', { cookie: u.cookie })).body.budget;
  assert.ok(al.some((a) => a.scope === 'tok:' + t.id && a.period === 'day' && a.pct >= 50), J(al));
});

// ---------------------------------------------------------------- settings: passkey, validation
test('setting a budget needs a fresh passkey ceremony for exactly those settings; a command line session cannot', async () => {
  const w = aiWorld();
  const { u, t } = await setup(w);
  const cli = await cliSession(w, u);
  assert.equal((await w.req('POST', '/v1/budget/begin', { bearer: cli, ...anon, body: { scope: 'account', dailyCents: 100 } })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', '/v1/budget/finish', { bearer: cli, ...anon, body: { scope: 'account', dailyCents: 100 } })).body.error, 'passkey_required');
  assert.equal((await w.req('POST', '/v1/budget/begin', { cookie: u.cookie, body: { scope: 'account' }, xleash: false })).body.error, 'csrf');
  // begun for $1, finished for $1000: refused
  const b = await w.req('POST', '/v1/budget/begin', { cookie: u.cookie, body: { scope: 'account', dailyCents: 100 } });
  const f = await w.req('POST', '/v1/budget/finish', { cookie: u.cookie, body: { scope: 'account', dailyCents: 100000, challengeId: b.body.challengeId, credential: await u.auth.get(b.body.options) } });
  assert.notEqual(f.status, 200);
  assert.equal(db(w).prepare('SELECT COUNT(*) AS n FROM budgets').get().n, 0);
  // the GET view is open to any session, the command line too
  assert.equal((await w.req('GET', '/v1/budget', { bearer: cli, ...anon })).status, 200);
  // removing caps also takes a passkey, and is audited
  assert.equal((await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 100 })).status, 200);
  const rm = await setBudget(w, u, { scope: 'tok:' + t.id });
  assert.equal(rm.status, 200); assert.equal(rm.body.removed, true);
  assert.deepEqual(auditRows(w, u.id).filter((e) => e.action === 'budget_set').map((e) => e.detail.daily_cents), [100, null]);
  // another account's token or key cannot be named
  const other = await setup(w);
  assert.equal((await w.req('POST', '/v1/budget/begin', { cookie: u.cookie, body: { scope: 'tok:' + other.t.id, dailyCents: 1 } })).status, 404);
  assert.equal((await w.req('POST', '/v1/budget/begin', { cookie: u.cookie, body: { scope: 'cred:' + other.u.cred, dailyCents: 1 } })).status, 404);
});

test('settings are validated strictly: unknown fields, wrong types and out-of-range values are refused, not defaulted', () => {
  const bad = [
    null, [], 'x', {}, { scope: 'everything' }, { scope: 'tok:abc' }, { scope: "tok:' OR 1=1 --" }, { scope: 'account', dailyCents: -1 }, { scope: 'account', dailyCents: 0 },
    { scope: 'account', dailyCents: 1.5 }, { scope: 'account', dailyCents: '100' }, { scope: 'account', dailyCents: 1e12 }, { scope: 'account', daily: 100 },
    { scope: 'account', dailyCents: 200, monthlyCents: 100 }, { scope: 'account', ask: 'yes', dailyCents: 1 }, { scope: 'account', ask: true },
    { scope: 'account', runaway: { calls: 3 } }, { scope: 'account', runaway: { calls: 3, minutes: 61 } }, { scope: 'account', runaway: { calls: 3, minutes: 5, x: 1 } },
    { scope: 'tok:' + 'a'.repeat(24), runaway: { calls: 3, minutes: 5 } }, { scope: 'account', unpricedPerDay: -1 }, { scope: 'tok:' + 'a'.repeat(24), unpricedPerDay: 1 },
    { scope: 'account', __proto__: { dailyCents: 1 }, polluted: 1 },
  ];
  for (const b of bad) assert.throws(() => Budget.normaliseSettings(b), (e) => e.status === 400, J(b));
  assert.deepEqual(Budget.normaliseSettings({ scope: 'account', dailyCents: 100, monthlyCents: 1000, ask: true, runaway: { calls: 50, minutes: 5 }, unpricedPerDay: 0 }),
    { scope: 'account', daily: 100, monthly: 1000, ask: true, runaway: { calls: 50, cents: null, minutes: 5 }, unpricedPerDay: 0 });
});

test('no secret is ever logged or stored in the clear: not the provider key, not the token, not the prompt', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const lines = [];
  const orig = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(orig)) console[k] = (...a) => lines.push(a.join(' '));
  try {
    const { u, t } = await setup(w);
    await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 2, ask: false });
    const secret = 'my private prompt 0xC0FFEE';
    const body = J({ model: 'gpt-4o', max_tokens: 900, messages: [{ role: 'user', content: secret }] });
    await call(w, t.token, body); await call(w, t.token, body); await call(w, t.token, body);
    w.answer = () => { throw new Error('boom ' + OA); };
    await call(w, t.token, chat('gpt-4o', 1));
    const all = lines.join('\n') + J(db(w).prepare('SELECT * FROM audit').all()) + J(db(w).prepare('SELECT * FROM budget_spend').all()) + J(db(w).prepare('SELECT * FROM budgets').all()) + J(db(w).prepare('SELECT * FROM counters').all());
    assert.ok(!all.includes(OA), 'no provider key');
    assert.ok(!all.includes(t.token), 'no Counterseal token');
    assert.ok(!all.includes('0xC0FFEE'), 'no prompt text');
  } finally { Object.assign(console, orig); }
});

test('Workers Free: a metered call stays well under 50 D1 queries, with caps, ask mode and the runaway detector all on', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = await withVapid(aiWorld());
  const { u, t } = await setup(w);
  await subscribe(w, u);
  for (const s of [{ scope: 'account', dailyCents: 1000, monthlyCents: 10000, ask: true, runaway: { calls: 100, cents: 1000, minutes: 5 } }, { scope: 'cred:' + u.cred, dailyCents: 1000 }, { scope: 'tok:' + t.id, dailyCents: 1000, ask: true }])
    assert.equal((await setBudget(w, u, s)).status, 200);
  w.env.DB.cap = 50;
  const r = await call(w, t.token);
  assert.equal(r.status, 200, J(r.body));
  assert.ok(r.queries <= 30, `${r.queries} queries`);
  const v = await w.req('GET', '/v1/budget', { cookie: u.cookie });
  assert.equal(v.status, 200); assert.ok(v.queries <= 15, `${v.queries} queries for the view`);
});

test('sweep and account deletion remove old totals and every budget', async () => {
  const w = aiWorld();
  const { u, t } = await setup(w);
  await setBudget(w, u, { scope: 'tok:' + t.id, dailyCents: 100 });
  const raw = db(w);
  for (const p of ['d:2026-01-01', 'd:2026-10-09', 'm:2025-01', 'm:2026-10']) raw.prepare('INSERT INTO budget_spend (account_id, scope, period, amount, cap) VALUES (?, ?, ?, 1, 100)').run(u.id, 'tok:' + t.id, p);
  const { sweep } = await import('../src/index.js');
  await sweep(w.env, Date.UTC(2026, 9, 10));
  assert.deepEqual(raw.prepare('SELECT period FROM budget_spend ORDER BY period').all().map((r) => r.period), ['d:2026-10-09', 'm:2026-10']);
  const del = await w.req('POST', '/v1/me/delete/begin', { cookie: u.cookie, body: {} });
  assert.equal((await w.req('POST', '/v1/me/delete/finish', { cookie: u.cookie, body: { confirm: 'delete', challengeId: del.body.challengeId, credential: await u.auth.get(del.body.options) } })).status, 200);
  assert.equal(raw.prepare('SELECT COUNT(*) AS n FROM budget_spend').get().n, 0);
  assert.equal(raw.prepare('SELECT COUNT(*) AS n FROM budgets').get().n, 0);
});

test('the app shows live spend and edits budgets with a passkey, without innerHTML', async () => {
  const { readFileSync } = await import('node:fs');
  const js = readFileSync(new URL('../../site/public/app/app.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('../../site/public/app/index.html', import.meta.url), 'utf8');
  assert.match(js, /\/v1\/budget/);
  assert.match(js, /\/v1\/budget\/begin/);
  assert.match(js, /runaway: 'too many AI calls/);
  assert.match(html, /id="budget"/);
  const part = js.slice(js.indexOf('// ---- Budget seal'), js.indexOf('// ---- end Budget seal'));
  assert.ok(part.length > 200);
  assert.ok(!/innerHTML/.test(part));
  assert.ok(!/[–—]/.test(part) && !/[–—]/.test(html.slice(html.indexOf('id="budget"'), html.indexOf('id="budget"') + 3000)));
});

test('the docs say what it caps and what it cannot, with the price date; no dashes and no double hyphen', async () => {
  const { readFileSync } = await import('node:fs');
  const doc = readFileSync(new URL('../../docs/BUDGET_SEAL.md', import.meta.url), 'utf8');
  const note = readFileSync(new URL('../../docs/CLOUD_KILL_SWITCH.md', import.meta.url), 'utf8');
  for (const t of [doc, note]) assert.ok(!/[–—]|--/.test(t));
  assert.ok(doc.includes(M.PRICES_DATE), 'the doc names the price table date in the code');
  for (const s of Object.values(M.PRICE_SOURCES)) assert.ok(doc.includes(s));
  assert.match(doc, /## What it cannot cap/);
  assert.match(doc, /Only calls that go through Counterseal/);
  assert.match(note, /not built/i);
});

// ---------------------------------------------------------------- release gate 10 Oct: M1, M2, M3
test('gate M1: an OpenAI stream without stream_options is sent with include_usage, so it is settled from its real usage', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { t } = await setup(w);
  let sent = null;
  w.answer = (url, init) => {
    sent = JSON.parse(new TextDecoder().decode(init.body));
    return new Response('data: {"choices":[{"delta":{"content":"x"}}]}\n\ndata: {"model":"o1-pro","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":100000}}\n\ndata: [DONE]\n\n', { headers: { 'content-type': 'text/event-stream' } });
  };
  const body = J({ model: 'o1-pro', stream: true, messages: [{ role: 'user', content: 'hi' }] });
  assert.equal((await call(w, t.token, body)).status, 200);
  assert.deepEqual(sent.stream_options, { include_usage: true });
  assert.equal(sent.model, 'o1-pro');
  assert.equal(totals(w)['tok d:2026-10-10'], M.costOf([150, 600, null], { input: 10, output: 100000, cacheRead: 0, cacheWrite: 0 }), 'the real cost, not the estimate');
  // a request that already asks for usage is sent as it is
  const own = J({ model: 'gpt-4o', stream: true, stream_options: { include_usage: true }, max_tokens: 10, messages: [] });
  assert.equal(M.readRequest('openai', own, jsonView).needsUsage, false);
  assert.equal(M.readRequest('anthropic', J({ model: 'claude-opus-5-5', stream: true, max_tokens: 10 }), jsonView).needsUsage, false, 'Anthropic streams always carry usage');
});

test('gate M2: the estimate counts every choice (n), and an odd n is read as the most allowed', () => {
  const one = M.readRequest('openai', J({ model: 'gpt-4o', max_tokens: 1000, messages: [] }), jsonView);
  const many = M.readRequest('openai', J({ model: 'gpt-4o', max_tokens: 1000, n: 8, messages: [] }), jsonView);
  assert.ok(many.estimate - one.estimate >= 7 * 1000 * 10 - 10, 'eight choices reserve eight outputs');
  const odd = M.readRequest('openai', J({ model: 'gpt-4o', max_tokens: 10, n: '5', messages: [] }), jsonView);
  assert.ok(odd.estimate >= M.MAX_CHOICES * 10 * 10, 'n that is not a plain number: the most choices');
});

test('gate M3: the unpriced allowance is per account, so minting another token does not buy more calls', async () => {
  at(Date.UTC(2026, 9, 10, 12));
  const w = aiWorld();
  const { u, t } = await setup(w);
  assert.equal((await setBudget(w, u, { scope: 'account', dailyCents: 100, unpricedPerDay: 2 })).status, 200);
  const t2 = await mint(w, u, {});
  assert.equal((await call(w, t.token, chat('gpt-4o-2024-08-06'))).status, 200);
  assert.equal((await call(w, t2.token, chat('gpt-4o-2024-08-06'))).status, 200);
  const h = await call(w, t2.token, chat('gpt-4o-2024-08-06'));
  assert.equal(h.status, 428);
  assert.match(h.body.message, /This account has used its 2 unpriced calls/);
  // a trailing slash is the same metered path, so it is priced, not unpriced
  assert.equal((await call(w, t.token, chat('gpt-4o', 10), '/v1/chat/completions/')).status, 200);
  assert.ok(totals(w)['acct d:2026-10-10'] > 0, 'priced and reserved');
});
