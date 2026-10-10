// The dashboard's side of break glass and alert channels: the page's own code run against a small fake DOM and the answers the
// real Worker gives. The banner on every page, the team page's window and channel lists, and the forms that run the passkey
// ceremonies with exactly what was typed. Everything shown is text (no innerHTML), and a webhook address is never shown.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { World } from './helpers.js';
import { _resetMemoryBuckets } from '../src/ratelimit.js';
import { _resetSeen } from '../src/admin.js';
import { page } from './app-fake.js';
import { founder, add, ceremony, openWindow, vault, makeToken, guardKey } from './bg-helpers.js';

beforeEach(() => { _resetMemoryBuckets(); _resetSeen(); });
const SLACK = 'https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdEFGH1234ijklMNOP5678';

async function fixtures() {
  const w = new World();
  w.env.__channelFetch = async () => new Response('ok');
  const u = await founder(w, 'Gautam'), asha = await add(w, u, 'Asha');
  const cred = await vault(w, u); const tok = await makeToken(w, u, cred, 'deploy agent'); const gk = await guardKey(w, u, 'laptop guard');
  const ch = await ceremony(w, u, '/v1/team/channels', { kind: 'slack', url: SLACK, label: 'ops room' });
  assert.equal(ch.status, 200, JSON.stringify(ch.body));
  const win = await openWindow(w, asha, { tokenId: tok.id });
  assert.equal(win.status, 200, JSON.stringify(win.body));
  const get = async (p, who = u) => (await w.req('GET', p, { cookie: who.cookie })).body;
  return { w, u, asha, tok, gk, ch: ch.body, win: win.body, me: await get('/v1/me'), team: await get('/v1/team'), tokens: await get('/v1/tokens'), guardKeys: await get('/v1/guard/keys') };
}
const routes = (f, over = {}) => ({
  'GET /v1/me': async () => [200, f.me], 'GET /v1/meta': async () => [200, { providers: [], app: 'https://leash.test', legacyApp: null }], 'GET /v1/credentials': async () => [200, { credentials: [] }],
  'GET /v1/tokens': async () => [200, f.tokens], 'GET /v1/holds': async () => [200, { holds: [] }], 'GET /v1/audit': async () => [200, { entries: [] }], 'GET /v1/agent-keys': async () => [200, { agentKeys: [] }],
  'GET /v1/push/key': async () => [200, { enabled: false }], 'GET /v1/team': async () => [200, f.team], 'GET /v1/guard/keys': async () => [200, f.guardKeys], ...over,
});

test('the banner shows on every page while a window is open: who, for what, why, how long, and a way to close it', async () => {
  const f = await fixtures();
  const p = await page(routes(f, { [`DELETE /v1/team/breakglass/${f.win.id}`]: async () => [200, { ok: true }] }));
  assert.equal(p.byId('bgBanner').hidden, false);
  assert.match(p.byId('bgTitle').textContent, /^Break glass is open for \d+ min$/);
  const t = p.byId('bgText').textContent;
  for (const s of ['Asha opened it', 'for deploy agent', 'prod is down, second approver asleep', 'Not expected? Close it.']) assert.ok(t.includes(s), s);
  p.byId('bgClose').click(); await p.settle();
  assert.ok(p.calls.some((c) => c.method === 'DELETE' && c.path === `/v1/team/breakglass/${f.win.id}`));
  assert.match(p.toast(), /^Closed\. Held actions wait for approval again\.$/);
  // no window: no banner
  const none = JSON.parse(JSON.stringify(f.me)); none.breakglass = [];
  const q = await page(routes(f, { 'GET /v1/me': async () => [200, none] }));
  assert.equal(q.byId('bgBanner').hidden, true);
});

test('the team page lists the open window and the channels (label, service, host; never the address), and offers test and remove to an owner', async () => {
  const f = await fixtures();
  const p = await page(routes(f, { [`POST /v1/team/channels/${f.ch.id}/test`]: async () => [200, { ok: true, status: 200 }], [`DELETE /v1/team/channels/${f.ch.id}`]: async () => [200, { ok: true }] }));
  await p.go('team');
  const open = p.byId('bgOpenNow').textContent;
  assert.ok(open.includes('Asha') && open.includes('prod is down') && open.includes('deploy agent'), open);
  const list = p.byId('channels');
  assert.ok(list.textContent.includes('ops room') && list.textContent.includes('Slack') && list.textContent.includes('hooks.slack.com'));
  assert.ok(!list.textContent.includes('abcdEFGH') && !JSON.stringify(f.team).includes('abcdEFGH'), 'the address is not in the page or in the answer');
  assert.equal(p.byId('noChannels').hidden, true);
  assert.equal(p.byId('bgNew').disabled, true, 'one window at a time');
  // the scope list: live tokens and guard keys of the account
  const opts = p.byId('bgScope').children.map((o) => o.textContent);
  assert.ok(opts.includes('Token: deploy agent') && opts.includes('Guard key: laptop guard'), opts.join('|'));
  const btns = list.all((c) => c.tag === 'button');
  btns.find((b) => b.textContent === 'Send a test').click(); await p.settle();
  assert.equal(p.toast(), 'Sent. Look in the channel.');
  btns.find((b) => b.textContent === 'Remove').click(); await p.settle();
  assert.ok(p.calls.some((c) => c.method === 'DELETE' && c.path === `/v1/team/channels/${f.ch.id}`));
});

test('opening a window runs the passkey ceremony with exactly what was chosen; a short reason is refused before anything is sent', async () => {
  const f = await fixtures();
  const noWin = JSON.parse(JSON.stringify(f.team)); noWin.windows = [];
  const p = await page(routes(f, {
    'GET /v1/team': async () => [200, noWin],
    'POST /v1/team/breakglass/begin': async () => [200, { challengeId: 'aa', options: { challenge: 'AAAA', rpId: 'leash.test' } }],
    'POST /v1/team/breakglass/finish': async () => [200, { id: 'x'.repeat(24), expires_at: Date.now() + 60_000, scope: null }],
  }));
  await p.go('team');
  p.byId('bgReason').value = 'no';
  p.byId('bgNew').click(); await p.settle();
  assert.match(p.toast(), /Say why/);
  assert.equal(p.calls.filter((c) => c.path.includes('breakglass')).length, 0);
  p.byId('bgReason').value = 'Prod is down';
  p.byId('bgMinutes').value = '15';
  p.byId('bgScope').value = f.tok.id;
  p.byId('bgNew').click(); await p.settle();
  const sent = p.calls.filter((c) => c.path.includes('/breakglass/'));
  assert.deepEqual(sent.map((c) => `${c.method} ${c.path}`), ['POST /v1/team/breakglass/begin', 'POST /v1/team/breakglass/finish']);
  assert.deepEqual(sent[0].body, { minutes: 15, reason: 'Prod is down', tokenId: f.tok.id });
  assert.equal(sent[1].body.challengeId, 'aa'); assert.equal(sent[1].body.minutes, 15);
  assert.equal(p.byId('bgReason').value, '', 'cleared');
  assert.match(p.toast(), /Break glass is open\. Everyone was told\./);
});

test('adding a channel sends what was typed through the passkey ceremony and clears the address from the page', async () => {
  const f = await fixtures();
  const p = await page(routes(f, {
    'POST /v1/team/channels/begin': async () => [200, { challengeId: 'bb', options: { challenge: 'AAAA', rpId: 'leash.test' } }],
    'POST /v1/team/channels/finish': async () => [200, { id: 'y'.repeat(24) }],
  }));
  await p.go('team');
  p.byId('chNew').click(); await p.settle();
  assert.match(p.toast(), /Give it a name/);
  p.byId('chKind').value = 'slack'; p.byId('chLabel').value = 'ops room 2'; p.byId('chUrl').value = SLACK;
  p.byId('chNew').click(); await p.settle();
  const sent = p.calls.filter((c) => c.path.startsWith('/v1/team/channels/'));
  assert.deepEqual(sent[0].body, { kind: 'slack', label: 'ops room 2', url: SLACK });
  assert.equal(p.byId('chUrl').value, '', 'the address does not stay in the form');
  assert.equal(p.byId('chLabel').value, '');
  const html = readFileSync(new URL('../../site/public/app/index.html', import.meta.url), 'utf8');
  assert.match(html, /id="chUrl" type="password" autocomplete="off"/, 'a password field: not shown over a shoulder, not remembered');
  const src = readFileSync(new URL('../../site/public/app/app.js', import.meta.url), 'utf8');
  assert.ok(!/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(/.test(src));
});

test('a viewer sees the window and the channels but none of the controls', async () => {
  const f = await fixtures();
  const vera = await add(f.w, f.u, 'Vera', 'viewer');
  const get = async (p) => (await f.w.req('GET', p, { cookie: vera.cookie })).body;
  const me = await get('/v1/me'), team = await get('/v1/team');
  const p = await page(routes(f, { 'GET /v1/me': async () => [200, me], 'GET /v1/team': async () => [200, team] }));
  await p.go('team');
  assert.equal(p.byId('bgBanner').hidden, false, 'a viewer sees the banner and can close it (closing only tightens)');
  assert.equal(p.byId('channels').all((c) => c.tag === 'button').length, 0, 'no test or remove');
  assert.ok(p.byId('channels').textContent.includes('ops room'));
  assert.equal(p.calls.filter((c) => c.path === '/v1/tokens' || c.path === '/v1/guard/keys').length, 1, 'the token list was fetched only by load(), not for a scope list a viewer cannot use');
});

// the phone: a push that carries nothing, then the notification the service worker builds from /v1/alerts
function serviceWorker(responses) {
  const listeners = {}, shown = [];
  const self = {
    addEventListener: (type, fn) => { listeners[type] = fn; }, skipWaiting() {}, clients: { claim() {}, matchAll: async () => [], openWindow: async () => {} },
    location: { origin: 'https://counterseal.example' },
    registration: { showNotification: async (title, o) => { shown.push(JSON.parse(JSON.stringify({ title, ...o }))); } },
  };
  const ctx = vm.createContext({ self, URL, Promise, JSON, Array, Object, String, Number, console, fetch: async (url) => responses(url) });
  vm.runInContext(readFileSync(new URL('../../site/public/sw.js', import.meta.url), 'utf8'), ctx);
  const fire = async (type, ev) => { let p; listeners[type]({ ...ev, waitUntil: (x) => { p = x; } }); await p; };
  return { fire, shown };
}
test('the phone says what happened: break glass opened or closed, a channel connected, in words with no reason or address in them', async () => {
  let team = [{ kind: 'breakglass_opened', at: 5, minutes: 30 }];
  const sw = serviceWorker(() => ({ ok: true, status: 200, json: async () => ({ holds: [], signins: [], passkeys: [], frozen_at: null, team }) }));
  await sw.fire('push', {});
  assert.equal(sw.shown.at(-1).title, 'Counterseal: break glass is open');
  assert.match(sw.shown.at(-1).body, /for up to 30 minutes, and every call is on the record\. Not expected\? Tap to close it\./);
  assert.equal(sw.shown.at(-1).data.url, '/app#team');
  team = [{ kind: 'breakglass_closed', at: 6 }]; await sw.fire('push', {});
  assert.equal(sw.shown.at(-1).title, 'Counterseal: break glass was closed');
  team = [{ kind: 'channel_added', at: 7, channel: 'discord' }]; await sw.fire('push', {});
  assert.equal(sw.shown.at(-1).title, 'A channel now hears your Counterseal alerts');
  assert.match(sw.shown.at(-1).body, /^Discord was connected\. It is only told: nobody can approve from it\./);
  team = [{ kind: 'channel_added', at: 8, channel: '<script>' }]; await sw.fire('push', {});
  assert.match(sw.shown.at(-1).body, /^A chat service was connected/);
});
