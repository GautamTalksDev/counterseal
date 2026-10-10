// The installable app: the service worker runs here (node:vm with a stand-in for the worker's globals) to prove it never
// stores private data, never offers an approve action, opens the exact hold, and sets the icon badge; the manifest and
// the icons are complete; the app page links them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync, existsSync } from 'node:fs';

const SITE = new URL('../../site/public/', import.meta.url);
const read = (p) => readFileSync(new URL(p, SITE), 'utf8');
const ORIGIN = 'https://counterseal.test';

/** load sw.js with fake self, caches and fetch; returns the handlers and what happened */
function worker({ fetchImpl, ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0' } = {}) {
  const handlers = {}, stored = new Map(), shown = [], badges = [], opened = [];
  const cache = { put: async (k, r) => { stored.set(typeof k === 'string' ? k : new URL(k.url).pathname, r); }, match: async (k) => stored.get(k)?.clone() };
  const self = {
    location: new URL(ORIGIN + '/sw.js'),
    navigator: { userAgent: ua, setAppBadge: async (n) => badges.push(n), clearAppBadge: async () => badges.push(0) },
    addEventListener: (t, f) => { handlers[t] = f; },
    skipWaiting: async () => {},
    clients: { claim: async () => {}, matchAll: async () => [], openWindow: async (u) => opened.push(u) },
    registration: { showNotification: async (title, o) => shown.push({ title, ...o }) },
  };
  const caches = { open: async () => cache, keys: async () => ['counterseal-shell-v1', 'old-cache'], delete: async () => true, match: async (k) => stored.get(k)?.clone() };
  const ctx = vm.createContext({ self, caches, fetch: fetchImpl || (async () => new Response('x')), URL, Response, Request, Headers, console, Promise, Set, Map, JSON, Number, Array, String, Math, Date, Object });
  vm.runInContext(read('sw.js'), ctx, { filename: 'sw.js' });
  return { handlers, stored, shown, badges, opened, self };
}
const event = (props) => { const waits = []; return { ...props, waitUntil: (p) => waits.push(p), respondWith: (p) => { waits.push(p); event.responded = p; }, waits }; };
const ok = (body = 'ok', headers = {}) => { const r = new Response(body, { status: 200, headers }); Object.defineProperty(r, 'type', { value: 'basic' }); return r; };

test('the service worker caches only the app\'s own files: never the API, the proxy, credentials, queries or no-store answers', async () => {
  const seen = [];
  const w = worker({ fetchImpl: async (req) => { seen.push(typeof req === 'string' ? req : req.url); return ok('x', { 'cache-control': 'public, max-age=60' }); } });
  const install = event({}); w.handlers.install(install); await Promise.all(install.waits);
  const cached = [...w.stored.keys()];
  assert.ok(cached.includes('/app') && cached.includes('/app/app.js') && cached.includes('/styles.css'));
  for (const k of cached) assert.ok(!/^\/(v1|p|\.well-known)\//.test(k), k);
  // fetches it leaves alone (no respondWith): the API, the proxy, writes, other sites, queries, bearer requests, other pages
  const untouched = [
    new Request(ORIGIN + '/v1/holds'), new Request(ORIGIN + '/v1/me'), new Request(ORIGIN + '/p/github/user'), new Request(ORIGIN + '/.well-known/security.txt'),
    new Request(ORIGIN + '/app/app.js', { method: 'POST', body: '{}' }), new Request('https://evil.test/app/app.js'), new Request(ORIGIN + '/app/app.js?x=1'),
    new Request(ORIGIN + '/styles.css', { headers: { authorization: 'Bearer lsh_x' } }), new Request(ORIGIN + '/docs/'), new Request(ORIGIN + '/privacy/'),
  ];
  for (const req of untouched) { const e = event({ request: req }); let used = false; e.respondWith = () => { used = true; }; w.handlers.fetch(e); assert.equal(used, false, req.method + ' ' + req.url); }
  // a shell file: network first, and an answer marked no-store or private is never kept
  w.stored.clear();
  const w2 = worker({ fetchImpl: async () => ok('fresh', { 'cache-control': 'no-store' }) });
  const e = event({ request: new Request(ORIGIN + '/app/app.js') }); let p; e.respondWith = (x) => { p = x; }; w2.handlers.fetch(e);
  assert.equal(await (await p).text(), 'fresh'); await Promise.all(e.waits);
  assert.equal(w2.stored.size, 0, 'no-store is never cached');
});

test('offline: the app page and its files come from the copy; nothing else does', async () => {
  let online = true;
  const w = worker({ fetchImpl: async () => { if (!online) throw new TypeError('offline'); return ok('shell'); } });
  const install = event({}); w.handlers.install(install); await Promise.all(install.waits);
  online = false;
  for (const url of [ORIGIN + '/app', ORIGIN + '/app#hold=' + 'a'.repeat(24)]) {
    const req = new Request(url); Object.defineProperty(req, 'mode', { value: 'navigate' });
    const e = event({ request: req }); let p; e.respondWith = (x) => { p = x; }; w.handlers.fetch(e);
    assert.equal(await (await p).text(), 'shell', url);
  }
});

test('a notification never approves: its only action is Freeze; a tap opens the exact hold; the badge counts what waits', async () => {
  const hold = { id: 'b'.repeat(24), kind: 'proxy', method: 'DELETE', host: 'api.github.com', path: '/repos/acme/app', why: 'Deletes the repository.', created_at: Date.now(), needs: 1, votes: [] };
  const w = worker({ fetchImpl: async (u) => (String(u).endsWith('/v1/alerts') ? new Response(JSON.stringify({ holds: [hold, { ...hold, id: 'c'.repeat(24), created_at: 1 }], signins: [], passkeys: [], frozen_at: null, team: [] })) : ok()) });
  const e = event({}); w.handlers.push(e); await Promise.all(e.waits);
  const n = w.shown[0];
  assert.match(n.title, /DELETE api\.github\.com/);
  assert.equal(n.data.url, '/app#hold=' + hold.id);
  assert.match(n.body, /Approving needs your passkey in the app/);
  assert.deepEqual(Array.from(n.actions || [], (a) => a.action), ['freeze']);
  assert.deepEqual(w.badges, [2]);
  // the source has no approve action anywhere
  assert.ok(!/action:\s*'approve'/i.test(read('sw.js')));
  // tapping it opens that hold, and does nothing else
  const c = event({ notification: { close() {}, data: { url: '/app#hold=' + hold.id } }, action: '' });
  w.handlers.notificationclick(c); await Promise.all(c.waits);
  assert.deepEqual(w.opened, [ORIGIN + '/app#hold=' + hold.id]);
  // the demo: no Freeze button, and it says it is a demo
  const d = worker({ fetchImpl: async () => new Response(JSON.stringify({ holds: [{ ...hold, kind: 'demo', path: '/repos/you/practice-repo' }], signins: [], passkeys: [], team: [] })) });
  const de = event({}); d.handlers.push(de); await Promise.all(de.waits);
  assert.match(d.shown[0].title, /^Demo:/); assert.equal(d.shown[0].actions, undefined);
  // nothing waiting clears the badge; Linux and Android are left alone
  const z = worker({ fetchImpl: async () => new Response(JSON.stringify({ holds: [], signins: [], passkeys: [], team: [] })) });
  const ze = event({}); z.handlers.push(ze); await Promise.all(ze.waits);
  assert.deepEqual(z.badges, [0]);
  const l = worker({ ua: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0', fetchImpl: async () => new Response(JSON.stringify({ holds: [hold], signins: [], passkeys: [], team: [] })) });
  const le = event({}); l.handlers.push(le); await Promise.all(le.waits);
  assert.deepEqual(l.badges, []);
});

test('the manifest makes an installable app: name, standalone, scope, every icon size, maskable, monochrome, shortcuts to waiting approvals', () => {
  const m = JSON.parse(read('manifest.webmanifest'));
  assert.equal(m.name, 'Counterseal'); assert.equal(m.display, 'standalone'); assert.equal(m.start_url, '/app'); assert.equal(m.id, '/app');
  const sizes = m.icons.filter((i) => i.purpose === 'any' && i.type === 'image/png').map((i) => i.sizes);
  for (const s of ['48x48', '72x72', '96x96', '128x128', '144x144', '192x192', '256x256', '384x384', '512x512']) assert.ok(sizes.includes(s), s);
  assert.ok(m.icons.some((i) => i.purpose === 'maskable' && i.sizes === '512x512'));
  assert.ok(m.icons.some((i) => i.purpose === 'monochrome'));
  for (const i of m.icons) assert.ok(existsSync(new URL('.' + i.src, SITE)), i.src);
  // PNG sizes are what the manifest says
  for (const i of m.icons.filter((x) => x.type === 'image/png')) {
    const b = readFileSync(new URL('.' + i.src, SITE));
    assert.equal(`${b.readUInt32BE(16)}x${b.readUInt32BE(20)}`, i.sizes, i.src);
  }
  assert.ok(m.shortcuts.some((s) => s.url === '/app#held'));
  for (const s of m.shortcuts) for (const i of s.icons) assert.ok(existsSync(new URL('.' + i.src, SITE)), i.src);
  const app = read('app/index.html');
  assert.match(app, /<link rel="manifest" href="\/manifest.webmanifest">/);
  assert.match(app, /<link rel="apple-touch-icon" href="\/apple-touch-icon.png">/);
  const t = readFileSync(new URL('./apple-touch-icon.png', SITE));
  assert.equal(`${t.readUInt32BE(16)}x${t.readUInt32BE(20)}`, '180x180');
});

test('security.txt is valid (RFC 9116): contact, an Expires in the future and under a year away, canonical, policy', async () => {
  const { SECURITY_TXT } = await import('../src/index.js');
  const t = SECURITY_TXT({ ORIGIN: 'https://counterseal.gautamkhosla.com', RP_ID: 'counterseal.gautamkhosla.com' });
  assert.match(t, /^Contact: mailto:security@gautamkhosla\.com$/m);
  const exp = Date.parse(/^Expires: (.+)$/m.exec(t)[1]);
  assert.ok(exp > Date.now() + 30 * 86_400_000, 'Expires is more than 30 days away (move it a year forward: docs/RELEASE.md)');
  assert.ok(exp < Date.now() + 366 * 86_400_000, 'RFC 9116 recommends less than a year');
  assert.match(t, /^Canonical: https:\/\/counterseal\.gautamkhosla\.com\/\.well-known\/security\.txt$/m);
  assert.match(t, /^Policy: https:\/\/counterseal\.gautamkhosla\.com\/security\/$/m);
});
