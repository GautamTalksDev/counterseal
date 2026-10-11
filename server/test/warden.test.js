// The Warden (site/public/app/warden.js): the mapping from the account's real state to the mascot's mood, and the
// dashboard's Content Security Policy, which the mascot and the v2 cards must not weaken.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { wardenState, topPct, WARDEN_STATES, WARDEN_ALT } from '../../site/public/app/warden.js';

const SITE = new URL('../../site/public/', import.meta.url);
const read = (p) => readFileSync(new URL(p, SITE), 'utf8');
const scope = (s, spent, cap, extra = 0) => ({ scope: s, label: s, day: { spent, cap, extra }, month: { spent, cap: null } });
const budget = (...scopes) => ({ scopes });
const NOW = 1_800_000_000_000;

test('calm when nothing is waiting, nothing tripped and no cap is near', () => {
  const w = wardenState({ holds: [], tokens: [{ id: 't', label: 'a' }], budget: budget(scope('account', 1_000_000, 10_000_000)), now: NOW });
  assert.equal(w.state, 'calm');
  assert.equal(wardenState().state, 'calm');
});

test('held: one or more pending calls, with the count in the words', () => {
  assert.equal(wardenState({ holds: [{ id: 'h', rule: 'irreversible' }] }).hot, '1 call');
  const w = wardenState({ holds: [{ id: 'a' }, { id: 'b' }] });
  assert.equal(w.state, 'held'); assert.equal(w.hot, '2 calls'); assert.equal(w.badge, 'CALL HELD');
});

test('spend80 at 80% of any cap (day or month, with a one-time raise counted), cap at 100% or a budget.cap hold', () => {
  assert.equal(wardenState({ budget: budget(scope('tok:1', 7_900_000, 10_000_000)) }).state, 'calm');
  assert.equal(wardenState({ budget: budget(scope('tok:1', 8_000_000, 10_000_000)) }).state, 'spend80');
  assert.equal(wardenState({ budget: budget(scope('tok:1', 10_000_000, 10_000_000)) }).state, 'cap');
  assert.equal(wardenState({ budget: budget(scope('tok:1', 10_000_000, 10_000_000, 5_000_000)) }).state, 'calm', 'raised once: 10 of 15');
  assert.equal(wardenState({ budget: { scopes: [{ scope: 'account', day: { spent: 0, cap: null }, month: { spent: 9_000_000, cap: 10_000_000 } }] } }).state, 'spend80');
  assert.equal(wardenState({ holds: [{ id: 'h', rule: 'budget.cap' }] }).state, 'cap');
  assert.equal(topPct(null), null); assert.equal(topPct(budget(scope('account', 5, null))), null);
});

test('tripped: a freeze, a tripped live token or a breaker hold; a revoked token does not count', () => {
  assert.equal(wardenState({ frozenAt: NOW }).state, 'tripped');
  assert.equal(wardenState({ frozenAt: NOW }).badge, 'FROZEN');
  assert.equal(wardenState({ tokens: [{ id: 't', tripped_at: NOW }] }).state, 'tripped');
  assert.equal(wardenState({ tokens: [{ id: 't', tripped_at: NOW, revoked: 1 }] }).state, 'calm');
  assert.equal(wardenState({ holds: [{ id: 'h', rule: 'brake.tripped' }] }).state, 'tripped');
});

test('priority: tripped over cap over held over spend80 over approved over calm', () => {
  const all = { frozenAt: NOW, holds: [{ id: 'h' }], budget: budget(scope('tok:1', 10_000_000, 10_000_000)), approvedAt: NOW, now: NOW };
  assert.equal(wardenState(all).state, 'tripped');
  assert.equal(wardenState({ ...all, frozenAt: null }).state, 'cap');
  assert.equal(wardenState({ ...all, frozenAt: null, budget: budget(scope('tok:1', 9_000_000, 10_000_000)) }).state, 'held');
  assert.equal(wardenState({ ...all, frozenAt: null, holds: [], budget: budget(scope('tok:1', 9_000_000, 10_000_000)) }).state, 'spend80');
  assert.equal(wardenState({ approvedAt: NOW, now: NOW + 1000 }).state, 'approved');
  assert.equal(wardenState({ approvedAt: NOW, now: NOW + 7000 }).state, 'calm', 'an approval shows for a few seconds only');
  assert.equal(wardenState({ approvedAt: NOW + 5000, now: NOW }).state, 'calm', 'a clock in the future is ignored');
});

test('every state has words, an alt text and its pictures (an animated WebP and a still PNG), all small enough for the web', () => {
  let total = 0;
  for (const s of WARDEN_STATES) {
    assert.ok(WARDEN_ALT[s] && WARDEN_ALT[s].length > 20, s);
    for (const ext of ['webp', 'png']) {
      const f = new URL(`media/warden/${s}.${ext}`, SITE);
      assert.ok(existsSync(f), `${s}.${ext}`);
      total += statSync(f).size;
    }
  }
  assert.ok(total < 3 * 1024 * 1024, `all states under 3 MB, got ${total}`);
  const samples = [wardenState({}), wardenState({ holds: [{}] }), wardenState({ frozenAt: 1 }), wardenState({ holds: [{ rule: 'budget.cap' }] }), wardenState({ tokens: [{ tripped_at: 1 }] })];
  for (const w of samples) for (const v of Object.values(w)) assert.ok(!/[–—]|--/.test(String(v)), v);
  for (const v of Object.values(WARDEN_ALT)) assert.ok(!/[–—]|--/.test(v), v);
});

test('CSP: scripts only from this origin, no inline code or styles, Trusted Types required', () => {
  const line = read('_headers').split('\n').find((l) => l.trim().startsWith('Content-Security-Policy:'));
  assert.ok(line, 'the site sends a CSP');
  const csp = Object.fromEntries(line.split(':').slice(1).join(':').split(';').map((d) => d.trim().split(/\s+/)).map(([k, ...v]) => [k, v]));
  assert.deepEqual(csp['script-src'], ["'self'"]);
  assert.deepEqual(csp['style-src'], ["'self'"]);
  assert.deepEqual(csp['img-src'], ["'self'", 'data:'], 'the mascot loads from this origin');
  assert.deepEqual(csp['require-trusted-types-for'], ["'script'"]);
  assert.deepEqual(csp['trusted-types'], ['leash-sw']);
  assert.deepEqual(csp['object-src'], ["'none'"]); assert.deepEqual(csp['frame-ancestors'], ["'none'"]); assert.deepEqual(csp['base-uri'], ["'none'"]);
  for (const v of Object.values(csp)) assert.ok(!v.some((x) => /unsafe-|\*/.test(x)), v.join(' '));
});

test('the dashboard page and its code keep to that CSP: no inline scripts, handlers or styles, no HTML sinks', () => {
  const html = read('app/index.html');
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) { assert.match(m[1], /\bsrc="\/app\//); assert.equal(m[2].trim(), ''); }
  assert.ok(!/\son[a-z]+\s*=/i.test(html), 'no inline event handlers');
  assert.ok(!/\sstyle\s*=/i.test(html), 'no inline style attributes');
  assert.ok(/id="wImg"[^>]*alt="[^"]{20,}"/.test(html), 'the Warden has a text alternative');
  assert.ok(/aria-live="polite"/.test(html), 'mood changes are announced');
  for (const f of ['app/app.js', 'app/warden.js']) {
    const js = read(f);
    assert.ok(!/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|\beval\(|new Function\(/.test(js), f);
  }
  assert.match(read('app/app.js'), /prefers-reduced-motion: reduce/, 'a still picture for reduced motion');
  assert.match(read('sw.js'), /'\/app\/warden\.js'/, 'the offline copy includes the mapping the app imports');
  const css = read('styles.css');
  assert.match(css, /prefers-color-scheme:light/); assert.match(css, /prefers-reduced-motion:reduce/);
});

test('the PWA icons are the Warden and the manifest lists them', () => {
  const m = JSON.parse(read('manifest.webmanifest'));
  for (const n of ['192', '512']) {
    assert.ok(m.icons.some((i) => i.src === `/icon-${n}.png` && i.purpose === 'any'));
    assert.ok(m.icons.some((i) => i.src === `/icon-maskable-${n}.png` && i.purpose === 'maskable'));
    const png = readFileSync(new URL(`icon-${n}.png`, SITE));
    assert.equal(png.readUInt32BE(16), Number(n)); assert.equal(png.readUInt32BE(20), Number(n));
  }
  for (const f of ['favicon.ico', 'favicon-16.png', 'favicon-32.png']) assert.ok(existsSync(new URL(f, SITE)), f);
});
