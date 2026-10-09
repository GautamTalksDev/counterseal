// Counterseal landing: live console feed, the nine-second comparison, the playable demo, the irreversible map.
// DOM building only (Trusted Types: no innerHTML). Respects prefers-reduced-motion.
import { liveGlow } from './glow.js';
liveGlow();
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => { const n = document.createElement(tag); Object.assign(n, props); for (const k of kids) if (k != null) n.append(k); return n; };
const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
const wait = (ms) => new Promise((r) => setTimeout(r, RM ? 0 : ms));

// ------------------------------------------------------------ copy install command
$('copyCmd').onclick = async () => {
  try { await navigator.clipboard.writeText($('cmdText').textContent); $('copyCmd').classList.add('copied'); setTimeout(() => $('copyCmd').classList.remove('copied'), 1500); } catch {}
};

// ------------------------------------------------------------ 1. hero console feed (calm: one row every ~2s, max 5)
const FEED = [
  ['GET', 'api.github.com/repos/acme/app/pulls', 'coding-agent'],
  ['POST', 'api.github.com/repos/acme/app/issues', 'coding-agent'],
  ['GET', 'api.stripe.com/v1/charges?limit=20', 'support-bot'],
  ['PATCH', 'api.cloudflare.com/zones/9a1/dns_records/44', 'infra-agent'],
  ['GET', 'api.supabase.com/v1/projects/abc/health', 'infra-agent'],
  ['POST', 'api.github.com/repos/acme/app/pulls/412/reviews', 'coding-agent'],
  ['GET', 'backboard.railway.app  query { deployments }', 'coding-agent'],
];
const feed = $('feed');
let fi = 0;
function pushFeed() {
  const [m, p, a] = FEED[fi++ % FEED.length];
  feed.prepend(el('li', {}, el('span', { className: 'dotc' }), el('span', { className: 'm', textContent: m }), el('span', { className: 'p', textContent: p }), el('span', { className: 'a', textContent: a }), el('span', { className: 's', textContent: 'allowed' })));
  while (feed.children.length > 5) feed.lastChild.remove();
}
for (let i = 0; i < 5; i++) pushFeed();
if (!RM) setInterval(() => { if (!document.hidden) pushFeed(); }, 2200);

// ------------------------------------------------------------ reveal on scroll
const io = new IntersectionObserver((es) => { for (const e of es) if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }, { rootMargin: '0px 0px -10% 0px' });
for (const n of document.querySelectorAll('.sec > *, .logos, .final > *')) { n.classList.add('reveal'); io.observe(n); }

// ------------------------------------------------------------ 2. nine seconds, side by side
const BAD = [
  [0.0, 'd', '> fix the credential mismatch in staging'],
  [1.6, '', 'agent  searching repo for RAILWAY_TOKEN'],
  [3.2, 'k', 'agent  found token in scripts/domains.sh'],
  [5.0, '', 'agent  POST backboard.railway.app'],
  [5.1, 'd', '       mutation { volumeDelete(volumeId: "vol_prod") }'],
  [6.8, 'r', 'api    200  volume deleted'],
  [7.6, 'r', 'api    backups deleted with volume (24)'],
  [9.0, 'r', 'prod   database unreachable. newest restore: 3 months old.'],
];
const GOOD = [
  [0.0, 'd', '> fix the credential mismatch in staging'],
  [1.6, '', 'agent  searching repo for RAILWAY_TOKEN'],
  [3.2, 'k', 'agent  found lsh_ token (scoped: staging, read+deploy)'],
  [5.0, '', 'agent  POST backboard.railway.app'],
  [5.1, 'd', '       mutation { volumeDelete(volumeId: "vol_prod") }'],
  [5.2, 'w', 'leash  HELD  rw.mutation: cannot be undone'],
  [6.4, 'd', 'phone  notification: "Your agent wants to delete vol_prod"'],
  [8.1, 'g', 'phone  denied with Face ID'],
  [9.0, 'g', 'agent  Understood. Snapshot the volume first instead?'],
];
let nineRun = 0;
async function playNine() {
  const run = ++nineRun;
  const tb = $('termBad'), tg = $('termGood'), cb = $('tBad'), cg = $('tGood');
  tb.replaceChildren(); tg.replaceChildren(); cb.className = 'timer mono'; cg.className = 'timer mono';
  const start = performance.now();
  let ib = 0, ig = 0;
  const step = () => {
    if (run !== nineRun) return;
    const t = RM ? 9 : Math.min(9, (performance.now() - start) / 1000);
    while (ib < BAD.length && BAD[ib][0] <= t) { const [, c, s] = BAD[ib++]; tb.append(el('span', { className: c, textContent: s }), '\n'); }
    while (ig < GOOD.length && GOOD[ig][0] <= t) { const [, c, s] = GOOD[ig++]; tg.append(el('span', { className: c, textContent: s }), '\n'); }
    cb.textContent = `${t.toFixed(1)}s`; cg.textContent = `${t.toFixed(1)}s`;
    if (t >= 6.8) cb.classList.add('red');
    if (t >= 8.1) cg.classList.add('ok');
    if (t < 9) requestAnimationFrame(step);
  };
  step();
}
new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { playNine(); o.disconnect(); } }, { threshold: 0.4 }).observe($('vs'));
$('replay').onclick = playNine;

// ------------------------------------------------------------ 3. the playable demo
const SC = [
  { label: 'List open pull requests', sub: 'GitHub, read only', kind: 'allow', call: 'GET api.github.com/repos/acme/app/pulls?state=open', reply: '200  12 open pull requests' },
  { label: 'Delete the staging volume', sub: 'Railway, the PocketOS call', kind: 'hold', call: 'POST backboard.railway.app  mutation { volumeDelete(volumeId: "vol_prod") }', what: 'Delete volume vol_prod', why: 'Deletes a volume and its backups. This cannot be undone.', rule: 'rw.mutation' },
  { label: 'Force push a rewritten main', sub: 'GitHub, history rewrite', kind: 'hold', call: 'PATCH api.github.com/repos/acme/app/git/refs/heads/main  {"force":true}', what: 'Force push acme/app main', why: 'Rewrites history for everyone on the repo.', rule: 'gh.force-push' },
  { label: 'Clean up old users', sub: 'Supabase SQL', kind: 'hold', call: 'POST api.supabase.com/v1/projects/abc/database/query  DELETE FROM users', what: 'DELETE FROM users', why: 'No WHERE clause. This removes every row.', rule: 'sb.sql' },
  { label: 'Refund the last 40 orders', sub: 'Stripe, moves money', kind: 'hold', call: 'POST api.stripe.com/v1/refunds  x40', what: 'Refund 40 charges', why: 'Moves money back to customers. Not reversible.', rule: 'st.money' },
];
const term = $('term'), picks = $('picks');
let busy = false, decide = null;
function line(cls, text) { term.append(el('span', { className: cls, textContent: text }), '\n'); term.scrollTop = term.scrollHeight; }
async function typeLine(text) { const s = el('span'); term.append(s, '\n'); for (const ch of text) { s.textContent += ch; await wait(8); } }
function phoneHold(sc) {
  $('phIdle').hidden = true; $('phHold').hidden = false;
  $('phWhat').textContent = sc.what; $('phWhy').textContent = sc.why;
  const ph = $('phone'); ph.classList.remove('buzz'); void ph.offsetWidth; ph.classList.add('buzz');
  return new Promise((res) => { decide = res; });
}
function phoneIdle() { $('phHold').hidden = true; $('phIdle').hidden = false; decide = null; }
$('phOk').onclick = () => decide && decide(true);
$('phNo').onclick = () => decide && decide(false);
async function run(sc, btn) {
  if (busy) return; busy = true;
  [...picks.children].forEach((b) => b.classList.toggle('on', b === btn));
  term.replaceChildren();
  line('d', `> ${sc.label.toLowerCase()}`);
  await wait(250); await typeLine(`agent  ${sc.call}`);
  await wait(300);
  if (sc.kind === 'allow') { line('g', 'leash  allowed. key injected server side, the agent never saw it'); line('d', `api    ${sc.reply}`); busy = false; return; }
  line('w', `leash  HELD  ${sc.rule}`); line('w', `       ${sc.why}`);
  line('d', 'agent  That cannot be undone, so I have paused and asked you to approve it.');
  const ok = await phoneHold(sc);
  phoneIdle();
  if (ok) { line('g', 'phone  approved with Face ID (this exact request, once, 10 min)'); await wait(300); line('d', 'agent  retrying... done.'); }
  else { line('r', 'phone  denied'); await wait(300); line('d', 'agent  Understood, I will not do that. Want a safer plan?'); }
  busy = false;
}
for (const sc of SC) {
  const b = el('button', { type: 'button' }, el('b', { textContent: sc.label }), el('small', {}, el('i', { className: sc.kind === 'hold' ? 'h' : '' }), sc.sub));
  b.onclick = () => run(sc, b); picks.append(b);
}
line('d', 'Pick something on the left for the agent to try.');

// ------------------------------------------------------------ 4. the irreversible map
fetch('/v1/meta').then((r) => r.json()).then((m) => {
  $('mapVer').textContent = `v${m.mapVersion}`;
  const tabs = $('mapTabs'), rows = $('mapRows');
  const show = (p) => {
    [...tabs.children].forEach((b) => b.setAttribute('aria-selected', String(b.dataset.id === p.id)));
    rows.replaceChildren(el('div', { className: 'mrow h' }, el('span', { textContent: 'Rule' }), el('span', { textContent: 'Call' }), el('span', { textContent: 'Why it is held' })));
    for (const r of p.irreversible) rows.append(el('div', { className: 'mrow' }, el('span', { className: 'id', textContent: r.id }), el('span', { className: 'rt', textContent: `${r.method} ${r.path}` }), el('span', { className: 'why', textContent: r.why })));
  };
  for (const p of m.providers) {
    const b = el('button', { type: 'button', role: 'tab', textContent: `${p.name}  ${p.irreversible.length}` }); b.dataset.id = p.id;
    b.onclick = () => show(p); tabs.append(b);
  }
  if (m.providers.length) show(m.providers[0]);
}).catch(() => {});
