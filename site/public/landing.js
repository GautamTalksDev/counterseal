// Counterseal homepage. Every demo here runs in this tab with real cryptography (see /js/core.js) and sends nothing
// anywhere. The page makes two same-origin reads: the irreversible map (/v1/meta, with a bundled copy as fallback) and
// the public log's head (/v1/stats). DOM is built with createElement and textContent only (Trusted Types, no innerHTML).
import { waxLight } from '/js/bg.js';
import { impression, press } from '/js/impression.js';
import { ORIGIN, MAP_VERSION, canEd25519, newAgentKey, signRequest, verifyAgentSig, BrokerError, DemoLog, DemoAccount, verify, sha256hex, hex, b64 } from '/js/core.js';

const $ = (id) => document.getElementById(id);
const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
const wait = (ms) => new Promise((r) => setTimeout(r, RM ? 0 : ms));
const SVGNS = 'http://www.w3.org/2000/svg';
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else if (k.startsWith('aria-') || k.startsWith('data-')) n.setAttribute(k, v); else n[k] = v;
  }
  for (const c of kids) if (c != null) n.append(c);
  return n;
}
function svg(tag, attrs = {}) { const n = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v)); return n; }
const short = (s, n = 10) => (s.length > n + 1 ? s.slice(0, n) + '…' : s);
const pretty = (o) => JSON.stringify(o, null, 2);
const brand = (s) => String(s).replace(/\bLEASH\b/g, 'Counterseal');

waxLight();

// ------------------------------------------------------------------ small things
$('copyCmd').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText('npx counterseal login'); $('copyCmd').classList.add('copied'); $('copyCmd').setAttribute('aria-label', 'Copied: npx counterseal login'); setTimeout(() => $('copyCmd').classList.remove('copied'), 1600); } catch { /* clipboard blocked: the command is visible */ }
});
const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }), { threshold: 0.12, rootMargin: '0px 0px -6% 0px' });
document.querySelectorAll('.rv').forEach((n) => io.observe(n));
// nav: highlight the section in view
const navLinks = [...document.querySelectorAll('.links a[href^="#"]')];
const navIo = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) navLinks.forEach((a) => a.classList.toggle('cur', a.getAttribute('href') === '#' + e.target.id)); }), { rootMargin: '-40% 0px -55% 0px' });
navLinks.forEach((a) => { const s = document.querySelector(a.getAttribute('href')); if (s) navIo.observe(s); });

// ------------------------------------------------------------------ video loops: loaded near the viewport, playing only while seen
for (const v of document.querySelectorAll('video')) {
  if (RM) continue; // the poster stays
  let loaded = false;
  new IntersectionObserver((es) => es.forEach((e) => {
    if (e.isIntersecting) {
      if (!loaded) { for (const s of v.querySelectorAll('source')) s.src = s.dataset.src; v.load(); loaded = true; }
      v.play().catch(() => {});
    } else if (loaded) v.pause();
  }), { rootMargin: '200px 0px' }).observe(v);
}

// ------------------------------------------------------------------ the Merkle tree drawing (shared by the hero and Record)
/** RFC 6962 shape: node(start, n) splits at the largest power of two below n */
function layout(n) {
  const nodes = [];
  const split = (k) => { let p = 1; while (p * 2 < k) p *= 2; return p; };
  const build = (start, size, depth) => {
    const node = { start, size, depth };
    if (size > 1) { const k = split(size); node.l = build(start, k, depth + 1); node.r = build(start + k, size - k, depth + 1); }
    nodes.push(node);
    return node;
  };
  const root = build(0, n, 0);
  return { root, nodes, depth: Math.max(...nodes.map((x) => x.depth)) };
}
function proofNodes(root, m) {
  const path = [], sib = [];
  let cur = root;
  while (cur.l) { path.push(cur); if (m < cur.r.start) { sib.push(cur.r); cur = cur.l; } else { sib.push(cur.l); cur = cur.r; } }
  path.push(cur);
  return { path: new Set(path), sib: new Set(sib) };
}
function drawTree(svgEl, n, { sel = -1, fresh = [], bad = -1, labels = false, onPick } = {}) {
  svgEl.replaceChildren();
  if (!n) return;
  const vb = svgEl.viewBox.baseVal, W = vb.width, H = vb.height, padX = labels ? 18 : 8, padY = labels ? 14 : 6;
  const { root, nodes, depth } = layout(n);
  const lw = (W - 2 * padX) / Math.max(1, n - 1 || 1);
  const pos = new Map();
  const place = (nd) => {
    if (!nd.l) { pos.set(nd, [n === 1 ? W / 2 : padX + nd.start * lw, padY + (H - 2 * padY - (labels ? 14 : 0)) * (depth ? nd.depth / depth : 1)]); return; }
    place(nd.l); place(nd.r);
    const a = pos.get(nd.l), b = pos.get(nd.r);
    pos.set(nd, [(a[0] + b[0]) / 2, padY + (H - 2 * padY - (labels ? 14 : 0)) * (nd.depth / Math.max(1, depth))]);
  };
  place(root);
  const pf = sel >= 0 ? proofNodes(root, sel) : { path: new Set(), sib: new Set() };
  for (const nd of nodes) if (nd.l) for (const c of [nd.l, nd.r]) {
    const [x1, y1] = pos.get(nd), [x2, y2] = pos.get(c);
    svgEl.append(svg('line', { x1, y1, x2, y2, class: pf.path.has(nd) && pf.path.has(c) ? 'pl' : '' }));
  }
  const r = labels ? 7 : 3.4;
  for (const nd of nodes) {
    const [x, y] = pos.get(nd);
    let cls = nd.l ? '' : 'lf';
    if (nd === root) cls += ' rt';
    else if (pf.sib.has(nd)) cls += ' pf';
    if (!nd.l && fresh.includes(nd.start)) cls += ' new';
    if (!nd.l && nd.start === sel) cls += ' sel';
    if (!nd.l && nd.start === bad) cls += ' bad';
    const c = svg('circle', { cx: x, cy: y, r: nd === root ? r + 1.5 : r, class: cls.trim() });
    if (!nd.l && onPick) {
      c.setAttribute('tabindex', '0'); c.setAttribute('role', 'button'); c.setAttribute('aria-label', `Receipt #${nd.start}`);
      c.addEventListener('click', () => onPick(nd.start));
      c.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onPick(nd.start); } });
    }
    svgEl.append(c);
    if (labels && !nd.l && (n <= 24 || nd.start % 2 === 0 || nd.start === sel)) { const t = svg('text', { x, y: y + 20, 'text-anchor': 'middle' }); t.textContent = '#' + nd.start; svgEl.append(t); }
  }
}

// ------------------------------------------------------------------ shared demo state
const S = { log: null, acct: null, agent: null, cps: [], fresh: [], focus: -1 };
const REQ = { method: 'POST', path: '/p/stripe/v1/refunds', body: 'charge=ch_demo_3Pq&amount=4200', ctype: 'application/x-www-form-urlencoded', host: 'api.stripe.com', rule: 'st.money', why: 'Moves money.' };
const url = () => ORIGIN + REQ.path;
const nonces = new Set();
const seen = async (k) => { if (nonces.has(k)) return true; nonces.add(k); return false; };
const reqObj = (headers, method = REQ.method) => ({ method, url: url(), headers: new Headers({ 'content-type': REQ.ctype, ...headers }) });

async function seedLog() {
  S.log = await new DemoLog('demo-log-in-this-tab').init();
  S.acct = new DemoAccount(S.log);
  const T = 'token:3f1a9c0d7e2b4a6c8d0e1f2a';
  const seeds = [
    ['proxy', { method: 'POST', host: 'api.github.com', path: '/repos/acme/app/issues', status: 201 }],
    ['proxy', { method: 'PATCH', host: 'api.github.com', path: '/repos/acme/app/pulls/412', status: 200 }],
    ['hold', { method: 'DELETE', host: 'api.github.com', path: '/repos/acme/old-site', rule: 'gh.delete' }],
    ['deny', { method: 'DELETE', host: 'api.github.com', rule: 'gh.delete', by: 'web' }],
    ['proxy', { method: 'POST', host: 'api.cloudflare.com', path: '/zones/9a1/dns_records', status: 200 }],
    ['hold', { method: 'POST', host: 'api.supabase.com', path: '/v1/projects/abcd/database/query', rule: 'sb.sql' }],
    ['approve', { method: 'POST', host: 'api.supabase.com', rule: 'sb.sql', passkey: '5be1c0a7d2f9e381' }],
    ['proxy_approved', { method: 'POST', host: 'api.supabase.com', path: '/v1/projects/abcd/database/query', rule: 'sb.sql' }],
  ];
  for (const [action, detail] of seeds) await S.acct.record(action === 'approve' || action === 'deny' ? 'web' : T, action, detail);
  S.cps.push(await S.log.checkpoint());
}

// ------------------------------------------------------------------ HERO: one refund, three seals
const seal = $('seal'), turn = $('sealTurn');
let impF = null, impB = null, running = false;
function step(id, cls, title, parts) {
  const li = $(id);
  li.classList.remove('on', 'done', 'hold', 'bad');
  for (const c of cls) li.classList.add(c);
  if (title) li.querySelector('b').textContent = title;
  if (parts) { const p = $(id + 't'); p.replaceChildren(...parts.map((x) => (typeof x === 'string' ? x : el('span', { class: x[0], text: x[1] })))); }
}
function treeMini(sel) { drawTree($('mtree'), S.log.size, { sel, fresh: S.fresh }); }

async function runHero() {
  if (running) return;
  running = true;
  $('again').disabled = true; $('acts').hidden = true; $('toast').classList.remove('on'); $('heldN').classList.remove('on');
  seal.classList.remove('turned', 'held', 'sealed', 'denied'); seal.classList.add('idle');
  ['st1', 'st2', 'st3', 'st4'].forEach((s) => step(s, [], null, null));
  step('st1', [], 'Sealed by the agent', ['Waiting for the agent’s signature.']);
  step('st2', [], 'Held for your passkey', ['The broker checks the irreversible map.']);
  step('st3', [], 'Countersealed by you', ['Waiting for you.']);
  step('st4', [], 'Recorded in the log', ['Each decision becomes a receipt.']);
  S.fresh = [];
  treeMini(-1);
  impF && impF.draw(0);

  // 1. the agent makes its own key and seals the request
  S.agent = await newAgentKey();
  whoKey();
  impF = impression($('impF'), { kind: 'seal', bytes: S.agent.bytes, ring: `AGENT KEY · ${S.agent.keyid.slice(0, 10)} · ED25519 ·` });
  impF.draw(0);
  await wait(500);
  step('st1', ['on'], null, ['Signing the request with a fresh Ed25519 key…']);
  const signed = await signRequest({ method: REQ.method, url: url(), body: REQ.body, contentType: REQ.ctype }, { key: S.agent.privateKey, kid: S.agent.keyid });
  const sl = $('sigLine');
  sl.replaceChildren('Signature-Input: sig1=("@method" "@target-uri" "content-digest" "content-type");created=' + signed.created + ';keyid="', el('b', { text: short(S.agent.keyid, 12) }), '";nonce="' + short(signed.nonce, 8) + '";tag="leash-pop"');
  await press(impF, 760, RM);
  await wait(250);
  const t0 = performance.now();
  await verifyAgentSig(reqObj(signed.headers), new TextEncoder().encode(REQ.body), S.agent, seen);
  const ms = (performance.now() - t0).toFixed(1);
  step('st1', ['done'], null, ['Signed with the agent’s own Ed25519 key ', ['k', short(S.agent.keyid, 10)], ` (RFC 9421). Checks passed in ${ms} ms; the nonce is used up.`]);

  // 2. the broker holds it
  await wait(650);
  const holdId = hex(crypto.getRandomValues(new Uint8Array(12)));
  const held = await S.acct.record('token:3f1a9c0d7e2b4a6c8d0e1f2a', 'hold', { method: REQ.method, host: REQ.host, path: '/v1/refunds', agent_key: S.agent.keyid, rule: REQ.rule, hold: holdId, preview_sha256: await sha256hex(REQ.body) });
  S.fresh.push(held.index);
  S.cps.push(await S.log.checkpoint());
  S.holdCp = S.cps[S.cps.length - 1];
  seal.classList.add('held');
  step('st2', ['hold'], 'Held for your passkey', [['w', 'HTTP 428 held_for_approval'], ` · rule ${REQ.rule}: ${REQ.why} Receipt #${held.index} sealed as `, ['w', 'held'], '.']);
  $('acts').hidden = false;
  $('heldN').textContent = '1'; $('heldN').classList.add('on');
  $('toast').classList.add('on');
  treeMini(held.index);
  S.holdId = holdId;
  running = false;
}

async function decide(ok) {
  if (running || $('acts').hidden) return;
  running = true;
  $('acts').hidden = true; $('toast').classList.remove('on'); $('heldN').classList.remove('on');
  seal.classList.remove('held');
  if (ok) {
    // 3. the counterseal: a passkey ceremony in the real app; a stand-in here
    const assertion = crypto.getRandomValues(new Uint8Array(32));
    const fp = (await sha256hex(b64(assertion))).slice(0, 16);
    impB = impression($('impB'), { kind: 'counter', bytes: assertion, ring: `COUNTERSEALED · PASSKEY ${fp.slice(0, 6)} · ONCE ·` });
    impB.draw(0);
    seal.classList.add('turned');
    await wait(900);
    await press(impB, 760, RM);
    const ap = await S.acct.record('web', 'approve', { hold: S.holdId, method: REQ.method, host: REQ.host, rule: REQ.rule, passkey: fp });
    S.fresh.push(ap.index);
    step('st2', ['done'], 'Held, then approved', [['w', 'HTTP 428'], ` · ${REQ.rule} · receipt #${ap.index - 1}`]);
    step('st3', ['on'], 'Countersealed by you', ['Approved. The agent can retry that exact request once.']);
    treeMini(ap.index);
    await wait(900);
    // the agent retries the identical request, signed again with a fresh nonce
    const again = await signRequest({ method: REQ.method, url: url(), body: REQ.body, contentType: REQ.ctype }, { key: S.agent.privateKey, kid: S.agent.keyid });
    await verifyAgentSig(reqObj(again.headers), new TextEncoder().encode(REQ.body), S.agent, seen);
    const ex = await S.acct.record('token:3f1a9c0d7e2b4a6c8d0e1f2a', 'proxy_approved', { method: REQ.method, host: REQ.host, path: '/v1/refunds', agent_key: S.agent.keyid, rule: REQ.rule, hold: S.holdId });
    S.fresh.push(ex.index);
    step('st3', ['done'], 'Countersealed by you', ['The agent retried, freshly signed. The approval matched and was used up; the call went out with the vault’s key: ', ['k', 'approved'], '. (Here, nothing leaves your browser.)']);
    await recordStep(ex.index, `#${ap.index - 1} held, #${ap.index} approved, #${ex.index} executed`);
    seal.classList.add('sealed');
  } else {
    const dn = await S.acct.record('web', 'deny', { hold: S.holdId, method: REQ.method, host: REQ.host, rule: REQ.rule, by: 'web' });
    S.fresh.push(dn.index);
    seal.classList.add('denied');
    step('st2', ['done'], 'Held, then denied', [['w', 'HTTP 428'], ` · ${REQ.rule} · receipt #${dn.index - 1}`]);
    step('st3', ['bad'], 'Denied by you', ['Nothing reached Stripe. If the agent tries again, it is held again.']);
    await recordStep(dn.index, `#${dn.index - 1} held, #${dn.index} denied`);
  }
  $('again').disabled = false;
  running = false;
  recordView(S.focus = S.log.size - 1);
}

async function recordStep(index, list) {
  const cp = await S.log.checkpoint();
  S.cps.push(cp);
  const b = await S.log.bundle(index, cp);
  const v = await verify.bundle(b, S.log.vkey);
  const cons = await S.log.consistency(S.holdCp.size, cp.size);
  const okCons = await verify.consistency(S.holdCp.size, cp.size, await S.log.root(S.holdCp.size), await S.log.root(cp.size), cons);
  step('st4', ['done'], 'Recorded in the log', [`${list}. `, ['k', v.ok ? 'VERIFIED' : 'NOT VERIFIED'], `: #${index} proved in ${b.inclusion_proof.length} hashes to a signed checkpoint of ${cp.size}. `, okCons ? 'The log only grew since the hold.' : 'Consistency proof failed.']);
  treeMini(index);
}

$('heroOk').addEventListener('click', () => decide(true).catch(fail));
$('heroNo').addEventListener('click', () => decide(false).catch(fail));
$('again').addEventListener('click', () => runHero().catch(fail));
function fail(e) { running = false; step('st1', ['bad'], 'This browser stopped the demo', [String(e && e.message || e)]); $('again').disabled = false; }

// ------------------------------------------------------------------ NINE SECONDS
let raceT = null;
function race() {
  clearInterval(raceT);
  const A = $('raceA'), B = $('raceB'), bA = $('barA'), bB = $('barB'), tA = $('raceAt'), tB = $('raceBt');
  const cmd = 'mutation volumeDelete(volumeId: "vol_prod")';
  tA.textContent = cmd; tB.textContent = cmd; bA.style.width = '0%'; bB.style.width = '0%'; A.textContent = '0.0s'; B.textContent = '0.0s';
  if (RM) { A.textContent = '9.0s'; bA.style.width = '100%'; tA.replaceChildren(el('b', { text: 'Deleted. ' }), 'The volume and the backups on it.'); tB.replaceChildren(el('b', { text: '428 held_for_approval. ' }), 'rw.mutation. Waiting for your passkey.'); bB.style.width = '6%'; return; }
  const start = performance.now();
  setTimeout(() => { bB.style.width = '6%'; tB.replaceChildren(el('b', { text: '428 held_for_approval. ' }), 'rw.mutation. Waiting for your passkey.'); }, 220);
  raceT = setInterval(() => {
    const s = Math.min(9, ((performance.now() - start) / 1000) * 3);
    A.textContent = s.toFixed(1) + 's'; bA.style.width = (s / 9) * 100 + '%';
    if (s >= 9) { clearInterval(raceT); tA.replaceChildren(el('b', { text: 'Deleted. ' }), 'The volume and the backups on it.'); }
  }, 50);
}
$('replay').addEventListener('click', race);
new IntersectionObserver((es, o) => es.forEach((e) => { if (e.isIntersecting) { race(); o.disconnect(); } }), { threshold: 0.4 }).observe($('race'));
$('replay').after(el('p', { class: 'fine', text: 'Played at 3x speed.' }));

// ------------------------------------------------------------------ I APPROVE: pick a call, decide on the phone
const TRIES = [
  { label: 'List open pull requests', m: 'GET', p: 'github', host: 'api.github.com', path: '/repos/acme/app/pulls' },
  { label: 'Refund a customer $42', m: 'POST', p: 'stripe', host: 'api.stripe.com', path: '/v1/refunds', body: 'charge=ch_demo_3Pq&amount=4200', rule: 'st.money' },
  { label: 'Force push main', m: 'PATCH', p: 'github', host: 'api.github.com', path: '/repos/acme/app/git/refs/heads/main', body: '{"sha":"9f3c1e0","force":true}', rule: 'gh.force-push' },
  { label: 'Delete the repository', m: 'DELETE', p: 'github', host: 'api.github.com', path: '/repos/acme/app', rule: 'gh.delete' },
  { label: 'DROP TABLE users', m: 'POST', p: 'supabase', host: 'api.supabase.com', path: '/v1/projects/abcd/database/query', body: '{"query":"DROP TABLE users;"}', rule: 'sb.sql' },
  { label: 'Purge the whole cache', m: 'POST', p: 'cloudflare', host: 'api.cloudflare.com', path: '/zones/9a1/purge_cache', body: '{"purge_everything":true}', rule: 'cf.purge' },
  { label: 'Delete a Railway volume', m: 'POST', p: 'railway', host: 'backboard.railway.app', path: '/', body: 'mutation { volumeDelete(volumeId: "vol_prod") }', rule: 'rw.mutation' },
  { label: 'Open an issue', m: 'POST', p: 'github', host: 'api.github.com', path: '/repos/acme/app/issues', body: '{"title":"Flaky test"}' },
];
let META = null, current = null;
const whyOf = (rule) => {
  if (!META) return '';
  for (const p of META.providers) for (const r of p.irreversible) if (r.id === rule) return r.why;
  return '';
};
function renderTries() {
  const box = $('tries'); box.replaceChildren();
  TRIES.forEach((t, i) => {
    const b = el('button', { class: 'try', type: 'button', 'aria-pressed': 'false' },
      el('b', { text: t.label }), el('span', { class: 'v ' + (t.rule ? 'h' : 'a'), text: t.rule ? 'held' : 'allowed' }),
      el('code', { text: `${t.m} /p/${t.p}${t.path === '/' ? '/' : t.path}` }));
    b.addEventListener('click', () => pick(i, b));
    box.append(b);
  });
}
function out(pre, parts) { pre.replaceChildren(...parts.map((x) => (typeof x === 'string' ? x : el('span', { class: x[0], text: x[1] })))); }
function pick(i, btn) {
  document.querySelectorAll('.try').forEach((b) => b.setAttribute('aria-pressed', 'false'));
  btn.setAttribute('aria-pressed', 'true');
  current = TRIES[i];
  const t = current, id = hex(crypto.getRandomValues(new Uint8Array(12)));
  $('phRes').hidden = true;
  if (!t.rule) {
    $('phCard').hidden = true; $('phIdle').hidden = false;
    out($('apOut'), [`${t.m} /p/${t.p}${t.path === '/' ? '/' : t.path}\n\n`, ['s2', 'HTTP 200'], `  x-leash-decision: allowed\n\nThe call went straight through with the real key, injected by the broker. ${t.m === 'GET' ? 'Reads are not recorded.' : 'A write: its "allowed" decision becomes a receipt.'}`]);
    return;
  }
  const approveUrl = `${ORIGIN}/app#hold=${id}`, why = whyOf(t.rule);
  $('phIdle').hidden = true; $('phCard').hidden = false;
  $('phWhat').textContent = `billing-agent wants to ${t.m} ${t.host}`;
  $('phPath').textContent = t.path;
  $('phWhy').textContent = why;
  $('phRule').textContent = `rule ${t.rule} · map ${META ? META.mapVersion : MAP_VERSION}`;
  out($('apOut'), [`${t.m} /p/${t.p}${t.path === '/' ? '/' : t.path}\n\n`, ['s4', 'HTTP 428'], '\n' + pretty({ error: 'held_for_approval', hold_id: id, approve_url: approveUrl, rule: t.rule, map_version: META ? META.mapVersion : MAP_VERSION, message: `Counterseal held this request because it cannot be undone: ${why} Stop and ask your human to approve it at ${approveUrl} . After they approve, retry the exact same request once.` })]);
  $('phCard').classList.remove('in'); void $('phCard').offsetWidth;
}
$('phOk').addEventListener('click', () => {
  if (!current) return;
  $('phCard').hidden = true; $('phRes').hidden = false;
  $('phRes').replaceChildren(el('b', { text: 'Approved.' }), 'The agent can retry that exact request once.');
  const pre = $('apOut'); pre.append('\n\n', 'retry, same request → ', el('span', { class: 's2', text: 'HTTP 200' }), '  x-leash-decision: approved\nThe approval is used up. One more retry would be held again.');
});
$('phNo').addEventListener('click', () => {
  if (!current) return;
  $('phCard').hidden = true; $('phRes').hidden = false;
  $('phRes').replaceChildren(el('b', { text: 'Denied.' }), 'The agent was told no.');
  const pre = $('apOut'); pre.append('\n\n', 'retry, same request → ', el('span', { class: 's4', text: 'HTTP 428' }), '  held again\nA denied call never runs.');
});

// ------------------------------------------------------------------ II PROVE WHO: try to get past the signature
let whoImp = null;
function whoKey() {
  $('whoKey').textContent = `keyid ${S.agent.keyid}`;
  const c = $('whoSeal');
  whoImp = impression(c, { kind: 'seal', bytes: S.agent.bytes, ring: `AGENT KEY · ${S.agent.keyid.slice(0, 10)} · ED25519 ·` });
  whoImp.draw(1);
}
function show(title, reqLines, status, json, note) {
  $('twTitle').textContent = title;
  const cls = status < 300 ? 's2' : status === 428 ? 's4' : 's5';
  out($('twOut'), [reqLines.join('\n') + '\n\n', [cls, `HTTP ${status}`], '\n' + pretty(json) + (note ? '\n\n' + note : '')]);
}
const reqLines = (h, body = REQ.body) => [`${REQ.method} ${REQ.path}`, 'Authorization: Bearer lsh_7c1e…', `Content-Type: ${REQ.ctype}`, ...(h['content-digest'] ? [`Content-Digest: ${short(h['content-digest'], 22)}`] : []), ...(h['signature-input'] ? [`Signature-Input: ${short(h['signature-input'], 70)}`, `Signature: ${short(h.signature, 26)}`] : []), '', body];
async function attempt(kind) {
  if (!S.agent) return;
  const enc = (s) => new TextEncoder().encode(s);
  const sign = (key = S.agent.privateKey, kid = S.agent.keyid) => signRequest({ method: REQ.method, url: url(), body: REQ.body, contentType: REQ.ctype }, { key, kid });
  const held = () => ({ error: 'held_for_approval', rule: REQ.rule, message: `Counterseal held this request because it cannot be undone: ${REQ.why} …` });
  try {
    if (kind === 'signed') {
      const s = await sign();
      await verifyAgentSig(reqObj(s.headers), enc(REQ.body), S.agent, seen);
      return show('Signed by the real agent', reqLines(s.headers), 428, held(), 'Signature verified. The request moves on to the policy and the irreversible map, which hold this refund for your passkey.');
    }
    if (kind === 'stolen') {
      await verifyAgentSig(reqObj({}), enc(REQ.body), S.agent, seen);
    }
    if (kind === 'amount') {
      const s = await sign(), body = 'charge=ch_demo_3Pq&amount=420000';
      try { await verifyAgentSig(reqObj(s.headers), enc(body), S.agent, seen); }
      catch (e) { return show('The amount changed after signing', reqLines(s.headers, body), e.status, e.json(), 'The signature covers a digest of the body. 4200 became 420000, so the digest no longer matches.'); }
    }
    if (kind === 'replay') {
      const s = await sign();
      await verifyAgentSig(reqObj(s.headers), enc(REQ.body), S.agent, seen);
      try { await verifyAgentSig(reqObj(s.headers), enc(REQ.body), S.agent, seen); }
      catch (e) { return show('The same signature, sent twice', reqLines(s.headers), e.status, e.json(), 'The first copy was accepted. Each nonce is accepted once per key, so the copy is refused.'); }
    }
    if (kind === 'forge') {
      const mine = await newAgentKey();
      const s = await sign(mine.privateKey, S.agent.keyid);
      try { await verifyAgentSig(reqObj(s.headers), enc(REQ.body), S.agent, seen); }
      catch (e) { return show('Signed with a key nobody registered', reqLines(s.headers), e.status, e.json(), 'The attacker copied the real keyid, but only the registered public key is used to check the signature.'); }
    }
  } catch (e) {
    if (e instanceof BrokerError) return show(kind === 'stolen' ? 'A stolen token, no signature' : 'Refused', reqLines({}), e.status, e.json(), kind === 'stolen' ? 'The token was copied, but not the agent’s private key. The call stops here, before the policy, the token’s rate limit or the provider.' : '');
    return show('Error', [], 500, { error: String(e.message || e) });
  }
}
document.querySelectorAll('.tb').forEach((b) => b.addEventListener('click', () => {
  document.querySelectorAll('.tb').forEach((x) => x.setAttribute('aria-pressed', 'false'));
  b.setAttribute('aria-pressed', 'true');
  attempt(b.dataset.t);
}));

// ------------------------------------------------------------------ III RECORD: the tree, proofs, a rewrite
let badLeaf = -1;
function recordView(sel) {
  if (!S.log) return;
  drawTree($('bigTree'), S.log.size, { sel, fresh: S.fresh, bad: badLeaf, labels: true, onPick: (i) => { badLeaf = -1; S.focus = i; recordView(i); prove(i); } });
  $('treeInfo').textContent = `${S.log.size} receipts · log key made in this tab`;
  if (sel >= 0) $('rJson').textContent = pretty(S.log.entries[sel]);
}
async function prove(i) {
  const cp = await S.log.checkpoint();
  const b = await S.log.bundle(i, cp);
  const r = await verify.bundle(b, S.log.vkey);
  const rc = S.log.entries[i].receipt;
  out($('rOut'), [['s2', 'VERIFIED'], `\nentry #${r.index} of ${r.treeSize}\n${rc.action} (${rc.decision})${rc.meta.rule ? ' · rule ' + rc.meta.rule : ''}${rc.meta.agent_key ? ' · signed by an agent key' : ''}${rc.meta.passkey ? ' · passkey' : ''}\nrecorded by the broker itself\n\nleaf    ${short(b.leaf_hash, 22)}\n${b.inclusion_proof.map((h, k) => `proof ${k + 1} ${short(h, 22)}`).join('\n')}\nroot    ${short(b64(await S.log.root(cp.size)), 22)}\n\nThe checkpoint over that root is signed (Ed25519) by this tab’s log key.`]);
}
$('rProve').addEventListener('click', () => { badLeaf = -1; const i = S.focus >= 0 ? S.focus : S.log.size - 1; recordView(i); prove(i); });
$('rGrow').addEventListener('click', async () => {
  badLeaf = -1;
  const a = S.cps[0], b = await S.log.checkpoint();
  const proof = await S.log.consistency(a.size, b.size);
  const ok = await verify.consistency(a.size, b.size, await S.log.root(a.size), await S.log.root(b.size), proof);
  recordView(-1);
  out($('rOut'), [[ok ? 's2' : 's5', ok ? 'CONSISTENT' : 'NOT CONSISTENT'], `\ncheckpoint of ${a.size} entries → checkpoint of ${b.size} entries\n${proof.map((h, k) => `proof ${k + 1} ${short(b64(h), 22)}`).join('\n')}\n\nEvery entry in the older checkpoint is still there, unchanged, in the same order. Anyone who kept an old checkpoint can check this.`]);
});
$('rRewrite').addEventListener('click', async () => {
  const i = S.fresh.length ? S.fresh[0] : Math.max(0, S.log.size - 1);
  const cp = await S.log.checkpoint();
  const b = await S.log.bundle(i, cp);
  const forged = structuredClone(b.entry);
  const was = forged.receipt.decision;
  forged.receipt.decision = was === 'held' ? 'allowed' : 'held';
  const lines = [];
  try { await verify.bundle({ ...b, entry: forged }, S.log.vkey); lines.push(['s2', 'VERIFIED?']); }
  catch (e) { lines.push(['s5', 'NOT VERIFIED'], `  ${e.message}\n`); }
  // the forger also recomputes the leaf hash
  const enc = new TextEncoder().encode((await import('/receipts-sdk.js')).canonical(forged));
  const leaf = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([0, ...enc])));
  try { await verify.bundle({ ...b, entry: forged, leaf_hash: b64(leaf) }, S.log.vkey); lines.push('?'); }
  catch (e) { lines.push(['s5', 'NOT VERIFIED'], `  ${e.message}\n`); }
  // and rebuilds the whole tree and signs a new head: anyone holding an older checkpoint catches it
  const fake = await new DemoLog('demo-log-in-this-tab').init();
  for (let k = 0; k < S.log.size; k++) await fake.append(k === i ? forged : S.log.entries[k]);
  const old = S.cps[S.cps.length - 1];
  const proof = await fake.consistency(old.size, fake.size);
  const ok = await verify.consistency(old.size, fake.size, await S.log.root(old.size), await fake.root(fake.size), proof);
  lines.push([ok ? 's2' : 's5', ok ? 'CONSISTENT?' : 'NOT CONSISTENT'], '  with the checkpoint you already hold\n');
  badLeaf = i; recordView(i);
  $('rJson').textContent = pretty(forged);
  out($('rOut'), [`Receipt #${i}: "${was}" rewritten as "${forged.receipt.decision}".\n\n1. Keep the old proof:\n`, ...lines.slice(0, 2), '2. Recompute the leaf hash too:\n', ...lines.slice(2, 4), '3. Rebuild the tree and re-sign it:\n', ...lines.slice(4), '\nThe log is append-only and every checkpoint is signed, so a rewrite is caught by anyone who kept an earlier checkpoint.']);
});

// the real public log, read just now (same origin; absent on a static preview)
(async () => {
  try {
    const r = await fetch('/v1/stats', { headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error('status ' + r.status);
    const s = await r.json();
    if (!s.checkpoint) { $('rlHead').textContent = 'The public log has no entries yet.'; $('rlSize').textContent = '0'; $('rlRoot').textContent = 'none'; $('rlSig').textContent = 'none yet'; return; }
    const cp = await verify.checkpoint(s.checkpoint, s.verifier_key);
    $('rlHead').textContent = `${s.origin}: signature checks out against the log's published key, here in your browser.`;
    $('rlHead').classList.add('ok');
    $('rlSize').textContent = cp.size.toLocaleString('en');
    $('rlRoot').textContent = short(s.root, 18);
    $('rlSig').textContent = 'Ed25519, verified';
  } catch {
    $('rlHead').textContent = 'The public log could not be reached from this page right now.';
    $('rlSize').textContent = 'n/a'; $('rlRoot').textContent = 'n/a'; $('rlSig').textContent = 'n/a';
  }
})();

// ------------------------------------------------------------------ the irreversible map
async function loadMeta() {
  for (const u of ['/v1/meta', '/data/meta.json']) {
    try { const r = await fetch(u); if (r.ok) { const j = await r.json(); if (j && Array.isArray(j.providers)) return j; } } catch { /* next */ }
  }
  return null;
}
function renderMap() {
  if (!META) return;
  $('mapV').textContent = META.mapVersion;
  const tabs = $('mapTabs'), rows = $('mapRows');
  const groups = [...META.providers.map((p) => ({ id: p.id, name: p.name, host: p.host, note: p.note, rules: p.irreversible })), { id: 'all', name: 'Every provider', host: '', rules: META.common || [] }];
  const showG = (g, btn) => {
    tabs.querySelectorAll('.tab').forEach((t) => t.setAttribute('aria-selected', String(t === btn)));
    rows.replaceChildren(...(g.note ? [el('div', { class: 'mnote', text: g.note })] : []), ...g.rules.map((r) => el('div', { class: 'mrow' }, el('span', { class: 'id', text: r.id }), el('span', { class: 'mp' }, el('b', { text: r.method === '*' ? 'ANY' : r.method }), r.path), el('span', { class: 'wy', text: r.why }))));
  };
  tabs.replaceChildren();
  groups.forEach((g, i) => {
    const b = el('button', { class: 'tab', type: 'button', role: 'tab', 'aria-selected': 'false', text: `${g.name} ${g.rules.length}` });
    b.addEventListener('click', () => showG(g, b));
    b.addEventListener('keydown', (e) => { if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { const all = [...tabs.children]; const n = all[(all.indexOf(b) + (e.key === 'ArrowRight' ? 1 : all.length - 1)) % all.length]; n.focus(); n.click(); } });
    tabs.append(b);
    if (i === 0) showG(g, b);
  });
}

// ------------------------------------------------------------------ start
renderTries();
loadMeta().then((m) => { META = m; renderMap(); });
(async () => {
  if (!(await canEd25519())) {
    step('st1', ['bad'], 'This browser cannot make Ed25519 keys', ['The live demo needs WebCrypto Ed25519 (current Chrome, Edge, Firefox and Safari have it).']);
    return;
  }
  await seedLog();
  recordView(-1);
  await runHero();
  S.focus = S.log.size - 1;
  recordView(S.focus);
})().catch(fail);
