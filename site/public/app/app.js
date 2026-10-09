// Counterseal dashboard. No innerHTML (Trusted Types enforced), no third-party code, no secrets kept in the page.
// The one exception is an agent key made here: it is generated in this browser, downloaded at once, and dropped.
import { BRAND } from '/brand.js';
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => { const n = document.createElement(tag); Object.assign(n, props); for (const k of kids) if (k != null) n.append(k); return n; };
const b64u = { enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)) };

function toast(msg) { const t = $('toast'); t.textContent = msg; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 4200); }

async function api(method, path, body) {
  const r = await fetch(path, { method, credentials: 'same-origin', headers: { 'x-leash': '1', ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(j.message || j.error || 'Request failed'); e.code = j.error; throw e; }
  return j;
}

// ---- WebAuthn
async function getAssertion(options) {
  const cred = await navigator.credentials.get({ publicKey: { ...options, challenge: b64u.dec(options.challenge) } });
  return { id: cred.id, authenticatorData: b64u.enc(cred.response.authenticatorData), clientDataJSON: b64u.enc(cred.response.clientDataJSON), signature: b64u.enc(cred.response.signature) };
}
/** begin -> passkey -> finish, for any ceremony that takes {challengeId, credential} */
async function ceremony(beginPath, finishPath, extra = {}) {
  const b = await api('POST', beginPath, extra);
  const credential = await getAssertion(b.options);
  return api('POST', finishPath, { ...extra, challengeId: b.challengeId, credential });
}

$('register').onclick = async () => {
  try {
    const name = $('name').value.trim(); if (!name) return toast('Type your name first.');
    const b = await api('POST', '/v1/auth/register/begin', { name });
    const o = b.options;
    const cred = await navigator.credentials.create({ publicKey: { ...o, challenge: b64u.dec(o.challenge), user: { ...o.user, id: b64u.dec(o.user.id) } } });
    await api('POST', '/v1/auth/register/finish', { challengeId: b.challengeId, credential: { id: cred.id, attestationObject: b64u.enc(cred.response.attestationObject), clientDataJSON: b64u.enc(cred.response.clientDataJSON) } });
    boot();
  } catch (e) { toast(e.message); }
};
$('login').onclick = async () => { try { await ceremony('/v1/auth/login/begin', '/v1/auth/login/finish'); boot(); } catch (e) { toast(e.message); } };
$('logout').onclick = async () => { await api('POST', '/v1/auth/logout', {}); location.reload(); };

// ---- data
let meta;
async function load() {
  const [c, t, h, a, ak, me] = await Promise.all([api('GET', '/v1/credentials'), api('GET', '/v1/tokens'), api('GET', '/v1/holds'), api('GET', '/v1/audit'), api('GET', '/v1/agent-keys'), api('GET', '/v1/me')]);
  // holds
  const H = $('holds'); H.replaceChildren();
  $('holdCount').textContent = String(h.holds.length); $('holdCount').classList.toggle('hot', h.holds.length > 0);
  for (const x of h.holds) {
    const ok = el('button', { className: 'btn pri', textContent: 'Approve with passkey' });
    const no = el('button', { className: 'btn dan', textContent: 'Deny' });
    ok.onclick = async () => { try { await ceremony(`/v1/holds/${x.id}/approve/begin`, `/v1/holds/${x.id}/approve/finish`); toast('Approved. The agent can retry that exact request once.'); load(); } catch (e) { toast(e.message); } };
    no.onclick = async () => { try { await api('POST', `/v1/holds/${x.id}/deny`, {}); toast('Denied.'); load(); } catch (e) { toast(e.message); } };
    H.append(el('div', { className: 'hold', id: 'hold-' + x.id },
      el('div', { className: 'hold-top' }, el('span', { className: 'badge warn', textContent: 'Held' }), el('span', { className: 'dim mono', textContent: `${x.token_label || 'agent'}  ${new Date(x.created_at).toLocaleTimeString()}` })),
      el('div', { className: 'what', textContent: `${x.method} ${x.host}${x.path}` }),
      x.preview ? el('pre', { className: 'preview mono', textContent: x.preview }) : null,
      el('p', { className: 'dim', textContent: `${x.why} Rule ${x.rule}.` }),
      el('div', { className: 'row' }, ok, no)));
  }
  // creds
  const C = $('creds'); C.replaceChildren(); const tc = $('tokCred'); tc.replaceChildren();
  for (const x of c.credentials) {
    const del = el('button', { className: 'btn sm dan', textContent: 'Delete' });
    del.onclick = async () => { if (!confirm(`Delete ${x.label}? Tokens using it stop working.`)) return; await api('DELETE', `/v1/credentials/${x.id}`); load(); };
    C.append(el('div', {}, el('span', {}, el('b', { textContent: x.label }), el('span', { className: 'dim', textContent: `  ${x.provider}  ...${x.hint}` })), del));
    tc.append(el('option', { value: x.id, textContent: `${x.label} (${x.provider})` }));
  }
  $('noCreds').hidden = c.credentials.length > 0;
  // tokens
  const T = $('tokens'); T.replaceChildren();
  for (const x of t.tokens.filter((y) => !y.revoked)) {
    const rv = el('button', { className: 'btn sm dan', textContent: 'Revoke' });
    rv.onclick = async () => { await api('DELETE', `/v1/tokens/${x.id}`); load(); };
    const bound = x.agent_key ? `, signed by ${x.agent_key_label}${x.agent_key_revoked ? ' (key revoked: token stopped)' : ''}` : '';
    T.append(el('div', {}, el('span', {}, el('b', { textContent: x.label }), el('span', { className: 'dim', textContent: `  ${x.provider}, expires ${new Date(x.expires_at).toLocaleDateString()}${x.policy.unattendedIrreversible.length ? ', has pre-approvals' : ''}${bound}` })), rv));
  }
  $('noTokens').hidden = t.tokens.some((y) => !y.revoked);
  // agent keys
  const K = $('agentKeys'); K.replaceChildren();
  const active = ak.agentKeys.filter((k) => !k.revoked_at);
  for (const x of active) {
    const rv = el('button', { className: 'btn sm dan', textContent: 'Revoke' });
    rv.onclick = async () => { if (!confirm(`Revoke ${x.label}? ${x.tokens} token(s) bound to it stop working at once.`)) return; try { await api('DELETE', `/v1/agent-keys/${x.id}`); load(); } catch (e) { toast(e.message); } };
    K.append(el('div', {}, el('span', {}, el('b', { textContent: x.label }), el('span', { className: 'dim mono', textContent: `  ${x.keyid.slice(0, 16)}...  ${x.tokens} token(s)${x.last_used ? ', last used ' + new Date(x.last_used).toLocaleString() : ''}` })), rv));
  }
  $('noAgentKeys').hidden = active.length > 0;
  for (const sel of [$('tokAgentKey'), $('rkSigner')]) {
    const keep = sel.value; const first = sel.options[0];
    sel.replaceChildren(first, ...active.map((k) => el('option', { value: k.id, textContent: k.label })));
    sel.value = active.some((k) => k.id === keep) ? keep : '';
  }
  // the receipts list reads the log's Durable Object, so it is fetched only while that view is open
  if (current === 'receipts') receiptsView(me.receipts).catch(() => {});
  // audit
  const A = $('audit'); A.replaceChildren();
  for (const x of a.entries.slice(0, 40)) A.append(el('div', {}, el('span', { className: 'mono', textContent: `${new Date(x.at).toLocaleString()}  ${x.action}${x.receipt !== null && x.receipt !== undefined ? '  receipt #' + x.receipt : ''}` }), el('span', { className: 'dim mono', textContent: x.detail.path ? `${x.detail.method} ${x.detail.path}` : x.actor })));
}

async function mint(pre) {
  try {
    let policy;
    const raw = $('policy').value.trim();
    if (raw) policy = JSON.parse(raw);
    const body = { credentialId: $('tokCred').value, label: $('tokLabel').value.trim() || 'agent', policy, ...($('tokAgentKey').value ? { agentKeyId: $('tokAgentKey').value } : {}) };
    const r = pre ? await ceremony('/v1/tokens/passkey/begin', '/v1/tokens/passkey/finish', body) : await api('POST', '/v1/tokens', body);
    $('newToken').hidden = false;
    $('newTokenVal').textContent = r.token;
    $('newTokenMcp').textContent = JSON.stringify({ mcpServers: { leash: { command: 'npx', args: ['-y', 'leashcli', 'mcp'], env: { LEASH_URL: location.origin, LEASH_TOKENS: `${r.provider}=${r.token}`, ...(r.agentKey ? { LEASH_AGENT_KEY: '<path to the agent key file>' } : {}) } } } }, null, 2);
    load();
  } catch (e) { toast(e instanceof SyntaxError ? 'The policy is not valid JSON.' : e.message); }
}
$('mint').onclick = () => mint(false);
$('mintPre').onclick = () => mint(true);
$('addCred').onclick = async () => {
  try {
    await api('POST', '/v1/credentials', { provider: $('prov').value, label: $('credLabel').value.trim() || undefined, secret: $('secret').value.trim() });
    $('secret').value = ''; toast('Stored in the vault.'); load();
  } catch (e) { toast(e.message); }
};
$('delConfirm').oninput = () => { $('delAccount').disabled = $('delConfirm').value.trim() !== 'delete'; };
$('delAccount').onclick = async () => {
  try { await ceremony('/v1/me/delete/begin', '/v1/me/delete/finish', { confirm: 'delete' }); location.replace('/'); } catch (e) { toast(e.message); }
};
$('verify').onclick = async () => { const v = await api('GET', '/v1/audit/verify'); toast(v.ok ? `Chain intact: ${v.entries} entries.` : `Chain BROKEN at entry ${v.brokenAt}.`); };

// ---- views
let current = 'holds';
function show(view) {
  const changed = current !== view;
  current = view;
  if (changed && view === 'receipts') load().catch(() => {});
  for (const s of document.querySelectorAll('.view')) s.hidden = s.dataset.view !== view;
  for (const a of document.querySelectorAll('#snav a')) a.classList.toggle('on', a.dataset.view === view);
}
for (const a of document.querySelectorAll('#snav a')) a.onclick = (e) => { e.preventDefault(); show(a.dataset.view); };

// ---- deep links: #hold=<id>, #device=<code>
function route() {
  const hm = location.hash.match(/^#hold=([0-9a-f]{24})$/);
  if (hm) show('holds');
  if (hm) setTimeout(() => { const n = $('hold-' + hm[1]); if (n) n.scrollIntoView({ behavior: 'smooth' }); }, 300);
  const dm = location.hash.match(/^#device=([A-Z0-9]{4}-[A-Z0-9]{4})$/);
  $('devicePanel').hidden = !dm;
  if (dm) {
    $('deviceCode').textContent = dm[1];
    $('deviceOk').onclick = async () => { try { await ceremony('/v1/device/approve/begin', '/v1/device/approve/finish', { user_code: dm[1] }); toast('CLI signed in. You can close this.'); history.replaceState(null, '', '/app'); route(); load(); } catch (e) { toast(e.message); } };
    $('deviceNo').onclick = () => { history.replaceState(null, '', '/app'); route(); };
  }
}
window.addEventListener('hashchange', route);

// ---- alerts (Web Push). The push itself carries nothing; sw.js fetches the held request after it wakes.
const swPolicy = window.trustedTypes ? trustedTypes.createPolicy('leash-sw', { createScriptURL: (u) => { if (u !== '/sw.js') throw new Error('blocked'); return u; } }) : null;
const pushOk = () => 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
async function pushState() {
  const panel = $('pushPanel');
  const k = await api('GET', '/v1/push/key');
  if (!k.enabled) { panel.hidden = true; return; }
  panel.hidden = false;
  if (!pushOk()) {
    $('pushHint').textContent = `This browser cannot show alerts here. On iPhone: open ${BRAND.name} in Safari, tap Share, then Add to Home Screen, and open it from your home screen.`;
    for (const b of ['pushOn', 'pushTest', 'pushOff']) $(b).hidden = true;
    return;
  }
  const reg = await navigator.serviceWorker.getRegistration('/');
  const sub = reg ? await reg.pushManager.getSubscription() : null;
  $('pushOn').hidden = !!sub; $('pushTest').hidden = !sub; $('pushOff').hidden = !sub;
}
$('pushOn').onclick = async () => {
  try {
    const k = await api('GET', '/v1/push/key');
    if ((await Notification.requestPermission()) !== 'granted') return toast('Alerts are blocked in this browser. Allow notifications for this site, then try again.');
    const reg = await navigator.serviceWorker.register(swPolicy ? swPolicy.createScriptURL('/sw.js') : '/sw.js', { scope: '/' });
    await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64u.dec(k.key) });
    await api('POST', '/v1/push/subscribe', { endpoint: sub.endpoint });
    toast('Alerts are on for this device.'); pushState();
  } catch (e) { toast(e.message); }
};
$('pushTest').onclick = async () => { try { const r = await api('POST', '/v1/push/test', {}); toast(r.sent ? 'Test sent. The alert should arrive in a few seconds.' : `No device answered (${r.devices} registered): ${(r.results || []).map((x) => x.service + ' ' + (x.status || '') + ' ' + (x.reason || x.error || '')).join('; ') || 'none'}`); } catch (e) { toast(e.message); } };
$('pushOff').onclick = async () => {
  try {
    const reg = await navigator.serviceWorker.getRegistration('/');
    const sub = reg ? await reg.pushManager.getSubscription() : null;
    if (sub) { await api('POST', '/v1/push/unsubscribe', { endpoint: sub.endpoint }); await sub.unsubscribe(); }
    toast('Alerts are off for this device.'); pushState();
  } catch (e) { toast(e.message); }
};

// ---- receipts (Record)
const download = (name, text) => {
  const a = el('a', { href: URL.createObjectURL(new Blob([text], { type: 'application/json' })), download: name });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};
async function receiptsView(r) {
  $('rcptOn').hidden = r.on; $('rcptOff').hidden = !r.on;
  $('rcptState').textContent = r.on ? 'Public receipts are on' : 'Public receipts are off';
  $('rcptHint').textContent = r.on
    ? `Every decision on a write is sealed in the public log. This month: ${r.usage} of ${r.quota ?? 'unlimited'} (${r.today} today, ${r.dayCap ?? 'unlimited'} a day)${r.skipped ? `; ${r.skipped} decision(s) could not be sealed because a limit was reached, and stay in your audit log only` : ''}.`
    : 'Decisions stay in your private audit log only. Turn receipts on to seal each one in the public log (method, provider host, decision, rule and hashes; never a path, body, key, name or IP).';
  const [mine, keys] = await Promise.all([api('GET', '/v1/my/receipts'), api('GET', '/v1/keys')]);
  const R = $('receipts'); R.replaceChildren();
  for (const x of mine.receipts) {
    const rc = x.entry.receipt || {};
    const dl = el('button', { className: 'btn sm', textContent: 'Bundle' });
    dl.onclick = async () => {
      try {
        const b = await api('GET', `/v1/my/receipts/${x.index}/bundle`);
        if (!$('keepOpening').checked) delete b.opening;
        download(`receipt-${x.index}.json`, JSON.stringify(b, null, 2));
      } catch (e) { toast(e.message); }
    };
    R.append(el('div', {}, el('span', { className: 'mono', textContent: `#${x.index}  ${new Date(x.entry.received_at).toLocaleString()}  ${rc.decision || ''}` }), el('span', { className: 'dim mono', textContent: `${rc.action || ''}  ${x.entry.source === 'broker' ? 'broker' : 'reported by ' + (rc.agent || 'agent')}` }), dl));
  }
  $('noReceipts').hidden = mine.receipts.length > 0;
  const K = $('apiKeys'); K.replaceChildren();
  const live = keys.keys.filter((k) => !k.revoked);
  for (const k of live) {
    const rv = el('button', { className: 'btn sm dan', textContent: 'Revoke' });
    rv.onclick = async () => { try { await api('DELETE', `/v1/keys/${k.id}`); load(); } catch (e) { toast(e.message); } };
    K.append(el('div', {}, el('span', {}, el('b', { textContent: k.label }), el('span', { className: 'dim', textContent: `  ${k.signer_pub ? 'signed receipts only' : 'unsigned'}${k.last_used ? ', last used ' + new Date(k.last_used).toLocaleString() : ''}` })), rv));
  }
  $('noApiKeys').hidden = live.length > 0;
}
$('rcptOn').onclick = async () => { try { await api('POST', '/v1/me/receipts/on', {}); toast('Receipts are on.'); load(); } catch (e) { toast(e.message); } };
$('rcptOff').onclick = async () => {
  if (!confirm('Turn public receipts off? Future decisions will stay in your private audit log only. Receipts already published stay in the log.')) return;
  try { await ceremony('/v1/me/receipts/off/begin', '/v1/me/receipts/off/finish'); toast('Receipts are off.'); load(); } catch (e) { toast(e.message); }
};
$('rkNew').onclick = async () => {
  try {
    const r = await api('POST', '/v1/keys', { label: $('rkLabel').value.trim() || 'agent', ...($('rkSigner').value ? { agentKeyId: $('rkSigner').value } : {}) });
    $('newRk').hidden = false; $('newRkVal').textContent = r.key; load();
  } catch (e) { toast(e.message); }
};

// ---- agent keys (Prove who): generated here, private half downloaded at once, never sent
$('akNew').onclick = async () => {
  try {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: priv.x, d: priv.d };
    const label = $('akLabel').value.trim() || 'agent';
    const b = await api('POST', '/v1/agent-keys/begin', { publicKey: jwk.x });
    const proof = b64u.enc(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, new TextEncoder().encode(b.sign)));
    const r = await api('POST', '/v1/agent-keys', { label, publicKey: jwk.x, challengeId: b.challengeId, proof });
    download(`agent-key-${label.replace(/[^A-Za-z0-9_-]+/g, '-').slice(0, 40)}.json`, JSON.stringify(jwk, null, 2));
    toast(`Agent key registered. Keep the downloaded file on the agent's machine only.`);
    $('akLabel').value = ''; load(); void r;
  } catch (e) { toast(e.name === 'NotSupportedError' ? 'This browser cannot make Ed25519 keys. Use npx leashcli agent-key instead.' : e.message); }
};

async function boot() {
  try {
    const me = await api('GET', '/v1/me');
    $('signedOut').hidden = true; $('signedIn').hidden = false; $('logout').hidden = false;
    $('who').textContent = me.account.name;
    $('avatar').textContent = (me.account.name.trim()[0] || '?').toUpperCase();
    meta = meta || (await api('GET', '/v1/meta'));
    const p = $('prov'); p.replaceChildren(...meta.providers.map((x) => el('option', { value: x.id, textContent: x.name })));
    route(); await load(); pushState().catch(() => {});
    clearInterval(boot.poll); boot.poll = setInterval(() => load().catch(() => {}), 5000);
  } catch {
    $('signedOut').hidden = false; $('signedIn').hidden = true;
  }
}
boot();
