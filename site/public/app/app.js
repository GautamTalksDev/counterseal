// Counterseal dashboard. No innerHTML (Trusted Types enforced), no third-party code, no secrets kept in the page.
// The one exception is an agent key made here: it is generated in this browser, downloaded at once, and dropped.
import { BRAND } from '/brand.js';
const $ = (id) => document.getElementById(id);
// a "Move to Counterseal" link carries its one-time token in the fragment: read it, then take it out of the address bar
// and the history at once, so it is never shown, bookmarked, logged or sent as a Referer
let moveToken = null;
{ const mv = location.hash.match(/^#move=([A-Za-z0-9_-]{43})$/); if (mv) { moveToken = mv[1]; history.replaceState(null, '', '/app'); } }
// a team invite works the same way: the one-time token is in the fragment, read once and taken out of the address bar,
// and it only ever travels in a POST body
let inviteToken = null;
{ const iv = location.hash.match(/^#invite=([A-Za-z0-9_-]{43})$/); if (iv) { inviteToken = iv[1]; history.replaceState(null, '', '/app'); } }
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

// ---- Brakes: amounts with the currency's own decimals (the same table as the server's, server/src/money.js), Freeze
const ZERO = new Set('bif clp djf gnf jpy kmf krw mga pyg rwf vnd vuv xaf xof xpf'.split(' '));
const THREE = new Set('bhd jod kwd omr tnd'.split(' '));
const exponent = (cur) => (ZERO.has(cur) ? 0 : THREE.has(cur) ? 3 : 2);
/** 124000 usd -> "1,240.00 USD" (whole numbers only; never a float) */
function fmtMinor(amount, cur) {
  const e = exponent(cur), s = String(amount).padStart(e + 1, '0');
  return `${(e ? s.slice(0, -e) : s).replace(/\B(?=(\d{3})+(?!\d))/g, ',')}${e ? '.' + s.slice(-e) : ''} ${cur.toUpperCase()}`;
}
/** "50.00" in a currency -> its smallest unit as a whole number, or null if it is not an amount in that currency */
function toMinor(text, cur) {
  const e = exponent(cur), m = /^(\d{1,12})(?:\.(\d{1,3}))?$/.exec(text.trim());
  if (!m || (m[2] || '').length > e) return null;
  const n = Number(m[1] + (m[2] || '').padEnd(e, '0'));
  return Number.isSafeInteger(n) && n >= 1 ? n : null;
}
const HOLD_BADGE = { 'brake.tripped': 'Breaker tripped', 'brake.money-per-call': 'Over a cap', 'brake.money-per-day': 'Over a cap', 'brake.money-currency': 'Wrong currency', 'brake.money-unreadable': 'Not readable' };
const TRIP_WHY = { writes_per_hour: 'too many writes in an hour', repeat: 'the same request again and again' };
/** what a token's brakes say, in words: one line each */
function brakesLines(x, spent) {
  const l = x.policy.limits, m = x.policy.money, out = [];
  if (l && l.writesPerHour) out.push(`Breaker: trips after ${l.writesPerHour} write${l.writesPerHour === 1 ? '' : 's'} in an hour.`);
  if (l && l.repeatsPer5Min) out.push(`Breaker: trips when the same request is sent more than ${l.repeatsPer5Min} times in 5 minutes.`);
  if (m) out.push(`Money caps: Stripe refunds and payouts pass up to ${fmtMinor(m.perCall, m.currency)} a call and ${fmtMinor(m.perDay, m.currency)} a UTC day. Let through today: ${fmtMinor((spent && spent[m.currency]) || 0, m.currency)}.`);
  return out;
}
/** the bar at the top: Freeze is always on screen, and while frozen it says so and offers the passkey way out */
let frozenNow = false;
function freezeBar(at) {
  const on = !!at;
  frozenNow = on;
  $('freezeBar').classList.toggle('on', on);
  $('fzTitle').textContent = on ? `Frozen since ${new Date(at).toLocaleTimeString()}` : 'Agents are running';
  $('fzSub').textContent = on ? 'Every agent token is refused (423) and nothing is approved. Only your passkey ends it.' : 'One tap stops every agent token. Only your passkey starts them again.';
  $('freezeBtn').hidden = on; $('unfreezeBtn').hidden = !on;
}
$('freezeBtn').onclick = async () => {
  try { const r = await api('POST', '/v1/me/freeze', {}); freezeBar(r.frozen_at); toast('Frozen. Every agent token is stopped.'); load(); } catch (e) { toast(e.message); }
};
$('unfreezeBtn').onclick = async () => {
  try { await ceremony('/v1/me/unfreeze/begin', '/v1/me/unfreeze/finish'); freezeBar(null); toast('Unfrozen. Your agents can work again.'); load(); } catch (e) { toast(e.message); }
};

// ---- who you are on the team: the server checks your role on every request; the page only hides what it would refuse
const LEVEL = { viewer: 0, member: 1, approver: 2, owner: 3 };
const ROLE_TEXT = { owner: 'Owner', approver: 'Approver', member: 'Member', viewer: 'Viewer' };
let ME = { id: null, role: 'owner', name: '' }, SEALS = { quorum: 1, selfApprove: true, pending: null }, NAMES = new Map();
const can = (need) => (LEVEL[ME.role] ?? -1) >= LEVEL[need];
// revoking a token or key: its maker or an owner (anyone else who sees trouble freezes the account)
const mayRevoke = (maker) => !maker || maker === ME.id || can('owner');
function applyRole() {
  for (const n of document.querySelectorAll('[data-need]')) n.hidden = !can(n.dataset.need);
  $('whoRole').textContent = ROLE_TEXT[ME.role] || '';
}
const when = (t) => new Date(t).toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' });
const left = (t) => { const m = Math.max(0, Math.round((t - Date.now()) / 60_000)); return m >= 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m} min`; };
/** what a waiting change does, in a few words: "one seal instead of two", "the person who asked may be one of them" */
function lowering(p, now) {
  const parts = [];
  if (p.quorum < now.quorum) parts.push(`${p.quorum === 1 ? 'one seal' : `${p.quorum} seals`} instead of ${now.quorum === 2 ? 'two' : now.quorum}`);
  if (p.selfApprove && !now.selfApprove) parts.push('the person whose agent asked may be one of the seals');
  return parts.join(', and ') || 'a lower setting';
}
/** the banner on every page while lowering the protection is waiting its 24 hours */
function loweringBanner(p) {
  $('qBanner').hidden = !p;
  if (!p) return;
  $('qbTitle').textContent = `Protection will be lowered in ${left(p.effectiveAt)}`;
  $('qbText').textContent = `From ${when(p.effectiveAt)}: ${lowering(p, SEALS)}. Every member was alerted. Not expected? An owner or approver can cancel it with their passkey.`;
}
/** wax discs: one per seal needed, filled for each seal given */
function discs(need, have, big = false) {
  const box = el('span', { className: 'discs' });
  for (let i = 0; i < need; i++) box.append(el('span', { className: 'wax' + (i < have ? ' on' : '') + (big ? ' lg' : '') }));
  return box;
}
const cancelLowering = async () => {
  try { await ceremony('/v1/team/quorum/cancel/begin', '/v1/team/quorum/cancel/finish'); toast('Cancelled. Nothing changes.'); load(); } catch (e) { toast(e.message); }
};
$('qbCancel').onclick = cancelLowering;
$('qbOpen').onclick = () => show('team');
/** the banner on every page while a break-glass window is open: who, until when, and a way to close it (any member) */
let bgWindow = null;
function breakGlassBanner(list) {
  bgWindow = Array.isArray(list) && list[0] ? list[0] : null;
  $('bgBanner').hidden = !bgWindow;
  if (!bgWindow) return;
  $('bgTitle').textContent = `Break glass is open for ${left(bgWindow.expires_at)}`;
  $('bgText').textContent = `${bgWindow.opened_by_name || 'A teammate'} opened it${bgWindow.scope ? ` for ${bgWindow.scope.label || 'one token'}` : ' for every token and guard key'}: ${bgWindow.reason || 'no reason given'}. Held actions it covers go through and are on the record. Not expected? Close it.`;
}
$('bgOpen').onclick = () => show('team');
const closeBreakGlass = async (id) => { try { await api('DELETE', `/v1/team/breakglass/${id}`); toast('Closed. Held actions wait for approval again.'); load(); if (current === 'team') teamView(); } catch (e) { toast(e.message); } };
$('bgClose').onclick = () => { if (bgWindow) closeBreakGlass(bgWindow.id); };

// ---- data
let meta;
async function load() {
  const [c, t, h, a, ak, me] = await Promise.all([api('GET', '/v1/credentials'), api('GET', '/v1/tokens'), api('GET', '/v1/holds'), api('GET', '/v1/audit'), api('GET', '/v1/agent-keys'), api('GET', '/v1/me')]);
  ME = me.member || ME; SEALS = me.team || SEALS;
  applyRole();
  $('sealCount').textContent = String(SEALS.quorum); $('sealCount').classList.toggle('two', SEALS.quorum > 1);
  $('preNote').hidden = SEALS.quorum <= 1 && SEALS.selfApprove;
  $('mintPre').disabled = !$('preNote').hidden;
  loweringBanner(SEALS.pending);
  breakGlassBanner(me.breakglass);
  if (current === 'team') teamView().catch(() => {});
  freezeBar(me.account.frozen_at);
  // holds
  const H = $('holds');
  // keep the cursor in a deny reason being typed across the refresh
  const typing = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.hold : null;
  H.replaceChildren();
  $('holdCount').textContent = String(h.holds.length); $('holdCount').classList.toggle('hot', h.holds.length > 0);
  for (const x of h.holds) H.append(holdCard(x));
  for (const id of [...drafts.keys()]) if (!h.holds.some((x) => x.id === id)) drafts.delete(id);
  if (typing && /^[0-9a-f]{24}$/.test(typing)) { const i = H.querySelector(`input[data-hold="${typing}"]`); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }
  // creds
  const C = $('creds'); C.replaceChildren(); const tc = $('tokCred'); tc.replaceChildren();
  for (const x of c.credentials) {
    const del = el('button', { className: 'btn sm dan', textContent: 'Delete', hidden: !can('owner') });
    del.onclick = async () => { if (!confirm(`Delete ${x.label}? Tokens using it stop working.`)) return; try { await api('DELETE', `/v1/credentials/${x.id}`); load(); } catch (e) { toast(e.message); } };
    C.append(el('div', {}, el('span', {}, el('b', { textContent: x.label }), el('span', { className: 'dim', textContent: `  ${x.provider}${x.host ? ' ' + x.host : ''}  ...${x.hint}` })), del));
    tc.append(el('option', { value: x.id, textContent: `${x.label} (${x.provider})` }));
  }
  $('noCreds').hidden = c.credentials.length > 0;
  // the gates form offers the vault's keys for "no approval, no key"
  const gc = $('gtCred'), gkeep = gc.value;
  gc.replaceChildren(el('option', { value: '', textContent: 'None' }), ...c.credentials.map((x) => el('option', { value: x.id, textContent: `${x.label} (${x.provider})` })));
  gc.value = c.credentials.some((x) => x.id === gkeep) ? gkeep : '';
  // tokens
  const T = $('tokens'); T.replaceChildren();
  for (const x of t.tokens.filter((y) => !y.revoked)) {
    const rv = el('button', { className: 'btn sm dan', textContent: 'Revoke', hidden: !can('member') || !mayRevoke(x.member_id) });
    rv.onclick = async () => { try { await api('DELETE', `/v1/tokens/${x.id}`); load(); } catch (e) { toast(e.message); } };
    const bound = x.agent_key ? `, signed by ${x.agent_key_label}${x.agent_key_revoked ? ' (key revoked: token stopped)' : ''}` : '';
    const maker = x.member_id && x.member_id !== ME.id && NAMES.has(x.member_id) ? `, made by ${NAMES.get(x.member_id)}` : '';
    const brakes = brakesLines(x, x.spent_today);
    // a tripped breaker: its writes are waiting; a passkey resets it
    let rs = null;
    if (x.tripped_at) {
      rs = el('button', { className: 'btn sm pri', textContent: 'Reset with passkey' });
      rs.onclick = async () => { try { await ceremony(`/v1/tokens/${x.id}/reset/begin`, `/v1/tokens/${x.id}/reset/finish`); toast('Reset. This token\'s writes flow again.'); load(); } catch (e) { toast(e.message); } };
    }
    T.append(el('div', {},
      el('span', {}, el('b', { textContent: x.label }), x.tripped_at ? el('span', { className: 'badge dan', textContent: 'Tripped' }) : null,
        el('span', { className: 'dim', textContent: `  ${x.provider}, expires ${new Date(x.expires_at).toLocaleDateString()}${x.policy.unattendedIrreversible.length ? `, has pre-approvals${SEALS.quorum > 1 || !SEALS.selfApprove ? ' (paused: one person cannot approve alone on this team)' : ''}` : ''}${bound}${maker}` }),
        x.tripped_at ? el('span', { className: 'dim brk tripped', textContent: `Tripped at ${new Date(x.tripped_at).toLocaleTimeString()} (${TRIP_WHY[x.tripped_why] || 'a limit'}). Its writes wait for you; reads still pass.` }) : null,
        ...brakes.map((t) => el('span', { className: 'dim brk', textContent: t }))),
      el('span', { className: 'acts' }, rs, rv)));
  }
  $('noTokens').hidden = t.tokens.some((y) => !y.revoked);
  // agent keys
  const K = $('agentKeys'); K.replaceChildren();
  const active = ak.agentKeys.filter((k) => !k.revoked_at);
  for (const x of active) {
    const rv = el('button', { className: 'btn sm dan', textContent: 'Revoke', hidden: !can('member') || !mayRevoke(x.member_id) });
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
  if (current === 'gates') gatesView().catch(() => {});
  // audit
  const A = $('audit'); A.replaceChildren();
  for (const x of a.entries.slice(0, 40)) A.append(el('div', {}, el('span', { className: 'mono', textContent: `${new Date(x.at).toLocaleString()}  ${x.action}${x.receipt !== null && x.receipt !== undefined ? '  receipt #' + x.receipt : ''}` }), el('span', { className: 'dim mono', textContent: x.detail.path ? `${x.detail.method} ${x.detail.path}` : x.actor })));
}

// ---- hold cards. Four kinds: an API call the broker holds, and approvals asked for by a coding agent's guard (a shell
// command or a tool call) or by a deploy gate. For those, the card's headline is what the agent wants, and the exact
// command or call is shown in full underneath (the server makes invisible and control characters visible); the short
// summary comes from the guard and is labelled as such.
const KIND = { proxy: 'API call', shell: 'Shell command', tool: 'Tool call', deploy: 'Deploy' };
const drafts = new Map(); // hold id -> a deny reason being typed
const WANTS = { shell: 'wants to run this command', tool: 'wants to make this tool call', deploy: 'wants to deploy' };
// The seals on a card (two-person seal): one wax disc per seal needed, filled for each seal given, who gave it, when and
// with which passkey; and whether you can add yours. The server decides; the card only explains.
function sealsRow(x) {
  const need = x.needs || 1, votes = x.votes || [];
  if (need < 2 && !votes.length) return null;
  const by = votes.map((v) => `${v.member === ME.id ? 'you' : v.name || 'someone'} at ${new Date(v.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} (passkey ${String(v.passkey).slice(0, 4)}...)`).join('; ');
  const text = votes.length
    ? `${votes.length} of ${need} seals: approved by ${by}. ${votes.length < need ? `Waiting for ${need - votes.length === 1 ? 'a second approver' : `${need - votes.length} more approvers`}.` : ''}`
    : `Needs ${need} seals from ${need} different owners or approvers, each with their own passkey.`;
  return el('div', { className: 'seals' }, discs(need, votes.length), el('span', { textContent: text }));
}
/** why you cannot add your seal to this hold, or '' */
function noSeal(x) {
  if (!can('approver')) return 'Only owners and approvers can seal. You can deny it.';
  if ((x.votes || []).some((v) => v.member === ME.id)) return 'You have sealed this. It needs another approver.';
  if (x.self_approve === false && x.requested_by && x.requested_by === ME.id) return 'Your own token or guard key asked for this, so someone else on your team must seal it.';
  return '';
}

// A deploy hold (a GitHub Actions job waiting at a deploy gate). Everything in the table is from the token GitHub signed
// for the job, which Counterseal verified; the workflow's own text is kept apart and says it is not verified. The links
// were built by the server from checked values, and are only followed if they are plain github.com addresses.
const GH_LINK = /^https:\/\/github\.com\/[A-Za-z0-9._\/-]{1,250}$/;
function ghLink(href, text) {
  if (typeof href !== 'string' || !GH_LINK.test(href)) return el('span', { className: 'mono', textContent: text });
  const a = el('a', { href, textContent: text, className: 'ul mono', target: '_blank' });
  a.rel = 'noopener noreferrer';
  return a;
}
function deployFacts(g) {
  const mono = (t) => el('span', { className: 'mono', textContent: t });
  const dim = (t) => el('span', { className: 'dim', textContent: t });
  const row = (k, ...v) => [el('dt', { textContent: k }), el('dd', {}, ...v)];
  const sha = String(g.sha || '');
  return el('div', { className: 'deploy' },
    el('p', { className: 'signed' }, el('span', { className: 'badge ok', textContent: 'Signed by GitHub' }), ' The facts below are from the token GitHub signed for this job. Counterseal checked its signature.'),
    g.bind ? el('p', { className: 'alert', textContent: `First run of this gate. Approving also binds it to ${g.repository} (GitHub id ${g.repository_id}), so a renamed or re-created repository cannot use it.` }) : null,
    el('dl', { className: 'facts' },
      ...row('Repository', mono(g.repository), g.visibility ? dim(` (${g.visibility})`) : null),
      ...row('Commit', ghLink(g.commit_url, sha.slice(0, 7)), el('span', { className: 'dim mono sha', textContent: '  ' + sha })),
      ...row('Branch or tag', mono(g.ref)),
      ...row('Workflow', mono(g.workflow_ref)),
      ...(g.job_workflow_ref && g.job_workflow_ref !== g.workflow_ref ? row('Job\'s workflow', mono(g.job_workflow_ref)) : []),
      ...row('Environment', g.environment ? mono(g.environment) : dim('none')),
      ...row('Started by', g.actor ? mono(g.actor) : dim('unknown'), dim(` (${g.event})`)),
      ...row('Run', ghLink(g.run_url, `#${g.run_id}, attempt ${g.run_attempt}`)),
      ...(g.runner ? row('Runner', dim(g.runner)) : [])),
    g.summary ? el('p', { className: 'unverified' }, el('span', { className: 'badge kind', textContent: 'Not verified' }), ' Text from the workflow: ', el('span', { textContent: g.summary })) : null);
}

function holdCard(x) {
  const kind = KIND[x.kind] ? x.kind : 'proxy';
  const guard = kind !== 'proxy';
  const two = (x.needs || 1) > 1;
  const ok = el('button', { className: 'btn pri', type: 'button', textContent: two ? 'Add your seal with passkey' : 'Approve with passkey' });
  const no = el('button', { className: 'btn dan', type: 'button', textContent: 'Deny' });
  const why = noSeal(x);
  if (why) { ok.disabled = true; ok.title = why; }
  if (frozenNow) { ok.disabled = true; ok.title = 'Unfreeze first: nothing is approved while frozen.'; }
  ok.onclick = async () => {
    try {
      const r = await ceremony(`/v1/holds/${x.id}/approve/begin`, `/v1/holds/${x.id}/approve/finish`);
      toast(!r.approved ? r.note : kind === 'deploy' ? 'Approved. The job can go on, once, within 10 minutes.' : guard ? 'Approved. The agent can run that exact command once, within 10 minutes.' : 'Approved. The agent can retry that exact request once.');
      load();
    } catch (e) { toast(e.message); }
  };
  const deny = async (reason) => { try { await api('POST', `/v1/holds/${x.id}/deny`, reason ? { reason } : {}); drafts.delete(x.id); toast(reason ? (kind === 'deploy' ? 'Denied. The job log shows your reason.' : 'Denied. The agent gets your reason.') : 'Denied.'); load(); } catch (e) { toast(e.message); } };
  no.onclick = () => deny(null);
  // deny with a reason: the guard hands it back to the agent (as data), so "not today, use staging" reaches it. The list
  // refreshes every few seconds, so a reason being typed is kept as a draft and the card is rebuilt with it.
  let reasonRow = null, withReason = null;
  if (guard) {
    const input = el('input', { maxLength: 200, placeholder: kind === 'deploy' ? 'Reason, shown in the job log (200 characters)' : 'Reason, shown to the agent (200 characters)', autocomplete: 'off', spellcheck: true });
    input.setAttribute('aria-label', kind === 'deploy' ? 'Reason for denying, shown in the job log' : 'Reason for denying, shown to the agent');
    input.dataset.hold = x.id;
    const send = el('button', { className: 'btn dan', type: 'button', textContent: 'Deny with this reason' });
    send.onclick = () => deny(input.value.trim() || null);
    input.onkeydown = (e) => { if (e.key === 'Enter') send.click(); };
    input.oninput = () => drafts.set(x.id, input.value);
    reasonRow = el('div', { className: 'row reason-row', hidden: !drafts.has(x.id) }, input, send);
    if (drafts.has(x.id)) input.value = drafts.get(x.id);
    withReason = el('button', { className: 'btn', type: 'button', textContent: 'Deny with a reason' });
    withReason.onclick = () => {
      reasonRow.hidden = !reasonRow.hidden;
      if (reasonRow.hidden) drafts.delete(x.id); else { drafts.set(x.id, input.value); input.focus(); }
    };
  }
  const who = x.token_label || x.agent || 'agent';
  const facts = kind === 'deploy' && x.context && x.context.gate ? deployFacts(x.context.gate) : null;
  const where = x.context && (x.context.cwd || x.context.session)
    ? [x.context.cwd ? `in folder ${x.context.cwd}` : null, x.context.session ? `agent session ${x.context.session}` : null].filter(Boolean).join(', ')
    : null;
  return el('div', { className: 'hold' + (guard ? ' hold-guard' : ''), id: 'hold-' + x.id },
    el('div', { className: 'hold-top' },
      el('span', { className: 'badges' }, el('span', { className: 'badge warn', textContent: HOLD_BADGE[x.rule] || 'Held' }), el('span', { className: 'badge kind', textContent: KIND[kind] })),
      el('span', { className: 'dim mono', textContent: `${who}${guard && !facts && x.agent && x.agent !== who ? ' (' + x.agent + ')' : ''}  ${new Date(x.created_at).toLocaleTimeString()}` })),
    x.headline ? el('div', { className: 'amount', textContent: x.headline }) : null, // a held Stripe refund or payout: its amount first, in large type
    guard
      ? el('div', { className: 'what' }, el('span', { className: 'agent', textContent: x.agent || 'agent' }), ` ${WANTS[kind]}${where ? ', ' + where : ''}:`)
      : el('div', { className: 'what', textContent: `${x.method} ${x.host}${x.path}` }),
    // a deploy: the facts GitHub signed (and apart from them the workflow's own text), not a block of text
    facts || (x.preview ? el('pre', { className: 'preview mono' + (guard ? ' exact' : ''), textContent: x.preview }) : null),
    guard && !facts ? el('p', { className: 'dim small', textContent: `Summary from the guard: ${x.path}` }) : null,
    // (a deploy card's facts already say what the server's reason says; it keeps to the one thing they do not)
    el('p', { className: 'dim', textContent: facts ? `The job is paused until you decide. Rule ${x.rule}.` : `${x.why} Rule ${x.rule}.` }),
    sealsRow(x),
    el('div', { className: 'row' }, ok, no, withReason),
    why && !frozenNow ? el('p', { className: 'dim small seal-why', textContent: why }) : null,
    reasonRow);
}

/** the Brakes fields of the new token form: {limits?, money?}, or throws an Error saying what to fix */
function brakesFromForm() {
  const out = {}, whole = (id, lo, hi, what) => {
    const v = $(id).value.trim(); if (!v) return null;
    const n = /^\d{1,5}$/.test(v) ? Number(v) : NaN;
    if (!(n >= lo && n <= hi)) throw new Error(`${what} must be a whole number from ${lo} to ${hi}.`);
    return n;
  };
  const w = whole('brWrites', 1, 5000, 'Writes an hour'), r = whole('brRepeats', 2, 100, 'The repeat limit');
  if (w || r) out.limits = { ...(w ? { writesPerHour: w } : {}), ...(r ? { repeatsPer5Min: r } : {}) };
  const cur = $('brCur').value.trim().toLowerCase(), call = $('brCall').value.trim(), day = $('brDay').value.trim();
  if (cur || call || day) {
    if (!/^[a-z]{3}$/.test(cur)) throw new Error('Money caps need a currency of three letters, like usd.');
    const pc = toMinor(call, cur), pd = toMinor(day, cur);
    if (pc === null || pd === null) throw new Error(`Type the caps as amounts in ${cur.toUpperCase()}${exponent(cur) ? ` with up to ${exponent(cur)} decimals` : ', without decimals'}, like ${exponent(cur) ? '50.00' : '5000'}.`);
    if (pd < pc) throw new Error('The daily cap must be at least the per-call cap.');
    out.money = { currency: cur, perCall: pc, perDay: pd };
    $('brHint').textContent = `That is ${pc} and ${pd} in ${cur.toUpperCase()}'s smallest unit (what Stripe's API counts in).`;
  }
  return out;
}
async function mint(pre) {
  try {
    let policy;
    const raw = $('policy').value.trim();
    if (raw) policy = JSON.parse(raw);
    const brakes = brakesFromForm();
    if (brakes.limits || brakes.money) policy = { ...(policy || {}), ...brakes };
    // money caps loosen holds, so they are only ever set with the passkey
    if (brakes.money) pre = true;
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
// a provider whose key goes to the merchant's own address (Shopify) asks for it
let PROV = {};
const showHost = () => { const h = PROV[$('prov').value]?.perCredentialHost; $('hostBox').hidden = !h; if (h) { $('credHostLbl').textContent = h.label; $('credHost').placeholder = h.example; } };
$('prov').onchange = showHost;
$('addCred').onclick = async () => {
  try {
    await api('POST', '/v1/credentials', { provider: $('prov').value, label: $('credLabel').value.trim() || undefined, secret: $('secret').value.trim(), ...(PROV[$('prov').value]?.perCredentialHost ? { host: $('credHost').value.trim() } : {}) });
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
  if (changed && view === 'gates') gatesView().catch(() => {});
  if (changed && view === 'account') { passkeysView().catch(() => {}); cliSessionsView().catch(() => {}); guardKeysView().catch(() => {}); }
  if (changed && view === 'team') teamView().catch((e) => toast(e.message));
  for (const s of document.querySelectorAll('.view')) s.hidden = s.dataset.view !== view;
  for (const a of document.querySelectorAll('#snav a')) a.classList.toggle('on', a.dataset.view === view);
}
for (const a of document.querySelectorAll('#snav a')) a.onclick = (e) => { e.preventDefault(); show(a.dataset.view); };

// ---- deep links: #hold=<id>, #device (command line sign-in), #cli=<id> (the alert after one), #freeze (the alert's
// Freeze button could not freeze: this only brings you to the button, it never presses it)
function route() {
  // an invite link opened in a tab where the app is already running: take the token out of the address bar at once
  if (/^#invite=/.test(location.hash)) {
    const iv = location.hash.match(/^#invite=([A-Za-z0-9_-]{43})$/);
    history.replaceState(null, '', '/app');
    if (!iv) return toast('This invite link is incomplete. Ask for the whole link.');
    inviteToken = iv[1]; clearInterval(boot.poll); inviteIn();
    return;
  }
  if (location.hash === '#freeze') { window.scrollTo(0, 0); ($('freezeBtn').hidden ? $('unfreezeBtn') : $('freezeBtn')).focus(); }
  const hm = location.hash.match(/^#hold=([0-9a-f]{24})$/);
  if (hm) show('holds');
  // the alert after a passkey was added opens the passkey list; a team alert (someone joined, a role changed, the
  // protection will be lowered) opens the team
  if (location.hash === '#account') { show('account'); history.replaceState(null, '', '/app'); }
  if (location.hash === '#team') { show('team'); history.replaceState(null, '', '/app'); }
  if (hm) setTimeout(() => { const n = $('hold-' + hm[1]); if (n) n.scrollIntoView({ behavior: 'smooth' }); }, 300);
  const dm = /^#device(=.*)?$/.exec(location.hash);
  if (dm && $('devicePanel').hidden) deviceOpen(!!dm[1]);
  if (!dm) $('devicePanel').hidden = true;
  const cm = /^#cli=([0-9a-f]{24})$/.exec(location.hash);
  $('cliPanel').hidden = !cm;
  if (cm) cliAlert(cm[1]).catch((e) => toast(e.message));
}
window.addEventListener('hashchange', route);

// ---- command line sign-in (#device). Device-code phishing: someone starts leashcli login on their own machine and
// sends you the code. So this page never takes a code from a link (a link that carries one is shown as a warning), you
// type the code from your own terminal, you see when and where the sign-in started next to where you are, and "No,
// deny it" comes first. Approving needs your passkey.
const regionName = (() => { try { const d = new Intl.DisplayNames(undefined, { type: 'region' }); return (c) => { try { return d.of(c) || c; } catch { return c; } }; } catch { return (c) => c; } })();
const place = (x) => [x && x.country ? (x.country === 'T1' ? 'the Tor network' : regionName(x.country)) : null, x && x.network ? `network ${x.network}` : null].filter(Boolean).join(', ') || 'unknown';
const ago = (ms) => { const s = Math.max(0, Math.round(ms / 1000)); return s < 60 ? `${s} seconds ago` : `${Math.round(s / 60)} minute${Math.round(s / 60) === 1 ? '' : 's'} ago`; };
let deviceCode = null;
function deviceOpen(fromLink) {
  // a code in the address bar came from a link, never from our CLI: drop it and say so
  if (fromLink) history.replaceState(null, '', '/app#device');
  deviceCode = null;
  $('devicePanel').hidden = false; $('devEnter').hidden = false; $('devReview').hidden = true;
  $('devLinkWarn').hidden = !fromLink; $('devCode').value = ''; $('devMine').checked = false; $('devApprove').disabled = true;
  $('devCode').focus();
}
function deviceClose() { history.replaceState(null, '', '/app'); $('devicePanel').hidden = true; route(); }
$('devCancel').onclick = deviceClose;
$('devCode').onkeydown = (e) => { if (e.key === 'Enter') $('devNext').click(); };
$('devNext').onclick = async () => {
  try {
    const r = await api('POST', '/v1/device/lookup', { user_code: $('devCode').value });
    deviceCode = r.user_code;
    $('devRCode').textContent = r.user_code;
    $('devStarted').textContent = r.started_at ? `${ago(r.now - r.started_at)} (${new Date(r.started_at).toLocaleTimeString()})` : 'in the last few minutes';
    $('devFrom').textContent = place(r.from);
    $('devHere').textContent = place(r.here);
    $('devDays').textContent = `${r.session_days} days`;
    const warn = r.same.country === false
      ? `This sign-in started in ${place({ country: r.from.country })}, but you are in ${place({ country: r.here.country })}. A different country is a strong sign that someone else is asking for your approval. Deny it unless you ran it on a computer there.`
      : r.same.network === false
        ? `This sign-in started on a different network from the one you are on now. That is normal if you ran it on another computer or a server; if you did not, deny it.`
        : !r.from.country && !r.from.network ? 'Counterseal could not tell where this sign-in started. Approve only if you ran it yourself.' : '';
    $('devMismatch').textContent = warn; $('devMismatch').hidden = !warn;
    $('devMine').checked = false; $('devApprove').disabled = true;
    $('devEnter').hidden = true; $('devReview').hidden = false;
    $('devDeny').focus();
  } catch (e) { toast(e.message); }
};
$('devMine').onchange = () => { $('devApprove').disabled = !$('devMine').checked; };
$('devDeny').onclick = async () => {
  try { await api('POST', '/v1/device/deny', { user_code: deviceCode }); toast('Denied. That command line is not signed in.'); deviceClose(); load(); } catch (e) { toast(e.message); }
};
$('devApprove').onclick = async () => {
  if (!$('devMine').checked || !deviceCode) return;
  try { await ceremony('/v1/device/approve/begin', '/v1/device/approve/finish', { user_code: deviceCode }); toast('Approved. The command line is signed in; you can revoke it under Account.'); deviceClose(); load(); } catch (e) { toast(e.message); }
};

// ---- the alert after a command line sign-in (#cli=<id>): one tap revokes it and everything it made
async function cliAlert(id) {
  const { sessions } = await api('GET', '/v1/sessions');
  const s = sessions.find((x) => x.id === id);
  const open = s && s.status !== 'revoked';
  $('cliRevoke').hidden = !open; $('cliMine').textContent = open ? 'It was me' : 'Close';
  $('cliRevoke').textContent = s && s.status === 'ended' ? 'Revoke what it made' : 'Revoke it';
  $('cliWhat').textContent = !s ? 'That sign-in is not on this account, or is more than 7 days old.'
    : `Signed in ${new Date(s.created_at).toLocaleString()} from ${place(s)}.${s.status === 'ended' ? ' It has signed out or expired, but tokens and keys it made may still work.' : s.status === 'revoked' ? ' It was revoked.' : ''}`;
  $('cliMine').onclick = () => { history.replaceState(null, '', '/app'); route(); };
  $('cliRevoke').onclick = async () => {
    try { const r = await api('DELETE', `/v1/sessions/${id}`); toast(revokedText(r.revoked)); history.replaceState(null, '', '/app'); route(); load(); } catch (e) { toast(e.message); }
  };
}
const revokedText = (r) => `Revoked, with ${r.tokens} token(s), ${r.agentKeys} agent key(s), ${r.receiptsKeys} receipts key(s) and ${r.guardKeys ?? 0} guard key(s) it made.`;

// ---- guard keys: what a coding agent's hook (leashcli guard) holds. It asks for your approval; it can never give one.
async function guardKeysView() {
  const { keys } = await api('GET', '/v1/guard/keys');
  const live = keys.filter((k) => !k.revoked && (k.expires_at === null || k.expires_at > Date.now()));
  const L = $('guardKeys'); L.replaceChildren();
  for (const k of live) {
    const rv = el('button', { className: 'btn sm dan', type: 'button', textContent: 'Revoke', hidden: !can('member') || !mayRevoke(k.member_id) });
    rv.onclick = async () => {
      if (!confirm(`Revoke ${k.label}? Its guard stops asking for approvals, and every command it guards is refused until you install a new key.`)) return;
      try { const r = await api('DELETE', `/v1/guard/keys/${k.id}`); toast(`Revoked.${r.closed ? ` ${r.closed} open approval(s) closed.` : ''}`); guardKeysView(); load(); } catch (e) { toast(e.message); }
    };
    const maker = k.member_id && k.member_id !== ME.id && NAMES.has(k.member_id) ? ` by ${NAMES.get(k.member_id)}` : '';
    const facts = [`made ${new Date(k.created_at).toLocaleDateString()}${maker}${k.made_by === 'cli' ? ' from a command line' : ''}`, k.last_used ? `last used ${new Date(k.last_used).toLocaleString()}` : 'never used', k.expires_at ? `ends ${new Date(k.expires_at).toLocaleDateString()}` : null].filter(Boolean).join(', ');
    L.append(el('div', {}, el('span', {}, el('b', { textContent: k.label }), el('span', { className: 'dim', textContent: `  ${facts}` })), rv));
  }
  $('noGuardKeys').hidden = live.length > 0;
}
$('gkNew').onclick = async () => {
  try {
    const r = await api('POST', '/v1/guard/keys', { label: $('gkLabel').value.trim() || 'guard' });
    $('newGk').hidden = false; $('newGkVal').textContent = r.key; $('gkLabel').value = '';
    guardKeysView();
  } catch (e) { toast(e.message); }
};
// ---- deploy gates: a GitHub Actions job waits for your passkey. A gate accepts only what is listed here.
const GATE_EVENTS = [['push', true], ['workflow_dispatch', true], ['release', true], ['deployment', true], ['merge_group', true], ['schedule', false], ['repository_dispatch', false]];
const lines = (id) => $(id).value.split('\n').map((s) => s.trim()).filter(Boolean);
/** the step to paste into the job; the gate id is public (it is pasted into workflow files), not a secret */
function gateSnippet(g) {
  return [
    'permissions:',
    '  id-token: write   # lets the job ask GitHub for the token the gate checks',
    '  contents: read',
    ...(g.environments ? ['# the job must run in one of: ' + g.environments.join(', '), 'environment: ' + g.environments[0]] : []),
    'steps:',
    '  # copy action/deploy-gate from the Counterseal repository to .github/actions/counterseal-gate',
    '  - uses: ./.github/actions/counterseal-gate',
    '    with:',
    `      gate: ${g.id}`,
    '      summary: deploy ${{ github.sha }}',
    ...(g.credential ? ['  # the step\'s outputs token and base-url are the key this gate hands out, after you approve'] : []),
  ].join('\n');
}
const copy = async (text) => { try { await navigator.clipboard.writeText(text); toast('Copied.'); } catch { toast('Select the text and copy it.'); } };
async function gatesView() {
  const box = $('gtEvents');
  if (!box.childElementCount) for (const [name, on] of GATE_EVENTS) box.append(el('label', { className: 'chk' }, el('input', { type: 'checkbox', value: name, checked: on }), name));
  const { gates } = await api('GET', '/v1/gates');
  const live = gates.filter((g) => !g.revoked);
  const L = $('gates'); L.replaceChildren();
  for (const g of live) {
    const rv = el('button', { className: 'btn sm dan', type: 'button', textContent: 'Revoke', hidden: !can('member') || !mayRevoke(g.member_id) });
    rv.onclick = async () => {
      if (!confirm(`Revoke ${g.label}? Jobs waiting at it are cancelled${g.credential ? ', and the tokens it handed out stop' : ''}.`)) return;
      try { const r = await api('DELETE', `/v1/gates/${g.id}`); toast(`Revoked.${r.closed ? ` ${r.closed} waiting request(s) closed.` : ''}`); gatesView(); load(); } catch (e) { toast(e.message); }
    };
    const cp = el('button', { className: 'btn sm', type: 'button', textContent: 'Copy step' });
    cp.onclick = () => copy(gateSnippet(g));
    const line = (t) => el('span', { className: 'dim brk', textContent: t });
    L.append(el('div', {},
      el('span', {},
        el('b', { textContent: g.label }),
        g.bound ? el('span', { className: 'badge ok', textContent: 'Bound to the repository' }) : el('span', { className: 'badge kind', textContent: 'Binds on its first approved run' }),
        line(`Repository ${g.repository}${g.bound ? ` (GitHub id ${g.bound.repository_id}, bound ${new Date(g.bound.at).toLocaleDateString()})` : ''}`),
        line(`Workflows: ${g.workflows.join(', ')}`),
        line(`Branches and tags: ${g.refs.join(', ')}`),
        line(g.environments ? `Environments: ${g.environments.join(', ')}` : 'Environments: any, or none'),
        line(`Triggers: ${g.events.join(', ')}`),
        line(g.publish_repo ? 'Public receipts name this repository' : 'Public receipts: DEPLOY, the decision and the rule; never the repository'),
        g.credential ? line(`Hands out a 15 minute token for ${g.credential.label || 'a vault key'} (${g.credential.provider || 'provider'}) after approval${g.credential.preapproved ? `; pre-approves ${g.credential.preapproved} irreversible call pattern(s)` : ''}`) : null,
        el('span', { className: 'dim brk mono', textContent: `${g.id}${g.last_used ? '  last passed ' + new Date(g.last_used).toLocaleString() : '  never passed'}${g.member_id && g.member_id !== ME.id && NAMES.has(g.member_id) ? `  made by ${NAMES.get(g.member_id)}` : ''}` })),
      el('span', { className: 'acts' }, cp, rv)));
  }
  $('noGates').hidden = live.length > 0;
}
$('gtNew').onclick = async () => {
  try {
    const body = { label: $('gtLabel').value.trim(), repository: $('gtRepo').value.trim(), workflows: lines('gtWorkflows'), refs: lines('gtRefs'), events: [...$('gtEvents').querySelectorAll('input')].filter((i) => i.checked).map((i) => i.value) };
    const envs = lines('gtEnvs');
    if (envs.length) body.environments = envs;
    if ($('gtPublish').checked) body.publishRepo = true;
    const policy = $('gtPolicy').value.trim();
    if ($('gtCred').value) { body.credentialId = $('gtCred').value; if (policy) body.policy = JSON.parse(policy); }
    else if (policy) throw new Error('A policy is for the key a gate hands out. Pick a key, or clear the policy.');
    const g = await ceremony('/v1/gates/passkey/begin', '/v1/gates/passkey/finish', body);
    $('newGate').hidden = false;
    $('newGateSnippet').textContent = gateSnippet(g);
    $('newGateCopy').onclick = () => copy(gateSnippet(g));
    toast('Gate made. Paste the step into your workflow.');
    gatesView(); load();
  } catch (e) { toast(e instanceof SyntaxError ? 'The policy is not valid JSON.' : e.message); }
};
async function cliSessionsView() {
  const { sessions } = await api('GET', '/v1/sessions');
  const L = $('cliSessions'); L.replaceChildren();
  for (const s of sessions) {
    // on a team: your own command lines, or anyone's for an owner (the server checks it too)
    const mine = !s.member || s.member === ME.id;
    const rv = s.status === 'revoked' || (!mine && !can('owner')) ? null : el('button', { className: 'btn sm dan', textContent: s.status === 'ended' ? 'Revoke what it made' : 'Revoke' });
    if (rv) rv.onclick = async () => {
      if (!confirm('Revoke this command line sign-in? It is signed out, and every token, agent key, receipts key and guard key it made is revoked.')) return;
      try { const r = await api('DELETE', `/v1/sessions/${s.id}`); toast(revokedText(r.revoked)); cliSessionsView(); guardKeysView(); load(); } catch (e) { toast(e.message); }
    };
    const state = s.status === 'live' ? `ends ${new Date(s.expires_at).toLocaleDateString()}${s.current ? ' (this one)' : ''}` : s.status === 'ended' ? 'signed out or expired' : 'revoked';
    const whose = !mine && NAMES.has(s.member) ? `${NAMES.get(s.member)}, ` : '';
    L.append(el('div', {}, el('span', {}, el('b', { textContent: new Date(s.created_at).toLocaleString() }), el('span', { className: 'dim', textContent: `  ${whose}from ${place(s)}, ${state}` })), rv));
  }
}

// ---- the team (two-person seal). Every change here takes the signed-in person's own passkey; Counterseal checks the
// role, the last-owner rule and the quorum rules again on the server.
async function teamView() {
  const t = await api('GET', '/v1/team');
  ME = { ...ME, id: t.me.id, role: t.me.role }; applyRole();
  NAMES = new Map(t.members.map((m) => [m.id, m.name]));
  // the seals needed, now
  $('qDiscs').replaceChildren(...discs(t.quorum, t.quorum, true).childNodes);
  $('qTitle').textContent = t.quorum === 1 ? 'One seal' : `${t.quorum} seals`;
  $('qNow').textContent = `${t.quorum === 1 ? 'Any one owner or approver approves a held action with their passkey.' : `${t.quorum} different owners or approvers must each approve with their own passkey before a held action can go ahead.`} ${t.selfApprove ? 'The person whose agent token or guard key asked may be one of them.' : 'The person whose agent token or guard key asked cannot be one of them.'} ${t.voters} ${t.voters === 1 ? 'person' : 'people'} on this team can seal${t.votersNow < t.voters ? ` (${t.voters - t.votersNow} from later: a new approver's seal counts 24 hours after joining while two are required)` : ''}.`;
  // the form starts from what is in force now; a waiting change is shown above it, with its countdown
  $(t.quorum > 1 ? 'q2' : 'q1').checked = true; $('qSelf').checked = !!t.selfApprove;
  $('q2').disabled = t.voters < 2;
  $('q2').closest('label').title = t.voters < 2 ? 'Two seals need two owners or approvers. Invite an approver first.' : '';
  $('qPending').hidden = !t.pending;
  if (t.pending) $('qPendingText').textContent = `Waiting: from ${when(t.pending.effectiveAt)} (in ${left(t.pending.effectiveAt)}), ${lowering(t.pending, t)}.`;
  // people
  $('teamCount').textContent = `${t.members.length} of ${t.maxMembers}`;
  const owners = t.members.filter((m) => m.role === 'owner').length;
  const M = $('members'); M.replaceChildren();
  for (const m of t.members) {
    const facts = [m.label && m.label !== m.name ? `invited as ${m.label}` : null, `${m.passkeys} passkey${m.passkeys === 1 ? '' : 's'}`, m.last_used ? `last used ${new Date(m.last_used).toLocaleDateString()}` : 'not used yet', m.votes_from ? `seals count from ${when(m.votes_from)}` : null].filter(Boolean).join(', ');
    const acts = el('span', { className: 'acts' });
    if (can('owner')) {
      const sel = el('select', { className: 'sm', ariaLabel: `Role of ${m.name}` }, ...['owner', 'approver', 'member', 'viewer'].map((r) => el('option', { value: r, textContent: ROLE_TEXT[r], selected: r === m.role })));
      const go = el('button', { className: 'btn sm', type: 'button', textContent: 'Change with passkey', hidden: true });
      sel.onchange = () => { go.hidden = sel.value === m.role; };
      go.onclick = async () => {
        try { const r = await ceremony(`/v1/team/members/${m.id}/role/begin`, `/v1/team/members/${m.id}/role/finish`, { role: sel.value }); toast(`${m.name} is now ${ROLE_TEXT[r.role].toLowerCase()}.${r.votesFrom ? ` Their seal counts from ${when(r.votesFrom)}.` : ''}`); teamView(); load(); } catch (e) { toast(e.message); sel.value = m.role; go.hidden = true; }
      };
      acts.append(sel, go);
    }
    // the last owner can be neither removed nor demoted (the server refuses it too)
    if ((can('owner') || m.you) && !(m.role === 'owner' && owners < 2)) {
      const rm = el('button', { className: 'btn sm dan', type: 'button', textContent: m.you ? 'Leave team' : 'Remove' });
      rm.onclick = async () => {
        const msg = m.you
          ? 'Leave this team? You are signed out everywhere, your passkeys for it are removed, and the tokens, guard keys and receipts keys you made stop working. Confirm with your passkey.'
          : `Remove ${m.name}? They are signed out everywhere, their passkeys and alert devices are removed, their seals on waiting actions are dropped, and the tokens, guard keys and receipts keys they made stop working. Confirm with your passkey.`;
        if (!confirm(msg)) return;
        try { await ceremony(`/v1/team/members/${m.id}/remove/begin`, `/v1/team/members/${m.id}/remove/finish`); if (m.you) return location.replace('/app'); toast(`${m.name} was removed.`); teamView(); load(); } catch (e) { toast(e.message); }
      };
      acts.append(rm);
    }
    M.append(el('div', {},
      el('span', { className: 'who-line' }, el('b', { textContent: m.name }), m.you ? el('span', { className: 'dim', textContent: ' (you)' }) : null,
        el('span', { className: 'badge role r-' + m.role, textContent: ROLE_TEXT[m.role] }),
        el('span', { className: 'dim brk', textContent: facts })),
      acts));
  }
  // open invites
  const I = $('invites'); I.replaceChildren();
  for (const i of t.invites) {
    const rv = el('button', { className: 'btn sm dan', type: 'button', textContent: 'Revoke' });
    rv.onclick = async () => { try { await api('DELETE', `/v1/team/invites/${i.id}`); toast('Invite revoked. The link no longer works.'); teamView(); } catch (e) { toast(e.message); } };
    I.append(el('div', {}, el('span', {}, el('b', { textContent: i.label }), el('span', { className: 'dim', textContent: `  ${ROLE_TEXT[i.role]}, works until ${when(i.expires_at)}, made by ${NAMES.get(i.created_by) || 'an owner'}` })), rv));
  }
  $('noInvites').hidden = t.invites.length > 0;
  breakGlassBanner(t.windows);
  // break glass: the open window, and the tokens and guard keys it can be limited to
  const W = $('bgOpenNow'); W.replaceChildren();
  for (const x of t.windows || []) {
    const cl = el('button', { className: 'btn sm dan', type: 'button', textContent: 'Close now' });
    cl.onclick = () => closeBreakGlass(x.id);
    W.append(el('div', {}, el('span', {}, el('b', { textContent: `Open until ${when(x.expires_at)}` }), el('span', { className: 'dim brk', textContent: `  ${x.opened_by_name || 'a teammate'}: ${x.reason || ''}  (${x.scope ? x.scope.label || 'one token' : 'every token and guard key'})` })), cl));
  }
  const sc = $('bgScope'), keep = sc.value;
  const [tk, gk] = can('approver') ? await Promise.all([api('GET', '/v1/tokens'), api('GET', '/v1/guard/keys')]) : [{ tokens: [] }, { keys: [] }];
  sc.replaceChildren(el('option', { value: '', textContent: 'Every token and guard key' }),
    ...tk.tokens.filter((x) => !x.revoked && x.expires_at > Date.now()).map((x) => el('option', { value: x.id, textContent: `Token: ${x.label}` })),
    ...gk.keys.filter((x) => !x.revoked && (!x.expires_at || x.expires_at > Date.now())).map((x) => el('option', { value: x.id, textContent: `Guard key: ${x.label}` })));
  sc.value = [...sc.options].some((o) => o.value === keep) ? keep : '';
  $('bgNew').disabled = !!(t.windows && t.windows.length);
  // alert channels
  const C = $('channels'); C.replaceChildren();
  for (const c of t.channels || []) {
    const acts = el('span', { className: 'acts' });
    if (can('owner')) {
      const tst = el('button', { className: 'btn sm', type: 'button', textContent: 'Send a test' });
      tst.onclick = async () => { try { const r = await api('POST', `/v1/team/channels/${c.id}/test`, {}); toast(r.ok ? 'Sent. Look in the channel.' : 'The service did not accept it. Check the address.'); teamView(); } catch (e) { toast(e.message); } };
      const rm = el('button', { className: 'btn sm dan', type: 'button', textContent: 'Remove' });
      rm.onclick = async () => { if (!confirm(`Remove ${c.label}? It hears nothing more.`)) return; try { await api('DELETE', `/v1/team/channels/${c.id}`); toast('Removed.'); teamView(); } catch (e) { toast(e.message); } };
      acts.append(tst, rm);
    }
    C.append(el('div', {}, el('span', {}, el('b', { textContent: c.label }), el('span', { className: 'badge kind', textContent: c.name }),
      el('span', { className: 'dim brk', textContent: `  ${c.host}, ${c.disabled ? 'stopped after repeated failures: send a test to turn it back on' : c.last_ok_at ? `last worked ${new Date(c.last_ok_at).toLocaleString()}` : c.failures ? `${c.failures} failure(s)` : 'not used yet'}` })), acts));
  }
  $('noChannels').hidden = (t.channels || []).length > 0;
}
$('bgNew').onclick = async () => {
  try {
    const reason = $('bgReason').value.trim();
    if (reason.length < 3) return toast('Say why, in a few words. The whole team is told.');
    if (!confirm('Open break glass? Held actions it covers will go through without a second approver, every member and channel is told, and every call is on the record.')) return;
    const body = { minutes: Number($('bgMinutes').value), reason };
    if ($('bgScope').value) body.tokenId = $('bgScope').value;
    await ceremony('/v1/team/breakglass/begin', '/v1/team/breakglass/finish', body);
    $('bgReason').value = '';
    toast('Break glass is open. Everyone was told.'); teamView(); load();
  } catch (e) { toast(e.message); }
};
$('chNew').onclick = async () => {
  try {
    const label = $('chLabel').value.trim(), url = $('chUrl').value.trim();
    if (!label || !url) return toast('Give it a name and paste the webhook address.');
    await ceremony('/v1/team/channels/begin', '/v1/team/channels/finish', { kind: $('chKind').value, label, url });
    $('chUrl').value = ''; $('chLabel').value = '';
    toast('Added. Send a test to see it arrive.'); teamView();
  } catch (e) { toast(e.message); }
};
$('qPendingCancel').onclick = cancelLowering;
$('qSave').onclick = async () => {
  try {
    const quorum = $('q2').checked ? 2 : 1, selfApprove = $('qSelf').checked;
    const r = await ceremony('/v1/team/quorum/begin', '/v1/team/quorum/finish', { quorum, selfApprove });
    toast(r.pending ? `Saved. The lower protection starts at ${when(r.pending.effectiveAt)}; every member was alerted and an approver can cancel it.` : 'Saved. It applies now, to actions already waiting too.');
    teamView(); load();
  } catch (e) { toast(e.message); }
};
$('ivNew').onclick = async () => {
  try {
    const label = $('ivLabel').value.trim();
    if (!label) return toast('Say who the invite is for. They see it, and so does your team.');
    const r = await ceremony('/v1/team/invites/begin', '/v1/team/invites/finish', { role: $('ivRole').value, label, hours: Number($('ivHours').value) });
    $('newInv').hidden = false; $('newInvVal').textContent = r.url; $('ivLabel').value = '';
    $('newInvNote').textContent = `Works once, until ${when(r.expiresAt)}.`;
    teamView();
  } catch (e) { toast(e.message); }
};
$('invLater').onclick = () => { inviteToken = null; location.replace('/app'); };
$('ivCopy').onclick = async () => { try { await navigator.clipboard.writeText($('newInvVal').textContent); toast('Copied. Send it privately.'); } catch { toast('Select the link and copy it.'); } };

// ---- joining a team from an invite (#invite=<token>): the page shows the account, who invited you and the role before
// anything is made, then makes your own passkey for this team. An authenticator that already holds one of the team's
// passkeys refuses to make another (excludeCredentials), so one device cannot join twice.
async function inviteIn() {
  $('signedOut').hidden = false; $('signedIn').hidden = true;
  for (const id of ['login', 'authMain', 'authIntro', 'devSignedOut']) $(id).hidden = true;
  $('inviteIn').hidden = false;
  const bad = (msg) => { $('invBad').textContent = msg; $('invBad').hidden = false; $('invForm').hidden = true; $('invWarn').hidden = true; $('login').hidden = false; $('authIntro').hidden = false; };
  let l;
  try { l = await api('POST', '/v1/invites/lookup', { token: inviteToken }); } catch (e) { $('invAccount').textContent = 'a Counterseal team'; return bad(e.message); }
  $('invAccount').textContent = l.account; $('invInviter').textContent = l.inviter; $('invInviter2').textContent = l.inviter;
  $('invRole').textContent = ROLE_TEXT[l.role] || l.role;
  $('invRoleText').textContent = { approver: '(you seal held actions with your passkey)', member: '(you make tokens and keys for your agents)', viewer: '(you read, and can deny)' }[l.role] || '';
  $('invLabel').textContent = l.label; $('invUntil').textContent = when(l.expires_at);
  $('invName').focus();
  $('invJoin').onclick = async () => {
    try {
      const name = $('invName').value.trim(); if (!name) return toast('Type your name first.');
      const b = await api('POST', '/v1/invites/begin', { token: inviteToken, name });
      const o = b.options;
      const cred = await navigator.credentials.create({ publicKey: { ...o, challenge: b64u.dec(o.challenge), user: { ...o.user, id: b64u.dec(o.user.id) }, excludeCredentials: (o.excludeCredentials || []).map((c) => ({ type: c.type, id: b64u.dec(c.id) })) } });
      await api('POST', '/v1/invites/finish', { token: inviteToken, challengeId: b.challengeId, credential: { id: cred.id, attestationObject: b64u.enc(cred.response.attestationObject), clientDataJSON: b64u.enc(cred.response.clientDataJSON) } });
      inviteToken = null; $('inviteIn').hidden = true;
      for (const id of ['login', 'authMain', 'authIntro']) $(id).hidden = false;
      toast(`Welcome to ${l.account}.`); boot();
    } catch (e) { toast(e.name === 'InvalidStateError' ? 'This device already holds a passkey for this team. Each person joins once, with their own passkey.' : e.message); }
  };
}

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

// ---- the domain move
async function moveIn() {
  try {
    const b = await api('POST', '/v1/move/begin', { token: moveToken });
    $('moveName').textContent = b.name; $('moveIn').hidden = false;
    $('moveCreate').onclick = async () => {
      try {
        const o = b.options;
        const cred = await navigator.credentials.create({ publicKey: { ...o, challenge: b64u.dec(o.challenge), user: { ...o.user, id: b64u.dec(o.user.id) } } });
        await api('POST', '/v1/move/finish', { token: moveToken, challengeId: b.challengeId, credential: { id: cred.id, attestationObject: b64u.enc(cred.response.attestationObject), clientDataJSON: b64u.enc(cred.response.clientDataJSON) } });
        moveToken = null; $('moveIn').hidden = true; toast('Your passkey on this host is ready.'); boot();
      } catch (e) { toast(e.message); }
    };
  } catch (e) { toast(e.message); }
}
$('moveBtn').onclick = async () => {
  try { const r = await ceremony('/v1/me/move/begin', '/v1/me/move/finish'); location.assign(r.url); } catch (e) { toast(e.message); }
};
async function passkeysView() {
  const p = await api('GET', '/v1/passkeys');
  const P = $('passkeys'); P.replaceChildren();
  for (const x of p.passkeys) {
    const rm = el('button', { className: 'btn sm dan', textContent: 'Remove' });
    rm.disabled = p.passkeys.length < 2;
    rm.onclick = async () => {
      if (!confirm('Remove this passkey? It will no longer sign in, and every other browser signed in to this account is signed out. Confirm with your passkey.')) return;
      try { const r = await ceremony(`/v1/passkeys/${x.id}/remove/begin`, `/v1/passkeys/${x.id}/remove/finish`); toast(`Passkey removed.${r.signedOut ? ` ${r.signedOut} other browser session(s) signed out.` : ''}`); passkeysView(); } catch (e) { toast(e.message); }
    };
    P.append(el('div', {}, el('span', {}, el('b', { textContent: x.host ? new URL(x.host).host : 'passkey' }), el('span', { className: 'dim', textContent: `  added ${new Date(x.created_at).toLocaleDateString()}${x.last_used ? ', last used ' + new Date(x.last_used).toLocaleDateString() : ''}` })), rm));
  }
}

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
    const rv = el('button', { className: 'btn sm dan', textContent: 'Revoke', hidden: !can('member') || !mayRevoke(k.member_id) });
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
    ME = me.member || ME; SEALS = me.team || SEALS; applyRole();
    // on a team, your own name (the account's name is the team's)
    const shown = ME.name || me.account.name;
    $('who').textContent = shown; $('who').title = ME.founder ? me.account.name : `${shown}, on ${me.account.name}`;
    $('movePanel').hidden = !me.host.legacy; $('moveHost').textContent = me.host.primary;
    $('avatar').textContent = (shown.trim()[0] || '?').toUpperCase();
    api('GET', '/v1/team').then((t) => { NAMES = new Map(t.members.map((m) => [m.id, m.name])); }).catch(() => {});
    meta = meta || (await api('GET', '/v1/meta'));
    const p = $('prov'); p.replaceChildren(...meta.providers.map((x) => el('option', { value: x.id, textContent: x.name })));
    PROV = Object.fromEntries(meta.providers.map((x) => [x.id, x])); showHost();
    route(); await load(); pushState().catch(() => {});
    clearInterval(boot.poll); boot.poll = setInterval(() => load().catch(() => {}), 5000);
  } catch {
    $('signedOut').hidden = false; $('signedIn').hidden = true;
    // a command line sign-in waits for you here; the code is typed after you sign in, never taken from the link
    $('devSignedOut').hidden = !/^#device/.test(location.hash);
    // on the old host, sign-in stays and sign-up moves to the product's host
    try {
      meta = meta || (await api('GET', '/v1/meta'));
      if (meta.app && meta.app !== location.origin) { $('signupBox').hidden = true; $('signupMoved').hidden = false; $('signupLink').href = meta.app + '/app'; }
      // a sign-in code works on both hosts: point people whose account is on the other host there
      const other = meta.app && meta.app !== location.origin ? meta.app : meta.legacyApp;
      if (/^#device/.test(location.hash) && /^https?:\/\/[a-z0-9.:-]+$/.test(other || '')) { $('devOtherHost').hidden = false; $('devOtherLink').href = other + '/app#device'; $('devOtherLink').textContent = new URL(other).host + '/app#device'; }
    } catch { /* offline: the form still works or explains itself */ }
  }
}
if (moveToken) { $('signedOut').hidden = false; $('signedIn').hidden = true; moveIn(); } else if (inviteToken) inviteIn(); else boot();
