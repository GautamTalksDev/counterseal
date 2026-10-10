// The evidence pack, checked in your browser. No DOM and no network here: app.js fetches the pages from
// GET /v1/export/evidence and calls these; server/test/app-trust.test.js runs the same code under Node.
//
// Why in the browser: the server would have to load and re-hash every audit entry, and a Worker on the free plan gets
// 10 ms of CPU per request. Your browser has all the time it needs, and you do not have to trust the server's word that
// the chain is intact: it recomputes every SHA-256 itself (WebCrypto).
//
// Each audit entry commits to the one before it (server/src/audit.js):
//   hash = SHA-256(prev_hash | account_id | at | actor | action | detail)
// The first entry of an account commits to 64 zeros, so a pack that starts at the account's first entry proves nothing
// before it was removed; a pack for a date range proves the range is complete and unedited between its ends.

const ZERO = '0'.repeat(64);
const te = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
export const sha256hex = async (s) => hex(await crypto.subtle.digest('SHA-256', te.encode(s)));

/** entries: oldest first, each {seq, at, actor, action, detail (the stored JSON text), prev_hash, hash, receipt}.
 *  Returns {ok, entries, first, last, head} or {ok: false, brokenAt, reason}. */
export async function verifyChain(entries, accountId, { fromStart = false } = {}) {
  if (!Array.isArray(entries)) return { ok: false, brokenAt: null, reason: 'not a list of entries' };
  let prev = fromStart ? ZERO : entries.length ? entries[0].prev_hash : ZERO;
  let lastSeq = -Infinity;
  for (const e of entries) {
    if (!e || typeof e.detail !== 'string' || typeof e.hash !== 'string') return { ok: false, brokenAt: e?.seq ?? null, reason: 'malformed entry' };
    if (!(e.seq > lastSeq)) return { ok: false, brokenAt: e.seq, reason: 'out of order' };
    if (e.prev_hash !== prev) return { ok: false, brokenAt: e.seq, reason: 'does not follow the entry before it (an entry is missing or was changed)' };
    const h = await sha256hex(`${e.prev_hash}|${accountId}|${e.at}|${e.actor}|${e.action}|${e.detail}`);
    if (h !== e.hash) return { ok: false, brokenAt: e.seq, reason: 'its contents do not match its hash (it was edited)' };
    prev = e.hash; lastSeq = e.seq;
  }
  return { ok: true, entries: entries.length, first: entries[0]?.seq ?? null, last: entries.length ? entries[entries.length - 1].seq : null, head: prev, fromStart };
}

// the broker's decisions, as server/src/ledger.js names them (and the demo, which is never public)
export const DECISIONS = { proxy: 'allowed', hold: 'held', deny: 'denied', approve: 'approved', proxy_approved: 'executed', run_approved: 'executed' };

/** a spreadsheet cell: quoted, and text that a spreadsheet would run as a formula is made plain text */
const cell = (v) => {
  let s = v === null || v === undefined ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
};
const COLS = ['seq', 'time_utc', 'action', 'decision', 'actor', 'method', 'host', 'path', 'rule', 'kind', 'hold', 'seals', 'quorum', 'passkey', 'receipt', 'hash'];
/** one row per decision (held, approved, denied, allowed, executed), oldest first */
export function decisionsCsv(entries) {
  const rows = [COLS.join(',')];
  for (const e of entries) {
    if (!Object.hasOwn(DECISIONS, e.action)) continue;
    let d = {};
    try { d = JSON.parse(e.detail) || {}; } catch { /* a malformed detail still gets its row */ }
    const seals = e.action !== 'approve' ? '' : Array.isArray(d.votes) ? d.votes.length : 1;
    rows.push([e.seq, new Date(e.at).toISOString(), e.action, DECISIONS[e.action], e.actor, d.method, d.host, d.path, d.rule, d.kind || (e.actor.startsWith('token:') ? 'proxy' : ''), d.hold, seals, d.quorum, d.passkey, e.receipt, e.hash].map(cell).join(','));
  }
  return rows.join('\r\n') + '\r\n';
}

// How the pack lines up with two frameworks people ask about. Our interpretation, not legal advice and not an audit
// opinion: Counterseal is not certified against either, and using it does not make anyone compliant.
// Sources (read 9 Oct 2026): Regulation (EU) 2024/1689 Art. 12, 19 and 26, ai-act-service-desk.ec.europa.eu; AICPA
// Trust Services Criteria (2017, revised points of focus 2022) CC6.1, CC6.3, CC8.1.
export const MAPPING = {
  note: 'Our interpretation, to help you talk to your auditor or lawyer. Not legal advice, not an audit opinion, and not a claim that using Counterseal makes you compliant with anything.',
  items: [
    { framework: 'EU AI Act', ref: 'Art. 12 (record-keeping)', text: 'High-risk AI systems must allow automatic recording of events (logs) over their lifetime. Where your AI agent is part of such a system, the audit log records each irreversible action it asked for, whether it was held, who approved or denied it and when, as hash-chained events.' },
    { framework: 'EU AI Act', ref: 'Art. 19 (automatically generated logs, providers)', text: 'Providers keep the logs under their control for a period appropriate to the purpose, at least six months. Counterseal keeps your audit log while your account exists; export the pack to keep your own copy for as long as you need.' },
    { framework: 'EU AI Act', ref: 'Art. 26(6) (deployers)', text: 'Deployers keep the logs under their control for at least six months. The same as Art. 19: the pack is your copy, and the chain lets you show it was not edited.' },
    { framework: 'SOC 2', ref: 'CC6.1 (logical access)', text: 'Agents get scoped proxy tokens, never the real keys, which stay encrypted in the vault. The pack lists the decisions made on those tokens.' },
    { framework: 'SOC 2', ref: 'CC6.3 (access is authorised, with separation of duties)', text: 'Irreversible calls wait for a named person\'s passkey approval; with two seals, two different people must approve, and the person whose token asked can be excluded. Each approval in the pack names the passkey fingerprint and, on a team, every seal.' },
    { framework: 'SOC 2', ref: 'CC8.1 (changes are authorised)', text: 'Infrastructure changes an agent makes through Counterseal (deletes, force pushes, migrations, deploys) are held until approved, and the approval is bound to that exact request and used once.' },
  ],
};
