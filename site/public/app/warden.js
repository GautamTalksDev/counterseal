// The Warden: the dashboard's mascot. One pure function maps the account's real state (held calls, the freeze, tripped
// breakers, Budget seal spend and a fresh approval) to one of six moods, with the words shown beside it. No DOM here,
// so the mapping is tested on its own (server/test/warden.test.js) and the page only swaps a picture and some text.
export const WARDEN_STATES = ['calm', 'held', 'approved', 'spend80', 'cap', 'tripped'];
export const WARDEN_ALT = {
  calm: 'The Warden, a ceramic seal, stands calm with a green wax seal on its belly.',
  held: 'The Warden holds its amber wax seal close: a call is waiting for your passkey.',
  approved: 'The Warden stamps a green seal with a tick: approved.',
  spend80: 'The Warden looks worried, its amber seal showing a gauge: spend is near a cap.',
  cap: 'The Warden raises a flipper to stop, its red seal showing a bar: spend stopped at the cap.',
  tripped: 'The Warden stands braced, its red seal showing an open lock: the breaker tripped.',
};
const APPROVED_MS = 6000;

/** the highest share of a cap reached by any budget, today or this month (null when no budget has a cap) */
export function topPct(budget) {
  let top = null;
  for (const s of (budget && Array.isArray(budget.scopes) ? budget.scopes : [])) {
    for (const p of [s.day, s.month]) {
      if (!p || !p.cap) continue;
      const pct = Math.floor((Math.max(0, p.spent || 0) * 100) / (p.cap + (p.extra || 0)));
      if (top === null || pct > top) top = pct;
    }
  }
  return top;
}

/**
 * x: { holds, tokens, frozenAt, budget, approvedAt, now }. Returns { state, badge, lead, hot, tail, sub }.
 * Order: a freeze or a tripped breaker first (nothing writes), then a cap (the next metered call is stopped), then held
 * calls (they wait for you), then spend at 80%, then a passkey approval in the last few seconds, then calm.
 */
export function wardenState(x = {}) {
  const holds = Array.isArray(x.holds) ? x.holds : [];
  const tokens = (Array.isArray(x.tokens) ? x.tokens : []).filter((t) => t && !t.revoked);
  const now = typeof x.now === 'number' ? x.now : Date.now();
  const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
  if (x.frozenAt) return { state: 'tripped', badge: 'FROZEN', lead: 'Everything is ', hot: 'frozen', tail: '.', sub: 'Every agent token is stopped. Only a passkey starts them again.' };
  const tripped = tokens.filter((t) => t.tripped_at).length + holds.filter((h) => h.rule === 'brake.tripped').length;
  if (tripped) return { state: 'tripped', badge: 'BREAKER TRIPPED', lead: 'Breaker ', hot: 'tripped', tail: '.', sub: 'A token went past its limits. Its writes wait for you; reads still pass. Reset it with your passkey.' };
  const pct = topPct(x.budget);
  const capHeld = holds.some((h) => h.rule === 'budget.cap');
  if ((pct !== null && pct >= 100) || capHeld) return { state: 'cap', badge: 'CAP HIT', lead: 'Spend ', hot: 'stopped', tail: ' at the cap.', sub: 'The next AI model call through Counterseal is stopped before it is sent, until the cap resets or you raise it.' };
  if (holds.length) return { state: 'held', badge: 'CALL HELD', lead: '', hot: n(holds.length, 'call', 'calls'), tail: ' held for you.', sub: 'Irreversible calls wait for your passkey.' };
  if (pct !== null && pct >= 80) return { state: 'spend80', badge: `SPEND ${Math.min(pct, 99)}%`, lead: 'Spend at ', hot: `${Math.min(pct, 99)}%`, tail: ' of a cap.', sub: 'Calls still go through. At the cap the next one is stopped before it is sent.' };
  if (x.approvedAt && now - x.approvedAt >= 0 && now - x.approvedAt < APPROVED_MS) return { state: 'approved', badge: 'APPROVED', lead: 'Sealed. ', hot: 'Approved', tail: '.', sub: 'The agent can retry that exact request once.' };
  return { state: 'calm', badge: 'ALL CLEAR', lead: '', hot: 'All clear', tail: '.', sub: 'Agents are working. Anything they cannot take back waits for your passkey.' };
}
