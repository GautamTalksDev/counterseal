// Private launch numbers for the operator: GET /v1/admin/stats with Authorization: Bearer <STATS_TOKEN>.
// Counts only: never an id, name, email, IP, path or key. 404 (as for any unknown route) when STATS_TOKEN is not set or
// the token is wrong, so the endpoint does not even show that it exists. Eight aggregate queries and one cached
// Durable Object read; no writes.
import { HttpError, sha256, eqBytes, now } from './util.js';

const DAY = 86_400_000;

/** constant-time: both sides are hashed first, so the comparison never depends on where they differ or on length */
export async function checkStatsToken(env, request) {
  const want = env.STATS_TOKEN;
  const m = (request.headers.get('authorization') || '').match(/^Bearer (\S{1,512})$/);
  if (typeof want !== 'string' || want.length < 32 || !m) throw new HttpError(404, 'not_found');
  if (!eqBytes(await sha256(m[1]), await sha256(want))) throw new HttpError(404, 'not_found');
}

export async function stats(env, head) {
  const t = now(), d1 = t - DAY, d7 = t - 7 * DAY, d30 = t - 30 * DAY;
  const one = (sql, ...a) => env.DB.prepare(sql).bind(...a).first();
  const [accounts, byDay, tokens, keys, audit, holds, push, receipts] = await Promise.all([
    one('SELECT COUNT(*) AS total, SUM(created_at > ?) AS last24h, SUM(created_at > ?) AS last7d, SUM(last_seen > ?) AS active7d, SUM(receipts = 1) AS receiptsOn, SUM(plan != \'free\') AS paid FROM accounts', d1, d7, d7),
    env.DB.prepare("SELECT strftime('%Y-%m-%d', created_at / 1000, 'unixepoch') AS day, COUNT(*) AS n FROM accounts WHERE created_at > ? GROUP BY day ORDER BY day").bind(d30).all(),
    one('SELECT COUNT(*) AS total, SUM(created_at > ?) AS last7d, SUM(agent_key_id IS NOT NULL) AS bound FROM tokens', d7),
    one('SELECT COUNT(*) AS total, SUM(created_at > ?) AS last7d FROM agent_keys', d7),
    env.DB.prepare("SELECT action, COUNT(*) AS total, SUM(at > ?) AS last7d FROM audit WHERE action IN ('hold', 'approve', 'deny', 'proxy', 'proxy_approved', 'cli_signin_approved', 'agent_signature_failed') GROUP BY action").bind(d7).all(),
    one("SELECT COUNT(*) AS pending FROM holds WHERE status = 'pending' AND expires_at > ?", t),
    one('SELECT COUNT(*) AS total FROM push_subs'),
    env.DB.prepare('SELECT day, receipts FROM global_usage WHERE day >= ? ORDER BY day').bind(new Date(d30).toISOString().slice(0, 10)).all(),
  ]);
  const a = Object.fromEntries(audit.results.map((r) => [r.action, { total: r.total, last7d: r.last7d || 0 }]));
  const pick = (k) => a[k] || { total: 0, last7d: 0 };
  const n = (v) => v || 0;
  return {
    at: t,
    accounts: { total: n(accounts.total), last24h: n(accounts.last24h), last7d: n(accounts.last7d), active7d: n(accounts.active7d), receiptsOn: n(accounts.receiptsOn), paidPlans: n(accounts.paid), byDay30d: byDay.results },
    tokens: { minted: n(tokens.total), last7d: n(tokens.last7d), boundToAgentKeys: n(tokens.bound) },
    agentKeys: { registered: n(keys.total), last7d: n(keys.last7d) },
    cli: { signIns: pick('cli_signin_approved') },
    decisions: { holds: pick('hold'), approvals: pick('approve'), denials: pick('deny'), allowedWrites: pick('proxy'), executedAfterApproval: pick('proxy_approved'), pendingNow: n(holds.pending), unsignedUseOfBoundTokens: pick('agent_signature_failed') },
    pushSubscriptions: n(push.total),
    receipts: { logEntries: head?.size || 0, byDay30d: receipts.results },
  };
}

// "Active" means any signed-in request or proxied call: the account's last_seen day is written at most once a day per
// account per isolate (an UPDATE that only matches when the stored day is older, so most calls write nothing).
const seen = new Map();
export function markSeen(env, accountId) {
  const t = now(), day = Math.floor(t / DAY);
  if (seen.get(accountId) === day) return null;
  if (seen.size > 50_000) seen.clear();
  seen.set(accountId, day);
  return env.DB.prepare('UPDATE accounts SET last_seen = ? WHERE id = ? AND (last_seen IS NULL OR last_seen < ?)').bind(t, accountId, day * DAY).run();
}
export const _resetSeen = () => seen.clear();
