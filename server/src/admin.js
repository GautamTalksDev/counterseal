// Private launch numbers for the operator: GET /v1/admin/stats with Authorization: Bearer <STATS_TOKEN>.
// Counts only: never an id, name, email, IP, path or key. 404 (as for any unknown route) when STATS_TOKEN is not set or
// the token is wrong, so the endpoint does not even show that it exists. Twelve aggregate queries and one cached
// Durable Object read; no writes.
//
// The launch funnel (`funnel`): accounts that made a token, made a first protected call, tried the demo, run the app
// installed, and turned alerts on, in total and by UTC day for 30 days. The by-day numbers come from the first-time
// markers of migration 0012 (src/trust.js); the totals also count older evidence (any token made, a token or guard key
// ever used, an alert device), so accounts from before the markers are not lost.
import { HttpError, sha256, eqBytes, now } from './util.js';
import { rewrap } from './vault.js';

const DAY = 86_400_000;

/** constant-time: both sides are hashed first, so the comparison never depends on where they differ or on length */
export async function checkStatsToken(env, request, name = 'STATS_TOKEN') {
  const want = env[name];
  const m = (request.headers.get('authorization') || '').match(/^Bearer (\S{1,512})$/);
  if (typeof want !== 'string' || want.length < 32 || !m) throw new HttpError(404, 'not_found');
  if (!eqBytes(await sha256(m[1]), await sha256(want))) throw new HttpError(404, 'not_found');
}

export async function stats(env, head) {
  const t = now(), d1 = t - DAY, d7 = t - 7 * DAY, d30 = t - 30 * DAY;
  const one = (sql, ...a) => env.DB.prepare(sql).bind(...a).first();
  const [accounts, byDay, tokens, keys, audit, holds, receipts, guardKeys, kinds, teams, gates, firsts] = await Promise.all([
    one(`SELECT COUNT(*) AS total, SUM(created_at > ?1) AS last24h, SUM(created_at > ?2) AS last7d, SUM(last_seen > ?2) AS active7d, SUM(receipts = 1) AS receiptsOn, SUM(plan != 'free') AS paid,
      SUM(first_call_at IS NOT NULL OR EXISTS (SELECT 1 FROM tokens t WHERE t.account_id = accounts.id AND t.last_used IS NOT NULL) OR EXISTS (SELECT 1 FROM guard_keys g WHERE g.account_id = accounts.id AND g.last_used IS NOT NULL)) AS called,
      SUM(demo_at IS NOT NULL) AS demo, SUM(installed_at IS NOT NULL) AS installed,
      SUM(alerts_at IS NOT NULL OR EXISTS (SELECT 1 FROM push_subs p WHERE p.account_id = accounts.id)) AS alerts,
      SUM(installed_at IS NOT NULL OR alerts_at IS NOT NULL OR EXISTS (SELECT 1 FROM push_subs p WHERE p.account_id = accounts.id)) AS appOrAlerts FROM accounts`, d1, d7),
    env.DB.prepare("SELECT strftime('%Y-%m-%d', created_at / 1000, 'unixepoch') AS day, COUNT(*) AS n FROM accounts WHERE created_at > ? GROUP BY day ORDER BY day").bind(d30).all(),
    one('SELECT COUNT(*) AS total, SUM(created_at > ?) AS last7d, SUM(agent_key_id IS NOT NULL) AS bound, COUNT(DISTINCT account_id) AS accounts FROM tokens', d7),
    one('SELECT COUNT(*) AS total, SUM(created_at > ?) AS last7d FROM agent_keys', d7),
    env.DB.prepare("SELECT action, COUNT(*) AS total, SUM(at > ?) AS last7d FROM audit WHERE action IN ('hold', 'approve', 'deny', 'proxy', 'proxy_approved', 'run_approved', 'gate_passed', 'cli_signin_approved', 'agent_signature_failed') GROUP BY action").bind(d7).all(),
    one("SELECT COUNT(*) AS pending FROM holds WHERE status = 'pending' AND expires_at > ?", t),
    env.DB.prepare('SELECT day, receipts FROM global_usage WHERE day >= ? ORDER BY day').bind(new Date(d30).toISOString().slice(0, 10)).all(),
    one('SELECT COUNT(*) AS total, SUM(created_at > ?) AS last7d, SUM(revoked = 0) AS active FROM guard_keys', d7),
    env.DB.prepare('SELECT kind, COUNT(*) AS n FROM holds WHERE created_at > ? GROUP BY kind').bind(d7).all(),
    // two-person seal: accounts with more than one person, the people on them, and accounts that require two seals
    one('SELECT (SELECT COUNT(DISTINCT account_id) FROM members WHERE removed_at IS NULL AND id != account_id) AS teams, (SELECT COUNT(*) FROM members WHERE removed_at IS NULL) AS members, (SELECT COUNT(*) FROM accounts WHERE quorum >= 2) AS quorum2, (SELECT COUNT(*) FROM windows WHERE opened_at > ?) AS windows7d, (SELECT COUNT(*) FROM channels) AS channels, (SELECT COUNT(*) FROM push_subs) AS pushTotal', d7),
    one('SELECT COUNT(*) AS total, SUM(created_at > ?) AS last7d, SUM(revoked = 0) AS active, SUM(repository_id IS NOT NULL) AS bound, SUM(credential_id IS NOT NULL) AS withKey FROM gates', d7),
    // the funnel by UTC day, one query for all five markers
    env.DB.prepare(FIRSTS_BY_DAY).bind(d30).all(),
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
    decisions: { holds: pick('hold'), approvals: pick('approve'), denials: pick('deny'), allowedWrites: pick('proxy'), executedAfterApproval: pick('proxy_approved'), commandsRunAfterApproval: pick('run_approved'), deploysPassedAfterApproval: pick('gate_passed'), pendingNow: n(holds.pending), unsignedUseOfBoundTokens: pick('agent_signature_failed') },
    // coding-agent approvals (guard keys): keys made, and the last 7 days' holds by kind (proxy, shell, tool, deploy)
    guard: { keys: n(guardKeys.total), activeKeys: n(guardKeys.active), keysLast7d: n(guardKeys.last7d), holdsLast7dByKind: Object.fromEntries(kinds.results.map((r) => [r.kind, r.n])) },
    team: { accountsWithTeams: n(teams.teams), people: n(teams.members), accountsRequiringTwoSeals: n(teams.quorum2), breakGlassWindowsLast7d: n(teams.windows7d), alertChannels: n(teams.channels) },
    // deploy gates (GitHub Actions): gates made, still active, bound to a repository, handing out a key; counts only
    gates: { made: n(gates.total), madeLast7d: n(gates.last7d), active: n(gates.active), bound: n(gates.bound), handingOutAKey: n(gates.withKey) },
    funnel: {
      accountsWithToken: n(tokens.accounts), accountsWithFirstProtectedCall: n(accounts.called), accountsTriedDemo: n(accounts.demo),
      accountsWithAppInstalled: n(accounts.installed), accountsWithAlertsOn: n(accounts.alerts), accountsWithAppInstalledOrAlertsOn: n(accounts.appOrAlerts),
      byDay30d: byDayOf(firsts.results),
    },
    pushSubscriptions: n(teams.pushTotal),
    receipts: { logEntries: head?.size || 0, byDay30d: receipts.results },
  };
}

const FIRSTS = { token: 'first_token_at', firstProtectedCall: 'first_call_at', demo: 'demo_at', installed: 'installed_at', alertsOn: 'alerts_at' };
const FIRSTS_BY_DAY = Object.entries(FIRSTS).map(([k, col]) => `SELECT '${k}' AS k, strftime('%Y-%m-%d', ${col} / 1000, 'unixepoch') AS day, COUNT(*) AS n FROM accounts WHERE ${col} > ?1 GROUP BY day`).join(' UNION ALL ');
/** [{day, token, firstProtectedCall, demo, installed, alertsOn}], oldest first, only days with something */
function byDayOf(rows) {
  const days = new Map();
  for (const r of rows) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(r.day) || !Object.hasOwn(FIRSTS, r.k)) continue;
    if (!days.has(r.day)) days.set(r.day, Object.fromEntries([['day', r.day], ...Object.keys(FIRSTS).map((k) => [k, 0])]));
    days.get(r.day)[r.k] = r.n;
  }
  return [...days.values()].sort((a, b) => a.day.localeCompare(b.day));
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

// Master key rotation (docs/KEY_ROTATION.md): POST /v1/admin/vault/rewrap with the ADMIN_TOKEN bearer
// (its own secret: the read-only STATS_TOKEN cannot move keys), after LEASH_KEK_NEXT
// (or LEASH_KEK plus LEASH_KEK_OLD) was set. Each call moves up to PAGE rows of each sealed table to the
// new key and returns where to continue ({"after": {"credentials": id, "channels": id}}); `next` is null for a table
// that is done. Counts and row-id cursors only, never a secret: only the data key is unwrapped and wrapped again.
const SEALED = { credentials: 'SELECT id, wrapped_dek, dek_iv FROM credentials WHERE id > ? ORDER BY id LIMIT ?', channels: 'SELECT id, wrapped_dek, dek_iv FROM channels WHERE id > ? ORDER BY id LIMIT ?', sso_configs: 'SELECT id, wrapped_dek, dek_iv FROM sso_configs WHERE id > ? AND wrapped_dek IS NOT NULL ORDER BY id LIMIT ?' };
const PAGE = 100;
export async function rewrapVault(env, body) {
  const after = body?.after && typeof body.after === 'object' ? body.after : {};
  const out = {};
  for (const [table, sql] of Object.entries(SEALED)) {
    const from = typeof after[table] === 'string' ? after[table].slice(0, 64) : '';
    if (after[table] === null) { out[table] = { checked: 0, rewrapped: 0, failed: 0, next: null }; continue; }
    const rows = (await env.DB.prepare(sql).bind(from, PAGE).all()).results;
    const r = { checked: rows.length, rewrapped: 0, failed: 0, next: rows.length === PAGE ? rows[rows.length - 1].id : null };
    const updates = [];
    for (const row of rows) {
      let w;
      try { w = await rewrap(env, row); } catch (e) { if (e instanceof HttpError && e.status === 503) throw e; r.failed++; continue; }
      if (!w) continue;
      // the WHERE on the old wrap: a row changed in between (deleted, or rewrapped by another call) is left alone
      updates.push(env.DB.prepare(`UPDATE ${table} SET wrapped_dek = ?, dek_iv = ? WHERE id = ? AND wrapped_dek = ?`).bind(w.wrapped_dek, w.dek_iv, row.id, row.wrapped_dek));
      r.rewrapped++;
    }
    if (updates.length) await env.DB.batch(updates);
    out[table] = r;
  }
  return { ...out, rotating: Boolean(env.LEASH_KEK_NEXT || env.LEASH_KEK_OLD), done: Object.values(out).every((t) => t.next === null) };
}
