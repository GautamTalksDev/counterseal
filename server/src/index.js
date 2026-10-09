// The Worker: /v1/* control API and public log API, /p/<provider>/* agent proxy, /.well-known/security.txt, and
// everything else is the static site (ASSETS). One Worker, one D1 database (leash), one Durable Object (the log).
//   Approve: the broker holds irreversible calls until a passkey approves (broker.js, providers.js, policy.js).
//   Record:  decisions and agent-reported receipts are sealed in a public RFC 6962 log (ledger.js, log.js).
//   Prove who: tokens can be bound to an agent's Ed25519 key; requests must then be signed (agentkeys.js).
import { HttpError, json, errorResponse, readJson, now } from './util.js';
import * as A from './auth.js';
import * as B from './broker.js';
import * as K from './agentkeys.js';
import * as G from './approvals.js';
import * as Gt from './gates.js';
import { list as auditList, verifyChain, audit } from './audit.js';
import { limit, readLimit, ipBucket } from './ratelimit.js';
import { metaOf } from './providers.js';
import * as Push from './push.js';
import { LEDGER_ROUTES, PUBLIC_PATH, CORS, logOf, apiKey, cachedHead, quotaFor, dayCapFor, usageOf, cleanupStatements, forgetAccount, deleteStatements, int } from './ledger.js';
import { logKey } from './note.js';
import { directoryTool } from './tools.js';
import { stats, checkStatsToken, markSeen } from './admin.js';
import * as Move from './move.js';
import * as Brakes from './brakes.js';
import * as Team from './team.js';
import { BRAND } from './brand.js';
export { ReceiptLog } from './log.js';

const ID = '([0-9a-f]{24})';
// the least role a signed-in route needs (src/team.js): reads are open to every member, writes default to MEMBER (a
// viewer only reads and denies); the fifth element of a route overrides it
const { viewer: ANY, member: MEMBER, approver: APPROVER, owner: OWNER } = Team.LEVEL;
// on the old host, these stay (the dashboard and what it loads); /v1, /p and /.well-known are handled before this
const KEEP_ON_OLD_HOST = /^\/(app(\/.*)?|sw\.js|manifest\.webmanifest|styles\.css|brand\.js|favicon\.svg|icon-\d+\.png|fonts\/.*)$/;
const movedPermanently = (location) => new Response(null, { status: 301, headers: { location, 'cache-control': 'public, max-age=3600', 'strict-transport-security': 'max-age=63072000; includeSubDomains; preload', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' } });
const DO_READS = /^\/v1\/(log\/(entries|proof\/)|my\/)/;
// The site's security headers, the same as the "/*" block of site/public/_headers (server/test/second-pass.test.js
// checks they match). Pages the Worker serves through env.ASSETS (every page listed in run_worker_first) may not get
// _headers applied (Cloudflare: "attach any custom headers ... directly within that Worker script"), so the Worker adds
// any that are missing; a header the asset already has is kept as it is.
export const SITE_HEADERS = {
  'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; media-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'; require-trusted-types-for 'script'; trusted-types leash-sw; upgrade-insecure-requests",
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'x-frame-options': 'DENY',
};
function withSiteHeaders(res) {
  if (Object.keys(SITE_HEADERS).every((k) => res.headers.has(k))) return res;
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(SITE_HEADERS)) if (!out.headers.has(k)) out.headers.set(k, v);
  return out;
}
const REG_PER_DAY = (env) => Number(env.REG_PER_IP_DAY) || 5;
// [method, regex, guard, handler, role?]
//   public / publicw (with Origin check): per-IP D1 limit;  pub: public log reads, in-memory limit, CORS open
//   key: receipts API key (lsr_);  session: read with any session;  write: session + CSRF for web
//   webw: web (passkey) session only, never a CLI session
//   guard: a guard key (lsg_) from a coding-agent hook; per-network limit in memory, the routes add their own limits
//   role (signed-in routes): the least team role needed, ANY < MEMBER < APPROVER < OWNER. Default: ANY for session
//   (reads), MEMBER for write and webw. A role is checked on the server for every request; a passkey proves presence,
//   not authority.
//   gate:  a GitHub Actions OIDC token (verified in the route, src/oidc.js); poll: a gate poll secret (gps_); both with a
//          per-network limit in memory (GitHub's runners share networks, so it is generous), the routes add their own limits
const ROUTES = [
  ['GET', /^\/v1\/meta$/, 'public', (c) => ({ app: A.hosts(c.env)[0].origin, legacyApp: A.hosts(c.env)[1]?.origin || null, ...metaOf() })],
  ['POST', /^\/v1\/auth\/register\/begin$/, 'publicw', (c) => A.registerBegin(c.env, c.body)],
  ['POST', /^\/v1\/auth\/register\/finish$/, 'publicw', async (c) => {
    await limit(c.env.DB, await ipBucket(c.env, c.request, 'regday'), REG_PER_DAY(c.env), 86_400_000, now());
    const out = await A.registerFinish(c.env, c.body, c.request);
    maybeSweep(c);
    return out;
  }],
  ['POST', /^\/v1\/auth\/login\/begin$/, 'publicw', (c) => A.loginBegin(c.env)],
  ['POST', /^\/v1\/auth\/login\/finish$/, 'publicw', async (c) => { const out = await A.loginFinish(c.env, c.body); maybeSweep(c); return out; }],
  ['POST', /^\/v1\/auth\/logout$/, 'write', (c) => A.logout(c.env, c.s), ANY],
  // CLI sign-in (device code). The browser side is web session only: type the code, review where it started, then deny
  // or approve with a passkey (src/auth.js explains the phishing defences). Any member may sign in their own command
  // line; it gets their role.
  ['POST', /^\/v1\/device\/start$/, 'public', (c) => A.deviceStart(c.env, c.request, A.whereFrom(c.cf))],
  ['POST', /^\/v1\/device\/poll$/, 'public', (c) => A.devicePoll(c.env, c.body)],
  ['POST', /^\/v1\/device\/lookup$/, 'webw', (c) => A.deviceLookup(c.env, c.s, c.body, A.whereFrom(c.cf)), ANY],
  ['POST', /^\/v1\/device\/deny$/, 'webw', (c) => A.deviceDeny(c.env, c.s, c.body), ANY],
  ['POST', /^\/v1\/device\/approve\/begin$/, 'webw', (c) => A.deviceApproveBegin(c.env, c.s, c.body), ANY],
  ['POST', /^\/v1\/device\/approve\/finish$/, 'webw', (c) => A.deviceApproveFinish(c.env, c.s, c.body), ANY],
  // command line sessions: list (any session), revoke one and everything it made (web session only; your own, or
  // anyone's for an owner)
  ['GET', /^\/v1\/sessions$/, 'session', (c) => A.listCliSessions(c.env, c.s)],
  ['DELETE', /^\/v1\/sessions\/([0-9a-f]{24})$/, 'webw', (c) => A.revokeCliSession(c.env, c.s, c.m[1]), ANY],
  // what a phone shows after a payload-free push: held requests, command line sign-ins and passkeys added in the last
  // 15 minutes, whether the account is frozen (and since when), and team events (someone joined; the quorum will be
  // lowered)
  ['GET', /^\/v1\/alerts$/, 'session', async (c) => ({
    holds: (await B.listHolds(c.env, c.s, 'pending')).holds, signins: await A.recentCliSignins(c.env, c.s.accountId), passkeys: await Move.recentPasskeys(c.env, c.s.accountId),
    frozen_at: (await c.env.DB.prepare('SELECT frozen_at FROM accounts WHERE id = ?').bind(c.s.accountId).first())?.frozen_at ?? null,
    team: await Team.recentEvents(c.env, c.s.accountId),
  })],
  // Brakes. Freeze: any signed-in session of any member, a viewer too (stopping is always safe). Unfreeze and resetting
  // a tripped breaker: an owner or approver, in a web session with a fresh passkey ceremony, never a command line session.
  ['POST', /^\/v1\/me\/freeze$/, 'write', (c) => Brakes.freeze(c.env, c.s), ANY],
  ['POST', /^\/v1\/me\/unfreeze\/begin$/, 'webw', (c) => Brakes.unfreezeBegin(c.env, c.s), APPROVER],
  ['POST', /^\/v1\/me\/unfreeze\/finish$/, 'webw', (c) => Brakes.unfreezeFinish(c.env, c.s, c.body), APPROVER],
  ['POST', new RegExp(`^/v1/tokens/${ID}/reset/begin$`), 'webw', (c) => Brakes.resetBegin(c.env, c.s, c.m[1]), APPROVER],
  ['POST', new RegExp(`^/v1/tokens/${ID}/reset/finish$`), 'webw', (c) => Brakes.resetFinish(c.env, c.s, c.m[1], c.body), APPROVER],
  ['GET', /^\/v1\/me$/, 'session', async (c) => {
    const account = await c.env.DB.prepare('SELECT id, name, created_at, receipts, plan, frozen_at, quorum, self_approve, quorum_pending, self_approve_pending, quorum_effective_at FROM accounts WHERE id = ?').bind(c.s.accountId).first();
    const u = await usageOf(c.env, c.s.accountId);
    const { receipts, quorum, self_approve, quorum_pending, self_approve_pending, quorum_effective_at, ...rest } = account || {};
    return {
      account: account ? rest : null, kind: c.s.kind,
      // who is signed in: on a team, one member with their own role (the account's founder: the account's id and name)
      member: { id: c.s.memberId, role: c.s.role, name: c.s.memberName || account?.name || null, founder: c.s.memberId === c.s.accountId },
      // the seals a held action needs now, and a lowering that is waiting (the app shows it on every page)
      team: Team.effective({ quorum, self_approve, quorum_pending, self_approve_pending, quorum_effective_at }),
      // which host this is, and where the product lives (the app offers "Move to Counterseal" on the old host)
      host: { here: A.rp(c.env).origin, legacy: A.rp(c.env).legacy, primary: A.hosts(c.env)[0].origin },
      // receipts numbers at the top level as well, as the receipts API always had them
      usage: u.usage, quota: c.env.UNLIMITED ? null : quotaFor(c.env),
      receipts: { on: !!receipts, usage: u.usage, today: u.today, skipped: u.skipped, quota: c.env.UNLIMITED ? null : quotaFor(c.env), dayCap: c.env.UNLIMITED ? null : dayCapFor(c.env) },
    };
  }],
  // deleting the account erases the whole team's data: an owner, with a fresh passkey ceremony
  ['POST', /^\/v1\/me\/delete\/begin$/, 'webw', (c) => deleteBegin(c.env, c.s), OWNER],
  ['POST', /^\/v1\/me\/delete\/finish$/, 'webw', (c) => deleteAccount(c.env, c.s, c.body), OWNER],
  // public receipts on or off (an owner). On: a web session. Off hides future decisions from the public log, which is
  // what an agent that wanted to act unseen would want, so it needs a fresh passkey ceremony, and turning off is itself
  // on the record.
  ['POST', /^\/v1\/me\/receipts\/on$/, 'webw', async (c) => {
    await c.env.DB.prepare('UPDATE accounts SET receipts = 1 WHERE id = ?').bind(c.s.accountId).run();
    await audit(c.env, c.s.accountId, 'web', 'receipts_on', who(c.s));
    return { ok: true, on: true };
  }, OWNER],
  ['POST', /^\/v1\/me\/receipts\/off\/begin$/, 'webw', async (c) => {
    const { id, challenge } = await A.newChallenge(c.env, 'receipts_off', c.s.accountId);
    return { challengeId: id, options: { challenge, rpId: A.rp(c.env).rpId, userVerification: 'required', timeout: 300000 } };
  }, OWNER],
  ['POST', /^\/v1\/me\/receipts\/off\/finish$/, 'webw', async (c) => {
    const ch = await A.takeChallenge(c.env, c.body.challengeId, 'receipts_off');
    if (ch.account_id !== c.s.accountId) throw new HttpError(403, 'forbidden');
    await A.checkAssertion(c.env, c.body.credential, ch.challenge, c.s);
    await c.env.DB.prepare('UPDATE accounts SET receipts = 0 WHERE id = ?').bind(c.s.accountId).run();
    await audit(c.env, c.s.accountId, 'web', 'receipts_off', who(c.s));
    return { ok: true, on: false };
  }, OWNER],
  // the domain move: a one-time link from the old host, and a new passkey on the new host for the same person
  ['POST', /^\/v1\/me\/move\/begin$/, 'webw', (c) => Move.linkBegin(c.env, c.s), ANY],
  ['POST', /^\/v1\/me\/move\/finish$/, 'webw', (c) => Move.linkFinish(c.env, c.s, c.body), ANY],
  ['POST', /^\/v1\/move\/begin$/, 'publicw', (c) => Move.registerBegin(c.env, c.body)],
  ['POST', /^\/v1\/move\/finish$/, 'publicw', (c) => Move.registerFinish(c.env, c.body)],
  ['GET', /^\/v1\/passkeys$/, 'session', (c) => Move.listPasskeys(c.env, c.s)],
  // removing one of your own passkeys needs a fresh passkey ceremony and signs out your other web sessions
  ['POST', new RegExp(`^/v1/passkeys/${ID}/remove/begin$`), 'webw', (c) => Move.removeBegin(c.env, c.s, c.m[1]), ANY],
  ['POST', new RegExp(`^/v1/passkeys/${ID}/remove/finish$`), 'webw', (c) => Move.removeFinish(c.env, c.s, c.m[1], c.body), ANY],
  ['GET', /^\/v1\/push\/key$/, 'session', (c) => Push.publicKey(c.env)],
  // alerts are a browser feature: only a web session adds, removes or tests a device (a stolen CLI session could
  // otherwise fill the account's 10 device slots, or learn when holds happen through a device of its own)
  ['POST', /^\/v1\/push\/subscribe$/, 'webw', (c) => Push.subscribe(c.env, c.s, c.body), ANY],
  ['POST', /^\/v1\/push\/unsubscribe$/, 'webw', (c) => Push.unsubscribe(c.env, c.s, c.body), ANY],
  ['POST', /^\/v1\/push\/test$/, 'webw', async (c) => { await limit(c.env.DB, 'pushtest:' + c.s.accountId, 3, 60_000, now()); return Push.notify(c.env, c.s.accountId, c.env.__pushFetch || fetch); }, ANY],
  ['GET', /^\/v1\/credentials$/, 'session', (c) => B.listCredentials(c.env, c.s)],
  ['POST', /^\/v1\/credentials$/, 'write', (c) => B.addCredential(c.env, c.s, c.body)],
  // deleting a vaulted key breaks every token on it (the whole team's): an owner, never a CLI session
  ['DELETE', new RegExp(`^/v1/credentials/${ID}$`), 'webw', (c) => B.deleteCredential(c.env, c.s, c.m[1]), OWNER],
  ['GET', /^\/v1\/tokens$/, 'session', (c) => B.listTokens(c.env, c.s)],
  ['POST', /^\/v1\/tokens$/, 'write', (c) => B.mintToken(c.env, c.s, c.body, false)],
  // pre-approving irreversible calls is approving in advance: someone who may approve, and only while one seal is enough
  ['POST', /^\/v1\/tokens\/passkey\/begin$/, 'webw', (c) => B.mintBegin(c.env, c.s), APPROVER],
  ['POST', /^\/v1\/tokens\/passkey\/finish$/, 'webw', (c) => B.mintFinish(c.env, c.s, c.body), APPROVER],
  ['DELETE', new RegExp(`^/v1/tokens/${ID}$`), 'write', (c) => B.revokeToken(c.env, c.s, c.m[1])],
  ['GET', /^\/v1\/holds$/, 'session', (c) => B.listHolds(c.env, c.s, c.url.searchParams.get('status'))],
  // a seal: an owner or approver, with their own passkey (src/team.js checks the rest in the same transaction)
  ['POST', new RegExp(`^/v1/holds/${ID}/approve/begin$`), 'webw', (c) => B.approveBegin(c.env, c.s, c.m[1]), APPROVER],
  ['POST', new RegExp(`^/v1/holds/${ID}/approve/finish$`), 'webw', (c) => B.approveFinish(c.env, c.s, c.m[1], c.body), APPROVER],
  // deny is always safe: any member, any session
  ['POST', new RegExp(`^/v1/holds/${ID}/deny$`), 'write', (c) => B.denyHold(c.env, c.s, c.m[1], c.body), ANY],
  // The team (two-person seal, src/team.js). Every change that adds people or changes what they may do needs an owner
  // and a fresh passkey ceremony; revoking an invite only tightens. Joining is public, on the product's host, with the
  // invite's token in the POST body.
  ['GET', /^\/v1\/team$/, 'session', (c) => Team.getTeam(c.env, c.s)],
  ['POST', /^\/v1\/team\/invites\/begin$/, 'webw', (c) => Team.inviteBegin(c.env, c.s, c.body), OWNER],
  ['POST', /^\/v1\/team\/invites\/finish$/, 'webw', (c) => Team.inviteFinish(c.env, c.s, c.body), OWNER],
  ['DELETE', new RegExp(`^/v1/team/invites/${ID}$`), 'write', (c) => Team.revokeInvite(c.env, c.s, c.m[1]), OWNER],
  ['POST', new RegExp(`^/v1/team/members/${ID}/role/begin$`), 'webw', (c) => Team.roleBegin(c.env, c.s, c.m[1], c.body), OWNER],
  ['POST', new RegExp(`^/v1/team/members/${ID}/role/finish$`), 'webw', (c) => Team.roleFinish(c.env, c.s, c.m[1], c.body), OWNER],
  // removal: an owner removes anyone (the rules in team.js permitting); anyone may leave
  ['POST', new RegExp(`^/v1/team/members/${ID}/remove/begin$`), 'webw', (c) => Team.removeBegin(c.env, c.s, c.m[1]), ANY],
  ['POST', new RegExp(`^/v1/team/members/${ID}/remove/finish$`), 'webw', (c) => Team.removeFinish(c.env, c.s, c.m[1], c.body), ANY],
  ['POST', /^\/v1\/team\/quorum\/begin$/, 'webw', (c) => Team.quorumBegin(c.env, c.s, c.body), OWNER],
  ['POST', /^\/v1\/team\/quorum\/finish$/, 'webw', (c) => Team.quorumFinish(c.env, c.s, c.body), OWNER],
  ['POST', /^\/v1\/team\/quorum\/cancel\/begin$/, 'webw', (c) => Team.cancelBegin(c.env, c.s), APPROVER],
  ['POST', /^\/v1\/team\/quorum\/cancel\/finish$/, 'webw', (c) => Team.cancelFinish(c.env, c.s, c.body), APPROVER],
  ['POST', /^\/v1\/invites\/lookup$/, 'publicw', (c) => Team.inviteLookup(c.env, c.request, c.body)],
  ['POST', /^\/v1\/invites\/begin$/, 'publicw', (c) => Team.joinBegin(c.env, c.request, c.body)],
  ['POST', /^\/v1\/invites\/finish$/, 'publicw', (c) => Team.joinFinish(c.env, c.request, c.body)],
  // Guard keys (lsg_): what a coding-agent hook holds to ask for approvals. Making one or revoking one never loosens
  // anything (a guard key can ask, never approve), so a CLI session may do both.
  ['GET', /^\/v1\/guard\/keys$/, 'session', (c) => G.listKeys(c.env, c.s)],
  ['POST', /^\/v1\/guard\/keys$/, 'write', (c) => G.createKey(c.env, c.s, c.body)],
  ['DELETE', new RegExp(`^/v1/guard/keys/${ID}$`), 'write', (c) => G.revokeKey(c.env, c.s, c.m[1])],
  // Approvals for what the broker does not proxy (a coding agent's command, an MCP tool call): ask, wait, use once.
  ['POST', /^\/v1\/approvals$/, 'guard', (c) => G.create(c)],
  ['GET', new RegExp(`^/v1/approvals/${ID}$`), 'guard', (c) => G.status(c, c.m[1])],
  ['POST', new RegExp(`^/v1/approvals/${ID}/use$`), 'guard', (c) => G.use(c, c.m[1])],
  // Deploy gates: a GitHub Actions job waits for a passkey approval. Making a gate needs a passkey ceremony (it decides which
  // repository may ask you, and in phase 2 which key a run gets); revoking only tightens, so any signed-in session may.
  ['GET', /^\/v1\/gates$/, 'session', (c) => Gt.listGates(c.env, c.s)],
  ['POST', /^\/v1\/gates\/passkey\/begin$/, 'webw', (c) => Gt.createBegin(c.env, c.s)],
  ['POST', /^\/v1\/gates\/passkey\/finish$/, 'webw', (c) => Gt.createFinish(c.env, c.s, c.body)],
  ['DELETE', /^\/v1\/gates\/(gate_[0-9a-f]{24})$/, 'write', (c) => Gt.revoke(c.env, c.s, c.m[1])],
  ['POST', /^\/v1\/gate\/request$/, 'gate', (c) => Gt.request(c)],
  ['GET', new RegExp(`^/v1/gate/status/${ID}$`), 'poll', (c) => Gt.status(c, c.m[1])],
  ['POST', new RegExp(`^/v1/gate/cancel/${ID}$`), 'poll', (c) => Gt.cancel(c, c.m[1])],
  ['GET', /^\/v1\/audit$/, 'session', async (c) => { const v = c.url.searchParams.get('before'); return { entries: await auditList(c.env, c.s.accountId, v === null ? 0 : int(v, 'before')) }; }],
  ['GET', /^\/v1\/audit\/verify$/, 'session', (c) => verifyChain(c.env, c.s.accountId)],
  // agent keys (Prove who). Registering needs proof of possession; revoking breaks every token bound to the key, so
  // like deleting a vaulted key it needs a web session.
  ['GET', /^\/v1\/agent-keys$/, 'session', (c) => K.list(c.env, c.s)],
  ['POST', /^\/v1\/agent-keys\/begin$/, 'write', (c) => K.registerBegin(c.env, c.s, c.body)],
  ['POST', /^\/v1\/agent-keys$/, 'write', (c) => K.registerFinish(c.env, c.s, c.body)],
  ['DELETE', new RegExp(`^/v1/agent-keys/${ID}$`), 'webw', (c) => K.revoke(c.env, c.s, c.m[1])],
  // the free Web Bot Auth checker's one server call: fetch an agent's public key directory (SSRF-safe)
  ['GET', /^\/v1\/tools\/directory$/, 'tool', (c) => directoryTool(c)],
  // the operator's private launch numbers (aggregate counts only; 404 without the STATS_TOKEN secret)
  ['GET', /^\/v1\/admin\/stats$/, 'admin', async (c) => {
    let head = null;
    try { head = await cachedHead({ key: await logKey(c.env), log: c.log }); } catch { /* the log is optional for these numbers */ }
    return stats(c.env, head);
  }],
  ...LEDGER_ROUTES,
];

// Erase an account and everything tied to it. Web session only (an agent holding a CLI session can't do it), a fresh
// passkey ceremony (a stolen cookie alone can't), and the body must say {"confirm":"delete"} so a stray request can't.
// Public log entries stay (that is the point of a public log) but are unlinked: the server forgets whose they were.
async function deleteBegin(env, s) {
  const { id, challenge } = await A.newChallenge(env, 'delete', s.accountId);
  return { challengeId: id, options: { challenge, rpId: A.rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}
async function deleteAccount(env, s, body) {
  if (body?.confirm !== 'delete') throw new HttpError(400, 'confirm_required', 'Send {"confirm":"delete"}.');
  const ch = await A.takeChallenge(env, body.challengeId, 'delete');
  if (ch.account_id !== s.accountId) throw new HttpError(403, 'forbidden');
  await A.checkAssertion(env, body.credential, ch.challenge, s);
  const id = s.accountId;
  // order matters: receipts keys stop working first, then the log is unlinked, then the rows go (the whole team's)
  await forgetAccount(env, id);
  await env.DB.batch([
    ...deleteStatements(env.DB, id),
    ...Brakes.deleteStatements(env.DB, id), // their tokens' daily totals and breaker windows, before the tokens go
    ...['push_subs', 'hold_votes', 'holds', 'guard_keys', 'gate_polls', 'gate_runs', 'gates', 'tokens', 'agent_keys', 'credentials', 'audit', 'sessions', 'move_links', 'passkeys', 'challenges', 'device_codes', 'invites', 'members'].map((t) => env.DB.prepare(`DELETE FROM ${t} WHERE account_id = ?`).bind(id)),
    env.DB.prepare('DELETE FROM accounts WHERE id = ?').bind(id),
  ]);
  return { body: { deleted: true, note: 'Account deleted. Receipts already in the public log stay there by design; they are no longer linked to you on our side.' }, cookie: '__Host-leash=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' };
}

// Security events, logged live (wrangler tail) with the error code, status, method and path (ids redacted). Never an IP
// address, token, API key, cookie, account id or request body. Workers Logs are off, so nothing here is stored.
const SECURITY_EVENTS = new Set(['api_key_required', 'api_key_invalid', 'csrf', 'replay', 'slow_down', 'unknown_passkey', 'bad_signature',
  'bad_signerProof', 'bad_signerPublicKey', 'signer_taken', 'sig_requires_signer_key', 'signature_required', 'stale_ts',
  'challenge_expired', 'bad_challenge', 'bad_origin', 'bad_rp', 'user_verification_required', 'too_large', 'quota', 'daily_quota', 'log_at_capacity',
  'not_configured', 'log_key_invalid', 'log_key_changed', 'token_invalid', 'agent_signature_required', 'bad_agent_signature', 'agent_signature_replayed',
  'agent_key_revoked', 'passkey_required', 'bad_proof', 'key_taken', 'code_not_found', 'bad_user_code', 'too_many_holds',
  'guard_key_required', 'guard_key_invalid', 'hash_mismatch', 'account_frozen',
  'role_required', 'approver_required', 'own_request', 'already_sealed', 'seal_not_yet', 'invite_invalid', 'already_member', 'hold_changed',
  'oidc_required', 'oidc_malformed', 'oidc_alg', 'oidc_unknown_kid', 'oidc_bad_signature', 'oidc_issuer', 'oidc_audience', 'oidc_expired', 'oidc_not_yet_valid',
  'oidc_lifetime', 'oidc_claims', 'oidc_replayed', 'oidc_keys_unavailable', 'gate_refused', 'poll_secret_required']);
/** an audit detail's `member` on a team (the founder's entries keep their shape) */
const who = (s) => (s.memberId && s.memberId !== s.accountId ? { member: s.memberId } : {});
const logPath = (url) => url.pathname.startsWith('/p/') ? url.pathname.split('/').slice(0, 3).join('/') + '/...' : url.pathname.replace(/\/[0-9a-f]{24}(?=\/|$)/g, '/:id');
function securityLog(e, request, url) {
  if (!(e instanceof HttpError) || !SECURITY_EVENTS.has(e.code)) return;
  const line = JSON.stringify({ event: 'security', code: e.code, status: e.status, method: request.method, path: logPath(url) });
  if (e.status >= 500) console.error(line); else console.warn(line);
}

export const SECURITY_TXT = (env) => [
  `Contact: mailto:${BRAND.security}`,
  'Expires: 2027-10-01T00:00:00.000Z',
  'Preferred-Languages: en',
  `Canonical: ${A.rp(env).origin}/.well-known/security.txt`,
  `Policy: ${A.rp(env).origin}/security/`,
  '',
].join('\n');
const TEXT_HEADERS = { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=3600', 'x-content-type-options': 'nosniff' };
function wellKnown(url, request, env) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method not allowed', { status: 405, headers: { ...TEXT_HEADERS, allow: 'GET, HEAD' } });
  if (url.pathname === '/.well-known/security.txt') return new Response(request.method === 'HEAD' ? null : SECURITY_TXT(env), { headers: TEXT_HEADERS });
  return new Response('Not found', { status: 404, headers: TEXT_HEADERS });
}

export async function handle(request, rawEnv, opts = {}) {
  const url = new URL(request.url);
  // work that may finish after the response (ctx.waitUntil on Workers); its failure is logged, never thrown
  const ctx = opts.ctx || rawEnv.__ctx;
  const waitUntil = (p) => {
    const q = Promise.resolve(p).catch((e) => console.error(JSON.stringify({ event: 'background_failed', message: String(e?.message || e).slice(0, 200) })));
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(q);
    return q;
  };
  const env = { ...rawEnv, __ctx: ctx ? { waitUntil } : undefined, __log: opts.log || rawEnv.__log, __rp: A.hostOf(rawEnv, request) };
  const isPublic = PUBLIC_PATH.test(url.pathname);
  try {
    if (url.pathname.startsWith('/.well-known/')) return wellKnown(url, request, env);
    // agent proxy
    const pm = url.pathname.match(/^\/p\/([a-z]+)\/(.*)$/);
    if (pm) {
      await limit(env.DB, await ipBucket(env, request, 'pip'), 1200, 60_000, now());
      return await B.proxy(env, request, pm[1], pm[2], opts.fetcher || fetch);
    }
    if (!url.pathname.startsWith('/v1/')) {
      // the old host keeps /app (sign-in for its passkeys); every other page moves to the product's host
      const here = A.hosts(env).find((h) => h.origin === url.origin);
      if (here && here.legacy && !KEEP_ON_OLD_HOST.test(url.pathname)) return movedPermanently(A.hosts(env)[0].origin + url.pathname + url.search);
      return env.ASSETS ? withSiteHeaders(await env.ASSETS.fetch(request)) : json({ error: 'not_found' }, 404);
    }
    if (request.method === 'OPTIONS') {
      if (isPublic) return new Response(null, { status: 204, headers: { ...CORS, 'access-control-allow-methods': 'GET', 'access-control-max-age': '86400' } });
      return json({ error: 'no_cors' }, 403);
    }
    for (const [method, re, guard, fn, role] of ROUTES) {
      if (method !== request.method) continue;
      const m = url.pathname.match(re);
      if (!m) continue;
      const t = now();
      // request.cf: Cloudflare's data about the caller's network (country, network name); tests and local dev pass opts.cf
      const c = { env, request, url, m, body: {}, waitUntil, cf: request.cf || opts.cf || null, get log() { return logOf(env); } };
      // the log's name and key, for the routes that sign or name the log (the broker's own routes work without it)
      if (guard === 'pub' || guard === 'key' || isPublic || /^\/v1\/(keys|my)(\/|$)/.test(url.pathname)) c.key = await logKey(env);
      if (guard === 'public' || guard === 'publicw') await limit(env.DB, await ipBucket(env, request, guard === 'public' ? 'pub' : 'pubw'), 60, 60_000, t);
      if (guard === 'publicw' && !A.originAllowed(env, request)) throw new HttpError(403, 'csrf');
      // reads of the public log and the tool: no storage write per request
      if (guard === 'pub') await readLimit(env, await ipBucket(env, request, 'pubr'), Number(env.PUB_RPM) || 600, t);
      if (guard === 'tool') await readLimit(env, await ipBucket(env, request, 'tool'), Number(env.TOOL_RPM) || 10, t);
      if (guard === 'admin') { await readLimit(env, await ipBucket(env, request, 'admin'), 30, t); await checkStatsToken(env, request); }
      // receipts: the hard limits (quotas, daily capacity) are reserved in D1; the per-key rate limit costs no D1 write
      if (guard === 'key') { c.k = await apiKey(env, request); await readLimit(env, 'key:' + c.k.id, 1200, t); }
      // guard keys: waiting for an approval writes nothing to D1, so this limit lives in memory too
      if (guard === 'guard') { await readLimit(env, await ipBucket(env, request, 'guard'), Number(env.GUARD_RPM) || 240, t); c.g = await G.guardKey(env, request); }
      // deploy gates: waiting and asking write nothing to D1 for their limits either. A hosted runner's network is shared with
      // many other people, so the per-network limit is generous; the gate (30 new holds an hour) and the poll secret (30 a minute) have their own.
      if (guard === 'gate') await readLimit(env, await ipBucket(env, request, 'gate'), Number(env.GATE_RPM) || 600, t);
      if (guard === 'poll') { await readLimit(env, await ipBucket(env, request, 'gatepoll'), Number(env.GATE_RPM) || 600, t); c.poll = await Gt.pollAuth(request); }
      if (guard === 'session' || guard === 'write' || guard === 'webw') {
        c.s = await A.session(env, request, guard !== 'session');
        if (guard === 'webw' && c.s.kind !== 'web') throw new HttpError(403, 'passkey_required', `This needs your passkey in the ${BRAND.name} app.`);
        // the team role, on the server, for every signed-in request (reads: any member; writes: not a viewer, unless the
        // route says otherwise)
        Team.requireLevel(c.s, role ?? (guard === 'session' ? ANY : MEMBER));
        const seen = markSeen(env, c.s.accountId);
        if (seen) waitUntil(seen);
        // reads cost no D1 write for their limit; writes are counted in D1 so the limit holds across isolates
        if (guard === 'session') await readLimit(env, 'acct:' + c.s.accountId, 300, t);
        else await limit(env.DB, 'acct:' + c.s.accountId, 300, 60_000, t);
      }
      // reads that reach the log's Durable Object (Workers Free: 100k Durable Object requests a day) have a tighter limit:
      // 120 a minute per network for the public ones, 60 a minute per account for your own receipts
      if (request.method === 'GET' && DO_READS.test(url.pathname)) await readLimit(env, c.s ? 'do:' + c.s.accountId : await ipBucket(env, request, 'pubdo'), c.s ? 60 : Number(env.PUB_DO_RPM) || 120, t);
      if (request.method === 'POST') c.body = await readJson(request, guard === 'key' ? 262144 : 16384);
      const out = await fn(c);
      if (out instanceof Response) return out;
      if (out && out.cookie) return json(out.body, 200, { 'set-cookie': out.cookie });
      return json(out);
    }
    return isPublic ? json({ error: 'not_found' }, 404, CORS) : json({ error: 'not_found' }, 404);
  } catch (e) {
    securityLog(e, request, url);
    const r = errorResponse(e, { method: request.method, path: logPath(url) });
    // verifiers and monitors in browsers must be able to read public errors (429, 400, 503) too
    if (isPublic) r.headers.set('access-control-allow-origin', '*');
    return r;
  }
}

// Expired rows are always rejected at read time; this only tidies them away. There is no cron (the account's five cron
// triggers are used by other Workers): it runs on about 1 in 50 requests, and after sign-ins and sign-ups at most every
// 10 minutes per isolate, always after the response, so no request waits for it. One batch, 18 statements (D1 allows 50).
export async function sweep(env, t = Date.now()) {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM challenges WHERE expires_at < ?').bind(t),
    env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(t),
    env.DB.prepare('DELETE FROM device_codes WHERE expires_at < ?').bind(t),
    env.DB.prepare('DELETE FROM ratelimits WHERE reset_at < ?').bind(t),
    env.DB.prepare('DELETE FROM nonces WHERE expires_at < ?').bind(t),
    env.DB.prepare('DELETE FROM move_links WHERE expires_at < ?').bind(t - 86400_000),
    env.DB.prepare("UPDATE holds SET status = 'expired' WHERE status IN ('pending','approved') AND expires_at < ?").bind(t),
    // request previews are only needed while a human is deciding; drop them a day after the hold is closed
    env.DB.prepare("UPDATE holds SET preview = NULL WHERE preview IS NOT NULL AND status NOT IN ('pending','approved') AND expires_at < ?").bind(t - 86400_000),
    // two-person seal: seals are only needed while their hold is open (at most 40 minutes; the audit log keeps every
    // seal), and an invite that expired a day ago is gone
    env.DB.prepare('DELETE FROM hold_votes WHERE at < ?').bind(t - 2 * 86400_000),
    env.DB.prepare('DELETE FROM invites WHERE expires_at < ?').bind(t - 86400_000),
    // a deploy hold also names the person who started the run (their GitHub login): dropped with the preview. The private
    // audit log keeps the repository, commit and run, never that name.
    env.DB.prepare("UPDATE holds SET context = NULL WHERE kind = 'deploy' AND context IS NOT NULL AND status NOT IN ('pending','approved') AND expires_at < ?").bind(t - 86400_000),
    env.DB.prepare('DELETE FROM gate_polls WHERE expires_at < ?').bind(t),
    ...cleanupStatements(env.DB, t),
    ...Brakes.sweepStatements(env.DB, t), // breaker windows that ended, daily money totals older than 35 days
  ]);
}
let lastSweep = 0;
function maybeSweep(c) {
  const t = now();
  if (t - lastSweep < 10 * 60_000) return;
  lastSweep = t;
  c.waitUntil(sweep(c.env, t));
}

export default {
  async fetch(request, env, ctx) {
    if (Math.random() < 0.02) ctx.waitUntil(sweep(env).catch(() => {}));
    return handle(request, env, { ctx });
  },
  // kept for a paid plan or a freed cron slot; wrangler.jsonc declares no cron
  async scheduled(event, env) {
    await sweep(env);
  },
};
