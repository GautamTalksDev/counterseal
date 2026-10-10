// The two-person seal (feature 2a): team members, invites, roles, and quorum votes on held actions.
//
// One account, several people, each with their own passkey (no shared credentials). Every member signs in with their
// own passkey, and every web or CLI session belongs to the member whose passkey made it. Roles, checked on the server
// for every request (a passkey proves presence, not authority):
//   owner     everything: the team, the quorum, the vault, deleting the account; seals held actions
//   approver  seals held actions; makes tokens, guard keys and keys; cancels a pending lowering of the quorum
//   member    makes tokens, guard keys and keys for their agents; cannot seal
//   viewer    reads; may deny a held action and freeze the account (stopping is always safe)
// The account always keeps an owner: the last one can be neither removed nor demoted. Owners may change one another
// (an owner can delete the whole account anyway, so making someone an owner is full trust); every change of who is on
// the team or what they may do is audited and wakes every member's devices.
//
// Seals (votes). A held action (a brokered call, a coding agent's command, a tool call or a deploy) is approved when
// `quorum` different approvers have each sealed it with a fresh passkey ceremony. A seal is one row per (hold, member):
// the member comes from the passkey used, so one person with two passkeys or two browsers counts once. Each seal is bound
// to the hold's exact request hash (carried by the challenge), expires with the hold, and counts only while its member is
// still an owner or approver. With self-approval off, the member who made the token or guard key that asked cannot be
// one of them. Any member's denial ends the hold.
//
// Protection is never lowered at once: raising the quorum (or turning self-approval off) takes effect immediately;
// lowering it (or turning self-approval on) takes effect 24 hours later, alerts every member's devices, and any approver
// can cancel it in that time. While two seals are required, a new approver's seal counts only 24 hours after they joined
// or were promoted, so neither an owner nor a stolen invite link can mint a second vote on the spot. There is no cron: a
// pending change is applied when it is read (effective() below, and the same CASE in SQL).
//
// Invites: an owner makes one with a fresh passkey ceremony. The token is 32 random bytes, stored only as SHA-256, single
// use, 2 hours by default (24 at most), bound to the account and to the owner who made it (it dies if they stop being an
// owner), 10 an hour per account, and travels only in the URL fragment and POST bodies (never in a request line, a log
// or a Referer), like the move link. The invite page shows the account, the inviter and the role before anything is
// created. Joining makes a new passkey on this host; an authenticator that already holds one of the account's passkeys
// is excluded, and a browser already signed in to the account is refused (one person, one membership).
//
// Extension points for break-glass windows and team alert channels (feature 2b) are listed in docs/PROTOCOL.md (Team).
import { HttpError, b64u, rand, randomId, sha256hex, now, str, cleanText } from './util.js';
import { verifyRegistration } from './webauthn.js';
import { newChallenge, takeChallenge, checkAssertion, rp, hosts, startWebSession, session as readSession } from './auth.js';
import { audit } from './audit.js';
import { limit, allow } from './ratelimit.js';
import { notify } from './push.js';
import { BRAND } from './brand.js';

export const ROLES = ['owner', 'approver', 'member', 'viewer'];
export const LEVEL = { viewer: 0, member: 1, approver: 2, owner: 3 };
export const INVITE_ROLES = ['approver', 'member', 'viewer'];
export const MAX_MEMBERS = 10, MAX_OPEN_INVITES = 10, MAX_QUORUM = 2, INVITES_PER_HOUR = 10;
export const LOWER_DELAY = 24 * 3600_000, VOTE_DELAY = 24 * 3600_000, INVITE_HOURS = 2, INVITE_MAX_HOURS = 24;
export const GRANT_TTL = 10 * 60_000; // an approved hold is used once within 10 minutes (as in broker.js)
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const NAME = /^[\p{L}\p{N} ._'-]+$/u;
const LABEL = /^[\p{L}\p{N} ._:/()',-]+$/u; // what an invite is for ("Asha, platform team"); shown with textContent only
const ID = /^[0-9a-f]{24}$/;
const sameText = (a, b) => String(a).trim().toLowerCase() === String(b).trim().toLowerCase();

// ---------------------------------------------------------------- who is who
/** the member behind a row that has member_id and account_id (NULL member_id: written before teams, the founder) */
export const memberOf = (row) => row.member_id || row.account_id;

/** SQL: the role of member M in account A (both SQL expressions), or NULL when they are not, or no longer, a member.
 *  The founder has no members row until the team is first changed; until then they are the owner. */
export const ROLE_OF = (M, A) => `COALESCE((SELECT CASE WHEN removed_at IS NULL THEN role END FROM members WHERE id = ${M} AND account_id = ${A}), CASE WHEN ${M} = ${A} AND NOT EXISTS (SELECT 1 FROM members WHERE id = ${M} AND account_id = ${A}) THEN 'owner' END)`;
/** SQL: the quorum and the self-approval switch of account A in force at time T (a pending change applies once due) */
const DUE = (T) => `quorum_effective_at IS NOT NULL AND quorum_pending IS NOT NULL AND quorum_effective_at <= ${T}`;
export const Q_NOW = (A, T) => `(SELECT CASE WHEN ${DUE(T)} THEN quorum_pending ELSE quorum END FROM accounts WHERE id = ${A})`;
export const SA_NOW = (A, T) => `(SELECT CASE WHEN ${DUE(T)} THEN self_approve_pending ELSE self_approve END FROM accounts WHERE id = ${A})`;
/** SQL: how many people of account A can seal (owners and approvers; an account without a team: its founder) */
const VOTERS = (A, except = null) => `(CASE WHEN EXISTS (SELECT 1 FROM members WHERE account_id = ${A}) THEN (SELECT COUNT(*) FROM members WHERE account_id = ${A} AND removed_at IS NULL AND role IN ('owner','approver')${except ? ` AND id != ${except}` : ''}) ELSE ${except ? `(CASE WHEN ${except} = ${A} THEN 0 ELSE 1 END)` : '1'} END)`;
/** SQL: member M's seal counts on hold H (an alias or table name with account_id and requested_by) at time T */
const ELIGIBLE = (M, H, T) => `(${ROLE_OF(M, `${H}.account_id`)} IN ('owner','approver')
  AND COALESCE((SELECT votes_from FROM members WHERE id = ${M} AND account_id = ${H}.account_id), 0) <= ${T}
  AND NOT (${SA_NOW(`${H}.account_id`, T)} = 0 AND ${H}.requested_by IS NOT NULL AND ${H}.requested_by = ${M}))`;

/** the quorum settings in force at time t, from an accounts row (or any row carrying its quorum columns) */
export function effective(a, t = now()) {
  const due = a && a.quorum_effective_at != null && a.quorum_pending != null && a.quorum_effective_at <= t;
  const q = due ? a.quorum_pending : a?.quorum;
  const sa = due ? a.self_approve_pending : a?.self_approve;
  return {
    quorum: Number.isInteger(q) && q >= 1 ? q : 1,
    selfApprove: sa === 0 ? false : true,
    pending: !due && a && a.quorum_effective_at != null && a.quorum_pending != null
      ? { quorum: a.quorum_pending, selfApprove: a.self_approve_pending !== 0, effectiveAt: a.quorum_effective_at } : null,
  };
}

/** one person may approve alone (quorum 1, self-approval on): only then do pre-approvals and money caps apply, or can be
 *  made, since each is one person approving in advance */
export const oneSealEnough = (e) => e.quorum <= 1 && e.selfApprove;

/** a role at least this level, or 403 (the route table in index.js calls this for every signed-in request) */
export function requireLevel(sess, need) {
  if ((LEVEL[sess.role] ?? -1) >= need) return;
  const want = need >= LEVEL.owner ? 'an owner' : need >= LEVEL.approver ? 'an owner or an approver' : 'a team member who can make keys (not a viewer)';
  throw new HttpError(403, 'role_required', `This needs ${want} of this ${BRAND.name} account. Your role is ${sess.role}.`, { role: sess.role });
}

const ceremony = async (env, kind, accountId, name = null) => {
  const { id, challenge } = await newChallenge(env, kind, accountId, name);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
};
/** the passkey ceremony's second half for a team change: the challenge was issued for this kind and account, and the
 *  passkey is the signed-in member's own */
async function confirm(env, sess, body, kind) {
  const ch = await takeChallenge(env, body.challengeId, kind);
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess);
  return ch;
}
const founderRow = (db, accountId) => db.prepare("INSERT OR IGNORE INTO members (id, account_id, name, role, created_at, votes_from) SELECT id, id, name, 'owner', created_at, 0 FROM accounts WHERE id = ?").bind(accountId);

/** wake every member's devices (the push carries nothing; the phone reads /v1/alerts), optionally not one member's */
function alertTeam(env, accountId, exceptMember, bucket = 'pushteam:') {
  const p = (async () => { if (await allow(env.DB, bucket + accountId, 1, 60_000, now())) await notify(env, accountId, env.__pushFetch || fetch, { exceptMember }); })().catch(() => {});
  if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(p);
  return p;
}

// ---------------------------------------------------------------- reading the team
async function accountRow(env, accountId) {
  const a = await env.DB.prepare('SELECT id, name, created_at, quorum, self_approve, quorum_pending, self_approve_pending, quorum_effective_at FROM accounts WHERE id = ?').bind(accountId).first();
  if (!a) throw new HttpError(401, 'signed_out');
  return a;
}
/** the account's members (the founder too, with or without a row), with how many passkeys each has and when one was
 *  last used */
async function membersOf(env, accountId) {
  const m = (await env.DB.prepare(`SELECT id, name, label, role, created_at, invited_by, votes_from FROM members WHERE account_id = ?1 AND removed_at IS NULL
      UNION ALL SELECT id, name, NULL, 'owner', created_at, NULL, 0 FROM accounts WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM members WHERE id = ?1) ORDER BY created_at`).bind(accountId).all()).results;
  const p = (await env.DB.prepare('SELECT COALESCE(member_id, account_id) AS m, COUNT(*) AS n, MAX(last_used) AS last FROM passkeys WHERE account_id = ? GROUP BY m').bind(accountId).all()).results;
  const pk = new Map(p.map((r) => [r.m, r]));
  return m.map((r) => ({ ...r, founder: r.id === accountId, passkeys: pk.get(r.id)?.n || 0, last_used: pk.get(r.id)?.last || null }));
}

/** GET /v1/team (any member): the members, the quorum (and a pending change), open invites, and who you are */
export async function getTeam(env, sess) {
  const t = now(), a = await accountRow(env, sess.accountId);
  const members = await membersOf(env, sess.accountId);
  const inv = (await env.DB.prepare('SELECT id, role, label, created_by, created_at, expires_at FROM invites WHERE account_id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT 20').bind(sess.accountId, t).all()).results;
  const e = effective(a, t);
  const voters = members.filter((m) => m.role === 'owner' || m.role === 'approver');
  return {
    me: { id: sess.memberId, role: sess.role },
    quorum: e.quorum, selfApprove: e.selfApprove, pending: e.pending, maxQuorum: MAX_QUORUM, lowerDelayHours: LOWER_DELAY / 3600_000,
    voters: voters.length, votersNow: voters.filter((m) => !(m.votes_from > t)).length,
    members: members.map(({ invited_by, ...m }) => ({ ...m, invited_by: invited_by || null, votes_from: m.votes_from > t ? m.votes_from : null, you: m.id === sess.memberId })),
    invites: inv, maxMembers: MAX_MEMBERS,
  };
}

// ---------------------------------------------------------------- invites (owner, passkey)
function inviteParams(body) {
  if (!INVITE_ROLES.includes(body.role)) throw new HttpError(400, 'bad_role', `An invite is for an approver, a member or a viewer. Make someone an owner after they join.`);
  const label = str(body.label, 'label', { max: 60, re: LABEL });
  const hours = body.hours === undefined ? INVITE_HOURS : body.hours;
  if (!Number.isInteger(hours) || hours < 1 || hours > INVITE_MAX_HOURS) throw new HttpError(400, 'bad_hours', `An invite lasts 1 to ${INVITE_MAX_HOURS} hours.`);
  return { role: body.role, label, hours };
}
async function roomFor(env, accountId, t) {
  const r = await env.DB.prepare('SELECT (SELECT COUNT(*) FROM members WHERE account_id = ?1 AND removed_at IS NULL) AS members, EXISTS (SELECT 1 FROM members WHERE id = ?1) AS has_founder, (SELECT COUNT(*) FROM invites WHERE account_id = ?1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?2) AS open').bind(accountId, t).first();
  const people = r.members + (r.has_founder ? 0 : 1);
  if (people + r.open >= MAX_MEMBERS) throw new HttpError(409, 'team_full', `A team has up to ${MAX_MEMBERS} people, counting open invites. Remove someone or revoke an invite first.`);
  if (r.open >= MAX_OPEN_INVITES) throw new HttpError(409, 'too_many_invites', `Up to ${MAX_OPEN_INVITES} open invites. Revoke one first.`);
}

export async function inviteBegin(env, sess, body) {
  const p = inviteParams(body);
  await roomFor(env, sess.accountId, now());
  // what the passkey approves is exactly what is made: the role, label and lifetime ride in the challenge
  return ceremony(env, 'team_invite', sess.accountId, JSON.stringify(p));
}

export async function inviteFinish(env, sess, body) {
  const ch = await confirm(env, sess, body, 'team_invite');
  const p = JSON.parse(ch.name);
  const t = now(), a = sess.accountId;
  await limit(env.DB, 'invite:' + a, INVITES_PER_HOUR, 3600_000, t);
  await roomFor(env, a, t);
  const token = b64u(rand(32)), id = randomId(), expiresAt = t + p.hours * 3600_000;
  const [, ins] = await env.DB.batch([
    founderRow(env.DB, a),
    env.DB.prepare(`INSERT INTO invites (id, hash, account_id, role, label, created_by, created_at, expires_at) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
      WHERE (SELECT COUNT(*) FROM members WHERE account_id = ?3 AND removed_at IS NULL) + (SELECT COUNT(*) FROM invites WHERE account_id = ?3 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?7) < ?9`)
      .bind(id, await sha256hex(token), a, p.role, p.label, sess.memberId, t, expiresAt, MAX_MEMBERS),
  ]);
  if (!ins.meta.changes) throw new HttpError(409, 'team_full', `A team has up to ${MAX_MEMBERS} people, counting open invites.`);
  // the audit log names the invite, never its token or the token's hash
  await audit(env, a, sess.kind, 'invite_created', { invite: id, role: p.role, label: p.label, by: sess.memberId, expires_at: expiresAt });
  return {
    id, role: p.role, label: p.label, expiresAt, url: `${hosts(env)[0].origin}/app#invite=${token}`,
    note: `Shown once. Send it privately to the person you named. It works once, until it expires, and shows them this account's name, your name and the role before they join.`,
  };
}

/** DELETE /v1/team/invites/:id (owner): revoking only tightens */
export async function revokeInvite(env, sess, id) {
  const r = await env.DB.prepare('UPDATE invites SET revoked_at = ? WHERE id = ? AND account_id = ? AND used_at IS NULL AND revoked_at IS NULL').bind(now(), id, sess.accountId).run();
  if (!r.meta.changes) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, sess.kind, 'invite_revoked', { invite: id, by: sess.memberId });
  return { ok: true };
}

// ---------------------------------------------------------------- joining (public, on the product's host)
function joinHost(env) {
  if (rp(env).legacy) throw new HttpError(403, 'invite_on_new_host', `Open the invite at ${hosts(env)[0].origin}.`);
}
/** a live invite whose owner is still an owner: who invites, to which account, for which role */
async function liveInvite(env, token) {
  const hash = await sha256hex(str(token, 'token', { re: TOKEN }));
  const row = await env.DB.prepare(`SELECT i.id, i.account_id, i.role, i.label, i.expires_at, i.created_by, a.name AS account,
      COALESCE((SELECT name FROM members WHERE id = i.created_by AND account_id = i.account_id), a.name) AS inviter
    FROM invites i JOIN accounts a ON a.id = i.account_id
    WHERE i.hash = ?1 AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?2 AND ${ROLE_OF('i.created_by', 'i.account_id')} = 'owner'`).bind(hash, now()).first();
  if (!row) throw new HttpError(400, 'invite_invalid', 'This invite was used, has expired, was revoked, or is wrong. Ask the person who invited you for a new one.');
  return { hash, ...row };
}
/** a browser already signed in to the inviting account is a member already */
async function notMemberYet(env, request, accountId) {
  let s = null;
  try { s = await readSession(env, request, false); } catch { /* signed out, or signed in elsewhere: fine */ }
  if (s && s.accountId === accountId) throw new HttpError(409, 'already_member', 'This browser is signed in to that account already. One person joins once; sign out first if this invite is for someone else on this device.');
}
async function nameFree(env, accountId, name) {
  const taken = (await env.DB.prepare('SELECT name FROM members WHERE account_id = ?1 AND removed_at IS NULL UNION ALL SELECT name FROM accounts WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM members WHERE id = ?1)').bind(accountId).all()).results;
  if (taken.some((r) => sameText(r.name, name))) throw new HttpError(409, 'name_taken', 'Someone in this team already uses that name. Add an initial or a surname.');
}

/** POST /v1/invites/lookup {token}: what the invite page shows before anything is made */
export async function inviteLookup(env, request, body) {
  joinHost(env);
  const l = await liveInvite(env, body.token);
  await notMemberYet(env, request, l.account_id);
  return { account: l.account, inviter: l.inviter, role: l.role, label: l.label, expires_at: l.expires_at };
}

export async function joinBegin(env, request, body) {
  joinHost(env);
  const l = await liveInvite(env, body.token);
  const name = str(typeof body.name === 'string' ? body.name.trim() : body.name, 'name', { max: 60, re: NAME });
  await notMemberYet(env, request, l.account_id);
  await nameFree(env, l.account_id, name);
  const r = rp(env);
  // an authenticator that already holds one of this account's passkeys refuses to make another (WebAuthn
  // excludeCredentials): the same device or passkey manager cannot join a second time as a second person
  const exclude = (await env.DB.prepare('SELECT cred_id FROM passkeys WHERE account_id = ? LIMIT 100').bind(l.account_id).all()).results.map((x) => ({ type: 'public-key', id: x.cred_id }));
  const { id, challenge } = await newChallenge(env, 'team_join', l.account_id, JSON.stringify({ hash: l.hash, name }));
  return {
    challengeId: id, account: l.account, inviter: l.inviter, role: l.role,
    options: {
      challenge, rp: { id: r.rpId, name: r.name }, user: { id: b64u(rand(16)), name, displayName: `${name} (${l.account})`.slice(0, 120) },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], excludeCredentials: exclude,
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, attestation: 'none', timeout: 300000,
    },
  };
}

export async function joinFinish(env, request, body) {
  joinHost(env);
  const ch = await takeChallenge(env, body.challengeId, 'team_join');
  const p = JSON.parse(ch.name);
  const hash = await sha256hex(str(body.token, 'token', { re: TOKEN }));
  if (p.hash !== hash) throw new HttpError(400, 'invite_invalid', 'This invite does not match the one you started with. Start again.');
  await notMemberYet(env, request, ch.account_id);
  const r = rp(env);
  const c = await verifyRegistration(body.credential || {}, { challenge: ch.challenge, origin: r.origin, rpId: r.rpId });
  if (await env.DB.prepare('SELECT 1 AS x FROM passkeys WHERE cred_id = ?').bind(c.credId).first()) throw new HttpError(409, 'passkey_exists', 'That passkey is already registered. Use a new one for this team.');
  await nameFree(env, ch.account_id, p.name);
  const t = now(), mid = randomId(), a = ch.account_id;
  // One transaction. The invite is consumed only if it is live, its owner is still an owner, the team has room and the
  // name is free; the member and their passkey are written only if this request consumed it.
  let res;
  try {
    res = await env.DB.batch([
      env.DB.prepare(`UPDATE invites SET used_at = ?1, used_by = ?2 WHERE hash = ?3 AND account_id = ?4 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?1
        AND ${ROLE_OF('created_by', 'account_id')} = 'owner'
        AND (SELECT COUNT(*) FROM members WHERE account_id = ?4 AND removed_at IS NULL) < ?5
        AND NOT EXISTS (SELECT 1 FROM members WHERE account_id = ?4 AND removed_at IS NULL AND name = ?6 COLLATE NOCASE)`).bind(t, mid, hash, a, MAX_MEMBERS, p.name),
      // while two seals are required, a new approver's seal counts only after 24 hours
      env.DB.prepare(`INSERT INTO members (id, account_id, name, label, role, created_at, invited_by, votes_from)
        SELECT ?1, ?2, ?3, label, role, ?4, created_by, CASE WHEN ${Q_NOW('?2', '?4')} >= 2 THEN ?4 + ?5 ELSE ?4 END FROM invites WHERE hash = ?6 AND used_by = ?1`).bind(mid, a, p.name, t, VOTE_DELAY, hash),
      env.DB.prepare('INSERT INTO passkeys (cred_id, account_id, alg, jwk, sign_count, created_at, rp_id, member_id) SELECT ?, ?, ?, ?, ?, ?, ?, ? FROM invites WHERE hash = ? AND used_by = ?')
        .bind(c.credId, a, c.alg, JSON.stringify(c.jwk), c.signCount, t, r.rpId, mid, hash, mid),
    ]);
  } catch (e) {
    if (/UNIQUE|constraint/i.test(String(e && e.message))) throw new HttpError(409, 'passkey_exists', 'That passkey is already registered. Use a new one for this team.');
    throw e;
  }
  if (!res[0].meta.changes) throw new HttpError(400, 'invite_invalid', 'This invite was used, has expired, was revoked, or the team is full. Ask for a new one.');
  const m = await env.DB.prepare('SELECT i.id AS invite, i.role, i.label, i.created_by, m.votes_from FROM invites i JOIN members m ON m.id = i.used_by WHERE i.hash = ?').bind(hash).first();
  await audit(env, a, 'web', 'member_joined', { member: mid, name: p.name, role: m.role, label: m.label, invite: m.invite, invited_by: m.created_by, ...(m.votes_from > t ? { votes_from: m.votes_from } : {}) });
  // everyone on the team is told at once: a stolen invite link cannot add someone quietly
  await alertTeam(env, a, mid);
  return startWebSession(env, a, mid);
}

// ---------------------------------------------------------------- roles and removal (owner, passkey)
async function target(env, sess, id) {
  if (!ID.test(id)) throw new HttpError(404, 'not_found');
  const members = await membersOf(env, sess.accountId);
  const m = members.find((x) => x.id === id);
  if (!m) throw new HttpError(404, 'not_found');
  const a = await accountRow(env, sess.accountId);
  return { m, members, q: effective(a).quorum };
}
const isVoter = (role) => role === 'owner' || role === 'approver';
/** the rules every role change and removal keeps: the account always has an owner (the last one can be neither removed
 *  nor demoted, so nobody can lock the account out), and there are always at least as many people who can seal as the
 *  quorum needs */
function keepsRules(sess, { m, members, q }, to) {
  const after = members.map((x) => (x.id === m.id ? { ...x, role: to } : x)).filter((x) => x.role);
  if (!after.some((x) => x.role === 'owner')) throw new HttpError(409, 'last_owner', 'The account needs at least one owner. Make someone else an owner first.');
  const voters = after.filter((x) => isVoter(x.role)).length;
  if (voters < q) throw new HttpError(409, 'not_enough_approvers', `${q} seals are required, so the team needs at least ${q} owners or approvers. Lower the quorum first (it takes 24 hours) or add an approver.`);
}

export async function roleBegin(env, sess, id, body) {
  if (!ROLES.includes(body.role)) throw new HttpError(400, 'bad_role', 'A role is owner, approver, member or viewer.');
  const tg = await target(env, sess, id);
  if (tg.m.role === body.role) throw new HttpError(409, 'same_role', `They are already ${body.role === 'owner' || body.role === 'approver' ? 'an' : 'a'} ${body.role}.`);
  keepsRules(sess, tg, body.role);
  return ceremony(env, 'member_role:' + id, sess.accountId, body.role);
}

export async function roleFinish(env, sess, id, body) {
  const ch = await confirm(env, sess, body, 'member_role:' + id);
  const role = ch.name;
  const tg = await target(env, sess, id);
  keepsRules(sess, tg, role);
  const t = now(), a = sess.accountId;
  // the same rules again, in the statement itself, so two owners changing roles at once cannot break them
  const [, up] = await env.DB.batch([
    founderRow(env.DB, a),
    env.DB.prepare(`UPDATE members SET role = ?1,
        votes_from = CASE WHEN ?1 IN ('owner','approver') AND role NOT IN ('owner','approver') THEN (CASE WHEN ${Q_NOW('?3', '?4')} >= 2 THEN ?4 + ?5 ELSE ?4 END) ELSE votes_from END
      WHERE id = ?2 AND account_id = ?3 AND removed_at IS NULL AND role != ?1
        AND (role != 'owner' OR ?1 = 'owner' OR (SELECT COUNT(*) FROM members WHERE account_id = ?3 AND removed_at IS NULL AND role = 'owner' AND id != ?2) >= 1)
        AND (role NOT IN ('owner','approver') OR ?1 IN ('owner','approver') OR (SELECT COUNT(*) FROM members WHERE account_id = ?3 AND removed_at IS NULL AND role IN ('owner','approver') AND id != ?2) >= ${Q_NOW('?3', '?4')})`)
      .bind(role, id, a, t, VOTE_DELAY),
    // no longer able to seal: their seals on waiting holds are dropped
    env.DB.prepare(`DELETE FROM hold_votes WHERE account_id = ?1 AND member_id = ?2 AND ?3 NOT IN ('owner','approver') AND hold_id IN (SELECT id FROM holds WHERE account_id = ?1 AND status = 'pending')
      AND EXISTS (SELECT 1 FROM members WHERE id = ?2 AND account_id = ?1 AND role = ?3)`).bind(a, id, role),
    // no longer an owner: their open invites die
    env.DB.prepare(`UPDATE invites SET revoked_at = ?1 WHERE account_id = ?2 AND created_by = ?3 AND used_at IS NULL AND revoked_at IS NULL AND ?4 != 'owner'
      AND EXISTS (SELECT 1 FROM members WHERE id = ?3 AND account_id = ?2 AND role = ?4)`).bind(t, a, id, role),
  ]);
  if (!up.meta.changes) throw new HttpError(409, 'try_again', 'The team changed while you confirmed. Look again and retry.');
  const row = await env.DB.prepare('SELECT votes_from FROM members WHERE id = ?').bind(id).first();
  await audit(env, a, 'web', 'member_role_changed', { member: id, name: tg.m.name, from: tg.m.role, to: role, by: sess.memberId, ...(row?.votes_from > t ? { votes_from: row.votes_from } : {}) });
  // who may seal or run the team is never changed quietly: every member's devices are told
  await alertTeam(env, a, sess.memberId);
  return { ok: true, role, votesFrom: row?.votes_from > t ? row.votes_from : null };
}

export async function removeBegin(env, sess, id) {
  const tg = await target(env, sess, id);
  if (sess.role !== 'owner' && sess.memberId !== id) throw new HttpError(403, 'role_required', 'Only an owner can remove someone else. You can leave the team yourself.');
  keepsRules(sess, tg, null);
  return ceremony(env, 'member_remove:' + id, sess.accountId);
}

/** Removing someone, in one transaction: they are marked removed (only if the rules still hold), and then, only if that
 *  happened, their sessions, passkeys and alert devices are deleted, their seals on waiting holds are dropped, the
 *  tokens, guard keys and receipts keys they made are revoked, what those asked for is closed, and their open invites
 *  die. */
export async function removeFinish(env, sess, id, body) {
  await confirm(env, sess, body, 'member_remove:' + id);
  const tg = await target(env, sess, id);
  if (sess.role !== 'owner' && sess.memberId !== id) throw new HttpError(403, 'role_required');
  keepsRules(sess, tg, null);
  const t = now(), a = sess.accountId, db = env.DB;
  const gone = `EXISTS (SELECT 1 FROM members WHERE id = ?2 AND account_id = ?1 AND removed_at = ?3)`;
  const mine = (tbl) => `account_id = ?1 AND COALESCE(${tbl}member_id, ${tbl}account_id) = ?2`;
  const out = await db.batch([
    founderRow(db, a),
    db.prepare(`UPDATE members SET removed_at = ?3 WHERE id = ?2 AND account_id = ?1 AND removed_at IS NULL
      AND (SELECT COUNT(*) FROM members WHERE account_id = ?1 AND removed_at IS NULL AND role = 'owner' AND id != ?2) >= 1
      AND ${VOTERS('?1', '?2')} >= ${Q_NOW('?1', '?3')}`).bind(a, id, t),
    db.prepare(`DELETE FROM sessions WHERE ${mine('')} AND ${gone}`).bind(a, id, t),
    db.prepare(`DELETE FROM passkeys WHERE ${mine('')} AND ${gone}`).bind(a, id, t),
    db.prepare(`DELETE FROM push_subs WHERE ${mine('')} AND ${gone}`).bind(a, id, t),
    db.prepare(`DELETE FROM hold_votes WHERE account_id = ?1 AND member_id = ?2 AND hold_id IN (SELECT id FROM holds WHERE account_id = ?1 AND status IN ('pending','approved')) AND ${gone}`).bind(a, id, t),
    // what they asked for is closed (a pending hold of theirs, or an approved one not yet used)
    db.prepare(`UPDATE holds SET status = 'expired' WHERE account_id = ?1 AND requested_by = ?2 AND status IN ('pending','approved') AND ${gone}`).bind(a, id, t),
    db.prepare(`UPDATE tokens SET revoked = 1 WHERE ${mine('')} AND revoked = 0 AND ${gone}`).bind(a, id, t),
    db.prepare(`UPDATE guard_keys SET revoked = 1 WHERE ${mine('')} AND revoked = 0 AND ${gone}`).bind(a, id, t),
    db.prepare(`UPDATE api_keys SET revoked = 1 WHERE ${mine('')} AND revoked = 0 AND ${gone}`).bind(a, id, t),
    db.prepare(`UPDATE invites SET revoked_at = ?3 WHERE account_id = ?1 AND created_by = ?2 AND used_at IS NULL AND revoked_at IS NULL AND ${gone}`).bind(a, id, t),
  ]);
  if (!out[1].meta.changes) throw new HttpError(409, 'try_again', 'The team changed while you confirmed. Look again and retry.');
  const n = (i) => out[i].meta.changes;
  const revoked = { sessions: n(2), passkeys: n(3), devices: n(4), seals: n(5), holds: n(6), tokens: n(7), guardKeys: n(8), receiptsKeys: n(9), invites: n(10) };
  await audit(env, a, 'web', 'member_removed', { member: id, name: tg.m.name, role: tg.m.role, by: sess.memberId, ...revoked });
  // the rest of the team is told (the removed person's own devices are gone already)
  await alertTeam(env, a, sess.memberId);
  const self = id === sess.memberId;
  return self
    ? { body: { ok: true, left: true, revoked }, cookie: '__Host-leash=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' }
    : { ok: true, revoked };
}

// ---------------------------------------------------------------- the quorum (owner, passkey; cancel: approver, passkey)
function quorumParams(body) {
  const q = body.quorum;
  if (!Number.isInteger(q) || q < 1 || q > MAX_QUORUM) throw new HttpError(400, 'bad_quorum', `The quorum is 1 or ${MAX_QUORUM}.`);
  if (typeof body.selfApprove !== 'boolean') throw new HttpError(400, 'bad_selfApprove', 'selfApprove is true or false.');
  return { quorum: q, selfApprove: body.selfApprove };
}
async function enoughVoters(env, accountId, q) {
  const members = await membersOf(env, accountId);
  const voters = members.filter((m) => isVoter(m.role)).length;
  if (voters < q) throw new HttpError(409, 'not_enough_approvers', `${q} seals need at least ${q} owners or approvers. Invite an approver first.`);
}

export async function quorumBegin(env, sess, body) {
  const p = quorumParams(body);
  const e = effective(await accountRow(env, sess.accountId));
  if (!e.pending && e.quorum === p.quorum && e.selfApprove === p.selfApprove) throw new HttpError(409, 'same_quorum', 'That is the setting already. Nothing would change.');
  await enoughVoters(env, sess.accountId, p.quorum);
  return ceremony(env, 'team_quorum', sess.accountId, JSON.stringify(p));
}

/** what a request does: each part that tightens applies now; each part that loosens waits 24 hours (and replaces any
 *  change already waiting); a request that loosens nothing clears a waiting change */
export function plan(cur, want, t) {
  const loosens = want.quorum < cur.quorum || (want.selfApprove && !cur.selfApprove);
  return {
    now: { quorum: Math.max(cur.quorum, want.quorum), selfApprove: cur.selfApprove && want.selfApprove },
    pending: loosens ? { quorum: want.quorum, selfApprove: want.selfApprove, effectiveAt: t + LOWER_DELAY } : null,
  };
}

export async function quorumFinish(env, sess, body) {
  const ch = await confirm(env, sess, body, 'team_quorum');
  const want = JSON.parse(ch.name);
  const t = now(), a = await accountRow(env, sess.accountId);
  await enoughVoters(env, sess.accountId, want.quorum);
  const cur = effective(a, t);
  const pl = plan(cur, want, t);
  // compare-and-set on what was read: a concurrent change (say, another owner's raise) is never silently overwritten
  const r = await env.DB.prepare(`UPDATE accounts SET quorum = ?1, self_approve = ?2, quorum_pending = ?3, self_approve_pending = ?4, quorum_effective_at = ?5
    WHERE id = ?6 AND quorum IS ?7 AND self_approve IS ?8 AND quorum_pending IS ?9 AND self_approve_pending IS ?10 AND quorum_effective_at IS ?11 AND ${VOTERS('?6')} >= ?12`)
    .bind(pl.now.quorum, pl.now.selfApprove ? 1 : 0, pl.pending ? pl.pending.quorum : null, pl.pending ? (pl.pending.selfApprove ? 1 : 0) : null, pl.pending ? pl.pending.effectiveAt : null,
      sess.accountId, a.quorum, a.self_approve, a.quorum_pending, a.self_approve_pending, a.quorum_effective_at, want.quorum).run();
  if (!r.meta.changes) throw new HttpError(409, 'try_again', 'The team changed while you confirmed. Look again and retry.');
  await audit(env, sess.accountId, 'web', 'quorum_changed', { from: { quorum: cur.quorum, selfApprove: cur.selfApprove }, now: pl.now, pending: pl.pending, cancelled: cur.pending && !pl.pending ? cur.pending : undefined, by: sess.memberId });
  // lowering protection is never quiet: every member's devices are woken, and the alert offers to cancel it
  if (pl.pending) await alertTeam(env, sess.accountId, null, 'pushquorum:');
  return { ok: true, quorum: pl.now.quorum, selfApprove: pl.now.selfApprove, pending: pl.pending };
}

export async function cancelBegin(env, sess) {
  const e = effective(await accountRow(env, sess.accountId));
  if (!e.pending) throw new HttpError(404, 'no_pending', 'No change to the quorum is waiting.');
  return ceremony(env, 'team_quorum_cancel', sess.accountId);
}

export async function cancelFinish(env, sess, body) {
  await confirm(env, sess, body, 'team_quorum_cancel');
  const t = now(), a = await accountRow(env, sess.accountId);
  const e = effective(a, t);
  const r = await env.DB.prepare('UPDATE accounts SET quorum_pending = NULL, self_approve_pending = NULL, quorum_effective_at = NULL WHERE id = ? AND quorum_effective_at IS NOT NULL AND quorum_effective_at > ?').bind(sess.accountId, t).run();
  if (!r.meta.changes || !e.pending) throw new HttpError(409, 'no_pending', 'No change to the quorum is waiting (it may have taken effect already).');
  await audit(env, sess.accountId, 'web', 'quorum_change_cancelled', { pending: e.pending, by: sess.memberId });
  await alertTeam(env, sess.accountId, sess.memberId, 'pushquorum:');
  return { ok: true, quorum: e.quorum, selfApprove: e.selfApprove };
}

// ---------------------------------------------------------------- seals on held actions
const SEAL_READ = `SELECT h.id, h.status, h.expires_at, h.req_hash, h.requested_by, h.needs, h.method, h.host, h.rule, h.kind, h.context,
    a.receipts, a.frozen_at, a.quorum, a.self_approve, a.quorum_pending, a.self_approve_pending, a.quorum_effective_at,
    ${ROLE_OF('?3', 'h.account_id')} AS role,
    COALESCE((SELECT votes_from FROM members WHERE id = ?3 AND account_id = h.account_id), 0) AS votes_from,
    EXISTS (SELECT 1 FROM hold_votes v WHERE v.hold_id = h.id AND v.member_id = ?3) AS voted
  FROM holds h JOIN accounts a ON a.id = h.account_id WHERE h.id = ?1 AND h.account_id = ?2`;
// Freeze (src/brakes.js): nothing is sealed or approved while the account is frozen; freezing also drops the seals
// already on waiting holds, so nothing anyone said yes to before the freeze counts after it
const NOT_FROZEN = (A) => `NOT EXISTS (SELECT 1 FROM accounts WHERE id = ${A} AND frozen_at IS NOT NULL)`;
const frozen = () => new HttpError(423, 'account_frozen', 'This account is frozen. Unfreeze it with your passkey first; approvals wait until then.');

/** why this member cannot seal this hold now, or null */
function cannotSeal(row, memberId, t) {
  if (!row || row.status !== 'pending' || row.expires_at <= t) return new HttpError(404, 'not_found');
  if (row.frozen_at) return frozen();
  if (!isVoter(row.role)) return new HttpError(403, 'approver_required', 'Only owners and approvers can seal a held action. You can deny it.');
  if (row.votes_from > t) return new HttpError(403, 'seal_not_yet', `Two seals are required, so a new approver's seal counts 24 hours after they joined or were promoted: from ${new Date(row.votes_from).toISOString().slice(0, 16).replace('T', ' ')} UTC.`, { votes_from: row.votes_from });
  if (!effective(row, t).selfApprove && row.requested_by && row.requested_by === memberId) return new HttpError(403, 'own_request', 'This was asked for by a token or guard key you made, and your team requires someone else to seal it.');
  if (row.voted) return new HttpError(409, 'already_sealed', 'You have sealed this already. It needs another approver.');
  return null;
}
/** the seals a hold needs now: what it was made with, or more if the quorum was raised since */
const required = (row, t) => Math.max(row.needs || 1, effective(row, t).quorum);

/** approve, step 1: the checks before anyone is asked for a passkey; the challenge carries the hold's request hash */
export async function sealBegin(env, sess, holdId) {
  const t = now();
  const row = await env.DB.prepare(SEAL_READ).bind(holdId, sess.accountId, sess.memberId).first();
  const no = cannotSeal(row, sess.memberId, t);
  if (no) throw no;
  return ceremony(env, 'approve:' + holdId, sess.accountId, row.req_hash);
}

/** approve, step 2: one seal, in one transaction with the check that may approve the hold. Returns what happened and
 *  the audit detail; the caller writes the audit entry. */
export async function sealFinish(env, sess, holdId, body) {
  const ch = await takeChallenge(env, body.challengeId, 'approve:' + holdId);
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  // the passkey must be the signed-in member's own: the seal is theirs, whoever's browser this is
  await checkAssertion(env, body.credential, ch.challenge, sess);
  const passkey = (await sha256hex(String(body.credential.id))).slice(0, 16);
  const t = now(), m = sess.memberId, db = env.DB;
  const row = await db.prepare(SEAL_READ).bind(holdId, sess.accountId, m).first();
  const no = cannotSeal(row, m, t);
  if (no) throw no;
  // the seal is for the exact request the approver was shown when they began
  if (!ch.name || ch.name !== row.req_hash) throw new HttpError(409, 'hold_changed', 'This held action is not the one you began approving. Start again.');
  // the seal (if this member may still seal, the hold is still waiting for exactly this request, and the account is not
  // frozen), and then the approval (if the seals that still count reach the quorum), in one transaction: two approvers
  // sealing at the same moment cannot both approve, and one of them cannot be counted twice
  const [vote, flip] = await db.batch([
    db.prepare(`INSERT INTO hold_votes (hold_id, member_id, account_id, passkey, req_hash, at)
      SELECT h.id, ?3, h.account_id, ?4, h.req_hash, ?5 FROM holds h WHERE h.id = ?1 AND h.account_id = ?2 AND h.status = 'pending' AND h.expires_at > ?5 AND h.req_hash = ?6
        AND ${NOT_FROZEN('h.account_id')} AND ${ELIGIBLE('?3', 'h', '?5')}
      ON CONFLICT (hold_id, member_id) DO NOTHING`).bind(holdId, sess.accountId, m, passkey, t, ch.name),
    db.prepare(`UPDATE holds SET status = 'approved', decided_at = ?3, expires_at = ?3 + ?4
      WHERE id = ?1 AND account_id = ?2 AND status = 'pending' AND expires_at > ?3 AND ${NOT_FROZEN('?2')}
        AND (SELECT COUNT(*) FROM hold_votes v WHERE v.hold_id = holds.id AND v.req_hash = holds.req_hash AND ${ELIGIBLE('v.member_id', 'holds', '?3')}) >= MAX(holds.needs, ${Q_NOW('?2', '?3')})`)
      .bind(holdId, sess.accountId, t, GRANT_TTL),
  ]);
  const after = await db.prepare(`SELECT h.status, a.frozen_at, (SELECT json_group_array(json_object('member', v.member_id, 'passkey', v.passkey, 'at', v.at)) FROM hold_votes v
      WHERE v.hold_id = h.id AND v.req_hash = h.req_hash AND ${ELIGIBLE('v.member_id', 'h', '?2')}) AS votes FROM holds h JOIN accounts a ON a.id = h.account_id WHERE h.id = ?1`).bind(holdId, t).first();
  const votes = sealsOf(after?.votes);
  const need = required(row, t);
  if (!vote.meta.changes) {
    if (after?.frozen_at) throw frozen();
    if (votes.some((v) => v.member === m)) throw new HttpError(409, 'already_sealed', 'You have sealed this already. It needs another approver.');
    throw new HttpError(409, after?.status === 'approved' ? 'already_approved' : 'try_again', after?.status === 'approved' ? 'Another approver completed the seals just now.' : 'The held action changed while you confirmed. Look again.');
  }
  // final: this seal completed the quorum (the caller seals the approval); otherwise the hold may still have been approved
  // by another approver's seal that landed in between (status)
  return { final: flip.meta.changes === 1, status: after?.status || 'pending', row, passkey, votes, need, receipts: !!row.receipts };
}

/** after a seal that did not complete the quorum: wake the other members' devices (at most once a minute per account,
 *  shared with hold alerts) so a second approver looks */
export const nudge = (env, accountId, exceptMember) => alertTeam(env, accountId, exceptMember, 'pushhold:');

/** the seals from a VOTES_JSON column, oldest first */
export const sealsOf = (json) => JSON.parse(json || '[]').sort((a, b) => a.at - b.at || String(a.member).localeCompare(String(b.member)));

/** the hold card's seals: who sealed, with which passkey and when (only seals that still count) */
export const VOTES_JSON = (H, T) => `(SELECT json_group_array(json_object('member', v.member_id, 'name', COALESCE((SELECT name FROM members WHERE id = v.member_id AND account_id = ${H}.account_id), (SELECT name FROM accounts WHERE id = ${H}.account_id)), 'passkey', v.passkey, 'at', v.at))
  FROM hold_votes v WHERE v.hold_id = ${H}.id AND v.req_hash = ${H}.req_hash AND ${ELIGIBLE('v.member_id', H, T)})`;

/** team events of the last 15 minutes, for the alert a phone shows (from the audit log, like CLI sign-ins) */
export async function recentEvents(env, accountId) {
  const rows = (await env.DB.prepare("SELECT at, action, detail FROM audit WHERE account_id = ? AND action IN ('member_joined','member_role_changed','member_removed','quorum_changed','quorum_change_cancelled') AND at > ? ORDER BY seq DESC LIMIT 5").bind(accountId, now() - 15 * 60_000).all()).results;
  const out = [];
  const name = (d) => cleanText(d.name || '').slice(0, 60);
  const role = (r) => (ROLES.includes(r) ? r : null);
  for (const r of rows) {
    const d = JSON.parse(r.detail);
    if (r.action === 'member_joined') out.push({ kind: 'member_joined', at: r.at, name: name(d), role: role(d.role) });
    else if (r.action === 'member_role_changed') out.push({ kind: 'member_role_changed', at: r.at, name: name(d), from: role(d.from), to: role(d.to) });
    else if (r.action === 'member_removed') out.push({ kind: 'member_removed', at: r.at, name: name(d), role: role(d.role) });
    else if (r.action === 'quorum_changed' && d.pending) out.push({ kind: 'quorum_lowering', at: r.at, from: d.from, to: { quorum: d.pending.quorum, selfApprove: d.pending.selfApprove }, effective_at: d.pending.effectiveAt });
    else if (r.action === 'quorum_change_cancelled') out.push({ kind: 'quorum_lowering_cancelled', at: r.at });
  }
  return out;
}
