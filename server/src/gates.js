// Deploy Gate: a GitHub Actions job waits for a passkey approval before it goes on.
//
// The flow. The owner makes a gate in the app (with a passkey): which repository, workflows, refs, environments and events
// it accepts. A workflow step (action/deploy-gate) asks GitHub for an OIDC token whose audience is this gate, and sends it
// here. The token is verified (oidc.js); what it says about the run (repository, workflow, ref, commit, run, attempt,
// environment, actor) is checked against the gate, then becomes a hold of kind "deploy" on the same holds table, alerts,
// approve and deny routes and public receipts as every other approval. The step polls with a secret (gps_) that reads that
// one hold. When the owner approves with a passkey, the next poll spends the approval (once) and the job goes on.
//
// Phase 2, "no approval, no key": a gate may name a vaulted key and a policy. On approval the poll also returns a fresh
// Counterseal token (lsh_) for that key that lasts 15 minutes, so the deploy key does not exist for the job before
// approval, and the real key never leaves the vault.
//
// What a gate is and is not: a passkey-approved pause in a job that asks for it. A person who can edit the workflow file can
// remove the step, so protect the workflow file (branch protection, CODEOWNERS), or use phase 2, where the job has nothing
// to deploy with until a human approves.
//
// Workers Free: waiting writes nothing to D1 (the poll's rate limit is in memory, the long poll is one read an iteration),
// GitHub's key set is fetched at most every 10 minutes per isolate, and a request that is refused writes nothing at all.
import { HttpError, json, b64u, rand, randomId, sha256hex, now, str, cleanText } from './util.js';
import { audit } from './audit.js';
import { newChallenge, takeChallenge, checkAssertion, appOrigin, hosts, rp } from './auth.js';
import { limit, readLimit, allow } from './ratelimit.js';
import { notify } from './push.js';
import { PENDING_PER_ACCOUNT, MAX_LIVE_TOKENS } from './broker.js';
import { markSeen } from './admin.js';
import { normalisePolicy } from './policy.js';
import { d1Seen } from './agentkeys.js';
import { int } from './ledger.js';
import { verifyGithubToken, SKEW } from './oidc.js';
import { GATE_AGENT, GATE_HOST, GATE_METHOD, gateHash, gateContext, factsOf, previewOf } from './gatefacts.js';
import { WAIT_MAX, WAIT_STEP, WAIT_READS, POLLS_PER_MINUTE } from './approvals.js';
import { BRAND } from './brand.js';
import * as Team from './team.js';
import * as Channels from './channels.js';

export const MAX_GATES = 20, HOLDS_PER_HOUR = 30, PENDING_PER_GATE = 10, TOKEN_TTL = 15 * 60_000, GRANT_WINDOW = 11 * 60_000;
export const DEFAULT_MINUTES = 15, MAX_MINUTES = 60, MAX_SUMMARY = 120;
/** the workflow events a gate may accept. pull_request, pull_request_target and workflow_run are never offered: they run in
 *  the context of code from a fork or from another workflow. */
export const EVENTS = ['push', 'workflow_dispatch', 'release', 'deployment', 'merge_group', 'schedule', 'repository_dispatch'];
export const DEFAULT_EVENTS = ['push', 'workflow_dispatch', 'release', 'deployment', 'merge_group'];

const GATE_ID = /^gate_[0-9a-f]{24}$/;
const LABEL = /^[\p{L}\p{N} ._:/()-]+$/u;
const OWNER_REPO = /^[A-Za-z0-9-]{1,39}\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const WORKFLOW = /^\.github\/workflows\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.ya?ml$/;
// an exact ref, or a prefix with one trailing * (refs/heads/release/*); "every branch" is not expressible on purpose
const REF_PATTERN = /^(?!.*\/\/)(?!.*\.\.)refs\/(?:heads|tags)\/[A-Za-z0-9._/-]{1,150}\*?$/;
const ENVIRONMENT = /^[A-Za-z0-9][A-Za-z0-9 ._:/()-]{0,99}$/;
const POLL = /^Bearer (gps_[A-Za-z0-9_-]{43})$/;
const OIDC_BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

/** the audience a gate's tokens must carry: this service's product host and the gate, so a token made for one gate (or
 *  for another service) is no use at any other */
export const audienceFor = (env, gateId) => `${hosts(env)[0].origin}/gate/${gateId}`;

/** Freeze (src/brakes.js): while the owner has the account frozen nothing new is asked, a wait ends at once with this
 *  answer, and no approval is spent. Same code and status as every other frozen answer (423 account_frozen). */
const frozen = () => new HttpError(423, 'account_frozen', `This ${BRAND.name} account is frozen: every agent token, coding-agent approval and deploy gate is stopped. Its owner can unfreeze it with a passkey in the app.`);

const sleep = (env, ms) => (env.__sleep ? env.__sleep(ms) : globalThis.scheduler?.wait ? globalThis.scheduler.wait(ms) : new Promise((ok) => setTimeout(ok, ms)));
const statusOf = (h, t = now()) => (['pending', 'approved'].includes(h.status) && h.expires_at <= t ? 'expired' : h.status);
const tokenIdOf = (gateId) => 'd:' + gateId;

// ---------------------------------------------------------------- gates (managed from the app)
function list(v, name, re, { min = 0, max = 10 } = {}) {
  if (v === undefined || v === null) { if (min) throw new HttpError(400, 'bad_' + name, `${name} needs at least ${min}.`); return []; }
  if (!Array.isArray(v) || v.length < min || v.length > max) throw new HttpError(400, 'bad_' + name, `${name} is a list of ${min} to ${max}.`);
  for (const x of v) if (typeof x !== 'string' || !re.test(x)) throw new HttpError(400, 'bad_' + name, `${name} has an entry that is not in the expected form.`);
  return [...new Set(v)];
}

/** a fresh passkey ceremony makes a gate: a gate decides which repository may ask you for deploys (and, in phase 2, which
 *  key a run gets), so a stolen session or a command line sign-in cannot add one. Revoking one only tightens, so any
 *  signed-in session may. */
export async function createBegin(env, sess) {
  const { id, challenge } = await newChallenge(env, 'gate', sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}

const FIELDS = new Set(['challengeId', 'credential', 'label', 'repository', 'workflows', 'refs', 'environments', 'events', 'publishRepo', 'credentialId', 'policy']);
export async function createFinish(env, sess, body) {
  if (sess.kind !== 'web') throw new HttpError(403, 'passkey_required');
  for (const k of Object.keys(body)) if (!FIELDS.has(k)) throw new HttpError(400, 'bad_field', `Unknown field. Send only: ${[...FIELDS].join(', ')}.`);
  // read and check everything first, so a wrong form costs the person nothing but the form (the challenge is single use)
  const label = str(body.label, 'label', { max: 60, re: LABEL });
  const repository = str(body.repository, 'repository', { max: 140, re: OWNER_REPO });
  const workflows = list(body.workflows, 'workflows', WORKFLOW, { min: 1, max: 5 });
  const refs = list(body.refs, 'refs', REF_PATTERN, { min: 1, max: 10 });
  const environments = list(body.environments, 'environments', ENVIRONMENT, { max: 10 });
  const events = body.events === undefined ? DEFAULT_EVENTS : list(body.events, 'events', new RegExp(`^(?:${EVENTS.join('|')})$`), { min: 1, max: EVENTS.length });
  if (body.publishRepo !== undefined && typeof body.publishRepo !== 'boolean') throw new HttpError(400, 'bad_publishRepo', 'publishRepo is true or false.');
  if (body.policy !== undefined && body.credentialId === undefined) throw new HttpError(400, 'policy_needs_credential', 'A policy is for the key a gate hands out; name the key with credentialId.');
  let credential = null, policy = null;
  if (body.credentialId !== undefined) {
    credential = await env.DB.prepare('SELECT id, provider, label FROM credentials WHERE id = ? AND account_id = ?').bind(str(body.credentialId, 'credentialId', { max: 40 }), sess.accountId).first();
    if (!credential) throw new HttpError(404, 'not_found');
    policy = normalisePolicy(body.policy, true); // the passkey ceremony below is what allows pre-approved irreversible operations
    // Pre-approving irreversible calls (or money caps) is one person approving in advance: an owner or approver, and only
    // while one seal is enough, as for a token (src/broker.js mintToken).
    if (policy.unattendedIrreversible.length || policy.money) {
      Team.requireLevel(sess, Team.LEVEL.approver);
      const q = Team.effective(await env.DB.prepare('SELECT quorum, self_approve, quorum_pending, self_approve_pending, quorum_effective_at FROM accounts WHERE id = ?').bind(sess.accountId).first());
      if (!Team.oneSealEnough(q)) throw new HttpError(409, 'quorum_blocks_preapproval', `Your team requires ${q.quorum > 1 ? `${q.quorum} different approvers` : 'someone other than the maker'} for irreversible calls, so no one can pre-approve them or set money caps alone.`);
    }
  }
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM gates WHERE account_id = ? AND revoked = 0').bind(sess.accountId).first();
  if (n.n >= MAX_GATES) throw new HttpError(409, 'too_many_gates', `Up to ${MAX_GATES} active gates. Revoke one first.`);

  const ch = await takeChallenge(env, body.challengeId, 'gate');
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess);
  const id = 'gate_' + randomId(), t = now();
  await env.DB.prepare('INSERT INTO gates (id, account_id, label, repository, workflows, refs, environments, events, publish_repo, credential_id, policy, created_at, member_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(id, sess.accountId, label, repository, JSON.stringify(workflows), JSON.stringify(refs), environments.length ? JSON.stringify(environments) : null, JSON.stringify(events), body.publishRepo ? 1 : 0, credential ? credential.id : null, policy ? JSON.stringify(policy) : null, t, sess.memberId || null).run();
  await audit(env, sess.accountId, 'web', 'gate_created', { id, label, repository, workflows, refs, environments, events, publish_repo: body.publishRepo ? 1 : 0, ...(credential ? { credential: credential.id, provider: credential.provider, preapproved: policy.unattendedIrreversible.length } : {}) });
  return gateView({ id, label, repository, workflows: JSON.stringify(workflows), refs: JSON.stringify(refs), environments: environments.length ? JSON.stringify(environments) : null, events: JSON.stringify(events), publish_repo: body.publishRepo ? 1 : 0, created_at: t, revoked: 0, member_id: sess.memberId || sess.accountId, policy: policy ? JSON.stringify(policy) : null, credential_id: credential?.id ?? null, credential_provider: credential?.provider ?? null, credential_label: credential?.label ?? null });
}

const parse = (s, fallback = null) => { try { return s ? JSON.parse(s) : fallback; } catch { return fallback; } };
function gateView(g) {
  const policy = parse(g.policy);
  return {
    id: g.id, label: g.label, repository: g.repository, workflows: parse(g.workflows, []), refs: parse(g.refs, []), environments: parse(g.environments), events: parse(g.events, []),
    bound: g.repository_id ? { repository_id: g.repository_id, repository_owner_id: g.repository_owner_id, at: g.bound_at } : null,
    publish_repo: !!g.publish_repo,
    credential: g.credential_id ? { id: g.credential_id, provider: g.credential_provider || null, label: g.credential_label || null, preapproved: policy ? policy.unattendedIrreversible.length : 0 } : null,
    created_at: g.created_at, last_used: g.last_used ?? null, revoked: g.revoked,
    // who made it (on a team the app shows "made by"; with self-approval off they cannot seal what it asks for)
    member_id: g.member_id || g.account_id,
  };
}

export async function listGates(env, sess) {
  const r = await env.DB.prepare('SELECT g.*, c.provider AS credential_provider, c.label AS credential_label FROM gates g LEFT JOIN credentials c ON c.id = g.credential_id AND c.account_id = g.account_id WHERE g.account_id = ? ORDER BY g.created_at DESC LIMIT 100').bind(sess.accountId).all();
  return { gates: r.results.map(gateView), server: hosts(env)[0].origin };
}

/** revoking only tightens, so any signed-in session of its maker or an owner may (anyone else who sees trouble freezes the
 *  account, src/brakes.js). The gate's open holds are closed, and the tokens it handed out stop. */
export async function revoke(env, sess, id) {
  // the holds and tokens go only once the gate is revoked (by its maker or an owner), as for a guard key (approvals.js)
  const gone = 'EXISTS (SELECT 1 FROM gates WHERE id = ?2 AND account_id = ?1 AND revoked = 1)';
  const [g, h, tk] = await env.DB.batch([
    env.DB.prepare(`UPDATE gates SET revoked = 1 WHERE id = ? AND account_id = ? AND revoked = 0 ${Team.MAKER_OR_OWNER}`).bind(id, sess.accountId, ...Team.makerOrOwner(sess)),
    env.DB.prepare(`UPDATE holds SET status = 'expired' WHERE account_id = ?1 AND token_id = ?3 AND status IN ('pending','approved') AND ${gone}`).bind(sess.accountId, id, tokenIdOf(id)),
    env.DB.prepare(`UPDATE tokens SET revoked = 1 WHERE account_id = ?1 AND revoked = 0 AND id IN (SELECT token_id FROM gate_runs WHERE gate_id = ?2 AND account_id = ?1) AND ${gone}`).bind(sess.accountId, id),
  ]);
  if (!g.meta.changes) throw await Team.notRevoked(env, sess, 'gates', id);
  await audit(env, sess.accountId, sess.kind, 'gate_revoked', { id, closed: h.meta.changes, tokens: tk.meta.changes });
  return { ok: true, closed: h.meta.changes, tokens: tk.meta.changes };
}

// ---------------------------------------------------------------- the run asks: POST /v1/gate/request (Bearer: the OIDC token)
const refAllowed = (refs, ref) => refs.some((p) => (p.endsWith('*') ? ref.startsWith(p.slice(0, -1)) : ref === p));
const refuse = (reason, message) => new HttpError(403, 'gate_refused', message, { reason });

/** does this verified run fit what the gate accepts? The repository is checked first and says nothing about what the gate
 *  is bound to, so a caller from another repository learns only that it is not this gate's. */
function checkRun(g, c) {
  const bound = !!g.repository_id;
  const sameRepo = bound ? c.repository_id === g.repository_id && c.repository_owner_id === g.repository_owner_id : c.repository.toLowerCase() === g.repository.toLowerCase();
  if (!sameRepo) throw refuse('repository', 'This run is not in the repository this gate belongs to.');
  const workflows = parse(g.workflows, []);
  for (const [which, w] of [['workflow', c.workflow], ['job workflow', c.job_workflow]]) {
    if (w.repository.toLowerCase() !== c.repository.toLowerCase() || !workflows.includes(w.path)) throw refuse('workflow', `The ${which} ${w.path} is not one this gate accepts. Reusable workflows from other repositories are not supported.`);
  }
  if (!refAllowed(parse(g.refs, []), c.ref)) throw refuse('ref', `The ref ${c.ref} is not on this gate's list.`);
  const envs = parse(g.environments);
  if (envs && !envs.includes(c.environment)) throw refuse('environment', c.environment ? `The environment ${c.environment} is not one this gate accepts.` : 'This gate needs the job to run in one of its environments.');
  if (!parse(g.events, []).includes(c.event_name)) throw refuse('event', `The ${c.event_name} event is not one this gate accepts.`);
}

const REQUEST_FIELDS = new Set(['gate', 'summary', 'timeout_minutes']);
export async function request(c) {
  const env = c.env, t = now();
  const m = OIDC_BEARER.exec(c.request.headers.get('authorization') || '');
  if (!m) throw new HttpError(401, 'oidc_required', "Send GitHub's OIDC token as: Authorization: Bearer <token>. The Counterseal Deploy Gate action does this for you; the job needs permissions: id-token: write.");
  const b = c.body;
  for (const k of Object.keys(b)) if (!REQUEST_FIELDS.has(k)) throw new HttpError(400, 'bad_field', `Unknown field. Send only: ${[...REQUEST_FIELDS].join(', ')}.`);
  const gateId = str(b.gate, 'gate', { max: 29, re: GATE_ID });
  let summary = null;
  if (b.summary !== undefined && b.summary !== null) {
    if (typeof b.summary !== 'string' || b.summary.length > MAX_SUMMARY * 4) throw new HttpError(400, 'bad_summary', `summary is text of ${MAX_SUMMARY} characters at most.`);
    summary = cleanText(b.summary).slice(0, MAX_SUMMARY) || null;
  }
  let minutes = DEFAULT_MINUTES;
  if (b.timeout_minutes !== undefined) {
    if (!Number.isInteger(b.timeout_minutes) || b.timeout_minutes < 1 || b.timeout_minutes > MAX_MINUTES) throw new HttpError(400, 'bad_timeout', `timeout_minutes is a whole number from 1 to ${MAX_MINUTES}.`);
    minutes = b.timeout_minutes;
  }
  // 1. GitHub's signature and the token's own claims, before anything touches the database (the audience names this gate)
  const claims = await verifyGithubToken(env, m[1], { audience: audienceFor(env, gateId), now: t });
  // 2. the gate, and whether this run is the kind it accepts. A refused run writes nothing and alerts no one.
  const g = await env.DB.prepare('SELECT g.*, a.receipts AS receipts_on, a.frozen_at, a.quorum, a.self_approve, a.quorum_pending, a.self_approve_pending, a.quorum_effective_at FROM gates g JOIN accounts a ON a.id = g.account_id WHERE g.id = ?').bind(gateId).first();
  if (!g || g.revoked) throw new HttpError(404, 'gate_not_found', 'There is no such gate, or it was revoked.');
  checkRun(g, claims);
  // Freeze: nothing new is asked, held or alerted, and the token is not spent. (After the run is known to be this gate's:
  // a caller from another repository still learns nothing about the account.)
  if (g.frozen_at) throw frozen();
  // 3. the token is spent: it can ask once (a replay of a token that was used, or leaked, finds nothing to ask with)
  if (await d1Seen(env.DB)('oidc:' + claims.jti, (claims.exp + SKEW) * 1000)) throw new HttpError(401, 'oidc_replayed', 'This token was already used. The action asks GitHub for a fresh one on every try.');

  const bind = !g.repository_id;
  const facts = { gate: g.id, repository: claims.repository, repository_id: claims.repository_id, owner_id: claims.repository_owner_id, ref: claims.ref, sha: claims.sha, workflow_ref: claims.workflow_ref, job_workflow_ref: claims.job_workflow_ref, environment: claims.environment, run_id: claims.run_id, run_attempt: claims.run_attempt, check_run_id: claims.check_run_id };
  const hash = await gateHash(facts);
  const tokenId = tokenIdOf(g.id);
  const url = async (id) => `${await appOrigin(env, g.account_id)}/app#hold=${id}`;
  const rule = bind ? 'gate.bind' : 'gate.deploy';
  let hold = await env.DB.prepare("SELECT id, status, expires_at FROM holds WHERE token_id = ? AND req_hash = ? AND status IN ('approved','pending') AND expires_at > ? ORDER BY status = 'approved' DESC, created_at DESC LIMIT 1").bind(tokenId, hash, t).first();
  let created = false;
  if (!hold) {
    // asking is cheap for a workflow and costly for the human: 10 waiting per gate and 100 per account (a refusal writes
    // nothing), and 30 new holds an hour per gate
    const n = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM holds WHERE token_id = ?1 AND status = 'pending' AND expires_at > ?3) AS mine, (SELECT COUNT(*) FROM holds WHERE account_id = ?2 AND status = 'pending' AND expires_at > ?3) AS acct").bind(tokenId, g.account_id, t).first();
    if (n.mine >= PENDING_PER_GATE || n.acct >= PENDING_PER_ACCOUNT) {
      throw new HttpError(429, 'too_many_holds', `${n.mine >= PENDING_PER_GATE ? `${n.mine} runs of this gate are` : `${n.acct} requests are`} already waiting for approval, so this one was not held or sent. Review the waiting ones first.`);
    }
    await limit(env.DB, 'gate:' + g.id, HOLDS_PER_HOUR, 3600_000, t);
    const id = randomId(), expiresAt = t + minutes * 60_000;
    // two-person seal: the seals this hold needs now, and who "asked" (the gate's maker: with self-approval off they cannot
    // be one of the approvers, as for a token or a guard key)
    const needs = Team.effective(g, t).quorum, requestedBy = Team.memberOf(g);
    const context = gateContext(g, claims, { bind, publish: g.publish_repo, summary });
    const f = factsOf(context);
    const pv = previewOf(f);
    const why = bind
      ? `First run of this gate: approving also binds it to ${claims.repository} (GitHub id ${claims.repository_id}). The job is paused until you decide.`
      : "A GitHub Actions job is paused until you approve. The repository, workflow, commit and run are from the token GitHub signed for the job.";
    const path = `${claims.repository}@${claims.sha.slice(0, 7)} ${claims.environment || claims.ref}`.slice(0, 200);
    // one statement: two runs asking at the same moment make one hold, not two
    const ins = await env.DB.prepare(`INSERT INTO holds (id, account_id, token_id, req_hash, method, host, path, rule, why, created_at, expires_at, preview, kind, agent, context, needs, requested_by)
      SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'deploy', ?13, ?14, ?15, ?16 WHERE NOT EXISTS (SELECT 1 FROM holds WHERE token_id = ?3 AND req_hash = ?4 AND status = 'pending' AND expires_at > ?10)`)
      .bind(id, g.account_id, tokenId, hash, GATE_METHOD, GATE_HOST, path, rule, why, t, expiresAt, pv, GATE_AGENT, context, needs, requestedBy).run();
    if (ins.meta.changes) {
      hold = { id, expires_at: expiresAt, status: 'pending' };
      created = true;
      await audit(env, g.account_id, 'gate:' + g.id, 'hold', {
        method: GATE_METHOD, host: GATE_HOST, rule, hold: id, kind: 'deploy', agent: GATE_AGENT, gate: g.id,
        repository: claims.repository, sha: claims.sha, ref: claims.ref, run_id: claims.run_id, run_attempt: claims.run_attempt, environment: claims.environment,
        preview_sha256: await sha256hex(pv), ...(g.publish_repo ? { public_repo: claims.repository } : {}),
      }, { receipts: !!g.receipts_on });
      const seen = markSeen(env, g.account_id);
      if (seen) c.waitUntil(seen);
      // wake the owner's devices after responding; the push carries nothing. One alert a minute per account for held
      // requests (the same bucket as held API calls and commands).
      c.waitUntil((async () => {
        if (await allow(env.DB, 'pushhold:' + g.account_id, 1, 60_000, now())) {
          await notify(env, g.account_id, env.__pushFetch || fetch);
          await Channels.holdAlert(env, g.account_id, { who: g.label, rule, needs, holdId: id });
        }
      })());
    } else {
      hold = await env.DB.prepare("SELECT id, status, expires_at FROM holds WHERE token_id = ? AND req_hash = ? AND status IN ('approved','pending') ORDER BY created_at DESC LIMIT 1").bind(tokenId, hash).first();
      if (!hold) throw new HttpError(409, 'try_again', 'Another request for this run was decided just now. Ask again.');
    }
  }
  // the secret this run polls with: one per request, stored hashed, valid for this hold (and ten minutes after approval)
  const poll = 'gps_' + b64u(rand(32));
  await env.DB.prepare('INSERT INTO gate_polls (hash, account_id, gate_id, hold_id, expires_at) VALUES (?, ?, ?, ?, ?)').bind(await sha256hex(poll), g.account_id, g.id, hold.id, hold.expires_at + GRANT_WINDOW).run();
  return json({ id: hold.id, status: hold.status, poll, approve_url: await url(hold.id), expires_at: hold.expires_at, rule, created }, 202);
}

// ---------------------------------------------------------------- the run waits: GET /v1/gate/status/:id (Bearer gps_)
/** the poll secret in the header, hashed; no database yet */
export async function pollAuth(request) {
  const m = POLL.exec(request.headers.get('authorization') || '');
  if (!m) throw new HttpError(401, 'poll_secret_required', 'Send the poll secret you were given as: Authorization: Bearer gps_...');
  return { hash: await sha256hex(m[1]) };
}

const readHold = (env, p, id, t) => env.DB.prepare("SELECT h.id, h.status, h.deny_reason, h.expires_at, h.req_hash, h.context, h.rule, h.account_id, p.gate_id, a.frozen_at FROM gate_polls p JOIN holds h ON h.id = p.hold_id JOIN accounts a ON a.id = h.account_id WHERE p.hash = ? AND p.hold_id = ? AND p.expires_at > ? AND h.kind = 'deploy'").bind(p.hash, id, t).first();

/** GET /v1/gate/status/:id?wait=N: the decision, waiting up to N seconds for one (no D1 writes while it waits). The poll
 *  that finds the hold approved spends it: that approval is that run's, once. A freeze ends the wait with 423 at the next
 *  read (every 2 seconds), and an approval is never spent while the account is frozen. */
export async function status(c, id) {
  const env = c.env, t0 = now();
  const w = c.url.searchParams.get('wait');
  const wait = w === null ? 0 : int(w, 'wait', WAIT_MAX);
  await readLimit(env, 'gpoll:' + c.poll.hash.slice(0, 24), POLLS_PER_MINUTE, t0);
  let h = await readHold(env, c.poll, id, t0);
  if (!h) throw new HttpError(404, 'not_found');
  if (h.frozen_at) throw frozen();
  const deadline = t0 + wait * 1000;
  for (let i = 0; i < WAIT_READS && statusOf(h) === 'pending' && now() < deadline; i++) {
    await sleep(env, Math.min(WAIT_STEP, deadline - now()));
    h = await readHold(env, c.poll, id, now());
    if (!h) throw new HttpError(404, 'not_found');
    if (h.frozen_at) throw frozen();
  }
  const st = statusOf(h);
  if (st === 'approved') return pass(c, h);
  return { id: h.id, status: st, deny_reason: st === 'denied' ? h.deny_reason || null : null, expires_at: h.expires_at };
}

/** spend an approval: one atomic update (still approved, same hash, in time, and the gate still bound to this repository),
 *  then bind the gate on its first approved run and, for a gate with a key, mint the run's short-lived token */
async function pass(c, h) {
  const env = c.env, t = now();
  const f = factsOf(h.context);
  // the hold must still say what was approved: its stored facts hash to the hash the approval is bound to
  if (!f || (await gateHash(f)) !== h.req_hash) throw new HttpError(409, 'hash_mismatch', 'This approval is not for the run it names. Ask again.');
  const g = await env.DB.prepare('SELECT g.*, a.receipts AS receipts_on, a.frozen_at FROM gates g JOIN accounts a ON a.id = g.account_id WHERE g.id = ? AND g.account_id = ?').bind(h.gate_id, h.account_id).first();
  if (!g || g.revoked) throw new HttpError(409, 'gate_revoked', 'This gate was revoked.');
  if (g.frozen_at) throw frozen();
  // phase 2: check the key can be handed out before the approval is spent
  let cred = null;
  if (g.credential_id) {
    cred = await env.DB.prepare('SELECT id, provider FROM credentials WHERE id = ? AND account_id = ?').bind(g.credential_id, g.account_id).first();
    if (!cred) throw new HttpError(409, 'credential_gone', 'The key this gate hands out is no longer in the vault.');
    const live = await env.DB.prepare('SELECT COUNT(*) AS n FROM tokens WHERE account_id = ? AND revoked = 0 AND expires_at > ?').bind(g.account_id, t).first();
    if (live.n >= MAX_LIVE_TOKENS) throw new HttpError(409, 'too_many_tokens', `Up to ${MAX_LIVE_TOKENS} live tokens. Revoke some first; the approval is still good.`);
  }
  // (a freeze between the read above and this statement also stops it: the account is checked in the same statement)
  const u = await env.DB.prepare(`UPDATE holds SET status = 'used' WHERE id = ?1 AND token_id = ?2 AND req_hash = ?3 AND status = 'approved' AND expires_at > ?4 AND kind = 'deploy'
      AND EXISTS (SELECT 1 FROM gates x WHERE x.id = ?5 AND x.revoked = 0 AND (x.repository_id IS NULL OR (x.repository_id = ?6 AND x.repository_owner_id = ?7)))
      AND NOT EXISTS (SELECT 1 FROM accounts WHERE id = ?8 AND frozen_at IS NOT NULL) RETURNING id`)
    .bind(h.id, tokenIdOf(g.id), h.req_hash, t, g.id, f.repository_id, f.owner_id, g.account_id).first();
  if (!u) {
    const again = await readHold(env, c.poll, h.id, t);
    if (again && again.frozen_at) throw frozen();
    const st = again ? statusOf(again, t) : 'expired';
    if (st === 'used' || st === 'expired') return { id: h.id, status: st, deny_reason: null, expires_at: h.expires_at };
    throw new HttpError(409, 'gate_bound_elsewhere', 'This gate was bound to a different repository while the job waited. Ask again.');
  }
  // the first approved run binds the gate to GitHub's ids for the repository; later runs must match them
  await env.DB.prepare(`UPDATE gates SET last_used = ?1, repository_id = COALESCE(repository_id, ?2), repository_owner_id = COALESCE(repository_owner_id, ?3),
      repository = CASE WHEN repository_id IS NULL THEN ?4 ELSE repository END, bound_at = CASE WHEN repository_id IS NULL THEN ?1 ELSE bound_at END WHERE id = ?5`)
    .bind(t, f.repository_id, f.owner_id, f.repository, g.id).run();
  let token = null, tokenId = null;
  if (cred) {
    token = 'lsh_' + b64u(rand(32));
    tokenId = randomId();
    const policy = JSON.parse(g.policy);
    await env.DB.batch([
      env.DB.prepare('INSERT INTO tokens (id, account_id, credential_id, hash, label, policy, minted_by, expires_at, created_at, agent_key_id, session_id, member_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        // member_id: the gate's maker, so a pre-approval in its policy pauses when the team needs two seals or its maker can no longer seal
        .bind(tokenId, g.account_id, cred.id, await sha256hex(token), `gate: ${g.label}`.slice(0, 60), JSON.stringify(policy), 'gate', t + TOKEN_TTL, t, null, null, g.member_id || null),
      env.DB.prepare('INSERT INTO gate_runs (token_id, account_id, gate_id, hold_id, created_at) VALUES (?, ?, ?, ?, ?)').bind(tokenId, g.account_id, g.id, h.id, t),
    ]);
  }
  await audit(env, g.account_id, 'gate:' + g.id, 'gate_passed', {
    method: GATE_METHOD, host: GATE_HOST, rule: h.rule, hold: h.id, kind: 'deploy', gate: g.id, repository: f.repository, sha: f.sha, run_id: f.run_id, run_attempt: f.run_attempt,
    ...(tokenId ? { token: tokenId, credential: cred.id, provider: cred.provider } : {}), ...(f.publish ? { public_repo: f.repository } : {}),
  }, { receipts: !!g.receipts_on });
  return {
    id: h.id, status: 'approved', deny_reason: null, expires_at: h.expires_at,
    ...(token ? { token, provider: cred.provider, base_url: `${rp(env).origin}/p/${cred.provider}`, token_expires_at: t + TOKEN_TTL } : {}),
  };
}

/** POST /v1/gate/cancel/:id: the job gave up (timeout or cancelled), so nobody should be asked to approve it any more */
export async function cancel(c, id) {
  const env = c.env, t = now();
  const r = await env.DB.prepare("UPDATE holds SET status = 'expired' WHERE id = ?1 AND kind = 'deploy' AND status IN ('pending','approved') AND EXISTS (SELECT 1 FROM gate_polls p WHERE p.hash = ?2 AND p.hold_id = ?1 AND p.expires_at > ?3) RETURNING account_id, rule")
    .bind(id, c.poll.hash, t).first();
  if (!r) return { ok: true, cancelled: false };
  const g = await env.DB.prepare('SELECT gate_id FROM gate_polls WHERE hash = ?').bind(c.poll.hash).first();
  await audit(env, r.account_id, 'gate:' + (g?.gate_id || ''), 'gate_cancelled', { hold: id, gate: g?.gate_id || null });
  return { ok: true, cancelled: true };
}
