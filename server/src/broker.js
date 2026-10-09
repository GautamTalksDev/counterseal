// Credentials, proxy tokens, the proxy, and holds.
import { HttpError, json, b64u, rand, randomId, sha256hex, now, str, readBody, cleanText } from './util.js';
import { mapOf } from './approvals.js';
import { seal, open } from './vault.js';
import { summarize, PROVIDERS, MAP_VERSION } from './providers.js';
import { normalisePolicy, decide } from './policy.js';
import { audit } from './audit.js';
import { newChallenge, takeChallenge, checkAssertion, rp, hosts, appOrigin, sessionId } from './auth.js';
import { limit, allow } from './ratelimit.js';
import { notify } from './push.js';
import { verifyAgentSignature, d1Seen, ownActive } from './agentkeys.js';
import { BRAND } from './brand.js';
import { markSeen } from './admin.js';

const HOLD_TTL = 30 * 60_000, GRANT_TTL = 10 * 60_000, MAX_BODY = 1_048_576, MAX_RESP = 10 * 1_048_576;
export const PENDING_PER_TOKEN = 20, PENDING_PER_ACCOUNT = 100, MAX_CREDENTIALS = 50, MAX_LIVE_TOKENS = 200, LIST_TOKENS = 500;

// ---------------------------------------------------------------- credentials
export async function addCredential(env, sess, body) {
  const provider = str(body.provider, 'provider', { max: 20 });
  const P = PROVIDERS[provider];
  if (!P) throw new HttpError(400, 'bad_provider');
  const label = str(body.label ?? P.name, 'label', { max: 60, re: /^[\p{L}\p{N} ._:/()-]+$/u });
  const secret = str(body.secret, 'secret', { min: 8, max: 4096, re: /^[\x21-\x7e]+$/ });
  if (P.keyHint && !P.keyHint.test(secret)) throw new HttpError(400, 'bad_secret', `That does not look like a ${P.name} key.`);
  // every row an account can create has a ceiling (OWASP API4): the D1 budget is shared by everyone
  const have = await env.DB.prepare('SELECT COUNT(*) AS n FROM credentials WHERE account_id = ?').bind(sess.accountId).first();
  if (have.n >= MAX_CREDENTIALS) throw new HttpError(409, 'too_many_credentials', `Up to ${MAX_CREDENTIALS} keys in a vault. Delete one first.`);
  const id = randomId();
  const sealed = await seal(env, { id, accountId: sess.accountId, provider }, secret);
  await env.DB.prepare('INSERT INTO credentials (id, account_id, provider, label, hint, ct, iv, wrapped_dek, dek_iv, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(id, sess.accountId, provider, label, secret.slice(-4), sealed.ct, sealed.iv, sealed.wrapped_dek, sealed.dek_iv, now()).run();
  await audit(env, sess.accountId, sess.kind, 'add_credential', { id, provider, label });
  return { id, provider, label, hint: secret.slice(-4) };
}

export async function listCredentials(env, sess) {
  const r = await env.DB.prepare('SELECT id, provider, label, hint, created_at, last_used FROM credentials WHERE account_id = ? ORDER BY created_at DESC').bind(sess.accountId).all();
  return { credentials: r.results };
}

export async function deleteCredential(env, sess, id) {
  const r = await env.DB.prepare('DELETE FROM credentials WHERE id = ? AND account_id = ?').bind(id, sess.accountId).run();
  if (!r.meta.changes) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, sess.kind, 'delete_credential', { id });
  return { ok: true };
}

// ---------------------------------------------------------------- tokens
/** CLI or web can mint; only a passkey ceremony (web, with assertion) can pre-approve irreversible operations */
export async function mintToken(env, sess, body, byPasskey = false) {
  const cred = await env.DB.prepare('SELECT id, provider FROM credentials WHERE id = ? AND account_id = ?').bind(str(body.credentialId, 'credentialId', { max: 40 }), sess.accountId).first();
  if (!cred) throw new HttpError(404, 'not_found');
  const label = str(body.label ?? 'agent', 'label', { max: 60, re: /^[\p{L}\p{N} ._:/()-]+$/u });
  const policy = normalisePolicy(body.policy, byPasskey);
  const hours = Number.isInteger(body.ttlHours) && body.ttlHours > 0 && body.ttlHours <= 24 * 90 ? body.ttlHours : 24 * 7;
  // binding to an agent key only ever narrows a token (it then needs the agent's signature too), so a CLI session may do it
  const ak = body.agentKeyId !== undefined && body.agentKeyId !== null ? await ownActive(env, sess.accountId, body.agentKeyId) : null;
  const live = await env.DB.prepare('SELECT COUNT(*) AS n FROM tokens WHERE account_id = ? AND revoked = 0 AND expires_at > ?').bind(sess.accountId, now()).first();
  if (live.n >= MAX_LIVE_TOKENS) throw new HttpError(409, 'too_many_tokens', `Up to ${MAX_LIVE_TOKENS} live tokens. Revoke some first.`);
  const token = 'lsh_' + b64u(rand(32));
  const id = randomId();
  // a token minted by a CLI session never outlives that session, and revoking the session revokes it (a sign-in phished
  // out of someone cannot leave 90-day tokens behind)
  const cli = sess.kind === 'cli' ? await sessionId(sess.hash) : null;
  let expiresAt = now() + hours * 3600_000;
  if (cli && sess.expiresAt && expiresAt > sess.expiresAt) expiresAt = sess.expiresAt;
  await env.DB.prepare('INSERT INTO tokens (id, account_id, credential_id, hash, label, policy, minted_by, expires_at, created_at, agent_key_id, session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(id, sess.accountId, cred.id, await sha256hex(token), label, JSON.stringify(policy), byPasskey ? 'passkey' : sess.kind, expiresAt, now(), ak ? ak.id : null, cli).run();
  await audit(env, sess.accountId, sess.kind, 'mint', { id, credential: cred.id, provider: cred.provider, label, hours, preapproved: policy.unattendedIrreversible.length, ...(ak ? { agent_key: ak.keyid } : {}), ...(cli ? { session: cli, expires_at: expiresAt } : {}) });
  return { id, token, provider: cred.provider, baseUrl: `${rp(env).origin}/p/${cred.provider}`, expiresAt, ...(ak ? { agentKey: ak.keyid } : {}), note: `Shown once. ${BRAND.name} keeps only a hash.${cli && expiresAt === sess.expiresAt ? ' It ends with this command line sign-in; make longer-lived tokens in the app.' : ''}` };
}

/** the dangerous variant: pre-approving irreversible operations requires a fresh passkey assertion */
export async function mintBegin(env, sess) {
  const { id, challenge } = await newChallenge(env, 'mint', sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}
export async function mintFinish(env, sess, body) {
  if (sess.kind !== 'web') throw new HttpError(403, 'passkey_required');
  const ch = await takeChallenge(env, body.challengeId, 'mint');
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess.accountId);
  return mintToken(env, sess, body, true);
}

export async function listTokens(env, sess) {
  const r = await env.DB.prepare('SELECT t.id, t.label, t.policy, t.minted_by, t.expires_at, t.revoked, t.created_at, t.last_used, c.provider, c.label AS credential, k.keyid AS agent_key, k.label AS agent_key_label, k.revoked_at AS agent_key_revoked FROM tokens t JOIN credentials c ON c.id = t.credential_id LEFT JOIN agent_keys k ON k.id = t.agent_key_id WHERE t.account_id = ? ORDER BY t.created_at DESC LIMIT ?').bind(sess.accountId, LIST_TOKENS).all();
  return { tokens: r.results.map((t) => ({ ...t, policy: JSON.parse(t.policy) })) };
}

export async function revokeToken(env, sess, id) {
  const r = await env.DB.prepare('UPDATE tokens SET revoked = 1 WHERE id = ? AND account_id = ?').bind(id, sess.accountId).run();
  if (!r.meta.changes) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, sess.kind, 'revoke', { id });
  return { ok: true };
}

// ---------------------------------------------------------------- holds
export async function listHolds(env, sess, status) {
  await env.DB.prepare("UPDATE holds SET status = 'expired' WHERE account_id = ? AND status IN ('pending','approved') AND expires_at < ?").bind(sess.accountId, now()).run();
  const st = ['pending', 'approved', 'denied', 'used', 'expired'].includes(status) ? status : 'pending';
  // the label of what asked: an agent token, or for a coding-agent approval the guard key (token_id "g:<key id>")
  const r = await env.DB.prepare("SELECT h.*, COALESCE(t.label, g.label) AS token_label FROM holds h LEFT JOIN tokens t ON t.id = h.token_id LEFT JOIN guard_keys g ON h.kind != 'proxy' AND g.id = substr(h.token_id, 3) AND g.account_id = h.account_id WHERE h.account_id = ? AND h.status = ? ORDER BY h.created_at DESC LIMIT 100").bind(sess.accountId, st).all();
  const base = await appOrigin(env, sess.accountId);
  return { holds: r.results.map(({ req_hash, context, ...h }) => ({ ...h, context: holdContext(context), approve_url: `${base}/app#hold=${h.id}` })) };
}
/** a guard hold's context as the app shows it: the folder name and the agent's session, nothing else */
function holdContext(raw) {
  if (!raw) return null;
  try { const c = JSON.parse(raw); return { cwd: typeof c.cwd === 'string' ? c.cwd : null, session: typeof c.session === 'string' ? c.session : null }; } catch { return null; }
}

export async function approveBegin(env, sess, holdId) {
  if (sess.kind !== 'web') throw new HttpError(403, 'passkey_required', `Approve in the ${BRAND.name} app with your passkey.`);
  const h = await env.DB.prepare("SELECT id FROM holds WHERE id = ? AND account_id = ? AND status = 'pending' AND expires_at > ?").bind(holdId, sess.accountId, now()).first();
  if (!h) throw new HttpError(404, 'not_found');
  const { id, challenge } = await newChallenge(env, 'approve:' + holdId, sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}

export async function approveFinish(env, sess, holdId, body) {
  if (sess.kind !== 'web') throw new HttpError(403, 'passkey_required');
  const ch = await takeChallenge(env, body.challengeId, 'approve:' + holdId);
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess.accountId);
  const h = await env.DB.prepare("UPDATE holds SET status = 'approved', decided_at = ?, expires_at = ? WHERE id = ? AND account_id = ? AND status = 'pending' AND expires_at > ? RETURNING method, host, rule, kind, context")
    .bind(now(), now() + GRANT_TTL, holdId, sess.accountId, now()).first();
  if (!h) throw new HttpError(404, 'not_found');
  // which passkey approved: a short fingerprint of its credential id (the owner can match it to their passkey)
  const passkey = (await sha256hex(String(body.credential.id))).slice(0, 16);
  await audit(env, sess.accountId, 'web', 'approve', { hold: holdId, method: h.method, host: h.host, rule: h.rule, passkey, ...guardDetail(h) });
  return { ok: true, note: h.kind === 'proxy' || !h.kind ? 'The agent can now retry the exact same request once, within 10 minutes.' : 'The agent can now run that exact command once, within 10 minutes.' };
}

/** for a coding-agent approval: its kind, and the shell map version its receipts name */
function guardDetail(h) {
  if (!h.kind || h.kind === 'proxy') return {};
  const map = mapOf(h.context);
  return { kind: h.kind, ...(map ? { map } : {}) };
}

/** Deny is always safe, so any signed-in session may. An optional reason goes back to the agent that asked (a
 *  coding-agent approval reads it); it is cleaned of control, invisible and line-break characters and capped. */
export const DENY_REASON = 200;
export async function denyHold(env, sess, holdId, body = {}) {
  let reason = null;
  if (body.reason !== undefined && body.reason !== null) {
    if (typeof body.reason !== 'string' || body.reason.length > DENY_REASON) throw new HttpError(400, 'bad_reason', `A reason is text of ${DENY_REASON} characters at most.`);
    reason = cleanText(body.reason) || null;
  }
  const h = await env.DB.prepare("UPDATE holds SET status = 'denied', decided_at = ?, deny_reason = ? WHERE id = ? AND account_id = ? AND status = 'pending' RETURNING method, host, rule, kind, context").bind(now(), reason, holdId, sess.accountId).first();
  if (!h) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, sess.kind, 'deny', { hold: holdId, method: h.method, host: h.host, rule: h.rule, by: sess.kind, ...(reason ? { reason } : {}), ...guardDetail(h) });
  return { ok: true };
}

// ---------------------------------------------------------------- proxy
const PASS_REQ = ['accept', 'accept-language', 'content-type', 'user-agent', 'if-none-match', 'if-match', 'idempotency-key', 'stripe-version', 'x-github-api-version', 'prefer', 'range'];
// Upstream answers are served from our origin, so nothing in them may act on a browser there: no cookies, no CORS grants
// (an upstream's "Access-Control-Allow-Origin: *" would otherwise apply to counterseal), no clearing of site data, no
// policies, reports, preloads or refreshes. Our own headers replace them (PROXY_RESP_HEADERS).
const DROP_RESP = new Set(['set-cookie', 'set-cookie2', 'alt-svc', 'strict-transport-security', 'content-encoding', 'content-length', 'transfer-encoding', 'connection',
  'access-control-allow-origin', 'access-control-allow-credentials', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-expose-headers', 'access-control-max-age',
  'clear-site-data', 'content-security-policy', 'content-security-policy-report-only', 'permissions-policy', 'report-to', 'reporting-endpoints', 'nel', 'link', 'refresh',
  'x-frame-options', 'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'origin-agent-cluster', 'service-worker-allowed', 'x-content-type-options']);
export const PROXY_RESP_HEADERS = { 'content-security-policy': "default-src 'none'; sandbox; frame-ancestors 'none'", 'x-content-type-options': 'nosniff', 'cross-origin-resource-policy': 'same-origin', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY' };

/** One canonical path, used for matching and sent upstream unchanged: no traversal, no encoded slashes or dots that
 * could escape the provider base, no empty segments (checked before the trailing slash is dropped, so "/x//" cannot
 * become "/x/"), no ";" path parameters (some servers strip them before routing) or encoded NUL, and one trailing
 * slash dropped so /x and /x/ are the same path. */
export function canonPath(p) {
  if (/(^|\/)\.\.?(\/|$)/.test(p) || /%2f|%5c|%2e|%00/i.test(p) || /[\\\s;]/.test(p) || p.includes('//') || p.length > 2000) throw new HttpError(400, 'bad_path');
  // Decode escapes of unreserved characters (%72 is just "r") so rules see what the upstream router sees.
  p = p.replace(/%([0-9a-f]{2})/gi, (m, h) => { const c = String.fromCharCode(parseInt(h, 16)); return /[A-Za-z0-9\-_~]/.test(c) ? c : m.toUpperCase(); });
  return p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p;
}

/** What the approver sees. First LEASH's own parsed account of the request (mutations, SQL statements and every write
 * keyword or unknown function), which padding can't push out of view; then a size warning if the request is bigger than
 * the window; then the raw query string and body. Invisible and direction-changing characters are made visible so the
 * text can't be visually reordered or hidden. */
const PREVIEW = 2048;
const INVISIBLE = /[​-‏‪-‮⁠-⁩﻿­؜]/g;
const visible = (t) => String(t).replace(INVISIBLE, (c) => `<U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}>`);
/** max: the window; approvals for commands (approvals.js) pass one big enough that the exact command is never cut */
export function preview(search, text, max = PREVIEW) {
  const head = summarize(search, text);
  const raw = [search, text].filter(Boolean).join('\n\n');
  if (!raw && !head.length) return null;
  if (raw.length > max) head.push(`Request is ${raw.length} characters; only the first part is shown below. The ${BRAND.name} summary above covers all of it.`);
  if (INVISIBLE.test(raw)) head.push('Contains invisible or direction-changing characters (shown as <U+...>).');
  INVISIBLE.lastIndex = 0;
  const top = head.map((h) => visible(h)).join('\n');
  const room = Math.max(256, max - top.length - 2);
  let body = visible(raw);
  if (body.length > room) body = body.slice(0, room - 12) + '\n[truncated]';
  return (top ? top + '\n\n' : '') + body;
}

// A bound token used without a valid agent signature is the stolen-token case: note it in the owner's audit log, at
// most once per token every 10 minutes per isolate, so a flood of bad attempts cannot flood the log or the database.
const sigFailures = new Map();
function noteSignatureFailure(env, tok, method, host, e) {
  const t = now(), last = sigFailures.get(tok.id) || 0;
  if (t - last < 10 * 60_000) return;
  if (sigFailures.size > 10_000) sigFailures.clear();
  sigFailures.set(tok.id, t);
  const p = audit(env, tok.account_id, 'token:' + tok.id, 'agent_signature_failed', { method, host, error: e.code, reason: String(e.extra?.reason || '').slice(0, 80) }).catch(() => {});
  if (env.__ctx && env.__ctx.waitUntil) env.__ctx.waitUntil(p);
}

export async function proxy(env, request, provider, rest, fetcher = fetch) {
  const P = PROVIDERS[provider];
  if (!P) throw new HttpError(404, 'unknown_provider');
  const authz = request.headers.get('authorization') || '';
  const m = authz.match(/^Bearer (lsh_[A-Za-z0-9_-]{43})$/);
  if (!m) throw new HttpError(401, 'leash_token_required', `Send your ${BRAND.name} token as: Authorization: Bearer lsh_...`);
  // one query: the token, whether its account has public receipts on, and the agent key it is bound to (if any)
  const tok = await env.DB.prepare('SELECT t.*, a.receipts AS receipts_on, k.keyid AS agent_keyid, k.x AS agent_x, k.revoked_at AS agent_revoked, k.last_used AS agent_last_used, EXISTS (SELECT 1 FROM passkeys p WHERE p.account_id = t.account_id AND p.rp_id = ?) AS has_new_passkey FROM tokens t JOIN accounts a ON a.id = t.account_id LEFT JOIN agent_keys k ON k.id = t.agent_key_id AND k.account_id = t.account_id WHERE t.hash = ?').bind(hosts(env)[0].rpId, await sha256hex(m[1])).first();
  if (!tok || tok.revoked || tok.expires_at < now()) throw new HttpError(401, 'token_invalid');
  // a token bound to an agent key whose key is gone or revoked never works again (fails closed)
  if (tok.agent_key_id && (!tok.agent_keyid || tok.agent_revoked)) throw new HttpError(401, 'agent_key_revoked', 'The agent key this token is bound to was revoked.');
  const seen = markSeen(env, tok.account_id);
  if (seen) { if (env.__ctx) env.__ctx.waitUntil(seen); else await seen; }
  const cred = await env.DB.prepare('SELECT * FROM credentials WHERE id = ? AND account_id = ?').bind(tok.credential_id, tok.account_id).first();
  if (!cred || cred.provider !== provider) throw new HttpError(403, 'wrong_provider', `This token is for ${cred ? cred.provider : 'another provider'}.`);
  const policy = JSON.parse(tok.policy);

  const method = request.method.toUpperCase();
  if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) throw new HttpError(405, 'method');
  // path: no traversal, no encoded slashes or dots that could escape the provider base
  const path = canonPath('/' + rest);
  const url = new URL(request.url);
  const body = ['GET', 'HEAD'].includes(method) ? null : await readBody(request, MAX_BODY);
  // Prove who: a bound token needs the agent's own signature over this exact request. Checked before the token's rate
  // limit, so someone holding only the token can neither use it nor spend the real agent's request budget.
  let agentKey = null;
  if (tok.agent_key_id) {
    try {
      agentKey = (await verifyAgentSignature(request, body, { keyid: tok.agent_keyid, x: tok.agent_x }, d1Seen(env.DB))).keyid;
    } catch (e) {
      if (e instanceof HttpError) noteSignatureFailure(env, tok, method, P.host, e);
      throw e;
    }
  }
  await limit(env.DB, 'tok:' + tok.id, policy.perMinute, 60_000, now());
  // fatal: a body that is not valid UTF-8 could read one way to the broker and another way upstream; so could a body
  // the content-type declares to be in another charset (the broker always reads UTF-8)
  const cs = /;\s*charset\s*=\s*"?([^";\s]*)/i.exec(request.headers.get('content-type') || '');
  if (body && body.length && cs && !/^(utf-?8|us-ascii)$/i.test(cs[1])) throw new HttpError(400, 'bad_body', 'Request bodies must be UTF-8.');
  let bodyText = '';
  try { bodyText = body ? new TextDecoder('utf-8', { fatal: true }).decode(body) : ''; } catch { throw new HttpError(400, 'bad_body', 'Request body must be valid UTF-8.'); }

  const d = decide(policy, provider, method, path, bodyText, url.search);
  // An approval binds the exact bytes sent upstream, and the content-type that tells the upstream how to read them.
  const bodyHash = body ? b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', body))) : '';
  const reqHash = await sha256hex(JSON.stringify([method, P.host, path, url.search, request.headers.get('content-type') || '', bodyHash]));
  const where = { method, host: P.host, path: path.slice(0, 300), ...(agentKey ? { agent_key: agentKey } : {}) };
  const seal = { receipts: !!tok.receipts_on };
  if (d.decision === 'deny') {
    await audit(env, tok.account_id, 'token:' + tok.id, 'deny', { ...where, rule: d.rule }, seal);
    throw new HttpError(403, 'leash_denied', d.why, { rule: d.rule });
  }
  if (d.decision === 'hold') {
    // an approved grant for exactly this request? consume it atomically
    const g = await env.DB.prepare("UPDATE holds SET status = 'used' WHERE id = (SELECT id FROM holds WHERE token_id = ? AND req_hash = ? AND status = 'approved' AND expires_at > ? LIMIT 1) RETURNING id")
      .bind(tok.id, reqHash, now()).first();
    if (!g) {
      let h = await env.DB.prepare("SELECT id, expires_at FROM holds WHERE token_id = ? AND req_hash = ? AND status = 'pending' AND expires_at > ?").bind(tok.id, reqHash, now()).first();
      if (!h) {
        // Approval fatigue: someone holding a leaked token could make thousands of distinct held requests, each one an
        // alert, hoping a tired human taps approve. A token gets at most 20 waiting requests and an account 100; past
        // that, nothing new is held or alerted until a human has looked.
        const n = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM holds WHERE token_id = ?1 AND status = 'pending' AND expires_at > ?3) AS tok, (SELECT COUNT(*) FROM holds WHERE account_id = ?2 AND status = 'pending' AND expires_at > ?3) AS acct")
          .bind(tok.id, tok.account_id, now()).first();
        if (n.tok >= PENDING_PER_TOKEN || n.acct >= PENDING_PER_ACCOUNT) {
          throw new HttpError(429, 'too_many_holds', `${n.tok >= PENDING_PER_TOKEN ? `${n.tok} requests from this token are` : `${n.acct} requests are`} already waiting for approval, so this one was not held or sent. Stop and ask your human to review the waiting requests first.`);
        }
        h = { id: randomId(), expires_at: now() + HOLD_TTL };
        const pv = preview(url.search, bodyText);
        await env.DB.prepare('INSERT INTO holds (id, account_id, token_id, req_hash, method, host, path, rule, why, created_at, expires_at, preview) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(h.id, tok.account_id, tok.id, reqHash, method, P.host, where.path, d.rule, d.why, now(), h.expires_at, pv).run();
        await audit(env, tok.account_id, 'token:' + tok.id, 'hold', { ...where, rule: d.rule, hold: h.id, preview_sha256: await sha256hex(pv || '') }, seal);
        // wake the owner's devices after responding; the push itself carries nothing. At most one alert a minute per
        // account for held requests: the alert says how many are waiting, so a flood of holds is one buzz, not hundreds
        const p = (async () => { if (await allow(env.DB, 'pushhold:' + tok.account_id, 1, 60_000, now())) await notify(env, tok.account_id, env.__pushFetch || fetch); })().catch(() => {});
        if (env.__ctx) env.__ctx.waitUntil(p); else await p;
      }
      // the approve link goes where the owner can sign in: the product's host once they have a passkey there
      const approveUrl = `${await appOrigin(env, tok.account_id, !!tok.has_new_passkey)}/app#hold=${h.id}`;
      return json({
        error: 'held_for_approval', hold_id: h.id, approve_url: approveUrl, expires_at: h.expires_at, rule: d.rule, map_version: MAP_VERSION,
        message: `${BRAND.name} held this request because it cannot be undone: ${d.why} Stop and ask your human to approve it at ${approveUrl} . After they approve, retry the exact same request once.`,
      }, 428);
    }
    await audit(env, tok.account_id, 'token:' + tok.id, 'proxy_approved', { ...where, rule: d.rule, hold: g.id }, seal);
  }

  // forward
  const secret = await open(env, cred);
  const headers = new Headers();
  for (const h of PASS_REQ) { const v = request.headers.get(h); if (v) headers.set(h, v); }
  for (const [k, v] of Object.entries(P.auth(secret))) headers.set(k, v);
  if (!headers.has('user-agent')) headers.set('user-agent', 'leash-proxy');
  const upstream = `https://${P.host}${P.base}${path}${url.search}`;
  let res;
  try {
    res = await fetcher(upstream, { method, headers, body: body && body.length ? body : undefined, redirect: 'manual' });
  } catch {
    throw new HttpError(502, 'upstream_unreachable');
  }
  const len = Number(res.headers.get('content-length') || 0);
  if (len > MAX_RESP) throw new HttpError(502, 'upstream_too_large');
  const out = new Headers();
  for (const [k, v] of res.headers) if (!DROP_RESP.has(k.toLowerCase())) out.set(k, v);
  for (const [k, v] of Object.entries(PROXY_RESP_HEADERS)) out.set(k, v);
  out.set('x-leash-decision', d.decision === 'hold' ? 'approved' : 'allowed');
  out.set('cache-control', 'no-store');
  // redirects are never followed; a Location header pointing elsewhere is passed through as-is for the caller to judge
  await env.DB.batch([
    env.DB.prepare('UPDATE tokens SET last_used = ? WHERE id = ?').bind(now(), tok.id),
    env.DB.prepare('UPDATE credentials SET last_used = ? WHERE id = ?').bind(now(), cred.id),
  ]);
  if (agentKey && !(tok.agent_last_used > now() - 60_000)) await env.DB.prepare('UPDATE agent_keys SET last_used = ? WHERE id = ?').bind(now(), tok.agent_key_id).run();
  // writes are on the record; an approved call was already sealed as "executed", so its result is not sealed twice
  if (method !== 'GET' && method !== 'HEAD') await audit(env, tok.account_id, 'token:' + tok.id, 'proxy', { ...where, status: res.status, rule: d.rule }, d.decision === 'hold' ? { receipts: false } : seal);
  return new Response(res.body, { status: res.status, headers: out });
}
