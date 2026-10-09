// Credentials, proxy tokens, the proxy, and holds.
import { HttpError, json, b64u, rand, randomId, sha256hex, now, str } from './util.js';
import { seal, open } from './vault.js';
import { summarize, PROVIDERS, MAP_VERSION } from './providers.js';
import { normalisePolicy, decide } from './policy.js';
import { audit } from './audit.js';
import { newChallenge, takeChallenge, checkAssertion, rp } from './auth.js';
import { limit } from './ratelimit.js';
import { notify } from './push.js';

const HOLD_TTL = 30 * 60_000, GRANT_TTL = 10 * 60_000, MAX_BODY = 1_048_576, MAX_RESP = 10 * 1_048_576;

// ---------------------------------------------------------------- credentials
export async function addCredential(env, sess, body) {
  const provider = str(body.provider, 'provider', { max: 20 });
  const P = PROVIDERS[provider];
  if (!P) throw new HttpError(400, 'bad_provider');
  const label = str(body.label ?? P.name, 'label', { max: 60, re: /^[\p{L}\p{N} ._:/()-]+$/u });
  const secret = str(body.secret, 'secret', { min: 8, max: 4096, re: /^[\x21-\x7e]+$/ });
  if (P.keyHint && !P.keyHint.test(secret)) throw new HttpError(400, 'bad_secret', `That does not look like a ${P.name} key.`);
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
  const token = 'lsh_' + b64u(rand(32));
  const id = randomId();
  await env.DB.prepare('INSERT INTO tokens (id, account_id, credential_id, hash, label, policy, minted_by, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(id, sess.accountId, cred.id, await sha256hex(token), label, JSON.stringify(policy), byPasskey ? 'passkey' : sess.kind, now() + hours * 3600_000, now()).run();
  await audit(env, sess.accountId, sess.kind, 'mint', { id, credential: cred.id, provider: cred.provider, label, hours, preapproved: policy.unattendedIrreversible.length });
  return { id, token, provider: cred.provider, baseUrl: `${rp(env).origin}/p/${cred.provider}`, expiresAt: now() + hours * 3600_000, note: 'Shown once. LEASH keeps only a hash.' };
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
  const r = await env.DB.prepare('SELECT t.id, t.label, t.policy, t.minted_by, t.expires_at, t.revoked, t.created_at, t.last_used, c.provider, c.label AS credential FROM tokens t JOIN credentials c ON c.id = t.credential_id WHERE t.account_id = ? ORDER BY t.created_at DESC').bind(sess.accountId).all();
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
  const r = await env.DB.prepare('SELECT h.*, t.label AS token_label FROM holds h LEFT JOIN tokens t ON t.id = h.token_id WHERE h.account_id = ? AND h.status = ? ORDER BY h.created_at DESC LIMIT 100').bind(sess.accountId, st).all();
  return { holds: r.results.map(({ req_hash, ...h }) => h) };
}

export async function approveBegin(env, sess, holdId) {
  if (sess.kind !== 'web') throw new HttpError(403, 'passkey_required', 'Approve in the LEASH app with your passkey.');
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
  const r = await env.DB.prepare("UPDATE holds SET status = 'approved', decided_at = ?, expires_at = ? WHERE id = ? AND account_id = ? AND status = 'pending' AND expires_at > ?")
    .bind(now(), now() + GRANT_TTL, holdId, sess.accountId, now()).run();
  if (!r.meta.changes) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, 'web', 'approve', { hold: holdId });
  return { ok: true, note: 'The agent can now retry the exact same request once, within 10 minutes.' };
}

export async function denyHold(env, sess, holdId) {
  const r = await env.DB.prepare("UPDATE holds SET status = 'denied', decided_at = ? WHERE id = ? AND account_id = ? AND status = 'pending'").bind(now(), holdId, sess.accountId).run();
  if (!r.meta.changes) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, sess.kind, 'deny', { hold: holdId });
  return { ok: true };
}

// ---------------------------------------------------------------- proxy
const PASS_REQ = ['accept', 'accept-language', 'content-type', 'user-agent', 'if-none-match', 'if-match', 'idempotency-key', 'stripe-version', 'x-github-api-version', 'prefer', 'range'];
const DROP_RESP = new Set(['set-cookie', 'set-cookie2', 'alt-svc', 'strict-transport-security', 'content-encoding', 'content-length', 'transfer-encoding', 'connection']);

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
export function preview(search, text) {
  const head = summarize(search, text);
  const raw = [search, text].filter(Boolean).join('\n\n');
  if (!raw && !head.length) return null;
  if (raw.length > PREVIEW) head.push(`Request is ${raw.length} characters; only the first part is shown below. LEASH's summary above covers all of it.`);
  if (INVISIBLE.test(raw)) head.push('Contains invisible or direction-changing characters (shown as <U+...>).');
  INVISIBLE.lastIndex = 0;
  const top = head.map((h) => visible(h)).join('\n');
  const room = Math.max(256, PREVIEW - top.length - 2);
  let body = visible(raw);
  if (body.length > room) body = body.slice(0, room - 12) + '\n[truncated]';
  return (top ? top + '\n\n' : '') + body;
}

export async function proxy(env, request, provider, rest, fetcher = fetch) {
  const P = PROVIDERS[provider];
  if (!P) throw new HttpError(404, 'unknown_provider');
  const authz = request.headers.get('authorization') || '';
  const m = authz.match(/^Bearer (lsh_[A-Za-z0-9_-]{43})$/);
  if (!m) throw new HttpError(401, 'leash_token_required', 'Send your LEASH token as: Authorization: Bearer lsh_...');
  const tok = await env.DB.prepare('SELECT * FROM tokens WHERE hash = ?').bind(await sha256hex(m[1])).first();
  if (!tok || tok.revoked || tok.expires_at < now()) throw new HttpError(401, 'token_invalid');
  const cred = await env.DB.prepare('SELECT * FROM credentials WHERE id = ? AND account_id = ?').bind(tok.credential_id, tok.account_id).first();
  if (!cred || cred.provider !== provider) throw new HttpError(403, 'wrong_provider', `This token is for ${cred ? cred.provider : 'another provider'}.`);
  const policy = JSON.parse(tok.policy);
  await limit(env.DB, 'tok:' + tok.id, policy.perMinute, 60_000, now());

  const method = request.method.toUpperCase();
  if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) throw new HttpError(405, 'method');
  // path: no traversal, no encoded slashes or dots that could escape the provider base
  const path = canonPath('/' + rest);
  const url = new URL(request.url);
  const body = ['GET', 'HEAD'].includes(method) ? null : new Uint8Array(await request.arrayBuffer());
  if (body && body.length > MAX_BODY) throw new HttpError(413, 'too_large');
  // fatal: a body that is not valid UTF-8 could read one way to LEASH and another way upstream; so could a body the
  // content-type declares to be in another charset (LEASH always reads UTF-8)
  const cs = /;\s*charset\s*=\s*"?([^";\s]*)/i.exec(request.headers.get('content-type') || '');
  if (body && body.length && cs && !/^(utf-?8|us-ascii)$/i.test(cs[1])) throw new HttpError(400, 'bad_body', 'Request bodies must be UTF-8.');
  let bodyText = '';
  try { bodyText = body ? new TextDecoder('utf-8', { fatal: true }).decode(body) : ''; } catch { throw new HttpError(400, 'bad_body', 'Request body must be valid UTF-8.'); }

  const d = decide(policy, provider, method, path, bodyText, url.search);
  // An approval binds the exact bytes sent upstream, and the content-type that tells the upstream how to read them.
  const bodyHash = body ? b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', body))) : '';
  const reqHash = await sha256hex(JSON.stringify([method, P.host, path, url.search, request.headers.get('content-type') || '', bodyHash]));
  const where = { method, host: P.host, path: path.slice(0, 300) };
  if (d.decision === 'deny') {
    await audit(env, tok.account_id, 'token:' + tok.id, 'deny', { ...where, rule: d.rule });
    throw new HttpError(403, 'leash_denied', d.why, { rule: d.rule });
  }
  if (d.decision === 'hold') {
    // an approved grant for exactly this request? consume it atomically
    const g = await env.DB.prepare("UPDATE holds SET status = 'used' WHERE id = (SELECT id FROM holds WHERE token_id = ? AND req_hash = ? AND status = 'approved' AND expires_at > ? LIMIT 1) RETURNING id")
      .bind(tok.id, reqHash, now()).first();
    if (!g) {
      let h = await env.DB.prepare("SELECT id, expires_at FROM holds WHERE token_id = ? AND req_hash = ? AND status = 'pending' AND expires_at > ?").bind(tok.id, reqHash, now()).first();
      if (!h) {
        h = { id: randomId(), expires_at: now() + HOLD_TTL };
        const pv = preview(url.search, bodyText);
        await env.DB.prepare('INSERT INTO holds (id, account_id, token_id, req_hash, method, host, path, rule, why, created_at, expires_at, preview) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(h.id, tok.account_id, tok.id, reqHash, method, P.host, where.path, d.rule, d.why, now(), h.expires_at, pv).run();
        await audit(env, tok.account_id, 'token:' + tok.id, 'hold', { ...where, rule: d.rule, hold: h.id, preview_sha256: await sha256hex(pv || '') });
        // wake the owner's devices after responding; the push itself carries nothing
        const p = notify(env, tok.account_id, env.__pushFetch || fetch).catch(() => {});
        if (env.__ctx) env.__ctx.waitUntil(p); else await p;
      }
      const approveUrl = `${rp(env).origin}/app#hold=${h.id}`;
      return json({
        error: 'held_for_approval', hold_id: h.id, approve_url: approveUrl, expires_at: h.expires_at, rule: d.rule, map_version: MAP_VERSION,
        message: `LEASH held this request because it cannot be undone: ${d.why} Stop and ask your human to approve it at ${approveUrl} . After they approve, retry the exact same request once.`,
      }, 428);
    }
    await audit(env, tok.account_id, 'token:' + tok.id, 'proxy_approved', { ...where, rule: d.rule, hold: g.id });
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
  out.set('x-leash-decision', d.decision === 'hold' ? 'approved' : 'allowed');
  out.set('cache-control', 'no-store');
  // redirects are never followed; a Location header pointing elsewhere is passed through as-is for the caller to judge
  await env.DB.batch([
    env.DB.prepare('UPDATE tokens SET last_used = ? WHERE id = ?').bind(now(), tok.id),
    env.DB.prepare('UPDATE credentials SET last_used = ? WHERE id = ?').bind(now(), cred.id),
  ]);
  if (method !== 'GET' && method !== 'HEAD') await audit(env, tok.account_id, 'token:' + tok.id, 'proxy', { ...where, status: res.status, rule: d.rule });
  return new Response(res.body, { status: res.status, headers: out });
}
