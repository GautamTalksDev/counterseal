// Team sign-in with the team's identity provider: OpenID Connect single sign-on (SSO). No dependencies.
//
// What SSO does and does not do here. SSO signs a team member in to the app and decides who is on the team; it never
// approves anything. Sealing a held action, unfreezing, changing the team or the quorum: all of them still need the
// member's own passkey (src/team.js, src/auth.js verifyPasskey). A member who joined through SSO and has no passkey yet
// can read and deny, and adds their first passkey from that SSO session (passkeyBegin/passkeyFinish below).
//
// The flow is the OIDC authorization code flow (OpenID Connect Core 1.0, section 3.1) with PKCE S256 (RFC 7636), state
// and nonce, as RFC 9700 (OAuth 2.0 Security Best Current Practice) asks:
//   1. POST /v1/sso/start {team}: a state (32 random bytes), a nonce and a PKCE verifier are made; only the SHA-256 of the
//      state is stored, with the nonce, the verifier and the SHA-256 of a binding value set in a __Host- cookie in this
//      browser (SameSite=Lax, so it comes back on the provider's top-level redirect). 10 minutes, single use.
//   2. GET /v1/sso/callback?code&state: the state is consumed in one statement (a replayed state finds nothing), the
//      binding cookie must match (a callback link sent to someone else fails: no login CSRF), the code is exchanged at
//      the token endpoint with the verifier, and the ID token is verified (verifyIdToken) before any claim is read.
//   3. The person is found by issuer + sub (never by email). Someone new joins only when their verified email is in one
//      of the account's allowed domains, the team has room, and then with the default role (viewer or member; SSO
//      never makes an owner or an approver). The email domain is checked again on every sign-in.
// ID token checks (RFC 7515, RFC 7517, RFC 7518, RFC 8725, OIDC Core 3.1.3.7): the algorithm must be one this account
// accepts (RS256 or ES256, from the provider's discovery document) and is never taken on trust from the token (so `none`
// and HS256 fail); the key comes only from the provider's JWKS by kid (jku, jwk, x5u, x5c and crit are refused); the
// signature is checked first; then iss (exact), aud (contains the client id; azp must be the client id when present or
// when there are several audiences), exp, iat (not in the future, at most 10 minutes old), nbf, nonce, sub, email and
// email_verified. JWKS are cached per provider for 10 minutes; an unknown kid may refetch once a minute (key rotation).
//
// Removal. Someone removed or disabled at the provider cannot sign in again: the provider refuses them. With "SSO
// required" (enforce) on, members other than owners cannot sign in with a passkey alone either (src/auth.js loginFinish),
// so removal at the provider takes their access away at their next sign-in; a web session they already had ends within
// an hour without activity and after 12 hours at most (src/auth.js). Owners keep passkey sign-in, so a provider outage
// never locks an account out. Automatic deprovisioning (SCIM 2.0, RFC 7643/7644) is not built yet; until then an owner
// removes the member in the app as well, which ends their sessions at once.
import { HttpError, b64u, rand, randomId, sha256hex, now, str, cleanText, readCapped } from './util.js';
import { verifyRegistration } from './webauthn.js';
import { newChallenge, takeChallenge, checkAssertion, rp, host, startWebSession } from './auth.js';
import { audit } from './audit.js';
import { seal, open } from './vault.js';
import { MAX_MEMBERS, founderRow, alertTeam } from './team.js';
import { BRAND } from './brand.js';

export const STATE_TTL = 10 * 60_000, SKEW = 60, MAX_AGE = 600, MAX_TOKEN = 16384, MAX_DOC = 65536;
export const JWKS_TTL = 10 * 60_000, JWKS_REFETCH_MIN = 60_000, MAX_DOMAINS = 10;
export const ALGS = ['RS256', 'ES256'];
export const SSO_ROLES = ['viewer', 'member'];
export const CALLBACK = '/v1/sso/callback';
export const BIND_COOKIE = '__Host-leash-sso';
const ID = /^[0-9a-f]{24}$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const CLIENT_ID = /^[\x21-\x7e]{1,255}$/;
const NAME = /^[\p{L}\p{N} ._'-]+$/u;

const bad = (code, message, status = 401) => new HttpError(status, code, message);
const te = new TextEncoder();

// ---------------------------------------------------------------- fetching from the provider
/** an https URL on a public host name (never an IP literal, localhost, credentials or a fragment) */
export function publicHttps(raw, what) {
  let u;
  try { u = new URL(String(raw)); } catch { throw bad('sso_bad_url', `The ${what} is not a URL.`, 400); }
  const h = u.hostname.toLowerCase();
  if (u.protocol !== 'https:' || u.username || u.password || u.hash || !h.includes('.') || h === 'localhost' || h.endsWith('.localhost')
    || /^[0-9.]+$/.test(h) || h.includes(':') || h.startsWith('[')) throw bad('sso_bad_url', `The ${what} must be an https address on a public host name.`, 400);
  return u;
}

async function getJson(env, url, init = {}, what = 'identity provider') {
  const f = env.__ssoFetch || fetch;
  let res;
  try {
    res = await f(url, { ...init, redirect: 'error', signal: typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(5000) : undefined });
  } catch { throw bad('sso_unreachable', `The ${what} could not be reached. Try again.`, 503); }
  let body;
  try { body = JSON.parse(new TextDecoder().decode(await readCapped(res.body, MAX_DOC))); } catch { body = null; }
  return { status: res.status, body };
}

/** the provider's discovery document (OIDC Discovery 1.0 section 4), checked: its issuer is exactly the one configured */
export async function discover(env, issuer) {
  const iss = publicHttps(issuer, 'issuer').href.replace(/\/$/, '') === issuer.replace(/\/$/, '') ? issuer : null;
  if (!iss) throw bad('sso_bad_url', 'The issuer is not a plain https address.', 400);
  const { status, body: d } = await getJson(env, issuer.replace(/\/$/, '') + '/.well-known/openid-configuration', { headers: { accept: 'application/json' } });
  if (status !== 200 || !d || typeof d !== 'object') throw bad('sso_discovery', 'The identity provider did not return a discovery document.', 400);
  if (d.issuer !== issuer) throw bad('sso_discovery', 'The discovery document names another issuer. Use exactly the issuer it states.', 400);
  for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) publicHttps(d[k], k);
  const offered = Array.isArray(d.id_token_signing_alg_values_supported) ? d.id_token_signing_alg_values_supported : ['RS256'];
  const algs = ALGS.filter((a) => offered.includes(a));
  if (!algs.length) throw bad('sso_discovery', 'The identity provider signs ID tokens with no algorithm accepted here (RS256 or ES256).', 400);
  if (Array.isArray(d.code_challenge_methods_supported) && !d.code_challenge_methods_supported.includes('S256')) throw bad('sso_discovery', 'The identity provider does not support PKCE with S256.', 400);
  const methods = Array.isArray(d.token_endpoint_auth_methods_supported) ? d.token_endpoint_auth_methods_supported : ['client_secret_basic'];
  return { authorization_endpoint: d.authorization_endpoint, token_endpoint: d.token_endpoint, jwks_uri: d.jwks_uri, algs, methods };
}

// ---------------------------------------------------------------- the key sets (one cache per jwks_uri, per isolate)
const KEYS = new Map(); // jwks_uri -> { keys: Map(kid -> jwk), at, tried }
export function _resetSso() { KEYS.clear(); }
export const _ssoCache = (uri) => KEYS.get(uri) || null;

async function loadKeys(env, uri) {
  const { status, body } = await getJson(env, uri, { headers: { accept: 'application/json' } }, "identity provider's key set");
  if (status !== 200 || !body || !Array.isArray(body.keys)) throw bad('sso_keys_unavailable', "The identity provider's signing keys could not be read.", 503);
  const keys = new Map();
  for (const k of body.keys.slice(0, 50)) {
    if (!k || typeof k !== 'object' || (k.use && k.use !== 'sig')) continue;
    if (k.kty === 'RSA' && typeof k.n === 'string' && typeof k.e === 'string') keys.set(typeof k.kid === 'string' ? k.kid : '', { kty: 'RSA', n: k.n, e: k.e, alg: k.alg });
    if (k.kty === 'EC' && k.crv === 'P-256' && typeof k.x === 'string' && typeof k.y === 'string') keys.set(typeof k.kid === 'string' ? k.kid : '', { kty: 'EC', crv: 'P-256', x: k.x, y: k.y, alg: k.alg });
  }
  return keys;
}

async function keyFor(env, uri, kid, alg) {
  const t = now();
  let c = KEYS.get(uri);
  if (!c || t - c.at > JWKS_TTL) {
    try { c = { keys: await loadKeys(env, uri), at: t, tried: t }; KEYS.set(uri, c); } catch (e) { if (!c) throw e; }
  }
  let k = c.keys.get(kid);
  if (!k && t - c.tried > JWKS_REFETCH_MIN) {
    c.tried = t;
    try { c = { keys: await loadKeys(env, uri), at: t, tried: t }; KEYS.set(uri, c); } catch { /* keep the old keys */ }
    k = c.keys.get(kid);
  }
  if (!k) throw bad('sso_unknown_kid', 'The ID token was signed with a key the identity provider does not publish.');
  if (k.alg && k.alg !== alg) throw bad('sso_alg', 'The ID token key is for another algorithm.');
  if ((alg === 'RS256') !== (k.kty === 'RSA')) throw bad('sso_alg', 'The ID token key does not match its algorithm.');
  return alg === 'RS256'
    ? crypto.subtle.importKey('jwk', { kty: 'RSA', n: k.n, e: k.e, ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    : crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: k.x, y: k.y, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

const B64U = /^[A-Za-z0-9_-]*$/;
function unb64u(s, what) {
  if (typeof s !== 'string' || !B64U.test(s) || s.length % 4 === 1) throw bad('sso_malformed', `The ID token's ${what} is not base64url.`);
  const p = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(p + '==='.slice((p.length + 3) % 4));
  return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
}
const parse = (bytes, what) => { try { const v = JSON.parse(new TextDecoder().decode(bytes)); if (v && typeof v === 'object' && !Array.isArray(v)) return v; } catch { /* below */ } throw bad('sso_malformed', `The ID token's ${what} is not a JSON object.`); };

/** constant-time string comparison (for the nonce) */
function same(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** verifies an ID token for this account's configuration; returns its claims. Throws HttpError(401, sso_*) otherwise. */
export async function verifyIdToken(env, cfg, token, nonce) {
  if (typeof token !== 'string' || token.length > MAX_TOKEN) throw bad('sso_malformed', 'No usable ID token.');
  const parts = token.split('.');
  if (parts.length !== 3) throw bad('sso_malformed', 'The ID token is not a signed JWT.');
  const header = parse(unb64u(parts[0], 'header'), 'header');
  const algs = JSON.parse(cfg.algs);
  if (typeof header.alg !== 'string' || !algs.includes(header.alg)) throw bad('sso_alg', 'The ID token is signed with an algorithm this account does not accept.');
  for (const k of ['jku', 'jwk', 'x5u', 'x5c', 'crit']) if (k in header) throw bad('sso_alg', `The ID token header carries "${k}", which is refused.`);
  const key = await keyFor(env, cfg.jwks_uri, typeof header.kid === 'string' ? header.kid : '', header.alg);
  const sig = unb64u(parts[2], 'signature');
  const algo = header.alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
  if (header.alg === 'ES256' && sig.length !== 64) throw bad('sso_bad_signature', 'The ID token signature is not valid.');
  let ok = false;
  try { ok = await crypto.subtle.verify(algo, key, sig, te.encode(parts[0] + '.' + parts[1])); } catch { ok = false; }
  if (!ok) throw bad('sso_bad_signature', 'The ID token signature is not valid.');
  const c = parse(unb64u(parts[1], 'payload'), 'payload');
  const t = Math.floor(now() / 1000);
  if (c.iss !== cfg.issuer) throw bad('sso_issuer', 'The ID token is from another issuer.');
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(cfg.client_id) || aud.some((a) => typeof a !== 'string')) throw bad('sso_audience', 'The ID token is not for this application.');
  if ((aud.length > 1 || c.azp !== undefined) && c.azp !== cfg.client_id) throw bad('sso_audience', 'The ID token was issued to another party (azp).');
  if (typeof c.exp !== 'number' || c.exp + SKEW < t) throw bad('sso_expired', 'The ID token has expired. Sign in again.');
  if (typeof c.iat !== 'number' || c.iat > t + SKEW || c.iat < t - MAX_AGE - SKEW) throw bad('sso_expired', 'The ID token is not fresh. Sign in again.');
  if (c.nbf !== undefined && (typeof c.nbf !== 'number' || c.nbf > t + SKEW)) throw bad('sso_expired', 'The ID token is not valid yet.');
  if (!same(c.nonce, nonce)) throw bad('sso_nonce', 'The ID token does not belong to this sign-in.');
  if (typeof c.sub !== 'string' || !c.sub || c.sub.length > 255) throw bad('sso_claims', 'The ID token has no subject.');
  if (typeof c.email !== 'string' || c.email.length > 254 || !/^[^@\s]+@[^@\s]+$/.test(c.email)) throw bad('sso_claims', 'The identity provider did not send an email address. Add the email scope and claim.');
  if (c.email_verified !== true) throw bad('sso_claims', 'The identity provider did not say the email address is verified (email_verified).');
  return c;
}

// ---------------------------------------------------------------- configuration (an owner, a fresh passkey ceremony)
function settings(body) {
  const b = body && typeof body === 'object' ? body : {};
  const issuer = str(typeof b.issuer === 'string' ? b.issuer.trim() : b.issuer, 'issuer', { max: 300 });
  publicHttps(issuer, 'issuer');
  const clientId = str(b.clientId, 'clientId', { re: CLIENT_ID });
  if (b.clientSecret !== undefined && b.clientSecret !== null) str(b.clientSecret, 'clientSecret', { max: 512, re: /^[\x21-\x7e]+$/ });
  if (!Array.isArray(b.domains) || !b.domains.length || b.domains.length > MAX_DOMAINS) throw new HttpError(400, 'bad_domains', `List 1 to ${MAX_DOMAINS} email domains whose people may sign in.`);
  const domains = [...new Set(b.domains.map((d) => (typeof d === 'string' ? d.trim().toLowerCase() : '')))];
  if (domains.some((d) => !DOMAIN.test(d))) throw new HttpError(400, 'bad_domains', 'A domain is not a plain domain name (for example example.com).');
  const defaultRole = b.defaultRole ?? 'viewer';
  if (!SSO_ROLES.includes(defaultRole)) throw new HttpError(400, 'bad_defaultRole', 'People who join through SSO start as viewer or member. Promote them in the team page afterwards.');
  const enforce = b.enforce === true;
  return { issuer, clientId, clientSecret: b.clientSecret || null, domains: domains.sort(), defaultRole, enforce };
}
/** what the passkey approves: these exact settings (the secret by its hash) */
const settingsHash = async (s) => sha256hex(JSON.stringify({ ...s, clientSecret: s.clientSecret ? await sha256hex(s.clientSecret) : null }));

const loginLink = (env, id) => `${host(env).origin}/app/#sso=${id}`;
const view = (env, c) => c && ({
  id: c.id, issuer: c.issuer, clientId: c.client_id, clientSecret: !!c.ct, domains: JSON.parse(c.domains), defaultRole: c.default_role,
  enforce: !!c.enforce, algs: JSON.parse(c.algs), changedAt: c.changed_at, loginLink: loginLink(env, c.id), redirectUri: host(env).origin + CALLBACK,
});

/** GET /v1/team/sso: the configuration (never the client secret) and, for owners, who signed in through it */
export async function get(env, sess) {
  const c = await env.DB.prepare('SELECT * FROM sso_configs WHERE account_id = ?').bind(sess.accountId).first();
  const out = { sso: view(env, c), redirectUri: host(env).origin + CALLBACK, scim: 'planned' };
  if (sess.role === 'owner') {
    out.identities = (await env.DB.prepare('SELECT i.member_id, i.email, i.issuer, i.created_at, i.last_login, m.removed_at FROM sso_identities i LEFT JOIN members m ON m.id = i.member_id AND m.account_id = i.account_id WHERE i.account_id = ? ORDER BY i.created_at LIMIT 100').bind(sess.accountId).all()).results
      .map((r) => ({ member: r.member_id, email: r.email, issuer: r.issuer, created_at: r.created_at, last_login: r.last_login, removed: r.removed_at != null }));
  }
  return out;
}

export async function setBegin(env, sess, body) {
  const s = settings(body);
  const { id, challenge } = await newChallenge(env, 'sso_set', sess.accountId, await settingsHash(s));
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}

export async function setFinish(env, sess, body) {
  const s = settings(body);
  const ch = await takeChallenge(env, body.challengeId, 'sso_set');
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess);
  if (ch.name !== await settingsHash(s)) throw new HttpError(409, 'sso_changed', 'These are not the settings you began with. Start again.');
  const d = await discover(env, s.issuer);
  const method = !s.clientSecret ? 'none' : d.methods.includes('client_secret_basic') ? 'client_secret_basic' : d.methods.includes('client_secret_post') ? 'client_secret_post' : null;
  if (!method) throw new HttpError(400, 'sso_discovery', 'The identity provider accepts no client secret method supported here (client_secret_basic or client_secret_post).');
  const old = await env.DB.prepare('SELECT id, rev FROM sso_configs WHERE account_id = ?').bind(sess.accountId).first();
  const id = old?.id || randomId(), t = now();
  const sealed = s.clientSecret ? await seal(env, { id, accountId: sess.accountId, provider: 'sso' }, s.clientSecret) : { ct: null, iv: null, wrapped_dek: null, dek_iv: null };
  await env.DB.prepare(`INSERT INTO sso_configs (id, account_id, rev, issuer, client_id, authorization_endpoint, token_endpoint, jwks_uri, algs, auth_method, domains, default_role, enforce, ct, iv, wrapped_dek, dek_iv, created_by, created_at, changed_at)
    VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?18)
    ON CONFLICT(account_id) DO UPDATE SET rev = rev + 1, issuer = ?3, client_id = ?4, authorization_endpoint = ?5, token_endpoint = ?6, jwks_uri = ?7, algs = ?8, auth_method = ?9, domains = ?10, default_role = ?11, enforce = ?12, ct = ?13, iv = ?14, wrapped_dek = ?15, dek_iv = ?16, changed_at = ?18`)
    .bind(id, sess.accountId, s.issuer, s.clientId, d.authorization_endpoint, d.token_endpoint, d.jwks_uri, JSON.stringify(d.algs), method, JSON.stringify(s.domains), s.defaultRole, s.enforce ? 1 : 0, sealed.ct, sealed.iv, sealed.wrapped_dek, sealed.dek_iv, sess.memberId, t).run();
  await audit(env, sess.accountId, 'web', old ? 'sso_changed' : 'sso_on', { issuer: s.issuer, client_id: s.clientId, domains: s.domains, default_role: s.defaultRole, enforce: s.enforce, by: sess.memberId });
  await alertTeam(env, sess.accountId, sess.memberId);
  return get(env, sess);
}

export async function offBegin(env, sess) {
  const { id, challenge } = await newChallenge(env, 'sso_off', sess.accountId);
  return { challengeId: id, options: { challenge, rpId: rp(env).rpId, userVerification: 'required', timeout: 300000 } };
}
/** turning SSO off: sign-ins in progress die with it; members keep their passkeys and their place on the team */
export async function offFinish(env, sess, body) {
  const ch = await takeChallenge(env, body.challengeId, 'sso_off');
  if (ch.account_id !== sess.accountId) throw new HttpError(403, 'forbidden');
  await checkAssertion(env, body.credential, ch.challenge, sess);
  const r = await env.DB.batch([
    env.DB.prepare('DELETE FROM sso_configs WHERE account_id = ?').bind(sess.accountId),
    env.DB.prepare('DELETE FROM sso_states WHERE account_id = ?').bind(sess.accountId),
  ]);
  if (!r[0].meta.changes) throw new HttpError(404, 'not_found');
  await audit(env, sess.accountId, 'web', 'sso_off', { by: sess.memberId });
  await alertTeam(env, sess.accountId, sess.memberId);
  return { ok: true, sso: null };
}

// ---------------------------------------------------------------- signing in
const bindCookie = (v, age) => `${BIND_COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
const s256 = async (v) => b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(v))));

/** POST /v1/sso/start {team}: where to send the browser (the provider's authorization endpoint) */
export async function start(env, body) {
  const team = str(body?.team, 'team', { re: ID });
  const c = await env.DB.prepare('SELECT id, account_id, rev, client_id, authorization_endpoint FROM sso_configs WHERE id = ?').bind(team).first();
  if (!c) throw new HttpError(404, 'sso_not_found', 'This team has no single sign-on. Ask an owner for the right link.');
  const state = b64u(rand(32)), nonce = b64u(rand(32)), verifier = b64u(rand(32)), binding = b64u(rand(32)), t = now();
  await env.DB.prepare('INSERT INTO sso_states (hash, config_id, account_id, rev, nonce, verifier, binding, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(await sha256hex(state), c.id, c.account_id, c.rev, nonce, verifier, await sha256hex(binding), t, t + STATE_TTL).run();
  const u = new URL(c.authorization_endpoint);
  for (const [k, v] of Object.entries({ response_type: 'code', client_id: c.client_id, redirect_uri: host(env).origin + CALLBACK, scope: 'openid email profile', state, nonce, code_challenge: await s256(verifier), code_challenge_method: 'S256' })) u.searchParams.set(k, v);
  return { body: { url: u.href }, cookie: bindCookie(binding, STATE_TTL / 1000) };
}

async function redeem(env, cfg, code, verifier) {
  const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: host(env).origin + CALLBACK, code_verifier: verifier });
  const headers = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  if (cfg.auth_method === 'none') form.set('client_id', cfg.client_id);
  else {
    const secret = await open(env, { ...cfg, provider: 'sso', host: null });
    if (cfg.auth_method === 'client_secret_basic') headers.authorization = 'Basic ' + btoa(`${encodeURIComponent(cfg.client_id)}:${encodeURIComponent(secret)}`);
    else { form.set('client_id', cfg.client_id); form.set('client_secret', secret); }
  }
  const { status, body } = await getJson(env, cfg.token_endpoint, { method: 'POST', headers, body: form.toString() });
  if (status !== 200 || !body || typeof body.id_token !== 'string') throw bad('sso_token', 'The identity provider did not accept the sign-in. Start again.');
  return body.id_token;
}

const cleanName = (claims) => {
  const n = cleanText(typeof claims.name === 'string' ? claims.name : '').replace(/[^\p{L}\p{N} ._'-]/gu, '').slice(0, 50).trim();
  const fallback = claims.email.split('@')[0].replace(/[^\p{L}\p{N}._'-]/gu, '').slice(0, 50);
  return NAME.test(n) ? n : NAME.test(fallback) ? fallback : 'Member';
};

/** GET /v1/sso/callback: the provider sends the browser back here. Returns {accountId, memberId, joined}. */
export async function finish(env, request, url) {
  const err = url.searchParams.get('error');
  const state = url.searchParams.get('state'), code = url.searchParams.get('code');
  if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(state)) throw bad('sso_state', 'This sign-in link is not valid. Start again.', 400);
  const binding = (request.headers.get('cookie') || '').match(new RegExp(`(?:^|;\\s*)${BIND_COOKIE}=([A-Za-z0-9_-]{43})`))?.[1];
  const t = now();
  // single use: consumed in one statement, so a replayed state (or two tabs racing) finds nothing
  const st = await env.DB.prepare('UPDATE sso_states SET used_at = ?1 WHERE hash = ?2 AND used_at IS NULL AND expires_at > ?1 RETURNING *').bind(t, await sha256hex(state)).first();
  if (!st) throw bad('sso_state', 'This sign-in was already used or has expired. Start again.', 400);
  if (!binding || await sha256hex(binding) !== st.binding) throw bad('sso_state', 'This sign-in was started in another browser. Start again here.', 400);
  if (err) throw bad('sso_denied', 'The identity provider did not sign you in.', 401);
  if (typeof code !== 'string' || !code || code.length > 2048) throw bad('sso_token', 'The identity provider sent no code.', 400);
  const cfg = await env.DB.prepare('SELECT * FROM sso_configs WHERE id = ? AND account_id = ?').bind(st.config_id, st.account_id).first();
  if (!cfg || cfg.rev !== st.rev) throw bad('sso_state', 'Single sign-on for this team changed while you were signing in. Start again.', 400);
  const claims = await verifyIdToken(env, cfg, await redeem(env, cfg, code, st.verifier), st.nonce);
  const email = claims.email.toLowerCase(), domain = email.split('@')[1];
  if (!JSON.parse(cfg.domains).includes(domain)) throw bad('sso_domain', `People from ${domain} cannot sign in to this team.`, 403);
  const a = cfg.account_id;
  const known = await env.DB.prepare('SELECT i.member_id, m.removed_at, m.id AS m_id FROM sso_identities i LEFT JOIN members m ON m.id = i.member_id AND m.account_id = i.account_id WHERE i.account_id = ? AND i.issuer = ? AND i.sub = ?').bind(a, cfg.issuer, claims.sub).first();
  if (known) {
    if (!known.m_id || known.removed_at != null) throw bad('sso_removed', 'You were removed from this team. Ask an owner to invite you again.', 403);
    await env.DB.prepare('UPDATE sso_identities SET email = ?, last_login = ? WHERE account_id = ? AND issuer = ? AND sub = ?').bind(email, t, a, cfg.issuer, claims.sub).run();
    await audit(env, a, 'web', 'sso_login', { member: known.member_id, issuer: cfg.issuer });
    return { accountId: a, memberId: known.member_id, joined: false };
  }
  // someone new: one transaction, written only while the team has room; the name gets a number when it is taken
  const base = cleanName(claims), mid = randomId();
  const taken = new Set((await env.DB.prepare('SELECT LOWER(name) AS n FROM members WHERE account_id = ?1 AND removed_at IS NULL UNION ALL SELECT LOWER(name) FROM accounts WHERE id = ?1').bind(a).all()).results.map((r) => r.n));
  let name = base;
  for (let i = 2; taken.has(name.toLowerCase()) && i < 100; i++) name = `${base.slice(0, 46)} ${i}`;
  const res = await env.DB.batch([
    founderRow(env.DB, a),
    env.DB.prepare(`INSERT INTO members (id, account_id, name, label, role, created_at, invited_by, votes_from)
      SELECT ?1, ?2, ?3, 'SSO', ?4, ?5, NULL, ?5 WHERE (SELECT COUNT(*) FROM members WHERE account_id = ?2 AND removed_at IS NULL) < ?6`).bind(mid, a, name, cfg.default_role, t, MAX_MEMBERS),
    env.DB.prepare('INSERT INTO sso_identities (account_id, issuer, sub, member_id, email, created_at, last_login) SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM members WHERE id = ?)').bind(a, cfg.issuer, claims.sub, mid, email, t, t, mid),
  ]);
  if (!res[1].meta.changes) throw bad('sso_team_full', `This team already has ${MAX_MEMBERS} people. An owner can remove someone first.`, 409);
  await audit(env, a, 'web', 'member_joined', { member: mid, name, role: cfg.default_role, via: 'sso', issuer: cfg.issuer });
  await alertTeam(env, a, mid);
  return { accountId: a, memberId: mid, joined: true };
}

/** the callback's answer: a session cookie and a redirect into the app, or a redirect with the error's code */
export async function callbackResponse(env, request, url) {
  const headers = new Headers({ 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff' });
  headers.append('set-cookie', bindCookie('', 0));
  try {
    const r = await finish(env, request, url);
    const s = await startWebSession(env, r.accountId, r.memberId, 'sso');
    headers.append('set-cookie', s.cookie);
    headers.set('location', `${host(env).origin}/app/${r.joined ? '#sso-joined' : ''}`);
  } catch (e) {
    if (!(e instanceof HttpError)) throw e;
    console.warn(JSON.stringify({ event: 'security', code: e.code, status: e.status, method: 'GET', path: CALLBACK }));
    headers.set('location', `${host(env).origin}/app/#sso-error=${encodeURIComponent(e.code)}`);
  }
  return new Response(null, { status: 303, headers });
}

// ---------------------------------------------------------------- the first passkey of someone who joined through SSO
async function passkeyCount(env, sess) {
  return (await env.DB.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE account_id = ? AND COALESCE(member_id, account_id) = ?').bind(sess.accountId, sess.memberId).first()).n;
}
/** only from an SSO session, and only while the member has no passkey (more passkeys are added with a passkey) */
async function firstOnly(env, sess) {
  if (sess.via !== 'sso') throw new HttpError(403, 'passkey_required', 'Add passkeys from a session you started with your passkey.');
  if (await passkeyCount(env, sess)) throw new HttpError(409, 'has_passkey', 'You already have a passkey. Sign in with it to add another.');
}
export async function passkeyBegin(env, sess) {
  await firstOnly(env, sess);
  const r = rp(env);
  const exclude = (await env.DB.prepare('SELECT cred_id FROM passkeys WHERE account_id = ? LIMIT 100').bind(sess.accountId).all()).results.map((x) => ({ type: 'public-key', id: x.cred_id }));
  const { id, challenge } = await newChallenge(env, 'sso_passkey', sess.accountId, sess.memberId);
  const name = sess.memberName || 'Member';
  return {
    challengeId: id,
    options: {
      challenge, rp: { id: r.rpId, name: r.name }, user: { id: b64u(rand(16)), name, displayName: `${name} (${BRAND.name})`.slice(0, 120) },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], excludeCredentials: exclude,
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' }, attestation: 'none', timeout: 300000,
    },
  };
}
export async function passkeyFinish(env, sess, body) {
  const ch = await takeChallenge(env, body.challengeId, 'sso_passkey');
  if (ch.account_id !== sess.accountId || ch.name !== sess.memberId) throw new HttpError(403, 'forbidden');
  await firstOnly(env, sess);
  const r = rp(env);
  const c = await verifyRegistration(body.credential || {}, { challenge: ch.challenge, origin: r.origin, rpId: r.rpId });
  let ins;
  try {
    ins = await env.DB.prepare(`INSERT INTO passkeys (cred_id, account_id, alg, jwk, sign_count, created_at, rp_id, member_id)
      SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 WHERE NOT EXISTS (SELECT 1 FROM passkeys WHERE account_id = ?2 AND COALESCE(member_id, account_id) = ?8)`)
      .bind(c.credId, sess.accountId, c.alg, JSON.stringify(c.jwk), c.signCount, now(), r.rpId, sess.memberId).run();
  } catch (e) {
    if (/UNIQUE|constraint/i.test(String(e && e.message))) throw new HttpError(409, 'passkey_exists', 'That passkey is already registered. Use a new one.');
    throw e;
  }
  if (!ins.meta.changes) throw new HttpError(409, 'has_passkey', 'You already have a passkey.');
  await audit(env, sess.accountId, 'web', 'passkey_added', { member: sess.memberId, via: 'sso' });
  await alertTeam(env, sess.accountId, sess.memberId);
  return { ok: true };
}

