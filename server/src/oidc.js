// GitHub Actions OIDC tokens, verified with WebCrypto. No dependencies.
//
// What GitHub documents (opened 9 Oct 2026):
//  - "OpenID Connect reference", https://docs.github.com/en/actions/reference/security/oidc : the token's claims (iss, aud,
//    sub, jti, exp, iat, nbf, repository, repository_id, repository_owner, repository_owner_id, run_id, run_attempt, actor,
//    workflow_ref, job_workflow_ref, environment, event_name, ref, ...); the audience defaults to the repository owner's URL
//    and is set with the "audience" query parameter on ACTIONS_ID_TOKEN_REQUEST_URL (bearer ACTIONS_ID_TOKEN_REQUEST_TOKEN);
//    the job needs `permissions: id-token: write`; the docs' own example shows the claims repository_id, run_id, run_number
//    and run_attempt as strings, so numbers here are read from digit strings.
//  - The discovery document, https://token.actions.githubusercontent.com/.well-known/openid-configuration : issuer
//    "https://token.actions.githubusercontent.com", jwks_uri ".../.well-known/jwks", id_token_signing_alg_values_supported
//    ["RS256"] (only), and claims_supported, which includes `sha`, `check_run_id` and `job_workflow_ref`.
// How a token is checked here follows RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 section 3.3 (RS256 is RSASSA-PKCS1-v1_5 with
// SHA-256) and RFC 8725 (JWT best current practice): the algorithm is pinned to RS256 before anything is read from the
// token (never taken from its header, so `none` and HS256-with-the-public-key fail), the key comes only from GitHub's own
// key set by `kid` (never from the token: `jku`, `jwk`, `x5u`, `x5c` and `crit` are refused), the signature is checked
// before any claim is trusted, and then iss, aud, exp, nbf, iat and jti are all checked.
import { HttpError, readCapped, now as clock } from './util.js';

export const ISSUER = 'https://token.actions.githubusercontent.com';
export const JWKS_URL = `${ISSUER}/.well-known/jwks`;
export const SKEW = 60;                    // seconds of clock difference allowed on exp, nbf and iat
export const MAX_LIFE = 3600;              // a token valid for more than an hour from now is refused (bounds the replay record)
export const MAX_TOKEN = 8192;             // characters; GitHub's tokens are about 2 KB
export const JWKS_TTL = 10 * 60_000;       // the key set is fetched at most every 10 minutes per isolate
export const JWKS_STALE_OK = 60 * 60_000;  // if GitHub cannot be reached, keys this far past their time still verify
export const JWKS_REFETCH_MIN = 60_000;    // an unknown kid may cause one early refetch a minute at most (key rotation)
const MAX_JWKS = 65_536, MAX_KEYS = 20;

const bad = (code, message, status = 401) => new HttpError(status, code, message);

// ---------------------------------------------------------------- the key set
// kid -> { n, e, key } where key is the imported CryptoKey, made on first use and kept while the JWK is unchanged.
// at: when the keys were last fetched; next: not before this time is the next fetch tried (the ttl after a success, 10 s
// after a failure); tried: when a fetch was last started (rotation refetches are spaced from it).
const S = { keys: new Map(), at: 0, next: 0, tried: 0, inflight: null };
const RETRY = 10_000;
export function _resetOidc() { S.keys = new Map(); S.at = 0; S.next = 0; S.tried = 0; S.inflight = null; }
export const _oidcState = () => ({ kids: [...S.keys.keys()], at: S.at, next: S.next, tried: S.tried });

const B64U = /^[A-Za-z0-9_-]+$/;
function fromB64u(s, what) {
  if (typeof s !== 'string' || !s || !B64U.test(s) || s.length % 4 === 1) throw bad('oidc_malformed', `The token's ${what} is not base64url.`);
  const p = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(p + '==='.slice((p.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function fetchKeySet(env) {
  const f = env.__oidcFetch || fetch;
  let res;
  try {
    res = await f(JWKS_URL, { headers: { accept: 'application/json' }, redirect: 'error', signal: typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(3000) : undefined });
  } catch { throw bad('oidc_keys_unavailable', "GitHub's signing keys could not be fetched. Try again.", 503); }
  if (res.status !== 200) throw bad('oidc_keys_unavailable', "GitHub's signing keys could not be fetched. Try again.", 503);
  let doc;
  try { doc = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await readCapped(res.body, MAX_JWKS))); } catch { throw bad('oidc_keys_unavailable', "GitHub's signing keys could not be read. Try again.", 503); }
  if (!doc || !Array.isArray(doc.keys) || doc.keys.length > MAX_KEYS) throw bad('oidc_keys_unavailable', "GitHub's signing keys could not be read. Try again.", 503);
  const next = new Map();
  for (const k of doc.keys) {
    // RS256 keys only; a key that is not a plain 2048-bit-or-larger RSA signing key with the usual exponent is skipped
    if (!k || typeof k !== 'object' || k.kty !== 'RSA' || (k.alg !== undefined && k.alg !== 'RS256') || (k.use !== undefined && k.use !== 'sig')) continue;
    if (typeof k.kid !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(k.kid) || k.e !== 'AQAB' || typeof k.n !== 'string' || !B64U.test(k.n)) continue;
    let size; try { size = fromB64u(k.n, 'key').length; } catch { continue; }
    if (size < 256 || size > 1024) continue;
    const old = S.keys.get(k.kid);
    next.set(k.kid, old && old.n === k.n && old.e === k.e ? old : { n: k.n, e: k.e, key: null });
  }
  if (!next.size) throw bad('oidc_keys_unavailable', "GitHub's signing keys could not be read. Try again.", 503);
  return next;
}

/** the key set, refreshed when its time is up. One fetch at a time; if GitHub cannot be reached the old keys keep
 *  verifying for an hour more, then the answer is 503 (never "valid"). */
async function refresh(env, t) {
  if (!S.inflight) {
    S.inflight = (async () => {
      S.tried = t;
      try { S.keys = await fetchKeySet(env); S.at = t; S.next = t + JWKS_TTL; }
      catch (e) { S.next = t + RETRY; if (!S.keys.size) throw e; /* otherwise the old keys keep verifying for a while (keyFor) */ }
    })().finally(() => { S.inflight = null; });
  }
  await S.inflight;
}

async function keyFor(env, kid, t) {
  if (t >= S.next || t < S.at) await refresh(env, t);
  // GitHub unreachable: keys up to an hour past their time still verify, then nothing does
  if (!S.keys.size || t - S.at > JWKS_TTL + JWKS_STALE_OK) throw bad('oidc_keys_unavailable', "GitHub's signing keys could not be fetched. Try again.", 503);
  let entry = S.keys.get(kid);
  // a kid we do not know may be a key rotation: one early refetch a minute at most (random kids must not make this Worker
  // fetch from GitHub on every request)
  if (!entry && t - S.tried >= JWKS_REFETCH_MIN) { await refresh(env, t); entry = S.keys.get(kid); }
  if (!entry) throw bad('oidc_unknown_kid', "The token was signed with a key that is not in GitHub's key set.");
  if (!entry.key) entry.key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: entry.n, e: entry.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  return entry.key;
}

// ---------------------------------------------------------------- the claims we use, each checked to a strict shape
const UNSAFE = '\\p{Cc}\\p{Cf}\\p{Cs}\\p{Zl}\\p{Zp}';
const REPO = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const OWNER = /^[A-Za-z0-9-]{1,39}$/;
const DIGITS = /^[0-9]{1,20}$/;
const SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const REF = new RegExp(`^refs/[^\\s${UNSAFE}]{1,250}$`, 'u');
const ENV = new RegExp(`^[^${UNSAFE}]{1,255}$`, 'u');
const WORKFLOW_REF = new RegExp(`^([A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100})/(\\.github/workflows/[A-Za-z0-9._-]{1,100}\\.ya?ml)@(refs/[^\\s${UNSAFE}]{1,250})$`, 'u');
const JTI = /^[A-Za-z0-9._:=+/-]{1,128}$/;
const ACTOR = /^[A-Za-z0-9_.@[\]-]{1,100}$/;
const EVENT = /^[a-z_]{1,40}$/;

/** GitHub sends ids as strings ("74"), the docs' example does; a safe integer is accepted too. Returns the digits. */
function digits(v, name, optional = false) {
  if ((v === undefined || v === null || v === '') && optional) return '';
  const s = typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? String(v) : v;
  if (typeof s !== 'string' || !DIGITS.test(s)) throw bad('oidc_claims', `The token's ${name} claim is missing or not a number.`);
  return s.replace(/^0+(?=\d)/, '');
}
function text(v, name, re) {
  if (typeof v !== 'string' || !re.test(v)) throw bad('oidc_claims', `The token's ${name} claim is missing or not the expected shape.`);
  return v;
}
/** a workflow ref "owner/repo/.github/workflows/file.yml@refs/heads/main" as { repository, path, ref } */
export function parseWorkflowRef(s) {
  const m = typeof s === 'string' ? WORKFLOW_REF.exec(s) : null;
  return m ? { repository: m[1], path: m[2], ref: m[3] } : null;
}

/**
 * Verify a GitHub Actions OIDC token and return the claims this product uses. Throws HttpError (401, or 503 when GitHub's
 * key set cannot be had): oidc_malformed, oidc_alg, oidc_unknown_kid, oidc_bad_signature, oidc_issuer, oidc_audience,
 * oidc_expired, oidc_not_yet_valid, oidc_lifetime, oidc_claims, oidc_keys_unavailable.
 * `audience` is exactly the string the token must carry (one string, never an array: a token for several audiences is
 * a token for other services too).
 */
export async function verifyGithubToken(env, token, { audience, now = clock() } = {}) {
  if (typeof token !== 'string' || token.length < 20 || token.length > MAX_TOKEN) throw bad('oidc_malformed', 'Not a GitHub Actions OIDC token.');
  const parts = token.split('.');
  if (parts.length !== 3) throw bad('oidc_malformed', 'Not a GitHub Actions OIDC token.');
  let header;
  try { header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(fromB64u(parts[0], 'header'))); } catch (e) { if (e instanceof HttpError) throw e; throw bad('oidc_malformed', "The token's header is not JSON."); }
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw bad('oidc_malformed', "The token's header is not an object.");
  // RFC 8725 section 3.1 and 3.2: the algorithm is ours to pin, and the key never comes from the token
  if (header.alg !== 'RS256') throw bad('oidc_alg', 'GitHub signs with RS256 only.');
  for (const h of ['crit', 'jku', 'jwk', 'x5u', 'x5c']) if (Object.hasOwn(header, h)) throw bad('oidc_malformed', `The token's header has ${h}, which is not accepted.`);
  if (header.typ !== undefined && header.typ !== 'JWT') throw bad('oidc_malformed', "The token's typ is not JWT.");
  if (typeof header.kid !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(header.kid)) throw bad('oidc_malformed', "The token's kid is missing or not the expected shape.");
  const sig = fromB64u(parts[2], 'signature');
  if (sig.length < 256 || sig.length > 1024) throw bad('oidc_bad_signature', 'The signature does not verify.');
  const key = await keyFor(env, header.kid, now);
  if (!(await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sig, new TextEncoder().encode(parts[0] + '.' + parts[1])))) throw bad('oidc_bad_signature', 'The signature does not verify.');

  // the signature is good: now, and only now, read the claims
  let c;
  try { c = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(fromB64u(parts[1], 'payload'))); } catch (e) { if (e instanceof HttpError) throw e; throw bad('oidc_malformed', "The token's payload is not JSON."); }
  if (!c || typeof c !== 'object' || Array.isArray(c)) throw bad('oidc_malformed', "The token's payload is not an object.");
  if (c.iss !== ISSUER) throw bad('oidc_issuer', 'The token was not issued by GitHub Actions.');
  if (typeof c.aud !== 'string' || c.aud !== audience) throw bad('oidc_audience', 'The token was made for another audience. Use the Counterseal Deploy Gate action, which asks GitHub for the right one.');
  const num = (v, n) => { if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > 4e9) throw bad('oidc_claims', `The token's ${n} claim is missing or not a time.`); return v; };
  const exp = num(c.exp, 'exp'), nbf = num(c.nbf, 'nbf'), iat = num(c.iat, 'iat');
  const t = Math.floor(now / 1000);
  if (t > exp + SKEW) throw bad('oidc_expired', 'The token has expired. The action asks GitHub for a fresh one on every try.');
  if (t + SKEW < nbf) throw bad('oidc_not_yet_valid', 'The token is not valid yet (check the clock).');
  if (iat > t + SKEW) throw bad('oidc_not_yet_valid', 'The token was issued in the future (check the clock).');
  if (exp <= iat || exp - t > MAX_LIFE + SKEW) throw bad('oidc_lifetime', 'The token lives longer than an hour, which GitHub does not issue.');
  const jti = text(c.jti, 'jti', JTI);
  const repository = text(c.repository, 'repository', REPO);
  const wf = parseWorkflowRef(c.workflow_ref), jwf = parseWorkflowRef(c.job_workflow_ref);
  if (!wf) throw bad('oidc_claims', "The token's workflow_ref claim is missing or not a workflow in .github/workflows.");
  if (!jwf) throw bad('oidc_claims', "The token's job_workflow_ref claim is missing or not a workflow in .github/workflows.");
  const out = {
    jti, exp, iat,
    repository, repository_id: digits(c.repository_id, 'repository_id'),
    repository_owner: text(c.repository_owner, 'repository_owner', OWNER), repository_owner_id: digits(c.repository_owner_id, 'repository_owner_id'),
    ref: text(c.ref, 'ref', REF), sha: text(c.sha, 'sha', SHA),
    workflow_ref: c.workflow_ref, job_workflow_ref: c.job_workflow_ref, workflow: wf, job_workflow: jwf,
    environment: c.environment === undefined || c.environment === null || c.environment === '' ? '' : text(c.environment, 'environment', ENV),
    event_name: text(c.event_name, 'event_name', EVENT),
    run_id: digits(c.run_id, 'run_id'), run_attempt: digits(c.run_attempt, 'run_attempt'), check_run_id: digits(c.check_run_id, 'check_run_id', true),
    // shown to the approver, never decided on: a value in an unexpected shape is blanked rather than refused
    actor: typeof c.actor === 'string' && ACTOR.test(c.actor) ? c.actor : '',
    visibility: ['public', 'private', 'internal'].includes(c.repository_visibility) ? c.repository_visibility : '',
    runner: ['github-hosted', 'self-hosted'].includes(c.runner_environment) ? c.runner_environment : '',
  };
  if (!out.repository.toLowerCase().startsWith(out.repository_owner.toLowerCase() + '/')) throw bad('oidc_claims', "The token's repository and repository_owner claims disagree.");
  return out;
}
