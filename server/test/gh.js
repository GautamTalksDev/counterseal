// A stand-in for GitHub's OIDC issuer, for tests and the CPU bench: a real RSA-2048 key pair, its key set (as served at
// /.well-known/jwks), and tokens signed the way GitHub signs them (RS256, claims as the docs list them, ids as strings).
import { b64u } from '../src/util.js';
import { JWKS_URL, ISSUER } from '../src/oidc.js';

const enc = new TextEncoder();
const bytes = (s) => enc.encode(s);
const RSA = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };
let counter = 0;

export async function makeGithub() {
  const gh = { fetches: 0, failing: false, keys: new Map(), current: null, lastUrl: null };
  async function addKey(kid = `kid-${++counter}-${crypto.randomUUID().slice(0, 8)}`) {
    const kp = await crypto.subtle.generateKey(RSA, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    gh.keys.set(kid, { kid, kp, jwk: { kty: 'RSA', alg: 'RS256', use: 'sig', kid, n: jwk.n, e: jwk.e } });
    gh.current = kid;
    return kid;
  }
  await addKey();
  gh.addKey = addKey;
  /** key rotation: a new signing key, and the old one leaves the key set (unless keep) */
  gh.rotate = async ({ keep = false } = {}) => { const old = gh.current; const kid = await addKey(); if (!keep) gh.keys.delete(old); return kid; };
  gh.jwks = () => ({ keys: [...gh.keys.values()].map((k) => k.jwk) });
  /** what the Worker's fetch of the key set gets (env.__oidcFetch) */
  gh.fetch = async (url) => {
    gh.fetches++; gh.lastUrl = String(url);
    if (gh.failing || String(url) !== JWKS_URL) return new Response('down', { status: gh.failing ? 503 : 404 });
    return new Response(JSON.stringify(gh.jwks()), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  /** the claims of a deploy job in acme/app, as GitHub would put them. aud is required. */
  gh.claims = (over = {}) => {
    const iat = Math.floor(Date.now() / 1000);
    return {
      jti: crypto.randomUUID(), sub: 'repo:acme/app:environment:production', aud: 'https://leash.test/gate/gate_x', iss: ISSUER,
      iat, nbf: iat - 600, exp: iat + 300,
      ref: 'refs/heads/main', sha: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678', repository: 'acme/app', repository_id: '1001', repository_owner: 'acme', repository_owner_id: '77',
      actor: 'octocat', actor_id: '5', workflow: 'Deploy', workflow_ref: 'acme/app/.github/workflows/deploy.yml@refs/heads/main', job_workflow_ref: 'acme/app/.github/workflows/deploy.yml@refs/heads/main',
      environment: 'production', event_name: 'push', ref_type: 'branch', repository_visibility: 'private', runner_environment: 'github-hosted',
      run_id: '812', run_number: '40', run_attempt: '1', check_run_id: '5551', head_ref: '', base_ref: '',
      ...over,
    };
  };
  /** a signed token. header: extra or overriding header fields; kid/key: sign with another key; sig: replace the signature */
  gh.token = async (claims, { header = {}, kid = gh.current, key, tamper, sig, parts } = {}) => {
    const k = key || gh.keys.get(kid)?.kp.privateKey;
    const h = { alg: 'RS256', typ: 'JWT', kid, ...header };
    for (const [n, v] of Object.entries(h)) if (v === undefined) delete h[n];
    let p = JSON.stringify(claims);
    const signing = `${b64u(bytes(JSON.stringify(h)))}.${b64u(bytes(p))}`;
    const signature = sig !== undefined ? sig : k ? b64u(new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, k, bytes(signing)))) : '';
    if (parts) return parts(signing.split('.')[0], signing.split('.')[1], signature);
    if (tamper) return `${signing.split('.')[0]}.${b64u(bytes(JSON.stringify({ ...claims, ...tamper })))}.${signature}`;
    return `${signing}.${signature}`;
  };
  return gh;
}
