// Agent keys: sign requests to the broker (RFC 9421 HTTP Message Signatures, profile tag "leash-pop") and prove
// possession of a key when registering it. Zero dependencies, Node 20+ (WebCrypto Ed25519).
const te = new TextEncoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const b64u = (b) => b64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const sf = (s) => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';

export const POP_TAG = 'leash-pop';

/** RFC 7638 / RFC 8037 thumbprint of an Ed25519 public key (base64url x): the keyid */
export async function keyid(x) {
  return b64u(await crypto.subtle.digest('SHA-256', te.encode(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x }))));
}

/** a new Ed25519 key as a private JWK {kty, crv, x, d} */
export async function generateAgentKey() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const j = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return { kty: 'OKP', crv: 'Ed25519', x: j.x, d: j.d };
}

export const importAgentKey = (jwk) => crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d }, { name: 'Ed25519' }, false, ['sign']);

/** headers to add to one request: Signature-Input, Signature and, when there is a body, Content-Digest.
 *  Covers @method, @target-uri and content-digest. key: CryptoKey (Ed25519 private); kid: keyid(x). */
export async function signBrokerRequest({ method, url, body }, { key, kid, now = Math.floor(Date.now() / 1000), expiresIn = 60, nonce } = {}) {
  if (!(expiresIn > 0 && expiresIn <= 300)) throw new Error('expiresIn must be 1 to 300 seconds');
  const bytes = body == null ? new Uint8Array(0) : typeof body === 'string' ? te.encode(body) : new Uint8Array(body);
  const target = new URL(url).href;
  const out = {};
  const comps = ['@method', '@target-uri'];
  const lines = [`"@method": ${String(method).toUpperCase()}`, `"@target-uri": ${target}`];
  if (bytes.length) {
    out['content-digest'] = `sha-256=:${b64(await crypto.subtle.digest('SHA-256', bytes))}:`;
    comps.push('content-digest');
    lines.push(`"content-digest": ${out['content-digest']}`);
  }
  const n = nonce || b64u(crypto.getRandomValues(new Uint8Array(24)));
  const params = `(${comps.map(sf).join(' ')});created=${now};expires=${now + expiresIn};keyid=${sf(kid)};alg="ed25519";nonce=${sf(n)};tag=${sf(POP_TAG)}`;
  lines.push(`"@signature-params": ${params}`);
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, te.encode(lines.join('\n')));
  out['signature-input'] = `sig1=${params}`;
  out.signature = `sig1=:${b64(sig)}:`;
  return out;
}

/** proof of possession for POST /v1/agent-keys: a signature over the text from POST /v1/agent-keys/begin */
export async function proveAgentKey(key, text) {
  if (typeof text !== 'string' || !text.startsWith('leash/agent-key-proof/v1\n')) throw new Error('not an agent key proof text');
  return b64u(await crypto.subtle.sign({ name: 'Ed25519' }, key, te.encode(text)));
}
