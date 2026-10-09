// The homepage demo's engine. Everything runs in this tab with WebCrypto: a throwaway Ed25519 agent key, a real RFC 9421
// request signature, the broker's own signature checks, a private hash-chained audit log, broker receipts and a small
// RFC 6962 Merkle log with C2SP signed checkpoints under a throwaway demo log key. Nothing is sent anywhere.
//
// Ported from the broker so the demo behaves like the real thing:
//   signRequest       cli/sign.mjs signBrokerRequest (profile tag "leash-pop")
//   verifyAgentSig    server/src/agentkeys.js verifyAgentSignature (same checks, same error codes and messages)
//   auditHash         server/src/audit.js
//   brokerReceipt     server/src/ledger.js brokerReceipt, entries as in sealDecision
// Verification uses the site's copies of the published SDK: /websig.js and /receipts-sdk.js.
import { parseDictionary, signatureBase } from '/websig.js';
import { canonical, verifyBundle, verifyCheckpoint, verifyConsistency, verifyInclusion } from '/receipts-sdk.js';

const te = new TextEncoder();
export const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
export const b64u = (b) => b64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const unstd = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? te.encode(data) : data));
export const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
export const sha256hex = async (s) => hex(await sha256(s));
const sf = (s) => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
const cat = (...parts) => { const n = parts.reduce((s, p) => s + p.length, 0), o = new Uint8Array(n); let i = 0; for (const p of parts) { o.set(p, i); i += p.length; } return o; };

export const MAP_VERSION = '2026-10-09.1';
export const POP_TAG = 'leash-pop';
export const ORIGIN = 'https://counterseal.gautamkhosla.com';

/** True when this browser can make Ed25519 keys (WebCrypto). */
export async function canEd25519() {
  try { await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']); return true; } catch { return false; }
}

// ------------------------------------------------------------------ agent keys (Prove who)
export async function newAgentKey() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const keyid = b64u(await sha256(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })));
  return { privateKey: kp.privateKey, x: jwk.x, keyid, bytes: fromB64u(jwk.x) };
}

/** cli/sign.mjs signBrokerRequest: covers @method, @target-uri and, with a body, content-digest and content-type */
export async function signRequest({ method, url, body, contentType }, { key, kid, now = Math.floor(Date.now() / 1000), expiresIn = 60, nonce } = {}) {
  const bytes = body == null ? new Uint8Array(0) : te.encode(body);
  const target = new URL(url).href;
  const out = {};
  const comps = ['@method', '@target-uri'];
  const lines = [`"@method": ${method.toUpperCase()}`, `"@target-uri": ${target}`];
  if (bytes.length) {
    out['content-digest'] = `sha-256=:${b64(await sha256(bytes))}:`;
    comps.push('content-digest'); lines.push(`"content-digest": ${out['content-digest']}`);
    if (contentType) { comps.push('content-type'); lines.push(`"content-type": ${contentType.trim()}`); }
  }
  const n = nonce || b64u(crypto.getRandomValues(new Uint8Array(24)));
  const params = `(${comps.map(sf).join(' ')});created=${now};expires=${now + expiresIn};keyid=${sf(kid)};alg="ed25519";nonce=${sf(n)};tag=${sf(POP_TAG)}`;
  lines.push(`"@signature-params": ${params}`);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key, te.encode(lines.join('\n'))));
  out['signature-input'] = `sig1=${params}`;
  out.signature = `sig1=:${b64(sig)}:`;
  return { headers: out, sig, nonce: n, created: now, expires: now + expiresIn };
}

export class BrokerError extends Error {
  constructor(status, code, message, extra) { super(message); this.status = status; this.code = code; this.extra = extra; }
  json() { return { error: this.code, message: this.message, ...(this.extra || {}) }; }
}
const POP_WINDOW = 300;
const ALLOWED = new Set(['@method', '@target-uri', '@authority', '@path', '@query', 'content-digest', 'content-type']);
const NONCE = /^[A-Za-z0-9+/=_-]{8,128}$/;
const bad = (reason) => new BrokerError(401, 'bad_agent_signature', `Agent signature refused: ${reason}.`, { reason });

/** server/src/agentkeys.js verifyAgentSignature, step for step. request: {method, url, headers: Headers}; body: bytes */
export async function verifyAgentSig(request, body, key, seen, nowS = Math.floor(Date.now() / 1000)) {
  const si = request.headers.get('signature-input'), sg = request.headers.get('signature');
  if (!si || !sg) throw new BrokerError(401, 'agent_signature_required', 'This token is bound to an agent key, so every request must be signed with it (RFC 9421, tag "leash-pop").');
  if (si.length > 4096 || sg.length > 4096) throw bad('signature headers too long');
  let inputs, sigs;
  try { inputs = parseDictionary(si); sigs = parseDictionary(sg); } catch { throw bad('malformed Signature-Input or Signature'); }
  let found = null;
  for (const [label, input] of inputs) {
    if (input.params.tag !== POP_TAG) continue;
    if (found) throw bad('more than one leash-pop signature');
    found = [label, input];
  }
  if (!found) throw new BrokerError(401, 'agent_signature_required', 'No signature with tag "leash-pop" on this request.');
  const [label, input] = found, p = input.params, comps = input.list;
  if (!comps || !comps.length) throw bad('no covered components');
  const names = [];
  for (const c of comps) {
    if (typeof c.value !== 'string' || !ALLOWED.has(c.value) || Object.keys(c.params || {}).length) throw bad(`component ${JSON.stringify(String(c.value)).slice(0, 40)} is not allowed`);
    if (names.includes(c.value)) throw bad('a component is covered twice');
    names.push(c.value);
  }
  for (const r of ['@method', '@target-uri']) if (!names.includes(r)) throw bad(`must cover ${r}`);
  if (body && body.length && !names.includes('content-digest')) throw bad('a request with a body must cover content-digest');
  if (body && body.length && request.headers.get('content-type') && !names.includes('content-type')) throw bad('a request with a body must cover content-type');
  if (!Number.isInteger(p.created) || !Number.isInteger(p.expires)) throw bad('created and expires are required');
  if (p.expires <= p.created) throw bad('expires must be after created');
  if (p.expires - p.created > POP_WINDOW) throw bad(`window longer than ${POP_WINDOW} seconds`);
  if (p.created > nowS + 60) throw bad('created in the future');
  if (p.expires < nowS) throw bad('expired');
  if (p.alg !== undefined && p.alg !== 'ed25519') throw bad('alg must be ed25519');
  if (p.keyid !== key.keyid) throw bad('keyid is not the agent key bound to this token');
  if (typeof p.nonce !== 'string' || !NONCE.test(p.nonce)) throw bad('a nonce of 8 to 128 base64 characters is required');
  const s = sigs.get(label);
  if (!s || !s.value || typeof s.value.bytes !== 'string') throw bad('missing signature bytes');
  let base;
  try { base = signatureBase({ method: request.method, url: request.url, headers: request.headers }, comps.map((c) => ({ value: c.value, params: {} })), input.raw); }
  catch (e) { throw bad(String(e.message).slice(0, 80)); }
  let sigBytes;
  try { sigBytes = fromB64u(s.value.bytes); } catch { throw bad('signature is not base64'); }
  if (sigBytes.length !== 64) throw bad('signature must be 64 bytes');
  const pub = await crypto.subtle.importKey('raw', fromB64u(key.x), { name: 'Ed25519' }, false, ['verify']);
  if (!(await crypto.subtle.verify({ name: 'Ed25519' }, pub, sigBytes, te.encode(base)))) throw bad('signature does not verify');
  if (names.includes('content-digest')) {
    let d;
    try { d = parseDictionary(request.headers.get('content-digest') || ''); } catch { throw bad('malformed Content-Digest'); }
    const m = d.get('sha-256');
    if (!m || !m.value || typeof m.value.bytes !== 'string') throw bad('Content-Digest must carry sha-256');
    let want;
    try { want = fromB64u(m.value.bytes); } catch { throw bad('malformed Content-Digest'); }
    if (b64(want) !== b64(await sha256(body || new Uint8Array(0)))) throw bad('Content-Digest does not match the body');
  }
  if (await seen(`${key.keyid} ${p.nonce}`)) throw new BrokerError(401, 'agent_signature_replayed', 'This signature was already used. Sign each request with a fresh nonce.');
  return { keyid: key.keyid, base };
}

// ------------------------------------------------------------------ RFC 6962 Merkle log with signed checkpoints (Record)
const leafHash = (data) => sha256(cat(Uint8Array.of(0), data));
const nodeHash = (l, r) => sha256(cat(Uint8Array.of(1), l, r));
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };

export class DemoLog {
  constructor(name) { this.name = name; this.entries = []; this.leaves = []; this.cache = new Map(); }
  async init() {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    this.priv = kp.privateKey;
    const pub = fromB64u((await crypto.subtle.exportKey('jwk', kp.publicKey)).x);
    this.id = (await sha256(cat(te.encode(this.name + '\n'), Uint8Array.of(1), pub))).slice(0, 4);
    this.vkey = `${this.name}+${hex(this.id)}+${b64(cat(Uint8Array.of(1), pub))}`;
    return this;
  }
  get size() { return this.leaves.length; }
  async append(entryObj) {
    const text = canonical(entryObj);
    this.entries.push(entryObj);
    this.leaves.push(await leafHash(te.encode(text)));
    this.cache.clear();
    return this.leaves.length - 1;
  }
  async mth(start, n) {
    const k = start + ':' + n;
    if (this.cache.has(k)) return this.cache.get(k);
    let h;
    if (n === 0) h = await sha256(new Uint8Array(0));
    else if (n === 1) h = this.leaves[start];
    else { const s = split(n); h = await nodeHash(await this.mth(start, s), await this.mth(start + s, n - s)); }
    this.cache.set(k, h);
    return h;
  }
  root(n = this.size) { return this.mth(0, n); }
  /** RFC 6962 2.1.1 PATH(m, D[n]) */
  async inclusion(m, n = this.size, start = 0) {
    if (n === 1) return [];
    const k = split(n);
    if (m < k) return [...(await this.inclusion(m, k, start)), await this.mth(start + k, n - k)];
    return [...(await this.inclusion(m - k, n - k, start + k)), await this.mth(start, k)];
  }
  /** RFC 6962 2.1.2 PROOF(m, D[n]) */
  async consistency(m, n = this.size) {
    if (m === n) return [];
    const sub = async (m, n, b, start) => {
      if (m === n) return b ? [] : [await this.mth(start, n)];
      const k = split(n);
      if (m <= k) return [...(await sub(m, k, b, start)), await this.mth(start + k, n - k)];
      return [...(await sub(m - k, n - k, false, start + k)), await this.mth(start, k)];
    };
    return sub(m, n, true, 0);
  }
  /** a C2SP signed note over (name, size, root). The signature line starts with U+2014, as the format requires. */
  async checkpoint(n = this.size) {
    const body = `${this.name}\n${n}\n${b64(await this.root(n))}\n`;
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, this.priv, te.encode(body)));
    return { note: `${body}\n\u2014 ${this.name} ${b64(cat(this.id, sig))}\n`, size: n, sig };
  }
  /** a bundle in the exact shape the broker returns, verified with the SDK's verifyBundle */
  async bundle(index, cp) {
    return { index, leaf_hash: b64(this.leaves[index]), tree_size: cp.size, inclusion_proof: (await this.inclusion(index, cp.size)).map(b64), checkpoint: cp.note, entry: this.entries[index], log: this.vkey };
  }
}

export const verify = { bundle: verifyBundle, checkpoint: verifyCheckpoint, consistency: (m, n, a, b, proof) => verifyConsistency(m, n, a, b, proof), inclusion: verifyInclusion, unstd };

// ------------------------------------------------------------------ the broker's records (Approve + Record)
/** server/src/audit.js: each entry commits to the one before it */
export const auditHash = (prev, account, at, actor, action, detailJson) => sha256hex(`${prev}|${account}|${at}|${actor}|${action}|${detailJson}`);
export const DECISION = { proxy: 'allowed', hold: 'held', deny: 'denied', approve: 'approved', proxy_approved: 'executed' };

/** server/src/ledger.js brokerReceipt: fixed vocabulary only, never a path, body, key, token, name, email or IP */
export function brokerReceipt({ action, detail, auditHash: parent, at }) {
  const method = /^[A-Z]{3,7}$/.test(detail.method || '') ? detail.method : null;
  const host = /^[a-z0-9.-]{1,100}$/.test(detail.host || '') ? detail.host : null;
  const meta = { map: MAP_VERSION };
  if (detail.rule) meta.rule = detail.rule;
  if (detail.agent_key) meta.agent_key = true;
  if (detail.passkey) meta.passkey = true;
  return { agent: 'broker', action: method && host ? `${method} ${host}` : action === 'approve' ? 'approve' : 'decision', decision: DECISION[action], parent, ts: at, meta };
}

/** One demo account: a private audit chain, and receipts sealed into the demo log (as sealDecision does). */
export class DemoAccount {
  constructor(log) { this.log = log; this.id = hex(crypto.getRandomValues(new Uint8Array(12))); this.prev = '0'.repeat(64); this.audit = []; }
  async record(actor, action, detail) {
    const at = Date.now(), d = JSON.stringify(detail);
    const hash = await auditHash(this.prev, this.id, at, actor, action, d);
    this.audit.push({ at, actor, action, detail, prev: this.prev, hash });
    this.prev = hash;
    if (!DECISION[action]) return { hash };
    const receipt = brokerReceipt({ action, detail, auditHash: hash, at });
    const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
    const submitter = await sha256hex(`witness/submitter/v2\n${this.id}\nbroker\n${salt}`);
    const index = await this.log.append({ v: 2, source: 'broker', submitter, received_at: at, receipt });
    return { hash, index, receipt };
  }
}
