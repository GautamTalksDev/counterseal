#!/usr/bin/env node
// Counterseal receipts SDK: record agent receipts in the public log and verify them offline. Zero dependencies; tested
// in Node and browsers. Everything in a receipt is public and permanent. Send hashes, not content (see hashLabel).
//
//   import { Receipts, verifyBundle, sha256hex, hashLabel } from 'counterseal-sdk';
//   const w = new Receipts({ key: process.env.RECEIPTS_KEY });
//   const [bundle] = await w.record({ agent: 'billing-bot', action: 'stripe.refund', input_sha256: await sha256hex(JSON.stringify(args)) });
//   await verifyBundle(bundle, VERIFIER_KEY);   // true, or throws with the reason
//
// Bundles from record() are shareable: the owner opening (account id, key id, salt) is removed unless keepOpening is set.
//
// CLI:  receipts verify bundle.json [--key <verifier key>]
//       receipts prove-signer <challenge> --origin <log origin> --account <account id> --jwk <ed25519 private key JWK file>
const te = new TextEncoder();
const std = (b) => btoa(String.fromCharCode(...b));
const unstd = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const DASH = '—'; // signed-note signature lines start with U+2014 (protocol-mandated)
async function sha(...parts) {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const buf = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { buf.set(p, o); o += p.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
}
const leafHash = (data) => sha(Uint8Array.of(0), data);
const nodeHash = (l, r) => sha(Uint8Array.of(1), l, r);

const isPow2 = (n) => n > 0 && (n & (n - 1)) === 0;
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const nat = (n) => Number.isSafeInteger(n) && n >= 0; // indexes and sizes: never -1, 0.5 or "0"

/** RFC 9162 2.1.3.2: verify an inclusion proof against a root */
export async function verifyInclusion(index, size, leaf, proof, root) {
  if (!nat(index) || !nat(size) || index >= size) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else r = await nodeHash(r, p);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && eq(r, root);
}

/** RFC 9162 2.1.4.2: verify a consistency proof between two roots */
export async function verifyConsistency(m, n, oldRoot, newRoot, proof) {
  if (!nat(m) || !nat(n)) return false;
  if (m === n) return proof.length === 0 && eq(oldRoot, newRoot);
  if (m === 0 || m > n || proof.length === 0) return false;
  let p = [...proof];
  if (isPow2(m)) p = [oldRoot, ...p];
  let fn = m - 1, sn = n - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = p[0], sr = p[0];
  for (const c of p.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr); sr = await nodeHash(c, sr);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else sr = await nodeHash(sr, c);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && eq(fr, oldRoot) && eq(sr, newRoot);
}

/** verify a checkpoint note with a verifier key "name+hash+base64(0x01||pub)"; returns {origin, size, root} */
export async function verifyCheckpoint(note, vkey) {
  if (typeof note !== 'string') throw new Error('checkpoint missing');
  if (typeof vkey !== 'string') throw new Error('verifier key missing');
  const i1 = vkey.indexOf('+'), i2 = vkey.indexOf('+', i1 + 1);
  if (i1 < 1 || i2 !== i1 + 9) throw new Error('bad verifier key');
  const name = vkey.slice(0, i1), keyb64 = vkey.slice(i2 + 1);
  const keyBytes = unstd(keyb64);
  if (keyBytes[0] !== 1 || keyBytes.length !== 33) throw new Error('bad verifier key');
  const pub = await crypto.subtle.importKey('raw', keyBytes.slice(1), { name: 'Ed25519' }, false, ['verify']);
  const i = note.indexOf('\n\n');
  if (i < 0) throw new Error('malformed note');
  const body = note.slice(0, i + 1);
  const id = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...te.encode(name + '\n'), 1, ...keyBytes.slice(1)]))).slice(0, 4);
  let ok = false;
  for (const line of note.slice(i + 2).split('\n')) {
    if (!line.startsWith(DASH + ' ' + name + ' ')) continue;
    const raw = unstd(line.slice(name.length + 3));
    if (raw.length !== 68 || !raw.slice(0, 4).every((x, j) => x === id[j])) continue;
    if (await crypto.subtle.verify({ name: 'Ed25519' }, pub, raw.slice(4), te.encode(body))) ok = true;
  }
  if (!ok) throw new Error('signature does not verify');
  const [origin, size, root] = body.split('\n');
  if (origin !== name) throw new Error('origin mismatch');
  if (!/^(0|[1-9][0-9]{0,15})$/.test(size) || !nat(Number(size))) throw new Error('bad checkpoint size');
  const r = /^[A-Za-z0-9+/]{43}=$/.test(root) ? unstd(root) : null;
  if (!r || r.length !== 32) throw new Error('bad checkpoint root');
  return { origin, size: Number(size), root: r };
}


/** deterministic JSON (sorted keys), the encoding the log hashes */
export function canonical(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'number' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}

export async function sha256hex(data) {
  const b = typeof data === 'string' ? te.encode(data) : data;
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', b))].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/** a label safe to publish: 'sha256:' + hex SHA-256 of (salt + newline + text), or of text alone without a salt.
 *  Use a secret salt for guessable labels (customer ids, file names), or anyone can confirm a guess. */
export async function hashLabel(text, salt) {
  if (typeof text !== 'string') throw new Error('hashLabel takes a string');
  return 'sha256:' + (await sha256hex(salt === undefined ? text : salt + '\n' + text));
}

/** the public submitter commitment in a v2 entry, from the owner's opening (account id, key id, salt) */
export const submitterCommitment = (o) => sha256hex(`witness/submitter/v2\n${o.account_id}\n${o.key_id}\n${o.salt}`);

/** a copy of a bundle safe to hand to others. The opening (account id, key id, salt) links the entry to your account
 *  and links your entries to each other; it is removed unless keepOpening is true. */
export function shareableBundle(b, { keepOpening = false } = {}) {
  const { opening, ...rest } = b;
  return keepOpening && opening ? { ...rest, opening } : rest;
}

const b64url = (b) => std(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** text from a bundle made safe to print: control, bidi, zero-width and separator characters become \u{...} escapes */
export const printable = (v) => String(v).replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/gu, (c) => `\\u{${c.codePointAt(0).toString(16)}}`);

/** the text a signer proof signs: it names the log origin and the account the key is being bound to */
export const signerProofText = (challenge, signerPublicKey, { origin, account } = {}) => {
  if (typeof origin !== 'string' || !origin || typeof account !== 'string' || !account) throw new Error('signer proofs name the log origin and the account (both from POST /v1/keys/signer/begin)');
  return `witness/signer-proof/v2\n${origin}\n${account}\n${challenge}\n${signerPublicKey}`;
};

/** proof that you hold an Ed25519 private key, for binding its public key to an API key (POST /v1/keys/signer/begin
 *  returns challenge, origin and account) */
export async function signerProof(privateKey, challenge, signerPublicKey, { origin, account } = {}) {
  const text = signerProofText(challenge, signerPublicKey, { origin, account });
  return b64url(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, te.encode(text))));
}

/** verify a receipt bundle offline against the verifier key you pin (GET /v1/log/key). The bundle's own `log` field is
 *  only a hint: anyone can make a key, so it is never trusted, and a bundle naming a different key is refused. */
export async function verifyBundle(b, verifierKey) {
  if (!b || typeof b !== 'object' || !b.entry || !Array.isArray(b.inclusion_proof)) throw new Error('not a receipt bundle');
  if (typeof verifierKey !== 'string') throw new Error('verifier key missing: pin the log key you trust (GET /v1/log/key)');
  if (b.log !== undefined && b.log !== verifierKey) throw new Error('this bundle names a different log key than the one you pinned');
  if (!nat(b.index) || !nat(b.tree_size) || !b.inclusion_proof.every((x) => typeof x === 'string')) throw new Error('bad index, tree size or proof');
  const cp = await verifyCheckpoint(b.checkpoint, verifierKey);
  if (cp.size !== b.tree_size) throw new Error('tree size does not match the checkpoint');
  const leaf = await leafHash(te.encode(canonical(b.entry)));
  if (std(leaf) !== b.leaf_hash) throw new Error('entry does not match its leaf hash');
  if (!(await verifyInclusion(b.index, cp.size, leaf, b.inclusion_proof.map(unstd), cp.root))) throw new Error('inclusion proof does not verify');
  // optional: the owner's opening must match the public commitment
  if (b.opening && (await submitterCommitment(b.opening)) !== b.entry.submitter) throw new Error('opening does not match the submitter commitment');
  // source "broker": written by the broker itself for a decision it made (no API key holder can set it); otherwise the
  // receipt is what an agent reported about its own action
  return { ok: true, index: b.index, treeSize: cp.size, origin: cp.origin, receipt: b.entry.receipt, receivedAt: b.entry.received_at, ownerProved: !!b.opening, broker: b.entry.source === 'broker' };
}

/** prove a later checkpoint extends an earlier one (the log never rewrote history) */
export async function verifyExtends(oldNote, newNote, proofB64, verifierKey) {
  const a = await verifyCheckpoint(oldNote, verifierKey), b = await verifyCheckpoint(newNote, verifierKey);
  if (!(await verifyConsistency(a.size, b.size, a.root, b.root, proofB64.map(unstd)))) throw new Error('consistency proof does not verify');
  return true;
}

export class Receipts {
  constructor({ key, url = 'https://leash.gautamkhosla.com', signer, keepOpening = false } = {}) {
    if (!key || !/^lsr_/.test(key)) throw new Error('a receipts API key (lsr_...) is required');
    this.key = key; this.url = url.replace(/\/+$/, ''); this.signer = signer; // signer: CryptoKey (Ed25519 private) if the key requires signatures
    this.keepOpening = keepOpening; // true keeps the owner opening in returned bundles (do not share those)
  }
  async record(...receipts) {
    const list = receipts.flat();
    if (this.signer) for (const r of list) {
      if (r.ts === undefined) r.ts = Date.now(); // signed receipts need a ts within 10 minutes of the server clock; each signature is accepted once
      const { sig, ...rest } = r;
      r.sig = { alg: 'ed25519', value: b64url(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, this.signer, te.encode(canonical(rest))))) };
    }
    const res = await fetch(this.url + '/v1/receipts', { method: 'POST', redirect: 'error', headers: { authorization: 'Bearer ' + this.key, 'content-type': 'application/json' }, body: JSON.stringify({ receipts: list }) });
    const j = await res.json();
    if (!res.ok) throw new Error(j.message || j.error);
    return j.receipts.map((b) => shareableBundle(b, { keepOpening: this.keepOpening }));
  }
}

// ---- CLI. A verifier must never exit 0 without having verified something.
const USAGE = `receipts: verify Counterseal receipt bundles offline

  receipts verify <bundle.json> --key <verifier key>    exit 0 verified, 1 not verified
  receipts hash <text> [--salt <salt>]                   print a label hash to publish instead of the text
  receipts prove-signer <challenge> --origin <log origin> --account <account id> --jwk <file>
                                                         sign a key binding challenge with an Ed25519 private JWK

Pin the log's verifier key with --key (GET /v1/log/key). Without --key the bundle is checked only against the key
it carries, which anyone can make: that prints VERIFIED (UNPINNED KEY) and exits 3. Usage errors exit 2.`;

/** runs the CLI; returns the exit code */
export async function cli(args, out = console.log, err = console.error) {
  const opt = (name) => { const i = args.indexOf(name); if (i < 0) return undefined; const v = args[i + 1]; if (!v || v.startsWith('--')) throw new Error(`${name} needs a value`); args.splice(i, 2); return v; };
  try {
    const cmd = args.shift();
    if (cmd === 'help' || cmd === '--help' || cmd === '-h') { out(USAGE); return 0; }
    if (cmd === 'hash') {
      const salt = opt('--salt');
      if (args.length !== 1) throw new Error('hash takes exactly one text argument');
      out(await hashLabel(args[0], salt));
      return 0;
    }
    if (cmd === 'prove-signer') {
      const file = opt('--jwk'), origin = opt('--origin'), account = opt('--account');
      if (!file || !origin || !account || args.length !== 1) throw new Error('prove-signer takes one challenge, --origin <log origin>, --account <account id> and --jwk <file>');
      if (!/^[\x21-\x7e]{1,200}$/.test(origin) || !/^[0-9a-f]{24}$/.test(account) || !/^[A-Za-z0-9_-]{1,100}$/.test(args[0])) throw new Error('bad challenge, origin or account');
      const { readFileSync } = await import('node:fs');
      const jwk = JSON.parse(readFileSync(file, 'utf8'));
      const key = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', d: jwk.d, x: jwk.x }, { name: 'Ed25519' }, false, ['sign']);
      // say exactly what is being authorized before signing it
      err(`Binding Ed25519 public key ${printable(jwk.x)} to Counterseal account ${account} on log ${origin}. Only paste the proof into that account.`);
      out(await signerProof(key, args[0], jwk.x, { origin, account }));
      return 0;
    }
    if (cmd !== 'verify') throw new Error(cmd ? `unknown command: ${cmd}` : 'no command given');
    const key = opt('--key');
    if (args.length !== 1) throw new Error('verify takes exactly one bundle file');
    let b;
    try {
      const { readFileSync } = await import('node:fs');
      b = JSON.parse(readFileSync(args[0], 'utf8'));
    } catch (e) { err('NOT VERIFIED: ' + (e instanceof SyntaxError ? 'the file is not valid JSON' : 'cannot read ' + args[0])); return 1; }
    try {
      const r = await verifyBundle(b, key ?? b?.log);
      const rc = r.receipt || {}, p = printable;
      out(`${key ? 'VERIFIED ' : 'VERIFIED (UNPINNED KEY)'} entry #${r.index} of ${r.treeSize} in ${p(r.origin)}
  ${p(rc.agent)}: ${p(rc.action)}${rc.decision ? ' (' + p(rc.decision) + ')' : ''}${r.broker ? '\n  recorded by the broker itself, not reported by an agent' : ''}
  received ${Number.isFinite(r.receivedAt) ? new Date(r.receivedAt).toISOString() : 'unknown'}${r.ownerProved ? '\n  owner opening matches the submitter commitment' : ''}`);
      if (key) return 0;
      out('  Checked only against the key inside the bundle, which anyone can make. Pass --key <verifier key> (GET /v1/log/key) to check it is the real log.');
      return 3;
    } catch (e) { err('NOT VERIFIED: ' + e.message); return 1; }
  } catch (e) { err('receipts: ' + e.message + '\n\n' + USAGE); return 2; }
}

// Run as a program (also through an npm bin symlink): compare real paths, not file names.
if (typeof process !== 'undefined' && process.versions?.node && process.argv?.[1] && import.meta.url?.startsWith('file:')) {
  const { realpathSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  let main = false;
  try { main = realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { main = false; }
  if (main) process.exitCode = await cli(process.argv.slice(2));
}

/** the name this class had before the merge */
export const Witness = Receipts; // brand:history
