// RFC 6962 / RFC 9162 Merkle tree hashing, inclusion and consistency proofs.
// leaf hash  = SHA-256(0x00 || data);  node hash = SHA-256(0x01 || left || right)
// The tree is stored as "perfect subtree" nodes: node(level, index) covers leaves [index * 2^level, (index + 1) * 2^level).
// Every range the RFC algorithms ask for decomposes into such aligned perfect subtrees, so proofs need only stored nodes.

export async function sha(...parts) {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const buf = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { buf.set(p, o); o += p.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
}
export const leafHash = (data) => sha(Uint8Array.of(0), data);
export const nodeHash = (l, r) => sha(Uint8Array.of(1), l, r);

/** largest power of two strictly less than n (n >= 2) */
export function split(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

const isPow2 = (n) => n > 0 && (n & (n - 1)) === 0;
const log2 = (n) => 31 - Math.clz32(n);

/** after appending leaf `index` with hash `h`, the perfect-subtree nodes that become complete: [[level, idx, hash], ...] */
export async function appendNodes(index, h, getNode) {
  const out = [[0, index, h]];
  let level = 0, idx = index, cur = h;
  while (idx % 2 === 1) {
    const left = await getNode(level, idx - 1);
    cur = await nodeHash(left, cur);
    level++; idx = (idx - 1) / 2;
    out.push([level, idx, cur]);
  }
  return out;
}

/** MTH of leaves [start, start + size) using stored perfect nodes */
export async function mth(start, size, getNode) {
  if (size === 0) return sha();
  if (isPow2(size) && start % size === 0) return getNode(log2(size), start / size);
  const k = split(size);
  return nodeHash(await mth(start, k, getNode), await mth(start + k, size - k, getNode));
}

/** RFC 6962 2.1.1 PATH(m, D[start:start+n]) */
export async function inclusionProof(m, n, getNode, start = 0) {
  if (m < 0 || m >= n) throw new RangeError('index out of range');
  if (n === 1) return [];
  const k = split(n);
  if (m < k) return [...(await inclusionProof(m, k, getNode, start)), await mth(start + k, n - k, getNode)];
  return [...(await inclusionProof(m - k, n - k, getNode, start + k)), await mth(start, k, getNode)];
}

/** RFC 6962 2.1.2 PROOF(m, D[n]) */
export async function consistencyProof(m, n, getNode) {
  if (m <= 0 || m > n) throw new RangeError('bad sizes');
  if (m === n) return [];
  const sub = async (m, n, b, start) => {
    if (m === n) return b ? [] : [await mth(start, n, getNode)];
    const k = split(n);
    if (m <= k) return [...(await sub(m, k, b, start)), await mth(start + k, n - k, getNode)];
    return [...(await sub(m - k, n - k, false, start + k)), await mth(start, k, getNode)];
  };
  return sub(m, n, true, 0);
}

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const nat = (n) => Number.isSafeInteger(n) && n >= 0;

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
