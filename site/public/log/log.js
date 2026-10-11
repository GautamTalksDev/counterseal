// The public log explorer. Reads only the log's public API (same origin) and checks everything here, with the same SDK
// as the verify page: the checkpoint's signature, each inclusion proof, and a consistency proof from the last checkpoint
// this browser saw. Builds DOM with createElement and textContent only.
import { verifyCheckpoint, verifyInclusion, verifyExtends, canonical, printable } from '/receipts-sdk.js';

const $ = (id) => document.getElementById(id);
const te = new TextEncoder();
const unstd = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const std = (b) => btoa(String.fromCharCode(...b));
const short = (s, n = 16) => (s && s.length > n + 1 ? s.slice(0, n) + '…' : s || '');
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) { if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else if (k.startsWith('aria-')) n.setAttribute(k, v); else n[k] = v; }
  for (const c of kids) if (c != null) n.append(c);
  return n;
}
const getJson = async (u) => { const r = await fetch(u, { headers: { accept: 'application/json' } }); if (!r.ok) throw new Error(`${u.split('?')[0]} answered ${r.status}`); return r.json(); };
const leafOf = async (entry) => new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([0, ...te.encode(canonical(entry))])));
const store = { get() { try { return JSON.parse(localStorage.getItem('cs-last-checkpoint') || 'null'); } catch { return null; } }, set(v) { try { localStorage.setItem('cs-last-checkpoint', JSON.stringify(v)); } catch { /* storage blocked: fine */ } } };

let head = null, key = null, next = 0;

async function loadHead() {
  const s = await getJson('/v1/stats');
  key = s.verifier_key; $('vk').textContent = key || 'unavailable'; $('origin').textContent = s.origin || '';
  if (!s.checkpoint) {
    $('size').textContent = '0'; $('root').textContent = 'none'; $('updated').textContent = 'never'; $('sig').textContent = 'none yet';
    $('headNote').textContent = 'The log has no entries yet. The first decision on a write will be entry #0.';
    $('list').replaceChildren(el('div', { class: 'empty', text: 'No receipts yet.' }));
    return;
  }
  const cp = await verifyCheckpoint(s.checkpoint, key);
  head = { size: cp.size, root: cp.root, note: s.checkpoint };
  $('size').textContent = cp.size.toLocaleString('en');
  $('root').textContent = short(std(cp.root), 18); $('root').title = std(cp.root);
  $('updated').textContent = s.updated_at ? new Date(s.updated_at).toLocaleString() : 'unknown';
  $('sig').textContent = 'Ed25519, verified';
  $('headNote').textContent = `The latest checkpoint's signature checks out against the verifier key below, here in your browser. It covers ${cp.size.toLocaleString('en')} entries.`;
  await since();
  next = cp.size;
  await more();
}

async function since() {
  const last = store.get(), out = $('sinceOut');
  if (last && last.key === key && Number.isSafeInteger(last.size) && last.size > 0 && last.size <= head.size) {
    out.hidden = false;
    try {
      if (last.size === head.size) {
        await verifyExtends(last.note, head.note, [], key);
        out.className = 'verdict ok'; out.textContent = `UNCHANGED\nSame ${head.size} entries as on your last visit, same root.`;
      } else {
        const p = await getJson(`/v1/log/proof/consistency?first=${last.size}&second=${head.size}`);
        await verifyExtends(last.note, head.note, p.consistency_proof, key);
        out.className = 'verdict ok'; out.textContent = `CONSISTENT\nOn your last visit the log had ${last.size} entries. It now has ${head.size}, and the consistency proof (${p.consistency_proof.length} hashes) shows every earlier entry is still there, unchanged.`;
      }
    } catch (e) {
      out.className = 'verdict bad'; out.textContent = `NOT CONSISTENT\n${e.message}\nThe checkpoint your browser kept and today's head do not fit together. Keep both and report it to developwith.gt@gmail.com.`;
      return; // keep the old checkpoint as evidence
    }
  } else if (last && last.key !== key) {
    out.hidden = false; out.className = 'verdict bad'; out.textContent = 'The log key differs from the one your browser saw last time, so the two checkpoints cannot be compared.';
    return;
  }
  store.set({ key, size: head.size, note: head.note, at: Date.now() });
}

async function more() {
  if (!head || next <= 0) return;
  const count = Math.min(50, next), start = next - count;
  const j = await getJson(`/v1/log/entries?start=${start}&count=${count}`);
  let list = $('list').querySelector('.lx-list');
  if (!list) { list = el('ul', { class: 'lx-list' }); $('list').replaceChildren(list); }
  for (const r of [...j.entries].reverse()) list.append(row(r));
  next = start;
  $('older').hidden = next <= 0;
  $('range').textContent = `Showing #${next} to #${head.size - 1}`;
}

function row(r) {
  const rc = (r.entry && r.entry.receipt) || {}, meta = rc.meta || {};
  const dec = typeof rc.decision === 'string' ? rc.decision : 'reported';
  const li = el('li');
  const btn = el('button', { class: 'lx-row', type: 'button', 'aria-expanded': 'false' },
    el('span', { class: 'ix', text: '#' + r.index }),
    el('span', {}, el('span', { class: 'dec ' + dec.replace(/[^a-z]/g, ''), text: printable(dec) })),
    el('span', { class: 'ac', text: printable(rc.action || '') + (r.entry.source === 'broker' ? '' : '  (reported by an agent)') }),
    el('span', { class: 'ru', text: printable(meta.rule || '') }),
    el('span', { class: 'tm', text: r.entry.received_at ? new Date(r.entry.received_at).toLocaleString() : '' }));
  let open = null;
  btn.addEventListener('click', () => {
    if (open) { open.remove(); open = null; btn.setAttribute('aria-expanded', 'false'); return; }
    btn.setAttribute('aria-expanded', 'true');
    const verdict = el('pre', { class: 'verdict', hidden: true });
    const prove = el('button', { class: 'btn btn-pri sm', type: 'button', text: 'Prove it is in the log' });
    prove.addEventListener('click', () => proveRow(r, verdict));
    open = el('div', { class: 'lx-detail' }, el('pre', { text: JSON.stringify(r.entry, null, 2) }), prove, verdict);
    li.append(open);
  });
  li.append(btn);
  return li;
}

async function proveRow(r, out) {
  out.hidden = false;
  try {
    const leaf = await leafOf(r.entry);
    if (std(leaf) !== r.leaf_hash) throw new Error('the entry does not match its leaf hash');
    const p = await getJson(`/v1/log/proof/inclusion?index=${r.index}&size=${head.size}`);
    const ok = await verifyInclusion(r.index, head.size, leaf, p.inclusion_proof.map(unstd), head.root);
    if (!ok) throw new Error('the inclusion proof does not verify');
    out.className = 'verdict ok';
    out.textContent = `VERIFIED\nentry #${r.index} of ${head.size}\nleaf ${short(r.leaf_hash, 24)}\n${p.inclusion_proof.map((h, i) => `proof ${i + 1} ${short(h, 24)}`).join('\n')}\nroot ${short(std(head.root), 24)}, signed in the checkpoint above.`;
  } catch (e) {
    out.className = 'verdict bad'; out.textContent = 'NOT VERIFIED\n' + e.message;
  }
}

$('older').addEventListener('click', () => more().catch((e) => { $('range').textContent = e.message; }));
$('copyVk').addEventListener('click', async () => { try { await navigator.clipboard.writeText(key || ''); $('copyVk').textContent = 'Copied'; } catch { /* the key is shown above */ } });
loadHead().catch((e) => {
  $('headNote').textContent = 'The log could not be read right now: ' + e.message + '. Reload to try again.';
  for (const id of ['size', 'root', 'updated', 'sig']) $(id).textContent = 'n/a';
  $('list').replaceChildren(el('div', { class: 'empty', text: 'Receipts appear here once the log can be read.' }));
});
