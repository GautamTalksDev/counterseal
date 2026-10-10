// A strict JSON reader for the MCP wrapper (counterseal mcp wrap). Zero dependencies.
//
// The wrapper decides about a message from what it reads, and forwards the original bytes. That is only safe if every other
// reader of those bytes sees the same thing, and JSON parsers disagree: some keep the first copy of a repeated member name,
// some the last, Go's encoding/json matches names without regard to case (the Kelvin sign and the long s included). So this
// reader is strict: it reports repeated member names (equal, or equal once case is folded), and the caller refuses what could
// be read two ways. It also records where values start and end, so a message can be rewritten by cutting out or replacing
// one part while every other byte (ids, numbers, _meta) stays exactly as it was sent.
//
// Same rules as the strict reader in server/src/providers.js (jsonView), plus those two additions.
export class JsonError extends Error {}

const fold = (k) => k.toUpperCase().toLowerCase();
const PLAIN = /[^"\\\u0000-\u001f]+/y;
const NUM = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const WS = /[ \t\n\r]*/y;
const ESC = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
const HEX4 = /^[0-9a-fA-F]{4}$/;

/**
 * Read one JSON value from `text` (and nothing after it).
 * @param {string} text
 * @param {{track?: number, maxDepth?: number}} [o]  track: record spans for objects and arrays nested less than this deep
 * @returns {{value: any, spans: WeakMap|null, exactDupes: Map<string, number>, foldDupes: Map<string, number>}}
 *   exactDupes: member names that appear twice in one object, anywhere. foldDupes: names that appear twice in one object
 *   only once case is folded (the folded form). Each maps the name to the shallowest depth it was repeated at (0 is the
 *   top-level object, 1 the members of its members, and so on). spans.get(container) is {start, end, elems} for an
 *   array (each element [start, end]) or {start, end, members} for an object (each member {key, start, end}, start at the
 *   opening quote of the name, end after the value), as offsets into `text`. Values that repeat a name keep the last copy.
 * @throws {JsonError} when the text is not exactly one JSON value
 */
export function parseStrict(text, { track = 0, maxDepth = 64 } = {}) {
  const s = String(text);
  let i = 0;
  const spans = track ? new WeakMap() : null;
  const exactDupes = new Map(), foldDupes = new Map();
  const note = (m, k, d) => { if (!m.has(k) || m.get(k) > d) m.set(k, d); };
  const bad = (why) => { throw new JsonError(`${why} at ${i}`); };
  const ws = () => { WS.lastIndex = i; WS.exec(s); i = WS.lastIndex; };
  const str = () => {
    i++; // the opening quote
    let out = '';
    for (;;) {
      PLAIN.lastIndex = i;
      const m = PLAIN.exec(s);
      if (m) { out += m[0]; i += m[0].length; }
      const c = s[i];
      if (c === '"') { i++; return out; }
      if (c !== '\\') bad('unterminated string or raw control character');
      const e = s[i + 1];
      if (e === 'u') {
        const h = s.slice(i + 2, i + 6);
        if (!HEX4.test(h)) bad('bad \\u escape');
        out += String.fromCharCode(parseInt(h, 16)); i += 6; continue;
      }
      if (!Object.hasOwn(ESC, e)) bad('bad escape');
      out += ESC[e]; i += 2;
    }
  };
  const val = (d) => {
    if (d > maxDepth) bad('nested too deep');
    ws();
    const c = s[i];
    if (c === '{') {
      const start = i; i++; ws();
      const ents = [], members = [], exact = new Set(), folded = new Map();
      if (s[i] === '}') { i++; const o = {}; if (spans && d < track) spans.set(o, { start, end: i, members }); return o; }
      for (;;) {
        ws();
        if (s[i] !== '"') bad('expected a member name');
        const ks = i, k = str();
        if (exact.has(k)) note(exactDupes, k, d);
        else {
          const f = fold(k);
          if (folded.has(f)) note(foldDupes, f, d);
          folded.set(f, k);
        }
        exact.add(k);
        ws();
        if (s[i] !== ':') bad('expected ":"');
        i++;
        const v = val(d + 1);
        ents.push([k, v]);
        if (spans && d < track) members.push({ key: k, start: ks, end: i });
        ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === '}') { i++; break; }
        bad('expected "," or "}"');
      }
      const o = Object.fromEntries(ents); // own data properties, so "__proto__" stays an ordinary name
      if (spans && d < track) spans.set(o, { start, end: i, members });
      return o;
    }
    if (c === '[') {
      const start = i; i++; ws();
      const arr = [], elems = [];
      if (s[i] === ']') { i++; if (spans && d < track) spans.set(arr, { start, end: i, elems }); return arr; }
      for (;;) {
        ws();
        const es = i;
        arr.push(val(d + 1));
        elems.push([es, i]);
        ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === ']') { i++; break; }
        bad('expected "," or "]"');
      }
      if (spans && d < track) spans.set(arr, { start, end: i, elems });
      return arr;
    }
    if (c === '"') return str();
    if (s.startsWith('true', i)) { i += 4; return true; }
    if (s.startsWith('false', i)) { i += 5; return false; }
    if (s.startsWith('null', i)) { i += 4; return null; }
    NUM.lastIndex = i;
    const m = NUM.exec(s);
    if (!m) bad('not a JSON value');
    i += m[0].length;
    return Number(m[0]);
  };
  const value = val(0);
  ws();
  if (i !== s.length) bad('text after the value');
  return { value, spans, exactDupes, foldDupes };
}

export const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/** a JSON-RPC id as a Map key: 1 and "1" are different ids */
export const idKey = (id) => (typeof id === 'string' ? 's:' + id : typeof id === 'number' ? 'n:' + id : null);
