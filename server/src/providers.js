// Upstream APIs LEASH can broker, and the map of operations that cannot be undone.
// The irreversible map is the product: each rule names a real way an agent can destroy something, with the incident
// or doc it comes from. Rules match on method + path (glob) and, where the danger is in the body, on the body.
// Body checks fail closed: a body LEASH cannot read on a route that has a body rule is held.
// Version it; every change must come with a test in test/bypass.test.js, test/hardening.test.js or test/leash.test.js.
import { BRAND } from './brand.js';
export const MAP_VERSION = '2026-10-10.1';

// ---------------------------------------------------------------- strict JSON
// JSON parsers disagree on repeated keys (first copy wins, last copy wins, error), and some match keys without regard
// to case (Go's encoding/json folds case, including the Kelvin sign and the long s). So the view the rules read is
// strict: an object with two keys that are equal, or equal once case is folded, is unreadable; keys are folded to
// lower case; nesting deeper than 64 is unreadable. Returns undefined when the text is not one clean JSON value.
const fold = (k) => k.toUpperCase().toLowerCase();
const NO = Symbol('unreadable');
const PLAIN = /[^"\\\u0000-\u001f]+/y, NUM = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/y;
const ESC = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
let memoIn, memoOut; // several rules read the same body; parse it once
export function jsonView(text) {
  const s = String(text ?? '');
  if (s === memoIn) return memoOut;
  const v = parseStrict(s);
  memoIn = s; memoOut = v;
  return v;
}
function parseStrict(s) {
  let i = 0;
  const ws = () => { while (s[i] === ' ' || s[i] === '\t' || s[i] === '\n' || s[i] === '\r') i++; };
  const str = () => {
    let out = '';
    i++;
    for (;;) {
      PLAIN.lastIndex = i;
      const m = PLAIN.exec(s);
      if (m) { out += m[0]; i += m[0].length; }
      if (s[i] === '"') { i++; return out; }
      if (s[i] !== '\\') throw NO; // end of text or a raw control character
      const e = s[i + 1];
      if (e === 'u') { const h = s.slice(i + 2, i + 6); if (!/^[0-9a-fA-F]{4}$/.test(h)) throw NO; out += String.fromCharCode(parseInt(h, 16)); i += 6; continue; }
      if (!Object.hasOwn(ESC, e)) throw NO;
      out += ESC[e]; i += 2;
    }
  };
  const val = (d) => {
    if (d > 64) throw NO;
    ws();
    if (s[i] === '{') {
      i++; ws();
      const ents = [], seen = new Set();
      if (s[i] === '}') { i++; return {}; }
      for (;;) {
        ws();
        if (s[i] !== '"') throw NO;
        const k = fold(str());
        if (seen.has(k)) throw NO;
        seen.add(k);
        ws();
        if (s[i] !== ':') throw NO;
        i++;
        ents.push([k, val(d + 1)]);
        ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === '}') { i++; return Object.fromEntries(ents); } // own data properties, so "__proto__" stays a plain key
        throw NO;
      }
    }
    if (s[i] === '[') {
      i++; ws();
      const arr = [];
      if (s[i] === ']') { i++; return arr; }
      for (;;) { arr.push(val(d + 1)); ws(); if (s[i] === ',') { i++; continue; } if (s[i] === ']') { i++; return arr; } throw NO; }
    }
    if (s[i] === '"') return str();
    NUM.lastIndex = i;
    const m = NUM.exec(s);
    if (!m) throw NO;
    i += m[0].length;
    return m[0] === 'true' ? true : m[0] === 'false' ? false : m[0] === 'null' ? null : Number(m[0]);
  };
  try { const v = val(0); ws(); return i === s.length ? v : undefined; } catch (e) { if (e === NO) return undefined; throw e; }
}
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

// ---------------------------------------------------------------- form and query parameters
// Form and query parsers disagree too. Rack (Ruby) lets the last copy of a key win where others take the first; Rack 2
// also splits query strings on ";", drops spaces after a separator, strips leading brackets from a name and reads
// "a[b]" or "a[]" as nested. So the rules read every copy of a watched name, under a split on "&" and a split on "&"
// or ";", from the query string, the form body and (when it is one) the JSON body. Names are folded to lower case.
const SPLITS = [/&/, /[&;]/];
// form decoding exactly as URLSearchParams does it ("+" is a space, a bad escape is kept as is)
const formDecode = (s) => new URLSearchParams('x=' + s).get('x');
function formCopies(src, want, sep) {
  const out = [];
  for (const part of String(src || '').replace(/^\?/, '').split(sep)) {
    if (!part) continue;
    const eq = part.indexOf('=');
    const raw = eq < 0 ? part : part.slice(0, eq);
    const k = /[%+]/.test(raw) ? formDecode(raw) : raw;
    const s = k.replace(/^[\s[\]]+/, ''), cut = s.search(/[[\]]/);
    const base = (cut < 0 ? s : s.slice(0, cut)).trim();
    if (base.length > 64) continue; // longer than any watched name (checked before folding, which costs on a huge key)
    const name = fold(base);
    // odd: brackets, spaces or a different case; a server may read it as the watched name, or as something else.
    // Values are decoded only for watched names.
    if (want.has(name)) out.push({ name, value: eq < 0 ? '' : formDecode(part.slice(eq + 1)), odd: base !== k || name !== base });
  }
  return out;
}
/** Every copy of the watched parameters, or null when the body cannot be read one way: it looks like JSON but is not
 * clean JSON (see jsonView), or it looks like multipart form data. `j` is the JSON body when there is one. */
export function paramCopies(body, search, names) {
  const b = String(body || ''), want = new Set(names);
  let j, json = [];
  if (/^[\s\ufeff]*[[{]/.test(b)) {
    j = jsonView(b);
    if (j === undefined) return null;
    if (isObj(j)) json = names.filter((n) => Object.hasOwn(j, n)).map((n) => ({ name: n, value: j[n], odd: false }));
  } else if (/content-disposition/i.test(b)) return null; // a clean JSON body cannot carry a multipart part
  return { j, json, form: SPLITS.map((s) => formCopies(b, want, s)), query: SPLITS.map((s) => formCopies(search, want, s)) };
}
/** the copies of one name, and the most copies any one way of reading the request could see */
function copiesOf(c, name) {
  const of = (l) => l.filter((x) => x.name === name);
  const all = [...of(c.json), ...c.form.flatMap(of), ...c.query.flatMap(of)];
  return { all, n: of(c.json).length + Math.max(...c.form.map((l) => of(l).length)) + Math.max(...c.query.map((l) => of(l).length)) };
}
/** any copy of these names outside a JSON body (form reading of the body, or the query string) */
const outsideJson = (c) => c.form.some((l) => l.length) || c.query.some((l) => l.length);

/** The watched parameters of a form body, read one way only: {name: value} for each name that is present, or undefined
 * when the request cannot be read with certainty. Money caps (src/brakes.js) read amounts through this, so they see what
 * the map sees and refuse what the map's rules would hold: a JSON or multipart body, a copy in the query string, a name
 * repeated anywhere (also under a ";" split), an odd spelling (brackets, spaces, another case, escapes), or one name whose
 * value differs between the ways a server may split the body. */
export function strictForm(body, search, names) {
  const c = paramCopies(body, search, names);
  if (!c || c.j !== undefined || c.json.length || c.query.some((l) => l.length)) return undefined;
  // A watched name or value written with escapes ("%61mount", "1%300") reads as itself for a server that decodes and as
  // something else for one that does not. Nothing legitimate writes an amount, a currency or an id that way, so it is
  // unreadable.
  for (const part of String(body || '').split(/[&;]/)) {
    const eq = part.indexOf('='), rawName = eq < 0 ? part : part.slice(0, eq), rawValue = eq < 0 ? '' : part.slice(eq + 1);
    if ((/[%+]/.test(rawName) || /[%+]/.test(rawValue)) && names.includes(formDecode(rawName).replace(/^[\s[\]]+/, '').split(/[[\]]/)[0].trim().toLowerCase())) return undefined;
  }
  const out = {};
  for (const n of names) {
    const { all, n: k } = copiesOf(c, n);
    if (k > 1 || all.some((x) => x.odd)) return undefined;
    if (!all.length) continue;
    if (new Set(all.map((x) => x.value)).size > 1) return undefined;
    out[n] = all[0].value;
  }
  return out;
}

// Some servers let a POST say which method it really is (Rack and Laravel read `_method` from a form body, Symfony also
// from the query string). LEASH matches rules on the real method, so a request carrying `_method` anywhere a server
// might read it is held on every provider, and it cannot be pre-approved. Override headers (X-HTTP-Method-Override and
// friends) are never forwarded upstream (see broker.js PASS_REQ).
function methodOverride(body, search) {
  const want = new Set(['_method']), b = String(body || '');
  if (SPLITS.some((s) => formCopies(b, want, s).length || formCopies(search, want, s).length)) return true;
  const j = /^[\s\ufeff]*[[{]/.test(b) ? jsonView(b) : undefined;
  if (j !== undefined) return isObj(j) && Object.hasOwn(j, '_method');
  return /name\s*=\s*["']?\s*_method/i.test(b); // a multipart part (a clean JSON body cannot carry one)
}
export const COMMON = [
  { id: 'any.method-override', m: '*', p: '/**', always: true, test: methodOverride, why: `The request asks the API to treat it as a different method (_method). ${BRAND.name} matches its rules on the real method, so these always wait for a human.` },
];

// ---------------------------------------------------------------- SQL
// A real tokenizer: single-quoted strings, double-quoted and backtick identifiers, -- and nested /* */ comments.
// Returns null (unreadable, so held) for unterminated strings or comments, backslashes inside strings (E'' escapes
// would shift where a string ends) and any $ that is not a $1 style parameter (dollar quotes, $$ bodies).
export function sqlTokens(sql) {
  const s = String(sql ?? ''), out = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '-' && s[i + 1] === '-') { const j = s.indexOf('\n', i); i = j < 0 ? s.length : j + 1; continue; }
    if (c === '/' && s[i + 1] === '*') {
      let d = 1, j = i + 2;
      while (j < s.length && d) { if (s.startsWith('/*', j)) { d++; j += 2; } else if (s.startsWith('*/', j)) { d--; j += 2; } else j++; }
      if (d) return null;
      i = j; continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      let j = i + 1;
      for (;;) {
        if (j >= s.length || s[j] === '\\') return null;
        if (s[j] === c) { if (s[j + 1] === c) { j += 2; continue; } break; }
        j++;
      }
      out.push({ t: c === "'" ? 's' : 'id', v: '' }); i = j + 1; continue;
    }
    if (c === '$') { const m = s.slice(i).match(/^\$\d+/); if (!m) return null; out.push({ t: 'p', v: m[0] }); i += m[0].length; continue; }
    const w = s.slice(i).match(/^[A-Za-z_][A-Za-z0-9_]*/);
    if (w) { out.push({ t: 'w', v: w[0].toLowerCase() }); i += w[0].length; continue; }
    out.push({ t: c === ';' ? ';' : 'p', v: c }); i++;
  }
  return out;
}

// Words that make a statement more than a read, anywhere outside a string. Functions with side effects that a
// SELECT can call (pg_terminate_backend, set_config, nextval, lo_import, dblink_exec) are caught by prefix.
const SQL_WRITE = new Set(('insert update delete merge drop truncate alter create grant revoke do execute exec call copy into ' +
  'lock for set reset attach detach pragma vacuum reindex analyze notify listen load import refresh cluster comment security prepare ' +
  'deallocate savepoint begin commit rollback returning').split(' '));
const SQL_SAFE_FN = new Set(('count sum avg min max coalesce nullif greatest least lower upper length char_length substring substr trim ltrim rtrim '
  + 'replace concat concat_ws left right position strpos split_part abs round ceil ceiling floor trunc mod power sqrt now current_date '
  + 'date_trunc date_part extract to_char to_date to_timestamp age array_agg string_agg json_agg jsonb_agg json_build_object '
  + 'jsonb_build_object row_number rank dense_rank lag lead first_value last_value bool_and bool_or md5 gen_random_uuid cast '
  + 'array_length unnest jsonb_array_length json_array_length datetime date time strftime julianday ifnull iif printf instr typeof total group_concat').split(' '));
// keywords that are followed by "(" without being calls
const SQL_PAREN_KW = new Set('in exists any all over filter within as from join on where and or not values using select case then else when interval'.split(' '));
const SQL_FN = /^(pg_|lo_|dblink|set_config|nextval|setval|txid_|query_to_)/;

/** true only for one statement that is plainly a read: SELECT, WITH ... SELECT, EXPLAIN (no ANALYZE), SHOW */
export function sqlReadOnly(sql) {
  const tk = sqlTokens(sql);
  if (!tk) return false;
  while (tk.length && tk[tk.length - 1].t === ';') tk.pop();
  if (!tk.length || tk.some((x) => x.t === ';')) return false;
  if (tk[0].t !== 'w' || !['select', 'with', 'explain', 'show'].includes(tk[0].v)) return false;
  if (tk.some((x) => x.t === 'w' && (SQL_WRITE.has(x.v) || SQL_FN.test(x.v)))) return false;
  // Every function call must be a known pure function. Anything else (user functions, extensions, quoted names) is held.
  return tk.every((x, i) => !(tk[i + 1]?.v === '(') || (x.t === 'w' && (SQL_SAFE_FN.has(x.v) || SQL_PAREN_KW.has(x.v))) || x.t === 'p');
}

/** kept for callers and tests: anything that is not plainly read-only needs a human */
export const sqlDestructive = (sql) => !sqlReadOnly(sql);

/** every SQL string in a request body (sql, query, batch arrays), or null when the body is unreadable or ambiguous.
 * Read through jsonView: a repeated or case-variant "query" or "sql" key (parsers disagree on which copy wins) is
 * unreadable, so LEASH refuses to guess. */
export function sqlBodies(body) {
  const j = jsonView(body);
  if (j === undefined) return null;
  const out = [];
  const walk = (o) => {
    if (Array.isArray(o)) return o.length && o.every(walk);
    if (!o || typeof o !== 'object') return false;
    // D1 executes `sql`; Supabase executes `query`. A body carrying both could show one and run the other.
    if ('sql' in o && 'query' in o) return false;
    let found = false;
    for (const k of ['sql', 'query']) if (k in o) { if (typeof o[k] !== 'string') return false; out.push(o[k]); found = true; }
    if ('batch' in o) { if (!walk(o.batch)) return false; found = true; }
    return found;
  };
  return walk(j) ? out : null;
}
// an SQL field in the query string or in a form reading of the body could be what the server runs instead
const sqlHold = (b, q) => {
  const c = paramCopies(b, q, ['sql', 'query', 'batch']);
  if (!c || outsideJson(c)) return true;
  const l = sqlBodies(b);
  return !l || !l.length || l.some((s) => !sqlReadOnly(s));
};

// ---------------------------------------------------------------- GraphQL
// Lexer per the GraphQL spec: commas are whitespace, # starts a comment, strings and block strings are skipped.
export function gqlTokens(src) {
  const s = String(src), out = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/[\s,]/.test(c)) { i++; continue; }
    if (c === '#') { while (i < s.length && s[i] !== '\n' && s[i] !== '\r') i++; continue; }
    if (s.startsWith('"""', i)) { const j = s.indexOf('"""', i + 3); if (j < 0) return null; out.push({ t: 's' }); i = j + 3; continue; }
    if (c === '"') {
      let j = i + 1;
      for (;;) { if (j >= s.length || s[j] === '\n') return null; if (s[j] === '\\') { j += 2; continue; } if (s[j] === '"') break; j++; }
      out.push({ t: 's' }); i = j + 1; continue;
    }
    if (s.startsWith('...', i)) { out.push({ t: 'p', v: '...' }); i += 3; continue; }
    const w = s.slice(i).match(/^[_A-Za-z][_0-9A-Za-z]*/);
    if (w) { out.push({ t: 'n', v: w[0] }); i += w[0].length; continue; }
    out.push({ t: 'p', v: c }); i++;
  }
  return out;
}

/** root field names of every mutation in a document; null if the document cannot be read with certainty */
let gqlIn, gqlOut; // Shopify has several rules that read the same document: lex it once
export function gqlMutationFields(src) {
  if (src === gqlIn && gqlIn !== undefined) return gqlOut;
  const out = mutationFields(src);
  gqlIn = src; gqlOut = out;
  return out;
}
function mutationFields(src) {
  const tk = gqlTokens(src);
  if (!tk) return null;
  const fields = [];
  let i = 0;
  const skip = (open, close) => { let d = 0; do { if (i >= tk.length) return false; if (tk[i].v === open) d++; else if (tk[i].v === close) d--; i++; } while (d); return true; };
  while (i < tk.length) {
    const t = tk[i];
    if (t.v === '{') { if (!skip('{', '}')) return null; continue; } // shorthand query
    if (t.t !== 'n' || !['query', 'mutation', 'subscription', 'fragment'].includes(t.v)) return null;
    const isMut = t.v === 'mutation';
    i++;
    while (i < tk.length && tk[i].v !== '{') {
      if (tk[i].v === '(') { if (!skip('(', ')')) return null; } else i++;
    }
    if (i >= tk.length) return null;
    if (!isMut) { if (!skip('{', '}')) return null; continue; }
    i++; // into the root selection set
    while (i < tk.length && tk[i].v !== '}') {
      if (tk[i].v === '...') return null; // fragment spreads at a mutation root could hide any field
      if (tk[i].t !== 'n') return null;
      let name = tk[i++].v;
      if (tk[i]?.v === ':') { i++; if (tk[i]?.t !== 'n') return null; name = tk[i++].v; }
      fields.push(name);
      if (tk[i]?.v === '(') { if (!skip('(', ')')) return null; }
      while (tk[i]?.v === '@') { i += 2; if (tk[i]?.v === '(') { if (!skip('(', ')')) return null; } }
      if (tk[i]?.v === '{') { if (!skip('{', '}')) return null; }
    }
    if (i >= tk.length) return null;
    i++;
  }
  return fields;
}

// The only Railway mutations that pass without approval: restarting or redeploying what is already running.
// Everything else (deletes, resets, rollbacks, variable and volume changes, anything new) is held.
export const RAILWAY_SAFE = new Set(['serviceInstanceRedeploy', 'deploymentRestart', '__typename']);

// A POST GraphQL body LEASH can vouch for: one JSON object with a `query` string and only query, variables,
// operationName and extensions (without a persisted-query hash). Anything else that could pick the operation run is
// unreadable: batches, document ids, persisted queries, repeated or case-variant keys, and GraphQL parameters in the
// query string (Rails merges query string parameters over the body) or in a form reading of the body.
const GQL_BODY = new Set(['query', 'variables', 'operationname', 'extensions']);
const GQL_PARAMS = ['query', 'variables', 'operationname', 'extensions', 'documentid', 'doc_id', 'docid', 'queryid', 'id', 'persistedquery'];
export function gqlDocument(body, search = '') {
  const c = paramCopies(body, search, GQL_PARAMS);
  if (!c || outsideJson(c)) return null;
  const j = c.j;
  if (!isObj(j) || typeof j.query !== 'string' || Object.keys(j).some((k) => !GQL_BODY.has(k))) return null;
  if (j.extensions !== undefined && (!isObj(j.extensions) || Object.hasOwn(j.extensions, 'persistedquery'))) return null;
  return j.query;
}
/** GitHub's GraphQL API can do everything the REST map guards (deleteRepository, transferRepository, ...). Only pure queries pass. */
function ghGraphqlHold(body, search) {
  const d = gqlDocument(body, search);
  if (d === null) return true;
  const f = gqlMutationFields(d);
  return !f || f.length > 0;
}

/** A short, parsed account of what a request would do, shown above the raw preview so padding can't hide it. */
export function summarize(search, body) {
  const out = [];
  let j; try { j = JSON.parse(body || ''); } catch { j = undefined; }
  const gq = (q) => { const f = gqlMutationFields(q); return f === null ? `GraphQL ${BRAND.name} could not read` : f.length ? 'GraphQL mutations: ' + f.join(', ') : 'GraphQL query (read only)'; };
  if (j && typeof j === 'object' && !Array.isArray(j) && typeof j.query === 'string' && !/^\s*(select|with|explain|show|insert|update|delete|drop|create|alter)\b/i.test(j.query)) out.push(gq(j.query));
  const sqls = sqlBodies(body);
  if (sqls) for (const q of sqls) out.push('SQL: ' + sqlSummary(q));
  if (Array.isArray(j)) out.push(`Batch of ${j.length} requests`);
  const m = /[?&]query=([^&]*)/.exec(search || '');
  if (m) { try { out.push(gq(decodeURIComponent(m[1].replace(/\+/g, ' ')))); } catch { out.push(`Query string ${BRAND.name} could not read`); } }
  return out;
}
/** statement starts plus every write keyword or unknown function, in order */
export function sqlSummary(sql) {
  const tk = sqlTokens(sql);
  if (!tk) return 'could not be read (unterminated string or comment, backslash, or $ quoting)';
  const stmts = [[]];
  for (const x of tk) x.t === ';' ? stmts.push([]) : stmts[stmts.length - 1].push(x);
  const parts = stmts.filter((t) => t.length).map((t) => {
    const flags = [...new Set(t.filter((x, i) => x.t === 'w' && (SQL_WRITE.has(x.v) || SQL_FN.test(x.v) || (t[i + 1]?.v === '(' && !SQL_SAFE_FN.has(x.v) && !SQL_PAREN_KW.has(x.v)))).map((x) => x.v.toUpperCase()))];
    return t[0].v.toUpperCase() + (flags.length ? ' [' + flags.join(', ') + ']' : '');
  });
  return `${parts.length} statement${parts.length === 1 ? '' : 's'}: ` + parts.join('; ');
}

function railwayHold(body, search) {
  const d = gqlDocument(body, search); // batches, persisted queries and anything ambiguous are held
  if (d === null) return true;
  const f = gqlMutationFields(d);
  return !f || f.some((n) => !RAILWAY_SAFE.has(n));
}
// GET carries the document in ?query=; mutations over GET are refused by spec but held here in case they are not.
// Read the query string raw, strictly decoded and leniently decoded (URLSearchParams keeps going past a bad escape
// where decodeURIComponent gives up); a query string that does not decode cleanly is held.
function railwayGetHold(b, q) {
  const raw = String(q || '').replace(/\+/g, ' ');
  let strict;
  try { strict = decodeURIComponent(raw); } catch { return true; }
  const lenient = SPLITS.flatMap((s) => raw.replace(/^\?/, '').split(s).flatMap((p) => [...new URLSearchParams(p)].flat())).join('\n');
  return [raw, strict, lenient].some((t) => /mutation|persisted/i.test(t));
}

// ---------------------------------------------------------------- bodies
const set = (v) => v !== undefined && v !== false;
// GitHub: read the strict JSON view, so escapes, repeated keys and case variants cannot slip a value past. The body
// must be one JSON object, and a watched name in the query string or in a form reading of the body is held too.
const ghBody = (names, hit) => (b, q) => {
  const c = paramCopies(b, q, names);
  return !c || !isObj(c.j) || outsideJson(c) || hit(c.j);
};
const ghForce = ghBody(['force'], (j) => set(j.force));
const ghVisibility = ghBody(['visibility', 'private', 'archived'], (j) => Object.hasOwn(j, 'visibility') || Object.hasOwn(j, 'private') || set(j.archived));
// Stripe reads form parameters from the body and the query string (LEASH also reads a JSON body). Held when any copy
// of a watched parameter is set, when it appears more than once anywhere (Rack keeps the last copy, others the first),
// in an odd form ("confirm[]", " confirm", "Confirm"), or when the body cannot be read one way.
const truthy = (v) => v !== null && !['', 'false', '0'].includes(v.toLowerCase());
const stripeSet = (...names) => (b, q) => {
  const c = paramCopies(b, q, names);
  if (!c || (c.j !== undefined && !isObj(c.j))) return true;
  return names.some((n) => { const { all, n: k } = copiesOf(c, n); return k > 1 || all.some((x) => x.odd || truthy(String(x.value))); });
};
// Cloudflare purge: by file URL or by cache tag passes. purge_everything, a whole host, a URL prefix, any other field,
// or a body that is not one clean JSON object is held.
const cfPurge = (b, q) => {
  const c = paramCopies(b, q, ['purge_everything', 'hosts', 'prefixes']);
  return !c || !isObj(c.j) || outsideJson(c) || Object.keys(c.j).some((k) => k !== 'files' && k !== 'tags');
};
// D1 import: "init" (get an upload URL) and "poll" (status) pass; "ingest" runs an SQL file LEASH cannot read.
const d1Import = (b, q) => {
  const c = paramCopies(b, q, ['action']);
  return !c || !isObj(c.j) || outsideJson(c) || !['init', 'poll'].includes(c.j.action);
};

// ---------------------------------------------------------------- map 2026-10-10: Vercel, Neon, Fly.io, Resend, Shopify
// How these five were mapped: for Vercel, Neon, Fly.io and Resend from the provider's published OpenAPI document (every
// POST, PUT, PATCH and DELETE operation read, 9 Oct 2026); for Shopify from the Admin GraphQL schema Shopify serves for its
// docs (all 484 mutation names across 2026-01, 2026-07 and 2026-10). Every rule cites the reference page of the endpoint.
// Every provider holds every DELETE (the same rule as the first five). A rule's `why` says whether the action can be undone.

// Many Vercel paths carry a version segment (/v9/projects, /v10/projects) and a few do not. Rules do not care which.
const V = '{,/v*}';

// A flag that changes what a call does (Vercel's upsert). Held when any copy of it is set, when it appears more than once
// anywhere (parsers disagree on which copy wins), in an odd form (" upsert", "upsert[]", "Upsert"), or when the body cannot
// be read one way. A JSON array body is fine: the flag is a query parameter, so an array cannot hide a copy of it.
const flagSet = (...names) => (b, q) => {
  const c = paramCopies(b, q, names);
  if (!c) return true;
  return names.some((n) => { const { all, n: k } = copiesOf(c, n); return k > 1 || all.some((x) => x.odd || truthy(String(x.value))); });
};

// Resend. A sent email cannot be unsent, so a send that reaches more than one person waits for a human. One recipient is
// one address in `to` (a string or a list of one), nothing in `cc` or `bcc`. A list hidden in one string (comma, semicolon)
// or a display name that carries an "@" counts as more than one. Anything unreadable is held.
const oneAddress = (v) => typeof v === 'string' && v.length <= 320 && !/[,;]/.test(v) && (v.match(/@/g) || []).length === 1;
const rsEmpty = (v) => v === undefined || (Array.isArray(v) && v.length === 0) || v === '';
const rsRecipients = (b, q) => {
  const c = paramCopies(b, q, ['to', 'cc', 'bcc']);
  if (!c || !isObj(c.j) || outsideJson(c)) return true;
  const { to, cc, bcc } = c.j;
  const single = Array.isArray(to) ? to.length === 1 && oneAddress(to[0]) : oneAddress(to);
  return !single || !rsEmpty(cc) || !rsEmpty(bcc);
};
// Resend broadcast created with send=true goes out at once to a whole segment; only an explicit false (or no field) is a draft
const rsBroadcastNow = ghBody(['send'], (j) => set(j.send));
// Resend automations: switching one on makes it email contacts from then on; editing its steps changes what a live one sends
const rsAutomation = (patch) => ghBody(['status', 'steps', 'connections'], (j) =>
  (Object.hasOwn(j, 'status') && j.status !== 'disabled') || (patch && (Object.hasOwn(j, 'steps') || Object.hasOwn(j, 'connections'))));

// Shopify. The Admin API is GraphQL over POST to one path, so the danger is in the mutation names the document runs.
// Names are compared in lower case. Three kinds of rule: whole families by name, explicit lists, and "cannot read".
//  - delete family: any name containing "delete" or "destroy" (productDelete, orderDelete, productVariantsBulkDelete,
//    urlRedirectBulkDeleteAll, delegateAccessTokenDestroy, ...) so a mutation Shopify adds later with such a name is held
//    without a map change, plus the deletes with another verb (listed in SH_REMOVE).
//  - gift cards and store credit: every name that starts with giftCard or storeCredit.
//  - explicit lists below, each entry traced to the mutation's own description in Shopify's schema.
const SH_DELETE = /delete|destroy/;
const SH_REMOVE = new Set([
  'deliveryprofileremove', // "Enqueue the removal of a delivery profile."
  'shoplocaledisable', // "Deletes a locale for a shop. This also deletes all translations of this locale."
  'inventorydeactivate', // "Removes an inventory item's quantities from a location, and turns off inventory at the location."
  'inventorybulktoggleactivation', // "Activates or deactivates an inventory item at multiple locations", so it can do the same
  'locationdeactivate', // "Deactivates a location and moves inventory, pending orders, and moving transfers"
  'appuninstall', // "This action is irreversible. You can't restore an uninstalled app's configuration or data."
]);
const SH_MONEY = new Set([
  'refundcreate', 'returnprocess', // refunds to the customer
  'ordercapture', 'paymentschedulecapture', 'ordercreatemandatepayment', // charges the customer
  'subscriptionbillingattemptcreate', 'subscriptionbillingcyclecharge', 'subscriptionbillingcyclebulkcharge', // charges subscribers
  'ordermarkaspaid', 'ordercreatemanualpayment', 'transactionvoid', // changes what counts as paid
  'shippinglabelpurchase', 'shopifypaymentspayoutalternatecurrencycreate', // spends or pays out the merchant's money
  'apppurchaseonetimecreate', 'appsubscriptioncreate', 'appsubscriptionlineitemupdate', 'appusagerecordcreate', // charges the merchant
]);
// orderCancel: "Order cancellation is irreversible". subscriptionContractActivate only accepts a contract that is "active, paused, or
// failed", so a cancelled or expired subscription contract cannot be brought back.
const SH_CANCEL = new Set(['ordercancel', 'subscriptioncontractcancel', 'subscriptioncontractexpire']);
const SH_CUSTOMER_DATA = new Set(['customerrequestdataerasure', 'customermerge', 'customerpaymentmethodrevoke', 'privacyfeaturesdisable']);
const SH_ACCESS = new Set(['delegateaccesstokencreate', 'apprevokeaccessscopes']);
const SH_THEME = new Set(['themepublish', 'themefilesupsert', 'themefilescopy']);
const SH_WEBHOOK = new Set(['webhooksubscriptioncreate', 'webhooksubscriptionupdate']);
/** the rule id a Shopify GraphQL request trips, or null when it is a plain read. Memoised: several rules ask about one request. */
let shIn, shOut;
function shopifyClass(body, search) {
  const key = body + '\u0000' + search;
  if (key === shIn) return shOut;
  let out = null;
  const d = gqlDocument(body, search); // one JSON object with a query string and nothing that could pick another operation
  const f = d === null ? null : gqlMutationFields(d);
  if (!f) out = 'sh.unreadable';
  else {
    const n = f.map((x) => x.toLowerCase());
    const any = (test) => n.some(test);
    out = n.includes('bulkoperationrunmutation') ? 'sh.bulk'
      : any((x) => SH_DELETE.test(x) || SH_REMOVE.has(x)) ? 'sh.delete'
      : any((x) => SH_MONEY.has(x)) ? 'sh.money'
      : any((x) => /^(giftcard|storecredit)/.test(x)) ? 'sh.giftcard'
      : any((x) => SH_CANCEL.has(x)) ? 'sh.cancel'
      : any((x) => SH_CUSTOMER_DATA.has(x)) ? 'sh.customer-data'
      : any((x) => SH_ACCESS.has(x)) ? 'sh.access'
      : any((x) => SH_THEME.has(x)) ? 'sh.theme'
      : any((x) => SH_WEBHOOK.has(x)) ? 'sh.webhook'
      : null;
  }
  shIn = key; shOut = out;
  return out;
}
const shopify = (id) => (b, q) => shopifyClass(b, q) === id;

/** A per-store host: exactly "<store>.myshopify.com" for Shopify (the provider's `perCredentialHost.suffix`). ASCII only,
 * one label of letters, digits and hyphens that starts and ends with a letter or digit (at most 63 characters), and
 * none of: a port, user info, path, query, fragment, IP address, trailing dot, further subdomain, or punycode ("xn--" or
 * any other "--" in the third and fourth places, which IDNA reserves). Case is folded after the ASCII check, so no
 * Unicode lower-casing (the Kelvin sign) can turn into a letter. Returns the lower-case host or null. This host is
 * where the vaulted key is sent, so it is checked when a credential is added and again before every upstream call. */
export function storeHost(P, input) {
  const sfx = P?.perCredentialHost?.suffix;
  if (!sfx || typeof input !== 'string' || input.length > 80 || !/^[\x21-\x7e]+$/.test(input)) return null;
  const h = input.toLowerCase();
  if (!h.endsWith(sfx)) return null;
  const label = h.slice(0, -sfx.length);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) return null;
  if (label[2] === '-' && label[3] === '-') return null;
  return h;
}
/** the host word a public receipt may carry. A per-store host is a business name, so it is reduced to the shared suffix. */
export function publicHost(host) {
  const h = String(host ?? '');
  for (const P of Object.values(PROVIDERS)) if (P.perCredentialHost && h.endsWith(P.perCredentialHost.suffix)) return P.perCredentialHost.suffix.slice(1);
  return h;
}

export const PROVIDERS = {
  github: {
    name: 'GitHub',
    host: 'api.github.com',
    base: '',
    // owner and repo names are case-insensitive on GitHub, so rules match a lowercased path (upstream keeps the case)
    ci: true,
    auth: (k) => ({ authorization: `Bearer ${k}`, 'x-github-api-version': '2022-11-28' }),
    keyHint: /^(ghp_|github_pat_|gho_|ghs_)/,
    irreversible: [
      { id: 'gh.delete', m: 'DELETE', p: '/**', why: 'Any DELETE on GitHub removes something (repo, branch, release, key, member).' },
      { id: 'gh.force-push', m: 'PATCH', p: '/repos/*/*/git/refs/**', body: ghForce, why: 'Force-updating a ref rewrites history and can drop commits for everyone.' },
      { id: 'gh.transfer', m: 'POST', p: '/repos/*/*/transfer', why: 'Transferring a repository hands it to another owner.' },
      { id: 'gh.visibility', m: 'PATCH', p: '/repos/*/*', body: ghVisibility, why: 'Changing visibility can publish private code; archiving freezes a repo.' },
      { id: 'gh.protection', m: 'PUT', p: '/repos/*/*/branches/*/protection', why: 'Rewriting branch protection can remove the rules that guard main.' },
      { id: 'gh.graphql', m: 'POST', p: '/graphql', body: ghGraphqlHold, why: `A GitHub GraphQL mutation (deleteRepository, transferRepository, updateRepository and every other write), or a request ${BRAND.name} cannot read.` },
      { id: 'gh.graphql-get', m: 'GET', p: '/graphql', why: 'GitHub GraphQL over GET is not a normal client path.' },
      { id: 'gh.actions-secret', m: 'PUT', p: '/repos/*/*/actions/secrets/*', why: 'Overwriting a CI secret silently changes what production deploys with.' },
    ],
  },
  cloudflare: {
    name: 'Cloudflare',
    host: 'api.cloudflare.com',
    base: '/client/v4',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    irreversible: [
      { id: 'cf.delete', m: 'DELETE', p: '/**', why: 'Deletes a zone, DNS record, Worker, bucket, database or token.' },
      { id: 'cf.purge', m: 'POST', p: '/zones/*/purge_cache', body: cfPurge, why: 'Purging everything, a whole host or a URL prefix can take a site down under load.' },
      { id: 'cf.worker-put', m: 'PUT', p: '/accounts/*/workers/scripts/**', why: 'Uploading over a Worker replaces production code.' },
      { id: 'cf.dns-write', m: 'PUT,PATCH', p: '/zones/*/dns_records/*', why: 'Overwriting a DNS record can point a domain somewhere else.' },
      { id: 'cf.r2-config', m: 'PUT', p: '/accounts/*/r2/buckets/*/{lifecycle,cors,domains/**}', why: 'Bucket lifecycle rules can delete objects; domain changes expose a bucket.' },
      { id: 'cf.token-roll', m: 'PUT', p: '/user/tokens/*/value', why: 'Rolling an API token breaks everything using it.' },
      { id: 'cf.d1-sql', m: 'POST', p: '/accounts/*/d1/database/*/{query,raw}', body: sqlHold, why: 'SQL against a production D1 database that is not a single plain read.' },
      { id: 'cf.d1-import', m: 'POST', p: '/accounts/*/d1/database/*/import', body: d1Import, why: `Importing an SQL file into a production D1 database runs SQL ${BRAND.name} cannot read.` },
      { id: 'cf.d1-restore', m: 'POST', p: '/accounts/*/d1/database/*/time_travel/restore', why: 'Restoring a D1 database to an earlier point overwrites everything written since.' },
    ],
  },
  railway: {
    name: 'Railway',
    host: 'backboard.railway.app',
    base: '/graphql/v2',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    irreversible: [
      // PocketOS, 25 Apr 2026: one volumeDelete wiped the production database and its volume backups in 9 seconds.
      { id: 'rw.mutation', m: 'POST', p: '/**', body: railwayHold, why: `A Railway mutation other than a redeploy or restart, or a request ${BRAND.name} cannot read (PocketOS lost production to one volumeDelete).` },
      { id: 'rw.get-mutation', m: 'GET', p: '/**', body: railwayGetHold, why: 'A Railway mutation sent over GET.' },
      { id: 'rw.method', m: 'PUT,PATCH,DELETE', p: '/**', why: 'Railway\'s API is GraphQL over POST; a PUT, PATCH or DELETE is not a normal client path.' },
    ],
  },
  stripe: {
    name: 'Stripe',
    host: 'api.stripe.com',
    base: '',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    keyHint: /^(sk_|rk_)/,
    irreversible: [
      { id: 'st.delete', m: 'DELETE', p: '/**', why: 'Deletes customers, products, webhooks or cancels subscriptions.' },
      { id: 'st.money', m: 'POST', p: '/v1/{refunds,payouts,transfers,charges,topups}', why: 'Moves money.' },
      { id: 'st.money2', m: 'POST', p: '/v1/payment_intents/*/{confirm,capture}', why: 'Moves money.' },
      { id: 'st.pi-confirm', m: 'POST', p: '/v1/payment_intents', body: stripeSet('confirm'), why: 'Creating a payment intent with confirm=true charges the customer.' },
      { id: 'st.refund', m: 'POST', p: '/v1/{charges,application_fees}/*/{refund,refunds}', why: 'Refunds money.' },
      { id: 'st.invoice', m: 'POST', p: '/v1/invoices/*/{pay,void}', why: 'Paying or voiding an invoice cannot be undone.' },
      { id: 'st.credit-note', m: 'POST', p: '/v1/credit_notes', why: 'Issuing a credit note credits or refunds the customer.' },
      { id: 'st.credit-note-void', m: 'POST', p: '/v1/credit_notes/*/void', why: 'Voiding a credit note cannot be undone.' },
      { id: 'st.cancel', m: 'POST', p: '/v1/subscriptions/*/cancel', why: 'Cancels a paying customer.' },
      { id: 'st.cancel-at', m: 'POST', p: '/v1/subscriptions/*', body: stripeSet('cancel_at_period_end', 'cancel_at'), why: 'Schedules a paying customer to be cancelled.' },
      { id: 'st.webhook', m: 'POST', p: '/v1/webhook_endpoints/**', why: 'Changing webhooks can silently stop order fulfilment.' },
    ],
  },
  supabase: {
    name: 'Supabase',
    host: 'api.supabase.com',
    base: '',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    keyHint: /^sbp_/,
    irreversible: [
      { id: 'sb.delete', m: 'DELETE', p: '/**', why: 'Deletes a project, function, branch or secret.' },
      { id: 'sb.sql', m: 'POST', p: '/v1/projects/*/database/query', body: sqlHold, why: 'SQL on the database that is not a single plain read (SELECT, WITH ... SELECT, EXPLAIN, SHOW).' },
      { id: 'sb.migration', m: 'POST,PUT,PATCH', p: '/v1/projects/*/database/migrations', why: 'A database migration runs schema changes (and any SQL) on production.' },
      { id: 'sb.pause', m: 'POST', p: '/v1/projects/*/{pause,restore}', why: 'Pausing or restoring a project takes production offline.' },
      { id: 'sb.db-password', m: 'POST', p: '/v1/projects/*/database/password', why: 'Resetting the database password breaks every existing connection.' },
      { id: 'sb.config', m: 'PUT,PATCH', p: '/v1/projects/*/config/**', why: 'Changes production database, auth or network configuration.' },
      { id: 'sb.secrets', m: 'POST', p: '/v1/projects/*/secrets', why: 'Overwriting project secrets changes production configuration.' },
    ],
  },

  // Vercel REST API. Source: https://openapi.vercel.sh/ (258 write operations read on 9 Oct 2026). Reference pages are
  // https://vercel.com/docs/rest-api/<group>/<operation>, named per rule below. The API has no undelete for anything.
  vercel: {
    name: 'Vercel',
    host: 'api.vercel.com',
    base: '',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    irreversible: [
      // .../projects/delete-a-project, .../deployments/delete-a-deployment, .../domains/remove-a-domain-by-name,
      // .../aliases/delete-an-alias, .../projects/remove-an-environment-variable. Vercel: "Deleting your project will also delete
      // the deployments, domains, environment variables, and settings within it" (https://vercel.com/docs/projects/managing-projects).
      { id: 'vc.delete', m: 'DELETE', p: '/**', why: 'Any DELETE on Vercel removes something (project, deployment, domain, alias, environment variable, team). Deleting a project also deletes its deployments, domains, environment variables and settings. The API has no undelete.' },
      // .../deployments/create-a-new-deployment: "the deployment targets the environment inferred from the branch (production or
      // preview)" when the request does not name one, and a redeploy inherits the old settings.
      { id: 'vc.deploy', m: 'POST', p: `${V}/deployments`, why: 'Creating a deployment can go straight to production: when the request does not name a target, Vercel infers it from the branch. A production deploy replaces what visitors see, and rolling back is a second production change.' },
      // .../projects/point-production-traffic-to-a-given-deployment (promote), .../projects/point-production-traffic-to-a-previous-production-deployment-by-id
      // (rollback), .../aliases/assign-an-alias ("it will be removed from the old deployment and assigned to the new one"),
      // .../rolling-release/{start,approve-stage,complete}-..., .../project-routes/promote-restore-or-discard-a-routing-rule-version,
      // .../bulk-redirects/promote-a-staging-version-to-production-or-restore-a-previous-production-version
      { id: 'vc.production', m: 'POST', p: `${V}/{projects/*/promote/*,projects/*/rollback/*,deployments/*/aliases,projects/*/rolling-release/start,projects/*/rolling-release/approve-stage,projects/*/rolling-release/complete,projects/*/routes/versions,bulk-redirects/versions}`, why: 'Points production traffic or a live domain somewhere else: promote, rollback, assigning an alias (it moves off the deployment that had it), rolling releases, and promoting or restoring routing rules and bulk redirects. Visitors see it at once, and undoing it is another production change.' },
      // .../projects/pause-a-project; docs: "any users accessing your production deployment will see a 503 DEPLOYMENT_PAUSED error"
      { id: 'vc.pause', m: 'POST', p: `${V}/projects/*/pause`, why: 'Pausing a project takes its production deployment offline: visitors get a 503 until someone resumes the project.' },
      // .../projects/update-an-existing-project (build and install commands, root directory, framework, deployment protection,
      // password and SSO protection, trusted IPs, preview settings); the old values are not kept
      { id: 'vc.project-settings', m: 'PATCH', p: `${V}/projects/*`, why: 'Changes project settings: build and install commands, root directory, framework, deployment protection, trusted IPs. A wrong value breaks the next build or exposes previews, and the old value is not kept.' },
      // .../security/update-attack-challenge-mode, .../security/update-firewall-configuration, .../security/put-firewall-configuration,
      // .../security/returns-activated-waf-config ("Promotes a draft WAF config to an active config"), .../security/create-system-bypass-rule
      { id: 'vc.security', m: 'POST,PUT,PATCH', p: `${V}/security/{attack-mode,firewall/config,firewall/config/*/activate,firewall/bypass}`, why: 'Changes the firewall or Attack Challenge mode of a live project. A wrong rule can block every visitor or open the site to attack, and activating a config replaces the active one.' },
      // .../domains/update-or-move-apex-domain (moves a domain to another team), .../projects/update-a-project-domain,
      // .../projects/move-a-project-domain, .../domains-registrar/update-nameservers-for-a-domain,
      // .../domains-registrar/update-auto-renew-for-a-domain
      { id: 'vc.domain', m: 'POST,PATCH', p: `${V}/{domains/*,projects/*/domains/*,projects/*/domains/*/move,registrar/domains/*/nameservers,registrar/domains/*/auto-renew}`, why: 'Moves or repoints a domain: moving an apex domain to another team or project, changing a project domain, nameservers, or turning off auto-renew (a domain that lapses can be lost). Traffic and email can go elsewhere at once.' },
      // .../dns/update-an-existing-dns-record (PATCH); the PUT form replaces the records of a domain
      { id: 'vc.dns', m: 'PUT,PATCH', p: `${V}/domains/{records/*,*/records}`, why: 'Overwriting a DNS record can point a domain somewhere else, and the previous value is not kept.' },
      // .../domains-registrar/{buy-a-domain,buy-multiple-domains,transfer-in-a-domain,renew-a-domain}, .../billing/purchase-credits
      { id: 'vc.money', m: 'POST', p: `${V}/{registrar/domains/buy,registrar/domains/*/buy,registrar/domains/*/transfer,registrar/domains/*/renew,billing/buy}`, why: 'Spends money: buying, transferring or renewing a domain, or buying credits, charged to the team.' },
      // .../projects/edit-an-environment-variable, .../environment/updates-one-or-more-shared-environment-variables,
      // .../projects/create-one-or-more-environment-variables ("If you include upsert=true ... the existing variable's value will be updated")
      { id: 'vc.env', m: 'PATCH', p: `${V}/{projects/*/env/*,env}`, why: 'Overwrites an environment variable. The old value is not kept, and the next deployment that reads the new one can break production.' },
      { id: 'vc.env-upsert', m: 'POST', p: `${V}/projects/*/env`, body: flagSet('upsert'), why: 'Creating environment variables with upsert=true overwrites any that already exist. The old values are not kept.' },
      // .../edge-cache/dangerously-delete-by-tag and -by-source-image: "deleting the cache can cause many concurrent requests to the
      // origin leading to cache stampede problem". Vercel itself calls these "not recommended".
      { id: 'vc.cache', m: 'POST', p: `${V}/edge-cache/dangerously-*`, why: 'Deleting cache entries forces every next request through to your origin at once (a cache stampede). Vercel marks these calls dangerous and not recommended.' },
      // .../global-config/restore-global-config-backup
      { id: 'vc.restore', m: 'POST', p: `${V}/global-config/*/backups/*/restore`, why: 'Restoring an Edge Config backup replaces the live configuration with the backup. Changes made since are lost.' },
      // .../teams/invite-a-user, .../teams/update-a-team-member, .../projectmembers/adds-a-new-member-to-a-project,
      // .../access-groups/create-an-access-group-project, .../access-groups/update-an-access-group-project,
      // .../projects/create-project-transfer-request, .../projects/accept-project-transfer-request
      { id: 'vc.access', m: 'POST,PUT,PATCH', p: `${V}/{teams/*/members,teams/*/members/*,projects/*/members,access-groups/*/projects,access-groups/*/projects/*,projects/*/transfer-request,projects/transfer-request/*}`, why: 'Gives someone access or hands something over: team invites and role changes, project members, access groups, project transfers. Access given to the wrong person is a way in that does not go through Counterseal.' },
      // .../authentication/create-an-auth-token ("bearerToken ... is only provided once"); POST /api-keys makes an API key
      { id: 'vc.token', m: 'POST', p: `${V}/{user/tokens,api-keys}`, why: 'Makes a new Vercel token or API key. The agent would then hold a real key that does not go through Counterseal.' },
    ],
  },

  // Neon API v2. Source: https://neon.com/api_spec/release/v2.json (109 write operations read on 9 Oct 2026). Reference pages
  // are https://api-docs.neon.tech/reference/<operationId in lower case>, named per rule. SQL sent over a connection string
  // never passes through this API.
  neon: {
    name: 'Neon',
    host: 'console.neon.tech',
    base: '/api/v2',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    note: 'Management API v2 only; paths are relative to /api/v2. SQL sent over a connection string never passes through Counterseal.',
    irreversible: [
      // .../reference/deleteproject: "Deletes the specified project and all its endpoints, branches, databases, and users. Deleted
      // projects can be recovered within 7 days using POST /projects/{project_id}/recover." Also deleteprojectbranch (drops
      // connections), deleteprojectbranchdatabase, deleteprojectbranchrole, deletesnapshot, bucket and object deletes.
      { id: 'neon.delete', m: 'DELETE', p: '/**', why: 'Any DELETE on Neon removes something. A deleted project (its computes, branches, databases and roles) can be recovered for 7 days; a deleted branch, database, role, snapshot or stored object has no documented recovery, and deleting a branch drops its connections.' },
      // .../reference/restoreprojectbranch, .../reference/restoresnapshot, .../reference/finalizerestorebranch. Neon docs
      // (https://neon.com/docs/introduction/branch-restore): a restore "overwrites all data and schema on all databases in that
      // branch" and drops connections; a backup branch {name}_old_{timestamp} is kept.
      { id: 'neon.restore', m: 'POST', p: '/projects/*/{branches/*/restore,branches/*/finalize_restore,snapshots/*/restore}', why: 'Restoring overwrites all data and schema in the branch and interrupts its connections. Neon keeps the replaced state as a backup branch, which is the only way back.' },
      // .../reference/resetprojectbranchrolepassword: "Connections to the compute endpoint are dropped."
      { id: 'neon.password', m: 'POST', p: '/projects/*/branches/*/roles/*/reset_password', why: 'Resetting a role password drops its connections and breaks every app that still uses the old password.' },
      // .../reference/updateproject (history retention, IP allow list, default compute settings), .../reference/updateprojectendpoint
      // (compute settings, can disable the endpoint), .../reference/updateprojectbranchdatabase (rename)
      { id: 'neon.settings', m: 'PATCH', p: '/projects/{*,*/endpoints/*,*/branches/*/databases/*}', why: 'Changes project, compute or database settings: history retention, the IP allow list, compute size and whether it is disabled, a database name. A wrong value locks clients out or breaks connection strings.' },
      // .../reference/updateprojectbranch (name, protected, expiry), .../reference/updatesnapshot (name, expires_at),
      // .../reference/setsnapshotschedule (backup schedule)
      { id: 'neon.retention', m: 'PATCH,PUT', p: '/projects/*/{branches/*,snapshots/*,branches/*/backup_schedule}', why: 'Changes whether a branch is protected, when a branch or snapshot expires, or how often backups are taken. A shorter life or a missing backup is only noticed when it is needed.' },
      // .../reference/assignprojectvpcendpoint ("Set VPC endpoint restriction"), .../reference/assignorganizationvpcendpoint
      { id: 'neon.network', m: 'POST', p: '/{projects/*/vpc_endpoints/*,organizations/*/vpc/region/*/vpc_endpoints/*}', why: 'Restricting a project to a VPC endpoint locks out every client that is not on it.' },
      // .../reference/createprojecttransferrequest, .../reference/acceptprojecttransferrequest, .../reference/transferprojectsfromorgtoorg
      { id: 'neon.transfer', m: 'POST,PUT', p: '/{projects/*/transfer_requests,projects/*/transfer_requests/*,organizations/*/projects/transfer,users/me/projects/transfer}', why: 'Transferring a project hands it to another account or organization.' },
      // .../reference/createapikey ("the key is only returned once"), .../reference/createorgapikey, .../reference/createcredential,
      // .../reference/revealcredential, .../reference/rotatecredential, .../reference/rotateprojectbranchrealtimesecret
      { id: 'neon.secrets', m: 'POST', p: '/{api_keys,organizations/*/api_keys,projects/*/branches/*/credentials,projects/*/branches/*/credentials/*/reveal,projects/*/branches/*/credentials/*/rotate,projects/*/branches/*/realtime/rotate_secret}', why: 'Makes, reveals or rotates a key. A new or revealed key is one the agent holds outside Counterseal, and a rotated one stops working for everything that used the old value.' },
      // .../reference/grantpermissiontoproject, .../reference/setprojectmemberrole, .../reference/updateorganizationmember,
      // .../reference/createorganizationinvitations
      { id: 'neon.access', m: 'POST,PUT,PATCH', p: '/{projects/*/permissions,projects/*/members/*/role,organizations/*/members/*,organizations/*/invitations}', why: 'Gives someone access or changes a role. Access given to the wrong person is a way in that does not go through Counterseal.' },
      // Neon Auth: .../reference/addneonauthdomaintoredirecturiwhitelist, .../reference/updateneonauthoauthprovider,
      // .../reference/updateneonauthuserrole, .../reference/updateneonauthemailserver, .../reference/updateneonauthconfig and the rest of /auth
      { id: 'neon.auth', m: 'POST,PUT,PATCH', p: '/projects/{auth/**,*/auth/**,*/branches/*/auth,*/branches/*/auth/**}', why: 'Changes Neon Auth: trusted redirect domains, OAuth providers, email servers, user roles. A wrong trusted domain or role can let the wrong people sign in.' },
      // .../reference/createprojectbranchfunctiondeployment ("The newest deployment becomes active"), .../reference/updateprojectbranchfunction
      { id: 'neon.function', m: 'POST,PATCH', p: '/projects/*/branches/*/functions/{*,*/deployments}', why: 'Deploying or changing a branch function replaces the code that runs there (the newest deployment becomes active).' },
    ],
  },

  // Fly.io Machines API. Source: https://docs.fly.io/api/machines/openapi.json (100 operations read on 9 Oct 2026). Reference
  // pages are https://docs.fly.io/api/machines/<group>/<operation>, named per rule. Paths are relative to /v1. The flyctl
  // GraphQL API is a different host and is not brokered. Send the whole token line `fly tokens create` prints ("FlyV1 fm2_...",
  // prefix included, https://fly.io/auth.md); it goes upstream as `Authorization: Bearer <token>`.
  fly: {
    name: 'Fly.io',
    host: 'api.machines.dev',
    base: '/v1',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    note: 'Machines API only; paths are relative to /v1. Vault the whole token line that fly tokens create prints (FlyV1 fm2_...).',
    secretRe: /^(?:FlyV1 )?[\x21-\x7e]+$/,
    irreversible: [
      // .../apps/destroy-app, .../volumes/destroy-volume, .../machines/destroy-machine, .../tls-certificates/remove-certificate,
      // .../apps/remove-ip-assignment-from-app, .../postgres-clusters/delete-postgres-cluster. Fly docs
      // (https://docs.fly.io/volumes/volume-manage): destroying a volume "permanently delete[s] all its data" and "There is no undo";
      // a deleted volume's id can be listed for 24 hours and snapshots (5 days by default) "may still be restorable".
      { id: 'fly.delete', m: 'DELETE', p: '/**', why: 'Any DELETE on Fly.io removes something. Destroying a volume deletes its data with no undo (its snapshots may stay restorable for a few days); destroying an app with force=true stops every Machine and deletes the app at once.' },
      // .../machines/execute-command: "Execute a command on a specific Machine"
      { id: 'fly.exec', m: 'POST', p: '/apps/*/machines/*/exec', why: 'Runs a command inside a live Machine. Anything the Machine can do to its volume and its network, this can do.' },
      // .../machines/update-machine: "Update a Machine's configuration using the details provided in the request body."
      { id: 'fly.machine-update', m: 'POST', p: '/apps/*/machines/*', why: 'Replaces a Machine configuration (image, environment, mounts, services). It is a deploy to whatever that Machine serves.' },
      // .../machines/stop-machine, .../machines/suspend-machine, .../machines/signal-machine (SIGKILL is allowed),
      // .../machines/cordon-machine ("disabling its services, so the Fly Proxy won't route requests to it")
      { id: 'fly.machine-stop', m: 'POST', p: '/apps/*/machines/*/{stop,suspend,signal,cordon}', why: 'Takes a Machine out of service: stopped, suspended, killed by a signal, or cordoned so the proxy sends it no traffic.' },
      // .../volumes/extend-volume, .../volumes/update-volume (auto_backup_enabled, snapshot_retention). Fly docs: you "can't make a volume smaller".
      { id: 'fly.volume', m: 'PUT', p: '/apps/*/volumes/{*,*/extend}', why: 'Extending a volume cannot be undone (volumes cannot be made smaller) and is billed. Changing snapshot retention or backups decides how long data can be recovered.' },
      // .../secrets/update-app-secrets-belonging-to-an-app, .../secrets/create-or-update-secret, .../secrets/create-or-update-a-secret-key,
      // .../secrets/generate-a-random-secret-key
      { id: 'fly.secrets', m: 'POST', p: '/apps/*/{secrets,secrets/*,secretkeys/*,secretkeys/*/generate}', why: 'Overwrites app secrets. The old value is not kept.' },
      // .../apps/create-app-deploy-token
      { id: 'fly.token', m: 'POST', p: '/apps/*/deploy_token', why: 'Makes a deploy token. The agent would then hold a real key that does not go through Counterseal.' },
      // .../postgres-clusters/rotate-user-password ("optionally terminating the user's existing sessions"), .../postgres-clusters/update-user-role
      { id: 'fly.postgres', m: 'POST,PATCH', p: '/postgres/*/users/{*,*/rotate_password}', why: 'Rotating a Postgres password or changing a role breaks every client that still uses the old one.' },
    ],
  },

  // Resend API. Source: https://github.com/resend/resend-openapi (resend.yaml 1.5.1, read on 9 Oct 2026) and the endpoint list at
  // https://resend.com/docs/llms.txt (it also lists the Inboxes endpoints the OpenAPI file lacks). Reference pages are
  // https://resend.com/docs/api-reference/<group>/<operation>, named per rule. A sent email cannot be unsent.
  resend: {
    name: 'Resend',
    host: 'api.resend.com',
    base: '',
    auth: (k) => ({ authorization: `Bearer ${k}` }),
    keyHint: /^re_/,
    irreversible: [
      // .../domains/delete-domain (a sending domain stops sending), .../audiences/delete-audience, .../contacts/delete-contact,
      // .../segments/delete-segment, .../api-keys/delete-api-key, .../webhooks/delete-webhook, .../templates/delete-template
      { id: 'rs.delete', m: 'DELETE', p: '/**', why: 'Any DELETE on Resend removes something (domain, audience, contact, segment, API key, webhook, template). A deleted sending domain stops all sending from it, and the API has no undelete.' },
      // .../emails/send-batch-emails: "Up to 100 emails in a single call", each with up to 50 recipients in `to`
      { id: 'rs.batch', m: 'POST', p: '/emails/batch', why: 'Sends up to 100 emails in one call, each to up to 50 recipients. Sent email cannot be unsent.' },
      // .../broadcasts/send-broadcast ("Send or schedule a broadcast"), .../broadcasts/create-broadcast (`send: true` sends at once)
      { id: 'rs.broadcast', m: 'POST', p: '/broadcasts/*/send', why: 'Sends a broadcast to every contact in its segment. Sent email cannot be unsent.' },
      { id: 'rs.broadcast-now', m: 'POST', p: '/broadcasts', body: rsBroadcastNow, why: 'Creating a broadcast with send=true sends it to its whole segment at once. Only a draft is safe. Sent email cannot be unsent.' },
      // .../emails/send-email: "to ... Max 50"; `cc` and `bcc` take lists too
      { id: 'rs.recipients', m: 'POST', p: '/emails', body: rsRecipients, why: 'An email to more than one recipient (to, cc or bcc), a list hidden in one address, or a request Counterseal cannot read. One recipient passes; sent email cannot be unsent.' },
      // .../automations/create-automation and .../automations/update-automation: status enabled, or new steps on an automation
      { id: 'rs.automation', m: 'POST', p: '/automations', body: rsAutomation(false), why: 'An automation that is enabled emails contacts on its own from then on. Create it disabled and enable it yourself.' },
      { id: 'rs.automation-edit', m: 'PATCH', p: '/automations/*', body: rsAutomation(true), why: 'Enabling an automation, or changing the steps of one, changes what it emails to contacts from then on.' },
      // .../suppressions/remove-batch-suppressions: removing a suppression lets mail go again to an address that bounced or complained
      { id: 'rs.suppression', m: 'POST', p: '/suppressions/batch/remove', why: 'Removing suppressions lets email go again to addresses that bounced or complained, which can hurt the sending reputation of the whole domain.' },
      // .../webhooks/rotate-signing-secret
      { id: 'rs.webhook-secret', m: 'POST', p: '/webhooks/*/signing-secret/rotate', why: 'Rotating a webhook signing secret breaks verification for every receiver that still uses the old one.' },
      // Inboxes (private beta, in the docs but not yet in the OpenAPI file): .../inboxes/send-draft, .../inboxes/reply-thread-email
      // (reply_all, "50 total recipients") and .../inboxes/forward-thread-email ("to, cc, and bcc combined can't exceed 50")
      { id: 'rs.inbox-send', m: 'POST', p: '/inboxes/*/{drafts/*/send,threads/*/emails/*/reply,threads/*/emails/*/forward}', why: 'Sends from an inbox: a draft, a reply (with reply_all to everyone on the thread) or a forward to up to 50 recipients. Sent email cannot be unsent.' },
      // .../api-keys/create-api-key: "full_access - Can create, delete, get, and update any resource"
      { id: 'rs.api-key', m: 'POST', p: '/api-keys', why: 'Makes a Resend API key, possibly with full access. The agent would then hold a real key that does not go through Counterseal.' },
    ],
  },

  // Shopify Admin GraphQL API. The host is the merchant's own store, "<store>.myshopify.com", stored with the credential and
  // checked by storeHost() (the one place a vaulted key's destination is not fixed in this file). Only the GraphQL endpoint is
  // brokered: the legacy REST Admin API and everything else on the store (storefront pages, app proxies) are refused, so a
  // key never reaches a page it was not meant for. Mutation names come from Shopify's published Admin GraphQL schema
  // (https://shopify.dev/docs/api/admin-graphql); reference pages are https://shopify.dev/docs/api/admin-graphql/2026-07/mutations/<name>.
  shopify: {
    name: 'Shopify',
    host: '*.myshopify.com',
    base: '',
    auth: (k) => ({ 'x-shopify-access-token': k }),
    keyHint: /^(shpat_|shpca_|shpua_)/,
    perCredentialHost: { suffix: '.myshopify.com', label: 'Store address', example: 'your-store.myshopify.com' },
    paths: /^\/admin\/api\/(?:20\d\d-(?:01|04|07|10)|unstable)\/graphql\.json$/,
    note: 'Admin GraphQL API only: POST /admin/api/<version>/graphql.json (a version such as 2026-07, or unstable).',
    irreversible: [
      // the endpoint takes POST only (https://shopify.dev/docs/api/admin-graphql); GET and the other methods are not normal client paths
      { id: 'sh.get', m: 'GET', p: '/admin/api/*/graphql.json', why: 'Shopify GraphQL over GET is not a normal client path.' },
      { id: 'sh.method', m: 'PUT,PATCH,DELETE', p: '/**', why: 'Shopify GraphQL is POST only; a PUT, PATCH or DELETE is not a normal client path. (Every other path on the store is refused before the map is asked.)' },
      // a batch, a persisted query, a document id, a fragment spread at the mutation root, a form reading, or text that is not one JSON object
      { id: 'sh.unreadable', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.unreadable'), why: `A GraphQL request ${BRAND.name} cannot read with certainty: a batch, a persisted query, a fragment at the mutation root, a repeated key, or a body that is not one JSON object with a query.` },
      // .../mutations/bulkOperationRunMutation: "executes a specified GraphQL mutation multiple times using input data from a JSONL file"
      { id: 'sh.bulk', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.bulk'), why: `A bulk operation runs a mutation once per line of an uploaded file, which ${BRAND.name} cannot read.` },
      // .../mutations/productDelete ("Permanently deletes a product and all its associated data"), orderDelete ("Permanently deletes"),
      // collectionDelete, customerDelete, pageDelete, discountCodeDelete, webhookSubscriptionDelete, urlRedirectBulkDeleteAll and every
      // other name with delete or destroy; deliveryProfileRemove, shopLocaleDisable ("also deletes all translations"),
      // inventoryDeactivate, inventoryBulkToggleActivation, locationDeactivate, appUninstall ("This action is irreversible")
      { id: 'sh.delete', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.delete'), why: 'A Shopify mutation that deletes or removes data: any name with delete or destroy, a shipping profile, a locale and its translations, inventory at a location, a location, or the app itself. Shopify says product, order and app removals are permanent.' },
      // .../mutations/refundCreate, returnProcess, orderCapture, paymentScheduleCapture, orderCreateMandatePayment, subscriptionBillingAttemptCreate,
      // subscriptionBillingCycleCharge, subscriptionBillingCycleBulkCharge, orderMarkAsPaid, orderCreateManualPayment, transactionVoid,
      // shippingLabelPurchase, shopifyPaymentsPayoutAlternateCurrencyCreate, appPurchaseOneTimeCreate, appSubscriptionCreate,
      // appSubscriptionLineItemUpdate, appUsageRecordCreate
      { id: 'sh.money', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.money'), why: 'A Shopify mutation that moves money or changes what counts as paid: refunds, captures, charges to customers or to the merchant, marking an order paid, voiding a payment, buying a shipping label, a payout.' },
      // .../mutations/giftCardCreate, giftCardCredit, giftCardDebit, giftCardDeactivate ("cannot be re-enabled"), giftCardUpdate,
      // storeCreditAccountCredit, storeCreditAccountDebit
      { id: 'sh.giftcard', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.giftcard'), why: 'Gift cards and store credit are spendable value: creating, crediting, debiting or deactivating them (a deactivated gift card cannot be re-enabled).' },
      // .../mutations/orderCancel: "Order cancellation is irreversible."; .../mutations/subscriptionContractCancel, subscriptionContractExpire
      { id: 'sh.cancel', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.cancel'), why: 'Cancelling an order is irreversible (Shopify), and can refund the customer, restock inventory and notify them. A cancelled or expired subscription contract cannot be activated again.' },
      // .../mutations/customerRequestDataErasure, customerMerge, customerPaymentMethodRevoke, privacyFeaturesDisable
      { id: 'sh.customer-data', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.customer-data'), why: 'Erases, merges or disables protections on customer data: a data erasure request (Shopify has a separate mutation to cancel one), merging two customers, revoking a stored payment method, switching off privacy features.' },
      // .../mutations/delegateAccessTokenCreate, appRevokeAccessScopes
      { id: 'sh.access', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.access'), why: 'Makes a delegate access token (a key the agent would hold outside Counterseal) or revokes access scopes the app depends on.' },
      // .../mutations/themePublish ("Publishes a theme"), themeFilesUpsert and themeFilesCopy ("Copying to existing theme files will overwrite them")
      { id: 'sh.theme', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.theme'), why: 'Publishing a theme, or writing theme files, can change the live storefront. Counterseal cannot tell which theme is live.' },
      // .../mutations/webhookSubscriptionCreate, webhookSubscriptionUpdate: "Modify the endpoint URL" that store events go to
      { id: 'sh.webhook', m: 'POST', p: '/admin/api/*/graphql.json', body: shopify('sh.webhook'), why: 'A webhook subscription sends store events (orders, customers) to a URL. Changing one can stop fulfilment or send customer data elsewhere.' },
    ],
  },
};

/** the public description of the map: what GET /v1/meta serves (next to the app origin) and what site/public/data/meta.json
 * holds for the website when the Worker is not reachable (regenerate it with node scripts/gen-meta.mjs) */
export function metaOf() {
  return {
    mapVersion: MAP_VERSION,
    common: COMMON.map((r) => ({ id: r.id, method: r.m, path: r.p, why: r.why })),
    providers: Object.entries(PROVIDERS).map(([id, p]) => ({
      id, name: p.name, host: p.host, ...(p.perCredentialHost ? { perCredentialHost: p.perCredentialHost } : {}), ...(p.note ? { note: p.note } : {}),
      irreversible: p.irreversible.map((r) => ({ id: r.id, method: r.m, path: r.p, why: r.why })),
    })),
  };
}

/** tiny glob: * = one segment, ** = any depth, {a,b} = alternatives (which may use * and ** too; no nesting).
 * Throws on an unbalanced or nested brace. */
export function globToRe(g) {
  const part = (s) => {
    let re = '';
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '*') { if (s[i + 1] === '*') { re += '.*'; i++; } else re += '[^/]*'; }
      else if (c === '{') {
        const j = s.indexOf('}', i);
        if (j < 0 || s.slice(i + 1, j).includes('{')) throw new Error('bad glob');
        re += '(?:' + s.slice(i + 1, j).split(',').map(part).join('|') + ')';
        i = j;
      } else if (c === '}') throw new Error('bad glob');
      else re += esc(c);
    }
    return re;
  };
  return new RegExp('^' + part(String(g)) + '$');
}
const esc = (s) => s.replace(/[.+?^$()|[\]\\{}]/g, '\\$&');
const reCache = new Map();
export function globMatch(g, path) {
  let r = reCache.get(g);
  if (!r) { r = globToRe(g); if (reCache.size > 2000) reCache.clear(); reCache.set(g, r); } // bounded: policies are user text
  return r.test(path);
}

/** the path rules are matched against: canonical, and lowercased on case-insensitive providers */
export const matchPath = (provider, path) => (PROVIDERS[provider]?.ci ? path.toLowerCase() : path);

/** first irreversible rule this request trips, or null. `path` is canonical; `search` is the raw query string.
 * Fail closed on the shapes a server may treat as the same call:
 * - the map is matched case-insensitively on every provider (the rules are lower case; upstream still gets the case);
 * - a trailing format suffix ("/v1/refunds.json", Rails style) is also tried without it;
 * - HEAD trips the GET rules (many frameworks run the GET handler for HEAD);
 * - a method override (`_method`) trips COMMON on every provider. */
export function irreversibleRule(provider, method, path, body, search = '') {
  const P = PROVIDERS[provider];
  for (const r of COMMON) if (r.test(body, search)) return r;
  const lp = String(path).toLowerCase();
  const paths = [lp, lp.replace(/(\/[^/]+)\.[a-z0-9]{1,8}$/, '$1')];
  const methods = method === 'HEAD' ? ['HEAD', 'GET'] : [method];
  for (const r of P.irreversible) {
    if (!r.m.split(',').some((x) => methods.includes(x))) continue;
    if (!paths.some((p) => globMatch(r.p, p))) continue;
    if (r.body && !r.body(body, search)) continue;
    return r;
  }
  return null;
}
