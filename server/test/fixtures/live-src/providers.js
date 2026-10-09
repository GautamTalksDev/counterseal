// Upstream APIs LEASH can broker, and the map of operations that cannot be undone.
// The irreversible map is the product: each rule names a real way an agent can destroy something, with the incident
// or doc it comes from. Rules match on method + path (glob) and, where the danger is in the body, on the body.
// Body checks fail closed: a body LEASH cannot read on a route that has a body rule is held.
// Version it; every change must come with a test in test/bypass.test.js, test/hardening.test.js or test/leash.test.js.
export const MAP_VERSION = '2026-10-09.1';

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
  { id: 'any.method-override', m: '*', p: '/**', always: true, test: methodOverride, why: 'The request asks the API to treat it as a different method (_method). LEASH matches its rules on the real method, so these always wait for a human.' },
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
export function gqlMutationFields(src) {
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
  const gq = (q) => { const f = gqlMutationFields(q); return f === null ? 'GraphQL LEASH could not read' : f.length ? 'GraphQL mutations: ' + f.join(', ') : 'GraphQL query (read only)'; };
  if (j && typeof j === 'object' && !Array.isArray(j) && typeof j.query === 'string' && !/^\s*(select|with|explain|show|insert|update|delete|drop|create|alter)\b/i.test(j.query)) out.push(gq(j.query));
  const sqls = sqlBodies(body);
  if (sqls) for (const q of sqls) out.push('SQL: ' + sqlSummary(q));
  if (Array.isArray(j)) out.push(`Batch of ${j.length} requests`);
  const m = /[?&]query=([^&]*)/.exec(search || '');
  if (m) { try { out.push(gq(decodeURIComponent(m[1].replace(/\+/g, ' ')))); } catch { out.push('Query string LEASH could not read'); } }
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
      { id: 'gh.graphql', m: 'POST', p: '/graphql', body: ghGraphqlHold, why: 'A GitHub GraphQL mutation (deleteRepository, transferRepository, updateRepository and every other write), or a request LEASH cannot read.' },
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
      { id: 'cf.d1-import', m: 'POST', p: '/accounts/*/d1/database/*/import', body: d1Import, why: 'Importing an SQL file into a production D1 database runs SQL LEASH cannot read.' },
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
      { id: 'rw.mutation', m: 'POST', p: '/**', body: railwayHold, why: 'A Railway mutation other than a redeploy or restart, or a request LEASH cannot read (PocketOS lost production to one volumeDelete).' },
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
};

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
  if (!r) { r = globToRe(g); reCache.set(g, r); }
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
