// Is this SQL plainly a read? For the MCP wrapper (counterseal mcp wrap): a tool call whose SQL argument is anything else waits for
// your passkey. Zero dependencies.
//
// This is a copy of the tokenizer and the read-only check in server/src/providers.js (sqlTokens, sqlReadOnly and the word lists
// they use), which hold SQL sent through the Cloudflare D1 and Supabase management APIs. The CLI is published on its own and
// cannot import the server, so the code is copied; server/test/mcp-wrap.test.js fails if the two ever differ (it compares the
// source of both functions and runs the same statements through both). Change the server's, then copy it here.
const LIMITS = { sql: 32_768 }; // providers.js LIMITS.sql: longer SQL is not plainly a read

// A real tokenizer: single-quoted strings, double-quoted and backtick identifiers, -- and nested /* */ comments.
// Returns null (unreadable, so held) for unterminated strings or comments, backslashes inside strings (E'' escapes
// would shift where a string ends) and any $ that is not a $1 style parameter (dollar quotes, $$ bodies).
export function sqlTokens(sql) {
  const s = String(sql ?? ''), out = [];
  if (s.length > LIMITS.sql) return null; // too long to read within the CPU budget: unreadable, so held
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
