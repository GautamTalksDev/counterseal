// Counterseal shell map: which shell commands a coding agent should not run without a passkey approval.
// Zero dependencies, pure (no file system or network access of its own: callers pass what it may read).
//
// WHAT THIS IS. A seatbelt, not a sandbox. It runs on the machine of the agent it guards, reads the text of one
// command, and says whether that text matches a rule on the map of commands that cannot be taken back. It is only
// as strong as the hook that calls it, and the agent runs as the same user as the hook.
//
// WHAT IT READS. A real shell parser, not a regex: quoting, backslashes, $'..' strings, ; && || | & newlines,
// ( ) { } groups, if/for/while/case, functions, here-documents, $(..) and `..` and <(..) substitutions, brace
// expansion, simple variable assignments in the same command line, cd, and these wrappers: sudo, env, command,
// exec, nohup, time, nice, timeout, xargs, find -exec, watch, sh/bash/zsh -c (also -lc), eval, ssh, docker exec,
// kubectl exec, npx and its relatives, npm/pnpm/yarn/bun scripts (read from package.json), and a few more.
//
// WHAT IT DOES NOT READ (documented limits, see docs): aliases and shell functions defined outside the command
// line; the contents of script files (bash script.sh, ./deploy.sh, make, just), Makefiles; code in other languages
// (python -c, node -e); PowerShell and cmd; values of variables set elsewhere; globs (they stay unexpanded);
// encoded payloads (a decoder piped into a shell is held without being read); anything past depth 3 of nested
// shells or 24 levels of nesting; symlinks. A program name that is not a literal is held only when some word of
// the command is a keyword (destroy, delete, drop, truncate, reset, force, rm).
//
// Every rule has positive, negative and evasion vectors in sdk/shellmap.test.mjs.
export const SHELL_MAP_VERSION = '2026-10-10.1';

const SENT = '\uE000'; // marks a piece of a word whose value is not known (a variable, a substitution, a glob)

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

// ---------------------------------------------------------------- SQL: what the guard holds (added by the guard)
// The server holds anything that is not a plain read, because it guards production. A coding agent also runs
// ordinary writes against a local development database, so the guard holds the statements that destroy: DROP,
// TRUNCATE, DELETE or UPDATE without WHERE (or with a WHERE that is always true), ALTER ... DROP, code it cannot read.
// With `remote` (a database host that is not this machine) any write is held.
const SQL_CODE = new Set(['do', 'call', 'exec', 'execute']);
const tautology = (after) => /(^|\bor\s+)(1\s*=\s*1|true)\b/.test(after.map((x) => x.v).join(' '));
/** null when the SQL may run without a human, otherwise a short reason */
export function sqlGuard(sql, { remote = false } = {}) {
  const tk = sqlTokens(sql);
  if (!tk) return 'SQL the guard cannot read (an unterminated string or comment, a backslash in a string, or dollar quoting)';
  const stmts = [[]];
  for (const x of tk) x.t === ';' ? stmts.push([]) : stmts[stmts.length - 1].push(x);
  for (const t of stmts) {
    if (!t.length) continue;
    const words = t.filter((x) => x.t === 'w').map((x) => x.v);
    const first = t[0].t === 'w' ? t[0].v : '';
    if (words.includes('drop')) return 'DROP removes a table, column, database or other object for good';
    if (first === 'truncate') return 'TRUNCATE empties a table for good';
    if (SQL_CODE.has(first)) return `${first.toUpperCase()} runs code the guard cannot read`;
    if (first === 'copy' && words.includes('program')) return 'COPY ... PROGRAM runs a shell command from the database';
    if (t.some((x, i) => x.t === 'w' && SQL_FN.test(x.v) && t[i + 1]?.v === '(')) return 'calls a database function with side effects';
    const w = t.findIndex((x) => x.t === 'w' && x.v === 'where');
    for (const verb of ['delete', 'update']) {
      if (first !== verb && !(first === 'with' && words.includes(verb))) continue;
      if (w < 0) return `${verb.toUpperCase()} without WHERE changes every row`;
      if (tautology(t.slice(w + 1))) return `${verb.toUpperCase()} with a WHERE that is always true changes every row`;
    }
  }
  if (remote && !sqlReadOnly(sql)) return 'it is not a plain read, and the database is on another machine';
  return null;
}

// ---------------------------------------------------------------- small path and text helpers (POSIX, lexical)
const trimSlash = (p) => (p.length > 1 ? p.replace(/\/+$/, '') || '/' : p);
/** lexical normalisation of an absolute path: no symlink lookups */
export function normPath(p) {
  const out = [];
  for (const seg of String(p).split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return '/' + out.join('/');
}
const isInside = (p, root) => p === root || p.startsWith(root === '/' ? '/' : root + '/');
const base = (p) => String(p).replace(/\/+$/, '').split('/').pop();
const lc = (s) => String(s).toLowerCase();

/** tiny glob as in the server map: * = one segment, ** = any depth, {a,b} alternatives */
export function globMatch(g, path) {
  const part = (s) => {
    let re = '';
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '*') { if (s[i + 1] === '*') { re += '.*'; i++; } else re += '[^/]*'; }
      else if (c === '{') {
        const j = s.indexOf('}', i);
        if (j < 0) throw new Error('bad glob');
        re += '(?:' + s.slice(i + 1, j).split(',').map(part).join('|') + ')';
        i = j;
      } else re += c.replace(/[.+?^$()|[\]\\{}]/g, '\\$&');
    }
    return re;
  };
  return new RegExp('^' + part(String(g)) + '$').test(path);
}

// ---------------------------------------------------------------- redaction
// What is sent to the server and shown on your phone is the command with credentials removed. The approval is bound to
// that text, so two commands that differ only in a secret are the same request.
const REDACTIONS = [
  [/(\b[a-z][a-z0-9+.-]*:\/\/)([^\s/@:'"]*):([^\s/@'"]+)@/gi, '$1$2:[redacted]@'],
  [/(\b[a-z][a-z0-9+.-]*:\/\/)([^\s/@:'"]{8,})@/gi, '$1[redacted]@'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[redacted private key]'],
  [/\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}/g, '$1 [redacted]'],
  [/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g, '[redacted]'],
  [/\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}/g, '[redacted]'],
  [/\b(?:lsh|lsg)_[A-Za-z0-9_-]{16,}/g, '[redacted]'],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[redacted]'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, '[redacted]'],
  [/\bnpm_[A-Za-z0-9]{30,}/g, '[redacted]'],
  [/\b(?:sbp|shpat|shpca|shppa|re)_[A-Za-z0-9]{16,}/g, '[redacted]'],
  [/\bAIza[A-Za-z0-9_-]{30,}/g, '[redacted]'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '[redacted]'],
  [/(\b[A-Za-z_][A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)[A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|]+)/gi, '$1=[redacted]'],
  [/(--?(?:password|passwd|pwd|token|secret|api-?key|auth|access-?key|client-secret)(?:=|\s+))("[^"]*"|'[^']*'|[^\s;&|]+)/gi, '$1[redacted]'],
  [/(\bmysql(?:admin|dump)?\b[^|;&\n]*?\s-p)(?!\d+(?:\s|$))(\S+)/g, '$1[redacted]'],
];
export function redact(text) {
  let s = String(text ?? '');
  for (const [re, to] of REDACTIONS) s = s.replace(re, to);
  return s;
}

/** JSON with sorted keys at every level (a stable text for hashing and for what an approver sees) */
export function canonicalJson(v) {
  const walk = (x) => {
    if (Array.isArray(x)) return x.map(walk);
    if (x && typeof x === 'object') return Object.fromEntries(Object.keys(x).sort().map((k) => [k, walk(x[k])]));
    return x;
  };
  return JSON.stringify(walk(v));
}

// ---------------------------------------------------------------- shell parser
// A recursive descent parser over characters. It builds a small tree (commands with words and redirections, pipes,
// lists, groups, if/for/while/case, functions); expansions are kept as parts of a word and resolved later.
// Anything it cannot read throws Unreadable, and classify() then falls back to a plain scan of the text.
class Unreadable extends Error {}
const MAX_DEPTH = 24, MAX_NODES = 20000, MAX_STEPS = 60000;
const META = new Set([' ', '\t', '\r', '\n', ';', '&', '|', '(', ')', '<', '>']);
const NAME0 = /[A-Za-z_]/, NAMEN = /[A-Za-z0-9_]/;
const STOP_WORDS = new Set(['then', 'elif', 'else', 'fi', 'do', 'done', 'esac', '}', ']]']);

class Parser {
  constructor(src, depth = 0, budget = { n: 0 }) {
    this.s = String(src); this.i = 0; this.depth = depth; this.b = budget; this.pending = []; this.allMeta = false; this.dq = false;
    if (depth > MAX_DEPTH) throw new Unreadable('nested too deeply');
  }
  eof() { return this.i >= this.s.length; }
  tick() { if (++this.b.n > MAX_NODES) throw new Unreadable('too many commands'); }
  // blanks, backslash-newline and comments (a # at the start of a token)
  skipBlank() {
    for (;;) {
      const c = this.s[this.i];
      if (c === ' ' || c === '\t' || c === '\r') this.i++;
      else if (c === '\\' && this.s[this.i + 1] === '\n') this.i += 2;
      else if (c === '#') { while (this.i < this.s.length && this.s[this.i] !== '\n') this.i++; }
      else break;
    }
  }
  newline() { // at \n: step over it and read the bodies of here-documents opened on the line
    this.i++;
    const open = this.pending; this.pending = [];
    for (const r of open) this.heredocBody(r);
  }
  heredocBody(r) {
    const lines = [];
    for (;;) {
      if (this.i >= this.s.length) { r.unterminated = true; break; }
      const j = this.s.indexOf('\n', this.i);
      const line = this.s.slice(this.i, j < 0 ? this.s.length : j);
      this.i = j < 0 ? this.s.length : j + 1;
      const cmp = (r.strip ? line.replace(/^\t+/, '') : line).replace(/\r$/, '');
      if (cmp === r.delim) break;
      lines.push(r.strip ? line.replace(/^\t+/, '') : line);
    }
    r.body = lines.length ? lines.join('\n') + '\n' : '';
  }
  skipBlankNl() { for (;;) { this.skipBlank(); if (this.s[this.i] === '\n') this.newline(); else break; } }
  skipSeps() {
    for (;;) {
      this.skipBlank();
      const c = this.s[this.i];
      if (c === '\n') this.newline();
      else if (c === ';' && this.s[this.i + 1] !== ';' && this.s[this.i + 1] !== '&') this.i++;
      else break;
    }
  }
  // the next word if it is plain text (no quote, escape or expansion in it), else null
  peekRaw() {
    let j = this.i;
    while (j < this.s.length && !META.has(this.s[j])) {
      if ("'\"\\$`".includes(this.s[j])) return null;
      j++;
    }
    return this.s.slice(this.i, j);
  }
  atStop(stops) {
    if (!stops) return false;
    const c = this.s[this.i];
    if (c === ')') return stops.includes(')');
    if (c === ';') return stops.includes(';;');
    const w = this.peekRaw();
    return w !== null && stops.includes(w);
  }
  expectWord(word) {
    this.skipBlankNl();
    if (this.peekRaw() !== word) throw new Unreadable('expected ' + word);
    this.i += word.length;
  }
  expectChar(c) { this.skipBlank(); if (this.s[this.i] !== c) throw new Unreadable('expected ' + c); this.i++; }

  parseList(stops) {
    const items = [];
    for (;;) {
      this.skipSeps();
      if (this.eof() || this.atStop(stops)) break;
      items.push(this.parseAndOr());
      this.skipBlank();
      const c = this.s[this.i];
      if (c === ';' && this.s[this.i + 1] !== ';' && this.s[this.i + 1] !== '&') this.i++;
      else if (c === '&' && this.s[this.i + 1] !== '&') this.i++;
    }
    return { t: 'seq', items };
  }
  parseAndOr() {
    const parts = [this.parsePipeline()];
    for (;;) {
      this.skipBlank();
      const two = this.s.substr(this.i, 2);
      if (two === '&&' || two === '||') { this.i += 2; this.skipBlankNl(); parts.push(this.parsePipeline()); } else break;
    }
    return parts.length === 1 ? parts[0] : { t: 'seq', items: parts };
  }
  parsePipeline() {
    this.skipBlank();
    for (;;) { // `!` and `time` in front of a pipeline
      const w = this.peekRaw();
      if (w === '!' || w === 'time') { this.i += w.length; this.skipBlank(); if (w === 'time' && this.peekRaw() === '-p') { this.i += 2; this.skipBlank(); } } else break;
    }
    const cmds = [this.parseCommand()];
    for (;;) {
      this.skipBlank();
      if (this.s[this.i] === '|' && this.s[this.i + 1] !== '|') {
        this.i++; if (this.s[this.i] === '&') this.i++;
        this.skipBlankNl();
        cmds.push(this.parseCommand());
      } else break;
    }
    return cmds.length === 1 ? cmds[0] : { t: 'pipe', cmds };
  }
  redirs(node) { for (;;) { this.skipBlank(); const r = this.tryRedirect(); if (!r) break; (node.redirs ||= []).push(r); } return node; }

  parseCommand() {
    this.tick(); this.skipBlank();
    if (this.eof()) throw new Unreadable('missing command');
    const c = this.s[this.i];
    if (c === '(') {
      if (this.s[this.i + 1] === '(') return this.arithCommand();
      this.i++;
      const body = this.nested(() => this.parseList([')']));
      this.expectChar(')');
      return this.redirs({ t: 'sub', body });
    }
    const w = this.peekRaw();
    if (w === '{') { this.i++; const body = this.nested(() => this.parseList(['}'])); this.expectWord('}'); return this.redirs({ t: 'group', body }); }
    if (w === 'if') return this.redirs(this.parseIf());
    if (w === 'for' || w === 'select') return this.redirs(this.parseFor());
    if (w === 'while' || w === 'until') return this.redirs(this.parseWhile());
    if (w === 'case') return this.redirs(this.parseCase());
    if (w === '[[') return this.redirs(this.parseTest());
    if (w === 'function') return this.parseFunction();
    return this.parseSimple();
  }
  nested(fn) {
    if (++this.depth > MAX_DEPTH) throw new Unreadable('nested too deeply');
    try { return fn(); } finally { this.depth--; }
  }
  arithCommand() { // (( ... ))
    let d = 0;
    for (; this.i < this.s.length; this.i++) {
      if (this.s[this.i] === '(') d++;
      else if (this.s[this.i] === ')') { d--; if (d === 0) { this.i++; return this.redirs({ t: 'noop' }); } }
    }
    throw new Unreadable('unterminated ((');
  }
  parseIf() {
    this.i += 2;
    const conds = [], bodies = [];
    conds.push(this.nested(() => this.parseList(['then']))); this.expectWord('then');
    bodies.push(this.nested(() => this.parseList(['elif', 'else', 'fi'])));
    for (;;) {
      this.skipBlankNl();
      const w = this.peekRaw();
      if (w === 'elif') { this.i += 4; conds.push(this.nested(() => this.parseList(['then']))); this.expectWord('then'); bodies.push(this.nested(() => this.parseList(['elif', 'else', 'fi']))); }
      else if (w === 'else') { this.i += 4; bodies.push(this.nested(() => this.parseList(['fi']))); }
      else break;
    }
    this.expectWord('fi');
    return { t: 'if', conds, bodies };
  }
  parseFor() {
    this.i += this.peekRaw().length;
    this.skipBlank();
    if (this.s.startsWith('((', this.i)) { this.arithCommand(); this.skipSeps(); this.expectWord('do'); const body = this.nested(() => this.parseList(['done'])); this.expectWord('done'); return { t: 'for', name: null, words: null, body }; }
    const nameWord = this.readWord();
    const name = nameWord.parts.length === 1 && nameWord.parts[0].k === 'lit' ? nameWord.parts[0].s : null;
    this.skipBlankNl();
    let words = null;
    if (this.peekRaw() === 'in') {
      this.i += 2; words = [];
      for (;;) {
        this.skipBlank();
        const c = this.s[this.i];
        if (c === undefined || c === ';' || c === '\n') break;
        words.push(this.readWord());
      }
    }
    this.skipSeps();
    this.expectWord('do');
    const body = this.nested(() => this.parseList(['done']));
    this.expectWord('done');
    return { t: 'for', name, words, body };
  }
  parseWhile() {
    this.i += this.peekRaw().length;
    const cond = this.nested(() => this.parseList(['do']));
    this.expectWord('do');
    const body = this.nested(() => this.parseList(['done']));
    this.expectWord('done');
    return { t: 'while', cond, body };
  }
  parseCase() {
    this.i += 4;
    this.skipBlank();
    const word = this.readWord();
    this.skipBlankNl();
    this.expectWord('in');
    const clauses = [];
    for (;;) {
      this.skipSeps();
      if (this.eof()) throw new Unreadable('unterminated case');
      if (this.peekRaw() === 'esac') { this.i += 4; break; }
      this.skipBlank(); if (this.s[this.i] === '(') this.i++;
      const pats = [];
      for (;;) {
        this.skipBlank();
        if (this.s[this.i] === ')') { this.i++; break; }
        if (this.eof() || this.s[this.i] === '\n') throw new Unreadable('bad case pattern');
        pats.push(this.readWord(true));
      }
      const body = this.nested(() => this.parseList([';;', 'esac']));
      this.skipBlank();
      if (this.s[this.i] === ';') { this.i++; if (this.s[this.i] === ';') this.i++; if (this.s[this.i] === '&') this.i++; }
      clauses.push({ pats, body });
    }
    return { t: 'case', word, clauses };
  }
  parseTest() { // [[ ... ]]: the words matter only for the substitutions in them
    this.i += 2;
    const words = [];
    for (;;) {
      this.skipBlankNl();
      if (this.eof()) throw new Unreadable('unterminated [[');
      const c = this.s[this.i];
      if ('&|()<>!'.includes(c)) { this.i++; continue; }
      const w = this.readWord();
      if (w.parts.length === 1 && w.parts[0].k === 'lit' && !w.parts[0].q && w.parts[0].s === ']]') break;
      words.push(w);
    }
    return { t: 'test', words };
  }
  parseFunction() {
    this.i += 8;
    this.skipBlank();
    const name = this.readWord();
    this.skipBlank();
    if (this.s[this.i] === '(') { this.i++; this.expectChar(')'); }
    this.skipBlankNl();
    return { t: 'func', name: wordText(name), body: this.parseCommand() };
  }
  parseSimple() {
    const node = { t: 'cmd', assigns: [], words: [], redirs: [], start: this.i };
    for (;;) {
      this.skipBlank();
      if (this.eof()) break;
      const c = this.s[this.i];
      if (c === '\n' || c === ';' || c === '|' || c === ')') break;
      if (c === '&' && this.s[this.i + 1] !== '>') break;
      const r = this.tryRedirect();
      if (r) { node.redirs.push(r); continue; }
      if (c === '(') {
        if (node.words.length === 1 && !node.assigns.length && /^\(\s*\)/.test(this.s.slice(this.i, this.i + 40))) { // name() { ... }
          this.i++; this.expectChar(')'); this.skipBlankNl();
          return { t: 'func', name: wordText(node.words[0]), body: this.parseCommand() };
        }
        throw new Unreadable('unexpected (');
      }
      const w = this.readWord();
      if (!node.words.length) {
        const a = assignment(w);
        if (a) {
          if (a.word.parts.length === 0 && this.s[this.i] === '(') { // arr=(a b c)
            const j = this.matchParen(this.i); a.word = { parts: [{ k: 'var', name: '', q: false, mod: 'array' }], start: w.start, end: j + 1 }; this.i = j + 1;
          }
          node.assigns.push(a); continue;
        }
      }
      node.words.push(w);
    }
    node.end = this.i;
    node.raw = this.s.slice(node.start, node.end).trim();
    if (!node.words.length && !node.assigns.length && !node.redirs.length) throw new Unreadable('empty command at ' + this.i);
    return node;
  }
  // index of the ) that matches the ( at i, skipping quotes
  matchParen(i) {
    let d = 0;
    for (let j = i; j < this.s.length; j++) {
      const c = this.s[j];
      if (c === '\\') j++;
      else if (c === "'") { j = this.s.indexOf("'", j + 1); if (j < 0) break; }
      else if (c === '"') { for (j++; j < this.s.length && this.s[j] !== '"'; j++) if (this.s[j] === '\\') j++; }
      else if (c === '(') d++;
      else if (c === ')') { d--; if (d === 0) return j; }
    }
    throw new Unreadable('unbalanced (');
  }

  tryRedirect() {
    const m = /^(\d+|\{[A-Za-z_][A-Za-z0-9_]*\})?(&>>|&>|<<<|<<-|<<|<&|<>|<|>>|>&|>\||>)/.exec(this.s.slice(this.i, this.i + 24));
    if (!m) return null;
    const op = m[2], after = this.s[this.i + m[0].length];
    if ((op === '<' || op === '>') && after === '(' && !m[1]) return null; // <(..) and >(..) are substitutions
    this.i += m[0].length;
    this.skipBlank();
    if (op === '<<' || op === '<<-') {
      const w = this.readWord();
      const r = { op, fd: m[1], heredoc: true, delim: w.parts.map((p) => p.s ?? '').join(''), quoted: w.parts.some((p) => p.q), strip: op === '<<-', body: '', target: null };
      this.pending.push(r);
      return r;
    }
    const c = this.s[this.i];
    if (c === undefined || (META.has(c) && c !== '<' && c !== '>')) throw new Unreadable('redirection without a target');
    return { op, fd: m[1], target: this.readWord() };
  }

  // one word: parts are literals (q: quoted), variables, substitutions. A word with a brace expression also gets
  // `alts`: the words brace expansion makes of its text (that happens first, on the text as typed).
  // this.allMeta: the text of a ${V:-word}, where blanks and ; do not end the word; this.dq: that text inside double
  // quotes, where a single quote is just a letter.
  readWord(pattern = false, noBrace = false) {
    this.tick();
    const start = this.i, parts = [], dq = this.dq;
    let lit = '';
    const flush = () => { if (lit) { parts.push({ k: 'lit', s: lit, q: dq }); lit = ''; } };
    for (;;) {
      const c = this.s[this.i];
      if (c === undefined) break;
      if (META.has(c) && !this.allMeta) {
        if ((c === '<' || c === '>') && this.s[this.i + 1] === '(') { flush(); parts.push(this.procSub()); continue; }
        if (c === '|' && pattern) { lit += c; this.i++; continue; }
        break;
      }
      if (c === "'" && !dq) {
        const j = this.s.indexOf("'", this.i + 1);
        if (j < 0) throw new Unreadable('unterminated quote');
        flush(); parts.push({ k: 'lit', s: this.s.slice(this.i + 1, j), q: true }); this.i = j + 1;
      } else if (c === '"') {
        flush(); this.i++; this.dquote(parts);
      } else if (c === '\\') {
        const n = this.s[this.i + 1];
        if (n === '\n') { this.i += 2; continue; }
        if (dq) { if (n !== undefined && '$`"\\'.includes(n)) { lit += n; this.i += 2; } else { lit += '\\'; this.i++; } continue; }
        flush(); parts.push({ k: 'lit', s: n ?? '\\', q: true }); this.i += 2;
      } else if (c === '$') {
        flush(); this.dollar(parts, dq);
      } else if (c === '`') {
        flush(); parts.push(this.backtick(dq));
      } else if (c === '~' && this.i === start && !dq) {
        let j = this.i + 1;
        while (j < this.s.length && /[A-Za-z0-9._+-]/.test(this.s[j])) j++;
        const e = this.s[j];
        if (e === undefined || e === '/' || e === ':' || (META.has(e) && !this.allMeta)) { parts.push({ k: 'tilde', user: this.s.slice(this.i + 1, j) }); this.i = j; } else { lit += c; this.i++; }
      } else { lit += c; this.i++; }
    }
    flush();
    if (this.i === start) throw new Unreadable('unexpected ' + JSON.stringify(this.s[this.i] ?? 'end of text'));
    const word = { parts, start, end: this.i, raw: this.s.slice(start, this.i) };
    if (!pattern && !noBrace && !this.allMeta && word.raw.includes('{') && /[,.]/.test(word.raw)) {
      const raws = braceExpandRaw(word.raw);
      if (raws.length > 1 || raws[0] !== word.raw) word.alts = raws.map((t) => this.altWord(t, start));
    }
    return word;
  }
  altWord(t, at) {
    if (t === '') return { parts: [], start: at, end: at, raw: '' };
    const p = new Parser(t, this.depth + 1, this.b);
    const w = p.readWord(false, true);
    if (!p.eof()) throw new Unreadable('brace expansion made a word the parser cannot read');
    return w;
  }
  procSub() {
    this.i += 2;
    const body = this.nested(() => this.parseList([')']));
    this.expectChar(')');
    return { k: 'psub', body };
  }
  dquote(parts) {
    let lit = '';
    const flush = () => { parts.push({ k: 'lit', s: lit, q: true }); lit = ''; };
    for (;;) {
      const c = this.s[this.i];
      if (c === undefined) throw new Unreadable('unterminated "');
      if (c === '"') { this.i++; break; }
      if (c === '\\') {
        const n = this.s[this.i + 1];
        if (n === '\n') { this.i += 2; continue; }
        if (n !== undefined && '$`"\\'.includes(n)) { lit += n; this.i += 2; continue; }
        lit += '\\'; this.i++; continue;
      }
      if (c === '$') { if (lit) flush(); this.dollar(parts, true); continue; }
      if (c === '`') { if (lit) flush(); parts.push(this.backtick(true)); continue; }
      lit += c; this.i++;
    }
    flush();
  }
  backtick(inDq) {
    let j = this.i + 1, inner = '';
    for (;; j++) {
      const c = this.s[j];
      if (c === undefined) throw new Unreadable('unterminated `');
      if (c === '\\') { const n = this.s[j + 1]; if (n !== undefined && (n === '\\' || n === '`' || n === '$' || (inDq && n === '"'))) { inner += n; j++; } else inner += c; continue; }
      if (c === '`') break;
      inner += c;
    }
    this.i = j + 1;
    return { k: 'sub', body: parseScript(inner, this.depth + 1, this.b), q: inDq };
  }
  dollar(parts, q) {
    const n = this.s[this.i + 1];
    if (n === "'" && !q) { // $'..' with C escapes
      let j = this.i + 2;
      while (j < this.s.length && this.s[j] !== "'") { if (this.s[j] === '\\') j++; j++; }
      if (j >= this.s.length) throw new Unreadable('unterminated $\'');
      parts.push({ k: 'lit', s: ansiC(this.s.slice(this.i + 2, j)), q: true }); this.i = j + 1; return;
    }
    if (n === '"' && !q) { this.i += 2; this.dquote(parts); return; }
    if (n === '(') {
      if (this.s[this.i + 2] === '(') { const j = this.matchParen(this.i + 1); parts.push({ k: 'arith', q }); this.i = j + 1; return; }
      this.i += 2;
      const body = this.nested(() => this.parseList([')']));
      this.expectChar(')');
      parts.push({ k: 'sub', body, q }); return;
    }
    if (n === '{') {
      let d = 0, j = this.i + 1;
      for (; j < this.s.length; j++) {
        const c = this.s[j];
        if (c === '\\') j++;
        else if (c === "'") { const e = this.s.indexOf("'", j + 1); if (e < 0) throw new Unreadable('unterminated ${'); j = e; }
        else if (c === '"') { for (j++; j < this.s.length && this.s[j] !== '"'; j++) if (this.s[j] === '\\') j++; }
        else if (c === '{') d++;
        else if (c === '}') { d--; if (d === 0) break; }
      }
      if (j >= this.s.length) throw new Unreadable('unterminated ${');
      const inner = this.s.slice(this.i + 2, j);
      this.i = j + 1;
      const m = /^([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])([\s\S]*)$/.exec(inner);
      const part = { k: 'var', name: m ? m[1] : '', q, mod: m ? m[2] : (inner || '?') };
      if (!m || m[2]) part.subs = this.innerSubs(inner);
      parts.push(part); return;
    }
    if (n !== undefined && NAME0.test(n)) {
      let j = this.i + 2;
      while (j < this.s.length && NAMEN.test(this.s[j])) j++;
      parts.push({ k: 'var', name: this.s.slice(this.i + 1, j), q }); this.i = j; return;
    }
    if (n !== undefined && /[0-9@*#?$!-]/.test(n)) { parts.push({ k: 'var', name: n, q }); this.i += 2; return; }
    parts.push({ k: 'lit', s: '$', q: false }); this.i++;
  }
  // command substitutions hiding inside a ${..} modifier
  innerSubs(text) {
    const out = [];
    for (let i = text.indexOf('$('); i >= 0 && out.length < 8; i = text.indexOf('$(', i + 2)) {
      try { const p = new Parser(text, this.depth + 1, this.b); p.i = i; const j = p.matchParen(i + 1); out.push(parseScript(text.slice(i + 2, j), this.depth + 1, this.b)); } catch (e) { if (e instanceof Unreadable) { out.push(null); break; } throw e; }
    }
    return out;
  }
}

function parseScript(src, depth = 0, budget = { n: 0 }) {
  const p = new Parser(src, depth, budget);
  const body = p.parseList(null);
  p.skipSeps();
  if (!p.eof()) throw new Unreadable('unexpected ' + JSON.stringify(src[p.i]));
  return body;
}

function ansiC(s) {
  return s.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c.|[\s\S])/g, (_, e) => {
    const c = e[0];
    if (c === 'x') return String.fromCharCode(parseInt(e.slice(1), 16));
    if (c === 'u' || c === 'U') { try { return String.fromCodePoint(parseInt(e.slice(1), 16)); } catch { return ''; } }
    if (/[0-7]/.test(c)) return String.fromCharCode(parseInt(e, 8) & 255);
    if (c === 'c' && e.length === 2) return String.fromCharCode(e.charCodeAt(1) & 31);
    return { n: '\n', t: '\t', r: '\r', a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' }[c] ?? '\\' + e;
  });
}
const wordText = (w) => w.parts.map((p) => (p.k === 'lit' ? p.s : SENT)).join('');
// NAME=value at the start of a command; returns {name, add, word} with the value as a word
function assignment(w) {
  const p0 = w.parts[0];
  if (!p0 || p0.k !== 'lit' || p0.q) return null;
  const m = /^([A-Za-z_][A-Za-z0-9_]*)(\+?)=([\s\S]*)$/.exec(p0.s);
  if (!m) return null;
  const parts = w.parts.slice(1);
  if (m[3]) parts.unshift({ k: 'lit', s: m[3], q: false });
  return { name: m[1], add: !!m[2], word: { parts, start: w.start, end: w.end, raw: w.raw } };
}

// ---------------------------------------------------------------- evaluation
// Walks the tree in order, keeping what it can know about the line: simple NAME=value assignments, cd, loop
// variables, here-documents and what echo/printf feed into a pipe. Every command that would run is unwrapped
// (sudo, env, sh -c, xargs, ssh, ...) down to the program and its arguments, and the rules look at those.
const EMPTY = new Set();
const OPT_SET = (s) => new Set(String(s).split(/\s+/).filter(Boolean));

function newState(o) {
  return { o, vars: new Map(), aliases: new Map(), cwd: o.cwd, remote: null, hits: [], b: o.budget, depth: 0, lenient: false, via: null, res: o.res };
}
const fork = (st, patch = {}) => ({ ...st, vars: new Map(st.vars), aliases: new Map(st.aliases), ...patch });
const step = (st) => { if (++st.b.steps > MAX_STEPS) throw new Unreadable('too much to read'); };

function hit(st, rule, why, text) {
  if (st.o.disable.has(rule)) return;
  const t = redact(String(text).split(SENT).join('<?>')).replace(/\s+/g, ' ').trim().slice(0, 200);
  if (st.hits.some((h) => h.rule === rule && h.text === t)) return;
  const w = st.via ? `${why} (run by ${st.via})` : String(why);
  st.hits.push({ rule, why: w.length > 300 ? w.slice(0, 297).trimEnd() + '...' : w, text: t }); // the Approvals API takes at most 300
}

// ---- words
// Brace expansion works on the text of one word as typed, before quotes or variables are looked at: braces inside
// quotes, ${..}, $(..) and `..` are left alone, and $V{a,b} is $Va and $Vb (the variable names change).
function skipBalanced(s, i) { // s[i] is ( or {; the index of the matching close (or of the last character)
  const open = s[i], close = open === '(' ? ')' : '}';
  let d = 0;
  for (let j = i; j < s.length; j++) {
    const c = s[j];
    if (c === '\\') j++;
    else if (c === "'") { const e = s.indexOf("'", j + 1); if (e < 0) return s.length - 1; j = e; }
    else if (c === '"') { for (j++; j < s.length && s[j] !== '"'; j++) if (s[j] === '\\') j++; }
    else if (c === open) d++;
    else if (c === close) { d--; if (d === 0) return j; }
  }
  return s.length - 1;
}
function opaqueMask(s) { // true for every character that is quoted, escaped or inside an expansion
  const m = new Array(s.length).fill(false);
  const mark = (a, b) => { for (let k = a; k <= b && k < s.length; k++) m[k] = true; };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\') { mark(i, i + 1); i++; }
    else if (c === "'") { const e = s.indexOf("'", i + 1); const end = e < 0 ? s.length - 1 : e; mark(i, end); i = end; }
    else if (c === '"') { let j = i + 1; for (; j < s.length && s[j] !== '"'; j++) { if (s[j] === '\\') j++; else if (s[j] === '$' && (s[j + 1] === '(' || s[j + 1] === '{')) j = skipBalanced(s, j + 1); } mark(i, j); i = j; }
    else if (c === '$' && (s[i + 1] === '(' || s[i + 1] === '{')) { const e = skipBalanced(s, i + 1); mark(i, e); i = e; }
    else if (c === '$' && s[i + 1] === "'") { let j = i + 2; for (; j < s.length && s[j] !== "'"; j++) if (s[j] === '\\') j++; mark(i, j); i = j; }
    else if (c === '`') { let j = i + 1; for (; j < s.length && s[j] !== '`'; j++) if (s[j] === '\\') j++; mark(i, j); i = j; }
    else if ((c === '<' || c === '>') && s[i + 1] === '(') { const e = skipBalanced(s, i + 1); mark(i, e); i = e; }
  }
  return m;
}
function braceExpandRaw(s, depth = 0) {
  if (depth > 6 || !s.includes('{')) return [s];
  const op = opaqueMask(s);
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '{' || op[i]) continue;
    let d = 0, j = i;
    const commas = [];
    for (; j < s.length; j++) {
      if (op[j]) continue;
      const c = s[j];
      if (c === '{') d++;
      else if (c === '}') { d--; if (d === 0) break; } else if (c === ',' && d === 1) commas.push(j);
    }
    if (j >= s.length) continue;
    let alts = null;
    if (commas.length) {
      alts = []; let from = i + 1;
      for (const c of commas) { alts.push(s.slice(from, c)); from = c + 1; }
      alts.push(s.slice(from, j));
    } else if (!op.slice(i + 1, j).some(Boolean)) {
      const inner = s.slice(i + 1, j);
      let m = /^(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?$/.exec(inner);
      if (m) {
        const a = +m[1], b = +m[2], k = Math.max(1, Math.abs(+(m[3] || 1))), dir = a <= b ? 1 : -1;
        const width = /^-?0\d/.test(m[1]) || /^-?0\d/.test(m[2]) ? Math.max(m[1].replace('-', '').length, m[2].replace('-', '').length) : 0;
        alts = [];
        for (let x = a; dir > 0 ? x <= b : x >= b; x += dir * k) { const t = String(Math.abs(x)); alts.push((x < 0 ? '-' : '') + (width ? t.padStart(width, '0') : t)); if (alts.length > 100) return [s]; }
      } else if ((m = /^([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?$/.exec(inner))) {
        const a = m[1].charCodeAt(0), b = m[2].charCodeAt(0), k = Math.max(1, Math.abs(+(m[3] || 1))), dir = a <= b ? 1 : -1;
        alts = [];
        for (let x = a; dir > 0 ? x <= b : x >= b; x += dir * k) alts.push(String.fromCharCode(x));
      }
    }
    if (!alts) continue;
    const pre = s.slice(0, i), post = s.slice(j + 1), out = [];
    for (const a of alts) for (const x of braceExpandRaw(pre + a + post, depth + 1)) { out.push(x); if (out.length > 256) return [s]; }
    return out;
  }
  return [s];
}

// ---- parameter expansion: the forms bash has, for the values the line makes known.
// A variable the line never set is "unset" for ${V:-w} and friends (the default is the likely value: the person who
// writes ${TF:-terraform} means terraform); every other form of an unknown value is unknown (SENT).
const VARNAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const unknownText = (v) => typeof v !== 'string' || v.includes(SENT);
function lookupVar(name, st) {
  const v = st.vars.get(name);
  if (v !== undefined) return { known: true, value: v };
  switch (name) {
    case 'HOME': return { known: true, value: st.o.home ?? SENT };
    case 'PWD': return { known: true, value: st.cwd ?? SENT };
    case 'TMPDIR': case 'TMP': case 'TEMP': return { known: true, value: '/tmp' };
    default: return { known: false, value: SENT };
  }
}
// a shell pattern (* ? [..]) as a regular expression; null when it uses anything this does not read
function globToRegex(g) {
  if (/['"\\$`]/.test(g)) return null;
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*') re += '[\\s\\S]*';
    else if (c === '?') re += '[\\s\\S]';
    else if (c === '[') {
      const j = g.indexOf(']', i + 2);
      if (j < 0) { re += '\\['; continue; }
      let cls = g.slice(i + 1, j);
      if (!/^[!^]?[A-Za-z0-9_.,:;@%+=~ /-]+$/.test(cls) || cls.includes('[:')) return null;
      if (cls[0] === '!' || cls[0] === '^') cls = '^' + cls.slice(1);
      re += '[' + cls + ']'; i = j;
    } else re += c.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  }
  return new RegExp('^(?:' + re + ')$');
}
/**
 * The pieces of the word after :- := :+ or / in ${..}: quotes and expansions inside it work as usual (in double
 * quotes a single quote is just a letter). Null when it cannot be read.
 */
function wordChunks(text, st, dq) {
  if (text === '' || !/['"\\$`~]/.test(text)) return [{ text, quoted: dq, expansion: true }];
  try {
    const p = new Parser(text, st.depth + 1, st.b);
    p.allMeta = true; p.dq = dq;
    const w = p.readWord(false, true);
    if (!p.eof()) return null;
    const out = [];
    for (const part of w.parts) {
      if (part.k === 'lit' && !part.q) out.push({ text: part.s, quoted: false, expansion: true });
      else out.push(...partChunks(part, st));
    }
    return out;
  } catch (e) { if (e instanceof Unreadable) return null; throw e; }
}
const chunkText = (cs) => (cs ? cs.map((c) => c.text).join('') : SENT);
/** the value of a ${..}: a string, or the chunks of the default word that was used */
function paramExpand(p, st) {
  if (p.subs) for (const b of p.subs) if (b) walk(b, fork(st));
  const name = p.name, mod = p.mod ?? '';
  if (name === '!' && VARNAME.test(mod)) { // ${!R}: the variable that R names
    const r = lookupVar(mod, st);
    if (!r.known || unknownText(r.value) || !VARNAME.test(r.value)) return SENT;
    const t = lookupVar(r.value, st);
    return t.known ? t.value : SENT;
  }
  if (name === '#' && VARNAME.test(mod)) { const r = lookupVar(mod, st); return r.known && !unknownText(r.value) ? String([...r.value].length) : SENT; }
  if (!VARNAME.test(name) && !/^[0-9]+$/.test(name)) return mod ? SENT : lookupVar(name, st).value;
  const r = lookupVar(name, st), val = r.value;
  if (!mod) return val;
  let m;
  if ((m = /^(:?)([-=+?])([\s\S]*)$/.exec(mod))) {
    const colon = m[1] === ':', op = m[2];
    const state = !r.known ? 'unset' : unknownText(val) ? 'unknown' : (val === '' && colon ? 'unset' : 'set');
    if (state === 'unknown') return SENT;
    if (op === '-' || op === '=') {
      if (state === 'set') return val;
      const cs = wordChunks(m[3], st, !!p.q);
      if (cs === null) return SENT;
      if (op === '=' && VARNAME.test(name)) st.vars.set(name, chunkText(cs));
      return cs;
    }
    if (op === '+') return state === 'set' ? (wordChunks(m[3], st, !!p.q) ?? SENT) : '';
    return state === 'set' ? val : SENT;
  }
  if (!r.known || unknownText(val)) return SENT;
  const chars = [...val];
  if ((m = /^:\s*(-?\d+)\s*(?::\s*(-?\d+)\s*)?$/.exec(mod))) { // ${V:offset:length}
    const off = Number(m[1]), len = m[2] === undefined ? undefined : Number(m[2]);
    const o = off < 0 ? chars.length + off : off;
    if (o < 0 || o > chars.length) return '';
    const e = len === undefined ? chars.length : len < 0 ? chars.length + len : Math.min(o + len, chars.length);
    if (e < o) return SENT;
    return chars.slice(o, e).join('');
  }
  if (mod === '^^') return val.toUpperCase();
  if (mod === ',,') return val.toLowerCase();
  if (mod === '^') return chars.length ? chars[0].toUpperCase() + chars.slice(1).join('') : val;
  if (mod === ',') return chars.length ? chars[0].toLowerCase() + chars.slice(1).join('') : val;
  if ((m = /^@([ULu])$/.exec(mod))) return m[1] === 'U' ? val.toUpperCase() : m[1] === 'L' ? val.toLowerCase() : (chars.length ? chars[0].toUpperCase() + chars.slice(1).join('') : val);
  if ((m = /^(##?|%%?)([\s\S]*)$/.exec(mod))) { // ${V#pattern} ${V##pattern} ${V%pattern} ${V%%pattern}
    if (m[2] === '') return val;
    const re = globToRegex(m[2]);
    if (!re) return SENT;
    const n = val.length, longest = m[1].length === 2;
    if (m[1][0] === '#') {
      for (let k = longest ? n : 0; longest ? k >= 0 : k <= n; k += longest ? -1 : 1) if (re.test(val.slice(0, k))) return val.slice(k);
    } else {
      for (let k = longest ? 0 : n; longest ? k <= n : k >= 0; k += longest ? 1 : -1) if (re.test(val.slice(k))) return val.slice(0, k);
    }
    return val;
  }
  if ((m = /^\/([\/#%]?)([\s\S]*)$/.exec(mod))) { // ${V/pattern/replacement} and the // /# /% forms
    const mode = m[1], at = m[2].indexOf('/');
    const pat = at < 0 ? m[2] : m[2].slice(0, at), repText = at < 0 ? '' : m[2].slice(at + 1);
    if (pat === '') return val;
    const re = globToRegex(pat);
    const rep = chunkText(wordChunks(repText, st, true));
    if (!re || unknownText(rep) || rep.includes('&')) return SENT;
    const n = val.length;
    if (n === 0) return re.test('') ? rep : val; // a pattern like * matches an empty value
    // the longest match that starts at i (and, for the % form, ends at the end of the value); -1 when there is none
    const matchAt = (i) => { for (let e = n; e > i; e--) { if (mode === '%' && e !== n) continue; if (re.test(val.slice(i, e))) return e; } return -1; };
    let out = '', i = 0;
    while (i < n) {
      const j = mode === '#' && i !== 0 ? -1 : matchAt(i);
      if (j > i) { out += rep; i = j; if (mode !== '/') return out + val.slice(i); } else { out += val[i]; i++; }
    }
    return out;
  }
  return SENT;
}
/** what one part of a word comes to: chunks of text, each quoted or not (unquoted expansions are split at blanks) */
function partChunks(p, st) {
  switch (p.k) {
    case 'lit': return [{ text: p.s, quoted: !!p.q, expansion: false }];
    case 'var': { const r = paramExpand(p, st); return Array.isArray(r) ? r : [{ text: r, quoted: !!p.q, expansion: true }]; }
    case 'sub': { const out = walk(p.body, fork(st)); return [{ text: out ? out.replace(/\n+$/, '') : SENT, quoted: !!p.q, expansion: true }]; }
    case 'psub': { const out = walk(p.body, fork(st)); return [{ text: SENT, quoted: false, expansion: true, psub: out ?? null }]; }
    case 'tilde': return [{ text: p.user === '' ? (st.o.home ?? SENT) : SENT, quoted: true, expansion: false }];
    default: return [{ text: SENT, quoted: !!p.q, expansion: true }];
  }
}

/**
 * One word to the words it becomes, the way a shell does it: brace expansion first (the parser made `alts` from the
 * text), then the values of variables and substitutions, then splitting what was not quoted at blanks, so a word can
 * become several or none. Unknown pieces stay as SENT. `plain`: an assignment value or a redirection target, where
 * nothing is split or brace-expanded and the result is exactly one string.
 */
function expandWord(w, st, plain = false) {
  if (!plain && w.alts) {
    const all = [];
    for (const a of w.alts) { all.push(...expandWord(a, st, false)); if (all.length > 512) throw new Unreadable('too many words'); }
    return all.map((x) => ({ ...x, raw: w.raw }));
  }
  const chunks = [];
  for (const p of w.parts) chunks.push(...partChunks(p, st));
  const GLOB = /[*?[]/;
  const out = [];
  let cur = null, glob = false, psub, n = 0;
  const push = () => { out.push({ s: cur, glob, psub: n === 1 ? psub : undefined }); cur = null; glob = false; psub = undefined; n = 0; };
  for (const c of chunks) {
    const t = c.text;
    if (plain || c.quoted || !c.expansion || t.includes(SENT)) {
      if (cur === null) cur = '';
      cur += t; n++;
      if (!plain && !c.quoted && GLOB.test(t)) glob = true;
      if (c.psub !== undefined) psub = c.psub;
      continue;
    }
    if (t === '') continue; // an unquoted empty expansion is nothing at all
    const lead = /^[ \t\n]/.test(t), trail = /[ \t\n]$/.test(t);
    const toks = t.split(/[ \t\n]+/).filter(Boolean);
    if (!toks.length) { if (cur !== null) push(); continue; }
    if (lead && cur !== null) push();
    toks.forEach((tok, k) => {
      if (cur === null) cur = '';
      cur += tok; n++;
      if (GLOB.test(tok)) glob = true;
      if (k < toks.length - 1) push();
    });
    if (trail) push();
  }
  if (cur !== null) push();
  if (plain && !out.length) out.push({ s: '', glob: false });
  if (out.length > 512) throw new Unreadable('too many words');
  return out.map((x) => ({ s: x.s, lit: !x.s.includes(SENT), glob: x.glob, raw: w.raw, ...(x.psub != null ? { psub: x.psub } : {}) }));
}
const one = (w, st) => expandWord(w, st, true)[0];

// ---- the program name
const progName = (s) => lc(String(s).replace(/\/+$/, '').split('/').pop()).replace(/\.(exe|cmd|bat|ps1)$/, '');

// ---- known output of a command (only what can be told from its words)
function printfText(fmt, args) {
  let k = 0;
  const f = ansiC(fmt);
  let out = f.replace(/%([-+ #0]*\d*(?:\.\d+)?)([sdibqxXoc%])/g, (_, _f, c) => (c === '%' ? '%' : (args[k++] ?? '')));
  while (k > 0 && k < args.length) { // the format is reused while arguments are left
    const before = k;
    out += f.replace(/%([-+ #0]*\d*(?:\.\d+)?)([sdibqxXoc%])/g, (_, _f, c) => (c === '%' ? '%' : (args[k++] ?? '')));
    if (k === before) break;
  }
  return out;
}
function knownOutput(argv, stdin, st) {
  if (!argv.length || !argv[0].lit) return null;
  const prog = progName(argv[0].s), args = argv.slice(1);
  const allLit = args.every((a) => a.lit);
  switch (prog) {
    case 'echo': {
      if (!allLit) return null;
      let nl = true, esc = false, i = 0;
      for (; i < args.length && /^-[neE]+$/.test(args[i].s); i++) { if (args[i].s.includes('n')) nl = false; if (args[i].s.includes('e')) esc = true; }
      const t = args.slice(i).map((a) => a.s).join(' ');
      return (esc ? ansiC(t) : t) + (nl ? '\n' : '');
    }
    case 'printf': return allLit && args.length ? printfText(args[0].s, args.slice(1).map((a) => a.s)) : null;
    case 'pwd': return st.cwd ? st.cwd + '\n' : null;
    case 'mktemp': return '/tmp/mktemp.XXXXXX\n';
    case 'cat': return !args.length && stdin?.kind === 'heredoc' && !stdin.hasSubs ? stdin.text : (!args.length && stdin?.kind === 'here' ? stdin.text : null);
    case 'basename': return allLit && args[0] ? base(args[0].s) + '\n' : null;
    case 'dirname': return allLit && args[0] ? (args[0].s.replace(/\/+$/, '').replace(/\/[^/]*$/, '') || (args[0].s.startsWith('/') ? '/' : '.')) + '\n' : null;
    case 'git': return args.length === 2 && args[0].s === 'rev-parse' && args[1].s === '--show-toplevel' && st.o.root ? st.o.root + '\n' : null;
    default: return null;
  }
}

// ---- walking
/** walk a node; returns the text a command substitution of exactly this node would give, when that is known */
function walk(n, st, pipe = null) {
  step(st);
  switch (n.t) {
    case 'seq': {
      let last = null;
      for (const x of n.items) last = walk(x, st);
      return n.items.length === 1 ? last : null;
    }
    case 'sub': walk(n.body, fork(st)); doRedirs(n.redirs, st); return null;
    case 'group': walk(n.body, st); doRedirs(n.redirs, st); return null;
    case 'pipe': evalPipe(n, st); return null;
    case 'if': {
      for (const c of n.conds) walk(c, st);
      for (const b of n.bodies) walk(b, fork(st));
      return null;
    }
    case 'while': walk(n.cond, st); walk(n.body, fork(st)); return null;
    case 'for': evalFor(n, st); return null;
    case 'case': {
      expandWord(n.word, st);
      for (const c of n.clauses) walk(c.body, fork(st));
      return null;
    }
    case 'func': walk(n.body, fork(st)); return null;
    case 'test': for (const w of n.words) expandWord(w, st); return null;
    case 'cmd': return evalCmd(n, st, pipe);
    default: return null;
  }
}

function evalFor(n, st) {
  const lits = [];
  let known = n.words !== null && n.name !== null;
  if (n.words) for (const w of n.words) for (const x of expandWord(w, st)) { if (x.lit && !x.glob) lits.push(x.s); else known = false; }
  if (known && lits.length && lits.length <= 16) {
    for (const v of lits) { const f = fork(st); f.vars.set(n.name, v); walk(n.body, f); }
  } else {
    const f = fork(st);
    if (n.name) f.vars.set(n.name, SENT);
    walk(n.body, f);
  }
}

function evalPipe(n, st) {
  let prev = null;
  const names = [];
  for (const c of n.cmds) {
    const f = fork(st);
    let produced = null;
    if (c.t === 'cmd') {
      const pipe = prev ? { prev, names: [...names] } : null;
      produced = evalCmd(c, f, pipe, true);
    } else walk(c, f);
    prev = produced;
    if (produced?.argv?.length && produced.argv[0].lit) names.push(progName(produced.argv[0].s));
    else names.push('?');
  }
}

/** redirections: returns { stdin } and checks what is written to */
function doRedirs(redirs, st) {
  let stdin = null;
  for (const r of redirs || []) {
    if (r.heredoc) {
      let hasSubs = false;
      let text = r.body;
      if (!r.quoted && r.body) {
        const x = heredocText(r.body, st);
        if (x !== null) text = x;
        else for (const body of heredocSubs(r.body, st)) { hasSubs = true; walk(body, fork(st)); }
      }
      stdin = { kind: 'heredoc', text, hasSubs };
      continue;
    }
    const t = r.target ? one(r.target, st) : null;
    if (!t) continue;
    if (r.op === '<<<') { stdin = { kind: 'here', text: t.lit ? t.s + '\n' : null }; continue; }
    if (r.op === '<' ) { stdin = { kind: 'file', path: t.s, text: null }; continue; }
    if (/^(>|>>|>\||&>|&>>|>&)$/.test(r.op) && t.lit && /^\/dev\/(sd[a-z]|hd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|mmcblk\d|disk\d|rdisk\d|dm-\d|md\d|loop\d|sr\d)/.test(normPath(t.s))) {
      hit(st, 'sh.disk', 'Writes straight to a disk device, which overwrites whatever is stored on it.', `> ${t.s}`);
    }
  }
  return { stdin };
}
// An unquoted here-document is expanded by the shell that reads it, before any program sees it: $var, ${..}, $(..)
// and `..` are replaced (what is unknown becomes SENT), quotes mean nothing, and \ only escapes $ ` \ and newline.
// Null when the text cannot be read (the caller then falls back to looking for the substitutions only).
function heredocText(body, st) {
  if (!/[$`\\]/.test(body)) return body;
  let esc = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '\\') {
      const n = body[i + 1];
      if (n !== undefined && '$`\\\n'.includes(n)) { esc += c + n; i++; } else if (n === '"') { esc += '\\\\\\"'; i++; } else esc += c;
    } else if (c === '"') esc += '\\"';
    else esc += c;
  }
  try {
    const p = new Parser(esc + '"', st.depth + 1, st.b);
    const parts = [];
    p.dquote(parts);
    if (!p.eof()) return null;
    return parts.map((x) => partChunks(x, st).map((c) => c.text).join('')).join('');
  } catch (e) { if (e instanceof Unreadable) return null; throw e; }
}
// command substitutions inside an unquoted here-document are run by the shell
function heredocSubs(body, st) {
  const out = [];
  for (let i = body.indexOf('$('); i >= 0 && out.length < 8; i = body.indexOf('$(', i + 2)) {
    try {
      const p = new Parser(body, st.depth + 1, st.b); p.i = i;
      const j = p.matchParen(i + 1);
      out.push(parseScript(body.slice(i + 2, j), st.depth + 1, st.b));
    } catch (e) { if (e instanceof Unreadable) { st.res.unreadable = true; break; } throw e; }
  }
  for (let i = body.indexOf('`'); i >= 0 && out.length < 8;) {
    const j = body.indexOf('`', i + 1);
    if (j < 0) break;
    try { out.push(parseScript(body.slice(i + 1, j).replace(/\\([\\`$])/g, '$1'), st.depth + 1, st.b)); } catch (e) { if (e instanceof Unreadable) { st.res.unreadable = true; break; } throw e; }
    i = body.indexOf('`', j + 1);
  }
  return out;
}

function setVar(st, name, add, value) {
  st.vars.set(name, (add ? st.vars.get(name) ?? '' : '') + value);
}

function evalCmd(n, st, pipe, wantInfo = false) {
  const assigns = n.assigns.map((a) => ({ a, v: one(a.word, st) }));
  const argv = [];
  for (const w of n.words) argv.push(...expandWord(w, st));
  if (globalThis.__SHELLMAP_TRACE && argv.length) globalThis.__SHELLMAP_TRACE.push(argv.map((w) => w.s.split(SENT).join('<?>'))); // tests only: what each command's words came to
  const red = doRedirs(n.redirs, st);
  if (!argv.length) {
    for (const { a, v } of assigns) setVar(st, a.name, a.add, v.s);
    return null;
  }
  const stdin = red.stdin ?? (pipe ? { kind: 'pipe', prev: pipe.prev, names: pipe.names, text: pipe.prev?.text ?? null } : { kind: 'none' });
  const cx = { stdin, redirs: n.redirs, assigns: assigns.map(({ a, v }) => [a.name, v.s]) };
  runExec(argv, cx, st);
  const text = knownOutput(argv, stdin, st);
  return wantInfo ? { argv, text } : text;
}

// ---- unwrapping
const MAX_HOPS = 12;
const KEYWORDS = new Set(['destroy', 'delete', 'drop', 'truncate', 'reset', 'force', 'rm', 'rf']);
function dynamicProgram(argv, st) {
  const text = argv.map((w) => w.raw ?? w.s).join(' ');
  const words = (text.toLowerCase().match(/[a-z0-9]+/g) || []);
  if (words.some((x) => KEYWORDS.has(x))) {
    hit(st, 'sh.dynamic-program', 'The program to run is built at run time (a variable or a substitution) in a command with a dangerous word in it, so the guard cannot tell what it does.', text);
  }
}

function runExec(argv, cx, st) {
  step(st);
  for (let hop = 0; argv.length && hop < MAX_HOPS; hop++) {
    const w0 = argv[0];
    if (!w0.lit || w0.glob) { dynamicProgram(argv, st); return; }
    const prog = progName(w0.s);
    if (st.aliases.has(prog) && !cx.aliased) { cx = { ...cx, aliased: true }; argv = [...st.aliases.get(prog), ...argv.slice(1)]; continue; }
    const cx2 = { ...cx, prog, argv, args: argv.slice(1), st };
    runRules(prog, cx2);
    const u = UNWRAP[prog];
    if (!u) return;
    const r = u(cx2.args, cx2, st);
    if (!r) return;
    if (r.script !== undefined) { evalScript(r.script, r.st ?? st, r.cx ?? cx2, r.label); return; }
    if (r.argvs) { for (const a of r.argvs) runExec(a, r.cx ?? cx, r.st ?? st); return; }
    argv = r.argv; if (r.st) st = r.st; if (r.cx) cx = r.cx;
  }
}

/** run text as a script: sh -c, eval, ssh, npm scripts. Three levels at most. */
function evalScript(text, st, cx = {}, label = null) {
  if (st.depth >= 3) { lenientScript(text, st); st.res.unreadable = true; return; }
  let ast;
  try { ast = parseScript(text, 0, st.b); } catch (e) {
    if (!(e instanceof Unreadable)) throw e;
    st.res.unreadable = true;
    lenientScript(text, fork(st, { depth: st.depth + 1 }));
    return;
  }
  walk(ast, fork(st, { depth: st.depth + 1, via: label ? `${label}` : st.via, remote: cx.remote ?? st.remote }));
}

/** when the text cannot be parsed: split it on the usual separators and look at each piece as a command */
function lenientScript(text, st) {
  const f = fork(st, { lenient: true });
  for (const seg of String(text).split(/\n|;|&&|\|\||\||&|\(|\)|`|\$\(/)) {
    const words = seg.trim().split(/\s+/).filter(Boolean).map((raw) => {
      const s = raw.replace(/\\(.)/g, '$1').replace(/["']/g, '');
      return { s, lit: true, glob: /[*?[]/.test(s), raw };
    });
    if (words.length && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[0].s)) runExec(words, { stdin: { kind: 'none' }, redirs: [] }, f);
  }
}

// ---- option helpers
function skipOpts(args, val = EMPTY, o = {}) {
  let i = 0;
  while (i < args.length) {
    const a = args[i].s;
    if (a === '--') { i++; break; }
    if (o.assign && /^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) { i++; continue; }
    if (a.length > 1 && a[0] === '-') {
      i++;
      if (val.has(a)) i++;
      else if (a[1] !== '-' && a.length > 2 && !a.includes('=') && val.has('-' + a[a.length - 1])) i++;
      continue;
    }
    break;
  }
  return i;
}
const cmdAfter = (args, i, extra) => (i < args.length ? { argv: args.slice(i), ...extra } : null);

/** options and positionals of a command line. `val`: options that take a value (space separated list);
 * `go`: single dash long options (terraform -destroy, -chdir=dir). */
function argParse(args, spec = {}) {
  const val = spec.val ? OPT_SET(spec.val) : EMPTY;
  const flags = new Map(), pos = [], posW = [];
  let rest = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i], s = a.s;
    if (rest || s === '-' || s[0] !== '-') { pos.push(s); posW.push(a); continue; }
    if (s === '--') { rest = true; continue; }
    if (s.startsWith('--') || spec.go) {
      const eq = s.indexOf('=');
      if (eq > 0) flags.set(s.slice(0, eq), s.slice(eq + 1));
      else if (val.has(s)) flags.set(s, args[++i]?.s ?? '');
      else flags.set(s, true);
      continue;
    }
    for (let k = 1; k < s.length; k++) {
      const f = '-' + s[k];
      if (val.has(f)) { flags.set(f, s.length > k + 1 ? s.slice(k + 1) : (args[++i]?.s ?? '')); break; }
      flags.set(f, true);
    }
  }
  return { flags, pos, posW, has: (...n) => n.some((x) => flags.has(x)), get: (n) => flags.get(n) };
}
/** every value given for any of these options (repeats allowed): -f a -f b, --field=a */
function collect(args, names) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const s = args[i].s;
    for (const n of names) {
      if (s === n) { out.push(args[++i]?.s ?? ''); break; }
      if (n.startsWith('--') && s.startsWith(n + '=')) { out.push(s.slice(n.length + 1)); break; }
      if (!n.startsWith('--') && s.startsWith(n) && s.length > n.length && s[1] !== '-') { out.push(s.slice(n.length)); break; }
    }
  }
  return out;
}
const joinText = (args) => args.map((a) => a.s).join(' ');
const hasSent = (args) => args.some((a) => !a.lit);

// ---- what a pipe carries
// find tests that narrow the result to some of the files; -type, -prune and -print do not
const FIND_FILTER = /^-(name|iname|path|ipath|regex|iregex|newer|mtime|mmin|atime|ctime|cmin|size|user|group|perm|lname|wholename|samefile|inum|links)$/;
function pipeItems(stdin, st) {
  const prev = stdin?.prev;
  if (!prev) return stdin?.kind === 'heredoc' || stdin?.kind === 'here' ? (stdin.text ?? '').split(/\s+/).filter(Boolean).map((s) => ({ s, lit: true, glob: false, raw: s })) : null;
  if (prev.text != null) return prev.text.split(/\s+/).filter(Boolean).map((s) => ({ s, lit: true, glob: false, raw: s }));
  const argv = prev.argv || [];
  if (!argv.length || !argv[0].lit) return null;
  const prog = progName(argv[0].s), args = argv.slice(1);
  const under = (dir) => ({ s: dir + '/' + SENT, lit: false, glob: false, raw: dir + '/...', under: dir });
  const dirsOf = (list) => {
    const ds = list.filter((a) => a.lit && (a.s.startsWith('/') || a.s.startsWith('.') || a.s.startsWith('~')) ).map((a) => a.s);
    return ds.length ? ds : [st.cwd ? st.cwd : null];
  };
  if (prog === 'find') {
    const roots = [];
    for (const a of args) { if (a.s.startsWith('-') || a.s === '(' || a.s === '!') break; roots.push(a); }
    if (!roots.length) roots.push({ s: '.', lit: true, raw: '.' });
    const filtered = args.some((a) => FIND_FILTER.test(a.s));
    const items = roots.map((r) => (r.lit ? under(r.s) : { s: SENT, lit: false, glob: false, raw: r.raw }));
    if (!filtered) items.push(...roots);
    return items;
  }
  if (['ls', 'tree', 'du', 'stat', 'readlink', 'realpath'].includes(prog)) { // lists everything in the directory
    if (args.some((a) => !a.lit)) return null;
    const ds = args.filter((a) => !a.s.startsWith('-')).map((a) => a.s);
    return (ds.length ? ds : ['.']).map((d) => ({ s: d.replace(/\/+$/, '') + '/*', lit: true, glob: true, raw: d + '/*' }));
  }
  if (['locate', 'fd', 'fdfind', 'grep', 'rg', 'ag'].includes(prog) || (prog === 'git' && ['ls-files', 'ls-tree', 'status', 'diff', 'clean'].includes(args.find((a) => !a.s.startsWith('-'))?.s))) {
    if (args.some((a) => !a.lit)) return null;
    const ds = dirsOf(args);
    if (ds.some((d) => d === null)) return null;
    return ds.map(under);
  }
  return null;
}

// ---- how a path is judged for deleting
const SYSTEM_DIRS = new Set(['bin', 'boot', 'dev', 'etc', 'lib', 'lib32', 'lib64', 'libx32', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'usr', 'var', 'home', 'mnt', 'media', 'Users', 'System', 'Library', 'Applications', 'Volumes', 'private', 'opt', 'snap', 'nix']);
const TMP_DIRS = ['/tmp', '/var/tmp', '/private/tmp', '/dev/shm', '/private/var/folders', '/var/folders'];
const DISPOSABLE = /^(node_modules|dist|build|out|target|coverage|tmp|temp|\.next|\.nuxt|\.svelte-kit|\.output|\.cache|\.turbo|\.parcel-cache|\.vite|\.angular|\.gradle|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|\.nox|\.eggs|__pycache__|\.venv|venv|\.idea|\.dart_tool|\.terraform|\.serverless|\.vercel|\.wrangler|DerivedData|Pods|[^/]*\.egg-info|[^/]*\.pyc|[^/]*\.log|[^/]*\.tsbuildinfo)$/;

const short = (n) => (n.length > 80 ? n.slice(0, 80) + '...' : n);
/** judge an absolute, normalised path. `under`: the things below it are meant, not the directory itself. */
function classifyPath(n, st, under) {
  const { home, root } = st.o;
  if (st.remote === 'ssh') { // another machine: only a temporary directory is safe to empty
    if (n === '/') return 'the filesystem root';
    if (TMP_DIRS.some((t) => isInside(n, t) && n !== t)) return null;
    return `a path on another machine (${short(n)})`;
  }
  if (n === '/') return under ? `a path outside the project (/)` : 'the filesystem root';
  if (!under && home && n === home) return 'your home directory';
  const parts = n.split('/');
  if (!under && parts.length === 2 && SYSTEM_DIRS.has(parts[1])) return `a system directory (${n})`;
  if (st.remote === 'container') return null;
  if (TMP_DIRS.includes(n)) return under ? null : `the shared temporary directory (${n})`;
  if (TMP_DIRS.some((t) => isInside(n, t))) return null;
  if (root && isInside(n, root)) {
    if (n === root) return under ? null : 'the whole project directory';
    const rel = n.slice(root.length + 1);
    if (rel === '.git' || /^\.git\/(objects|refs|HEAD)(\/|$)/.test(rel)) return 'the git history of this project';
    return null;
  }
  if (!root) return null;
  return `a path outside the project (${short(n)})`;
}
/** a reason when deleting what this word names is dangerous, otherwise null */
function pathRisk(w, st) {
  const cwd = st.cwd;
  if (w.under !== undefined) {
    const d = w.under.startsWith('/') ? normPath(w.under) : cwd ? normPath(cwd + '/' + w.under) : null;
    return d ? classifyPath(d, st, true) : 'a relative path in a working directory the guard does not know';
  }
  const s = w.s;
  if (!w.lit) { // part of the path is a value the guard cannot see
    const tail = s.slice(s.lastIndexOf(SENT) + 1), pre = s.slice(0, s.indexOf(SENT));
    if (!tail.includes('..') && tail && DISPOSABLE.test(base(tail))) return null; // "$DIR/node_modules"
    if (pre.startsWith('/') && !pre.endsWith('/') && !tail.includes('/') && !tail.includes('..') && TMP_DIRS.some((t) => pre.startsWith(t + '/'))) return null; // /tmp/build-$$
    return 'a path built from a value the guard cannot see, which could be anything';
  }
  if (s === '') return null;
  if (/(^|\/)\.\*$/.test(s)) return 'everything that starts with a dot, which includes the parent directory';
  // a trailing * means everything inside the directory in front of it
  const m = /^(.*?)\/*(\*+|\.\*)$/.exec(s);
  const dir = m ? (m[1] === '' ? (s.startsWith('/') ? '/' : '.') : m[1]) : s;
  let n;
  if (dir.startsWith('/')) n = normPath(dir);
  else if (cwd) n = normPath(cwd + '/' + dir);
  else return !dir.split('/').includes('..') && DISPOSABLE.test(base(dir)) ? null : 'a relative path in a working directory the guard does not know';
  return classifyPath(n, st, false);
}

// ---- wrappers: programs that run another program (or a script). Each returns what runs next, or null.
const UNWRAP = Object.create(null);
const SUDO_VAL = OPT_SET('-u -g -h -p -C -T -r -t -U -D -R --user --group --host --prompt --close-from --command-timeout --role --type --other-user --chdir --chroot');
UNWRAP.sudo = (a) => {
  const i = skipOpts(a, SUDO_VAL, { assign: true });
  if (i >= a.length) return null;
  if (a.slice(0, i).some((x) => /^-[A-Za-z]*[si][A-Za-z]*$/.test(x.s))) return { script: joinText(a.slice(i)) };
  return cmdAfter(a, i);
};
UNWRAP.doas = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-u -C')));
UNWRAP.pkexec = (a) => cmdAfter(a, skipOpts(a, OPT_SET('--user')));
const suLike = (a) => {
  for (let i = 0; i < a.length; i++) {
    if (a[i].s === '-c' || a[i].s === '--command' || /^-[A-Za-z]*c$/.test(a[i].s)) return a[i + 1] ? { script: a[i + 1].s } : null;
    if (a[i].s.startsWith('--command=')) return { script: a[i].s.slice(10) };
  }
  return null;
};
UNWRAP.su = suLike; UNWRAP.runuser = (a) => suLike(a) || cmdAfter(a, (() => { const j = a.findIndex((x) => x.s === '--'); return j < 0 ? a.length : j + 1; })()); UNWRAP.sg = suLike;
UNWRAP.env = (a) => {
  let i = 0, script = null;
  while (i < a.length) {
    const x = a[i].s;
    if (x === '--') { i++; break; }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(x)) { i++; continue; }
    if (x === '-S' || x === '--split-string') { script = a[i + 1]?.s ?? ''; i += 2; continue; }
    if (x.startsWith('--split-string=')) { script = x.slice(15); i++; continue; }
    if (x.startsWith('-S') && x.length > 2) { script = x.slice(2); i++; continue; }
    if (x === '-u' || x === '-C' || x === '--unset' || x === '--chdir') { i += 2; continue; }
    if (x.startsWith('-') && x.length > 1) { i++; continue; }
    break;
  }
  if (script !== null) return { script: script + ' ' + joinText(a.slice(i)) };
  return cmdAfter(a, i);
};
UNWRAP.command = (a) => {
  if (a.some((x) => /^-[A-Za-z]*[vV]/.test(x.s))) return null;
  return cmdAfter(a, skipOpts(a));
};
UNWRAP.builtin = (a) => cmdAfter(a, 0);
UNWRAP.exec = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-a')));
UNWRAP.nohup = (a) => cmdAfter(a, skipOpts(a));
UNWRAP.time = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-f -o --format --output')));
UNWRAP.nice = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-n --adjustment')));
UNWRAP.ionice = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-c -n -p -P -u --class --classdata')));
UNWRAP.setsid = (a) => cmdAfter(a, skipOpts(a));
UNWRAP.stdbuf = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-i -o -e --input --output --error')));
UNWRAP.timeout = (a) => { const i = skipOpts(a, OPT_SET('-s -k --signal --kill-after')); return cmdAfter(a, i + 1); };
UNWRAP.chrt = (a) => (a.some((x) => x.s === '-p') ? null : cmdAfter(a, skipOpts(a) + 1));
UNWRAP.taskset = (a) => { if (a.some((x) => x.s === '-p')) return null; const c = a.some((x) => x.s === '-c' || x.s === '--cpu-list'); return cmdAfter(a, skipOpts(a, OPT_SET('-c --cpu-list')) + (c ? 0 : 1)); };
UNWRAP.unbuffer = (a) => cmdAfter(a, skipOpts(a));
UNWRAP.caffeinate = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-t -w')));
UNWRAP.strace = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-o -e -p -s -u -E -O -S -a')));
UNWRAP.ltrace = UNWRAP.strace;
UNWRAP.fakeroot = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-l -i -s -u')));
UNWRAP.busybox = (a) => cmdAfter(a, 0);
UNWRAP.flock = (a) => {
  const i = skipOpts(a, OPT_SET('-w -E --timeout --conflict-exit-code'));
  const c = a.findIndex((x, k) => k < i && (x.s === '-c' || x.s === '--command'));
  if (c >= 0) return { script: a[c + 1]?.s ?? '' };
  const j = a.findIndex((x) => x.s === '-c' || x.s === '--command');
  if (j >= 0) return a[j + 1] ? { script: a[j + 1].s } : null;
  return cmdAfter(a, i + 1);
};
UNWRAP.watch = (a) => { const i = skipOpts(a, OPT_SET('-n --interval -d')); return i < a.length ? { script: joinText(a.slice(i)) } : null; };
UNWRAP.chroot = (a, cx, st) => cmdAfter(a, skipOpts(a, OPT_SET('--userspec --groups')) + 1, { st: fork(st, { remote: 'container', cwd: null }) });
UNWRAP.nsenter = (a) => cmdAfter(a, skipOpts(a, OPT_SET('-t --target -S --setuid -G --setgid -w --wd -N -m -u -i -n -p -C -T -U')));
UNWRAP.unshare = (a) => cmdAfter(a, skipOpts(a, OPT_SET('--propagation --setgroups --map-user --map-group --map-users --map-groups --kill-child --mount-proc --time --monotonic --boottime')));
UNWRAP.at = (a, cx) => (cx.stdin?.text ? { script: cx.stdin.text } : null);
UNWRAP.batch = UNWRAP.at;
UNWRAP.eval = (a, cx, st) => {
  decodeCheck(a, st);
  return a.length ? { script: joinText(a) } : null;
};
UNWRAP.trap = (a) => { const i = skipOpts(a, OPT_SET('-p -l')); const s = a[i]?.s; return s && s !== '-' ? { script: s } : null; };

const DECODERS = new Set(['base64', 'base32', 'basenc', 'xxd', 'openssl', 'gunzip', 'zcat', 'gzcat', 'bzcat', 'xzcat', 'unzip', 'uudecode', 'tr', 'rev']);
const DECODER_RAW = /\b(base64|base32|basenc|xxd\s+-r|openssl\b[^|]*-d|gunzip|zcat|bzcat|xzcat|uudecode|unzip\s+-p)\b/;
function decodeCheck(args, st) {
  const text = args.map((x) => x.raw ?? x.s).join(' ');
  if (DECODER_RAW.test(text)) hit(st, 'sh.decode-exec', 'Decoded text is run as a command, so the guard cannot read what it does. Held without being read.', text);
  return null;
}

// shells: sh -c 'script', bash -lc, and scripts read from the pipe
const STDIN_PATH = /^\/(dev\/stdin|dev\/fd\/0|proc\/self\/fd\/0)$/;
const SHELLS =new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'fish', 'csh', 'tcsh', 'rbash', 'posh', 'yash']);
const SHELL_VAL = OPT_SET('-o -O +o +O --rcfile --init-file');
for (const sh of SHELLS) {
  UNWRAP[sh] = (a, cx, st) => {
    let i = 0, c = false;
    for (; i < a.length; i++) {
      const x = a[i].s;
      if (x === '--') { i++; break; }
      if (/^-[A-Za-z]*c[A-Za-z]*$/.test(x)) { c = true; continue; }
      if (SHELL_VAL.has(x)) { i++; continue; }
      if (x[0] === '-' || x[0] === '+') continue;
      break;
    }
    if (c) {
      const s = a[i];
      if (!s) return null;
      if (!s.lit) decodeCheck([s], st);
      return { script: s.s };
    }
    // no -c: a script file (not read), a process substitution whose text is known (bash <(echo ...)), or the script comes on standard input
    if (i < a.length && a[i].psub != null) return { script: a[i].psub };
    if (i < a.length && a[i].s !== '-' && a[i].s !== 's' && !STDIN_PATH.test(a[i].s)) return null;
    const sin = cx.stdin;
    if (sin?.text != null) return { script: sin.text };
    if (sin?.kind === 'pipe' && (sin.names || []).some((n) => DECODERS.has(n))) {
      hit(st, 'sh.decode-exec', 'Decoded text is piped into a shell, so the guard cannot read what it runs. Held without being read.', (cx.argv || []).map((w) => w.raw ?? w.s).join(' '));
    }
    return null;
  };
}
UNWRAP.python = UNWRAP.python3 = UNWRAP.node = UNWRAP.ruby = UNWRAP.perl = UNWRAP.php = (a, cx, st) => {
  // code in other languages is not read; only a decoder piped straight into an interpreter is held
  const sin = cx.stdin;
  if (sin?.kind === 'pipe' && (sin.names || []).some((n) => DECODERS.has(n)) && !a.length) hit(st, 'sh.decode-exec', 'Decoded text is piped into an interpreter, so the guard cannot read what it runs. Held without being read.', (cx.argv || []).map((w) => w.raw ?? w.s).join(' '));
  return null;
};
// source <(echo ...) and . <(...): the text of the process substitution is the script, when it is known
UNWRAP.source = UNWRAP['.'] = (a, cx) => (a[0]?.psub != null ? { script: a[0].psub } : (STDIN_PATH.test(a[0]?.s ?? '') && cx.stdin?.text != null ? { script: cx.stdin.text } : null));

UNWRAP.xargs = (a, cx, st) => {
  const val = OPT_SET('-I -L -l -n -P -s -E -e -d -a --arg-file --delimiter --max-args --max-procs --max-lines --max-chars --eof');
  const i = skipOpts(a, val);
  const opts = a.slice(0, i).map((x) => x.s);
  let cmd = a.slice(i);
  if (!cmd.length) cmd = [{ s: 'echo', lit: true, glob: false, raw: 'echo' }];
  const rep = opts.findIndex((x) => /^-I/.test(x) || x === '-i' || x.startsWith('-i') || x.startsWith('--replace'));
  let ph = null;
  if (rep >= 0) { const x = opts[rep]; ph = x === '-I' ? opts[rep + 1] : x.startsWith('-I') ? x.slice(2) : x.startsWith('--replace=') ? x.slice(10) : x.startsWith('-i') && x.length > 2 ? x.slice(2) : '{}'; }
  const items = (opts.some((x) => x === '-a' || x === '--arg-file' || x.startsWith('--arg-file=')) ? null : pipeItems(cx.stdin, st)) ?? [{ s: SENT, lit: false, glob: false, raw: '<input>' }];
  const next = { ...cx, stdin: { kind: 'none' } };
  if (ph) {
    const argvs = items.slice(0, 16).map((it) => cmd.map((w) => (w.s.includes(ph) ? { ...w, s: w.s.split(ph).join(it.s), lit: w.lit && it.lit, raw: w.raw } : w)));
    return { argvs, cx: next };
  }
  return { argv: [...cmd, ...items], cx: next };
};

UNWRAP.parallel = (a, cx, st) => {
  const i = skipOpts(a, OPT_SET('-j --jobs -S --sshlogin -a --arg-file -N -n -L -l -I --replace -d --delimiter -E --eof --joblog --results --workdir --timeout --tmpdir'));
  let end = a.findIndex((x, k) => k >= i && (x.s === ':::' || x.s === '::::'));
  if (end < 0) end = a.length;
  const cmd = a.slice(i, end).map((w) => (w.s === '{}' || /\{[.#/]*\}/.test(w.s) ? { ...w, s: SENT, lit: false } : w));
  const items = a.slice(end + 1).filter((x) => x.s !== ':::' && x.s !== '::::');
  if (!cmd.length) return null;
  return { argv: [...cmd, ...(items.length ? items : [{ s: SENT, lit: false, glob: false, raw: '<input>' }])] };
};

// SSH and containers run the command somewhere else
const SSH_VAL = OPT_SET('-p -i -l -o -F -J -L -R -D -b -c -E -e -I -m -O -S -W -w -B -Q -P');
UNWRAP.ssh = (a, cx, st) => {
  const i = skipOpts(a, SSH_VAL);
  if (i + 1 >= a.length) return null;
  return { script: joinText(a.slice(i + 1)), st: fork(st, { remote: 'ssh', cwd: null }), cx: { ...cx, remote: 'ssh' } };
};
const DOCKER_VAL = OPT_SET('-H --host --config -c --context -l --log-level --tlscacert --tlscert --tlskey');
const DOCKER_EXEC_VAL = OPT_SET('-e --env -u --user -w --workdir --env-file --detach-keys --index -f --file -p --project-name --profile');
const DOCKER_RUN_VAL = OPT_SET('-v --volume -e --env -p --publish --name --network --net -w --workdir -u --user --entrypoint --mount --env-file -l --label --cpus -m --memory --platform --pull --restart --add-host --cap-add --cap-drop --device -h --hostname --ipc --pid --security-opt --shm-size --tmpfs --ulimit --volumes-from --log-driver --log-opt --dns --group-add --gpus --health-cmd --runtime --stop-signal --stop-timeout --userns --uts --cgroupns --detach-keys --expose --link --mac-address --oom-score-adj --pids-limit --read-only-tmpfs --sysctl --cidfile --cpuset-cpus --cpu-shares --annotation --attach -a');
function containerRun(a, cx, st, valExtra, positionalBefore) {
  const i = skipOpts(a, valExtra);
  return cmdAfter(a, i + positionalBefore, { st: fork(st, { remote: 'container', cwd: null }) });
}
for (const d of ['docker', 'podman', 'nerdctl']) {
  const old = UNWRAP[d];
  UNWRAP[d] = (a, cx, st) => {
    let i = skipOpts(a, DOCKER_VAL);
    let sub = a[i]?.s;
    if (sub === 'container') { i++; sub = a[i]?.s; }
    if (sub === 'compose') { i++; i += skipOpts(a.slice(i), DOCKER_EXEC_VAL); sub = a[i]?.s; return composeUnwrap(a.slice(i + 1), sub, st); }
    if (sub === 'exec') return containerRun(a.slice(i + 1), cx, st, DOCKER_EXEC_VAL, 1);
    if (sub === 'run' || sub === 'create') return containerRun(a.slice(i + 1), cx, st, DOCKER_RUN_VAL, 1);
    return old ? old(a, cx, st) : null;
  };
}
function composeUnwrap(rest, sub, st) {
  if (sub === 'exec' || sub === 'run') return containerRun(rest, null, st, DOCKER_EXEC_VAL, 1);
  return null;
}
UNWRAP['docker-compose'] = (a, cx, st) => {
  const i = skipOpts(a, DOCKER_EXEC_VAL);
  return composeUnwrap(a.slice(i + 1), a[i]?.s, st);
};
const KUBE_VAL = OPT_SET('-n --namespace --context --cluster --user --kubeconfig -s --server --token --as --as-group --certificate-authority --client-certificate --client-key --request-timeout --cache-dir --tls-server-name -c --container -f --filename -l --selector');
for (const k of ['kubectl', 'oc']) {
  UNWRAP[k] = (a, cx, st) => {
    const i = skipOpts(a, KUBE_VAL);
    if (a[i]?.s !== 'exec' && a[i]?.s !== 'run') return null;
    const j = a.findIndex((x, n) => n > i && x.s === '--');
    if (j < 0) return null;
    return cmdAfter(a, j + 1, { st: fork(st, { remote: 'container', cwd: null }) });
  };
}
UNWRAP.vagrant = (a, cx, st) => {
  const c = a.findIndex((x) => x.s === '-c' || x.s === '--command');
  return c >= 0 && a[c + 1] ? { script: a[c + 1].s, st: fork(st, { remote: 'ssh', cwd: null }), cx: { ...cx, remote: 'ssh' } } : null;
};
UNWRAP.tmux = (a, cx, st) => {
  const A = argParse(a, { val: '-c -f -L -S -t -s -n -x -y -e -F -P' });
  const sub = A.pos[0];
  if (['new-session', 'new', 'new-window', 'neww', 'split-window', 'splitw', 'run-shell', 'run', 'respawn-pane', 'respawnp', 'respawn-window'].includes(sub) && A.pos.length > 1) return { script: A.pos[A.pos.length - 1] };
  if (['send-keys', 'send'].includes(sub)) return { script: A.pos.slice(1).filter((x) => x !== 'Enter' && x !== 'C-m').join(' ') };
  return null;
};

// package runners and environment wrappers: the command comes after their own words
const PKG_BIN = { '@railway/cli': 'railway', 'firebase-tools': 'firebase', '@neondatabase/neonctl': 'neonctl', 'neonctl': 'neonctl', 'wrangler': 'wrangler', '@cloudflare/wrangler': 'wrangler', '@vercel/cli': 'vercel', 'netlify-cli': 'netlify', '@supabase/cli': 'supabase', 'supabase': 'supabase', '@aws-amplify/cli': 'amplify', 'aws-cdk': 'cdk', '@pulumi/pulumi': 'pulumi', '@stripe/stripe-cli': 'stripe', 'drizzle-kit': 'drizzle-kit', 'prisma': 'prisma', '@prisma/cli': 'prisma', 'sequelize-cli': 'sequelize', 'knex': 'knex', 'typeorm': 'typeorm' };
function pkgCommand(w) {
  if (!w.lit) return w;
  let n = w.s;
  const at = n.lastIndexOf('@');
  if (at > 0) n = n.slice(0, at);
  const bin = PKG_BIN[n] ?? n.replace(/^@[^/]+\//, '');
  return { ...w, s: bin, raw: w.raw };
}
const NPX_VAL = OPT_SET('-p --package -c --call --node-arg --registry --cache --userconfig --loglevel');
const runnerPkg = (a, extra = EMPTY) => {
  const i = skipOpts(a, new Set([...NPX_VAL, ...extra]));
  if (i >= a.length) return null;
  const r = a.slice(i); r[0] = pkgCommand(r[0]);
  return { argv: r };
};
const runnerC = (a) => { const c = a.findIndex((x) => x.s === '-c' || x.s === '--call'); return c >= 0 && a[c + 1] ? { script: a[c + 1].s } : null; };
UNWRAP.npx = (a) => runnerC(a) || runnerPkg(a);
UNWRAP.bunx = (a) => runnerPkg(a, OPT_SET('--bun'));
UNWRAP.uvx = (a) => runnerPkg(a, OPT_SET('--from --with --python -p'));
UNWRAP.pipx = (a) => { const i = skipOpts(a); return a[i]?.s === 'run' ? runnerPkg(a.slice(i + 1), OPT_SET('--spec --python')) : null; };
UNWRAP.poetry = (a) => { const i = skipOpts(a, OPT_SET('-C --directory -P --project')); return a[i]?.s === 'run' ? cmdAfter(a, i + 1) : null; };
UNWRAP.pipenv = UNWRAP.poetry;
UNWRAP.uv = (a) => { const i = skipOpts(a, OPT_SET('--directory --project --python -p')); if (a[i]?.s === 'run') return cmdAfter(a, skipOpts(a.slice(i + 1), OPT_SET('--with --python -p --directory')) + i + 1); if (a[i]?.s === 'tool' && a[i + 1]?.s === 'run') return runnerPkg(a.slice(i + 2), OPT_SET('--from --with --python')); return null; };
UNWRAP.bundle = (a) => { const i = skipOpts(a); return a[i]?.s === 'exec' ? cmdAfter(a, skipOpts(a.slice(i + 1)) + i + 1) : null; };
const dashDash = (a) => { const j = a.findIndex((x) => x.s === '--'); return j >= 0 ? cmdAfter(a, j + 1) : null; };
const subThen = (subs, after = 0) => (a) => { const i = skipOpts(a); if (!subs.includes(a[i]?.s)) return null; const d = dashDash(a); if (d) return d; return cmdAfter(a, skipOpts(a.slice(i + 1)) + i + 1 + after); };
UNWRAP.mise = UNWRAP.rtx = subThen(['exec', 'x', 'run']);
UNWRAP.asdf = subThen(['exec'], 1);
UNWRAP.direnv = subThen(['exec'], 1);
UNWRAP.doppler = subThen(['run']);
UNWRAP.op = subThen(['run']);
UNWRAP.infisical = subThen(['run']);
UNWRAP.dotenvx = subThen(['run']);
UNWRAP['aws-vault'] = subThen(['exec'], 1);
UNWRAP.chamber = subThen(['exec'], 1);
UNWRAP.dotenv = (a) => dashDash(a) || cmdAfter(a, skipOpts(a, OPT_SET('-e -f -p -v -c')));
UNWRAP.railway = (a) => { const i = skipOpts(a); return a[i]?.s === 'run' ? (dashDash(a) || cmdAfter(a, skipOpts(a.slice(i + 1), OPT_SET('-s --service -e --environment')) + i + 1)) : null; };
UNWRAP.heroku = (a, cx, st) => { const i = skipOpts(a, OPT_SET('-a --app -r --remote')); return a[i]?.s === 'run' || a[i]?.s === 'run:detached' ? { script: joinText(a.slice(skipOpts(a.slice(i + 1), OPT_SET('-a --app -r --remote -s --size -e --env')) + i + 1)), st: fork(st, { remote: 'container', cwd: null }) } : null; };
UNWRAP.fly = UNWRAP.flyctl = (a, cx, st) => {
  const A = argParse(a, { val: '-a --app -C --command -s --select -t --token -c --config --region' });
  const c = A.get('-C') ?? A.get('--command');
  if (A.pos[0] === 'ssh' && typeof c === 'string') return { script: c, st: fork(st, { remote: 'ssh', cwd: null }), cx: { ...cx, remote: 'ssh' } };
  return null;
};
UNWRAP.gcloud = (a, cx, st) => {
  const A = argParse(a, { val: '--project --account --zone --region --command --ssh-flag --format --filter --impersonate-service-account' });
  const c = A.get('--command');
  return A.pos.includes('ssh') && typeof c === 'string' ? { script: c, st: fork(st, { remote: 'ssh', cwd: null }), cx: { ...cx, remote: 'ssh' } } : null;
};

// package.json scripts: npm run X, pnpm X, yarn X, bun run X (the scripts are read from the nearest package.json)
const PM_BUILTIN = new Set(['install', 'i', 'add', 'remove', 'rm', 'uninstall', 'un', 'update', 'up', 'upgrade', 'publish', 'pack', 'link', 'unlink', 'init', 'create', 'dlx', 'exec', 'x', 'run', 'run-script', 'test', 't', 'start', 'stop', 'restart', 'ci', 'audit', 'outdated', 'list', 'ls', 'why', 'config', 'cache', 'store', 'env', 'prune', 'rebuild', 'dedupe', 'patch', 'help', 'version', 'whoami', 'login', 'logout', 'info', 'view', 'search', 'bin', 'root', 'fetch', 'import', 'deploy', 'self-update', 'set', 'get', 'workspace', 'workspaces', 'plugin', 'node', 'npm', 'unpublish', 'deprecate', 'owner', 'dist-tag', 'access', 'token', 'team', 'org', 'tag', 'bunx', 'pm', 'completions', 'upgrade', 'repl']);
const PM_VAL = OPT_SET('-C --dir --prefix -w --workspace --filter -F --cwd --registry --loglevel --userconfig --cache --use-node-version --network-concurrency --cwd');
function findPackageJson(st) {
  let d = st.cwd;
  for (let k = 0; d && k < 8; k++) {
    const t = st.o.readFile(d + '/package.json');
    if (t != null) return t;
    if (d === '/' || (st.o.root && d === st.o.root)) break;
    d = d.replace(/\/[^/]*$/, '') || '/';
  }
  return null;
}
function runScripts(name, st, extra) {
  const raw = findPackageJson(st);
  if (raw == null) return;
  let scripts;
  try { scripts = JSON.parse(raw).scripts; } catch { return; }
  if (!scripts || typeof scripts !== 'object') return;
  for (const n of [`pre${name}`, name, `post${name}`]) {
    if (typeof scripts[n] === 'string') evalScript(scripts[n] + (n === name && extra ? ' ' + extra : ''), st, {}, `npm script "${n}"`);
  }
}
for (const pm of ['npm', 'pnpm', 'yarn', 'bun']) {
  UNWRAP[pm] = (a, cx, st) => {
    const i = skipOpts(a, PM_VAL);
    const sub = a[i]?.s;
    if (!sub) return null;
    if (sub === 'exec' || sub === 'x') { const d = dashDash(a.slice(i + 1)); return d || cmdAfter(a, skipOpts(a.slice(i + 1)) + i + 1); }
    if (sub === 'dlx') return runnerPkg(a.slice(i + 1));
    let name = null, restFrom = i + 1;
    if (sub === 'run' || sub === 'run-script' || sub === 'rum' || sub === 'urn') { const j = skipOpts(a.slice(i + 1), PM_VAL) + i + 1; name = a[j]?.s; restFrom = j + 1; }
    else if (['test', 't', 'tst'].includes(sub)) name = 'test';
    else if (['start', 'stop', 'restart'].includes(sub)) name = sub;
    else if (pm !== 'npm' && !PM_BUILTIN.has(sub) && !sub.startsWith('-')) name = sub;
    if (!name || !/^[\w:.@/-]+$/.test(name)) return null;
    const after = a.slice(restFrom).filter((x) => x.s !== '--');
    runScripts(name, st, after.every((x) => x.lit) ? after.map((x) => x.s).join(' ') : '');
    return null;
  };
}

// ---------------------------------------------------------------- builtins that change what the line knows
const setBuiltin = (a, cx, st) => {
  for (const x of a) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)(\+?)=([\s\S]*)$/.exec(x.s);
    if (m) setVar(st, m[1], !!m[2], m[3]);
  }
  return null;
};
UNWRAP.export = UNWRAP.declare = UNWRAP.typeset = UNWRAP.local = UNWRAP.readonly = setBuiltin;
UNWRAP.read = (a, cx, st) => { for (const x of a) if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(x.s)) st.vars.set(x.s, SENT); return null; };
UNWRAP.unset = (a, cx, st) => { for (const x of a) st.vars.delete(x.s); return null; };
UNWRAP.alias = (a, cx, st) => {
  for (const x of a) {
    const m = /^([^=\s]+)=([\s\S]*)$/.exec(x.s);
    if (m) st.aliases.set(m[1], m[2].trim().split(/\s+/).filter(Boolean).map((s) => ({ s, lit: true, glob: false, raw: s })));
  }
  return null;
};
UNWRAP.cd = UNWRAP.pushd = (a, cx, st) => {
  const t = a.filter((x) => !/^-[LPe@]*$/.test(x.s))[0];
  if (!t) { st.cwd = st.o.home ?? null; return null; }
  if (!t.lit || t.s === '-' || t.glob) { st.cwd = null; return null; }
  st.cwd = t.s.startsWith('/') ? normPath(t.s) : st.cwd ? normPath(st.cwd + '/' + t.s) : null;
  return null;
};
UNWRAP.popd = (a, cx, st) => { st.cwd = null; return null; };

// ---------------------------------------------------------------- the API map the curl rule uses
// Method and path globs of the server's irreversible map (server/src/providers.js), so that curl, wget and gh api
// to a brokered API are held too. A test checks this copy against the server. `guard install` stores the live map
// (GET /v1/meta) next to the config, and that replaces this copy when it is present.
// BEGIN GENERATED API MAP (node scripts/sync-guard.mjs writes this from server/src/providers.js; do not edit by hand)
export const BUNDLED_API_MAP = {
  mapVersion: "2026-10-10.1",
  providers: [
    { id: "github", host: "api.github.com", base: "", rules: [
      { id: "gh.delete", m: "DELETE", p: "/**", why: "Any DELETE on GitHub removes something (repo, branch, release, key, member).", body: false },
      { id: "gh.force-push", m: "PATCH", p: "/repos/*/*/git/refs/**", why: "Force-updating a ref rewrites history and can drop commits for everyone.", body: true },
      { id: "gh.transfer", m: "POST", p: "/repos/*/*/transfer", why: "Transferring a repository hands it to another owner.", body: false },
      { id: "gh.visibility", m: "PATCH", p: "/repos/*/*", why: "Changing visibility can publish private code; archiving freezes a repo.", body: true },
      { id: "gh.protection", m: "PUT", p: "/repos/*/*/branches/*/protection", why: "Rewriting branch protection can remove the rules that guard main.", body: false },
      { id: "gh.graphql", m: "POST", p: "/graphql", why: "A GitHub GraphQL mutation (deleteRepository, transferRepository, updateRepository and every other write), or a request Counterseal cannot read.", body: true },
      { id: "gh.graphql-get", m: "GET", p: "/graphql", why: "GitHub GraphQL over GET is not a normal client path.", body: false },
      { id: "gh.actions-secret", m: "PUT", p: "/repos/*/*/actions/secrets/*", why: "Overwriting a CI secret silently changes what production deploys with.", body: false },
    ] },
    { id: "cloudflare", host: "api.cloudflare.com", base: "/client/v4", rules: [
      { id: "cf.delete", m: "DELETE", p: "/**", why: "Deletes a zone, DNS record, Worker, bucket, database or token.", body: false },
      { id: "cf.purge", m: "POST", p: "/zones/*/purge_cache", why: "Purging everything, a whole host or a URL prefix can take a site down under load.", body: true },
      { id: "cf.worker-put", m: "PUT", p: "/accounts/*/workers/scripts/**", why: "Uploading over a Worker replaces production code.", body: false },
      { id: "cf.dns-write", m: "PUT,PATCH", p: "/zones/*/dns_records/*", why: "Overwriting a DNS record can point a domain somewhere else.", body: false },
      { id: "cf.r2-config", m: "PUT", p: "/accounts/*/r2/buckets/*/{lifecycle,cors,domains/**}", why: "Bucket lifecycle rules can delete objects; domain changes expose a bucket.", body: false },
      { id: "cf.token-roll", m: "PUT", p: "/user/tokens/*/value", why: "Rolling an API token breaks everything using it.", body: false },
      { id: "cf.d1-sql", m: "POST", p: "/accounts/*/d1/database/*/{query,raw}", why: "SQL against a production D1 database that is not a single plain read.", body: true },
      { id: "cf.d1-import", m: "POST", p: "/accounts/*/d1/database/*/import", why: "Importing an SQL file into a production D1 database runs SQL Counterseal cannot read.", body: true },
      { id: "cf.d1-restore", m: "POST", p: "/accounts/*/d1/database/*/time_travel/restore", why: "Restoring a D1 database to an earlier point overwrites everything written since.", body: false },
    ] },
    { id: "railway", host: "backboard.railway.app", base: "/graphql/v2", rules: [
      { id: "rw.mutation", m: "POST", p: "/**", why: "A Railway mutation other than a redeploy or restart, or a request Counterseal cannot read (PocketOS lost production to one volumeDelete).", body: true },
      { id: "rw.get-mutation", m: "GET", p: "/**", why: "A Railway mutation sent over GET.", body: true },
      { id: "rw.method", m: "PUT,PATCH,DELETE", p: "/**", why: "Railway's API is GraphQL over POST; a PUT, PATCH or DELETE is not a normal client path.", body: false },
    ] },
    { id: "stripe", host: "api.stripe.com", base: "", rules: [
      { id: "st.delete", m: "DELETE", p: "/**", why: "Deletes customers, products, webhooks or cancels subscriptions.", body: false },
      { id: "st.money", m: "POST", p: "/v1/{refunds,payouts,transfers,charges,topups}", why: "Moves money.", body: false },
      { id: "st.money2", m: "POST", p: "/v1/payment_intents/*/{confirm,capture}", why: "Moves money.", body: false },
      { id: "st.pi-confirm", m: "POST", p: "/v1/payment_intents", why: "Creating a payment intent with confirm=true charges the customer.", body: true },
      { id: "st.refund", m: "POST", p: "/v1/{charges,application_fees}/*/{refund,refunds}", why: "Refunds money.", body: false },
      { id: "st.invoice", m: "POST", p: "/v1/invoices/*/{pay,void}", why: "Paying or voiding an invoice cannot be undone.", body: false },
      { id: "st.credit-note", m: "POST", p: "/v1/credit_notes", why: "Issuing a credit note credits or refunds the customer.", body: false },
      { id: "st.credit-note-void", m: "POST", p: "/v1/credit_notes/*/void", why: "Voiding a credit note cannot be undone.", body: false },
      { id: "st.cancel", m: "POST", p: "/v1/subscriptions/*/cancel", why: "Cancels a paying customer.", body: false },
      { id: "st.cancel-at", m: "POST", p: "/v1/subscriptions/*", why: "Schedules a paying customer to be cancelled.", body: true },
      { id: "st.webhook", m: "POST", p: "/v1/webhook_endpoints/**", why: "Changing webhooks can silently stop order fulfilment.", body: false },
    ] },
    { id: "supabase", host: "api.supabase.com", base: "", rules: [
      { id: "sb.delete", m: "DELETE", p: "/**", why: "Deletes a project, function, branch or secret.", body: false },
      { id: "sb.sql", m: "POST", p: "/v1/projects/*/database/query", why: "SQL on the database that is not a single plain read (SELECT, WITH ... SELECT, EXPLAIN, SHOW).", body: true },
      { id: "sb.migration", m: "POST,PUT,PATCH", p: "/v1/projects/*/database/migrations", why: "A database migration runs schema changes (and any SQL) on production.", body: false },
      { id: "sb.pause", m: "POST", p: "/v1/projects/*/{pause,restore}", why: "Pausing or restoring a project takes production offline.", body: false },
      { id: "sb.db-password", m: "POST", p: "/v1/projects/*/database/password", why: "Resetting the database password breaks every existing connection.", body: false },
      { id: "sb.config", m: "PUT,PATCH", p: "/v1/projects/*/config/**", why: "Changes production database, auth or network configuration.", body: false },
      { id: "sb.secrets", m: "POST", p: "/v1/projects/*/secrets", why: "Overwriting project secrets changes production configuration.", body: false },
    ] },
    { id: "vercel", host: "api.vercel.com", base: "", rules: [
      { id: "vc.delete", m: "DELETE", p: "/**", why: "Any DELETE on Vercel removes something (project, deployment, domain, alias, environment variable, team). Deleting a project also deletes its deployments, domains, environment variables and settings. The API has no undelete.", body: false },
      { id: "vc.deploy", m: "POST", p: "{,/v*}/deployments", why: "Creating a deployment can go straight to production: when the request does not name a target, Vercel infers it from the branch. A production deploy replaces what visitors see, and rolling back is a second production change.", body: false },
      { id: "vc.production", m: "POST", p: "{,/v*}/{projects/*/promote/*,projects/*/rollback/*,deployments/*/aliases,projects/*/rolling-release/start,projects/*/rolling-release/approve-stage,projects/*/rolling-release/complete,projects/*/routes/versions,bulk-redirects/versions}", why: "Points production traffic or a live domain somewhere else: promote, rollback, assigning an alias (it moves off the deployment that had it), rolling releases, and promoting or restoring routing rules and bulk redirects. Visitors see it at once, and undoing it is another production change.", body: false },
      { id: "vc.pause", m: "POST", p: "{,/v*}/projects/*/pause", why: "Pausing a project takes its production deployment offline: visitors get a 503 until someone resumes the project.", body: false },
      { id: "vc.project-settings", m: "PATCH", p: "{,/v*}/projects/*", why: "Changes project settings: build and install commands, root directory, framework, deployment protection, trusted IPs. A wrong value breaks the next build or exposes previews, and the old value is not kept.", body: false },
      { id: "vc.security", m: "POST,PUT,PATCH", p: "{,/v*}/security/{attack-mode,firewall/config,firewall/config/*/activate,firewall/bypass}", why: "Changes the firewall or Attack Challenge mode of a live project. A wrong rule can block every visitor or open the site to attack, and activating a config replaces the active one.", body: false },
      { id: "vc.domain", m: "POST,PATCH", p: "{,/v*}/{domains/*,projects/*/domains/*,projects/*/domains/*/move,registrar/domains/*/nameservers,registrar/domains/*/auto-renew}", why: "Moves or repoints a domain: moving an apex domain to another team or project, changing a project domain, nameservers, or turning off auto-renew (a domain that lapses can be lost). Traffic and email can go elsewhere at once.", body: false },
      { id: "vc.dns", m: "PUT,PATCH", p: "{,/v*}/domains/{records/*,*/records}", why: "Overwriting a DNS record can point a domain somewhere else, and the previous value is not kept.", body: false },
      { id: "vc.money", m: "POST", p: "{,/v*}/{registrar/domains/buy,registrar/domains/*/buy,registrar/domains/*/transfer,registrar/domains/*/renew,billing/buy}", why: "Spends money: buying, transferring or renewing a domain, or buying credits, charged to the team.", body: false },
      { id: "vc.env", m: "PATCH", p: "{,/v*}/{projects/*/env/*,env}", why: "Overwrites an environment variable. The old value is not kept, and the next deployment that reads the new one can break production.", body: false },
      { id: "vc.env-upsert", m: "POST", p: "{,/v*}/projects/*/env", why: "Creating environment variables with upsert=true overwrites any that already exist. The old values are not kept.", body: true },
      { id: "vc.cache", m: "POST", p: "{,/v*}/edge-cache/dangerously-*", why: "Deleting cache entries forces every next request through to your origin at once (a cache stampede). Vercel marks these calls dangerous and not recommended.", body: false },
      { id: "vc.restore", m: "POST", p: "{,/v*}/global-config/*/backups/*/restore", why: "Restoring an Edge Config backup replaces the live configuration with the backup. Changes made since are lost.", body: false },
      { id: "vc.access", m: "POST,PUT,PATCH", p: "{,/v*}/{teams/*/members,teams/*/members/*,projects/*/members,access-groups/*/projects,access-groups/*/projects/*,projects/*/transfer-request,projects/transfer-request/*}", why: "Gives someone access or hands something over: team invites and role changes, project members, access groups, project transfers. Access given to the wrong person is a way in that does not go through Counterseal.", body: false },
      { id: "vc.token", m: "POST", p: "{,/v*}/{user/tokens,api-keys}", why: "Makes a new Vercel token or API key. The agent would then hold a real key that does not go through Counterseal.", body: false },
    ] },
    { id: "neon", host: "console.neon.tech", base: "/api/v2", rules: [
      { id: "neon.delete", m: "DELETE", p: "/**", why: "Any DELETE on Neon removes something. A deleted project (its computes, branches, databases and roles) can be recovered for 7 days; a deleted branch, database, role, snapshot or stored object has no documented recovery, and deleting a branch drops its connections.", body: false },
      { id: "neon.restore", m: "POST", p: "/projects/*/{branches/*/restore,branches/*/finalize_restore,snapshots/*/restore}", why: "Restoring overwrites all data and schema in the branch and interrupts its connections. Neon keeps the replaced state as a backup branch, which is the only way back.", body: false },
      { id: "neon.password", m: "POST", p: "/projects/*/branches/*/roles/*/reset_password", why: "Resetting a role password drops its connections and breaks every app that still uses the old password.", body: false },
      { id: "neon.settings", m: "PATCH", p: "/projects/{*,*/endpoints/*,*/branches/*/databases/*}", why: "Changes project, compute or database settings: history retention, the IP allow list, compute size and whether it is disabled, a database name. A wrong value locks clients out or breaks connection strings.", body: false },
      { id: "neon.retention", m: "PATCH,PUT", p: "/projects/*/{branches/*,snapshots/*,branches/*/backup_schedule}", why: "Changes whether a branch is protected, when a branch or snapshot expires, or how often backups are taken. A shorter life or a missing backup is only noticed when it is needed.", body: false },
      { id: "neon.network", m: "POST", p: "/{projects/*/vpc_endpoints/*,organizations/*/vpc/region/*/vpc_endpoints/*}", why: "Restricting a project to a VPC endpoint locks out every client that is not on it.", body: false },
      { id: "neon.transfer", m: "POST,PUT", p: "/{projects/*/transfer_requests,projects/*/transfer_requests/*,organizations/*/projects/transfer,users/me/projects/transfer}", why: "Transferring a project hands it to another account or organization.", body: false },
      { id: "neon.secrets", m: "POST", p: "/{api_keys,organizations/*/api_keys,projects/*/branches/*/credentials,projects/*/branches/*/credentials/*/reveal,projects/*/branches/*/credentials/*/rotate,projects/*/branches/*/realtime/rotate_secret}", why: "Makes, reveals or rotates a key. A new or revealed key is one the agent holds outside Counterseal, and a rotated one stops working for everything that used the old value.", body: false },
      { id: "neon.access", m: "POST,PUT,PATCH", p: "/{projects/*/permissions,projects/*/members/*/role,organizations/*/members/*,organizations/*/invitations}", why: "Gives someone access or changes a role. Access given to the wrong person is a way in that does not go through Counterseal.", body: false },
      { id: "neon.auth", m: "POST,PUT,PATCH", p: "/projects/{auth/**,*/auth/**,*/branches/*/auth,*/branches/*/auth/**}", why: "Changes Neon Auth: trusted redirect domains, OAuth providers, email servers, user roles. A wrong trusted domain or role can let the wrong people sign in.", body: false },
      { id: "neon.function", m: "POST,PATCH", p: "/projects/*/branches/*/functions/{*,*/deployments}", why: "Deploying or changing a branch function replaces the code that runs there (the newest deployment becomes active).", body: false },
    ] },
    { id: "fly", host: "api.machines.dev", base: "/v1", rules: [
      { id: "fly.delete", m: "DELETE", p: "/**", why: "Any DELETE on Fly.io removes something. Destroying a volume deletes its data with no undo (its snapshots may stay restorable for a few days); destroying an app with force=true stops every Machine and deletes the app at once.", body: false },
      { id: "fly.exec", m: "POST", p: "/apps/*/machines/*/exec", why: "Runs a command inside a live Machine. Anything the Machine can do to its volume and its network, this can do.", body: false },
      { id: "fly.machine-update", m: "POST", p: "/apps/*/machines/*", why: "Replaces a Machine configuration (image, environment, mounts, services). It is a deploy to whatever that Machine serves.", body: false },
      { id: "fly.machine-stop", m: "POST", p: "/apps/*/machines/*/{stop,suspend,signal,cordon}", why: "Takes a Machine out of service: stopped, suspended, killed by a signal, or cordoned so the proxy sends it no traffic.", body: false },
      { id: "fly.volume", m: "PUT", p: "/apps/*/volumes/{*,*/extend}", why: "Extending a volume cannot be undone (volumes cannot be made smaller) and is billed. Changing snapshot retention or backups decides how long data can be recovered.", body: false },
      { id: "fly.secrets", m: "POST", p: "/apps/*/{secrets,secrets/*,secretkeys/*,secretkeys/*/generate}", why: "Overwrites app secrets. The old value is not kept.", body: false },
      { id: "fly.token", m: "POST", p: "/apps/*/deploy_token", why: "Makes a deploy token. The agent would then hold a real key that does not go through Counterseal.", body: false },
      { id: "fly.postgres", m: "POST,PATCH", p: "/postgres/*/users/{*,*/rotate_password}", why: "Rotating a Postgres password or changing a role breaks every client that still uses the old one.", body: false },
    ] },
    { id: "resend", host: "api.resend.com", base: "", rules: [
      { id: "rs.delete", m: "DELETE", p: "/**", why: "Any DELETE on Resend removes something (domain, audience, contact, segment, API key, webhook, template). A deleted sending domain stops all sending from it, and the API has no undelete.", body: false },
      { id: "rs.batch", m: "POST", p: "/emails/batch", why: "Sends up to 100 emails in one call, each to up to 50 recipients. Sent email cannot be unsent.", body: false },
      { id: "rs.broadcast", m: "POST", p: "/broadcasts/*/send", why: "Sends a broadcast to every contact in its segment. Sent email cannot be unsent.", body: false },
      { id: "rs.broadcast-now", m: "POST", p: "/broadcasts", why: "Creating a broadcast with send=true sends it to its whole segment at once. Only a draft is safe. Sent email cannot be unsent.", body: true },
      { id: "rs.recipients", m: "POST", p: "/emails", why: "An email to more than one recipient (to, cc or bcc), a list hidden in one address, or a request Counterseal cannot read. One recipient passes; sent email cannot be unsent.", body: true },
      { id: "rs.automation", m: "POST", p: "/automations", why: "An automation that is enabled emails contacts on its own from then on. Create it disabled and enable it yourself.", body: true },
      { id: "rs.automation-edit", m: "PATCH", p: "/automations/*", why: "Enabling an automation, or changing the steps of one, changes what it emails to contacts from then on.", body: true },
      { id: "rs.suppression", m: "POST", p: "/suppressions/batch/remove", why: "Removing suppressions lets email go again to addresses that bounced or complained, which can hurt the sending reputation of the whole domain.", body: false },
      { id: "rs.webhook-secret", m: "POST", p: "/webhooks/*/signing-secret/rotate", why: "Rotating a webhook signing secret breaks verification for every receiver that still uses the old one.", body: false },
      { id: "rs.inbox-send", m: "POST", p: "/inboxes/*/{drafts/*/send,threads/*/emails/*/reply,threads/*/emails/*/forward}", why: "Sends from an inbox: a draft, a reply (with reply_all to everyone on the thread) or a forward to up to 50 recipients. Sent email cannot be unsent.", body: false },
      { id: "rs.api-key", m: "POST", p: "/api-keys", why: "Makes a Resend API key, possibly with full access. The agent would then hold a real key that does not go through Counterseal.", body: false },
    ] },
    { id: "shopify", host: "*.myshopify.com", base: "", rules: [
      { id: "sh.get", m: "GET", p: "/admin/api/*/graphql.json", why: "Shopify GraphQL over GET is not a normal client path.", body: false },
      { id: "sh.method", m: "PUT,PATCH,DELETE", p: "/**", why: "Shopify GraphQL is POST only; a PUT, PATCH or DELETE is not a normal client path. (Every other path on the store is refused before the map is asked.)", body: false },
      { id: "sh.unreadable", m: "POST", p: "/admin/api/*/graphql.json", why: "A GraphQL request Counterseal cannot read with certainty: a batch, a persisted query, a fragment at the mutation root, a repeated key, or a body that is not one JSON object with a query.", body: true },
      { id: "sh.bulk", m: "POST", p: "/admin/api/*/graphql.json", why: "A bulk operation runs a mutation once per line of an uploaded file, which Counterseal cannot read.", body: true },
      { id: "sh.delete", m: "POST", p: "/admin/api/*/graphql.json", why: "A Shopify mutation that deletes or removes data: any name with delete or destroy, a shipping profile, a locale and its translations, inventory at a location, a location, or the app itself. Shopify says product, order and app removals are permanent.", body: true },
      { id: "sh.money", m: "POST", p: "/admin/api/*/graphql.json", why: "A Shopify mutation that moves money or changes what counts as paid: refunds, captures, charges to customers or to the merchant, marking an order paid, voiding a payment, buying a shipping label, a payout.", body: true },
      { id: "sh.giftcard", m: "POST", p: "/admin/api/*/graphql.json", why: "Gift cards and store credit are spendable value: creating, crediting, debiting or deactivating them (a deactivated gift card cannot be re-enabled).", body: true },
      { id: "sh.cancel", m: "POST", p: "/admin/api/*/graphql.json", why: "Cancelling an order is irreversible (Shopify), and can refund the customer, restock inventory and notify them. A cancelled or expired subscription contract cannot be activated again.", body: true },
      { id: "sh.customer-data", m: "POST", p: "/admin/api/*/graphql.json", why: "Erases, merges or disables protections on customer data: a data erasure request (Shopify has a separate mutation to cancel one), merging two customers, revoking a stored payment method, switching off privacy features.", body: true },
      { id: "sh.access", m: "POST", p: "/admin/api/*/graphql.json", why: "Makes a delegate access token (a key the agent would hold outside Counterseal) or revokes access scopes the app depends on.", body: true },
      { id: "sh.theme", m: "POST", p: "/admin/api/*/graphql.json", why: "Publishing a theme, or writing theme files, can change the live storefront. Counterseal cannot tell which theme is live.", body: true },
      { id: "sh.webhook", m: "POST", p: "/admin/api/*/graphql.json", why: "A webhook subscription sends store events (orders, customers) to a URL. Changing one can stop fulfilment or send customer data elsewhere.", body: true },
    ] },
  ],
};
// END GENERATED API MAP

/** the map in the shape the curl rule uses, from the body of GET /v1/meta (providers with irreversible rules).
 * The server does not send each provider's base path yet, so it is taken from the bundled map by host. */
export function apiMapFromMeta(meta) {
  const bases = Object.fromEntries(BUNDLED_API_MAP.providers.map((p) => [p.host, p.base]));
  const providers = [];
  for (const p of Array.isArray(meta?.providers) ? meta.providers : []) {
    if (typeof p?.host !== 'string' || !Array.isArray(p.irreversible)) continue;
    const rules = p.irreversible.filter((r) => r && typeof r.id === 'string' && typeof r.method === 'string' && typeof r.path === 'string')
      .map((r) => ({ id: r.id.slice(0, 64), m: r.method, p: r.path, why: String(r.why ?? '').slice(0, 300) }));
    providers.push({ id: String(p.id ?? p.host), host: lc(p.host), base: typeof p.base === 'string' ? p.base : (bases[lc(p.host)] ?? ''), rules });
  }
  return { providers, mapVersion: typeof meta?.mapVersion === 'string' ? meta.mapVersion : null };
}
/** providers by host. A host such as *.myshopify.com (a store address per credential) matches one label in front of it. */
function hostMap(map) {
  const exact = new Map(), wild = [];
  for (const p of map?.providers || BUNDLED_API_MAP.providers) {
    const h = lc(p.host);
    if (h.startsWith('*.')) wild.push([h.slice(1), p]); else exact.set(h, p);
  }
  return { exact, wild };
}
const entryFor = (hm, host) => hm.exact.get(host) ?? hm.wild.find(([sfx]) => host.endsWith(sfx) && host.length > sfx.length && !host.slice(0, -sfx.length).includes('.'))?.[1];
const knownHosts = (hm) => [...hm.exact.keys(), ...hm.wild.map(([s]) => s)];

// rules whose server side test reads the body; the guard repeats the part of it that it can
const jsonOf = (t) => { try { const j = JSON.parse(t); return j && typeof j === 'object' ? j : null; } catch { return null; } };
function bodyFields(b) {
  if (!b || b.text == null) return null;
  const j = jsonOf(b.text);
  const f = new Map();
  if (j && !Array.isArray(j)) { for (const [k, v] of Object.entries(j)) f.set(lc(k), v); return f; }
  if (j) return null;
  for (const part of b.text.split('&')) { const e = part.indexOf('='); const k = lc(safeDecode(e < 0 ? part : part.slice(0, e)).replace(/\[.*$/, '')); if (k) f.set(k, e < 0 ? '' : part.slice(e + 1)); }
  return f;
}
const truthy = (v) => v !== undefined && v !== null && v !== false && !['', 'false', '0'].includes(String(v).toLowerCase());
const BODY_TESTS = {
  'gh.force-push': (b) => { const f = bodyFields(b); return !f || truthy(f.get('force')); },
  'gh.visibility': (b) => { const f = bodyFields(b); return !f || f.has('visibility') || f.has('private') || truthy(f.get('archived')); },
  'gh.graphql': (b) => b?.text == null || /\bmutation\b/i.test(b.text),
  'rw.mutation': (b) => b?.text == null || /\bmutation\b|persistedquery|doc_id|documentid/i.test(b.text),
  'rw.get-mutation': (b, search) => /mutation|persisted/i.test(search || '') || /mutation|persisted/i.test(safeDecode(search || '')),
  'st.pi-confirm': (b) => { const f = bodyFields(b); return !f || truthy(f.get('confirm')); },
  'st.cancel-at': (b) => { const f = bodyFields(b); return !f || f.has('cancel_at') || f.has('cancel_at_period_end'); },
  'cf.purge': (b) => { const f = bodyFields(b); return !f || [...f.keys()].some((k) => k !== 'files' && k !== 'tags'); },
  'cf.d1-import': (b) => { const f = bodyFields(b); return !f || !['init', 'poll'].includes(f.get('action')); },
  'cf.d1-sql': (b) => sqlBodyHold(b),
  'sb.sql': (b) => sqlBodyHold(b),
  // Vercel: creating variables with upsert=true overwrites the ones that exist
  'vc.env-upsert': (b, search) => { const f = bodyFields(b); return !f || truthy(f.get('upsert')) || /(^|[?&;])upsert(=|&|$)/i.test(search || '') && !/(^|[?&;])upsert=(false|0)(&|$)/i.test(search || ''); },
  // Resend: one recipient passes; a list, cc, bcc, or a body that is not one JSON object is held
  'rs.recipients': (b) => {
    const j = b?.text == null ? null : jsonOf(b.text);
    if (!j || Array.isArray(j)) return true;
    const one = (v) => typeof v === 'string' && v.length <= 320 && !/[,;]/.test(v) && (v.match(/@/g) || []).length === 1;
    const empty = (v) => v === undefined || v === '' || (Array.isArray(v) && !v.length);
    const single = Array.isArray(j.to) ? j.to.length === 1 && one(j.to[0]) : one(j.to);
    return !single || !empty(j.cc) || !empty(j.bcc);
  },
  'rs.broadcast-now': (b) => { const j = b?.text == null ? null : jsonOf(b.text); return !j || Array.isArray(j) || (j.send !== undefined && j.send !== false); },
  'rs.automation': (b) => { const j = b?.text == null ? null : jsonOf(b.text); return !j || Array.isArray(j) || (Object.hasOwn(j, 'status') && j.status !== 'disabled'); },
  'rs.automation-edit': (b) => { const j = b?.text == null ? null : jsonOf(b.text); return !j || Array.isArray(j) || (Object.hasOwn(j, 'status') && j.status !== 'disabled') || Object.hasOwn(j, 'steps') || Object.hasOwn(j, 'connections'); },
};
// Shopify: the Admin API is GraphQL over POST to one path, and the server tells deletes, refunds, cancellations, gift cards,
// theme and webhook changes apart by the mutation's name. The guard does not carry that table: every mutation, and any
// request it cannot read, is held. A plain query passes.
const SHOPIFY_MUTATION = (b) => b?.text == null || /\bmutation\b/i.test(b.text);
for (const id of ['sh.unreadable', 'sh.bulk', 'sh.delete', 'sh.money', 'sh.giftcard', 'sh.cancel', 'sh.customer-data', 'sh.access', 'sh.theme', 'sh.webhook']) BODY_TESTS[id] = SHOPIFY_MUTATION;
const safeDecode = (s) => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; } };
function sqlBodyHold(b) {
  const f = bodyFields(b);
  if (!f) return true;
  const list = [];
  for (const k of ['sql', 'query']) if (f.has(k)) list.push(f.get(k));
  if (f.has('batch') || !list.length) return true;
  return list.some((s) => typeof s !== 'string' || !sqlReadOnly(s));
}
/** the first rule of this provider the request trips, or null */
function apiHold(entry, method, rawPath, body, search) {
  const lp = lc(rawPath.startsWith(entry.base || '\u0000') ? rawPath.slice(entry.base.length) || '/' : rawPath);
  const paths = [lp, lp.replace(/(\/[^/]+)\.[a-z0-9]{1,8}$/, '$1')];
  const methods = method === 'HEAD' ? ['HEAD', 'GET'] : [method];
  for (const r of entry.rules) {
    if (r.m !== '*' && !r.m.split(',').some((x) => methods.includes(x))) continue;
    let ok = false;
    for (const p of paths) { try { if (globMatch(r.p, p)) { ok = true; break; } } catch { /* a bad glob in a downloaded map is skipped */ } }
    if (!ok) continue;
    const t = BODY_TESTS[r.id];
    if (t && !t(body, search)) continue;
    return r;
  }
  return null;
}
function parseUrl(u) {
  const s = String(u).trim().replace(/\\/g, '/');
  const m = /^([a-z][a-z0-9+.-]*):\/\/([\s\S]*)$/i.exec(s);
  const rest = m ? m[2] : s;
  const cut = rest.search(/[/?#]/);
  let hostpart = cut < 0 ? rest : rest.slice(0, cut);
  let path = cut < 0 ? '' : rest.slice(cut);
  const h = path.indexOf('#'); if (h >= 0) path = path.slice(0, h);
  const q = path.indexOf('?'); const search = q >= 0 ? path.slice(q) : ''; if (q >= 0) path = path.slice(0, q);
  hostpart = hostpart.replace(/^.*@/, '');
  const host = lc(hostpart.replace(/:\d*$/, '').replace(/\.+$/, ''));
  let dp = path; try { dp = decodeURIComponent(path.replace(/%2f/gi, '%252f')); } catch { /* keep the raw path */ }
  return { host, path: normPath('/' + dp.replace(/^\/+/, '').replace(/\u0000/g, '')), search, hasSent: s.includes(SENT) };
}
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const OVERRIDE_HEADER = /^(x-http-method-override|x-method-override|x-http-method)\s*:/i;
/** hold when this request goes to a host on the map and trips one of its rules */
const SHOPIFY_WHY = 'A Shopify GraphQL mutation (the map holds deletes, refunds, cancellations, gift cards, theme and webhook changes and more; the guard holds every mutation), or a request it cannot read.';
function apiRequestHold(cx, req) {
  const hm = hostMap(cx.st.o.apiMap);
  const u = parseUrl(req.url);
  let host = u.host;
  if (host.includes(SENT)) { // the host is built from a value: use a known host that appears literally
    const url = req.url.toLowerCase();
    const known = knownHosts(hm).find((h) => url.includes(h));
    if (!known) return null;
    host = known.startsWith('.') ? 'x' + known : known; // a wildcard host such as *.myshopify.com: any one label
  }
  const path = u.path.split('/').map((x) => (x.includes(SENT) ? 'x' : x)).join('/') || '/';
  const entry = entryFor(hm, host);
  if (!entry) return null;
  const override = req.headers.some((h) => OVERRIDE_HEADER.test(h)) || /(^|[?&])_method=/i.test(u.search) || (req.body?.text != null && /(^|[&{,"\s])_method\b/.test(req.body.text));
  if (override) return { id: 'sh.curl-api', why: `The request asks ${host} to treat it as a different method, which the map cannot read.` };
  const r = apiHold(entry, req.method, path, req.body, u.search);
  if (!r) return null;
  const shopify = BODY_TESTS[r.id] === SHOPIFY_MUTATION && req.method === 'POST';
  return { id: 'sh.curl-api', why: `${req.method} ${host} (${r.id}): ${shopify ? SHOPIFY_WHY : r.why}` };
}

// ---- reading curl, wget and httpie command lines
const CURL_VAL = '-X --request -H --header -d --data --data-raw --data-binary --data-ascii --data-urlencode -F --form --form-string --json -u --user -o --output -A --user-agent -e --referer -b --cookie -c --cookie-jar -T --upload-file -x --proxy --url -m --max-time --connect-timeout --retry --retry-delay --retry-max-time --resolve --cacert --cert --key --interface --limit-rate -w --write-out --oauth2-bearer --aws-sigv4 -K --config --proxy-user -r --range -z --time-cond --max-redirs --expect100-timeout --dns-servers';
function dataText(values) {
  if (!values.length) return null;
  if (values.some((v) => v.s.startsWith('@') || !v.lit)) return { text: null };
  return { text: values.map((v) => v.s).join('&') };
}
function curlRequests(cx) {
  const args = cx.args, A = argParse(args, { val: CURL_VAL });
  const wValues = (names) => { const out = []; for (let i = 0; i < args.length; i++) { const s = args[i].s; for (const n of names) { if (s === n && args[i + 1]) { out.push(args[i + 1]); i++; break; } if (s.startsWith(n + '=') && n.startsWith('--')) { out.push({ ...args[i], s: s.slice(n.length + 1) }); break; } if (!n.startsWith('--') && s[0] === '-' && s[1] !== '-' && s.length > 2 && s.includes(n[1]) ) { /* bundled short flag, value handled by argParse */ } } } return out; };
  let method = null;
  const x = A.get('-X') ?? A.get('--request');
  if (typeof x === 'string') method = x.toUpperCase();
  const dataFlags = ['-d', '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode', '--json', '-F', '--form', '--form-string'];
  const hasData = dataFlags.some((f) => A.has(f));
  const get = A.has('-G', '--get');
  if (!method) method = A.has('-I', '--head') ? 'HEAD' : A.has('-T', '--upload-file') ? 'PUT' : hasData && !get ? 'POST' : 'GET';
  const values = collect(args, ['-d', '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode', '--json']).map((s) => ({ s, lit: !s.includes(SENT) }));
  const forms = collect(args, ['-F', '--form', '--form-string']);
  let body = dataText(values);
  if (forms.length) body = { text: null }; // multipart: not read
  const headers = collect(args, ['-H', '--header']);
  const urls = [...A.posW.map((w) => w.s), ...collect(args, ['--url'])];
  return urls.map((url) => ({ method, url, headers, body: get && body ? null : body, getData: get && body ? body.text : null }));
}
function wgetRequests(cx) {
  const A = argParse(cx.args, { val: '-O --output-document -o --output-file -P --directory-prefix --header --method --post-data --post-file --body-data --body-file -U --user-agent -e --execute -t --tries -T --timeout --user --password -i --input-file --referer --load-cookies --save-cookies --certificate --private-key --ca-certificate -w --wait' });
  const m = A.get('--method');
  const hasBody = A.has('--post-data', '--post-file', '--body-data', '--body-file');
  const method = (typeof m === 'string' ? m : hasBody ? 'POST' : 'GET').toUpperCase();
  const data = A.get('--post-data') ?? A.get('--body-data');
  const body = hasBody ? { text: typeof data === 'string' && !data.startsWith('@') ? data : null } : null;
  return A.pos.map((url) => ({ method, url, headers: collect(cx.args, ['--header']), body }));
}
function httpieRequests(cx) {
  const A = argParse(cx.args, { val: '-a --auth -A --auth-type --proxy --timeout --verify --cert --cert-key -o --output --session --session-read-only --max-redirects --pretty --style -s --ignore-stdin' });
  const pos = [...A.pos];
  let method = null;
  if (pos[0] && METHODS.has(pos[0].toUpperCase()) && pos[0] === pos[0].toUpperCase()) method = pos.shift().toUpperCase();
  const url = pos.shift();
  if (!url) return [];
  const items = pos;
  const headers = items.filter((i) => /^[A-Za-z][\w-]*:(?!=)/.test(i) && !i.includes('=')).map((i) => i);
  const data = items.filter((i) => /^[^=:@\s]+(:=|=)(?!=)/.test(i));
  if (!method) method = data.length || A.has('--form', '-f', '--json', '-j') ? 'POST' : 'GET';
  const obj = {};
  for (const d of data) { const m = /^([^=:]+)(:=|=)([\s\S]*)$/.exec(d); if (m) obj[m[1]] = m[3]; }
  return [{ method, url: /^[a-z]+:\/\//i.test(url) || cx.prog !== 'https' && cx.prog !== 'xhs' ? url : 'https://' + url, headers, body: data.length ? { text: JSON.stringify(obj) } : null }];
}

// ---------------------------------------------------------------- the rules
const R = [];
const rule = (id, what, progs, test) => R.push({ id, what, progs: progs.split(' '), test });
const seqIn = (pos, words, window = 4) => { for (let s = 0; s + words.length <= Math.min(window, pos.length); s++) if (words.every((w, k) => pos[s + k] === w)) return true; return false; };
const anyIn = (pos, words, window = 4) => pos.slice(0, window).some((p) => words.includes(p));
const first = (pos, ...words) => words.includes(pos[0]);

rule('sh.terraform-destroy', 'terraform or tofu: destroy, apply -destroy, workspace delete (also terragrunt)', 'terraform tofu terragrunt', (cx) => {
  const a = argParse(cx.args, { go: true });
  const lead = cx.prog === 'terragrunt' ? a.pos.slice(0, 3) : a.pos.slice(0, 1);
  if (lead.includes('destroy')) return 'Destroys every resource this configuration manages.';
  if (lead.includes('apply') && a.has('-destroy', '--destroy')) return 'apply -destroy destroys every resource this configuration manages.';
  if (seqIn(a.pos, ['workspace', 'delete'], 2)) return 'Deleting a workspace forgets the state of everything in it.';
  return null;
});
rule('sh.pulumi-destroy', 'pulumi: destroy, stack rm, state delete', 'pulumi', (cx) => {
  const a = argParse(cx.args, { val: '-C --cwd -s --stack --color --logflow --tracing' });
  if (a.pos[0] === 'destroy') return 'Destroys every resource in the stack.';
  if (seqIn(a.pos, ['stack', 'rm'], 2) || seqIn(a.pos, ['stack', 'remove'], 2)) return 'Removing a stack forgets what it manages.';
  if (seqIn(a.pos, ['state', 'delete'], 2)) return 'Deleting state forgets a resource Pulumi manages.';
  return null;
});
rule('sh.iac-destroy', 'cdk, cdktf, sst, serverless, sam, amplify: destroy, remove, delete', 'cdk cdktf sst serverless sls sam amplify', (cx) => {
  const a = argParse(cx.args, { val: '--profile --region -c --context --stage -s --app -o --output' });
  if (a.pos[0] === 'destroy' || (['sst', 'serverless', 'sls'].includes(cx.prog) && a.pos[0] === 'remove') || (['sam', 'amplify'].includes(cx.prog) && a.pos[0] === 'delete')) return 'Tears down the deployed stack and its resources.';
  return null;
});
rule('sh.railway', 'railway: delete, down, volume delete, environment delete', 'railway', (cx) => {
  const a = argParse(cx.args, { val: '-s --service -e --environment -p --project' });
  if (a.pos[0] === 'run') return null;
  if (first(a.pos, 'delete', 'down')) return 'Deletes the project or removes the latest deployment (PocketOS lost production to one volume delete).';
  if (['volume', 'environment', 'service', 'project', 'domain', 'variables', 'variable'].includes(a.pos[0]) && ['delete', 'remove', 'rm'].includes(a.pos[1])) return 'Deletes data or a whole environment on Railway (PocketOS lost production to one volume delete).';
  return null;
});
rule('sh.fly', 'fly: apps destroy, volumes destroy, machine destroy', 'fly flyctl', (cx) => {
  const a = argParse(cx.args, { val: '-a --app -c --config -t --token --region -r' });
  const v = ['destroy', 'delete', 'remove', 'rm'];
  if (a.pos[0] === 'destroy') return 'Destroys the app, its machines and its volumes.';
  if (['apps', 'app'].includes(a.pos[0]) && v.includes(a.pos[1])) return 'Destroys the app, its machines, volumes and snapshots.';
  if (['volumes', 'volume', 'vol'].includes(a.pos[0]) && v.includes(a.pos[1])) return 'Destroying a volume deletes its data.';
  if (['machine', 'machines', 'm'].includes(a.pos[0]) && v.includes(a.pos[1])) return 'Destroys a machine.';
  if (['postgres', 'pg', 'mpg'].includes(a.pos[0]) && v.includes(a.pos[1])) return 'Destroys a database cluster.';
  if (['certs', 'cert'].includes(a.pos[0]) && v.includes(a.pos[1])) return 'Removes a certificate.';
  return null;
});
rule('sh.vercel', 'vercel: remove, rm, project rm, env rm, domains rm, alias rm', 'vercel', (cx) => {
  const a = argParse(cx.args, { val: '--scope -S --token -t --cwd -A --local-config -e --env -b --build-env -m --meta -N --name --target --regions' });
  const v = ['rm', 'remove'];
  if (v.includes(a.pos[0])) return 'Removes a deployment for good.';
  if (['project', 'projects', 'env', 'domains', 'domain', 'alias', 'aliases', 'teams', 'team', 'certs', 'secrets', 'integration'].includes(a.pos[0]) && v.includes(a.pos[1])) return 'Removes a project, variable, domain, alias or team for good.';
  return null;
});
rule('sh.wrangler', 'wrangler: delete, d1 delete, r2 bucket delete, kv namespace delete, d1 execute --remote with SQL that is not a plain read', 'wrangler', (cx) => {
  const a = argParse(cx.args, { val: '--command -c --file -f --config --env -e --name -n --database --binding --persist-to --preview-id' });
  const p = a.pos;
  if (p.slice(0, 4).includes('delete')) return 'Deletes a Worker, database, bucket, namespace, queue or secret.';
  if (seqIn(p, ['d1', 'time-travel', 'restore'], 3)) return 'Restoring a D1 database to an earlier point overwrites everything written since.';
  if (seqIn(p, ['d1', 'migrations', 'apply'], 3) && (a.has('--remote') || a.has('--preview'))) return 'Applies migration files to a production D1 database.';
  if (seqIn(p, ['d1', 'execute'], 2)) {
    const remote = a.has('--remote') || a.has('--preview');
    const cmd = a.get('--command') ?? a.get('-c');
    const file = a.get('--file') ?? a.get('-f');
    if (remote) {
      if (file) return 'Runs an SQL file on a production D1 database; the guard cannot read it.';
      if (typeof cmd !== 'string' || !sqlReadOnly(cmd)) return 'SQL that is not a plain read, run on a production D1 database.';
    } else if (typeof cmd === 'string') {
      const r = sqlGuard(cmd);
      if (r) return `SQL on the local D1 database that cannot be taken back: ${r}.`;
    }
  }
  return null;
});
rule('sh.supabase', 'supabase: db reset, projects delete, db push, migration repair', 'supabase', (cx) => {
  const a = argParse(cx.args, { val: '--project-ref --workdir --db-url -p --password --schema -s --experimental --network-id' });
  const p = a.pos;
  if (seqIn(p, ['db', 'reset'], 2)) return 'db reset drops and recreates the database (it wiped a day of data in anthropics/claude-code#47694), local or linked.';
  if (seqIn(p, ['projects', 'delete'], 2)) return 'Deletes the Supabase project.';
  if (seqIn(p, ['db', 'push'], 2)) return 'Applies local migrations to the linked database.';
  if (seqIn(p, ['migration', 'repair'], 2)) return 'Rewrites the migration history of the linked database.';
  if (seqIn(p, ['migration', 'up'], 2) && (a.has('--linked') || a.has('--db-url'))) return 'Applies migrations to a remote database.';
  if (first(p, 'stop') && a.has('--no-backup')) return 'stop --no-backup deletes the local database volumes.';
  if (['functions', 'branches', 'secrets', 'storage', 'sso', 'domains', 'vanity-subdomains', 'network-bans', 'orgs'].includes(p[0]) && ['delete', 'unset', 'rm', 'remove', 'disable'].includes(p[1])) return 'Deletes something on the Supabase project.';
  return null;
});
rule('sh.neon', 'neonctl: projects delete, branches delete, restore or reset', 'neonctl neon', (cx) => {
  const a = argParse(cx.args, { val: '--project-id --branch --api-key --org-id --context-file --output -o' });
  const g = ['projects', 'project', 'branches', 'branch', 'databases', 'database', 'roles', 'role'];
  if (g.includes(a.pos[0]) && ['delete', 'restore', 'reset', 'rm'].includes(a.pos[1])) return 'Deletes, resets or restores over a Neon project, branch, database or role.';
  return null;
});
rule('sh.prisma', 'prisma: migrate reset, db push --accept-data-loss or --force-reset, db execute, --shadow-database-url', 'prisma', (cx) => {
  const a = argParse(cx.args, { val: '--schema --url --file --name --to --from --shadow-database-url' });
  if ([...a.flags.keys()].some((k) => k.startsWith('--shadow-database-url')) || cx.args.some((x) => x.s.startsWith('--shadow-database-url'))) return 'A shadow database URL makes Prisma drop and recreate that database (all 22 tables of a production database were dropped in July 2026).';
  if (seqIn(a.pos, ['migrate', 'reset'], 2)) return 'migrate reset drops the database and every table in it.';
  if (seqIn(a.pos, ['db', 'push'], 2) && (a.has('--accept-data-loss') || a.has('--force-reset'))) return 'db push with --accept-data-loss or --force-reset drops data to match the schema.';
  if (seqIn(a.pos, ['db', 'execute'], 2)) return 'db execute runs SQL the guard cannot read.';
  return null;
});
rule('sh.drizzle', 'drizzle-kit: push, drop', 'drizzle-kit drizzle', (cx) => {
  const a = argParse(cx.args, { val: '--config --dialect --schema --out --url' });
  if (/^(push|drop)(:[a-z]+)?$/.test(a.pos[0] ?? '')) return 'push rewrites the database to match the schema (and drops what is not in it); drop deletes migrations.';
  return null;
});

// ---- SQL clients
const LOCAL_HOST = /^(localhost|127(\.\d+){3}|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$/;
const hostIsRemote = (h) => {
  const x = lc(String(h || '')).trim();
  if (!x || x.includes(SENT) || x.startsWith('/') || LOCAL_HOST.test(x)) return false;
  if (!x.includes('.')) return false; // db, postgres, mysql: a service name on this machine's network
  return !/\.(local|localhost|test|internal|lan|docker|home|localdomain)$/.test(x);
};
const hostOf = (s) => { const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)/i.exec(s) || /(?:^|\s)host=([^\s]+)/.exec(s); return m ? m[1] : null; };
const PSQL_READ_META = /^\\(d[a-zA-Z]{0,3}[+S]*|l\+?|conninfo|x|timing|pset|echo|q|\?|encoding|h|password)(\s|$)/;
function stdinSql(stdin) {
  if (!stdin) return null;
  if (stdin.kind === 'heredoc' || stdin.kind === 'here') return stdin.text == null ? { unknown: 'SQL read from a place the guard cannot see' } : { text: stdin.text };
  if (stdin.kind === 'pipe') return stdin.text != null ? { text: stdin.text } : { unknown: 'SQL piped in from a command the guard cannot read' };
  if (stdin.kind === 'file') return { unknown: 'SQL read from a file the guard cannot read' };
  return null;
}
function sqlClient(cx, conf) {
  const a = argParse(cx.args, { val: conf.val });
  const sqls = collect(cx.args, conf.sql.split(' ').filter(Boolean));
  const files = conf.file ? collect(cx.args, conf.file.split(' ').filter(Boolean)) : [];
  let host = a.get(conf.hostFlag ?? '-h') ?? a.get(conf.hostLong ?? '--host');
  for (const [k, v] of cx.assigns || []) if (/^(PGHOST|MYSQL_HOST)$/.test(k)) host = host ?? v;
  const conn = a.pos.find((p) => /^[a-z][a-z0-9+.-]*:\/\//i.test(p) || /\bhost=/.test(p));
  if (!host && conn) host = hostOf(conn);
  const remote = hostIsRemote(typeof host === 'string' ? host : '');
  const why = (r) => `Runs SQL that cannot be taken back${remote ? ' (database host ' + String(host).slice(0, 60) + ')' : ''}: ${r}.`;
  for (const f of files) return `Runs the SQL file ${f.slice(0, 60)}, which the guard cannot read.`;
  const todo = [...sqls];
  if (conf.positionalSql) todo.push(...a.pos.slice(conf.positionalSql));
  for (let sql of todo) {
    if (conf.meta) { // psql backslash commands: read-only describe commands pass, every other one is held
      const lines = sql.split('\n').filter((l) => l.trim());
      if (lines.length && lines.every((l) => PSQL_READ_META.test(l.trim()))) continue;
      if (/^\s*\\/.test(sql)) return why('a psql meta-command the guard does not know');
    }
    if (conf.dot && /^\s*\./.test(sql)) { if (/^\s*\.(tables|schema|dump|headers|mode|databases|indexes|indices|help|quit|exit|timer|show|fullschema|lint|dbinfo|width|separator|nullvalue)\b/.test(sql)) continue; return why('a sqlite shell command the guard does not know'); }
    if (conf.source && /^\s*(source\b|\\\.)/i.test(sql)) return why('it runs a file');
    const r = sqlGuard(sql, { remote });
    if (r) return why(r);
  }
  const s = stdinSql(cx.stdin);
  if (s?.unknown) return why(s.unknown);
  if (s?.text != null) { const r = sqlGuard(s.text.replace(conf.meta ? /^\s*\\[a-zA-Z+]+.*$/gm : /$^/g, ''), { remote }); if (r) return why(r); }
  return null;
}
const SQLC = {
  psql: { sql: '-c --command', file: '-f --file', val: '-c --command -f --file -d --dbname -h --host -p --port -U --username -o --output -L --log-file -v --set --variable -P --pset -F --field-separator -R --record-separator -T --table-attr', meta: true },
  pgcli: { sql: '-c --command', file: '', val: '-c --command -d --dbname -h --host -p --port -U --username -u --user --prompt --row-limit --less-chatty --pgclirc', meta: true },
  mysql: { sql: '-e --execute', file: '', val: '-e --execute -h --host -u --user -P --port -D --database -S --socket --default-character-set --ssl-mode --protocol', source: true },
  sqlite3: { sql: '-cmd', file: '', val: '-cmd -init -separator -newline -nullvalue -vfs -A', positionalSql: 1, dot: true },
  turso: { sql: '', file: '', val: '', positionalSql: 3 },
  usql: { sql: '-c --command', file: '-f --file', val: '-c --command -f --file -h --host -p --port -U --username -d --dbname -v --set', positionalSql: 99 },
  sqlcmd: { sql: '-Q -q', file: '-i', val: '-Q -q -i -S -U -P -d -H -s -w', hostFlag: '-S' },
  cockroach: { sql: '-e --execute', file: '', val: '-e --execute -f --file --url --host -d --database -u --user --certs-dir' },
  'clickhouse-client': { sql: '-q --query', file: '', val: '-q --query -h --host -u --user --password -d --database --port' },
};
SQLC.mariadb = SQLC.mycli = SQLC.mysql; SQLC.litecli = SQLC.sqlite3;
rule('sh.sql-cli', 'psql, mysql, mariadb, sqlite3, turso and other SQL clients: DROP, TRUNCATE, DELETE or UPDATE without WHERE, ALTER ... DROP, SQL from a file; any write to a database on another machine', 'psql pgcli mysql mariadb mycli sqlite3 litecli turso usql sqlcmd cockroach clickhouse-client', (cx) => {
  if (cx.prog === 'turso') {
    const a = argParse(cx.args, { val: '--group --location -t --token' });
    if (seqIn(a.pos, ['db', 'destroy'], 2)) return 'Destroys the Turso database.';
    if (seqIn(a.pos, ['db', 'shell'], 2)) return sqlClient({ ...cx, args: cx.args }, SQLC.turso);
    return null;
  }
  if (cx.prog === 'cockroach' && argParse(cx.args).pos[0] !== 'sql') return null;
  return sqlClient(cx, SQLC[cx.prog]);
});

rule('sh.db-reset', 'dropdb, dropuser, rails db:drop and db:reset, manage.py flush, artisan migrate:fresh, redis-cli FLUSHALL, pg_restore --clean and other tools that empty or drop a database', 'dropdb dropuser mysqladmin pg_restore mongorestore redis-cli valkey-cli mongosh mongo rails rake python python3 py django-admin php artisan alembic knex sequelize sequelize-cli typeorm mix dbmate flyway liquibase goose migrate atlas sqitch', (cx) => {
  const a = argParse(cx.args, { val: '-U --username -h --host -p --port -n --db -e --eval --eval-script --uri --host --port -c -u --user -a --auth' });
  const p = a.pos, pr = cx.prog;
  switch (pr) {
    case 'dropdb': case 'dropuser': return 'Drops a whole database or role.';
    case 'mysqladmin': return p.includes('drop') ? 'Drops a whole database.' : null;
    case 'pg_restore': return a.has('-c', '--clean') ? 'pg_restore --clean drops every object before restoring.' : null;
    case 'mongorestore': return a.has('--drop') ? 'mongorestore --drop replaces every collection it restores.' : null;
    case 'redis-cli': case 'valkey-cli': return p.some((x) => /^(flushall|flushdb)$/i.test(x)) ? 'FLUSHALL and FLUSHDB delete every key.' : null;
    case 'mongosh': case 'mongo': { const e = a.get('--eval') ?? a.get('-e'); return typeof e === 'string' && /dropDatabase|\.drop\(|dropCollection|deleteMany\(\s*\{\s*\}\s*\)|\.remove\(\s*\{\s*\}\s*\)/.test(e) ? 'Drops a database or empties a collection.' : null; }
    case 'rails': case 'rake': return p.some((x) => /^db:(drop|reset|schema:load|structure:load|migrate:reset|purge|setup|seed:replant|drop:all|truncate_all)\b/.test(x)) ? 'This database task drops or reloads every table.' : null;
    case 'python': case 'python3': case 'py': { const f = cx.args[0]?.s ?? ''; if (!/manage\.py$/.test(f)) return null; const sub = cx.args[1]?.s; return ['flush', 'reset_db', 'reset_schema', 'sqlclear'].includes(sub) || (sub === 'migrate' && cx.args.some((x) => x.s === 'zero')) ? 'This Django command empties the database or unapplies every migration.' : null; }
    case 'django-admin': return ['flush', 'reset_db', 'reset_schema'].includes(p[0]) ? 'This Django command empties the database.' : null;
    case 'php': case 'artisan': { const t = pr === 'php' ? cx.args.slice(1) : cx.args; if (pr === 'php' && !/artisan$/.test(cx.args[0]?.s ?? '')) return null; return t.some((x) => /^(migrate:fresh|migrate:reset|db:wipe)$/.test(x.s)) ? 'This Laravel command drops every table.' : null; }
    case 'alembic': return seqIn(p, ['downgrade', 'base'], 2) ? 'Downgrading to base unapplies every migration.' : null;
    case 'knex': return p.includes('migrate:rollback') && a.has('--all') ? 'Rolls back every migration.' : null;
    case 'sequelize': case 'sequelize-cli': return p.some((x) => /^db:(drop|migrate:undo:all)$/.test(x)) ? 'Drops the database or undoes every migration.' : null;
    case 'typeorm': return p.includes('schema:drop') ? 'Drops every table in the schema.' : null;
    case 'mix': return p.some((x) => /^ecto\.(drop|reset)$/.test(x)) ? 'Drops the database.' : null;
    case 'dbmate': return p[0] === 'drop' ? 'Drops the database.' : null;
    case 'flyway': return p.includes('clean') ? 'flyway clean drops every object in the schemas.' : null;
    case 'liquibase': return p.some((x) => /^(drop-all|dropAll)$/.test(x)) ? 'Drops everything in the database.' : null;
    case 'goose': return p.includes('reset') ? 'Rolls back every migration.' : null;
    case 'migrate': return p.includes('drop') ? 'Drops everything in the database.' : null;
    case 'atlas': return seqIn(p, ['schema', 'clean'], 2) ? 'Drops every object in the database.' : null;
    case 'sqitch': return p[0] === 'revert' ? 'Reverts deployed changes.' : null;
    default: return null;
  }
});

// ---- git
const GIT_VAL = OPT_SET('-C -c --git-dir --work-tree --namespace --exec-path --super-prefix --config-env');
function gitParts(cx) { const i = skipOpts(cx.args, GIT_VAL); return { sub: cx.args[i]?.s, rest: cx.args.slice(i + 1) }; }
rule('sh.git-force', 'git push with --force, -f, --force-with-lease, a +refspec, --mirror, --delete or :branch', 'git', (cx) => {
  const { sub, rest } = gitParts(cx);
  if (sub !== 'push') return null;
  const a = argParse(rest, { val: '--repo --receive-pack --exec -o --push-option --signed' });
  // git accepts any unambiguous prefix of a long option (--del, --force-w), so a flag counts if it is a long enough prefix
  const abbr = (full, min) => [...a.flags.keys()].some((k) => { const n = k.split('=')[0]; return n.length >= min && n.startsWith('--') && full.startsWith(n); });
  if (a.has('-n', '--dry-run') || abbr('--dry-run', 5)) return null;
  if (a.has('-f', '--force') || abbr('--force', 6) || abbr('--force-with-lease', 9)) return 'A force push rewrites the remote history and can drop other people\'s commits.';
  if (a.has('-d', '--delete') || abbr('--delete', 5)) return 'Deleting a remote branch or tag removes it for everyone who pulls from there.';
  if (abbr('--mirror', 4)) return 'A mirror push makes the remote an exact copy of this repository and deletes every other ref on it.';
  if (abbr('--prune', 5)) return 'push --prune deletes remote branches that do not exist here.';
  if (a.pos.slice(1).some((x) => /^[+:]./.test(x)) || /^\+./.test(a.pos[0] ?? '')) return 'A +refspec forces the update and a :branch refspec deletes the remote branch.';
  return null;
});
rule('sh.git-history', 'git filter-branch, filter-repo, reflog expire, gc --prune=now, prune, update-ref -d', 'git git-filter-repo', (cx) => {
  if (cx.prog === 'git-filter-repo') return 'Rewrites the history of every commit.';
  const { sub, rest } = gitParts(cx);
  const a = argParse(rest, { val: '--expire --expire-unreachable' });
  if (sub === 'filter-branch' || sub === 'filter-repo') return 'Rewrites the history of every commit it touches.';
  if (sub === 'reflog' && a.pos[0] === 'expire') return 'Expiring the reflog removes the only way back to dropped commits.';
  if (sub === 'gc' && /^(now|all)$/.test(String(a.get('--prune') ?? ''))) return 'gc --prune=now deletes unreachable commits for good.';
  if (sub === 'prune' && !a.has('-n', '--dry-run')) return 'prune deletes unreachable objects for good.';
  if (sub === 'update-ref' && a.has('-d')) return 'update-ref -d deletes a ref, which can orphan its commits.';
  return null;
});
rule('sh.git-discard', 'git reset --hard, clean -f, checkout or restore of the whole tree, checkout --force', 'git', (cx) => {
  const { sub, rest } = gitParts(cx);
  const a = argParse(rest, { val: '-b -B --orphan --conflict --pathspec-from-file --source -s' });
  if (sub === 'reset' && a.has('--hard')) return 'reset --hard throws away every uncommitted change.';
  if (sub === 'clean' && a.has('-f', '--force') && !a.has('-n', '--dry-run')) return 'clean -f deletes untracked files for good.';
  if ((sub === 'checkout' || sub === 'switch') && a.has('-f', '--force', '--discard-changes')) return `${sub} --force throws away uncommitted changes.`;
  if (sub === 'checkout' && a.pos.some((x) => x === '.' || x === ':/')) return 'Checking out the whole tree throws away every uncommitted change.';
  if (sub === 'restore' && a.pos.some((x) => x === '.' || x === ':/') && (!a.has('--staged', '-S') || a.has('--worktree', '-W'))) return 'Restoring the whole tree throws away every uncommitted change.';
  return null;
});

// ---- gh
const GH_FIELDS = ['-f', '--raw-field', '-F', '--field'];
rule('sh.gh', 'gh: repo delete, archive, rename, edit --visibility, release delete, secret set or delete, any delete, api -X DELETE, PATCH or PUT on the GitHub map', 'gh', (cx) => {
  const a = argParse(cx.args, { val: '-R --repo --hostname -X --method -H --header -f --raw-field -F --field --input -q --jq -t --template --cache -p --preview -B --branch -b --body -t --title' });
  const [g, v] = a.pos;
  if (g === 'api') {
    const method0 = a.get('-X') ?? a.get('--method');
    const fields = collect(cx.args, GH_FIELDS);
    const hasInput = a.has('--input');
    const method = typeof method0 === 'string' ? method0.toUpperCase() : (fields.length || hasInput ? 'POST' : 'GET');
    const ep = a.pos[1];
    if (!ep) return null;
    const unreadable = hasInput || fields.some((f) => /=@/.test(f)) || a.posW.slice(1, 2).some((w) => !w.lit) || fields.some((f) => f.includes(SENT));
    const text = unreadable ? null : (fields.length ? JSON.stringify(Object.fromEntries(fields.map((f) => { const e = f.indexOf('='); return e < 0 ? [f, ''] : [f.slice(0, e), f.slice(e + 1)]; }))) : '{}');
    const path = ep.startsWith('/') ? ep : '/' + ep;
    const entry = entryFor(hostMap(cx.st.o.apiMap), 'api.github.com') || BUNDLED_API_MAP.providers.find((p) => p.id === 'github');
    const u = parseUrl('https://api.github.com' + path);
    if (/^\/graphql/i.test(u.path)) {
      const q = fields.filter((f) => /^query=/.test(f)).join('\n');
      if (!q || /=@/.test(q) || unreadable || /\bmutation\b/i.test(q)) return 'A GitHub GraphQL mutation (or a query the guard cannot read) can delete or transfer a repository.';
      return null;
    }
    const r = apiHold(entry, method, u.path, text == null ? { text: null } : { text }, u.search);
    return r ? `${r.why} (${r.id}, ${method} ${u.path})` : null;
  }
  if (g === 'repo' && ['delete', 'archive', 'rename', 'transfer'].includes(v)) return 'Deleting, archiving, renaming or transferring a repository affects everyone who uses it.';
  if (g === 'repo' && v === 'edit' && (a.has('--visibility') || a.has('--accept-visibility-change-consequences'))) return 'Changing visibility can publish private code.';
  if ((g === 'secret' || g === 'variable') && ['set', 'delete', 'remove'].includes(v)) return 'Overwriting or deleting a CI secret changes what production deploys with.';
  if (v === 'delete' && g !== 'pr') return `gh ${g} delete removes it for good.`;
  return null;
});

// ---- kubernetes, helm
rule('sh.k8s', 'kubectl delete, drain, replace --force, apply --prune; helm uninstall or delete; argocd app delete', 'kubectl oc helm argocd flux', (cx) => {
  const a = argParse(cx.args, { val: '-n --namespace --context --cluster --user --kubeconfig -s --server --token --as --as-group --certificate-authority --client-certificate --client-key --request-timeout --cache-dir --tls-server-name -f --filename -l --selector -o --output --timeout --grace-period' });
  const dry = a.get('--dry-run');
  const isDry = a.has('--dry-run') && dry !== 'none' && dry !== 'false';
  if (cx.prog === 'helm') return ['uninstall', 'delete', 'un'].includes(a.pos[0]) && !isDry ? 'Uninstalling a release deletes everything it created.' : null;
  if (cx.prog === 'argocd') return a.pos[0] === 'app' && ['delete', 'rm'].includes(a.pos[1]) ? 'Deleting an Argo CD application can delete the workloads it manages.' : null;
  if (cx.prog === 'flux') return ['delete', 'uninstall'].includes(a.pos[0]) ? 'Deleting a Flux resource can delete the workloads it manages.' : null;
  if (isDry) return null;
  if (a.pos[0] === 'delete') return 'kubectl delete removes cluster resources (and the data in them).';
  if (a.pos[0] === 'drain') return 'drain evicts every pod from a node.';
  if (a.pos[0] === 'replace' && a.has('--force')) return 'replace --force deletes and recreates the resource.';
  if (a.pos[0] === 'apply' && (a.has('--prune') || a.has('--prune-allowlist'))) return 'apply --prune deletes resources that are not in the files.';
  return null;
});

// ---- docker
const COMPOSE_VAL = OPT_SET('-f --file -p --project-name --profile --env-file --project-directory --ansi --parallel');
rule('sh.docker', 'docker: volume rm or prune, system prune, container prune, rm -v, rm of every container, compose down -v', 'docker podman nerdctl docker-compose', (cx) => {
  let args = cx.args;
  if (cx.prog === 'docker-compose') args = [{ s: 'compose', lit: true }, ...args];
  const i = skipOpts(args, DOCKER_VAL);
  let sub = args[i]?.s, j = i + 1;
  if (sub === 'container' || sub === 'image' || sub === 'volume' || sub === 'network' || sub === 'system' || sub === 'builder') { const g = sub; sub = args[j]?.s; j++; return dockerSub(g, sub, args.slice(j)); }
  if (sub === 'compose') {
    const k = skipOpts(args.slice(j), COMPOSE_VAL) + j;
    const csub = args[k]?.s;
    const a = argParse(args.slice(k + 1), { val: '-t --timeout' });
    if (csub === 'down' && a.has('-v', '--volumes')) return 'down -v deletes the named volumes, which is where databases keep their data.';
    if (csub === 'rm' && a.has('-v', '--volumes')) return 'rm -v deletes the volumes of the containers.';
    return null;
  }
  return dockerSub(null, sub, args.slice(j));
});
function dockerSub(group, sub, rest) {
  const a = argParse(rest, {});
  const mass = rest.some((w) => !w.lit && /docker\s+(container\s+|image\s+)?(ps|ls|images)\b|\bls\s+-q|\bps\s+-a?q/.test(w.raw ?? ''));
  if (group === 'volume' && ['rm', 'remove', 'prune'].includes(sub)) return 'Deleting a volume deletes the data in it.';
  if (group === 'system' && sub === 'prune') return 'system prune removes stopped containers (and their data), networks and images' + (a.has('--volumes') ? ', and with --volumes every unused volume.' : '.');
  if (group === 'container' && sub === 'prune') return 'container prune removes every stopped container and the data in it.';
  if ((group === null || group === 'container' || group === 'image') && ['rm', 'rmi', 'remove'].includes(sub) && (mass || a.has('-v', '--volumes'))) return mass ? 'Removes every container or image at once.' : 'rm -v also deletes the volumes of the containers.';
  if (group === null && sub === 'volume') return null;
  return null;
}

// ---- cloud CLIs
const DEL_VERB = /^(delete|destroy|terminate|remove|purge|deregister|schedule-key-deletion|delete-[\w-]+|terminate-[\w-]+|remove-[\w-]+|deregister-[\w-]+|purge-[\w-]+)$/;
rule('sh.cloud', 'aws: delete-*, terminate-*, remove-*, deregister-*, s3 rm --recursive, s3 rb; gcloud, az, doctl, heroku, firebase and other cloud CLIs: delete, destroy', 'aws gcloud gsutil az doctl heroku hcloud linode-cli scw oci ibmcloud firebase netlify pscale atlas vault consul linode', (cx) => {
  const dry = cx.args.some((x) => /^--dry-?run$/.test(x.s));
  switch (cx.prog) {
    case 'aws': {
      const a = argParse(cx.args, { val: '--profile --region --endpoint-url --output --query --cli-input-json --cli-input-yaml --ca-bundle --cli-read-timeout --cli-connect-timeout --color --filters --instance-ids' });
      const [svc, op] = a.pos;
      if (dry) return null;
      if (svc === 's3') {
        if (op === 'rm' && (a.has('--recursive') || a.has('-r'))) return 'rm --recursive deletes every object under the path.';
        if (op === 'rb') return 'rb removes the bucket' + (a.has('--force') ? ' and everything in it.' : '.');
        if (op === 'sync' && a.has('--delete')) return 'sync --delete deletes everything at the destination that is not in the source.';
        return null;
      }
      return op && DEL_VERB.test(op) && !/^(remove-tags?|remove-from-)/.test(op) ? `aws ${svc} ${op} deletes or terminates something in your account.` : null;
    }
    case 'gcloud': {
      const a = argParse(cx.args, { val: '--project --account --configuration --billing-project --impersonate-service-account --format --filter --verbosity --zone --region --location' });
      if (a.pos.slice(0, 7).some((x) => x === 'delete' || x === 'destroy' || /^delete-/.test(x))) return 'gcloud delete removes the resource for good.';
      if (a.pos[0] === 'storage' && a.pos[1] === 'rm' && (a.has('-r', '-R', '--recursive') || a.pos.some((x) => /[*]/.test(x)))) return 'storage rm -r deletes every object under the path.';
      return null;
    }
    case 'gsutil': {
      const a = argParse(cx.args, { val: '-o -h -u' });
      if (a.pos[0] === 'rb') return 'rb removes the bucket.';
      if (a.pos[0] === 'rm' && (a.has('-r', '-R') || a.pos.some((x) => /[*]/.test(x)))) return 'rm -r deletes every object under the path.';
      return null;
    }
    case 'az': {
      const a = argParse(cx.args, { val: '--subscription --resource-group -g --name -n --output -o --query' });
      return a.pos.slice(0, 7).some((x) => x === 'delete' || x === 'purge' || /^delete-/.test(x)) ? 'az delete removes the resource for good.' : null;
    }
    case 'heroku': {
      const a = argParse(cx.args, { val: '-a --app -r --remote -t --team' });
      return /(:destroy|:delete|:reset|:purge|:remove)$/.test(a.pos[0] ?? '') || a.pos.slice(0, 3).some((x) => x === 'destroy') ? 'Destroys or resets an app, add-on or database.' : null;
    }
    case 'firebase': case 'netlify': {
      const a = argParse(cx.args, { val: '--project -P --token -c --config --site -s' });
      return /(:delete|:destroy|:remove|:disable)$/.test(a.pos[0] ?? '') || a.pos[0] === 'delete' ? `${cx.prog} ${a.pos[0]} removes data or a site for good.` : null;
    }
    case 'vault': case 'consul': {
      const a = argParse(cx.args, {});
      return a.pos.slice(0, 3).some((x) => x === 'delete' || x === 'destroy') ? `${cx.prog} delete removes secrets or keys for good.` : null;
    }
    default: {
      const a = argParse(cx.args, { val: '--profile --region --context -c --token -t -p --project --account' });
      return a.pos.slice(0, 5).some((x) => ['delete', 'destroy', 'terminate', 'remove'].includes(x)) ? `${cx.prog} delete removes the resource for good.` : null;
    }
  }
});

// ---- stripe
const STRIPE_MONEY = new Set(['refunds', 'payouts', 'transfers', 'topups', 'charges', 'credit_notes']);
rule('sh.stripe', 'stripe CLI: refunds create, payouts create, transfers create, subscriptions cancel, any delete, post or delete on the Stripe map', 'stripe', (cx) => {
  const a = argParse(cx.args, { val: '--api-key -d --data --expand -H --header --idempotency --stripe-account --stripe-version --device-name --project-name -c --config -l -i' });
  const [g, v] = a.pos;
  if (g === 'post' || g === 'delete' || g === 'get') {
    const method = g.toUpperCase();
    if (method === 'GET') return null;
    const path = a.pos[1] || '';
    const entry = entryFor(hostMap(cx.st.o.apiMap), 'api.stripe.com') || BUNDLED_API_MAP.providers.find((p) => p.id === 'stripe');
    const data = collect(cx.args, ['-d', '--data']);
    const r = apiHold(entry, method, parseUrl('https://api.stripe.com' + (path.startsWith('/') ? path : '/' + path)).path, { text: data.length ? data.join('&') : '' }, '');
    return r ? `${r.why} (${r.id})` : null;
  }
  if (v === 'delete') return 'Deletes it on your Stripe account.';
  if (STRIPE_MONEY.has(g) && ['create', 'update', 'void'].includes(v) && g !== 'charges') return 'Moves or issues money.';
  if (g === 'charges' && ['create', 'capture'].includes(v)) return 'Moves money.';
  if (['subscriptions', 'subscription'].includes(g) && v === 'cancel') return 'Cancels a paying customer.';
  if (g === 'payment_intents' && ['confirm', 'capture', 'cancel'].includes(v)) return 'Moves or cancels a payment.';
  if (g === 'invoices' && ['pay', 'void'].includes(v)) return 'Paying or voiding an invoice cannot be undone.';
  if (g === 'webhook_endpoints' && ['create', 'update'].includes(v)) return 'Changing webhooks can silently stop order fulfilment.';
  return null;
});

// ---- npm
rule('sh.npm', 'npm, pnpm, yarn: unpublish, deprecate, owner rm, dist-tag rm, access revoke, token revoke', 'npm pnpm yarn', (cx) => {
  const a = argParse(cx.args, { val: [...PM_VAL].join(' ') });
  let p = a.pos;
  if (cx.prog === 'yarn' && p[0] === 'npm') p = p.slice(1);
  if (p[0] === 'unpublish' || p[0] === 'deprecate') return 'A removed or deprecated package version breaks everyone who depends on it, and the name or version may not be reusable.';
  if ((p[0] === 'owner' || p[0] === 'dist-tag') && ['rm', 'remove'].includes(p[1])) return 'Removing an owner or a dist-tag changes who can publish or what users install.';
  if ((p[0] === 'access' && p[1] === 'revoke') || (p[0] === 'token' && p[1] === 'revoke')) return 'Revoking access or a token cuts people or automation off.';
  return null;
});

// ---- files, disks
const DEV_BLOCK = /^\/dev\/(sd[a-z]|hd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|mmcblk\d|disk\d|rdisk\d|dm-\d|md\d|loop\d|sr\d|mapper\/)/;
rule('sh.rm', 'rm -r on /, ~, the project root, .git, a variable that may be empty or a path outside the project; find -delete; shred; rsync --delete; chmod or chown -R on /; crontab -r', 'rm find shred rsync chmod chown chgrp crontab unlink', (cx) => {
  const st = cx.st;
  if (cx.prog === 'rm') {
    const a = argParse(cx.args, {});
    if (!(a.has('-r', '-R', '--recursive'))) return null;
    for (const w of a.posW) { const r = pathRisk(w, st); if (r) return `Recursively deletes ${r}.`; }
    if (a.has('--no-preserve-root')) return '--no-preserve-root lets rm delete the filesystem root.';
    return null;
  }
  if (cx.prog === 'shred') {
    const a = argParse(cx.args, { val: '-n --iterations -s --size --random-source' });
    for (const w of a.posW) { const r = pathRisk(w, st); if (r) return `shred overwrites ${r} so it cannot be recovered.`; }
    return null;
  }
  if (cx.prog === 'rsync') {
    const a = argParse(cx.args, { val: '-e --rsh --exclude --include --exclude-from --include-from --filter -f --rsync-path --port --bwlimit --timeout --log-file --backup-dir --suffix --partial-dir -T --temp-dir' });
    if (![...a.flags.keys()].some((k) => k === '--remove-source-files' || /^--delete(-|$)/.test(k)) || a.has('-n', '--dry-run')) return null;
    const dest = a.posW[a.posW.length - 1];
    if (!dest) return null;
    if (/^[^/\\]+:/.test(dest.s)) return 'rsync --delete removes files on another machine that are not in the source.';
    const r = pathRisk(dest, st);
    return r && !/the whole project/.test(r) ? `rsync --delete removes files in ${r} that are not in the source.` : (r ? 'rsync --delete would empty the destination of anything not in the source.' : null);
  }
  if (cx.prog === 'chmod' || cx.prog === 'chown' || cx.prog === 'chgrp') {
    const a = argParse(cx.args, { val: '--reference --from' });
    if (!a.has('-R', '--recursive')) return null;
    for (const w of a.posW.slice(1)) { if (w.lit && (w.s === '/' || w.s === '/*' || (st.o.home && (w.s === st.o.home || w.s === st.o.home + '/*')) || /^\/(etc|usr|bin|sbin|lib|lib64|var|boot|opt|root|home|sys|proc)\/?\*?$/.test(w.s))) return `A recursive ${cx.prog} on ${w.s} can lock you out of the system.`; }
    return null;
  }
  if (cx.prog === 'crontab') return cx.args.some((x) => /^-[A-Za-z]*r/.test(x.s)) ? 'crontab -r removes every scheduled job without asking.' : null;
  if (cx.prog === 'find') return findRule(cx);
  return null;
});
function findRule(cx) {
  const args = cx.args, st = cx.st;
  const roots = [];
  let i = 0;
  for (; i < args.length; i++) { const s = args[i].s; if (s.startsWith('-') && s.length > 1 || s === '(' || s === '!' || s === ')') break; roots.push(args[i]); }
  if (!roots.length) roots.push({ s: '.', lit: true, glob: false, raw: '.' });
  const expr = args.slice(i);
  const tests = expr.filter((x) => FIND_FILTER.test(x.s));
  const underRoot = (r) => (r.lit ? { s: r.s + '/' + SENT, lit: false, glob: false, raw: r.raw, under: r.s } : r);
  const del = expr.some((x) => x.s === '-delete');
  if (del) {
    for (const r of roots) {
      const risk = pathRisk(underRoot(r), st);
      if (risk) return `find -delete removes files in ${risk}.`;
      if (!tests.length) { const wipe = pathRisk(r, st); if (wipe) return `find -delete with no filter removes everything in ${wipe}.`; }
    }
  }
  for (let k = 0; k < expr.length; k++) {
    if (!['-exec', '-execdir', '-ok', '-okdir'].includes(expr[k].s)) continue;
    let e = k + 1;
    while (e < expr.length && expr[e].s !== ';' && expr[e].s !== '+') e++;
    // {} stands for what find found: below the roots when a test narrows it, otherwise everything including the roots
    const found = (r) => (!r.lit ? { s: SENT, lit: false, glob: false, raw: '{}' } : tests.length ? { s: r.s + '/' + SENT, lit: false, glob: false, raw: '{}', under: r.s } : { ...r, raw: '{}' });
    const inner = expr.slice(k + 1, e).map((w) => (w.s === '{}' ? found(roots[0]) : w));
    if (inner.length) runExec(inner, { stdin: { kind: 'none' }, redirs: [] }, fork(st));
    k = e;
  }
  return null;
}
rule('sh.disk', 'dd of=/dev/..., mkfs, wipefs, blkdiscard, sgdisk, diskutil erase, and writes to a disk device', 'dd mkfs wipefs blkdiscard sgdisk diskutil fdisk parted', (cx) => {
  if (cx.prog === 'dd') {
    const of = cx.args.find((x) => x.s.startsWith('of='));
    return of && DEV_BLOCK.test(of.s.slice(3)) ? 'dd to a disk device overwrites whatever is stored on it.' : null;
  }
  if (cx.prog === 'diskutil') return /^(erase\w*|partitionDisk|zeroDisk|randomDisk|secureErase|reformat|apfs)$/i.test(cx.args[0]?.s ?? '') && !(cx.args[0]?.s === 'apfs' && !/^delete/i.test(cx.args[1]?.s ?? '')) ? 'Erases or repartitions a disk.' : null;
  if (cx.prog === 'fdisk' || cx.prog === 'parted') return cx.args.some((x) => DEV_BLOCK.test(x.s)) && !cx.args.some((x) => /^-[A-Za-z]*l/.test(x.s) || x.s === 'print') ? 'Repartitions a disk.' : null;
  return 'Formats or wipes a disk or partition.';
});

// ---- HTTP clients
rule('sh.curl-api', 'curl, wget, httpie with a write method to a host on the API map (matched against that provider\'s rules)', 'curl wget http https xh xhs curlie', (cx) => {
  const reqs = cx.prog === 'wget' ? wgetRequests(cx) : cx.prog === 'curl' || cx.prog === 'curlie' ? curlRequests(cx) : httpieRequests(cx);
  const out = [];
  for (const r of reqs) { const h = apiRequestHold(cx, r); if (h) out.push({ id: h.id, why: h.why }); }
  return out.length ? out : null;
});

// ---------------------------------------------------------------- running the rules
const BY_PROG = new Map();
for (const r of R) for (const p of r.progs) { if (!BY_PROG.has(p)) BY_PROG.set(p, []); BY_PROG.get(p).push(r); }
const MKFS = /^(mkfs(\..+)?|mke2fs|mkswap|newfs)$/;
function runRules(prog, cx) {
  const key = MKFS.test(prog) ? 'mkfs' : prog;
  for (const r of BY_PROG.get(key) || []) {
    if (cx.st.o.disable.has(r.id)) continue;
    let out = null;
    try { out = r.test(cx); } catch (e) {
      if (e instanceof Unreadable || globalThis.__SHELLMAP_THROW) throw e;
      cx.st.res.errors = (cx.st.res.errors || 0) + 1;
    }
    if (!out) continue;
    for (const x of [].concat(out)) {
      const id = typeof x === 'object' && x.id ? x.id : r.id;
      hit(cx.st, id, typeof x === 'string' ? x : x.why, cx.argv.map((w) => w.raw ?? w.s).join(' '));
    }
  }
}

/** every rule: id and a short description (for docs, `guard map` and the site) */
export const SHELL_RULES = [
  ...R.map((r) => ({ id: r.id, what: r.what })),
  { id: 'sh.dynamic-program', what: 'a program name built at run time (variable or substitution) in a command that contains destroy, delete, drop, truncate, reset, force or rm' },
  { id: 'sh.decode-exec', what: 'decoded text (base64, xxd, gunzip, openssl) piped into a shell, an interpreter or eval; held without being read' },
];
// rules for MCP tool calls
export const TOOL_RULES = [
  { id: 'mcp.hold', what: 'a tool that matches a hold pattern in the policy file' },
  { id: 'mcp.name', what: 'a tool whose name says it deletes, drops, destroys, removes, truncates, resets, purges, revokes, cancels, refunds, transfers, pays, sends, publishes, deploys, merges, forces, wipes, terminates or archives, or runs SQL or a migration' },
  { id: 'mcp.sql', what: 'a tool call whose query or sql argument is SQL that is not a plain read' },
];

// ---------------------------------------------------------------- the entry point
const ABS = (p) => (typeof p === 'string' && p.startsWith('/') ? normPath(p) : null);
function normalizeOpts(o = {}) {
  const cwd = ABS(o.cwd);
  const home = ABS(o.home) ?? ABS(globalThis.process?.env?.HOME);
  return {
    cwd,
    root: ABS(o.root) ?? cwd,
    home,
    readFile: typeof o.readFile === 'function' ? o.readFile : () => null,
    apiMap: o.apiMap || BUNDLED_API_MAP,
    disable: new Set(o.disable || []),
    budget: { n: 0, steps: 0 },
  };
}

/**
 * Decide whether a shell command is on the map.
 * @param {string} command the command text as the agent sent it
 * @param {{cwd?: string, root?: string, home?: string, readFile?: (path: string) => string|null, apiMap?: object, disable?: string[]}} opts
 *   cwd: the agent's working directory (absolute); root: the project root (default cwd); readFile: lets the map read
 *   package.json scripts; apiMap: the API map from `apiMapFromMeta`; disable: rule ids to skip.
 * @returns {{version: string, hold: boolean, hits: {rule: string, why: string, text: string}[], unreadable: boolean}}
 */
export function classify(command, opts = {}) {
  const text = String(command ?? '');
  const o = normalizeOpts(opts);
  const res = { unreadable: false };
  o.res = res;
  let st = newState(o);
  if (text.length <= 1_000_000) {
    try {
      walk(parseScript(text, 0, o.budget), st);
      return done(st, res);
    } catch (e) {
      if (!(e instanceof Unreadable) && !(e instanceof RangeError)) { if (globalThis.__SHELLMAP_THROW) throw e; }
      if (globalThis.__SHELLMAP_THROW && !(e instanceof Unreadable)) throw e;
    }
  }
  // the text could not be read as a shell script: look at it piece by piece
  res.unreadable = true;
  st = newState({ ...o, budget: { n: 0, steps: 0 } });
  try { lenientScript(text.slice(0, 1_000_000), st); } catch (e) { if (globalThis.__SHELLMAP_THROW) throw e; }
  return done(st, res);
}
function done(st, res) {
  return { version: SHELL_MAP_VERSION, hold: st.hits.length > 0, hits: st.hits.map((h) => ({ rule: h.rule, why: h.why, text: h.text })), unreadable: res.unreadable };
}

// ---------------------------------------------------------------- MCP tool calls
const TOOL_WORDS = new Set('delete drop destroy remove truncate reset purge revoke cancel refund transfer pay payout send publish deploy merge force wipe terminate archive'.split(' '));
const TOOL_PAIRS = ['execute_sql', 'run_sql', 'apply_migration'];
const SQL_START = /^\s*(select\b|with\b|insert\s+into\b|update\s+\S+\s+set\b|delete\s+from\b|drop\s+\w|create\s+\w|alter\s+\w|truncate\b|merge\s+into\b|replace\s+into\b|grant\b|revoke\b|call\b|exec\b|explain\b|show\b|pragma\b|vacuum\b|copy\b|begin\b|set\s+\w)/i;
const toolTokens = (name) => String(name).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
const globRe = (g) => new RegExp('^' + String(g).replace(/[.+?^$()|[\]\\{}]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
/**
 * Decide whether an MCP tool call should wait for a human.
 * Order: policy `hold` patterns, SQL arguments that are not a plain read, policy `allow` patterns, then the default
 * words in the tool name. Tool annotations (readOnlyHint and friends) are never read: a server can say anything.
 * @param {{server?: string, tool: string, input?: object}} call
 * @param {{hold?: string[], allow?: string[], sqlArgs?: string[]}} policy
 */
export function classifyTool(call, policy = {}) {
  const tool = String(call?.tool ?? ''), server = String(call?.server ?? '');
  const names = [tool, server ? `${server}__${tool}` : tool, server ? `mcp__${server}__${tool}` : tool];
  const arr = (x) => (Array.isArray(x) ? x.filter((s) => typeof s === 'string' && s.length < 200).slice(0, 200) : []);
  const hold = arr(policy.hold), allow = arr(policy.allow);
  const sqlArgs = arr(policy.sqlArgs).length ? arr(policy.sqlArgs) : ['query', 'sql'];
  const label = (rule, why) => ({ hold: true, rule, why, tool, server });
  if (hold.some((g) => names.some((n) => globRe(g).test(n)))) return label('mcp.hold', 'This tool matches a hold pattern in your policy file.');
  const input = call?.input && typeof call.input === 'object' ? call.input : {};
  for (const k of sqlArgs) {
    for (const v of [].concat(input[k] ?? [])) {
      if (typeof v === 'string' && SQL_START.test(v) && !sqlReadOnly(v)) return label('mcp.sql', 'The tool was given SQL that is not a plain read.');
    }
  }
  if (allow.some((g) => names.some((n) => globRe(g).test(n)))) return { hold: false, tool, server };
  const tk = toolTokens(tool), joined = tk.join('_');
  if (tk.some((w) => TOOL_WORDS.has(w)) || TOOL_PAIRS.some((p) => joined.includes(p))) return label('mcp.name', 'The name of this tool says it changes or removes something that may not come back.');
  return { hold: false, tool, server };
}
