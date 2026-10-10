// What the MCP wrapper (counterseal mcp wrap) holds, and why. Zero dependencies. Pure functions: no files, no network.
//
// A tool call is held when (1) its name says it destroys, sends, pays or deploys, (2) your policy file asks for it, (3) a SQL
// argument is not plainly a read, (4) the tool calls itself destructive and your policy trusts that, or (5) the tool's
// definition changed since you pinned it (decided by the wrapper from the pin, not here). A held call waits for a passkey
// through the Approvals API. This is a seatbelt: it sees the names and arguments a client sends, and nothing else.
import { sqlReadOnly } from './mcp-sql.mjs';
import { parseStrict, isObj } from './mcp-json.mjs';

/** the version of the default hold list below; sent with every approval (it becomes the public receipt's map version) */
export const MCP_POLICY_VERSION = '2026-10-10.1';

export class PolicyError extends Error {}

export const DEFAULT_POLICY = Object.freeze({
  hold: Object.freeze([]), // tool name globs to hold, on top of the default list
  allow: Object.freeze([]), // tool name globs the default name list does not apply to (never lifts the SQL rule)
  sqlArgs: Object.freeze(['query', 'sql', 'statement', 'sql_query']), // argument names whose text is SQL
  trustAnnotations: false, // true: also hold a tool whose own definition says destructiveHint: true
  repin: 'terminal', // how a changed definition is accepted again: "terminal" (type it) or "passkey" (approve in the app)
});

// ---------------------------------------------------------------- the reasons (rule id -> text the human and the agent read)
// Fixed text only: nothing a server sends is ever copied into one of these.
export const WHY = Object.freeze({
  'mcp.name': 'The name of this tool says it deletes, sends, pays or deploys something for good, so a call waits for your passkey.',
  'mcp.policy': 'Your policy file for this MCP server asks for approval on this tool.',
  'mcp.sql': 'The SQL in this call is not one plain read (SELECT, WITH ... SELECT, EXPLAIN or SHOW), so it waits for your passkey.',
  'mcp.annotation': 'This tool says it is destructive (destructiveHint), and your policy trusts that.',
  'mcp.changed': 'This tool\'s definition changed since you pinned it, or it was never pinned. Until it is pinned again, every call to it waits for your passkey.',
  'mcp.repin': 'Pin the tool definitions of this MCP server again. They changed since the last pin, or none were pinned.',
});

// ---------------------------------------------------------------- the policy file
const PRINTABLE = /^[\x21-\x7e]{1,100}$/;
const KEYS = new Set(['hold', 'allow', 'sqlArgs', 'trustAnnotations', 'repin']);
const globList = (v, name) => {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > 200) throw new PolicyError(`${name} must be a list of at most 200 tool name patterns`);
  for (const g of v) {
    if (typeof g !== 'string' || !PRINTABLE.test(g)) throw new PolicyError(`${name}: a pattern is 1 to 100 printable characters without spaces`);
    if ((g.match(/\*/g) || []).length > 4) throw new PolicyError(`${name}: at most 4 "*" in a pattern`);
  }
  return [...v];
};

/** validate and fill in a policy read from JSON. Unknown keys are an error: a typo must not silently drop a protection. */
export function normalisePolicy(raw) {
  if (raw === undefined || raw === null) return { ...DEFAULT_POLICY, hold: [], allow: [], sqlArgs: [...DEFAULT_POLICY.sqlArgs] };
  if (!isObj(raw)) throw new PolicyError('the policy must be one JSON object');
  for (const k of Object.keys(raw)) if (!KEYS.has(k)) throw new PolicyError(`unknown policy key "${k.slice(0, 40)}" (known: ${[...KEYS].join(', ')})`);
  const out = { hold: globList(raw.hold, 'hold'), allow: globList(raw.allow, 'allow'), sqlArgs: [...DEFAULT_POLICY.sqlArgs], trustAnnotations: false, repin: 'terminal' };
  if (raw.sqlArgs !== undefined) {
    if (!Array.isArray(raw.sqlArgs) || raw.sqlArgs.length > 50 || raw.sqlArgs.some((x) => typeof x !== 'string' || x.length < 1 || x.length > 64)) throw new PolicyError('sqlArgs must be a list of at most 50 argument names (an empty list turns the SQL check off)');
    out.sqlArgs = [...raw.sqlArgs];
  }
  if (raw.trustAnnotations !== undefined) {
    if (typeof raw.trustAnnotations !== 'boolean') throw new PolicyError('trustAnnotations must be true or false');
    out.trustAnnotations = raw.trustAnnotations;
  }
  if (raw.repin !== undefined) {
    if (raw.repin !== 'terminal' && raw.repin !== 'passkey') throw new PolicyError('repin must be "terminal" or "passkey"');
    out.repin = raw.repin;
  }
  return out;
}

/** read a policy file's text: strict JSON (a repeated key is refused), then validated */
export function parsePolicy(text) {
  if (String(text).length > 65536) throw new PolicyError('the policy file is over 64 KB');
  let p;
  try { p = parseStrict(text); } catch (e) { throw new PolicyError('the policy file is not one JSON value: ' + e.message); }
  if (p.exactDupes.size) throw new PolicyError(`the policy file repeats a key: ${[...p.exactDupes.keys()].map((k) => k.slice(0, 40)).join(', ')}`);
  return normalisePolicy(p.value);
}

const globRe = (g, flags) => new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', flags);
const matches = (list, name, flags) => list.some((g) => globRe(g, flags).test(name));

// ---------------------------------------------------------------- the names
const BASES = ['delete', 'destroy', 'remove', 'truncate', 'refund', 'transfer', 'payout', 'publish', 'deploy', 'revoke', 'cancel', 'archive', 'terminate', 'wipe', 'purge', 'merge', 'send', 'pay', 'drop', 'reset', 'force'];
// plain verb forms of each word (delete, deletes, deleted, deleting) and, apart, the nouns made from them (deletion, deployment)
const VERB_EXTRA = {
  destroy: ['destroyed', 'destroying'], transfer: ['transferred', 'transferring'], cancel: ['cancelled', 'cancelling', 'canceled', 'canceling'],
  send: ['sent', 'sending'], pay: ['paid', 'paying'], drop: ['dropped', 'dropping'], reset: ['resetting'], force: ['forced', 'forcing'],
};
const NOUNS = ['deletion', 'deletions', 'removal', 'removals', 'truncation', 'publication', 'publications', 'deployment', 'deployments', 'revocation', 'revocations',
  'cancellation', 'cancellations', 'archival', 'termination', 'terminations', 'payment', 'payments'];
const VERB_FORMS = new Set();
for (const b of BASES) {
  for (const f of [b, b + 's', b + 'es', b + 'ed', b + 'd', b + 'ing', b.endsWith('e') ? b.slice(0, -1) + 'ing' : b + 'ing', ...(VERB_EXTRA[b] || [])]) VERB_FORMS.add(f);
}
const NOUN_FORMS = new Set(NOUNS);
const BASE_SET = new Set(BASES);
// a name that starts with one of these reads; it is left alone unless it also contains one of the words above exactly
const READ_VERBS = new Set(['get', 'list', 'read', 'search', 'find', 'describe', 'show', 'view', 'fetch', 'check', 'count', 'lookup', 'inspect', 'preview', 'query', 'select', 'browse', 'download', 'status', 'explain', 'ping', 'whoami', 'help']);
const READ_PREFIXES = [...READ_VERBS].filter((v) => v.length >= 3);
// tools that run arbitrary commands: held by name whatever their arguments say
const COMMAND_TOOLS = new Set(['apply_migration', 'run_command', 'execute_command', 'run_shell_command', 'exec', 'shell', 'bash', 'run_terminal_cmd', 'terminal']);
// tools that run SQL: held unless the SQL argument is plainly a read; held by name only when no SQL argument can be found
const SQL_TOOLS = new Set(['execute_sql', 'run_sql']);
// words in a tool name that say its text arguments are SQL
const SQLISH = new Set(['sql', 'db', 'database', 'postgres', 'postgresql', 'pg', 'mysql', 'mariadb', 'sqlite', 'supabase', 'neon', 'd1', 'sqlserver', 'mssql', 'oracle', 'redshift', 'bigquery', 'snowflake', 'clickhouse', 'duckdb']);
// The former single regex, ^(?:\s+|\/\*[\s\S]*?\*\/|--[^\n]*(?:\n|$)|\()*keyword\b, backtracked exponentially on long runs
// of space. It is now one left-to-right pass over the positions the prefix can reach, then a sticky keyword test at each:
// linear time on any input, and exactly the same answers. That includes the old regex's lenient reading of a block
// comment, which may end at ANY later "*/" (so "/* /* */ */ drop" counts as SQL, as nested comments do in PostgreSQL):
// a text that may be SQL is treated as SQL, never the other way round.
const SQL_KEYWORD = /(?:select|with|insert|update|delete|drop|create|alter|truncate|grant|revoke|merge|replace|upsert|call|do|exec|execute|copy|vacuum|reindex|analyze|set|reset|begin|commit|rollback|savepoint|pragma|attach|detach|lock|show|explain|values|table|use|load|import|refresh|cluster|comment|notify|listen|prepare|deallocate)\b/iy;
const SPACE = /\s/;
/** does this text start like a SQL statement? Free text under a "query" argument (a search, say) does not, and is not SQL. */
export const looksLikeSql = (text) => {
  const s = String(text), n = s.length;
  const reach = new Uint8Array(n + 1); // reach[i]: the prefix can end at i
  reach[0] = 1;
  let nl = -1; // the first newline at or after the last line comment's text (n when there is none)
  let open = Infinity; // the earliest position after a reachable "/*": any "*/" starting there or later closes a comment
  for (let i = 0; i <= n; i++) {
    if (!reach[i] && i >= 2 && s[i - 2] === '*' && s[i - 1] === '/' && i - 2 >= open) reach[i] = 1;
    if (!reach[i]) continue;
    SQL_KEYWORD.lastIndex = i;
    if (SQL_KEYWORD.test(s)) return true;
    if (i === n) break;
    const c = s[i];
    if (c === '(' || SPACE.test(c)) reach[i + 1] = 1;
    if (c === '/' && s[i + 1] === '*' && i + 2 < open) open = i + 2;
    if (c === '-' && s[i + 1] === '-') {
      // a line comment runs to its newline (or the end). nl only moves forward, so all the scans together are linear.
      if (nl < i + 2) { nl = i + 2; while (nl < n && s[nl] !== '\n') nl++; }
      reach[nl < n ? nl + 1 : n] = 1;
    }
  }
  return false;
};
const COMPACT = ['delete', 'destroy', 'remove', 'truncate', 'refund', 'transfer', 'payout', 'publish', 'deploy', 'revoke', 'cancel', 'archive', 'terminate', 'purge', 'wipe'];

/** the words of a tool name: split on anything that is not a letter or digit and on camelCase, lower case */
export const words = (name) => String(name).replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2').split(/[^A-Za-z0-9]+/).filter(Boolean).map((t) => t.toLowerCase());

/** 'command' | 'sql' | 'word' | null: whether the name alone says "hold" */
export function nameHit(name) {
  const norm = words(name).join('_');
  if (COMMAND_TOOLS.has(norm)) return 'command';
  if (SQL_TOOLS.has(norm)) return 'sql';
  const t = words(name);
  if (!t.length) return null;
  const exactVerb = t.some((x) => BASE_SET.has(x));
  if (t.length === 1) {
    // one word with no separators and no capitals, such as "deleteproject" or "projectdelete" (a lone noun such as "payments" is a listing)
    const w = t[0];
    if (VERB_FORMS.has(w)) return 'word';
    if (w.length < 7) return null;
    if (READ_PREFIXES.some((p) => w.startsWith(p))) return null;
    return COMPACT.some((b) => w.startsWith(b) || w.endsWith(b)) ? 'word' : null;
  }
  if (READ_VERBS.has(t[0]) && !exactVerb) return null;
  return t.some((x) => VERB_FORMS.has(x) || NOUN_FORMS.has(x)) ? 'word' : null;
}

// ---------------------------------------------------------------- the arguments
const fold = (k) => k.toUpperCase().toLowerCase();
/** every SQL text in a tool call's arguments: strings under a SQL argument name, at any depth (a name given as a string or a list of strings) */
export function sqlTexts(args, names) {
  const want = new Set(names.map(fold)), out = [];
  let nodes = 0;
  const walk = (v, d) => {
    if (d > 10 || nodes++ > 20000 || !v || typeof v !== 'object') return;
    if (Array.isArray(v)) { for (const x of v) walk(x, d + 1); return; }
    for (const [k, x] of Object.entries(v)) {
      if (want.has(fold(k)) && typeof x === 'string') out.push(x);
      else if (want.has(fold(k)) && Array.isArray(x) && x.every((y) => typeof y === 'string')) out.push(...x);
      else walk(x, d + 1);
    }
  };
  walk(args, 0);
  return out;
}

/**
 * Should this call be held? { rule, why } or null.
 * @param {{name: string, args: object, flags?: {destructive: boolean|null, readOnly: boolean|null}}} call  flags: from the pinned definition
 * @param {object} policy  a normalised policy
 */
export function classifyTool(call, policy = DEFAULT_POLICY) {
  const { name, args } = call;
  if (matches(policy.hold, name, 'i')) return { rule: 'mcp.policy', why: WHY['mcp.policy'] };
  const allowed = matches(policy.allow, name, '');
  const hit = nameHit(name);
  // a tool that runs SQL by its name has every text under a SQL argument checked; any other tool only the texts that start like SQL
  const sqlish = words(name).some((w) => SQLISH.has(w));
  const sql = policy.sqlArgs.length ? sqlTexts(args, policy.sqlArgs).filter((s) => sqlish || looksLikeSql(s)) : [];
  if (sql.some((s) => !sqlReadOnly(s))) return { rule: 'mcp.sql', why: WHY['mcp.sql'] };
  if (!allowed) {
    if (hit === 'command' || hit === 'word') return { rule: 'mcp.name', why: WHY['mcp.name'] };
    if (hit === 'sql' && !sql.length) return { rule: 'mcp.name', why: WHY['mcp.name'] };
  }
  if (policy.trustAnnotations && !allowed && call.flags && call.flags.destructive === true && call.flags.readOnly !== true) return { rule: 'mcp.annotation', why: WHY['mcp.annotation'] };
  return null;
}
