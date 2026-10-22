#!/usr/bin/env node
// counterseal mcp wrap: put a local MCP server (stdio) behind Counterseal. Zero dependencies, Node 20+.
//
//   counterseal mcp wrap --name <id> [--policy <file>] [--require-pin] -- <command> [args...]
//        what your MCP client runs instead of the server. Destructive tool calls wait for your passkey; the server's tool
//        definitions are pinned and a changed one is hidden from the model and held until you pin it again.
//   counterseal mcp pin --name <id> [--yes] [-- <command> [args...]]     pin (or pin again) what the server shows now
//   counterseal mcp unpin --name <id>                                     forget the pin: the next run pins afresh
//   counterseal mcp status --name <id> [--check]                          the pin, what waits for review, the policy
//
// The wrapper sits in the stream between your client and the server, reads newline-delimited JSON-RPC both ways (batches
// too, up to 4 MB a line), and forwards the original bytes of everything it lets through. A held tool call is answered at
// once with a tool result that says so (isError: true), so no client timeout runs; after you approve in the app, the agent
// calls the same tool with the same arguments again and that call goes through, once.
//
// THIS IS A SEATBELT, NOT A SANDBOX. It runs on the machine of the agent it guards, as the same user. It only sees what the
// client sends through it: an agent that can start the server another way, edit your client's MCP configuration, rewrite the
// pin or policy files, or use a tool the policy does not name is not stopped. Tool names and arguments are matched against a
// list, not understood. Prompts and resources are not pinned. For a hard stop, give the agent a Counterseal token instead of the
// real key (see the README). Pinning uses mcp-pin's published tool definition hash (see mcp-hash.mjs).
import { readFileSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnServer } from './spawn.mjs';
import { parseStrict, isObj, idKey } from './mcp-json.mjs';
import { canonicalize, definitionHash, setHash as setHashOf, instructionsHash, sha256 } from './mcp-hash.mjs';
import { classifyTool, normalisePolicy, parsePolicy, WHY, MCP_POLICY_VERSION, PolicyError } from './mcp-policy.mjs';
import * as Store from './mcp-store.mjs';
import { loadGuard, makeAsk, readApproval, failureText } from './mcp-ask.mjs';

export const WRAP_VERSION = '0.4.0';
export const MAX_LINE = 4 * 1024 * 1024;
const MAX_DETAIL = 4096;
const DENIED_FOR_MS = 5 * 60_000;
const RECHECK_MS = 60_000; // how long the wrapper trusts its last look at the server's tool definitions before a call
const MAX_PENDING = 20000;
// the folder names the Approvals API accepts (server/src/approvals.js CWD): no separators, no control, format or line-break characters
const CWD = /^(?!\.{1,2}$)[^/\\\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]{1,80}$/u;

// ---------------------------------------------------------------- lines
/** splits a byte stream into lines (LF), refusing any line over `max` bytes: it is skipped whole and onOverflow is called */
export class LineReader {
  constructor(max, onLine, onOverflow) { this.max = max; this.onLine = onLine; this.onOverflow = onOverflow; this.buf = []; this.len = 0; this.skipping = false; }
  push(chunk) {
    let start = 0;
    for (;;) {
      const nl = chunk.indexOf(0x0a, start);
      if (nl < 0) { this.#add(chunk.subarray(start)); return; }
      this.#add(chunk.subarray(start, nl));
      this.#emit();
      start = nl + 1;
    }
  }
  #add(b) {
    if (this.skipping || !b.length) return;
    this.len += b.length;
    if (this.len > this.max) { this.skipping = true; this.buf = []; this.len = 0; return; }
    this.buf.push(b);
  }
  #emit() {
    if (this.skipping) { this.skipping = false; this.onOverflow(); return; }
    const line = Buffer.concat(this.buf);
    this.buf = []; this.len = 0;
    this.onLine(line);
  }
  /** the stream ended: a last line without a newline still counts */
  end() { if (this.skipping || this.len) this.#emit(); }
}

const decoder = new TextDecoder('utf-8', { fatal: true });
/** a line as text, or null when it is not valid UTF-8 or is empty; one trailing CR is dropped */
export function lineText(buf) {
  let t;
  try { t = decoder.decode(buf); } catch { return null; }
  if (t.endsWith('\r')) t = t.slice(0, -1);
  return t.trim() === '' ? '' : t;
}

// ---------------------------------------------------------------- small helpers
export const rpcError = (id, code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
export const toolResult = (id, text) => ({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: true } });
const safeName = (n) => Store.escapeText(String(n)).replace(/[^\x20-\x7e]/g, '?').slice(0, 80);
const cleanReason = (r) => (typeof r === 'string' ? r.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\u200b-\u200f]/g, ' ').trim().slice(0, 200) : '');

/** replace the array a span describes (parts are the JSON text of its new elements); every other byte of `text` is kept */
export const spliceArray = (text, span, parts) => text.slice(0, span.start) + '[' + parts.join(',') + ']' + text.slice(span.end);
/** the text of the object a span describes, without the members named `key` */
export const withoutMember = (text, span, key) => '{' + span.members.filter((m) => m.key !== key).map((m) => text.slice(m.start, m.end)).join(',') + '}';
/** the same, without every member whose name is `key` once case is folded (a parser that ignores case would read "Instructions" as "instructions") */
export const withoutFolded = (text, span, key) => '{' + span.members.filter((m) => fold(m.key) !== key).map((m) => text.slice(m.start, m.end)).join(',') + '}';

// ---------------------------------------------------------------- reading JSON the way every parser would
// The wrapper decides by what it reads and passes on the original bytes, so it must be sure that the client, the server and itself
// read those bytes alike. Parsers differ on a repeated member name (first or last copy) and some (Go's encoding/json) match a name
// without regard to case, so a message is refused where it could be read two ways at a place the wrapper decides by.
const fold = (k) => k.toUpperCase().toLowerCase();
const RPC_NAMES = new Set(['jsonrpc', 'id', 'method', 'params', 'result', 'error']);
const PARAM_NAMES = new Set(['name', 'arguments', 'cursor', '_meta']);
const REPLY_NAMES = new Set(['jsonrpc', 'id', 'result', 'error', 'tools', 'instructions', 'method', 'params']);
/** a member of `obj` whose name is not written as the protocol writes it but folds to one of `names` (so some parsers would take it for that name) */
const oddCase = (obj, names) => { for (const k of Object.keys(obj)) if (!names.has(k) && names.has(fold(k))) return k; return null; };
/** can a reply from the server be read two ways in its envelope or its result (depth 0 and 1): a repeated name, or the names that matter in another case */
function ambiguousReply(p) {
  for (const d of p.exactDupes.values()) if (d <= 1) return true;
  for (const [f, d] of p.foldDupes) if (d <= 1 && REPLY_NAMES.has(f)) return true;
  return false;
}
/**
 * Hash each definition in the tools of a tools/list result: [{ h }] with h null when a definition has no single reading (it repeats
 * a member name somewhere inside it, or is not an object, or has no canonical form).
 */
function hashTools(text, p, tools) {
  const sp = p.spans && p.spans.get(tools);
  const dupes = p.exactDupes.size > 0;
  return tools.map((d, i) => {
    if (!isObj(d)) return { h: null };
    let readable = true;
    if (dupes) {
      try { readable = !!sp && parseStrict(text.slice(sp.elems[i][0], sp.elems[i][1])).exactDupes.size === 0; } catch { readable = false; }
    }
    if (!readable) return { h: null };
    try { return { h: definitionHash(d) }; } catch { return { h: null }; }
  });
}

/**
 * The text that identifies a tool call to the approver and binds the approval to it: the tool and its arguments in canonical
 * JSON (members sorted), at most 4096 characters. Longer arguments are shown by their start with their length and SHA-256, and the
 * hash covers all of it, so a retry with other arguments is a different request.
 */
export function detailOf(name, args, params = {}) {
  const extra = {};
  for (const k of Object.keys(params)) if (k !== 'name' && k !== 'arguments' && k !== '_meta') extra[k] = params[k];
  const hasExtra = Object.keys(extra).length > 0;
  const whole = canonicalize({ arguments: args, tool: name, ...(hasExtra ? { extra } : {}) });
  if (whole.length <= MAX_DETAIL) return { text: whole, truncated: false };
  const argsText = canonicalize(args);
  const head = { arguments_head: '', arguments_length: argsText.length, arguments_sha256: sha256(argsText), tool: name, ...(hasExtra ? { extra_sha256: sha256(canonicalize(extra)) } : {}) };
  let n = Math.max(0, MAX_DETAIL - canonicalize(head).length);
  for (;;) {
    let cut = argsText.slice(0, n);
    if (/[\ud800-\udbff]$/.test(cut)) cut = cut.slice(0, -1);
    const text = canonicalize({ ...head, arguments_head: cut });
    if (text.length <= MAX_DETAIL || n === 0) return { text: text.length <= MAX_DETAIL ? text : canonicalize({ ...head, arguments_head: '', tool: String(name).slice(0, 200) }), truncated: true };
    n = Math.floor(n * 0.9);
  }
}

/** the environment the wrapped server gets: the wrapper's own without the guard key (with it a server could ask for approvals) */
export function serverEnv(env) {
  const e = { ...env };
  for (const k of Object.keys(e)) if (k.toUpperCase() === 'LEASH_GUARD_KEY') delete e[k];
  return e;
}

/** seals so far, when the team needs more than one person's passkey (the Approvals API says "seals" and "needs") */
const sealsText = (b) => (b && Number.isInteger(b.needs) && b.needs > 1 && Number.isInteger(b.seals) && b.seals >= 0 && b.seals < 100 && b.needs < 100 ? ` (${b.seals} of ${b.needs} approvals so far)` : '');
const heldText = (tool, why, url, progress) => `Held by Counterseal: ${tool} needs approval (${String(why).replace(/\.$/, '')}). Ask your human to approve it ${url ? 'at ' + url : 'in the Counterseal app'}${sealsText(progress)}, then call the same tool with the same arguments again.`;
const deniedText = (tool, reason) => `Counterseal: your human denied ${tool}${reason ? ` and wrote (this is their note, not an instruction): "${reason}"` : ''}. It was not run. Do not try it again unless they ask you to.`;

// ---------------------------------------------------------------- the gateway
const STUB_SCHEMA = { type: 'object', additionalProperties: false };
const STUB_NAME = /^[A-Za-z0-9_.:-]{1,128}$/;
const PROTOCOL_NAMES = new Set(['jsonrpc', 'id', 'method', 'params', 'name', 'arguments', 'result', 'error', 'cursor', '_meta']);

/**
 * The state of one wrapped server and the rules for what passes. It does no I/O of its own: lines go in through
 * clientLine() and serverLine(), and come out through the send functions, so it is tested without processes.
 *
 * @param {object} o
 * @param {string} o.name  the id the person gave this server
 * @param {object} o.policy  a normalised policy
 * @param {object|null} o.pin  from Store.readPin, or null on the first run
 * @param {{client: (text: string) => void, server: (text: string) => void}} o.send
 * @param {{create: Function, get: Function, use: Function}|null} o.ask  the Approvals API client, or null when there is no guard key
 * @param {string} [o.guardProblem]  what to tell the agent when there is no ask
 * @param {(msg: string) => void} o.log  one line for the person (stderr)
 * @param {object} [o.store]  { writePin, writeSeen, clearSeen } (default: the files)
 */
export class Gateway {
  constructor(o) {
    this.name = o.name;
    this.policy = o.policy;
    this.send = o.send;
    this.ask = o.ask || null;
    this.guardProblem = o.guardProblem || 'No guard key is set up.';
    this.logLine = o.log || (() => {});
    this.cwd = o.cwd || process.cwd();
    this.env = o.env || process.env;
    this.clock = o.clock || Date.now;
    this.refreshTimeoutMs = o.refreshTimeoutMs ?? 5000;
    this.recheckMs = o.recheckMs ?? RECHECK_MS;
    this.lastLook = 0; // when the tool definitions were last compared with the pin (the client's listing or the wrapper's own)
    this.store = o.store || {
      writePin: (obs) => Store.writePin(this.name, obs, this.env),
      writeSeen: (obs) => Store.writeSeen(this.name, obs, this.env),
      clearSeen: () => Store.clearSeen(this.name, this.env),
    };
    this.pin = o.pin ? { ...o.pin, tools: Object.assign(Object.create(null), o.pin.tools) } : null;
    this.pending = new Map(); // id key -> { method, cursor, internal, resolve }
    this.groups = new Map(); // id key -> { local: response objects } for a batch part of which was answered here
    this.clientView = new Map(); // tool name -> the hash of the definition the client was last shown
    this.flags = new Map(); // tool name -> { d, r } from that definition
    this.refreshView = null; // tool name -> hash, from the wrapper's own listing
    this.listing = null;
    this.instructionsSeen = undefined;
    this.changedNames = new Set();
    this.noticed = new Set();
    this.ready = false;
    this.seq = 0;
    this.refreshing = null;
    this.refreshTimer = null;
    this.queue = Promise.resolve();
    this.asked = new Map(); // detail text -> { id, hash, url }
    this.denied = new Map(); // detail text -> { until, reason }
    this.sqlFolded = new Set(this.policy.sqlArgs.map((x) => x.toUpperCase().toLowerCase()));
  }

  log(msg) { this.logLine(`Counterseal: ${msg}`); }
  notice(msg) { if (!this.noticed.has(msg)) { this.noticed.add(msg); this.log(msg); } }
  /** resolves when every client line given so far has been dealt with */
  idle() { return this.queue; }
  stop() { clearTimeout(this.refreshTimer); for (const e of this.pending.values()) if (e.timer) clearTimeout(e.timer); }

  // ---------------------------------------------------------------- client to server
  clientLine(text) {
    this.queue = this.queue.then(() => this.#client(text)).catch((e) => this.log(`internal error: ${String(e && e.message).slice(0, 200)}`));
  }

  async #client(text) {
    let p;
    try { p = parseStrict(text, { track: 4 }); } catch { this.send.client(JSON.stringify(rpcError(null, -32700, 'Counterseal could not read that message as one unambiguous JSON value, so it was not passed on.'))); return; }
    if (Array.isArray(p.value)) return this.#clientBatch(text, p);
    const d = await this.#decideSafe(p.value, p);
    if (d.forward) { this.#register(p.value); this.#toServer(text, p.value); } else if (d.local) this.send.client(JSON.stringify(d.local));
  }

  /** #decide, but a failure inside the gateway never lets a message through: it is answered here as not run, and said on stderr */
  async #decideSafe(m, p) {
    try { return await this.#decide(m, p); } catch (e) {
      this.log(`internal error: ${String(e && e.message).slice(0, 200)}`);
      if (!isObj(m) || idKey(m.id) === null || typeof m.method !== 'string') return { local: null };
      const why = 'Counterseal had an internal problem, so this was not passed on. Try again.';
      return { local: fold(m.method.trim()) === 'tools/call' ? toolResult(m.id, why) : rpcError(m.id, -32603, why) };
    }
  }

  #toServer(text, msg) {
    if (isObj(msg) && msg.method === 'notifications/initialized') this.ready = true;
    this.send.server(text);
  }

  #register(m) {
    if (!isObj(m) || typeof m.method !== 'string') return;
    const key = idKey(m.id);
    if (key === null) return;
    if (this.pending.size > MAX_PENDING) this.pending.delete(this.pending.keys().next().value);
    this.pending.set(key, { method: m.method, cursor: isObj(m.params) && typeof m.params.cursor === 'string' ? m.params.cursor : null });
  }

  /** what makes a client message ambiguous: a name repeated in one object, two that differ only by case where it matters, or a protocol name in the wrong case */
  #ambiguous(p) {
    if (p.exactDupes.size) return `a repeated member name (${[...p.exactDupes.keys()].slice(0, 3).map((k) => safeName(k)).join(', ')})`;
    for (const [f, depth] of p.foldDupes) if (depth <= 1 && PROTOCOL_NAMES.has(f)) return `names that differ only by case (${safeName(f)})`;
    for (const f of p.foldDupes.keys()) if (this.sqlFolded.has(f)) return `names that differ only by case (${safeName(f)})`;
    const m = p.value;
    if (isObj(m)) {
      const odd = oddCase(m, RPC_NAMES) ?? (isObj(m.params) ? oddCase(m.params, PARAM_NAMES) : null);
      if (odd !== null) return `a protocol name written in another case (${safeName(odd)})`;
    }
    return null;
  }

  async #decide(m, p) {
    if (!isObj(m)) return { local: rpcError(null, -32600, 'Counterseal expects a JSON-RPC message object.') };
    const bad = this.#ambiguous(p);
    const isRequest = typeof m.method === 'string' && idKey(m.id) !== null;
    const isCall = typeof m.method === 'string' && fold(m.method.trim()) === 'tools/call'; // whatever its id (or none), and in whatever case
    if (bad) {
      this.log(`refused a message from the client that could be read two ways: ${bad}`);
      // answer what looks like a request, so the client does not wait for ever; a notification gets no answer
      if (!(isRequest || (idKey(m.id) !== null && Object.keys(m).some((k) => fold(k) === 'method')))) return { local: null };
      const id = p.exactDupes.get('id') === 0 || p.foldDupes.get('id') === 0 ? null : m.id; // an id written twice: the client's own copy is not known
      return { local: isCall ? toolResult(id, `Counterseal did not pass this call on: its JSON could be read two ways (${bad}).`) : rpcError(id, -32600, `Counterseal did not pass this message on: its JSON could be read two ways (${bad}).`) };
    }
    if (isRequest && typeof m.id === 'string' && m.id.startsWith('__cs_')) return { local: rpcError(m.id, -32600, 'Counterseal keeps request ids that start with __cs_ for itself.') };
    if (isCall) return this.#toolCall(m);
    return { forward: true };
  }

  async #clientBatch(text, p) {
    const arr = p.value;
    if (arr.length === 0) { this.send.client(JSON.stringify(rpcError(null, -32600, 'An empty batch is not a valid JSON-RPC message.'))); return; }
    const sp = p.spans.get(arr);
    const forward = [], local = [], ids = [];
    for (let i = 0; i < arr.length; i++) {
      const el = text.slice(sp.elems[i][0], sp.elems[i][1]);
      let ep;
      try { ep = parseStrict(el, { track: 4 }); } catch { local.push(rpcError(null, -32700, 'Counterseal could not read this part of the batch.')); continue; }
      const d = await this.#decideSafe(ep.value, ep);
      if (d.forward) {
        forward.push(el);
        this.#register(ep.value);
        if (isObj(ep.value) && typeof ep.value.method === 'string' && idKey(ep.value.id) !== null) ids.push(idKey(ep.value.id));
        if (isObj(ep.value) && ep.value.method === 'notifications/initialized') this.ready = true;
      } else if (d.local) local.push(d.local);
    }
    if (forward.length === arr.length) { this.send.server(text); return; }
    if (forward.length) this.send.server('[' + forward.join(',') + ']');
    if (!local.length) return;
    if (ids.length) { const g = { local }; for (const k of ids) this.groups.set(k, g); } // answered together with the server's replies
    else this.send.client(JSON.stringify(local));
  }

  // ---------------------------------------------------------------- tools/call
  async #toolCall(msg) {
    const params = msg.params;
    const answerable = idKey(msg.id) !== null; // a tools/call with no usable id has nowhere to send an answer: it is held or refused silently
    const reply = (r) => ({ local: answerable ? r : null });
    if (!isObj(params) || typeof params.name !== 'string' || params.name === '' || params.name.length > 256) return reply(rpcError(msg.id, -32602, 'Counterseal needs params.name to be a tool name.'));
    const args = params.arguments === undefined ? {} : params.arguments;
    if (!isObj(args)) return reply(rpcError(msg.id, -32602, 'Counterseal needs params.arguments to be an object.'));
    const name = params.name;
    const state = await this.#toolState(name);
    let verdict = null;
    if (state !== 'ok') verdict = { rule: 'mcp.changed', why: WHY['mcp.changed'] };
    else verdict = classifyTool({ name, args, flags: this.#flagsOf(name) }, this.policy);
    if (!verdict) return { forward: true };
    const out = await this.#hold({ name, args, params, verdict });
    if (out.run) return { forward: true };
    if (!answerable) this.log(`held a tools/call that has no usable id (${safeName(name)}): it was not passed on`);
    return reply(toolResult(msg.id, out.text));
  }

  #flagsOf(name) {
    const e = this.pin && this.pin.tools[name];
    if (e) return { destructive: e.d, readOnly: e.r };
    const f = this.flags.get(name);
    return f ? { destructive: f.d, readOnly: f.r } : undefined;
  }

  /** 'ok' | 'changed' | 'new' | 'unknown': is this tool the one that was pinned, as far as the wrapper can tell */
  async #toolState(name) {
    if (!this.pin) return 'ok'; // the first run: nothing to compare with yet (the first complete listing is pinned)
    const e = this.pin.tools[name];
    if (!e) return 'new';
    const check = () => {
      const cv = this.clientView.get(name), rv = this.refreshView ? this.refreshView.get(name) : undefined;
      if ((cv !== undefined && cv !== e.h) || (rv !== undefined && rv !== e.h)) return 'changed';
      return cv === undefined && rv === undefined ? 'unknown' : 'ok';
    };
    let st = check();
    // nobody has listed the tools in this session yet, or the last look is old: look again (a server may change a tool without saying so)
    if (st === 'unknown' || (st === 'ok' && this.clock() - this.lastLook >= this.recheckMs)) { await this.#refresh().catch(() => {}); st = check(); }
    return st === 'unknown' ? 'changed' : st;
  }

  async #hold({ name, args, params, verdict }) {
    const tool = safeName(name);
    // the approval names the server too (as the guard's hook does, mcp__<server>__<tool>): a yes for staging's drop_table
    // must not run prod's
    const det = detailOf(this.name ? `mcp__${this.name}__${name}` : name, args, params);
    const key = det.text;
    const d = this.denied.get(key);
    if (d && d.until > this.clock()) return { text: deniedText(tool, d.reason) };
    if (!this.ask) return { text: `Held by Counterseal: ${tool} was not run (${String(verdict.why).replace(/\.$/, '')}) and there is nothing to ask for approval with. ${this.guardProblem}` };
    const cwd = basename(this.cwd);
    const context = { session: this.name, ...(CWD.test(cwd) ? { cwd } : {}) }; // a folder name the server accepts, else none
    const why = det.truncated ? `${verdict.why} The arguments are longer than ${MAX_DETAIL} characters: the card shows their start and the SHA-256 of all of them.`.slice(0, 300) : verdict.why;
    const body = { kind: 'tool', agent: 'mcp', rule: verdict.rule, why, summary: `${this.name}: ${tool}`.slice(0, 200), detail: det.text, context, map: MCP_POLICY_VERSION };
    for (let attempt = 0; attempt < 2; attempt++) {
      let a = null;
      const known = this.asked.get(key);
      if (known) {
        const g = await this.ask.get(known.id, 0);
        if (g.status === 200) {
          const st = g.body.status;
          if (st === 'approved') a = known;
          else if (st === 'pending') return { text: heldText(tool, verdict.why, known.url, g.body) };
          else if (st === 'denied') {
            this.asked.delete(key);
            const reason = cleanReason(g.body.deny_reason);
            this.denied.set(key, { until: this.clock() + DENIED_FOR_MS, reason });
            return { text: deniedText(tool, reason) };
          } else this.asked.delete(key); // expired or used: ask again below
        } else if (g.status === 404) this.asked.delete(key);
        else return { text: `${failureText(g)} ${tool} was not run.` };
      }
      if (!a) {
        const c = await this.ask.create(body);
        if (c.status !== 200 && c.status !== 202) return { text: `${failureText(c)} ${tool} was not run.` };
        const r = readApproval(c.body);
        if (!r) return { text: `Counterseal sent an answer this wrapper does not understand, so ${tool} was not run.` };
        // a break-glass window (the team opened it, with passkeys) approves at once: nobody is asked, and the person should see that on stderr
        if (c.status === 200 && c.body.breakglass === true) this.log(`${tool} was approved without a question: a break-glass window is open on your Counterseal account`);
        this.asked.set(key, { id: r.id, hash: r.hash, url: r.url });
        if (c.status === 202 || r.status !== 'approved') return { text: heldText(tool, verdict.why, r.url) };
        a = { id: r.id, hash: r.hash, url: r.url };
      }
      const u = await this.ask.use(a.id, a.hash);
      if (u.status === 200) { this.asked.delete(key); return { run: true }; }
      if (u.status === 403) {
        this.asked.delete(key);
        const reason = cleanReason(u.body.deny_reason);
        this.denied.set(key, { until: this.clock() + DENIED_FOR_MS, reason });
        return { text: deniedText(tool, reason) };
      }
      if (u.status === 409 || u.status === 410) { this.asked.delete(key); continue; } // spent, expired or not approved after all: ask again
      return { text: `${failureText(u)} ${tool} was not run.` };
    }
    return { text: `Counterseal could not settle the approval for ${tool}, so it was not run. Try again.` };
  }

  // ---------------------------------------------------------------- server to client
  /** one line from the server (synchronous, so the order of what the client sees is the order the server wrote) */
  serverLine(text) {
    let p;
    try { p = parseStrict(text, { track: 4 }); } catch { this.log(`the server wrote something that is not JSON to its output, so it was not passed on: ${Store.shown(text, 100)}`); return; }
    if (Array.isArray(p.value)) { this.#serverBatch(text, p); return; }
    const out = this.#serverOne(text, p);
    if (out === null) return;
    const g = isObj(p.value) && typeof p.value.method !== 'string' ? this.#groupOf(p.value.id) : null;
    if (g) this.send.client(JSON.stringify(g.local)); // part of a batch was answered here: those answers go first
    this.send.client(out);
  }

  #groupOf(id) {
    const k = idKey(id);
    const g = k === null ? undefined : this.groups.get(k);
    if (!g) return null;
    for (const [kk, v] of this.groups) if (v === g) this.groups.delete(kk);
    return g;
  }

  #serverBatch(text, p) {
    const arr = p.value;
    const sp = p.spans.get(arr);
    const parts = [];
    let modified = false, group = null;
    for (let i = 0; i < arr.length; i++) {
      const el = text.slice(sp.elems[i][0], sp.elems[i][1]);
      let ep;
      try { ep = parseStrict(el, { track: 4 }); } catch { modified = true; continue; }
      const out = this.#serverOne(el, ep);
      if (out === null) { modified = true; continue; }
      if (out !== el) modified = true;
      parts.push(out);
      if (!group && isObj(ep.value) && typeof ep.value.method !== 'string') group = this.#groupOf(ep.value.id);
    }
    if (group) { for (const r of group.local) parts.push(JSON.stringify(r)); modified = true; }
    if (!parts.length) return;
    this.send.client(modified ? '[' + parts.join(',') + ']' : text);
  }

  /** what to pass on for one message from the server: its text (possibly rewritten), or null to drop it */
  #serverOne(text, p) {
    const m = p.value;
    if (!isObj(m)) { this.log('the server wrote a JSON-RPC message that is not an object, so it was not passed on'); return null; }
    // a message the client could read differently from the wrapper (a repeated or oddly cased protocol name) is not passed on
    const odd = oddCase(m, RPC_NAMES);
    const idTwice = p.exactDupes.get('id') === 0 || p.foldDupes.get('id') === 0;
    if (odd !== null || idTwice || [...p.exactDupes.values()].some((d) => d === 0) || [...p.foldDupes].some(([f, d]) => d === 0 && RPC_NAMES.has(f))) {
      this.log(`the server wrote a message whose protocol names could be read two ways${odd !== null ? ` ("${safeName(odd)}")` : ''}, so it was not passed on`);
      // a client waiting for this reply must not wait for ever: it gets an error (unless the id itself is unclear)
      const k = idTwice || typeof m.method === 'string' ? null : idKey(m.id);
      const ent = k === null ? undefined : this.pending.get(k);
      if (ent && !ent.internal) { this.pending.delete(k); return JSON.stringify(rpcError(m.id, -32603, 'Counterseal did not pass on the reply of the server: its JSON could be read two ways.')); }
      return null;
    }
    const hasMethod = Object.hasOwn(m, 'method');
    if (hasMethod && (typeof m.method !== 'string' || Object.hasOwn(m, 'result') || Object.hasOwn(m, 'error'))) { this.log('the server wrote a message that is both a request and a reply, so it was not passed on'); return null; }
    if (hasMethod) {
      if (m.method === 'notifications/tools/list_changed') this.#scheduleRefresh();
      return text;
    }
    const key = idKey(m.id);
    if (key === null) return text; // an error with no id (a parse error on the server side): the client should see it
    const ent = this.pending.get(key);
    if (!ent) { this.log('dropped a reply from the server to a request nobody made'); return null; }
    this.pending.delete(key);
    if (ent.internal) { if (ent.timer) clearTimeout(ent.timer); ent.resolve({ message: m, text, p }); return null; }
    if (isObj(m.result)) {
      if (ent.method === 'initialize' || ent.method === 'server/discover') return this.#instructions(text, p, m);
      if (ent.method === 'tools/list') return this.#toolsList(text, p, m, ent);
    }
    return text;
  }

  /** a tool list that cannot be read one way is not passed on: the client gets an error and nothing of it is trusted or pinned */
  #blockedList(m) {
    this.listing = null;
    this.notice(`"${this.name}" sent a tool list that could be read two ways (a repeated or oddly cased name), so it was not passed on`);
    return JSON.stringify(rpcError(m.id, -32603, 'Counterseal did not pass on this tool list: its JSON could be read two ways.'));
  }

  #instructions(text, p, m) {
    const res = m.result;
    const rs = p.spans.get(res);
    const variants = rs ? rs.members.filter((x) => fold(x.key) === 'instructions') : [];
    const ins = Object.hasOwn(res, 'instructions') ? res.instructions : undefined;
    const text0 = typeof ins === 'string' ? ins : null;
    const h = instructionsHash(text0);
    this.instructionsSeen = { h, text: text0 };
    if (!this.pin) return text; // the first run: what the server says is what gets pinned
    const odd = variants.length > 1 || variants.some((x) => x.key !== 'instructions') || ambiguousReply(p);
    if (!odd && (variants.length === 0 || (h !== null && h === this.pin.instructions))) return text; // nothing said, or what was pinned
    // new, changed or unclear: text the person has not approved is never passed on to the model
    this.notice(odd ? `"${this.name}" answered with instructions that could be read two ways (a repeated or oddly cased name). They were not passed on.`
      : `"${this.name}" changed what it tells the model about itself (its instructions) since you pinned them. That text was not passed on. Review and pin: counterseal mcp pin --name ${this.name}`);
    if (!rs) return text;
    return text.slice(0, rs.start) + withoutFolded(text, rs, 'instructions') + text.slice(rs.end);
  }

  #stub(name) {
    return JSON.stringify({ name, description: `Counterseal has blocked this tool: its definition changed since it was pinned, or it was never pinned. Do not call it. Ask your human to run: counterseal mcp pin --name ${this.name}`, inputSchema: STUB_SCHEMA });
  }

  #toolsList(text, p, m, ent) {
    const res = m.result;
    const rs = p.spans.get(res);
    const tools = res.tools;
    const variants = rs ? rs.members.filter((x) => fold(x.key) === 'tools') : [];
    if (!Array.isArray(tools)) return variants.length ? this.#blockedList(m) : text; // "Tools" is not "tools", but some parsers take it for it
    if (variants.length !== 1 || ambiguousReply(p)) return this.#blockedList(m);
    const sp = p.spans.get(tools);
    if (!sp) return text;
    // a listing that starts at a cursor this session never saw the start of is only part of the set: it is checked but never pinned
    if (ent.cursor === null || !this.listing) this.listing = { tools: new Map(), unreadable: false, partial: ent.cursor !== null };
    const L = this.listing;
    const hashed = hashTools(text, p, tools); // a definition that repeats a member name has no canonical form (h is null)
    const count = new Map();
    for (const d of tools) if (isObj(d) && typeof d.name === 'string') count.set(d.name, (count.get(d.name) || 0) + 1);
    const parts = [];
    let modified = false;
    for (let i = 0; i < tools.length; i++) {
      const d = tools[i];
      const el = text.slice(sp.elems[i][0], sp.elems[i][1]);
      if (!isObj(d) || typeof d.name !== 'string') { modified = true; this.notice(`"${this.name}" listed a tool without a name; it was not passed on`); continue; }
      const name = d.name;
      const h = hashed[i].h;
      const f = Store.flagsOf(d);
      const dup = count.get(name) > 1;
      L.tools.set(name, { h: h ?? 'unreadable', d: f.d, r: f.r, def: d });
      if (h === null || dup) L.unreadable = true;
      this.clientView.set(name, h === null || dup ? 'unreadable' : h);
      this.flags.set(name, f);
      if (!this.pin) { parts.push(el); continue; }
      const e = this.pin.tools[name];
      if (e && h !== null && !dup && e.h === h) { parts.push(el); continue; }
      modified = true;
      this.changedNames.add(name);
      if (STUB_NAME.test(name) && (e || name.length <= 64)) parts.push(this.#stub(name));
    }
    const next = res.nextCursor;
    if (!(typeof next === 'string' && next !== '')) this.#listingDone();
    return modified ? spliceArray(text, sp, parts) : text;
  }

  #listingDone() {
    const L = this.listing;
    this.listing = null;
    if (!L) return;
    this.lastLook = this.clock();
    const insH = this.instructionsSeen ? this.instructionsSeen.h : null;
    if (!this.pin) {
      if (L.partial) return; // not the whole set: nothing to pin yet
      // trust on first use: what the model was just shown is what gets pinned
      if (L.unreadable) { this.notice(`"${this.name}" shows tool definitions that cannot be read one way (a repeated name), so they were not pinned. Nothing is checked until they are.`); return; }
      try {
        const doc = this.store.writePin({ tools: L.tools, setHash: setHashOf([...L.tools.values()].map((e) => e.def)), instructions: insH });
        this.pin = { ...doc, tools: Object.assign(Object.create(null), doc.tools) };
        this.log(`first run of "${this.name}": pinned ${L.tools.size} tool definition${L.tools.size === 1 ? '' : 's'}. From now on a changed or new tool is hidden from the model and held until you run: counterseal mcp pin --name ${this.name}`);
      } catch (e) { this.notice(`could not save the pin for "${this.name}" (${String(e.message).slice(0, 120)}); nothing is checked this time`); }
      return;
    }
    const obs = { tools: L.tools, instructions: this.instructionsSeen ? { h: insH, text: this.instructionsSeen.text } : null };
    const cmp = Store.compare(this.pin, obs);
    const bad = cmp.added.length || cmp.changed.length || cmp.instructions === 'added' || cmp.instructions === 'changed' || L.unreadable;
    if (!bad) { if (!L.partial) { try { this.store.clearSeen(); } catch { /* nothing to clear */ } this.changedNames.clear(); } return; }
    const names = [...cmp.changed, ...cmp.added].slice(0, 5).map((n) => safeName(n));
    this.notice(`${cmp.changed.length + cmp.added.length || 'some'} tool definition${cmp.changed.length + cmp.added.length === 1 ? '' : 's'} of "${this.name}" changed or are new since you pinned them${names.length ? ` (${names.join(', ')}${cmp.changed.length + cmp.added.length > 5 ? ', ...' : ''})` : ''}. They are hidden from the model and calls to them wait for your passkey. Review and pin: counterseal mcp pin --name ${this.name}`);
    try { this.store.writeSeen({ tools: new Map([...L.tools].filter(([, e]) => e.h !== 'unreadable')), setHash: null, instructions: obs.instructions }); } catch (e) { this.log(`could not save what was seen: ${String(e.message).slice(0, 120)}`); }
  }

  // ---------------------------------------------------------------- the wrapper's own look at the server
  #scheduleRefresh() {
    if (!this.ready) return;
    clearTimeout(this.refreshTimer);
    this.refreshTimer = setTimeout(() => { this.#refresh().catch(() => {}); }, 300);
    if (this.refreshTimer.unref) this.refreshTimer.unref();
  }

  #internal(method, params) {
    return new Promise((resolve, reject) => {
      const id = `__cs_${++this.seq}`;
      const key = idKey(id);
      const timer = setTimeout(() => { this.pending.delete(key); reject(new Error('timeout')); }, this.refreshTimeoutMs);
      if (timer.unref) timer.unref();
      this.pending.set(key, { method, internal: true, timer, resolve });
      this.send.server(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    });
  }

  /** list the server's tools itself (never shown to the model) so a change is known even if the client does not look again */
  #refresh() {
    if (this.refreshing) return this.refreshing;
    if (!this.ready) return Promise.reject(new Error('the server is not initialised yet'));
    this.refreshing = (async () => {
      const view = new Map();
      let cursor = null, pages = 0;
      do {
        const r = await this.#internal('tools/list', cursor ? { cursor } : {});
        const res = r.message && r.message.result;
        if (!isObj(res) || !Array.isArray(res.tools)) throw new Error('no tool list');
        if (ambiguousReply(r.p)) { // the server's own answer to the wrapper can be read two ways: no tool can be trusted
          this.notice(`"${this.name}" answered the wrapper's own look at its tools with a list that can be read two ways. Calls to its tools wait for your passkey.`);
          for (const n of Object.keys(this.pin ? this.pin.tools : {})) view.set(n, 'unreadable');
          cursor = null;
          break;
        }
        const names = new Map();
        for (const d of res.tools) if (isObj(d) && typeof d.name === 'string') names.set(d.name, (names.get(d.name) || 0) + 1);
        const hashed = hashTools(r.text, r.p, res.tools);
        res.tools.forEach((d, i) => {
          if (!isObj(d) || typeof d.name !== 'string') return;
          view.set(d.name, names.get(d.name) === 1 && hashed[i].h !== null ? hashed[i].h : 'unreadable');
        });
        cursor = typeof res.nextCursor === 'string' && res.nextCursor ? res.nextCursor : null;
        pages++;
      } while (cursor && pages < 20);
      if (cursor) throw new Error('too many pages');
      this.refreshView = view;
      this.lastLook = this.clock();
      if (this.pin) {
        const odd = [];
        for (const [n, h] of view) { const e = this.pin.tools[n]; if (!e || e.h !== h) odd.push(n); }
        if (odd.length) this.notice(`"${this.name}" now shows ${odd.length} tool definition${odd.length === 1 ? '' : 's'} that differ from the pin (${odd.slice(0, 5).map(safeName).join(', ')}${odd.length > 5 ? ', ...' : ''}). Calls to them wait for your passkey. Review and pin: counterseal mcp pin --name ${this.name}`);
      }
    })().finally(() => { this.refreshing = null; });
    return this.refreshing;
  }
}

// ---------------------------------------------------------------- the command line
const out = (s) => process.stdout.write(s + '\n');
const err = (s) => process.stderr.write(s + '\n');
const fail = (m, code = 1) => { err(m); process.exit(code); };
const flag = (a, n) => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : undefined; };
const has = (a, n) => a.includes(n);

const USAGE = `usage:
  counterseal mcp wrap --name <id> [--policy <file>] [--require-pin] -- <command> [args...]
  counterseal mcp pin --name <id> [--yes] [-- <command> [args...]]
  counterseal mcp unpin --name <id>
  counterseal mcp status --name <id> [--check]
The first form is what your MCP client runs in place of the server (put "counterseal" in its command, or npx with "-y", "counterseal" first in its args).`;

function loadPolicy(name, file, env) {
  const p = Store.paths(name, env);
  const f = file || (existsSync(p.policy) ? p.policy : null);
  if (!f) return normalisePolicy();
  let text;
  try { text = readFileSync(f, 'utf8'); } catch (e) { throw new PolicyError(`${f} cannot be read: ${e.code || e.message}`); }
  return parsePolicy(text);
}

/** the line the wrapper writes to stderr */
const logger = (s) => process.stderr.write(s + '\n');

async function wrap(a, env) {
  const dd = a.indexOf('--');
  const flags = dd >= 0 ? a.slice(0, dd) : a;
  const cmd = dd >= 0 ? a.slice(dd + 1) : [];
  const name = flag(flags, '--name');
  if (!Store.validName(name) || !cmd.length) fail(USAGE, 2);
  let policy, pin;
  try { policy = loadPolicy(name, flag(flags, '--policy'), env); } catch (e) { fail(`Counterseal: the policy for "${name}" cannot be used (${e.message}). Nothing was started.`, 2); }
  try { pin = Store.readPin(name, env); } catch (e) { fail(`Counterseal: the pin for "${name}" cannot be used (${e.message}). Nothing was started. To start again from scratch: counterseal mcp unpin --name ${name}`, 3); }
  if (!pin && has(flags, '--require-pin')) fail(`Counterseal: "${name}" has no pin and --require-pin is set. Pin it first: counterseal mcp pin --name ${name} -- ${cmd.join(' ')}`, 3);
  const guard = loadGuard(env);
  const ask = guard.key ? makeAsk({ server: guard.server, key: guard.key, version: WRAP_VERSION, timeoutMs: Number(env.LEASH_MCP_TIMEOUT_MS) || 10000 }) : null;
  let child;
  try { child = spawnServer(cmd[0], cmd.slice(1), { stdio: ['pipe', 'pipe', 'inherit'], env: serverEnv(env) }); } catch (e) { fail(`Counterseal: could not start the server (${e.message}).`, 127); }
  let exiting = false, gw;
  const finish = (code) => { if (exiting) return; exiting = true; if (gw) gw.stop(); process.stdout.write('', () => process.exit(code)); };
  child.on('error', (e) => { err(`Counterseal: could not start the server (${e.code || e.message}).`); finish(127); });
  child.stdin.on('error', () => {});
  gw = new Gateway({
    name, policy, pin, ask, guardProblem: guard.problem, log: logger, cwd: process.cwd(), env,
    recheckMs: env.LEASH_MCP_RECHECK_MS !== undefined && env.LEASH_MCP_RECHECK_MS !== '' && Number.isFinite(Number(env.LEASH_MCP_RECHECK_MS)) && Number(env.LEASH_MCP_RECHECK_MS) >= 0 ? Math.min(Number(env.LEASH_MCP_RECHECK_MS), 3_600_000) : undefined, // 0: look before every call
    send: { client: (t) => process.stdout.write(t + '\n'), server: (t) => { if (!child.stdin.destroyed) child.stdin.write(t + '\n'); } },
  });
  err(pin ? `Counterseal: wrapping "${name}" (${Object.keys(pin.tools).length} pinned tools, pinned ${pin.pinnedAt || 'earlier'})` : `Counterseal: wrapping "${name}" (not pinned yet: the first complete tool list your client asks for will be pinned)`);
  if (!ask) err(`Counterseal: ${guard.problem} Held calls will be refused, not approved.`);
  const fromClient = new LineReader(MAX_LINE, (b) => { const t = lineText(b); if (t) gw.clientLine(t); else if (t === null) err('Counterseal: a line from the client was not valid UTF-8 and was dropped'); },
    () => err(`Counterseal: a line from the client was over ${MAX_LINE / 1048576} MB and was dropped`));
  const fromServer = new LineReader(MAX_LINE, (b) => { const t = lineText(b); if (t) gw.serverLine(t); else if (t === null) err('Counterseal: a line from the server was not valid UTF-8 and was dropped'); },
    () => err(`Counterseal: a line from the server was over ${MAX_LINE / 1048576} MB and was dropped`));
  process.stdin.on('data', (b) => fromClient.push(b));
  process.stdin.on('end', () => {
    fromClient.end();
    gw.idle().then(() => { try { child.stdin.end(); } catch { /* gone */ } const t = setTimeout(() => { try { child.kill(); } catch { /* gone */ } }, 5000); if (t.unref) t.unref(); });
  });
  child.stdout.on('data', (b) => fromServer.push(b));
  child.stdout.on('end', () => fromServer.end());
  child.on('close', (code, signal) => finish(code ?? (signal ? 1 : 0)));
  process.stdout.on('error', () => finish(1));
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => { try { child.kill(sig); } catch { /* gone */ } });
}

// ---------------------------------------------------------------- looking at a server directly (mcp pin -- <command>)
/** start the server, say hello, list every page of its tools; { tools: Map, instructions } */
export async function introspect(cmd, env = process.env, { timeoutMs = 30000 } = {}) {
  const child = spawnServer(cmd[0], cmd.slice(1), { stdio: ['pipe', 'pipe', 'inherit'], env: serverEnv(env) });
  const waits = new Map();
  let seq = 0;
  const reader = new LineReader(MAX_LINE, (b) => {
    const t = lineText(b);
    if (!t) return;
    let p; try { p = parseStrict(t, { track: 4 }); } catch { return; }
    if (isObj(p.value) && typeof p.value.method !== 'string') { const w = waits.get(idKey(p.value.id)); if (w) { waits.delete(idKey(p.value.id)); w({ message: p.value, text: t, p }); } }
  }, () => {});
  child.stdout.on('data', (b) => reader.push(b));
  child.stdin.on('error', () => {});
  const dead = new Promise((_, rej) => { child.on('error', (e) => rej(new Error(`could not start the server (${e.code || e.message})`))); child.on('close', () => rej(new Error('the server exited before it answered'))); });
  dead.catch(() => {});
  const write = (o) => child.stdin.write(JSON.stringify(o) + '\n');
  const request = (method, params) => Promise.race([dead, new Promise((resolve, reject) => {
    const id = ++seq;
    const t = setTimeout(() => { waits.delete(idKey(id)); reject(new Error(`the server did not answer ${method} in ${timeoutMs / 1000} seconds`)); }, timeoutMs);
    waits.set(idKey(id), (r) => { clearTimeout(t); resolve(r); });
    write({ jsonrpc: '2.0', id, method, params });
  })]);
  try {
    const init = await request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'leashcli-mcp-pin', version: WRAP_VERSION } });
    if (!isObj(init.message.result)) throw new Error('the server refused to start a session');
    const initSpan = init.p.spans.get(init.message.result);
    const insNames = initSpan ? initSpan.members.filter((x) => fold(x.key) === 'instructions') : [];
    if (ambiguousReply(init.p) || insNames.length > 1 || insNames.some((x) => x.key !== 'instructions')) throw new Error('the answer of the server to initialize can be read two ways (a repeated or oddly cased name)');
    const ins = Object.hasOwn(init.message.result, 'instructions') ? init.message.result.instructions : undefined;
    write({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const tools = new Map();
    let cursor = null, pages = 0, unreadable = false;
    do {
      const r = await request('tools/list', cursor ? { cursor } : {});
      const res = r.message.result;
      if (!isObj(res) || !Array.isArray(res.tools)) throw new Error('the server did not return a tool list');
      const resSpan = r.p.spans.get(res);
      if (ambiguousReply(r.p) || !resSpan || resSpan.members.filter((x) => fold(x.key) === 'tools').length !== 1) throw new Error('the tool list can be read two ways (a repeated or oddly cased name)');
      const counts = new Map();
      for (const d of res.tools) if (isObj(d) && typeof d.name === 'string') counts.set(d.name, (counts.get(d.name) || 0) + 1);
      const hashed = hashTools(r.text, r.p, res.tools);
      res.tools.forEach((d, i) => {
        if (!isObj(d) || typeof d.name !== 'string') throw new Error('a tool in the list has no name');
        const f = Store.flagsOf(d);
        const h = counts.get(d.name) === 1 && !tools.has(d.name) ? hashed[i].h : null;
        if (h === null) unreadable = true;
        tools.set(d.name, { h: h ?? 'unreadable', d: f.d, r: f.r, def: d });
      });
      cursor = typeof res.nextCursor === 'string' && res.nextCursor ? res.nextCursor : null;
      pages++;
    } while (cursor && pages < 50);
    if (cursor) throw new Error('the server has too many pages of tools');
    if (unreadable) throw new Error('some tool definitions repeat a member name or a tool name, so they have no single reading; they cannot be pinned');
    return { tools, instructions: { h: instructionsHash(typeof ins === 'string' ? ins : null), text: typeof ins === 'string' ? ins : null }, setHash: setHashOf([...tools.values()].map((e) => e.def)) };
  } finally {
    try { child.stdin.end(); } catch { /* gone */ }
    const t = setTimeout(() => { try { child.kill(); } catch { /* gone */ } }, 1500);
    if (t.unref) t.unref();
  }
}

// ---------------------------------------------------------------- pin, unpin, status
async function confirmTerminal(yes) {
  if (yes) { err('Counterseal: --yes skips the question. Run this yourself, in your own terminal: an agent that can run it can pin anything.'); return true; }
  if (!process.stdin.isTTY) fail('Counterseal: pinning needs your answer in a terminal. Run it yourself in a terminal, or add --yes.', 4);
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const ans = await new Promise((r) => rl.question('Type "pin" to trust these definitions, anything else to cancel: ', r));
  rl.close();
  return ans.trim() === 'pin';
}

async function confirmPasskey(name, cmp, obs, env) {
  const g = loadGuard(env);
  if (!g.key) fail(`Counterseal: ${g.problem} (this server's policy says repin: "passkey")`, 4);
  const ask = makeAsk({ server: g.server, key: g.key, version: WRAP_VERSION });
  const list = (a) => a.slice(0, 20);
  const detail = canonicalize({ added: list(cmp.added), changed: list(cmp.changed), instructions: cmp.instructions, new_tools_sha256: sha256(canonicalize([...obs.tools].map(([n, e]) => [n, e.h]).sort())), pin: name, removed: list(cmp.removed) });
  const c = await ask.create({ kind: 'tool', agent: 'mcp', rule: 'mcp.repin', why: WHY['mcp.repin'], summary: `${name}: pin ${cmp.added.length} new, ${cmp.changed.length} changed`.slice(0, 200), detail: detail.slice(0, MAX_DETAIL), context: { session: name }, map: MCP_POLICY_VERSION });
  if (c.status !== 200 && c.status !== 202) fail(`Counterseal: ${failureText(c)}`, 4);
  const r = readApproval(c.body);
  if (!r) fail('Counterseal: the server sent an answer this command does not understand.', 4);
  err(`Counterseal: waiting for your passkey${r.url ? ' at ' + r.url : ''} (up to 9 minutes)...`);
  const until = Date.now() + 9 * 60_000;
  let st = r.status;
  while (st !== 'approved') {
    if (Date.now() > until) fail('Counterseal: not approved in time. Nothing was pinned.', 4);
    const g2 = await ask.get(r.id, 20);
    if (g2.status !== 200) { if (g2.status === 429) { await new Promise((ok) => setTimeout(ok, 3000)); continue; } fail(`Counterseal: ${failureText(g2)}`, 4); }
    st = g2.body.status;
    if (st === 'denied') fail(`Counterseal: your human denied it${g2.body.deny_reason ? `: ${cleanReason(g2.body.deny_reason)}` : ''}. Nothing was pinned.`, 4);
    if (st === 'expired' || st === 'used') fail('Counterseal: the approval ended. Nothing was pinned.', 4);
  }
  const u = await ask.use(r.id, r.hash);
  if (u.status !== 200) fail(`Counterseal: ${failureText(u)}`, 4);
  return true;
}

async function pinCommand(a, env) {
  const dd = a.indexOf('--');
  const flags = dd >= 0 ? a.slice(0, dd) : a;
  const cmd = dd >= 0 ? a.slice(dd + 1) : [];
  const name = flag(flags, '--name');
  if (!Store.validName(name)) fail(USAGE, 2);
  let pin, policy;
  try { pin = Store.readPin(name, env); policy = loadPolicy(name, flag(flags, '--policy'), env); } catch (e) { fail(`Counterseal: ${e.message}`, 3); }
  let obs;
  if (cmd.length) {
    try { obs = await introspect(cmd, env); } catch (e) { fail(`Counterseal: ${e.message}. Nothing was pinned.`, 5); }
  } else {
    let seen; try { seen = Store.readSeen(name, env); } catch (e) { fail(`Counterseal: ${e.message}`, 3); }
    if (!seen) fail(`Counterseal: nothing waits for review. Run the server through "counterseal mcp wrap" first, or give the command: counterseal mcp pin --name ${name} -- <command> [args...]`, 5);
    obs = { tools: seen.tools, instructions: seen.instructions, setHash: seen.setHash };
    for (const e of obs.tools.values()) if (e.h === 'unreadable') fail('Counterseal: the server showed definitions that cannot be read one way, so they cannot be pinned.', 5);
  }
  const cmp = Store.compare(pin, obs);
  out(`${name}: ${obs.tools.size} tool${obs.tools.size === 1 ? '' : 's'} now; ${cmp.same} unchanged, ${cmp.changed.length} changed, ${cmp.added.length} new, ${cmp.removed.length} removed${cmp.instructions ? `, instructions ${cmp.instructions}` : ''}${pin ? '' : ' (nothing was pinned before)'}.`);
  if (cmp.lines.length) { out(''); for (const l of cmp.lines) out(l); out(''); } else if (!pin) { out(''); for (const n of [...obs.tools.keys()].sort()) out(`  ${Store.escapeText(n)}`); out(''); }
  if (pin && !cmp.added.length && !cmp.changed.length && !cmp.instructions) {
    if (!cmp.removed.length) { out('Nothing changed. The pin stays as it is.'); Store.clearSeen(name, env); return; }
  }
  const ok = policy.repin === 'passkey' ? await confirmPasskey(name, cmp, obs, env) : await confirmTerminal(has(flags, '--yes'));
  if (!ok) fail('Counterseal: cancelled. Nothing was pinned.', 4);
  const defs = [...obs.tools.values()].map((e) => e.def);
  const setHash = obs.setHash ?? (defs.every((d) => d !== undefined) ? setHashOf(defs) : null);
  const doc = Store.writePin(name, { tools: obs.tools, setHash, instructions: obs.instructions ? obs.instructions.h ?? null : null }, env);
  Store.clearSeen(name, env);
  out(`Pinned ${Object.keys(doc.tools).length} tool definition${Object.keys(doc.tools).length === 1 ? '' : 's'} for "${name}". Restart the MCP server in your client so the wrapper picks up the new pin.`);
}

async function statusCommand(a, env) {
  const name = flag(a, '--name');
  if (!Store.validName(name)) fail(USAGE, 2);
  const p = Store.paths(name, env);
  let pin, seen, policy;
  try { pin = Store.readPin(name, env); seen = Store.readSeen(name, env); policy = loadPolicy(name, flag(a, '--policy'), env); } catch (e) { fail(`Counterseal: ${e.message}`, 3); }
  out(`${name}`);
  out(pin ? `  pinned: ${Object.keys(pin.tools).length} tools${pin.pinnedAt ? ' on ' + pin.pinnedAt : ''}; set ${pin.setHash ? pin.setHash.slice(0, 16) : 'n/a'}; instructions ${pin.instructions ? 'pinned' : 'none'}   (${p.pin})` : `  not pinned yet (the first complete tool list a client asks for through the wrapper is pinned)   (${p.pin})`);
  if (seen) { const cmp = Store.compare(pin, { tools: seen.tools, instructions: seen.instructions }); out(`  waiting for review: ${cmp.added.length} new, ${cmp.changed.length} changed${cmp.instructions ? `, instructions ${cmp.instructions}` : ''}   (counterseal mcp pin --name ${name})`); }
  out(`  policy: ${existsSync(p.policy) ? p.policy : 'default'}; hold ${policy.hold.length} pattern${policy.hold.length === 1 ? '' : 's'}, allow ${policy.allow.length}, SQL arguments ${policy.sqlArgs.length ? policy.sqlArgs.join(', ') : 'not checked'}, trustAnnotations ${policy.trustAnnotations}, repin ${policy.repin}`);
  const g = loadGuard(env);
  out(g.key ? `  guard key: set; asks ${g.server}` : `  guard key: NOT SET. ${g.problem}`);
  if (has(a, '--check') && g.key) {
    const r = await makeAsk({ server: g.server, key: g.key, version: WRAP_VERSION }).get('0'.repeat(24), 0);
    out(r.status === 404 ? '  server: reachable, the guard key works' : r.status === 423 ? '  server: Counterseal is FROZEN: ' + failureText(r) : r.status === 401 ? '  server: the guard key was refused (revoked or ended)' : r.status === 0 ? '  server: could not be reached' : `  server: answered ${r.status}`);
  }
}

export async function main(argv, env = process.env) {
  const sub = argv[0], rest = argv.slice(1);
  // --help or -h before a "--" (what follows belongs to the server): the usage, nothing started, pinned or removed
  const dd = argv.indexOf('--');
  if ((dd < 0 ? argv : argv.slice(0, dd)).some((x) => x === '--help' || x === '-h')) { out(USAGE); return; }
  try {
    if (sub === 'wrap') return await wrap(rest, env);
    if (sub === 'pin') return await pinCommand(rest, env);
    if (sub === 'status') return await statusCommand(rest, env);
    if (sub === 'unpin') {
      const name = flag(rest, '--name');
      if (!Store.validName(name)) fail(USAGE, 2);
      const n = Store.removePin(name, env);
      out(`Removed ${n} file${n === 1 ? '' : 's'}. The next run of "${name}" through the wrapper pins what its server shows then.`);
      return;
    }
  } catch (e) {
    fail(`Counterseal: ${e && e.message ? e.message : e}`, 1);
  }
  fail(USAGE, 2);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main(process.argv.slice(2));
