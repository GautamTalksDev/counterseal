// What the MCP wrapper (leashcli mcp wrap) keeps on disk, and how it shows a server's definitions to a person. Zero dependencies.
//
// Per wrapped server, under ~/.config/leash/mcp/ (or $XDG_CONFIG_HOME/leash/mcp, or $LEASH_MCP_DIR):
//   <name>.json       your policy (optional; see mcp-policy.mjs)
//   <name>.pin.json   the pin: the hash of every tool definition you approved, and the definitions themselves (up to 512 KB)
//   <name>.seen.json  what the server showed last, when that differs from the pin: it waits here for `leashcli mcp pin`
// A pin file that exists but cannot be read is an error, never a fresh start: a damaged pin must not turn into "trust whatever
// the server says now". All files are written 0600 in a 0700 folder. Anything here can be edited by the agent if it runs as you:
// the pin is a seatbelt, not a sandbox.
import { readFileSync, writeFileSync, mkdirSync, renameSync, chmodSync, existsSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseStrict, isObj } from './mcp-json.mjs';
import { canonicalize } from './mcp-hash.mjs';

export class StoreError extends Error {}

export const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
export const validName = (n) => typeof n === 'string' && NAME_RE.test(n);

export const cfgDir = (env = process.env) => join(env.XDG_CONFIG_HOME || join(env.HOME || env.USERPROFILE || homedir(), '.config'), 'leash');
export const mcpDir = (env = process.env) => env.LEASH_MCP_DIR || join(cfgDir(env), 'mcp');
export const paths = (name, env = process.env) => {
  if (!validName(name)) throw new StoreError('the name is 1 to 64 letters, digits, "." "_" or "-", starting with a letter or digit');
  const d = mcpDir(env);
  return { dir: d, policy: join(d, `${name}.json`), pin: join(d, `${name}.pin.json`), seen: join(d, `${name}.seen.json`) };
};

const HASH = /^[0-9a-f]{64}$/;
const MAX_FILE = 4 * 1024 * 1024;
const MAX_STORED_DEFS = 512 * 1024;

export function writeAtomic(path, text, dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { chmodSync(dir, 0o700); } catch { /* not on every file system */ }
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, text, { mode: 0o600 });
  try { chmodSync(tmp, 0o600); } catch { /* not on every file system */ }
  renameSync(tmp, path);
}

function readJsonFile(path, what) {
  if (!existsSync(path)) return null;
  let text;
  try { text = readFileSync(path, 'utf8'); } catch (e) { throw new StoreError(`${what} cannot be read: ${e.code || e.message}`); }
  if (text.length > MAX_FILE) throw new StoreError(`${what} is over ${MAX_FILE / 1048576} MB`);
  let p;
  try { p = parseStrict(text); } catch (e) { throw new StoreError(`${what} is damaged: ${e.message}`); }
  if (p.exactDupes.size) throw new StoreError(`${what} repeats a name, so it can be read two ways`);
  return p.value;
}

/** annotation hints from a definition: true or false when the server said so with a boolean, else null */
export function flagsOf(def) {
  const a = isObj(def) && isObj(def.annotations) ? def.annotations : {};
  return { d: typeof a.destructiveHint === 'boolean' ? a.destructiveHint : null, r: typeof a.readOnlyHint === 'boolean' ? a.readOnlyHint : null };
}

// ---------------------------------------------------------------- the pin
/** the pin, or null when there is none yet; a pin that is damaged throws */
export function readPin(name, env = process.env) {
  const p = paths(name, env);
  const v = readJsonFile(p.pin, 'the pin file');
  if (v === null) return null;
  if (!isObj(v) || v.v !== 1 || !isObj(v.tools) || (v.instructions !== null && !HASH.test(String(v.instructions)))) throw new StoreError('the pin file is not a pin this version understands');
  const tools = Object.create(null);
  for (const [n, e] of Object.entries(v.tools)) {
    if (!isObj(e) || !HASH.test(String(e.h)) || ![true, false, null].includes(e.d) || ![true, false, null].includes(e.r)) throw new StoreError('the pin file has a damaged entry');
    tools[n] = { h: e.h, d: e.d, r: e.r, ...(isObj(e.def) ? { def: e.def } : {}) };
  }
  return { v: 1, name: v.name, pinnedAt: typeof v.pinnedAt === 'string' ? v.pinnedAt : null, tools, setHash: HASH.test(String(v.setHash)) ? v.setHash : null, instructions: v.instructions ?? null };
}

/** write a pin from what was observed: { tools: Map(name -> {h, def, d, r}), setHash, instructions: hash|null } */
export function writePin(name, obs, env = process.env, now = new Date()) {
  const p = paths(name, env);
  let stored = 0;
  const tools = {};
  for (const [n, e] of [...obs.tools].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const text = e.def === undefined ? '' : canonicalize(e.def);
    const keep = e.def !== undefined && stored + text.length <= MAX_STORED_DEFS;
    if (keep) stored += text.length;
    tools[n] = { h: e.h, d: e.d ?? null, r: e.r ?? null, ...(keep ? { def: e.def } : {}) };
  }
  const doc = { v: 1, name, pinnedAt: now.toISOString(), tools, setHash: obs.setHash ?? null, instructions: obs.instructions ?? null };
  writeAtomic(p.pin, JSON.stringify(doc, null, 2) + '\n', p.dir);
  return doc;
}

export function removePin(name, env = process.env) {
  const p = paths(name, env);
  let n = 0;
  for (const f of [p.pin, p.seen]) if (existsSync(f)) { unlinkSync(f); n++; }
  return n;
}

// ---------------------------------------------------------------- what the server showed that the pin does not have
export function readSeen(name, env = process.env) {
  const v = readJsonFile(paths(name, env).seen, 'the seen file');
  if (v === null) return null;
  if (!isObj(v) || v.v !== 1 || !isObj(v.tools)) throw new StoreError('the seen file is not one this version understands');
  const tools = new Map();
  for (const [n, e] of Object.entries(v.tools)) {
    if (!isObj(e) || !HASH.test(String(e.h))) throw new StoreError('the seen file has a damaged entry');
    tools.set(n, { h: e.h, d: e.d ?? null, r: e.r ?? null, ...(isObj(e.def) ? { def: e.def } : {}) });
  }
  const ins = isObj(v.instructions) && (v.instructions.h === null || HASH.test(String(v.instructions.h))) ? v.instructions : null;
  return { at: typeof v.at === 'string' ? v.at : null, tools, instructions: ins, setHash: HASH.test(String(v.setHash)) ? v.setHash : null };
}

export function writeSeen(name, obs, env = process.env, now = new Date()) {
  const p = paths(name, env);
  let stored = 0;
  const tools = {};
  for (const [n, e] of obs.tools) {
    const text = e.def === undefined ? '' : canonicalize(e.def);
    const keep = e.def !== undefined && stored + text.length <= MAX_STORED_DEFS;
    if (keep) stored += text.length;
    tools[n] = { h: e.h, d: e.d ?? null, r: e.r ?? null, ...(keep ? { def: e.def } : {}) };
  }
  const ins = obs.instructions && typeof obs.instructions.text === 'string' ? { h: obs.instructions.h, text: obs.instructions.text.slice(0, 16384) } : obs.instructions ? { h: obs.instructions.h } : null;
  writeAtomic(p.seen, JSON.stringify({ v: 1, at: now.toISOString(), tools, setHash: obs.setHash ?? null, instructions: ins }, null, 2) + '\n', p.dir);
}

export function clearSeen(name, env = process.env) {
  const f = paths(name, env).seen;
  if (existsSync(f)) unlinkSync(f);
}

// ---------------------------------------------------------------- showing a server's text to a person
// A definition is attacker-controlled text. Terminal escape codes, carriage returns and direction overrides in it can erase or
// disguise the very lines a reviewer is reading, so every control, invisible and direction character is shown as <U+XXXX>.
// A line break or tab is shown as \n or \t, so no text from a server can start a line of its own in what a person reviews.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/g;
export const escapeText = (t) => String(t).replace(UNSAFE, (c) => (c === '\n' ? '\\n' : c === '\t' ? '\\t' : `<U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}>`));
export function shown(t, max = 1200) {
  const s = escapeText(t);
  return s.length > max ? `${s.slice(0, max)} ... (${s.length - max} more characters)` : s;
}

const J = (v) => { try { return canonicalize(v); } catch { return '(no JSON form)'; } };

/** the lines that say how a definition differs from the pinned one (member by member), for a person to read */
export function diffDefinition(oldDef, newDef) {
  if (!isObj(newDef)) return ['  (no readable definition)'];
  if (!isObj(oldDef)) return ['  the pinned text was not stored, so only the new definition is shown:', ...Object.keys(newDef).sort().map((k) => `  + ${escapeText(k)}: ${shown(J(newDef[k]))}`)];
  const lines = [];
  for (const k of [...new Set([...Object.keys(oldDef), ...Object.keys(newDef)])].sort()) {
    const a = Object.hasOwn(oldDef, k), b = Object.hasOwn(newDef, k);
    if (a && b && J(oldDef[k]) === J(newDef[k])) continue;
    if (!a) lines.push(`  + ${escapeText(k)}: ${shown(J(newDef[k]))}`);
    else if (!b) lines.push(`  - ${escapeText(k)}: ${shown(J(oldDef[k]))}`);
    else lines.push(`  ~ ${escapeText(k)}:`, `      was: ${shown(J(oldDef[k]))}`, `      now: ${shown(J(newDef[k]))}`);
  }
  return lines;
}

/**
 * Compare a pin with what the server showed. { added, removed, changed, same, instructions } with the names, and `lines` for a person.
 * @param {object|null} pin  from readPin
 * @param {{tools: Map, instructions: object|null}} obs
 */
export function compare(pin, obs) {
  const added = [], changed = [], removed = [];
  let same = 0;
  for (const [n, e] of obs.tools) {
    const old = pin && pin.tools[n];
    if (!old) added.push(n); else if (old.h !== e.h) changed.push(n); else same++;
  }
  if (pin) for (const n of Object.keys(pin.tools)) if (!obs.tools.has(n)) removed.push(n);
  const insNow = obs.instructions ? obs.instructions.h ?? null : null;
  const instructions = pin ? (insNow !== pin.instructions ? (insNow === null ? 'removed' : pin.instructions === null ? 'added' : 'changed') : null) : null;
  const lines = [];
  for (const n of added.sort()) {
    lines.push(`NEW tool: ${escapeText(n)}`);
    const e = obs.tools.get(n);
    if (e.def !== undefined) lines.push(...(isObj(e.def) ? Object.keys(e.def).sort().map((k) => `  + ${escapeText(k)}: ${shown(J(e.def[k]))}`) : ['  (no readable definition)']));
  }
  for (const n of changed.sort()) {
    lines.push(`CHANGED tool: ${escapeText(n)}`);
    lines.push(...diffDefinition(pin.tools[n].def, obs.tools.get(n).def));
  }
  for (const n of removed.sort()) lines.push(`REMOVED tool: ${escapeText(n)} (nothing to review: it can no longer be called)`);
  if (instructions) {
    lines.push(`INSTRUCTIONS ${instructions}: the text the server tells the model about itself`);
    if (obs.instructions && typeof obs.instructions.text === 'string') lines.push(`      now: ${shown(obs.instructions.text, 2000)}`);
  }
  return { added, changed, removed, same, instructions, lines };
}
