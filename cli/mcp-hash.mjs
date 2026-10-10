// The tool definition hash, version 1, for the MCP wrapper (counterseal mcp wrap). Zero dependencies.
//
// The recipe is mcp-pin's published TOOL_DEFINITION_HASH (https://github.com/GautamTalksDev/mcp-pin, docs/TOOL_DEFINITION_HASH.md,
// MIT, version 1): a definition is hashed whole, as the server sent it, under the JSON Canonicalization Scheme (RFC 8785),
// so a client, a gateway, a registry and a lockfile can agree on what "the same definitions as approved" means. This is an
// independent implementation of that recipe; it passes mcp-pin's test vectors (server/test/mcp-wrap.test.js runs them).
//
// What the hash covers: every member of a definition (name, title, description, inputSchema, outputSchema, annotations,
// icons, _meta, and any member added to MCP later). What it does not: what a tool does when called, the server's code, or who
// wrote it. A changed hash means a person should look.
import { createHash } from 'node:crypto';
import { parseStrict } from './mcp-json.mjs';

export class HashError extends Error {}

export const sha256 = (s) => createHash('sha256').update(String(s), 'utf8').digest('hex');

/** RFC 8785: members sorted by UTF-16 code unit, no whitespace, numbers and strings as ECMAScript writes them */
export function canonicalize(v) {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean': return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new HashError('a number outside the double range has no canonical form');
      return JSON.stringify(v);
    case 'string': return JSON.stringify(v); // an unpaired surrogate is written as a lower case \u escape
    case 'object':
      if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
      return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
    default: throw new HashError('a ' + typeof v + ' has no JSON form');
  }
}

/** the hash of one definition, from a parsed value */
export const definitionHash = (def) => sha256(canonicalize(def));

/** the hash of one definition, from its JSON text; a repeated member name anywhere means no canonical form (null) */
export function definitionHashOfText(text) {
  const p = parseStrict(text);
  return p.exactDupes.size ? null : definitionHash(p.value);
}

/** the set hash of a whole listing (every page together); definitions without a string name have none (null) */
export function setHash(defs) {
  const per = [];
  for (const d of defs) {
    if (!d || typeof d !== 'object' || Array.isArray(d) || typeof d.name !== 'string') return null;
    per.push({ name: d.name, hash: definitionHash(d) });
  }
  per.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
  return sha256(per.map((t) => `${t.name}:${t.hash}`).join('\n'));
}

/** the hash of the server's instructions text exactly as received; a server with none has none (null) */
export const instructionsHash = (text) => (typeof text === 'string' ? sha256(text) : null);
