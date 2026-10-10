#!/usr/bin/env node
// The name every install line and command example uses for the CLI: one constant, BRAND.cliInstall in
// server/src/brand.js ("counterseal" once that package is on npm; "leashcli" until then).
//   node scripts/cli-name.mjs           rewrite every install line and command mention to BRAND.cliInstall
//   node scripts/cli-name.mjs --check   exit 1 if any still names the other one (server/test/brand.test.js runs this)
// It touches only command lines: `npx leashcli ...`, `"-y", "leashcli"` in MCP configs, "leashcli login" and the other
// subcommands in prose, and the CLI's own PKG constant. History ("the published leashcli 0.1.1") and package names in
// package.json files are left alone. Order to ship (docs/DEPLOY.md): publish the counterseal package first, then deploy.
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BRAND } from '../server/src/brand.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const NAMES = ['counterseal', 'leashcli'];
const SUB = 'login|logout|add|creds|tokens|token|revoke|freeze|holds|watch|agent-key|agent-keys|mcp|guard';
const TEXT = /\.(html|js|mjs|md)$/;
const SKIP = new Set(['fonts', 'img', 'media', 'node_modules', '.git', 'fixtures', 'test']);
// generated copies are rewritten by scripts/sync-guard.mjs from cli/; the site's SDK copies by rebrand.mjs
const GENERATED = new Set(['site/public/brand.js', 'site/public/receipts-sdk.js', 'site/public/websig.js']);

export function files() {
  const out = [];
  const walk = (dir) => { for (const n of readdirSync(dir)) { if (SKIP.has(n)) continue; const p = join(dir, n); if (statSync(p).isDirectory()) walk(p); else if (TEXT.test(n)) out.push(p); } };
  for (const d of ['site/public', 'docs', 'cli', 'plugins', 'server/src']) walk(join(ROOT, d));
  for (const f of ['README.md', 'SECURITY.md']) out.push(join(ROOT, f));
  return out.filter((p) => !GENERATED.has(relative(ROOT, p).replaceAll('\\', '/')));
}

/** the text with every command mention naming `name` */
export function rewrite(s, name) {
  return s
    // (a pinned version, npx leashcli@0.1.1, names that exact package on purpose and is left alone)
    .replace(/\bnpx (-y )?(?:leashcli|counterseal)\b(?!@)/g, (_, y) => `npx ${y || ''}${name}`)
    .replace(/(["'])-y\1, (["'])(?:leashcli|counterseal)\2/g, (_, q1, q2) => `${q1}-y${q1}, ${q2}${name}${q2}`)
    .replace(new RegExp(`\\b(?:leashcli|counterseal)(?= (?:${SUB})\\b)`, 'g'), name)
    .replace(/const PKG = '(?:leashcli|counterseal)'/, `const PKG = '${name}'`);
}

export function main(check, name = BRAND.cliInstall) {
  if (!NAMES.includes(name)) { console.error(`BRAND.cliInstall must be one of ${NAMES.join(', ')}`); return 1; }
  const stale = [];
  for (const f of files()) {
    const s = readFileSync(f, 'utf8'), t = rewrite(s, name);
    if (s === t) continue;
    if (check) stale.push(relative(ROOT, f)); else writeFileSync(f, t);
  }
  if (check && stale.length) { console.error(`install lines out of step with BRAND.cliInstall (${name}): ${stale.join(', ')}; run node scripts/cli-name.mjs`); return 1; }
  console.log(check ? `install lines name ${name}` : `install lines now name ${name}`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) process.exitCode = main(process.argv.includes('--check'));
