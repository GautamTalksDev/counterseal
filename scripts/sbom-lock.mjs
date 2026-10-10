#!/usr/bin/env node
// Writes the package-lock.json that `npm sbom --package-lock-only` reads, without running `npm install` (CI and the
// release never install anything; OpenSSF Scorecard counts an install without a lockfile as an unpinned dependency).
//   node scripts/sbom-lock.mjs cli                                   the CLI: no dependencies
//   node scripts/sbom-lock.mjs packages/leashcli manifest.json           the alias: its one dependency, with the tarball and
//                                                                    integrity npm itself reports (npm view counterseal@V --json)
// The caller removes the file after the SBOM is written.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export function lockFor(pkg, dists = {}) {
  const top = { name: pkg.name, version: pkg.version };
  for (const k of ['license', 'bin', 'engines']) if (pkg[k]) top[k] = pkg[k];
  const deps = pkg.dependencies || {};
  if (Object.keys(deps).length) top.dependencies = deps;
  const packages = { '': top };
  for (const [name, range] of Object.entries(deps)) {
    const m = dists[name] || {}, d = m.dist || {};
    if (!/^\d+\.\d+\.\d+$/.test(range) || !/^sha512-[A-Za-z0-9+/=]+$/.test(d.integrity || '') || !String(d.tarball || '').startsWith('https://registry.npmjs.org/')) {
      throw new Error(`${name}: an exact version and npm's own tarball and sha512 integrity are needed`);
    }
    packages[`node_modules/${name}`] = { version: range, resolved: d.tarball, integrity: d.integrity, ...Object.fromEntries(['license', 'bin', 'engines'].filter((k) => m[k]).map((k) => [k, m[k]])) };
  }
  return { name: pkg.name, version: pkg.version, lockfileVersion: 3, requires: true, packages };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('sbom-lock.mjs')) {
  const [dir, distFile] = process.argv.slice(2);
  if (!dir) { console.error('usage: node scripts/sbom-lock.mjs <package dir> [manifest.json]'); process.exit(2); }
  const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  const dists = {};
  if (distFile) { const names = Object.keys(pkg.dependencies || {}); if (names.length !== 1) { console.error('the manifest describes one dependency'); process.exit(2); } dists[names[0]] = JSON.parse(readFileSync(distFile, 'utf8')); }
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(lockFor(pkg, dists), null, 2) + '\n');
  console.log(`wrote ${join(dir, 'package-lock.json')}`);
}
