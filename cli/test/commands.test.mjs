// The command line tells help from a typo: help, --help, -h and no command print the help and exit 0; an unknown
// command (or guard subcommand) names itself on stderr and exits 2, so `counterseal tokns && deploy` stops there.
// The plugin runs pinned copies of these files (scripts/sync-guard.mjs), so they are checked too.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLIS = ['../leash.mjs', '../../plugins/counterseal/scripts/leash.mjs'].map((p) => fileURLToPath(new URL(p, import.meta.url)));
const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function run(cli, args) {
  // an empty config folder, so nothing on this machine is read or written
  const dir = mkdtempSync(join(tmpdir(), 'cs-commands-'));
  try {
    return spawnSync(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH, HOME: dir, XDG_CONFIG_HOME: dir }, encoding: 'utf8', timeout: 20_000 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

for (const cli of CLIS) {
  const which = cli.includes('plugins') ? 'plugin copy' : 'cli';
  test(`${which}: help, --help, -h and no command print the help, named counterseal, and exit 0`, () => {
    for (const args of [['help'], ['--help'], ['-h'], []]) {
      const name = args.join(' ') || '(no command)';
      const r = run(cli, args);
      assert.equal(r.status, 0, `${name}: ${r.stderr}`);
      assert.ok(r.stdout.startsWith(`counterseal ${VERSION}\n`), `${name}: ${r.stdout.slice(0, 40)}`);
      assert.match(r.stdout, /guard install\|uninstall\|status\|check\|map/);
      assert.equal(r.stderr, '');
    }
  });

  test(`${which}: an unknown command exits 2, names the command on stderr and prints nothing on stdout`, () => {
    for (const bad of ['bogus', 'tokns', 'gaurd', 'HELP', '--nope']) {
      const r = run(cli, [bad, 'install']);
      assert.equal(r.status, 2, `${bad}: exit ${r.status}`);
      assert.equal(r.stdout, '', `${bad}: nothing on stdout`);
      assert.ok(r.stderr.startsWith(`counterseal: unknown command "${bad}"\n`), r.stderr.slice(0, 80));
      assert.match(r.stderr, new RegExp(`\\ncounterseal ${esc(VERSION)}\\n`), 'the help follows on stderr');
    }
  });

  test(`${which}: --version still prints the version and exits 0`, () => {
    const r = run(cli, ['--version']);
    assert.equal(r.status, 0);
    assert.equal(r.stdout.trim(), VERSION);
  });

  test(`${which}: guard help exits 0; an unknown guard subcommand exits 2 on stderr`, () => {
    for (const args of [['guard'], ['guard', 'help'], ['guard', '--help'], ['guard', '-h']]) {
      const r = run(cli, args);
      assert.equal(r.status, 0, args.join(' '));
      assert.match(r.stdout, /^counterseal guard /);
      assert.match(r.stdout, /\n {2}install /);
    }
    const r = run(cli, ['guard', 'instal']);
    assert.equal(r.status, 2);
    assert.equal(r.stdout, '');
    assert.ok(r.stderr.startsWith('counterseal guard: unknown command "instal"\n'), r.stderr.slice(0, 80));
    assert.match(r.stderr, /\n {2}install /);
  });
}
