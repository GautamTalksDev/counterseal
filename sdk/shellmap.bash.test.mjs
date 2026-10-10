// The shell map against a real shell. Two differential tests with generated commands and bash as the oracle:
//  1. words: a command's words come out of the map's evaluator exactly as bash makes them (quotes, escapes, $'..',
//     parameter expansion, brace expansion, splitting, substitutions), for everything the evaluator can tell;
//  2. effect: wherever bash really runs `terraform destroy` (a stub on PATH logs its arguments), the map holds the
//     command, in 70 shapes (wrappers, loops, pipes, nested shells, eval, here-documents) and 40 spellings of the
//     program and the subcommand; and a quoted copy of the same text (echo, git commit -m, grep, here-document) is not held.
// Only stubs, echo, printf and cat run. Skipped without bash (Windows). SHELLMAP_FUZZ_N sets how many of each (default 300).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync, readFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classify } from './shellmap.mjs';

const HAVE_BASH = process.platform !== 'win32' && spawnSync('bash', ['--version']).status === 0;
const N = Math.max(10, Number(process.env.SHELLMAP_FUZZ_N) || 300);
const opts = { skip: HAVE_BASH ? false : 'bash is not available here' };

function rng(seed) {
  let s = seed >>> 0;
  return () => { s = (s + 0x6D2B79F5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const shq = (x) => `'${x.replace(/'/g, `'\\''`)}'`;
const dq = (x) => `"${x.replace(/(["\\$`])/g, '\\$1')}"`;

// ---------------------------------------------------------------- 1. words
const VARS = ['V', 'S', 'W', 'E', 'SP', 'P', 'N', 'U', 'L'];
const MODS = [
  ':-x', ':-', '-x', ':-a b', ':-"a b"', ":-'q'", ':=x', '=x', ':+alt', '+alt', ':0:3', ':2', ': -3', ':1:-2', ':0', ':100', ':1:100',
  '#t', '##t*r', '#*/', '##*/', '%m', '%%a*', '%.*', '%%.*', '%/*', '%%/*', '#?', '##?', '%?', '%%?', '#[a-z]', '#[!a-z]', '#', '%',
  '/r/R', '//r/R', '/#t/T', '/%m/M', '/a', '//a', '/a/', '//[a-c]/_', '/*/X', '//?/-', '/t*r/-', '^', '^^', ',', ',,', '@U', '@L', '@u',
];
const WORD_PRE = "V=terraform; S=destroy; W=TERRAFORM; E=''; SP='a b  c'; P=/usr/local/bin/tf.tar.gz; N=12345; R=V; L=' lead and trail '; ";
function wordAtoms(pick) {
  const v = () => pick(VARS), m = () => pick(MODS);
  return [
    () => pick(['abc', 'x-y', 'a.b', '/usr/bin', '100', 'k=v', 'a,b', '{', '}', '#x', '%', '=']),
    () => pick(["'a b'", "''", "'$V'", "'\\n'", "'a\"b'", "'it'\\''s'"]),
    () => pick(['"a b"', '""', '"$V"', '"${V}x"', '"$(echo hi)"', '"a\\"b"', '"\\$V"', '"\\\\"', '"a\\nb"', '"$SP"', '"$E"', '"$U"', '"x${U:-y z}"', '"${SP}"', '"$L"', '"a$S b"']),
    () => pick(['\\a', '\\ ', '\\$', '\\\\', "\\'", '\\"', '\\n', 'a\\ b', '\\*']),
    () => pick(["$'a\\tb'", "$'\\x41'", "$'\\101'", "$'\\u00e9'", "$'it\\'s'", "$'\\n'", "$'a b'", "$'\\x74erraform'", "$'\\e'", "$'\\\\'", "$''"]),
    () => pick(['$"abc"', '$"a $V"', '$"x"']),
    () => `$${v()}`, () => `\${${v()}}`, () => `\${${v()}${m()}}`, () => `\${${v()}${m()}}`, () => `"\${${v()}${m()}}"`,
    () => pick(['${#V}', '${#SP}', '${#U}', '${!R}', '"${!R}"', '${#N}']),
    () => pick(['$(echo a b)', '$(printf %s ab)', '`echo a`', '$(echo "  sp  ")', "$(printf 'a\\nb')", '$(echo)', '"$(echo a  b)"', '$(echo $V)', '$(echo "$V")x', '$(printf "")']),
    () => pick(['{a,b}', '{1..3}', 'x{a,b}y', '{a,b}{c,d}', 'a{,b}', '{$V,x}', '{"a b",c}', '{a,b', 'a}', '{a}', '{}', 'x{1..3}', '{a..c}', '{,}', '{a,}', '{a,b}$V', '$V{a,b}', '"{a,b}"', "{'a b',c}"]),
    () => pick(['~', '~/x', 'a~', '~root', '"~"']),
    () => pick(['*', 'a*', '?', '[a]', '"*"', '\\*', '$V*', '"$V"*']),
  ];
}

test('words: what the evaluator makes of a command line is what bash makes of it', opts, () => {
  const rand = rng(7), pick = (a) => a[Math.floor(rand() * a.length)];
  const atoms = wordAtoms(pick);
  const word = () => { let w = ''; for (let i = 0, n = 1 + Math.floor(rand() * 3); i < n; i++) w += pick(atoms)(); return w; };
  const work = mkdtempSync(join(tmpdir(), 'shellmap-words-'));
  const stats = { compared: 0, unknown: 0 }, bad = [];
  try {
    for (let i = 0; i < N * 3; i++) {
      const words = [word(), word()].slice(0, 1 + Math.floor(rand() * 2));
      const cmd = `${WORD_PRE}printf '%s\\0' ${words.join(' ')}`;
      const b = spawnSync('bash', ['--noprofile', '--norc', '-c', cmd], { cwd: work, env: { PATH: '/usr/bin:/bin', HOME: '/home/u', LC_ALL: 'C.UTF-8' }, encoding: 'utf8', timeout: 5000, input: '' });
      if (b.status !== 0 || b.error) continue; // a syntax error in bash: nothing to compare
      const want = b.stdout.split('\0'); want.pop();
      globalThis.__SHELLMAP_TRACE = [];
      let trace;
      try { classify(cmd, { cwd: work, home: '/home/u' }); trace = globalThis.__SHELLMAP_TRACE; } finally { globalThis.__SHELLMAP_TRACE = undefined; }
      const last = trace.filter((a) => a[0] === 'printf').at(-1);
      if (!last) { bad.push(`not read: ${cmd.slice(WORD_PRE.length)}`); continue; }
      const got = last.slice(2);
      if (got.some((x) => x.includes('<?>'))) { stats.unknown++; continue; } // the evaluator says it cannot tell ($$, $@, a variable it never saw)
      stats.compared++;
      const same = (got.length === 0 && want.length === 1 && want[0] === '') /* printf with no argument prints one empty string */ || (got.length === want.length && got.every((x, k) => x === want[k]));
      if (!same) bad.push(`evaluator ${JSON.stringify(got)}, bash ${JSON.stringify(want)}: ${cmd.slice(WORD_PRE.length)}`);
    }
  } finally { rmSync(work, { recursive: true, force: true }); }
  assert.deepEqual(bad.slice(0, 10), []);
  assert.ok(stats.compared > N, `most of the words were compared (${JSON.stringify(stats)})`);
});

// ---------------------------------------------------------------- 2. effect
const PROGS = [
  'terraform', "'terraform'", '"terraform"', "terra'form'", '"terra"form', 'ter""raform', '\\terraform', 't\\erraform',
  "$'terraform'", "$'\\x74erraform'", "$'\\164erraform'", "$'\\u0074erraform'", '$"terraform"', "t$'\\x65'rraform",
  '${V}', '"$V"', '${V:-nope}', '${U:-terraform}', '${V:0:9}', '${V#}', '${V%}', '${W,,}', '$V', '$(echo terraform)', '`echo terraform`',
  '"$(printf terraform)"', "$(printf '%s' terraform)", '{terraform,}', 't{e,}rraform', 'ter{ra,}form', '${V//x/x}', '$(echo ${V})',
  './terraform', '"${V}"', '${V:-}', '${!R}', '${U-terraform}', '${U=terraform}', '${V@L}',
];
const SUBS = [
  'destroy', "'destroy'", '"destroy"', "des''troy", "$'destroy'", "$'\\x64estroy'", '\\destroy', '${S}', '"$S"', '$(echo destroy)',
  '{destroy,}', 'd{e,}stroy', "$'\\144estroy'", '${S:0:7}', '${S,,}', '$S', '`echo destroy`', '"$(echo destroy)"', '${U:-destroy}', 'dest""roy',
];
const FLAGS = ['', '', '', ' -auto-approve', ' -force', ' -target=x'];
const CTX = [
  (x) => x, (x) => `sudo ${x}`, (x) => `env ${x}`, (x) => `env A=1 B=2 ${x}`, (x) => `command ${x}`, (x) => `nohup ${x}`, (x) => `time ${x}`,
  (x) => `exec ${x}`, (x) => `(${x})`, (x) => `{ ${x}; }`, (x) => `if true; then ${x}; fi`, (x) => `for i in 1; do ${x}; done`,
  (x) => `while true; do ${x}; break; done`, (x) => `true && ${x}`, (x) => `false || ${x}`, (x) => `true; ${x}`, (x) => `${x} & wait`,
  (x) => `${x} | cat`, (x) => `${x} > /dev/null`, (x) => `${x} 2>&1`, (x) => `${x} <<< hi`, (x) => `echo hi | ${x}`, (x) => `echo | xargs ${x}`,
  (x) => `sh -c ${shq(x)}`, (x) => `bash -c ${shq(x)}`, (x) => `bash -lc ${shq(x)}`, (x) => `sh -c ${dq(x)}`, (x) => `eval ${shq(x)}`,
  (x) => `eval ${dq(x)}`, (x) => `eval "$(echo ${shq(x)})"`, (x) => `$(${x})`, (x) => `echo $(${x})`, (x) => `echo \`${x}\``, (x) => `Z=$(${x})`,
  (x) => `cd /tmp && ${x}`, (x) => `${x}; echo done`, (x) => `find . -maxdepth 0 -exec ${x} \\;`, (x) => `cat <<EOF\nhello\nEOF\n${x}`,
  (x) => `cat <<EOF | sh\n${x}\nEOF`, (x) => `echo ${shq(x)} | sh`, (x) => `echo ${shq(x)} | bash`, (x) => `printf '%s\\n' ${shq(x)} | sh`,
  (x) => `f() { ${x}; }; f`, (x) => `X=1 ${x}`, (x) => `! ${x}`, (x) => `${x} || true`, (x) => `case a in a) ${x};; esac`,
  (x) => `until false; do ${x}; break; done`, (x) => `trap ${shq(x)} EXIT`, (x) => `sudo -E env X=1 ${x}`, (x) => `time -p ${x}`, (x) => `nice ${x}`,
  (x) => `timeout 5 ${x}`, (x) => `env -S ${shq(x)}`, (x) => `xargs -I{} ${x} <<< hi`, (x) => `xargs -0 ${x} <<< hi`, (x) => `source <(echo ${shq(x)})`,
  (x) => `. <(echo ${shq(x)})`, (x) => `bash <(echo ${shq(x)})`, (x) => `bash <<< ${shq(x)}`, (x) => `bash -c ${shq(`echo go; ${x}`)}`, (x) => `\\${x}`,
];
const LITERAL = [
  (x) => `echo ${shq(x)}`, (x) => `echo ${dq(x)}`, (x) => `printf '%s\\n' ${shq(x)}`, (x) => `git commit -m ${shq(x)}`, (x) => `grep -rn ${shq(x)} .`,
  (x) => `cat <<'EOF'\n${x}\nEOF`, (x) => `: ${shq(x)}`, (x) => `# ${x}`, (x) => `echo ok # ${x}`, (x) => `export NOTE=${shq(x)}`,
];
const EFFECT_PRE = ['', 'V=terraform; S=destroy; W=TERRAFORM; ', 'V=terraform S=destroy W=TERRAFORM\n', 'export V=terraform S=destroy W=TERRAFORM; R=V; '];

test('effect: wherever bash really runs terraform destroy the map holds the command, and a quoted copy of the text is not held', opts, () => {
  const rand = rng(1), pick = (a) => a[Math.floor(rand() * a.length)];
  const root = mkdtempSync(join(tmpdir(), 'shellmap-effect-'));
  const bin = join(root, 'bin'), work = join(root, 'work'), home = join(root, 'home'), log = join(root, 'log.txt');
  for (const d of [bin, work, home]) mkdirSync(d);
  writeFileSync(join(bin, 'terraform'), '#!/bin/sh\n{ printf \'ARGV\'; for a in "$@"; do printf \'\\t%s\' "$a"; done; printf \'\\n\'; } >> "$LOG"\n');
  writeFileSync(join(bin, 'sudo'), '#!/bin/sh\nexec "$@"\n');
  chmodSync(join(bin, 'terraform'), 0o755); chmodSync(join(bin, 'sudo'), 0o755);
  const stats = { ran: 0, missed: [], literal: 0, literalHeld: [] };
  try {
    for (let i = 0; i < N * 3; i++) {
      const literal = rand() < 0.14;
      const x = `${pick(PROGS)} ${pick(SUBS)}${pick(FLAGS)}`;
      const cmd = pick(EFFECT_PRE) + (literal ? pick(LITERAL) : pick(CTX))(x);
      writeFileSync(log, '');
      spawnSync('bash', ['--noprofile', '--norc', '-c', cmd], { env: { PATH: `${bin}:/usr/bin:/bin`, LOG: log, HOME: home, LC_ALL: 'C.UTF-8' }, cwd: work, timeout: 5000, input: '', encoding: 'utf8' });
      const ran = readFileSync(log, 'utf8').split('\n').filter(Boolean).some((l) => l.split('\t')[1] === 'destroy');
      const held = classify(cmd, { cwd: work, home }).hold;
      if (literal) { stats.literal++; if (!ran && held) stats.literalHeld.push(cmd); } else if (ran) { stats.ran++; if (!held) stats.missed.push(cmd); }
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
  assert.deepEqual(stats.missed.slice(0, 10), [], 'bash ran terraform destroy and the map did not hold it');
  assert.deepEqual(stats.literalHeld.slice(0, 10), [], 'a quoted copy of the text was held');
  assert.ok(stats.ran > N / 2 && stats.literal > 10, JSON.stringify({ ran: stats.ran, literal: stats.literal }));
});
