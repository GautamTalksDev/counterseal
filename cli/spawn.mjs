// Start the MCP server a client would start, on every platform. Zero dependencies.
//
// On Windows, Node cannot start npx, uvx or any other .cmd or .bat shim without a shell, so such a command is found on PATH
// and run through cmd.exe with every argument escaped. This is the approach of cross-spawn (MIT), which the official MCP
// TypeScript SDK uses to start stdio servers, and it is a port of src/spawn.js in mcp-pin (https://github.com/GautamTalksDev/mcp-pin,
// MIT), where the "spawn npx ENOENT" failure on Windows was found and fixed. Elsewhere it is a plain spawn.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';

const META = /([()\][%!^"`<>&|;, *?])/g;

function getEnv(env, name) {
  const key = Object.keys(env).find((k) => k.toUpperCase() === name);
  return key === undefined ? undefined : env[key];
}

// The file Windows would run for this command: the current folder first, then PATH, trying each PATHEXT extension when the
// name has none.
function findWindows(command, env, cwd, exists) {
  const exts = (getEnv(env, 'PATHEXT') || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean).map((e) => e.toLowerCase());
  const own = path.win32.extname(command).toLowerCase();
  const names = own && exts.includes(own) ? [command] : exts.map((e) => command + e);
  const dirs = /[\\/]/.test(command) ? [cwd] : [cwd].concat((getEnv(env, 'PATH') || '').split(';').filter(Boolean));
  for (const d of dirs) {
    for (const n of names) {
      const f = path.win32.resolve(d, n);
      if (exists(f)) return f;
    }
  }
  return null;
}

const escapeCommand = (s) => s.replace(META, '^$1');

// Quote for the program's own argument parser, then escape for cmd.exe. npm's node_modules\.bin shims pass arguments through
// cmd a second time.
// One pass, linear time (the regex form backtracked quadratically on long runs of backslashes). A line break or NUL cannot be
// escaped for cmd.exe (it ends the command line there), so such an argument is refused rather than passed to a shell.
export function escapeArgument(arg, twice) {
  const s = String(arg);
  if (/[\0\r\n]/.test(s)) throw new Error('an argument with a line break or NUL cannot be passed safely through cmd.exe');
  let a = '', run = 0;
  for (const ch of s) {
    if (ch === '\\') { run++; continue; }
    a += '\\'.repeat(ch === '"' ? run * 2 + 1 : run) + ch;
    run = 0;
  }
  a += '\\'.repeat(run * 2);
  a = ('"' + a + '"').replace(META, '^$1');
  return twice ? a.replace(META, '^$1') : a;
}

/** what to run: { command, args, verbatim } (verbatim: Windows must not re-quote the arguments) */
export function plan(command, args, opts = {}) {
  const platform = opts.platform || process.platform;
  if (platform !== 'win32') return { command, args, verbatim: false };
  const env = opts.env || process.env;
  const file = findWindows(command, env, opts.cwd || process.cwd(), opts.exists || existsSync);
  if (!file || /\.(com|exe)$/i.test(file)) return { command, args, verbatim: false };
  if (/[\0\r\n]/.test(file)) throw new Error('a command path with a line break or NUL cannot be passed safely through cmd.exe');
  const shim = /node_modules[\\/]\.bin[\\/][^\\/]+\.cmd$/i.test(file);
  const line = [escapeCommand(file)].concat(args.map((a) => escapeArgument(a, shim))).join(' ');
  return { command: getEnv(env, 'COMSPEC') || 'cmd.exe', args: ['/d', '/s', '/c', '"' + line + '"'], verbatim: true };
}

export function spawnServer(command, args, options = {}) {
  const p = plan(command, args, { env: options.env, cwd: options.cwd });
  return spawn(p.command, p.args, p.verbatim ? { ...options, windowsVerbatimArguments: true } : options);
}
