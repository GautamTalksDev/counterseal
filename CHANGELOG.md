# Changelog

All notable changes to Counterseal. The CLI follows [Semantic Versioning](https://semver.org/); the hosted service and
the self-hosted Worker change together with this repository (see [docs/DEPLOY.md](docs/DEPLOY.md) for migrations).

## Unreleased (branch `budget-seal`, not deployed)

### Added

- **Budget seal: hard spend caps on AI model calls.** OpenAI and Anthropic can now be brokered like the other APIs (the
  agent holds a Counterseal token, the key stays in the vault). Each call's cost is metered from the usage the provider
  returns times a price table in code (`server/src/metered.js`, read 2026-10-10, sources linked). Daily and monthly caps
  (UTC) per agent, per key and per account; at a cap the next call gets 402 and is never sent. "Ask me" mode asks for a
  passkey at 80% and raises a cap once at 100%. A runaway detector trips the agent's breaker on too many calls or too much
  spend in a few minutes. Alerts at 50%, 80% and 100%. Unknown models are never guessed. Every budget change needs a
  passkey. Migration `0014_budget_seal.sql` (two new tables). The public irreversible map is unchanged. See
  [docs/BUDGET_SEAL.md](docs/BUDGET_SEAL.md), including what it cannot cap, and [docs/CLOUD_KILL_SWITCH.md](docs/CLOUD_KILL_SWITCH.md).

## 0.4.0 (2026-10-10)

### Fixed

- **Guard: shell map `2026-10-10.2`, 29 rules.** Three gaps a replay test found, where a destructive command passed
  without a hold:
  - **Inline code** (new rule `sh.inline-code`). `python -c`, `node -e`/`-p`/`--eval`, `ruby -e`, `perl -e`, `php -r`
    and code fed to them on standard input (`python - <<EOF`) are skimmed for calls that delete files (`shutil.rmtree`,
    `os.remove`, `os.unlink`, `os.rmdir`, `os.removedirs`, `Path.unlink`, `Path.rmdir`, `fs.rm`, `fs.rmSync`,
    `fs.unlink`, `rimraf`, fs-extra `remove` and `emptyDir`, `FileUtils.rm_rf`, `File.delete`, `unlink`, `rmdir`). A
    literal target is judged like `rm -r` (inside the project passes); a target that is not a literal is held. Literal
    commands given to `os.system`, `subprocess`, `child_process`, `system` and backticks are read as shell text. The
    incident `python -c "import os,shutil; shutil.rmtree('C:/tmp',ignore_errors=True)"` is now held.
  - **PowerShell and cmd** (new rule `sh.win-delete`). `Remove-Item` and its aliases (`ri`, `rm`, `del`, `erase`, `rd`,
    `rmdir`) with `-Recurse` (any prefix), `/s` or a wildcard on a path outside the project, a pipe into a recursive
    delete, and `[IO.Directory]::Delete(path, $true)`. The text of `powershell -Command`, `pwsh -c` and `cmd /c` is read
    statement by statement through the whole map. `-EncodedCommand` is held without being read (`sh.decode-exec`).
  - **Windows paths.** `C:\x`, `C:/x`, `\\server\share` and `%TEMP%` are absolute paths, and `/mnt/c/x` and `/c/x` are
    the same folder as `C:\x`. `C:\tmp`, `C:\temp`, `C:\Windows\Temp`, a user's `AppData\Local\Temp` and `%TEMP%` are
    shared temporary directories; a drive root, `C:\Windows`, `C:\Users` and `C:\Program Files` are system directories.
    A path inside a Windows project root still passes, as it does for `rm`.
- The documented limits (header of `sdk/shellmap.mjs`, the docs page, the guide and the threat model) now say what is
  skimmed and what is still not read: script files, other calls in inline code, PowerShell beyond the statements above.

## 0.3.0 (October 2026)

Counterseal is LEASH, WITNESS and SIGIL merged into one product. The CLI is now the `counterseal` package on npm
(`leashcli` 0.1.1 was its first name and stays as a thin alias that runs the same CLI).

### Added

- **Record.** With receipts on, every decision the broker makes on a write (allowed, held, approved, executed, denied)
  becomes an entry in a public append-only log: an RFC 6962 Merkle tree with C2SP signed checkpoints, inclusion and
  consistency proofs, verifiable in the browser or offline with `sdk/receipts.mjs`. Allowed reads are not recorded.
  Receipts hold the method, the provider host, the decision, the rule and the map version, never a path, body, key,
  token, name, email or IP. New accounts start with receipts on.
- **Prove who.** Agent keys (Ed25519, registered with proof of possession). A token bound to an agent key only works on
  requests that key signed (RFC 9421). `counterseal agent-key` makes a key; the MCP server signs with `LEASH_AGENT_KEY`.
- **Guard.** `counterseal guard install|uninstall|status|check|map`: a hook that holds a coding agent's irreversible shell
  commands (27 rules, shell map `2026-10-10.1`) until a passkey approves that exact command, once. A Claude Code plugin
  and a marketplace file are in the repository. A seatbelt, not a sandbox.
- **Approvals API and guard keys** (`/v1/approvals`) for actions Counterseal does not proxy. A guard key can ask and read,
  never approve.
- **MCP gateway.** `counterseal mcp wrap`, `mcp pin`, `mcp unpin`, `mcp status`: hold destructive tool calls of any local
  stdio MCP server and pin its tool definitions.
- **Two-person seal.** Teams of up to 10 people with their own passkeys, roles (owner, approver, member, viewer), a
  quorum of two seals, delayed and announced lowering of the quorum, break-glass windows (5 to 60 minutes), and alerts to
  Slack, Discord and Google Chat. Alerts carry no command, path, body or amount.
- **Deploy Gate** for GitHub Actions (`action/deploy-gate`): a job waits for a passkey approval of that exact run, using
  GitHub's OIDC token. It can hand out a 15 minute token only after approval. Not run against real GitHub tokens yet.
- **Brakes.** Money caps on Stripe refunds and payouts, a breaker for too many or repeated writes, and Freeze
  (`counterseal freeze`). They cover calls through Counterseal, not LLM tokens.
- **Five more APIs** in the irreversible map (now `2026-10-10.1`): Vercel, Neon, Fly.io, Resend and Shopify, joining
  GitHub, Cloudflare, Railway, Stripe and Supabase. Management APIs only; SQL over a database connection never passes
  through Counterseal.
- **CLI sign-in** shows where the sign-in started, never carries the code in a link, lasts 7 days, and can be revoked in the
  app together with everything it made.
- **The app:** installable, with a first-run demo hold, a privacy center, a data export and an evidence pack.
- **Web Bot Auth checker** (free tool, runs in the browser).
- **Repository:** public under Apache-2.0, with a security policy, contributing guide and code of conduct.

### Changed

- Product and CLI renamed to Counterseal; the product host is `counterseal.gautamkhosla.com`. The old host
  `leash.gautamkhosla.com` keeps serving `/v1`, `/p` and `/app` sign-in so `leashcli` 0.1.1 and configured agents keep
  working; an account moves with a one-time link.
- CLI sessions last 7 days (they were 30).
- The repository URL is `github.com/GautamTalksDev/counterseal`; GitHub redirects the old `leash` address.

### Security

- Migrations 0004 to 0013 are additive; the code that ran before keeps working on a migrated database.
- A final security gate (threat model F1 to F7 and residual risks) and a second pass on limits and caps are in
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). The project is self-assessed, not independently audited.

## 0.1.1 (`leashcli`)

The broker only: vault, proxy tokens, an irreversible map for five APIs, passkey approvals, the audit log, and the MCP
server. Published as `leashcli`.
