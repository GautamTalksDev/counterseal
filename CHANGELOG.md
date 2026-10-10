# Changelog

All notable changes to Counterseal. The CLI follows [Semantic Versioning](https://semver.org/); the hosted service and
the self-hosted Worker change together with this repository (see [docs/DEPLOY.md](docs/DEPLOY.md) for migrations).

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
