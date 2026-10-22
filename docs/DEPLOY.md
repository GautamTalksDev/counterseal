# Deploy

Counterseal is one Cloudflare Worker (internal name `leash`) with one D1 database (`leash`), one SQLite-backed Durable
Object (`ReceiptLog`, the public log) and static assets. It fits the Workers Free plan.

## Upgrading the live service (from the broker-only version)

The live database keeps every row. Migrations `0004_record_and_prove.sql`, `0005_cli_signin.sql`, `0006_approvals.sql`,
`0007_gates.sql`, `0008_brakes.sql`, `0009_team.sql`, `0010_provider_host.sql`, `0011_breakglass.sql`, `0012_app_trust.sql` and `0013_reported_share.sql` only add tables, indexes
and defaulted or nullable columns, so the code that runs today keeps working on the migrated database, and the new code keeps
working with everything the old code wrote (`server/test/migration.test.js` runs the deployed code, migrates, then runs the new
code). CLI sessions made before 0005 keep their 30-day lifetime; new ones last 7 days. After 0006 every existing hold reads as
`kind: "proxy"` (a brokered API call); 0006 adds the guard keys table and the coding-agent approvals. 0007 (Deploy Gate) adds the tables `gates`, `gate_polls` and
`gate_runs`; it changes no existing row, and a hold made before it reads as it did (`kind: "proxy"`, or `shell` and `tool` for a
coding agent's approval). Apply every migration before deploying the code (the held list joins `gates`). 0008 (Brakes) adds `tokens.tripped_at`, `tokens.tripped_why`, `accounts.frozen_at` and the tables `spend` and
`counters`; every existing token and account is not tripped, not frozen and has no caps. 0009 (the two-person seal) adds the tables `members`, `invites` and `hold_votes`, a `member_id` on passkeys, sessions,
push devices, device codes, move links, tokens, guard keys, receipts keys and agent keys, the quorum columns on `accounts`
(quorum 1, self-approval on) and `needs` and `requested_by` on `holds`; every existing account is one person, its owner, and one
seal approves, as before (no row is rewritten: a NULL `member_id` means the account's founder). 0010 adds one nullable column, the
store address of a Shopify key (map `2026-10-10.1`). 0011 (break glass and alert
channels) adds the tables `windows` and `channels`; it changes no existing row, and
with no window and no channel nothing behaves differently. 0012 (the installable app, the first run and the privacy center)
adds nullable columns only: five first-time markers and `hold_days` on `accounts`,
and `seen_at` on `sessions`. A web session made before it counts its idle hour from when it was made, so the first deploy
signs out browsers that have been idle for an hour; command line sessions are unaffected. Closed holds older than 365 days are
deleted by the cleanup from then on (none exist yet). 0013 (the final security gate) adds one
column, `global_usage.reported` (default 0): the day's receipts that agents reported, so they can be held to their share of the
day (`REPORTED_DAILY_CAP`) while the broker's own decisions keep the rest.

```bash
cd server
npx -y wrangler@4 login
# 1. a backup point, before anything changes (keep the bookmark it prints)
npx -y wrangler@4 d1 time-travel info leash
# 2. new secrets (names only; values never leave your machine)
node dev/log-keygen.mjs | npx -y wrangler@4 secret put LOG_KEY_JWK        # the log's Ed25519 signing key; prints the public part to stderr: keep it
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))" | npx -y wrangler@4 secret put STATS_TOKEN   # optional: /v1/admin/stats
# 3. the additive migrations (applies 0004 to 0013; 0001 to 0003 are already applied)
npx -y wrangler@4 d1 migrations apply leash --remote
# 4. the code (creates the ReceiptLog Durable Object through the "v1" migration in wrangler.jsonc)
npx -y wrangler@4 deploy
```

Existing secrets stay as they are: `LEASH_KEK`, `IP_SALT`, `VAPID_PRIVATE_JWK`. Workers Logs are turned off in
`wrangler.jsonc` (`observability.enabled: false`); the deploy applies that. Both custom domains stay in `routes`
(counterseal.gautamkhosla.com and leash.gautamkhosla.com); `ORIGIN` / `RP_ID` are counterseal, the one host, and
leash.gautamkhosla.com answers every request with a 301 to the same path on counterseal (see "One host" below). No
table, column or account is removed: accounts whose only passkey was made on leash.gautamkhosla.com stay in D1 but can
no longer sign in (deleting them is a separate decision).

Then check:

```bash
curl -s https://counterseal.gautamkhosla.com/v1/log/key           # publish this verifier key (README, site, auditors)
curl -s https://counterseal.gautamkhosla.com/v1/stats             # {"tree_size":0,...} on a fresh log
curl -s https://counterseal.gautamkhosla.com/.well-known/security.txt
curl -s -H "authorization: Bearer $STATS_TOKEN" https://counterseal.gautamkhosla.com/v1/admin/stats
```

and in the app: on https://counterseal.gautamkhosla.com/app sign in, see your tokens and holds and approve a test hold.
Check that `curl -sI https://leash.gautamkhosla.com/app`, `.../v1/meta` and `.../p/github/user` all answer 301 with
`location: https://counterseal.gautamkhosla.com/...` (same path).
Run `npx counterseal login` (0.1.1): it prints `.../app#device` and a code; type the code in the app, check that the
approval screen shows your country and network, approve, and see the "A command line was signed in" alert and the
sign-in under Account, Command line sign-ins.

**`LOG_ORIGIN` is fixed for life.** It is signed into every checkpoint; the log pins its name and key at its first entry
and refuses to sign under others (`503 log_key_changed`). It is set to `counterseal.gautamkhosla.com/log`, the final
name; it is only a name and does not need to resolve. For the same reason, never rotate `LOG_KEY_JWK`: a new key means a
new log.

### Rollback

- **Code:** `npx -y wrangler@4 rollback` to the previous version. The old code runs on the migrated database (it ignores
  the new tables and columns). If Cloudflare refuses the rollback because of the Durable Object migration, deploy the
  previous code with this repository's `durable_objects` and `migrations` blocks kept in `wrangler.jsonc` and
  `export { ReceiptLog } from './log.js'` (with `log.js`, `merkle.js`, `note.js`, `brand.js`) added to its source.
  **Never add a `deleted_classes` migration**: it erases the public log.
- **Data:** no schema rollback is needed. Only if the data itself must go back, restore with
  `npx -y wrangler@4 d1 time-travel restore leash --bookmark <bookmark from step 1>` (this loses everything written since).

## Fresh install

```bash
cd server
npx -y wrangler@4 d1 create leash                      # paste the database_id into wrangler.jsonc
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))" | npx -y wrangler@4 secret put LEASH_KEK
node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))" | npx -y wrangler@4 secret put IP_SALT
node dev/vapid-keygen.mjs | npx -y wrangler@4 secret put VAPID_PRIVATE_JWK   # phone alerts (Web Push); optional
node dev/log-keygen.mjs | npx -y wrangler@4 secret put LOG_KEY_JWK          # the public log
npx -y wrangler@4 d1 migrations apply leash --remote   # 0001 to 0013
npx -y wrangler@4 deploy
```

`routes`, `RP_ID` and `ORIGIN` in `wrangler.jsonc` name the domain users see (the passkey RP ID must be that domain);
`BRAND.retiredDomain` in `server/src/brand.js` is the hostname that only redirects (drop its route on a fork).
Without `VAPID_PRIVATE_JWK`, phone alerts are off. Without `LOG_KEY_JWK`, the broker works and receipts are skipped.

## Settings (vars in wrangler.jsonc)

| Var | Default | What |
|---|---|---|
| `LOG_ORIGIN` | counterseal.gautamkhosla.com/log | the log's name, signed into checkpoints; never change once the log has an entry |
| `FREE_LIMIT` | 10000 | receipts per account per month (the broker's own decisions may use twice this) |
| `ACCOUNT_DAILY_CAP` | 2000 | receipts per account per UTC day (the broker's own decisions may use twice this) |
| `GLOBAL_DAILY_CAP` | 10000 | appends per UTC day across all accounts (`503 log_at_capacity` above it) |
| `REPORTED_DAILY_CAP` | 5000 | of those, at most this many reported through `POST /v1/receipts` (the rest is kept for decisions) |
| `REG_PER_IP_DAY` | 5 | new accounts per IP (salted hash, IPv6 /64) per day |
| `PUB_RPM` | 600 | public log reads per IP per minute (in memory per isolate) |
| `PUB_DO_RPM` | 120 | public reads that reach the Durable Object (entries, proofs) per IP per minute |
| `TOOL_RPM` | 10 | Web Bot Auth checker directory lookups per IP per minute |
| `GUARD_RPM` | 240 | requests with a guard key (`/v1/approvals*`) per IP per minute (in memory per isolate); each key also has 60 new holds an hour (D1) and 30 polls and 30 uses a minute (in memory) |
| `GATE_RPM` | 600 | requests of a deploy gate (`POST /v1/gate/request`, and separately `/v1/gate/status` and `/v1/gate/cancel`) per IP per minute (in memory per isolate; hosted runners share networks, so it is generous); each gate also has 30 new requests an hour (D1) and 10 waiting, each poll secret 30 polls a minute (in memory) |

Secrets: `LEASH_KEK`, `IP_SALT` (required), `VAPID_PRIVATE_JWK` (phone alerts), `LOG_KEY_JWK` (receipts), `STATS_TOKEN`
(the private stats endpoint; at least 32 characters, or the endpoint stays 404).

Recommended: a Workers Rate Limiting binding named `READ_LIMITER` replaces the in-memory buckets (shared across isolates
in a location). Replace the comment line that starts with `// Optional, replaces the in-memory read limiter:` with:

```jsonc
"ratelimits": [{ "name": "READ_LIMITER", "namespace_id": "1001", "simple": { "limit": 600, "period": 60 } }],
```

## Daily budgets on Workers Free

Workers Free allows 100,000 Worker requests, 100,000 Durable Object requests, 100,000 D1 rows written and 5 million D1
rows read a day (rows written are counted across the whole account), 10 ms of CPU and 50 D1 queries per invocation, and
5 cron triggers per account. This Worker declares no cron: cleanup runs in `ctx.waitUntil` on about 2% of requests and
after sign-ins.

| Operation | D1 rows written | Durable Object |
|---|---|---|
| Proxied read (GET), unbound token | about 4 (IP and token rate limits, last used) | none |
| Proxied read, bound token | about 5 (plus the nonce) | none |
| Proxied write that is sealed | about 8 (plus audit, usage, global usage, receipt index) | 1 request, about 7 rows |
| Held call, sealed | about 8 | 1 request, about 7 rows |
| Coding-agent approval asked (`POST /v1/approvals`), sealed | about 9, plus one per device alerted (at most one alert a minute) | 1 request, about 7 rows |
| Same command asked again while pending or approved | 0 | none |
| Waiting for a decision (`GET /v1/approvals/<id>?wait=20`) | 0 (at most 12 D1 queries, all reads) | none |
| Approval used (`POST /v1/approvals/<id>/use`), sealed | about 6 | 1 request, about 7 rows |
| Deploy gate: a run asks (`POST /v1/gate/request`), new hold, sealed | about 8, plus one per device alerted (at most one alert a minute); 12 D1 queries, 24 with 10 devices | 1 request, about 7 rows |
| Deploy gate: the same run asks again | 2 (the token's `jti`, a poll secret); 4 queries | none |
| Deploy gate: a run the gate refuses | 0 (1 read) | none |
| Deploy gate: waiting (`GET /v1/gate/status/<id>?wait=20`) | 0 (at most 12 D1 queries, all reads) | none |
| Break glass opened (passkey verify, the window, audit, the team's alert) | about 6; 13 D1 queries, more with devices and channels to tell | 1 request, about 7 rows |
| A call the map holds, let through by an open window | as an allowed sealed write: about 8; 12 D1 queries (one is the window's own read; a call the map does not hold, or any call while no window is open, costs nothing more) | 1 request, about 7 rows |
| A held call with one alert channel | about 10 (the hold, the alert's limit, the channel's bookkeeping); 16 D1 queries; one subrequest to the service, after the answer | 1 request, about 7 rows |
| Deploy gate: the poll that spends an approval, sealed | about 6 (about 8 with a key handed out); 9 queries (13) | 1 request, about 7 rows |
| Brakes: a write on a token with `writesPerHour` | one more (the hour's count) | |
| Brakes: ... with `repeatsPer5Min` too | two more (a row per distinct request in its 5 minutes, reused for repeats) | |
| Brakes: a capped Stripe refund or payout | one more (the day's total), plus one lookup at Stripe (a subrequest, no D1) | |
| Brakes: a call on a frozen account | 1 (the per-network limit); no token row, no audit entry except one per token every 10 minutes | none |
| Brakes: a token without `limits` or `money` | none | |
| Two-person seal: a proxied call on a team | none more (the quorum is read in the token's query) | |
| Two-person seal: one seal that does not complete the quorum | about 6 (limit, challenge, passkey counter, seal, audit), plus one per device nudged (at most one alert a minute) | none |
| Two-person seal: the seal that approves, sealed | about 9 (the above, the approval, receipt bookkeeping) | 1 request, about 7 rows |
| Two-person seal: making an invite / joining | about 7 / about 9, plus one per device alerted | none |
| Two-person seal: reading the team (`GET /v1/team`) | 0 (5 D1 queries) | none |
| First run: "Try a held call" (`POST /v1/demo/call`) | about 4 (limit, hold, audit, the demo marker once), plus one per device alerted (at most one alert a minute) | none (never sealed) |
| The demo agent's retry after approval | about 3 (the hold used, audit, limit) | none |
| Launch funnel markers (first token, first protected call, alerts, installed) | at most 1, once per account per isolate; never on a poll | none |
| Web session activity (the idle hour) | at most 1 a minute per active browser session; the background refresh writes nothing | none |
| The dashboard's background refresh | 0 (one request, `/v1/alerts`, every 5 seconds while the page is shown; the six-request full load when that changed or once a minute; nothing while hidden) | none |
| Data export (`POST /v1/me/export/begin` and `finish`) | about 5 (limit, challenge, passkey counter, audit); 21 D1 queries; then pages of 200 holds and 250 audit entries, 0 writes each | none |
| Evidence pack, one page of 250 audit entries (`GET /v1/export/evidence`; a page looks at 1,000 entries at most) | 0 (at most 4 D1 queries) | 1 request on the first page, within the 60 a minute per account |
| Retention cleanup (part of the sweep) | the closed holds it deletes | none |
| Receipts API, one unsigned receipt | about 3 | 1 request |
| Public log read (stats, checkpoint, key) | 0 | 0 within 10 s of the last head read per isolate |
| Public log read (entries, proofs) | 0 | 1 |

So the D1 row budget is the binding limit: roughly 12,000 sealed decisions or 25,000 proxied reads a day, shared with
sign-ins, the dashboard and every other Worker on the account. The receipts caps (10,000 a day) sit inside it.

Still open on Free: sign-in begin calls write a challenge per request, so a flood from many networks can use up the D1
budget; a flood of public entries and proof reads from many networks can use up the Durable Object budget (receipts then
stop until 00:00 UTC; decisions do not). Add a Cloudflare WAF rate limiting rule for `/v1/auth/*` and `/v1/log/*` (one rule
is included on Free) and configure `READ_LIMITER`.

## CPU on Workers Free

Measured in Node with `node bench/cpu.mjs` (9 Oct 2026; D1 and Durable Object storage time taken out, as it is I/O on
Workers). Medians, with the 95th percentile in brackets:

| Path | Worker CPU | Durable Object CPU |
|---|---|---|
| Proxied GET, unbound | 0.8 ms (1.5) | |
| Proxied GET, bound (RFC 9421 verify, nonce) | 1.1 ms (2.1) | |
| Proxied POST, bound, 1 KB body, sealed | 1.6 ms (3.2) | 0.5 ms |
| Held DELETE, bound, sealed | 1.1 ms (2.4) | 0.5 ms |
| Approve a hold (passkey verify), sealed | 1.1 ms (3.3) | 0.6 ms |
| Brakes: POST with both breaker limits, sealed | 1.4 ms (3.6) | 0.7 ms |
| Brakes: capped refund (Stripe lookup stubbed), sealed | 1.7 ms (4.1) | 0.6 ms |
| Brakes: refund over the cap, held, sealed | 1.5 ms (5.5) | 0.6 ms |
| Brakes: call on a frozen account (423) | 0.3 ms (0.5) | |
| Brakes: freeze / unfreeze (passkey verify) / reset a tripped token (passkey verify) | 0.4 ms (0.8) / 0.9 ms (1.7) / 1.0 ms (3.3) | |
| Receipts API, 25 unsigned (the cap) | 2.5 ms (5.0) | 3.9 ms |
| Receipts API, 12 signed (the cap) | 3.3 ms (5.6) | 1.6 ms |
| `/v1/stats` | 0.1 ms (0.5) | |

The Approvals API (branch `feat/approvals`), measured later the same day after rebasing on the second pass; the same
run measured a proxied GET, unbound, at 0.85 ms (2.0) and a held DELETE, bound, sealed at 1.5 ms (2.7), in line with the
table above:

| Path | Worker CPU | Durable Object CPU |
|---|---|---|
| `POST /v1/approvals`, 3 KB command, held, sealed | 1.0 ms (2.4) | 0.5 ms |
| `GET /v1/approvals/<id>` (no wait) | 0.3 ms (1.5) | |
| `GET /v1/approvals/<id>?wait=20` (11 reads; waiting itself is not CPU) | 0.4 ms (5.3) | |
| Approve a guard hold (passkey verify), sealed | 1.5 ms (3.4) | 0.8 ms |
| `POST /v1/approvals/<id>/use`, sealed | 0.7 ms (4.4) | 0.7 ms |
| `POST /v1/holds/<id>/deny` with a reason, sealed | 0.7 ms (2.5) | 0.6 ms |

The two-person seal (branch `feat/two-person`), measured after rebasing on Brakes and map `2026-10-10.1`; D1 queries per
invocation from `server/test/team.test.js` (budgets) and a counting run with receipts on and two devices per person:

| Path | Worker CPU | Durable Object CPU | D1 queries |
|---|---|---|---|
| `GET /v1/team` | 0.2 to 0.3 ms (0.4) | | 5 |
| A seal that does not complete the quorum (passkey verify, seal, nudge) | 1.2 to 1.3 ms (at most 6.3 over five runs) | | 15 |
| The seal that approves (passkey verify, seal, approval), sealed | 1.3 to 1.4 ms (at most 2.9) | 0.6 ms | 14 |
| Joining a team (registration verify, member and passkey, alert) | 0.7 to 0.9 ms (at most 2.8) | | 15 |
| A proxied GET on a team account | as on a one-person account (the same query count) | | 6 |
| Unfreeze / reset a tripped token on a team (passkey verify, plus the 24-hour check) | 1.0 ms (1.2) / 1.1 ms (6.2) | | |
The Deploy Gate (branch `feat/deploy-gate`), 9 Oct 2026, same method, 60 runs each. Verifying GitHub's OIDC token is
`crypto.subtle.verify` (RSASSA-PKCS1-v1_5, RSA-2048, SHA-256) plus claim checks; GitHub's key set is fetched at most every 10
minutes per isolate (a subrequest, not CPU) and the imported key is kept:

| Path | Worker CPU | Durable Object CPU |
|---|---|---|
| Verify a GitHub OIDC token (RS256 and claims, key cached) | 0.11 ms (0.81) | |
| Verify the first token of an isolate (key set parsed, RSA key imported) | 0.25 ms (0.42) | |
| `crypto.subtle.verify`, RSA-2048, alone | 0.05 ms (0.12) | |
| `POST /v1/gate/request`, new hold, sealed | 1.05 ms (1.41) | 0.60 ms |
| `POST /v1/gate/request`, the same run asked again | 0.59 ms (4.72) | |
| `GET /v1/gate/status/<id>` (no wait) | 0.19 ms (0.36) | |
| `GET /v1/gate/status/<id>?wait=20` (11 reads; waiting itself is not CPU) | 0.44 ms (4.49) | |
| `GET /v1/gate/status/<id>`, approved: spend once, bind, sealed | 0.73 ms (1.05) | 0.57 ms |
| The same, with a 15 minute token handed out (phase 2) | 0.96 ms (2.89) | 0.65 ms |
| `POST /v1/gate/cancel/<id>` | 0.47 ms (0.89) | |

Break glass and alert channels (part 2b of the two-person seal), same method; the stand-in for the chat services answers at once, so this is our own CPU:

| Path | Worker CPU | Durable Object CPU |
|---|---|---|
| Open a break-glass window (passkey verify, insert, team alert) | 1.6 ms (6.0) | |
| A DELETE the map would hold, let through by an open window, sealed | 1.9 ms (3.6) | 1.0 ms |
| Add an alert channel (passkey verify, seal the address, insert) | 1.7 ms (2.8) | |
| A held DELETE with one alert channel (hold, push check, unseal, post stubbed) | 3.2 ms (6.8) | 1.8 ms |

The app, the first run and the privacy center (branch feat/app-trust), same method, 9 Oct 2026:

| Path | Worker CPU | Durable Object CPU |
|---|---|---|
| "Try a held call" (`POST /v1/demo/call`: hold, audit, alert check) | 0.61 ms (0.95) | |
| Evidence pack, first page (250 audit entries as stored, the checkpoint) | 0.71 ms (1.08) | |
| Data export (every table but holds and the audit log, passkey verify included) | 2.78 ms (6.88) | |

The audit chain is verified in the browser, never on the server: re-hashing a long log would not fit in 10 ms.

These are Node numbers, not a load test on Workers. Run one before raising the batch caps in `server/src/receipts.js`.

## One host: counterseal.gautamkhosla.com (leash.gautamkhosla.com only redirects)

The product lives at **counterseal.gautamkhosla.com**, the one origin and passkey RP ID (`ORIGIN`, `RP_ID`). Both
hostnames stay custom domains in `routes`, served by the same Worker, so wrangler keeps the DNS record of the retired one.

| | counterseal.gautamkhosla.com | leash.gautamkhosla.com |
|---|---|---|
| Every request: pages, assets, `/app`, `/v1/*`, `/p/*`, `/.well-known/*`, any method | served | 301 to the same path and query on counterseal, no body, with HSTS, `nosniff`, `referrer-policy: no-referrer`, `default-src 'none'; frame-ancestors 'none'` and `x-frame-options: DENY`; no cookie is read or set, nothing is proxied |

- **Passkeys.** Every WebAuthn ceremony uses `RP_ID` and `ORIGIN`; a client never names an RP ID. A passkey whose
  recorded `passkeys.rp_id` is another RP ID (one made on leash.gautamkhosla.com) is refused, and the authenticator data
  proves the RP ID anyway. Such passkeys and their accounts stay in D1 (additive-only), unusable.
- **Sessions.** The `__Host-leash` cookie is host-only. CSRF checks accept a write only with an Origin equal to `ORIGIN`.
- **Assets.** `run_worker_first` is `true`, so the Worker sees every request and can redirect assets on the retired host
  too; on counterseal it passes everything outside `/v1`, `/p` and `/.well-known` to the assets binding and adds the
  site's security headers. Every asset request is therefore a Worker request (Workers Free: 100,000 a day).
- **Old clients.** leashcli 0.1.1 defaults to leash.gautamkhosla.com and does not follow redirects, so it stops working
  there; agents and tools configured with a leash.gautamkhosla.com base URL get a 301 and must be pointed at counterseal.
- **Move links.** The "Move to Counterseal" flow is gone; the `move_links` table stays (additive-only), no new rows are
  made, and old ones are swept a day after expiry and with their account.

## Publishing the CLI (publish first, then deploy)

From 0.3.0 the CLI is published as `counterseal` (`cli/package.json`, bin `counterseal`), and `leashcli`, its first name, is a
thin package (`packages/leashcli`) that depends on `counterseal` of the same version and runs it, so install lines and agent configs that name
leashcli keep working. `counterseal` 0.4.0 is on npm. The steps, with the release checklist, are in
[docs/RELEASE.md](RELEASE.md): a GitHub release tagged `cli-v<version>` (for example `cli-v0.4.0`) runs `.github/workflows/publish.yml` (npm trusted
publishing with provenance, a CycloneDX SBOM of each package attached to the release).

**Order.** Every install line on the site, in the docs and in the app names one package, `BRAND.cliInstall` in
`server/src/brand.js` (`counterseal` on this branch). So:

1. Publish the CLI (`counterseal`, then `leashcli`).
2. Check `npx counterseal --version` prints the new version on a clean machine.
3. Then deploy the Worker and site.

To deploy before publishing, set `cliInstall: 'leashcli'` in `server/src/brand.js`, run `node scripts/cli-name.mjs` (it
rewrites only command lines: `npx ...`, the MCP config's `"-y", "..."`, "... login" style mentions and the CLI's `PKG`
constant), run the tests, and deploy; the published `leashcli` then serves those lines until the new `counterseal` is out. Switch back the same way after publishing. `node scripts/cli-name.mjs --check` (in
CI and `server/test/brand.test.js`) fails if any line names the other package.

## The coding-agent guard (nothing to deploy on the Worker)

`counterseal guard` is a client of the Approvals API (migration 0006), so the Worker needs nothing beyond that. What makes it
available to people:

1. **Publish the CLI** (above): `guard.mjs` and `shellmap.mjs` are in the package's `files`. `npx counterseal guard` needs
   CLI 0.3.0 or later (0.4.0 is on npm).
2. **The plugin needs the repository to be readable by the people who add it.** `claude plugin marketplace add GautamTalksDev/counterseal`
   reads `.claude-plugin/marketplace.json` from the default branch, so the files must be on the branch people get (not only on
   a feature branch) and the repository must be public. No form and no store is involved. Submitting to Anthropic's directory
   is a separate, optional step with its own review (their portal), not done here.
3. **Keep the copies in step** whenever the map, the CLI or the server's irreversible map changes: `node scripts/sync-guard.mjs`
   rewrites the generated API map block in `sdk/shellmap.mjs` and the copies in `cli/`, `plugins/counterseal/scripts/` and `site/public/`;
   CI runs it with `--check`. A new plugin version (`plugins/counterseal/.claude-plugin/plugin.json`) is what makes Claude Code
   offer an update, because the scripts are pinned inside the plugin.
4. **Nothing is tested in the agents' own apps yet** (see the README): try `counterseal guard status` and one held command in each
   agent you intend to name in public copy before naming it.
