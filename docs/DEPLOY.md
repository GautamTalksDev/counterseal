# Deploy

Counterseal is one Cloudflare Worker (internal name `leash`) with one D1 database (`leash`), one SQLite-backed Durable
Object (`ReceiptLog`, the public log) and static assets. It fits the Workers Free plan.

## Upgrading the live service (from the broker-only version)

The live database keeps every row. Migration `0004_record_and_prove.sql` only adds tables and defaulted or nullable
columns, so the code that runs today keeps working on the migrated database, and the new code keeps working with
everything the old code wrote (`server/test/migration.test.js` runs the deployed code, migrates, then runs the new code).

```bash
cd server
npx -y wrangler@4 login
# 1. a backup point, before anything changes (keep the bookmark it prints)
npx -y wrangler@4 d1 time-travel info leash
# 2. new secrets (names only; values never leave your machine)
node dev/log-keygen.mjs | npx -y wrangler@4 secret put LOG_KEY_JWK        # the log's Ed25519 signing key; prints the public part to stderr: keep it
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))" | npx -y wrangler@4 secret put STATS_TOKEN   # optional: /v1/admin/stats
# 3. the additive migration (applies 0004 only; 0001 to 0003 are already applied)
npx -y wrangler@4 d1 migrations apply leash --remote
# 4. the code (creates the ReceiptLog Durable Object through the "v1" migration in wrangler.jsonc)
npx -y wrangler@4 deploy
```

Existing secrets stay as they are: `LEASH_KEK`, `IP_SALT`, `VAPID_PRIVATE_JWK`. Workers Logs are turned off in
`wrangler.jsonc` (`observability.enabled: false`); the deploy applies that. The deploy also adds the custom domain
counterseal.gautamkhosla.com (DNS record included) next to leash.gautamkhosla.com, and switches `ORIGIN` / `RP_ID` to
counterseal with leash as `LEGACY_ORIGIN` / `LEGACY_RP_ID` (see "Two hosts" below). The live data (3 accounts, 1 passkey
on 9 Oct 2026) keeps working on leash.gautamkhosla.com, and each account can move with the link described below.

Then check:

```bash
curl -s https://counterseal.gautamkhosla.com/v1/log/key           # publish this verifier key (README, site, auditors)
curl -s https://counterseal.gautamkhosla.com/v1/stats             # {"tree_size":0,...} on a fresh log
curl -s https://counterseal.gautamkhosla.com/.well-known/security.txt
curl -s -H "authorization: Bearer $STATS_TOKEN" https://counterseal.gautamkhosla.com/v1/admin/stats
```

and in the app: on https://leash.gautamkhosla.com/app sign in with the existing passkey, see the existing tokens and
holds, approve a test hold, then use Account, "Move with passkey" and finish on https://counterseal.gautamkhosla.com/app.
Check that https://leash.gautamkhosla.com/ answers 301 to counterseal and that `npx leashcli holds` (0.1.1) still works.

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
npx -y wrangler@4 d1 migrations apply leash --remote   # 0001 to 0004
npx -y wrangler@4 deploy
```

`routes`, `RP_ID` and `ORIGIN` in `wrangler.jsonc` name the domain users see (the passkey RP ID must be that domain);
leave out `LEGACY_ORIGIN` and `LEGACY_RP_ID` for a single host.
Without `VAPID_PRIVATE_JWK`, phone alerts are off. Without `LOG_KEY_JWK`, the broker works and receipts are skipped.

## Settings (vars in wrangler.jsonc)

| Var | Default | What |
|---|---|---|
| `LOG_ORIGIN` | counterseal.gautamkhosla.com/log | the log's name, signed into checkpoints; never change once the log has an entry |
| `FREE_LIMIT` | 10000 | receipts per account per month |
| `ACCOUNT_DAILY_CAP` | 2000 | receipts per account per UTC day |
| `GLOBAL_DAILY_CAP` | 10000 | appends per UTC day across all accounts (`503 log_at_capacity` above it) |
| `REG_PER_IP_DAY` | 5 | new accounts per IP (salted hash, IPv6 /64) per day |
| `PUB_RPM` | 600 | public log reads per IP per minute (in memory per isolate) |
| `PUB_DO_RPM` | 120 | public reads that reach the Durable Object (entries, proofs) per IP per minute |
| `TOOL_RPM` | 10 | Web Bot Auth checker directory lookups per IP per minute |

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
| Receipts API, 25 unsigned (the cap) | 2.5 ms (5.0) | 3.9 ms |
| Receipts API, 12 signed (the cap) | 3.3 ms (5.6) | 1.6 ms |
| `/v1/stats` | 0.1 ms (0.5) | |

These are Node numbers, not a load test on Workers. Run one before raising the batch caps in `server/src/receipts.js`.

## Two hosts: counterseal.gautamkhosla.com and leash.gautamkhosla.com

The product lives at **counterseal.gautamkhosla.com**. `wrangler deploy` adds it as a custom domain and creates its DNS
record (the zone gautamkhosla.com is already on the account); nothing has to be set up by hand. Both hostnames are
`routes` in `wrangler.jsonc`, served by the same Worker and the same assets, so the CSP, HSTS and every other header are
identical on both.

| | counterseal.gautamkhosla.com | leash.gautamkhosla.com |
|---|---|---|
| `/v1/*` API, `/p/*` proxy, `/.well-known/security.txt` | served | served exactly as before (the published CLI, leashcli 0.1.x, refuses redirects) |
| `/app` (dashboard, sign-in, approvals) | served; new passkeys use RP ID `counterseal.gautamkhosla.com` | served for the passkeys made there (RP ID `leash.gautamkhosla.com`); sign-up is refused and points to counterseal |
| Site pages (landing, docs, verify, tools, privacy, security, terms) | served | 301 to the same path and query on counterseal |

- **Passkeys.** WebAuthn ceremonies accept exactly two origins (`ORIGIN`, `LEGACY_ORIGIN`), each with its own RP ID
  (`RP_ID`, `LEGACY_RP_ID`), chosen by the request's Origin header (or, for the CLI and agents, the host they called).
  A client never names an RP ID. A challenge issued on one host is refused on the other. Each passkey records its RP ID
  (`passkeys.rp_id`; NULL means it was made before the move, on the old host).
- **Sessions.** The `__Host-leash` cookie is host-only, so each host has its own browser sessions. CSRF checks accept a
  write only from the same origin as the host it was sent to, and only from these two.
- **Moving an account.** On the old host, Account, "Move with passkey" makes a one-time link (32 random bytes, only its
  SHA-256 stored, single use, 10 minutes, 3 an hour per account, written to the audit log) to `counterseal/app#move=...`.
  The token travels in the URL fragment and in POST bodies, never in a path, query, log line or Referer. On the new host
  the person makes a new passkey that joins the same account. The old passkey keeps working on the old host until its
  owner removes it (Account, Passkeys; never the last one).
- **Approval links and phone alerts** point to counterseal once the account has a passkey there, and to the old host
  until then.
- **Pages added later** need their paths in `run_worker_first` (`server/test/domain.test.js` checks every page in
  `site/public` is listed), or the old host serves them instead of redirecting. Unknown paths on the old host get the
  404 page, not a redirect.
- **A single host.** Without `LEGACY_ORIGIN` and `LEGACY_RP_ID` the Worker serves one host, as before the move (the
  tests and `dev/local.js` run this way).
- **Rollback note.** Rolling the code back to the version before the move makes `ORIGIN` the only host again; passkeys
  made on counterseal then cannot sign in on the old host until the move is redeployed.

## Publishing the CLI

```bash
cd cli && npm publish --access public      # leashcli 0.2.0 (agent keys; its default server is counterseal); the planned new name is "counterseal"
```
