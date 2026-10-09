# Security

Counterseal holds other people's production keys and runs a public log. This page is the honest version of how it
protects them. The full threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting a vulnerability

Email **security@gautamkhosla.com** or open a private advisory on GitHub (Security tab, "Report a vulnerability").
Please do not open a public issue. You will get a reply within 7 days. Good-faith research is welcome; do not access
other people's data or degrade the service. `/.well-known/security.txt` carries the same contact.

## What it guarantees

| Property | How |
|---|---|
| The agent never holds a real key | Envelope-encrypted vault; agents hold `lsh_` proxy tokens; no API returns a secret |
| Irreversible calls wait for a human | Versioned irreversible map; approval needs a fresh passkey assertion from a web session and covers one exact request (method, host, path, query, content type, body hash) once, within 10 minutes |
| A leaked token alone is useless (for bound tokens) | A token bound to an agent key needs an RFC 9421 signature by that key on every request: method, full URL, body digest and content type covered, 5 minute window, each nonce once; checked before the policy, the token's rate limit and any upstream call; never downgraded to unsigned |
| A decision on the record cannot be quietly rewritten | Per-account hash-chained audit log (`/v1/audit/verify`); with receipts on, each decision is also an entry in a public RFC 6962 Merkle log with Ed25519-signed C2SP checkpoints; consistency proofs show the log only grew |
| No agent or API key holder can forge a broker receipt | `source: "broker"` is set only by the broker, outside the receipt; the receipts API fills only the inner receipt and refuses unknown fields |
| Public receipts leak nothing private | Broker receipts carry the method, the provider host, the decision, rule id, map version, two booleans, the time and the hash of the private audit entry; per-entry salted submitter commitments; never a path, query, body, key, token, account id, name, email or IP (tested) |
| A coding agent's held command waits for your passkey (guard, not yet deployed) | The guard asks `POST /v1/approvals` with a guard key (`lsg_`) that can ask and read its own approvals, never approve; an approval covers one exact command, its agent and folder name (SHA-256 bound), once, within 10 minutes, consumed atomically. Enforced on the agent's machine: a seatbelt, not a sandbox |
| An agent stays inside the money you gave it | Stripe refunds and payouts pass unattended only under a token's per-call and per-day caps (set with a passkey, one currency, amounts read by the map's strict form parser and held when anything is ambiguous, the day's total reserved atomically); a breaker holds the writes of a token that makes too many in an hour or repeats one request; Freeze stops every token at once and only a passkey ends it. This covers calls through Counterseal, not LLM tokens and not SQL sent over a database connection |
| A signed reported receipt was signed by that key | Receipts keys bound to an Ed25519 signer (proof of possession naming the log and the account) accept only receipts that signer signed, with a `ts` within 10 minutes, each signature once; small-order and non-canonical keys and signatures are refused |

## Controls, mapped to OWASP Top 10 (2025) and OWASP API Security Top 10 (2023)

| Area | Control | OWASP |
|---|---|---|
| Sign-in | Passkeys only (WebAuthn, user verification required, origin and RP ID checked, single-use 5-minute challenges, signature counters); a passkey already registered gets 409 | A07 |
| Sessions | `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Strict`, 12 h; CLI sessions are bearer tokens stored only as SHA-256 hashes, last 7 days, and can be revoked in the app together with every token, agent key, receipts key and guard key they made, even after they signed out; a token, receipts key or guard key a CLI session makes never outlives it | A07 |
| Guard keys and approvals | `lsg_` keys shown once, stored as SHA-256, 20 active per account; they authenticate only `/v1/approvals*`. Asking: fixed vocabularies (kind, agent, rule id), sizes capped, unknown fields refused, a folder name never a path, NUL and unpaired surrogates refused; 60 new holds an hour and 20 waiting per key, 100 waiting per account, one alert a minute per account. Waiting: a long poll of at most 20 s that writes nothing to D1. Using: one atomic update bound to key, hash and expiry. Deny reasons: 200 characters, control, format and line-break characters removed | A01, A04, API4, API6 |
| CLI sign-in (device code) | Against device-code phishing (RFC 8628 section 5.4, the IETF cross-device flows BCP): the code is never in a link (no `verification_uri_complete`; the app ignores a code in its address and warns); the person types it, sees what is granted and the country and network the sign-in started from next to their own (Cloudflare request data, never an IP), and must confirm they ran it before the passkey; "No, deny it" sends `access_denied`. Codes: 8 characters from a 28-character alphabet without modulo bias, single use, 5 minutes. Limits: 10 starts an hour per network, 10 lookups or denials per 10 minutes and 10 approvals an hour per account. Each sign-in is audited and wakes the owner's devices with a one-tap revoke | A07, API2, API4 |
| CSRF | Web writes require an `Origin` equal to the host they were sent to, from an allow list of two (counterseal and the old leash host), and an `x-leash: 1` header; CORS only on the public log's read endpoints | A01 |
| Two hosts | Each host has its own RP ID, chosen by the request's Origin (or its URL) from that allow list; a client never names one; passkeys and challenges are refused on the other host; host-only cookies; the old host serves `/v1`, `/p` and `/app` and redirects other pages | A01, A07 |
| Moving an account | One-time link made after a fresh passkey assertion on the old host: 32 random bytes, stored hashed, single use, bound to the account, 10 minutes, 3 an hour, in the URL fragment and POST bodies only, audited; the passkey it adds alerts the owner's devices | A07 |
| Authorization | Every query is scoped by `account_id`; another account's holds, tokens, credentials, agent keys, receipts keys and receipts return 404 (tested) | A01, API1 |
| Privilege separation | CLI sessions can mint tokens (with a breaker if they like), register agent keys, make guard keys, deny holds and freeze the account (stopping is always safe), but cannot approve holds, pre-approve irreversible operations, set money caps, reset a tripped breaker, unfreeze, delete vaulted keys, revoke agent keys, turn receipts on or off, approve, deny or revoke CLI sign-ins, or delete the account | A01, A06 |
| Secrets | AES-256-GCM per secret, data key wrapped by a master key (Workers secret), AAD binds account, row and provider; tokens, sessions and receipts keys stored as hashes; agent keys public only (a JWK with `d` is refused) | A04 |
| Input | Parameterized SQL; bodies capped while streaming (16 KB for the API, 256 KB for receipts, 1 MB for the proxy); strict JSON; strict receipt schema; plain-decimal query parameters | A05, API8 |
| SSRF | Upstream hosts fixed per provider, no redirects; push endpoints limited to known push services; the Web Bot Auth checker's directory fetch reaches only https public host names on port 443, at the fixed well-known path, no redirects, 5 s, 64 KB | A01, API7 |
| Abuse | Per token (policy, default 120 a minute), per account, per IP (salted hash, IPv6 /64 after full expansion), per receipts key; 5 sign-ups per IP a day; receipts quotas reserved atomically before appending; a global daily cap; reads that reach the log's Durable Object limited separately | API4 |
| Integrity | Appends serialized in one Durable Object and written in one storage transaction; the log pins its name and key at the first append and refuses to sign under others; approvals consumed atomically | A08 |
| Headers | Strict CSP with `require-trusted-types-for 'script'`, no innerHTML anywhere (CI check), HSTS, COOP, CORP, `X-Frame-Options: DENY`, `Permissions-Policy`; self-hosted fonts, no third-party requests | A02 |
| Supply chain | Zero runtime dependencies in the Worker, the CLI and the SDK; GitHub Actions pinned by SHA | A03, A08 |
| Logging | Security events (bad tokens, signatures, keys, CSRF, replays, rate limits, quota) and unexpected errors go to the live log stream with code, method and a redacted path (proxied paths are cut to the provider); never IPs, keys, tokens, cookies, account ids or bodies. Workers Logs are off, so nothing is stored | A09 |
| Errors | Clients get a generic 500 that leaks nothing; a full, broken or unreachable log never blocks a broker decision (the receipt is counted as skipped) | A10 |
| Agents (LLM Top 10) | Excessive agency is the threat this exists for: irreversible calls are held outside the model; tool descriptions tell the agent not to route around holds | LLM06 |

## What it does not protect against

- A human approving something they should not. The approve screen shows the exact method, host and path, the reason, and
  a preview of the request (query string, SQL or GraphQL, body; at most 2 KB). For a coding agent's command it shows the
  whole command (up to 4,096 characters, never cut) with hidden characters made visible.
- An agent getting around its guard. The coding-agent guard runs on the agent's machine and matches a map of commands: an
  agent that edits its hook settings, wraps a command in a script, or runs something the map does not know is not
  stopped by it. It is a seatbelt, not a sandbox; for a hard stop, give the agent a Counterseal token, not the real key.
- A person who approves a CLI sign-in someone sent them. The screen shows where it started and asks whether they ran it,
  and the alert and one-tap revoke limit the damage (a CLI session cannot approve holds), but a person who approves
  anyway has signed that command line in for up to 7 days. Country and network checks can be fooled by a VPN.
- An upstream API key that is itself over-scoped being used outside the broker. Keep keys you vault only in the vault.
- Calls the map does not know are irreversible. The map is versioned and conservative (every `DELETE` on GitHub,
  Cloudflare, Stripe, Supabase, Vercel, Neon, Fly.io and Resend, every Railway mutation except redeploy and restart, SQL
  unless plainly read-only); add `hold` rules to your policy for anything else.
- SQL that never passes through a management API. The map covers management APIs only: SQL sent straight over a database
  connection string (to Neon, Supabase or any Postgres) never passes through Counterseal.
- A Shopify mutation added after the map version whose name does not contain `delete` or `destroy`. Shopify's mutations are
  held by name (patterns plus reviewed lists), not by an allow list, and are checked against each Shopify release.
- A compromised agent machine: its agent key signs for whoever controls it, and a CLI session there can mint new
  tokens. Revoke the key; bound tokens stop at once. Approvals still need your passkey.
- The truth of reported receipts: they prove what an agent sent, when, and (if signed) with which key.
- The log operator showing two different histories: anyone comparing checkpoints would catch it, but only external
  witness cosigning (roadmap) prevents it.
- A compromised Cloudflare account. The master key and the log key live in Workers secrets.

## Hardening, 7 Oct 2026

- SQL to Supabase and D1 is an allow list: only a single SELECT, WITH ... SELECT, EXPLAIN (without ANALYZE) or SHOW
  passes, read by a real tokenizer. Dollar quotes, DO, EXECUTE, CALL, COPY, a second statement or anything unreadable is
  held. D1 bodies: every `sql`, `query` and batch entry is checked.
- Paths: empty segments are refused, one trailing slash is dropped, GitHub owner and repo are matched case-insensitively,
  and the exact path that was checked is the one sent upstream.
- GitHub force-push and visibility rules parse the JSON body; Railway mutations are read by a GraphQL lexer; Stripe money
  movers are held. Holds store a capped preview (deleted a day after the decision; the audit log keeps only its hash).
- Deleting your account needs a fresh passkey ceremony; deleting a vaulted key needs a web session.

## Hardening, 9 Oct 2026 (map `2026-10-09.1`)

Every item has a test in `server/test/bypass.test.js`: repeated or case-variant Stripe parameters, strict JSON (repeated
or case-folded keys are unreadable and held), Cloudflare purge read from parsed JSON, GraphQL parameters outside the body,
method overrides held everywhere, path variants and HEAD for GET, non-UTF-8 bodies refused, glob compilation, SQL through
other doors (migrations, D1 import, time travel restore).

## Five more providers, 10 Oct 2026 (map `2026-10-10.1`, migration `0010`)

Vercel, Neon, Fly.io, Resend and Shopify. Each is mapped from the provider's own published reference (Vercel, Neon, Fly.io
and Resend from their OpenAPI documents, Shopify from its Admin GraphQL schema, all 484 mutations of 2026-01, 2026-07 and
2026-10), and every rule cites the reference page of its endpoint in `server/src/providers.js`. Every item has a test in
`server/test/map-1010.test.js`, run in every spelling (case, trailing slash, format suffix, encoded letters), with the
parser-differential patterns of the 9 Oct hardening (repeated and escaped keys, query-string and form copies, method
overrides, non-UTF-8 bodies).

- **Shopify's store address is the one upstream address that is not fixed in code.** It is where a vaulted key is sent, so it
  is the SSRF surface and is held to the strictest check in the code (`storeHost`): printable ASCII, exactly one label of
  letters, digits and hyphens that starts and ends with a letter or digit, then exactly `.myshopify.com`. A port, user info,
  path, query, fragment, IP address, trailing dot, further subdomain, punycode (`xn--` or any `--` in the third and fourth
  places) or non-ASCII character is refused. It is checked when the key is added and again before every upstream call, the
  key is sealed together with its address (the address is part of the AES-GCM additional data, so a row moved to another
  store does not decrypt), and the database refuses anything else (a CHECK constraint on migration 0010).
- **Only the Admin GraphQL endpoint is brokered on Shopify** (`/admin/api/<version>/graphql.json`). Every other path on the
  store (the legacy REST API, storefront pages, app proxies) is refused with `404 unsupported_path` before anything is sent,
  so a key never reaches a page it was not meant for.
- **Public receipts never carry a store.** The host word for Shopify is `myshopify.com`; the store address is in the owner's
  private audit log and holds only.
- **Resend: a send to more than one person is held** (a list, a list hidden in one string, `cc`, `bcc`, batches, broadcasts,
  inbox replies and forwards, enabling an automation); one recipient passes. Sent email cannot be unsent.
- **Minting a new key is held on every new provider** (Vercel tokens, Neon and Resend API keys, Fly.io deploy tokens, Shopify
  delegate tokens): an agent that could mint one would hold a real key that does not go through Counterseal.
- A GraphQL read is a POST, so on Shopify (as on GitHub and Railway) it is recorded like any other POST.

## The merge, 9 Oct 2026

The public log (from WITNESS, after its own launch audit) and Ed25519 request signing (from SIGIL) became part of the broker. <!-- brand:history -->
The adversarial review of the merged system added: signed requests with a body must cover
the content type; tighter limits on reads that reach the log's Durable Object; the log refuses a changed name or key; a
log key whose private part does not match its public part is refused; receipt batches halved (25, 12 signed) for a CPU
margin on Workers Free; proxied paths are never written to log lines. Tests: `server/test/joints.test.js`,
`server/test/merge-hardening.test.js`, `server/test/migration.test.js`.

## Second pass before launch, 9 Oct 2026

- CLI sign-in against device-code phishing (see the CLI sign-in row above and threat model S11); a command line that
  signs itself out cannot hide what it made; the sign-in page is always counterseal, where accounts are made.
- Approval fatigue: at most 20 waiting holds per token and 100 per account (`429 too_many_holds`), and held requests
  alert devices at most once a minute per account.
- The audit hash chain no longer forks when one account writes in parallel (the insert checks the head it commits to).
  Agent keys and receipts keys made and revoked are now in the audit log.
- Removing a passkey needs a fresh passkey ceremony and signs out the account's other browsers; a passkey added through
  a move link alerts every device.
- Ceilings per account (OWASP API4): 50 vault keys, 200 live tokens, 20 receipts keys; list responses are bounded.
- Policy globs: `**` at most twice and one wildcard per segment (three `**` against a long path backtracked for seconds).
- Proxied answers cannot act on a browser at the counterseal origin: upstream CORS, Clear-Site-Data, policies, Link and
  Refresh are dropped; a sandboxing CSP, nosniff and CORP are set.
- Push devices can be added, removed or tested only from a web session.
- Pages served through the Worker get the site's security headers even if `_headers` is not applied to them.
Tests: `server/test/cli-signin.test.js`, `server/test/second-pass.test.js`.

## Approvals API, 9 Oct 2026 (branch `feat/approvals`, migration 0006, not deployed)

Guard keys and `POST /v1/approvals` for what the broker does not proxy (a coding agent's shell commands, MCP tool calls),
on the existing holds, approve, deny and receipts paths. Threat model section G; tests in
`server/test/approvals.test.js` (a guard key can never approve, use once, wrong hash, expiry, deny reasons, input
validation, the exact command on the card, the long poll's zero writes, limits, receipt privacy, revocation with the key
and with the CLI session that made it, D1 budgets) and the migration test on live-shaped data. Guard keys follow the
second pass: they end with the CLI session that made them and are revoked with it even after it signed out, guard holds
share the account's 100 waiting holds and its one alert a minute, and guard key events are in the audit log.

## Brakes, 9 Oct 2026

Money caps on Stripe refunds and payouts, a breaker per token, and Freeze (threat model S17 to S20; migration 0008, additive).
Amounts are read by the map's own strict form parser and held when they cannot be read one way; the day's total is reserved
with one conditional statement; only refunds and payouts can pass; caps, a breaker reset and an unfreeze need a passkey,
while a freeze can come from any signed-in session. Not covered, and said so: LLM spend, SQL over a connection string, calls
already in flight when a freeze lands, and a total that can reach twice the daily cap across midnight UTC.
Tests: `server/test/brakes-money.test.js`, `brakes-breaker.test.js`, `brakes-freeze.test.js`, `brakes-headline.test.js`,
`brakes-mcp.test.js`, and the migration test.
