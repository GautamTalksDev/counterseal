# Policy reference

Each `lsh_` token carries a policy. A policy can only **narrow** what the underlying key can do.

```json
{
  "allow": [{ "method": "GET", "path": "/repos/acme/**" }],
  "deny":  [{ "path": "/orgs/**" }],
  "hold":  [{ "method": "POST", "path": "/repos/*/*/releases" }],
  "default": "allow",
  "readOnly": false,
  "perMinute": 120,
  "unattendedIrreversible": [],
  "limits": { "writesPerHour": 200, "repeatsPer5Min": 3 },
  "money": { "currency": "usd", "perCall": 5000, "perDay": 20000 }
}
```

| Field | Type | Meaning |
|---|---|---|
| `allow` | rules | If present, only these calls pass (plus anything the default allows; see below). |
| `deny` | rules | Always refused with `403 leash_denied`. Checked first. |
| `hold` | rules | Held for approval even though the irreversible map does not require it. |
| `default` | `allow`, `hold`, `deny` | What happens to calls that match no rule. With an `allow` list, `allow` means "refuse the rest". |
| `readOnly` | boolean | Only `GET` and `HEAD`. |
| `perMinute` | 1 to 600 | Rate limit for this token. Default 120. |
| `unattendedIrreversible` | rules | Irreversible calls that may run **without** approval. Only settable in a passkey ceremony. |
| `limits` | `{writesPerHour?, repeatsPer5Min?}` | The breaker. `writesPerHour` 1 to 5000, `repeatsPer5Min` 2 to 100. Narrows, so any session may set it. |
| `money` | `{currency, perCall, perDay}` | Money caps for Stripe refunds and payouts. Loosens a hold, so only settable in a passkey ceremony. |

`limits` and `money` are checked strictly: a field that does not exist, a value out of range or a non-integer is refused
with `400 bad_policy` (a typo must not leave a token looking protected). A policy is fixed when the token is made; to change
a cap or a limit, make a new token and revoke the old one.

A **rule** is `{ "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "*", "path": "<glob>" }`. Paths are relative to
the provider's base (for Cloudflare, after `/client/v4`). Globs: `*` matches one path segment, `**` any depth, `{a,b}`
alternatives (which may contain `*` and `**`; braces cannot nest, and an unbalanced brace is refused with
`400 bad_policy`). A path may use `**` at most twice, and each segment (and each `{a,b}` alternative) at most one
wildcard, so `/repos/*/release-*` and `/**/issues/**` work but `/**/a/**/b/**` and `/*a*b` are refused with
`400 bad_policy`: globs run as regular expressions, and more wildcards than that can backtrack for seconds on a long
path.

Paths are matched in one canonical form, and that exact path is what the broker sends upstream: a path with an empty
segment (`//`, including a doubled trailing slash), a `;` path parameter or an encoded NUL is refused with
`400 bad_path`, one trailing slash is dropped (on requests and on your rules), and on GitHub, where owner and repo names
are case-insensitive, both the path and your rule are lowercased before matching. A `deny` or `hold` rule written for
`GET` also covers `HEAD`.

The irreversible map is stricter than your rules: it ignores case on every provider, also matches a path without a format
suffix such as `.json`, treats `HEAD` as `GET`, and holds any request that carries a method override (`_method`). A
method override hold cannot be pre-approved with `unattendedIrreversible`.

Paths for the newer providers are relative to their base, like Cloudflare's: Neon after `/api/v2`, Fly.io after `/v1`. Shopify is brokered through one path only, `/admin/api/<version>/graphql.json`
(a version such as `2026-07`, or `unstable`); every other path on the store is refused with `404 unsupported_path` before anything is sent. A Shopify key is stored with its store address
(`your-store.myshopify.com`), and a token goes only to that store. Shopify reads are POSTs too, so a `hold` or `deny` rule for Shopify names the GraphQL path, not a resource.

## Order of evaluation

0. The account is frozen: `423 account_frozen` for every call of every token, before anything else is read or written.
1. `deny`
2. `readOnly`
3. The irreversible map (held, unless the call matches `unattendedIrreversible`)
4. `hold`
5. `allow` list
6. `default`
7. Brakes, on a write that policy did not deny (a write is any request that is not `GET` or `HEAD`): a tripped token's
   writes are held (`brake.tripped`); a Stripe refund or payout under the money caps may pass step 3; a write that would
   go upstream is counted against `limits`.

## Brakes

**Money caps** (`money`). `perCall` and `perDay` are whole numbers of the currency's smallest unit, the way Stripe counts:
`5000` is 50.00 USD, `5000` is 5,000 JPY, `50000` is 50.000 KWD. `perDay` must be at least `perCall`. `currency` is three
lower case letters. A call passes only if all of this holds, and anything else is held with a rule id that says why:

| Rule id | Held because |
|---|---|
| `brake.money-unreadable` | The amount or currency could not be read with certainty: not a plain form body, a query string, a repeated, escaped or oddly spelled parameter, an amount that is not a whole number from 1 to 12 digits written the one canonical way, a refund that names both or neither of `charge` and `payment_intent` (or comes from a customer balance), a charge Stripe did not answer for or answered oddly, nothing left to refund |
| `brake.money-currency` | The call is in another currency than the caps (a refund takes the charge's currency) |
| `brake.money-per-call` | The amount is over `perCall` |
| `brake.money-per-day` | The day's total (UTC) plus this call would be over `perDay` |

A call that passes is allowed with rule `st.money:capped` and its amount is added to the token's total for the UTC day.
That is one conditional statement, so concurrent calls cannot both pass a cap they would together exceed. When Stripe
refuses the call (a 4xx), the amount is handed back; after a 5xx or no answer it stays counted, because the money may have
moved. A retry of the same call counts again. What you approve in the app is yours and is not counted.

Only `POST /v1/refunds` and `POST /v1/payouts`, spelled exactly so, can pass. Transfers, charges, top-ups, confirms and
captures, application fee refunds and the older `/v1/charges/<id>/refund` stay held by the map, caps or not. A cap turns a
map hold into an allow only when the rest of the token's policy (a `hold` rule, an `allow` list, `default`) would allow the
call; a call a `unattendedIrreversible` rule already lets through is still checked against the caps. A refund without
`amount` means everything that is left, which Counterseal reads from Stripe (`GET /v1/charges/<id>`: what was captured
less what was refunded; for a payment intent, what it received, which can only be too high). Amounts in the app and in
alerts use the currency's decimals (none for JPY, two for USD, three for KWD).

**Breaker** (`limits`). Counted once per write that is about to go upstream (not denied, not held, not an approved call).
`writesPerHour` counts the token's writes in a window that starts at its first write and lasts an hour; the write after
the limit trips the token. `repeatsPer5Min` counts one exact request (method, path, query, content type, body; headers
such as `Idempotency-Key` do not make it a different request) in a 5 minute window; with `3`, the fourth trips. Windows
are fixed, not sliding, so a burst across the end of a window can briefly reach twice the limit. POST requests that only
read (GraphQL, SQL) count as writes. A tripped token's writes are held with rule `brake.tripped` (at most 20 waiting per
token, as for every hold), its reads pass, and your devices are told once. Resetting it needs a passkey: it starts a fresh
window and closes the writes that were waiting.

**Freeze.** Stops every `lsh_` token of the account (`423 account_frozen`, for reads too) and the Approvals API (asking,
waiting for and using an approval answer `423` too). Approvals nobody used yet are void, and approving waits. The receipts
API keys (`lsr_`) are separate and are not stopped.

## Recipes

Read-only access to one GitHub org:

```json
{ "readOnly": true, "allow": [{ "path": "/repos/acme/**" }, { "path": "/orgs/acme/**" }] }
```

Let a release agent delete preview branches unattended, nothing else irreversible:

```json
{ "unattendedIrreversible": [{ "method": "DELETE", "path": "/repos/acme/web/git/refs/heads/preview-*" }] }
```

A support agent that may refund up to 50.00 USD a call and 200.00 USD a UTC day without asking, and is stopped if it
makes more than 100 writes an hour or sends the same request more than twice in 5 minutes (made with your passkey):

```json
{ "money": { "currency": "usd", "perCall": 5000, "perDay": 20000 }, "limits": { "writesPerHour": 100, "repeatsPer5Min": 2 } }
```

Hold every write to Stripe, not just the money-moving ones:

```json
{ "hold": [{ "method": "*", "path": "/v1/**" }], "allow": [{ "method": "GET", "path": "/v1/**" }], "default": "hold" }
```
