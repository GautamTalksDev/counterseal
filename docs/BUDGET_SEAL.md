# Budget seal

Spend limits on the AI model calls your agents make through Counterseal, best effort on streaming. Status: built on branch `budget-seal`,
not deployed, not merged.

Providers send budget alerts, often hours late. They do not stop the next call. Counterseal already sits between the
agent and the API: the agent holds a Counterseal token, the real key stays in the vault. So Counterseal can count what
each call costs and refuse the next one before it is sent.

## What it caps

Spend that flows through Counterseal, on two AI model APIs:

| Provider | Metered calls | Free (not counted) | Everything else |
|-|-|-|-|
| OpenAI (`/p/openai/...`) | `POST /v1/chat/completions`, `/v1/responses`, `/v1/completions` | file uploads, `responses/input_tokens`, deletes | unpriced |
| Anthropic (`/p/anthropic/...`) | `POST /v1/messages` | `messages/count_tokens`, deletes | unpriced |

Caps can be set per **agent** (one Counterseal token), per **key** (one vaulted credential, every agent that uses it) and
for the **whole account**, each for the UTC day and the UTC month. A call has to fit every cap it touches.

- **At a cap**, the next call gets `402 budget_exhausted` and is never sent. The answer says which budget is full, how
  much is left, what the call could have cost and when the budget starts again (next UTC midnight, or the first of the
  next UTC month).
- **"Ask me" mode** (per budget): the first call past 80% waits for your passkey. Approving lets that period run on to
  the cap. At the cap the call waits again, and approving raises that period's cap once, by one cap ("$15 of $15.
  Continue to $30?"). Deny, and nothing changes.
- **Runaway detector** (account setting, per agent): more calls, or more estimated dollars, in a window of 1 to 60
  minutes than you allow trips that agent's breaker (the same breaker as Brakes). Its writes wait until you reset it
  with your passkey. This is the fan out case: hundreds of sub agents in minutes.
- **Alerts**: your devices are woken at 50%, 80% and 100% of a cap. The push carries nothing; the app shows the numbers.
- **Freeze** still stops everything (423) before any budget is read.
- **Live view**: the Budget page in the app shows today and this month for the account, every metered key and every
  agent, with bars, what is left and the price table date.

Setting, raising, lowering or removing any budget takes a fresh passkey ceremony that names the exact settings, by an
owner or approver in the web app. A command line session cannot change a budget. Every change is in the audit log.

## How a call is counted

1. Before the call: an estimate is reserved. It leans high on purpose: every input byte counts as a third of a token
   (English is about four characters a token) and the full output limit the request allows (`max_tokens`,
   `max_completion_tokens` or `max_output_tokens`; 4096 if none).
2. The reservation adds the estimate to all six totals the call touches (agent, key, account; day, month) in one SQL
   statement. A `CHECK` on the table makes the whole statement fail if any total would pass its cap. So two calls near
   a cap cannot both pass; the tests run 30 and 50 at once.
3. After the answer: the real cost (the usage the provider returned, times the price table) replaces the estimate.
   Streams are read too (OpenAI sends usage only when the request sets `stream_options.include_usage`; without it the
   estimate stays). A refusal (4xx) gives the reservation back. A 5xx or an answer whose usage cannot be read keeps the
   estimate, because the call may have run.
4. If the real cost is above the estimate (the provider ran longer than the request allowed), the true total is kept
   (`over`). It can pass the cap by that call and by every other call already in flight. Nothing new goes after it.

## Prices

The table is in code, in `server/src/metered.js`: USD per million tokens for input, output and cache reads, with the
date it was read (`PRICES_DATE`, now 2026-10-10) and the source pages:

- OpenAI: https://developers.openai.com/api/docs/pricing (Standard tier, short context)
- Anthropic: https://platform.claude.com/docs/en/about-claude/pricing

Rules that keep it honest:

- Exact model names only. On Anthropic a dated snapshot of a listed model counts as that model. Nothing is matched by
  prefix, so a new model is never priced as an older one.
- A model that is not in the table is **unpriced**, never guessed. Each agent gets 10 unpriced calls a UTC day (the
  account can set 0 to 1000); past that each one waits for your passkey. Images, audio, batches and other paid calls
  on these hosts count the same way.
- The dear side wins: cache reads at the listed cache price, cache writes at twice the input price (the one hour rate),
  OpenAI cached input at the full input price, Claude Haiku 5.5 at its long prompt tier. If the provider says it ran a
  dearer listed model than the one asked for, the dearer price is charged.
- **Prices go stale.** The table must be re-read from the two pages above before each release, and the date updated.
  A stale table can undercount if a provider raises prices. The Budget page shows the date.

## What it cannot cap

Say this plainly wherever the feature is described:

- **Only calls that go through Counterseal.** A key used directly, another key in the same account at the provider, a
  key in a `.env` file, the provider's own console or playground, and other tools are not seen.
- **Not cloud bills.** AWS, Google Cloud, Cloudflare, Vercel or any usage billed by a provider's own account is outside
  it. See [CLOUD_KILL_SWITCH.md](CLOUD_KILL_SWITCH.md) for a later design.
- **Not the provider's own invoice.** Counterseal's numbers are an estimate from the usage the provider returned and a
  price table. Taxes, credits, discounts, batch pricing, long context surcharges and price changes are not modelled.
  Treat the meter as a seatbelt, not as the bill.
- **One call can go past a cap**, by the difference between its estimate and its real cost (see step 4).
- **Other APIs in the map** (GitHub, Cloudflare, Stripe and the rest) are not metered. Stripe refunds and payouts keep
  their own money caps (Brakes).
- It does not revoke or rotate the real key at the provider.

Claims allowed: "Counterseal stops your agent's AI calls at a budget you set, before they are sent, for calls that go
through Counterseal." Not allowed: "stops runaway AI bills", "caps your OpenAI bill", or anything that implies it sees
usage outside Counterseal.

## API

| Method and path | Who | What |
|-|-|-|
| `GET /v1/budget` | any member, any session | the live view: every scope, today and this month, caps, what is left, reset times, price table date |
| `POST /v1/budget/begin` | owner or approver, web | starts the passkey ceremony for the exact settings in the body |
| `POST /v1/budget/finish` | owner or approver, web | the same settings plus `challengeId` and `credential` |
| `GET /v1/alerts` | any session | now also lists totals at or past 50% of a cap (`budget`) |

Settings: `{ "scope": "account" | "cred:<key id>" | "tok:<token id>", "dailyCents": 500, "monthlyCents": 5000, "ask": true,
"runaway": { "calls": 60, "cents": 200, "minutes": 5 }, "unpricedPerDay": 10 }`. Every field except `scope` is optional; `null`
means no cap. `runaway` and `unpricedPerDay` are for `account` only. Unknown fields, wrong types and out of range values are
refused, never defaulted. Sending only a scope removes its budget.

New hold rules: `budget.ask`, `budget.cap`, `budget.unpriced`. New audit actions: `budget_set`, `budget_raised`,
`budget_alert`, `budget_block` (at most one per agent every 10 minutes). New breaker reason: `runaway`. Receipts and logs
carry rule ids, scopes, periods and amounts only, never prompts, keys or tokens.

## Cost on Workers Free

A metered call adds 3 D1 queries (read the budgets, reserve, settle) and 1 more with the runaway detector on; the test
with every option on stays under 30 queries for the whole call. No new cron: old totals go in the existing sweep (day
totals after 35 days, month totals after 13 months). Settling reads a copy of the answer after the response is sent, so
the agent is not slowed down.

## Shipping it (a later Tuesday)

1. Re-read both price pages and update `PRICES` and `PRICES_DATE` in `server/src/metered.js`.
2. Review and merge branch `budget-seal` into `merge`, then the normal release path. Run the full suite.
3. Take a D1 time travel bookmark, then apply migration `0014_budget_seal.sql` to the remote database, the same way as
   the earlier migrations in [DEPLOY.md](DEPLOY.md). It only adds two tables; nothing existing changes, and an account
   with no budget behaves exactly as before.
4. Deploy the Worker and the site (the app has a new Budget page and lists OpenAI and Anthropic in the vault).
5. Check with a test key: a token, a 1 cent daily cap, two calls; the second must answer 402 and not reach the provider.
6. No new secrets, no new cron, no change to the public irreversible map (still 10 APIs, map `2026-10-10.1`).
