-- Budget seal: hard spend caps on the AI model calls that go through Counterseal (OpenAI and Anthropic, metered from the
-- usage the provider returns, times the price table in src/prices.js). Additive only: two new tables. Nothing existing is
-- dropped, renamed or rewritten; an account with no rows here behaves exactly as before.

-- The caps a passkey holder set. scope: 'account', 'cred:<credential id>' (one vaulted key) or 'tok:<token id>' (one
-- agent). Amounts are in micro dollars (1 USD = 1,000,000); NULL is "no cap". ask = 1: at 80% of a cap the next call
-- waits for a passkey approval, and at 100% an approval raises that period's cap once by one cap ("ask me" mode).
-- runaway_* and unpriced_per_day are read from the 'account' row only.
CREATE TABLE budgets (
  account_id       TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  scope            TEXT NOT NULL,
  daily            INTEGER,
  monthly          INTEGER,
  ask              INTEGER NOT NULL DEFAULT 0,
  runaway_calls    INTEGER,          -- more calls than this in runaway_minutes trips the token's breaker
  runaway_micros   INTEGER,          -- more estimated spend than this in runaway_minutes trips it too
  runaway_minutes  INTEGER,
  unpriced_per_day INTEGER,          -- calls a token may make per UTC day to models or paths with no price; NULL: 10
  updated_at       INTEGER NOT NULL,
  PRIMARY KEY (account_id, scope)
);

-- Metered spend per scope and period, in micro dollars. period: 'd:YYYY-MM-DD' or 'm:YYYY-MM' (UTC). amount is reserved
-- before a call (an estimate) and settled after it (the real usage); the CHECK makes the reservation of every scope a call
-- touches one atomic step: if any of them would pass its cap, the single statement fails and nothing is written, so
-- concurrent calls near a cap cannot both pass. cap is the cap in force (a very large number when there is none), extra
-- what an "ask me" approval added for this period, over what real usage went past the cap after the call had been let
-- through (the true total is amount + over), asked = 1 once the 80% question was approved for this period.
CREATE TABLE budget_spend (
  account_id TEXT NOT NULL,
  scope      TEXT NOT NULL,
  period     TEXT NOT NULL,
  amount     INTEGER NOT NULL DEFAULT 0,
  over       INTEGER NOT NULL DEFAULT 0,
  cap        INTEGER NOT NULL,
  extra      INTEGER NOT NULL DEFAULT 0,
  asked      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (scope, period),
  CHECK (amount >= 0 AND amount <= cap + extra)
);
CREATE INDEX budget_spend_by_account ON budget_spend(account_id, period);
