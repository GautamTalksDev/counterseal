-- Brakes: money caps on Stripe refunds and payouts, a circuit breaker per token, and Freeze. Additive only: new nullable
-- columns and two small tables. Nothing existing is dropped, renamed or rewritten; every existing token and account
-- behaves exactly as before (not tripped, not frozen, no caps).

-- The breaker tripped (too many writes in an hour, or the same write repeated): the token's writes wait until a passkey
-- resets it. tripped_why is a fixed word (writes_per_hour or repeat), never request content.
ALTER TABLE tokens ADD COLUMN tripped_at INTEGER;
ALTER TABLE tokens ADD COLUMN tripped_why TEXT;

-- Freeze: every token of the account is stopped (423) until a passkey unfreezes it. Any signed-in session may freeze.
ALTER TABLE accounts ADD COLUMN frozen_at INTEGER;

-- What a token's money caps have let through today (UTC day), per currency, in the currency's smallest unit. One row per
-- token, day and currency; reserved with one conditional statement so concurrent calls cannot pass the cap together.
CREATE TABLE spend (
  token_id TEXT NOT NULL,
  day      TEXT NOT NULL,                 -- YYYY-MM-DD (UTC)
  currency TEXT NOT NULL,                 -- three lower case letters
  amount   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (token_id, day, currency)
);

-- Breaker counters: writes in the current hour window, and repeats of one exact request in the current 5 minute window.
-- A window starts at its first write and the row is reused once it has expired. Keys: w:<token id> and
-- r:<token id>:<first 12 hex of the request hash>. Only counts; no request content.
CREATE TABLE counters (
  k          TEXT PRIMARY KEY,
  n          INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
