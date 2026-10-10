-- Break-glass windows and team alert channels (two-person seal, part 2b). Additive only; 0009 is not touched.

-- A window lets the holds of the irreversible map through for at most 60 minutes, sealed and announced to the whole team.
-- It is opened by an owner or approver with a passkey, cannot be extended, and at most 3 are opened a day per account.
CREATE TABLE windows (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_id TEXT,                           -- a token's id, or g:<guard key id>; NULL: every token and guard key of the account
  opened_by TEXT NOT NULL,                 -- the member (the account's id for its founder)
  reason TEXT,                             -- what the opener wrote (up to 200 characters), shown to the team, never in a public receipt
  opened_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  closed_at INTEGER,
  closed_by TEXT
);
CREATE INDEX windows_open ON windows(account_id, expires_at);

-- A place a team's alerts are also sent (Slack, Discord, Google Chat). Notify only: approving always needs a passkey in the app.
-- The webhook URL is a secret: it is sealed with the vault's key (AES-GCM, bound to the account, the row and the kind).
CREATE TABLE channels (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                      -- slack | discord | gchat
  label TEXT NOT NULL,
  host TEXT NOT NULL,                      -- the host only, to show; the rest of the URL is the secret
  ct TEXT NOT NULL, iv TEXT NOT NULL, wrapped_dek TEXT NOT NULL, dek_iv TEXT NOT NULL,
  created_by TEXT,
  created_at INTEGER NOT NULL,
  last_ok_at INTEGER,
  failures INTEGER NOT NULL DEFAULT 0      -- consecutive; at 10 it stops sending until a test succeeds
);
CREATE INDEX channels_by_account ON channels(account_id);
