-- Merge: Record (public receipts) and Prove who (agent keys). Additive only: new tables, new nullable or defaulted
-- columns. Nothing existing is dropped, renamed or rewritten; existing accounts keep public receipts OFF until their
-- owner turns them on, and existing tokens stay unbound (no agent signature needed).

-- Record. The log itself lives in the ReceiptLog Durable Object; D1 keeps the control plane.
ALTER TABLE accounts ADD COLUMN receipts INTEGER NOT NULL DEFAULT 0;  -- 1: this account's broker decisions are sealed in the public log
-- the seam for a future paid plan (no billing exists): every account is on 'free'
ALTER TABLE accounts ADD COLUMN plan TEXT NOT NULL DEFAULT 'free';
-- the day the account last made a signed-in request or a proxied call (aggregate "active accounts" only)
ALTER TABLE accounts ADD COLUMN last_seen INTEGER;

-- receipts API keys (lsr_), for agents that log their own actions; only the SHA-256 of the key is stored
CREATE TABLE api_keys (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  hash        TEXT NOT NULL UNIQUE,
  label       TEXT NOT NULL,
  signer_pub  TEXT,                     -- optional Ed25519 public key (base64url): receipts must then be signed by it
  revoked     INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  last_used   INTEGER
);
CREATE INDEX api_keys_by_account ON api_keys(account_id);
CREATE INDEX api_keys_signer ON api_keys(signer_pub);

-- receipts per account: the month's count (quota), today's count (daily cap) and decisions that could not be sealed
CREATE TABLE usage (
  account_id   TEXT NOT NULL,
  month        TEXT NOT NULL,           -- YYYY-MM (UTC)
  receipts     INTEGER NOT NULL DEFAULT 0,
  day          TEXT,                    -- YYYY-MM-DD (UTC) that day_receipts counts
  day_receipts INTEGER NOT NULL DEFAULT 0,
  skipped      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (account_id, month)
);
-- appends per UTC day across all accounts (the log's global cap)
CREATE TABLE global_usage (day TEXT PRIMARY KEY, receipts INTEGER NOT NULL DEFAULT 0);
-- signed receipts: each (signer, signature) pair is accepted once; rows are pruned after 30 minutes
CREATE TABLE signed_receipts (signer TEXT NOT NULL, sig TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (signer, sig));

-- the public log index of the receipt for an audit entry (outside the hash chain, which covers the original columns)
ALTER TABLE audit ADD COLUMN receipt INTEGER;

-- Prove who. Agent public keys (Ed25519), registered with proof of possession; a key belongs to one account.
CREATE TABLE agent_keys (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  label       TEXT NOT NULL,
  keyid       TEXT NOT NULL UNIQUE,     -- RFC 7638 / RFC 8037 JWK SHA-256 thumbprint
  x           TEXT NOT NULL UNIQUE,     -- public key, base64url
  created_at  INTEGER NOT NULL,
  revoked_at  INTEGER,
  last_used   INTEGER
);
CREATE INDEX agent_keys_by_account ON agent_keys(account_id);
-- a token bound to an agent key needs that key's signature on every request (NULL: unbound, as before)
ALTER TABLE tokens ADD COLUMN agent_key_id TEXT;
-- signature nonces, each accepted once per key until its signature expires
CREATE TABLE nonces (k TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);

-- The domain move. Each passkey records the RP ID (host) it was made for; NULL: made before the move, on the old host.
ALTER TABLE passkeys ADD COLUMN rp_id TEXT;
-- the host a challenge was issued on; it is refused on the other one (NULL: issued before the move)
ALTER TABLE challenges ADD COLUMN origin TEXT;
-- one-time "move to the new host" links: only the SHA-256 of the token, single use, 10 minutes
CREATE TABLE move_links (
  hash        TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);
CREATE INDEX move_links_by_account ON move_links(account_id);
