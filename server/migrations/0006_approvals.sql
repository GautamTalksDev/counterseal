-- Approvals for actions Counterseal does not proxy: coding-agent commands and MCP tool calls now (CI deploys later).
-- They reuse the holds table, so the app, alerts, approve, deny and receipts work unchanged. Additive only.
ALTER TABLE holds ADD COLUMN kind TEXT NOT NULL DEFAULT 'proxy';  -- proxy | shell | tool | deploy
ALTER TABLE holds ADD COLUMN agent TEXT;                          -- fixed vocabulary (claude-code, codex, ...), NULL for proxy holds
ALTER TABLE holds ADD COLUMN deny_reason TEXT;                    -- from the approver, shown to the agent (200 chars at most)
ALTER TABLE holds ADD COLUMN context TEXT;                        -- JSON {cwd, session, map} for guard holds: a folder name, never a path
-- Guard keys: what a coding-agent hook holds. They can ask for an approval and read their own, never approve.
CREATE TABLE guard_keys (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  hash TEXT NOT NULL UNIQUE,      -- SHA-256 of the lsg_ key; the key itself is shown once
  label TEXT NOT NULL,
  session_id TEXT,                -- the CLI session that made it: revoked with it, and never outlives it
  expires_at INTEGER,             -- NULL: made in the app, lasts until revoked
  created_at INTEGER NOT NULL,
  last_used INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX guard_keys_by_account ON guard_keys(account_id);
