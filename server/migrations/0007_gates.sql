-- Deploy Gate: a GitHub Actions job waits for a passkey approval, bound to the claims in GitHub's signed OIDC token.
-- Holds are the 0006 table (kind 'deploy'), so the app, alerts, approve, deny and receipts work unchanged. Additive only.

-- A gate is what the owner configures: which repository, workflows, refs, environments and events it accepts. Nothing is
-- accepted by default: the repository, at least one workflow and at least one ref are required.
CREATE TABLE gates (
  id TEXT PRIMARY KEY,                     -- gate_<24 hex>: pasted in the workflow, so it is public and not a secret
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  repository TEXT NOT NULL,                -- owner/name as configured: shown, and the match until the gate is bound
  workflows TEXT NOT NULL,                 -- JSON list of workflow file paths in that repository
  refs TEXT NOT NULL,                      -- JSON list of exact refs, or refs with one trailing * (a prefix)
  environments TEXT,                       -- JSON list, or NULL: the job does not have to use an environment
  events TEXT NOT NULL,                    -- JSON list of workflow event names
  repository_id TEXT,                      -- GitHub's immutable ids, bound by the first approved run (digits)
  repository_owner_id TEXT,
  bound_at INTEGER,
  publish_repo INTEGER NOT NULL DEFAULT 0, -- 1: this gate's public receipts carry the repository name (the owner opted in)
  credential_id TEXT,                      -- phase 2: the vaulted key this gate hands out a short-lived token for
  policy TEXT,                             -- phase 2: the token's policy (JSON)
  created_at INTEGER NOT NULL,
  last_used INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0,
  member_id TEXT                           -- who made it (two-person seal): with self-approval off they cannot seal what it asks for
);
CREATE INDEX gates_by_account ON gates(account_id);

-- The secret a waiting job polls with (gps_...): only its SHA-256 is stored, it reads one hold, and it ends with it.
CREATE TABLE gate_polls (
  hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  gate_id TEXT NOT NULL,
  hold_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX gate_polls_by_hold ON gate_polls(hold_id);

-- Phase 2: the short-lived token an approved run was given (so a revoked gate can revoke what it handed out).
CREATE TABLE gate_runs (
  token_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  gate_id TEXT NOT NULL,
  hold_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX gate_runs_by_gate ON gate_runs(gate_id);
