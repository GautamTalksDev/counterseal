-- Two-person seal: team members, invites, roles and quorum votes. Additive only: new tables and new nullable or
-- defaulted columns. Nothing existing is dropped, renamed or rewritten. Every existing account keeps behaving exactly
-- as before: its one person is its owner, one passkey approval is enough (quorum 1), and that person may approve what
-- their own tokens ask for (self_approve 1).
--
-- Member ids. A member's id is 24 hex characters. The person who created the account (the founder) has the account's own
-- id as their member id, so every row written before this migration (member_id NULL) belongs to the founder:
-- the member behind a row is always COALESCE(member_id, account_id). The founder's members row is written the first time
-- the team is changed (the first invite); until then the founder is the owner without a row.
CREATE TABLE members (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,                  -- chosen by the member when they accept the invite (the founder: the account name)
  label       TEXT,                           -- what the owner called them in the invite, shown next to the name
  role        TEXT NOT NULL DEFAULT 'viewer', -- owner | approver | member | viewer
  created_at  INTEGER NOT NULL,
  invited_by  TEXT,                           -- member id of the owner who made the invite
  votes_from  INTEGER NOT NULL DEFAULT 0,     -- their seal counts from this time (24 hours after joining or promotion while two seals are required)
  removed_at  INTEGER                         -- removed: sessions, passkeys and alerts gone, tokens and keys revoked, votes dropped
);
CREATE INDEX members_by_account ON members(account_id);

-- who each row belongs to (NULL: the founder, see above)
ALTER TABLE passkeys ADD COLUMN member_id TEXT;
ALTER TABLE sessions ADD COLUMN member_id TEXT;
ALTER TABLE push_subs ADD COLUMN member_id TEXT;
ALTER TABLE device_codes ADD COLUMN member_id TEXT;   -- the member who approved a CLI sign-in; its session is theirs
ALTER TABLE move_links ADD COLUMN member_id TEXT;     -- the member whose passkey a move link adds
-- who made it (separation of duties: with self-approval off, its maker cannot seal what it asks for; removal revokes it)
ALTER TABLE tokens ADD COLUMN member_id TEXT;
ALTER TABLE guard_keys ADD COLUMN member_id TEXT;
ALTER TABLE api_keys ADD COLUMN member_id TEXT;

-- one-time invites: only the SHA-256 of the token is stored; single use, 2 hours by default and 24 at most, bound to the
-- account and to the owner who made it. The token travels in the URL fragment and POST bodies only.
CREATE TABLE invites (
  id          TEXT PRIMARY KEY,                -- public id, for listing and revoking (never the token or its hash)
  hash        TEXT NOT NULL UNIQUE,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  role        TEXT NOT NULL,                   -- approver | member | viewer
  label       TEXT NOT NULL,
  created_by  TEXT NOT NULL,                   -- member id of the owner
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  used_by     TEXT,                            -- the member id it created
  revoked_at  INTEGER
);
CREATE INDEX invites_by_account ON invites(account_id);

-- The quorum: how many different approvers must seal a held action, and whether the member who made the token or guard
-- key that asked may be one of them. Raising takes effect at once; lowering (or turning self-approval on) is stored as a
-- pending pair that takes effect at quorum_effective_at, 24 hours later, applied when read (there is no cron).
ALTER TABLE accounts ADD COLUMN quorum INTEGER NOT NULL DEFAULT 1;
ALTER TABLE accounts ADD COLUMN self_approve INTEGER NOT NULL DEFAULT 1;
ALTER TABLE accounts ADD COLUMN quorum_pending INTEGER;
ALTER TABLE accounts ADD COLUMN self_approve_pending INTEGER;
ALTER TABLE accounts ADD COLUMN quorum_effective_at INTEGER;

-- seals a hold needs (the effective quorum when it was made; a raise since then counts too) and who asked for it
ALTER TABLE holds ADD COLUMN needs INTEGER NOT NULL DEFAULT 1;
ALTER TABLE holds ADD COLUMN requested_by TEXT;     -- member id of the maker of the token or guard key; NULL: unknown

-- One seal per person per hold: a member with two passkeys, or two browsers, still counts once. Each seal is bound to the
-- hold's exact request hash. Rows go two days after they were cast (the audit log keeps every seal).
CREATE TABLE hold_votes (
  hold_id     TEXT NOT NULL,
  member_id   TEXT NOT NULL,
  account_id  TEXT NOT NULL,
  passkey     TEXT NOT NULL,                   -- 16 hex characters of SHA-256 of the credential id, as the audit log records
  req_hash    TEXT NOT NULL,
  at          INTEGER NOT NULL,
  PRIMARY KEY (hold_id, member_id)
);
CREATE INDEX hold_votes_by_account ON hold_votes(account_id, member_id);
