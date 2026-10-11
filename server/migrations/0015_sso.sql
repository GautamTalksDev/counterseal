-- Team sign-in with your identity provider (OIDC single sign-on). Additive only: three new tables and one new nullable
-- column. Nothing existing is dropped, renamed or rewritten; an account without a row in sso_configs behaves exactly as
-- before. SSO is for signing in and team membership only: approving a held action still needs the member's own passkey.

-- One identity provider per account, chosen by an owner with a fresh passkey ceremony. id is the public team login id
-- (it goes in the sign-in link); rev goes up on every change, so a sign-in started before a change cannot finish after it.
-- client_secret is optional (public clients use PKCE alone) and is sealed with the vault key like a vaulted API key.
CREATE TABLE sso_configs (
  id                     TEXT PRIMARY KEY,
  account_id             TEXT NOT NULL UNIQUE REFERENCES accounts(id) ON DELETE CASCADE,
  rev                    INTEGER NOT NULL DEFAULT 1,
  issuer                 TEXT NOT NULL,          -- exactly as the provider's discovery document states it
  client_id              TEXT NOT NULL,
  authorization_endpoint TEXT NOT NULL,
  token_endpoint         TEXT NOT NULL,
  jwks_uri               TEXT NOT NULL,
  algs                   TEXT NOT NULL,          -- JSON list: the signing algorithms accepted (RS256, ES256)
  auth_method            TEXT NOT NULL DEFAULT 'none', -- none | client_secret_basic | client_secret_post
  domains                TEXT NOT NULL,          -- JSON list of email domains whose people may sign in
  default_role           TEXT NOT NULL DEFAULT 'viewer', -- viewer | member: the role of someone new who signs in
  enforce                INTEGER NOT NULL DEFAULT 0,     -- 1: members other than owners must sign in with SSO
  ct TEXT, iv TEXT, wrapped_dek TEXT, dek_iv TEXT,       -- the sealed client secret, when there is one
  created_by             TEXT,
  created_at             INTEGER NOT NULL,
  changed_at             INTEGER NOT NULL
);

-- Sign-ins in progress (10 minutes, single use). Only the SHA-256 of the state is stored; binding is the SHA-256 of a
-- random value kept in a cookie in the browser that started the sign-in, so a callback link sent to someone else fails.
CREATE TABLE sso_states (
  hash        TEXT PRIMARY KEY,
  config_id   TEXT NOT NULL,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  rev         INTEGER NOT NULL,
  nonce       TEXT NOT NULL,
  verifier    TEXT NOT NULL,                     -- the PKCE code verifier (RFC 7636), sent only to the token endpoint
  binding     TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);
CREATE INDEX sso_states_by_expiry ON sso_states(expires_at);

-- Who is who: a person at the identity provider (issuer + sub, never the email) is one member of the account.
CREATE TABLE sso_identities (
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  issuer      TEXT NOT NULL,
  sub         TEXT NOT NULL,
  member_id   TEXT NOT NULL,
  email       TEXT NOT NULL,                     -- the verified email of the last sign-in, shown to owners
  created_at  INTEGER NOT NULL,
  last_login  INTEGER,
  PRIMARY KEY (account_id, issuer, sub)
);
CREATE INDEX sso_identities_by_member ON sso_identities(account_id, member_id);

-- how a web session was started: NULL a passkey (or before this column), 'sso' single sign-on
ALTER TABLE sessions ADD COLUMN via TEXT;
