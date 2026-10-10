-- The app, the first run and the privacy center (branch feat/app-trust). Additive only: seven nullable columns.
-- Launch funnel markers: each is written once, the first time it happens, with an UPDATE that only matches while the
-- column is still NULL (so repeats write nothing), and never from a poll. Accounts made before this migration get theirs
-- the next time it happens; /v1/admin/stats also counts older evidence (tokens, used tokens, alert devices).
ALTER TABLE accounts ADD COLUMN first_token_at INTEGER;  -- first agent token made
ALTER TABLE accounts ADD COLUMN first_call_at INTEGER;   -- first call through Counterseal (a proxied call or a guard approval request); never the demo
ALTER TABLE accounts ADD COLUMN demo_at INTEGER;         -- first "Try a held call" demo in the app
ALTER TABLE accounts ADD COLUMN installed_at INTEGER;    -- the app was first opened installed (standalone display mode)
ALTER TABLE accounts ADD COLUMN alerts_at INTEGER;       -- alerts were first turned on for a device
-- Retention: closed holds (with what was asked, the command or the request preview) are deleted this many days after they
-- closed. NULL means the default, 365. The owner can choose 30, 90 or 365 in the app.
ALTER TABLE accounts ADD COLUMN hold_days INTEGER;
-- Web sessions end after an hour without anything you did (OWASP ASVS 5.0 7.3.1): the time of your last action, written
-- at most once a minute per session. The app's background refresh does not count as an action. NULL (sessions made
-- before this migration): their creation time counts.
ALTER TABLE sessions ADD COLUMN seen_at INTEGER;
