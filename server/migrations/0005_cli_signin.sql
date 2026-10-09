-- CLI sign-in against device-code phishing. Additive only: new nullable columns and an index.
-- Where a sign-in started, coarse, from Cloudflare's request data: the country code and the network's name and number.
-- Never the IP address. Shown on the approval screen; the row goes when the code expires (5 minutes, then the sweep).
ALTER TABLE device_codes ADD COLUMN created_at INTEGER;
ALTER TABLE device_codes ADD COLUMN country TEXT;
ALTER TABLE device_codes ADD COLUMN network TEXT;
ALTER TABLE device_codes ADD COLUMN asn INTEGER;
-- a CLI session keeps where its sign-in started (country and network name), so its owner can review and revoke it
ALTER TABLE sessions ADD COLUMN country TEXT;
ALTER TABLE sessions ADD COLUMN network TEXT;
CREATE INDEX sessions_by_account ON sessions(account_id, kind);
-- what a CLI session made (its public id; NULL: made by a web session or before this migration). Revoking the session
-- revokes these too, and a token a CLI session mints never outlives it.
ALTER TABLE tokens ADD COLUMN session_id TEXT;
ALTER TABLE agent_keys ADD COLUMN session_id TEXT;
ALTER TABLE api_keys ADD COLUMN session_id TEXT;
