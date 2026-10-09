-- Map 2026-10-10: Shopify keys are sent to the merchant's own store, <store>.myshopify.com, so that address is stored
-- with the credential. Additive only: one new nullable column. NULL (every existing credential, and every provider with a
-- fixed address) means "the provider's fixed host". The code checks the value strictly when it is saved and again before
-- every upstream call, and the key is sealed together with it (src/vault.js). The CHECK below is a last line of defence in
-- the database: one plain label, letters, digits and hyphens, then exactly .myshopify.com.
ALTER TABLE credentials ADD COLUMN host TEXT CHECK (host IS NULL OR (host GLOB '[a-z0-9]*.myshopify.com' AND host NOT GLOB '*[^a-z0-9.-]*' AND host NOT GLOB '*.*.myshopify.com' AND length(host) <= 77));
