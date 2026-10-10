-- The broker's own decisions come first in the public log (final security gate, 9 Oct 2026). Receipts an agent reports
-- through POST /v1/receipts are also counted here, on the same row as the day's total, so they can be held to their own
-- share of the day (REPORTED_DAILY_CAP) in the same single statement. Additive only; existing rows start at 0.
ALTER TABLE global_usage ADD COLUMN reported INTEGER NOT NULL DEFAULT 0;
