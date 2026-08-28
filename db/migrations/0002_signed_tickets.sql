-- Signed ticket artifacts + first-scan-wins boarding.
-- boarded_at is the atomic consumption guard (UPDATE ... WHERE boarded_at
-- IS NULL): one ticket can be boarded exactly once, at exactly one gangway.
-- Idempotent-safe via IF NOT EXISTS, mirroring 0001.

ALTER TABLE tickets ADD COLUMN IF NOT EXISTS boarded_at  TIMESTAMPTZ;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS boarded_by  TEXT;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS artifact_kid TEXT;

-- Backfill tickets boarded before this migration so the first-scan-wins
-- guard applies to them too (a pre-migration embarked ticket stays consumed).
UPDATE tickets SET boarded_at = updated_at WHERE embarked AND boarded_at IS NULL;
