-- PRA-133: NFC tap acceptance. Tap instruments enroll an Ed25519 public key
-- (the tap payload is instrument-signed for offline-capable verification)
-- and carry a monotonic tap counter (anti-replay: a spent counter can never
-- be presented again, even by a cloned payload).

ALTER TABLE instruments
    ADD COLUMN IF NOT EXISTS public_key_hex TEXT,
    ADD COLUMN IF NOT EXISTS tap_counter BIGINT NOT NULL DEFAULT 0;

ALTER TABLE instruments DROP CONSTRAINT IF EXISTS instruments_kind_check;
ALTER TABLE instruments
    ADD CONSTRAINT instruments_kind_check CHECK (kind IN ('PHONE_QR', 'NFC_CARD', 'NFC_TAP', 'USSD_ALIAS'));

ALTER TABLE conductor_scans DROP CONSTRAINT IF EXISTS conductor_scans_artifact_kind_check;
ALTER TABLE conductor_scans
    ADD CONSTRAINT conductor_scans_artifact_kind_check
    CHECK (artifact_kind IN ('TICKET', 'PASS', 'ACCOUNT_DEBIT', 'NFC_TAP'));
