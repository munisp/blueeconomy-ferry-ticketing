-- PRA-136: refunds TO BlueFare fare accounts (ACCOUNT channel).
-- The booking refund rail (tickets.refunds, void dual control) returns value
-- to passenger clearing; this saga returns value to a fare account on the
-- ledger. Maker/checker four-eyes per repo convention (checker <> maker,
-- enforced in SQL and in DDL), durable idempotency, exactly-once against
-- the ledger via the deterministic transfer ID derived from refund_id.

CREATE TABLE IF NOT EXISTS fare_account_refunds (
    refund_id           TEXT PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES fare_accounts (account_id),
    amount_minor        BIGINT NOT NULL CHECK (amount_minor > 0),
    reason              TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL UNIQUE,
    state               TEXT NOT NULL CHECK (state IN ('REQUESTED', 'APPROVED', 'SETTLED', 'REJECTED')),
    maker               TEXT NOT NULL,
    checker             TEXT,
    ledger_transfer_id  TEXT,
    version             INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    correlation_id      TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at          TIMESTAMPTZ,
    settled_at          TIMESTAMPTZ,
    CHECK (checker IS NULL OR checker <> maker)
);

CREATE INDEX IF NOT EXISTS fare_account_refunds_account_idx
    ON fare_account_refunds (account_id, state);
