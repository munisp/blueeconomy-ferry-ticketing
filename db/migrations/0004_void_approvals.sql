-- Dual control (maker-checker) for voiding sold tickets (FE-7).
-- Voiding a PAID/ISSUED ticket at or above the configured amount threshold
-- requires two distinct officers: the first records a void approval request
-- (maker), the second confirms it by executing the void (checker). One row
-- per ticket; consumed_at marks the request spent by the confirming void.
-- Idempotent-safe, mirroring 0001-0003.

CREATE TABLE IF NOT EXISTS void_approvals (
    ticket_id        TEXT PRIMARY KEY REFERENCES tickets (ticket_id),
    requested_by     TEXT NOT NULL,
    amount_ngn_minor BIGINT NOT NULL CHECK (amount_ngn_minor > 0),
    correlation_id   TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at      TIMESTAMPTZ,
    consumed_by      TEXT
);
