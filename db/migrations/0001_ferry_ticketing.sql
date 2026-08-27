-- Workstream B: inland waterway e-ticketing + safety telematics.
-- All statements are idempotent-safe via IF NOT EXISTS. Capacity is enforced
-- in the database (CHECK + row locking); overbooking is impossible by
-- construction.

CREATE TABLE IF NOT EXISTS operators (
    operator_id      TEXT PRIMARY KEY,
    registered_name  TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vessels (
    vessel_id        TEXT PRIMARY KEY,
    operator_id      TEXT NOT NULL REFERENCES operators (operator_id),
    vessel_name      TEXT NOT NULL,
    imo_number       TEXT,
    capacity         INTEGER NOT NULL CHECK (capacity > 0),
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vessels_operator_idx ON vessels (operator_id);

CREATE TABLE IF NOT EXISTS trips (
    trip_id              TEXT PRIMARY KEY,
    vessel_id            TEXT NOT NULL REFERENCES vessels (vessel_id),
    operator_id          TEXT NOT NULL REFERENCES operators (operator_id),
    route_reference      TEXT NOT NULL,
    terminal_reference   TEXT NOT NULL,
    scheduled_departure  TIMESTAMPTZ NOT NULL,
    fare_ngn_minor       BIGINT NOT NULL CHECK (fare_ngn_minor > 0),
    capacity             INTEGER NOT NULL CHECK (capacity > 0),
    -- seats_reserved is only ever mutated through the serialized purchase
    -- path (UPDATE ... WHERE seats_reserved < capacity) so the CHECK makes
    -- overbooking impossible even under concurrent buyers.
    seats_reserved       INTEGER NOT NULL DEFAULT 0 CHECK (seats_reserved >= 0 AND seats_reserved <= capacity),
    status               TEXT NOT NULL DEFAULT 'SCHEDULED'
                         CHECK (status IN ('SCHEDULED', 'BOARDING_PAUSED', 'DEPARTED', 'CANCELLED')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS trips_operator_idx ON trips (operator_id);
CREATE INDEX IF NOT EXISTS trips_route_idx ON trips (route_reference);

CREATE TABLE IF NOT EXISTS tickets (
    ticket_id              TEXT PRIMARY KEY,
    trip_id                TEXT NOT NULL REFERENCES trips (trip_id),
    operator_id            TEXT NOT NULL REFERENCES operators (operator_id),
    -- Salted digest of the authoritative passenger record. Raw PII is never
    -- stored in the ticketing boundary export path.
    passenger_digest_sha256 TEXT NOT NULL,
    fare_ngn_minor         BIGINT NOT NULL CHECK (fare_ngn_minor > 0),
    currency               TEXT NOT NULL DEFAULT 'NGN' CHECK (currency = 'NGN'),
    channel                TEXT NOT NULL CHECK (channel IN ('DIRECT', 'AGENT_CASH_IN')),
    state                  TEXT NOT NULL CHECK (state IN ('RESERVED', 'PAID', 'ISSUED', 'REFUNDED', 'EXPIRED', 'VOID')),
    -- Optimistic-concurrency guard for state transitions.
    version                BIGINT NOT NULL DEFAULT 1,
    seat_number            INTEGER CHECK (seat_number IS NULL OR (seat_number > 0)),
    embarked               BOOLEAN NOT NULL DEFAULT FALSE,
    agent_id               TEXT,
    ledger_reserve_id      TEXT,
    ledger_post_id         TEXT,
    purchaser_principal    TEXT NOT NULL,
    correlation_id         TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tickets_trip_idx ON tickets (trip_id);
CREATE INDEX IF NOT EXISTS tickets_operator_idx ON tickets (operator_id);

-- Idempotent purchase: one row per idempotency key, scoped to the purchaser.
CREATE TABLE IF NOT EXISTS purchase_idempotency (
    idempotency_key  TEXT PRIMARY KEY,
    purchaser_principal TEXT NOT NULL,
    ticket_id        TEXT NOT NULL REFERENCES tickets (ticket_id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Agent cash-in is a ledger event: cash received by the agent against the
-- ticket reserve.
CREATE TABLE IF NOT EXISTS cash_in_events (
    cash_in_id       TEXT PRIMARY KEY,
    ticket_id        TEXT NOT NULL REFERENCES tickets (ticket_id),
    agent_id         TEXT NOT NULL,
    amount_ngn_minor BIGINT NOT NULL CHECK (amount_ngn_minor > 0),
    ledger_transfer_id TEXT NOT NULL,
    recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS manifests (
    manifest_id            TEXT PRIMARY KEY,
    trip_id                TEXT NOT NULL REFERENCES trips (trip_id),
    operator_id            TEXT NOT NULL REFERENCES operators (operator_id),
    vessel_reference       TEXT NOT NULL,
    terminal_reference     TEXT NOT NULL,
    scheduled_departure    TIMESTAMPTZ NOT NULL,
    passenger_count        INTEGER NOT NULL CHECK (passenger_count >= 0),
    expected_passengers    INTEGER NOT NULL CHECK (expected_passengers >= 0),
    manifest_digest_sha256 TEXT NOT NULL,
    exported_by_principal  TEXT NOT NULL,
    exported_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (trip_id, exported_at)
);
CREATE INDEX IF NOT EXISTS manifests_trip_idx ON manifests (trip_id);

-- Transactional outbox: written in the same transaction as the domain change,
-- drained at-least-once by the outbox-publisher with idempotent keys.
CREATE TABLE IF NOT EXISTS ferry_outbox (
    event_id     TEXT PRIMARY KEY,
    topic        TEXT NOT NULL CHECK (topic IN ('ferries.ticketing.v1', 'ferries.manifest.v1')),
    subject_id   TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    payload      JSONB NOT NULL,
    correlation_id TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ferry_outbox_unpublished_idx
    ON ferry_outbox (created_at) WHERE published_at IS NULL;
