-- BlueFare: account-based fare system (pass products, fare capping, offline
-- validation, conductor store-and-forward, BlueFare accounts, settlement).
-- Idempotent-safe via IF NOT EXISTS / DROP CONSTRAINT IF EXISTS, mirroring
-- 0001-0004. All money is integer NGN minor units (kobo).

-- Zero-fare cap tickets: a fully capped journey is priced 0 and still issues
-- a valid ticket (seat consumed, first-scan-wins preserved), so the fare
-- floor relaxes from > 0 to >= 0. Positive fares are unchanged.
ALTER TABLE tickets DROP CONSTRAINT IF EXISTS tickets_fare_ngn_minor_check;
ALTER TABLE tickets ADD CONSTRAINT tickets_fare_ngn_minor_check CHECK (fare_ngn_minor >= 0);

-- ACCOUNT channel: the fare was collected from a prepaid BlueFare account
-- (funds entered the ledger at top-up; the journey debits the account).
ALTER TABLE tickets DROP CONSTRAINT IF EXISTS tickets_channel_check;
ALTER TABLE tickets ADD CONSTRAINT tickets_channel_check CHECK (channel IN ('DIRECT', 'AGENT_CASH_IN', 'ACCOUNT'));
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS account_id TEXT;

-- Fare events ride their own topic; the outbox publisher allowlist mirrors
-- this set and fails closed on anything else.
ALTER TABLE ferry_outbox DROP CONSTRAINT IF EXISTS ferry_outbox_topic_check;
ALTER TABLE ferry_outbox ADD CONSTRAINT ferry_outbox_topic_check
    CHECK (topic IN ('ferries.ticketing.v1', 'ferries.manifest.v1', 'ferries.fare.v1'));

-- ---------------------------------------------------------------------------
-- Pass products and passes (Citizen Services Advisory §4.1).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pass_products (
    product_id       TEXT PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('DAY', 'WEEK', 'MONTH')),
    scope_type       TEXT NOT NULL CHECK (scope_type IN ('ROUTE', 'ZONE', 'NETWORK')),
    -- scope_ref is the route_reference or zone name; '' for NETWORK.
    scope_ref        TEXT NOT NULL DEFAULT '',
    price_ngn_minor  BIGINT NOT NULL CHECK (price_ngn_minor > 0),
    -- NULL operator_id = ministry/platform product valid across operators.
    operator_id      TEXT REFERENCES operators (operator_id),
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Pass purchases mirror the ticket saga (RESERVED -> PAID -> ISSUED) with the
-- same two-phase ledger reserve/post and durable idempotency keys.
CREATE TABLE IF NOT EXISTS pass_purchases (
    purchase_id          TEXT PRIMARY KEY,
    product_id           TEXT NOT NULL REFERENCES pass_products (product_id),
    pass_id              TEXT,
    owner_digest         TEXT NOT NULL,
    price_ngn_minor      BIGINT NOT NULL CHECK (price_ngn_minor > 0),
    channel              TEXT NOT NULL CHECK (channel IN ('DIRECT', 'AGENT_CASH_IN', 'ACCOUNT')),
    agent_id             TEXT,
    account_id           TEXT,
    state                TEXT NOT NULL CHECK (state IN ('RESERVED', 'PAID', 'ISSUED', 'EXPIRED', 'VOID')),
    version              BIGINT NOT NULL DEFAULT 1,
    ledger_reserve_id    TEXT,
    ledger_post_id       TEXT,
    purchaser_principal  TEXT NOT NULL,
    correlation_id       TEXT NOT NULL,
    idempotency_key      TEXT NOT NULL UNIQUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS passes (
    pass_id      TEXT PRIMARY KEY,
    product_id   TEXT NOT NULL REFERENCES pass_products (product_id),
    owner_digest TEXT NOT NULL,
    valid_from   TIMESTAMPTZ NOT NULL,
    valid_to     TIMESTAMPTZ NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    purchase_id  TEXT NOT NULL REFERENCES pass_purchases (purchase_id),
    version      BIGINT NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS passes_owner_idx ON passes (owner_digest);

-- Blocklist source for offline validators (delta endpoint pagination).
CREATE TABLE IF NOT EXISTS pass_revocations (
    pass_id    TEXT PRIMARY KEY REFERENCES passes (pass_id),
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason     TEXT NOT NULL DEFAULT ''
);

-- Conductor-admitted pass rides (settlement + subsidy reporting input).
CREATE TABLE IF NOT EXISTS pass_rides (
    ride_id          TEXT PRIMARY KEY,  -- conductor scan id (dedupe by construction)
    pass_id          TEXT NOT NULL REFERENCES passes (pass_id),
    operator_id      TEXT NOT NULL,
    route_reference  TEXT NOT NULL DEFAULT '',
    device_id        TEXT NOT NULL DEFAULT '',
    admitted_at      TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Rotating offline-validation keys distributed to conductor devices. The
-- private half is env-injected at the API; this table is the public,
-- distributable directory (epoch -> public key + status).
CREATE TABLE IF NOT EXISTS pass_validation_keys (
    epoch          INTEGER PRIMARY KEY CHECK (epoch > 0),
    kid            TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('CURRENT', 'PREVIOUS', 'RETIRED')),
    rotated_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Fare capping (Advisory §4.1/§4.2). Accumulators are the OLGP record; money
-- movements stay in TigerBeetle through the same saga step + outbox.
-- Period rollover is lazy: period_start is derived on read/write, no cron.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cap_rules (
    rule_id        TEXT PRIMARY KEY,
    operator_id    TEXT REFERENCES operators (operator_id),  -- NULL = platform default
    period_kind    TEXT NOT NULL CHECK (period_kind IN ('DAY', 'WEEK')),
    cap_ngn_minor  BIGINT NOT NULL CHECK (cap_ngn_minor > 0),
    scope_type     TEXT NOT NULL DEFAULT 'NETWORK' CHECK (scope_type IN ('NETWORK', 'ZONE', 'ROUTE')),
    scope_ref      TEXT NOT NULL DEFAULT '',
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS route_zones (
    route_reference TEXT PRIMARY KEY,
    zone            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS route_groups (
    route_reference TEXT NOT NULL,
    group_name      TEXT NOT NULL,
    PRIMARY KEY (route_reference, group_name)
);

CREATE TABLE IF NOT EXISTS fare_cap_accumulators (
    subject_ref      TEXT NOT NULL,  -- BlueFare account id or salted passenger digest
    period_kind      TEXT NOT NULL CHECK (period_kind IN ('DAY', 'WEEK')),
    period_start     DATE NOT NULL,
    scope_type       TEXT NOT NULL DEFAULT 'NETWORK',
    scope_ref        TEXT NOT NULL DEFAULT '',
    spent_ngn_minor  BIGINT NOT NULL DEFAULT 0 CHECK (spent_ngn_minor >= 0),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_ref, period_kind, period_start, scope_type, scope_ref)
);

-- One row per priced journey (cap engine decision record + compensation
-- input). charged_minor = min(fare, cap remaining) computed under the row
-- lock so concurrent journeys can never overspend a cap.
CREATE TABLE IF NOT EXISTS cap_journeys (
    journey_id          TEXT PRIMARY KEY,
    subject_ref         TEXT NOT NULL,
    account_id          TEXT,
    trip_id             TEXT NOT NULL,
    route_reference     TEXT NOT NULL,
    operator_id         TEXT NOT NULL,
    standard_fare_minor BIGINT NOT NULL CHECK (standard_fare_minor >= 0),
    charged_minor       BIGINT NOT NULL CHECK (charged_minor >= 0),
    pricing_class       TEXT NOT NULL CHECK (pricing_class IN ('STANDARD', 'CONCESSION', 'TRANSFER', 'CAPPED', 'ZERO_CAP')),
    concession_class    TEXT NOT NULL DEFAULT 'STANDARD',
    ticket_id           TEXT,
    reversed            BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cap_journeys_subject_idx ON cap_journeys (subject_ref, created_at);
CREATE INDEX IF NOT EXISTS cap_journeys_operator_idx ON cap_journeys (operator_id, created_at);

-- Encoded concession rules (student/elderly/PWD): eligibility is a referenced
-- policy instrument, never discretion.
CREATE TABLE IF NOT EXISTS fare_rules (
    rule_id               TEXT PRIMARY KEY,
    kind                  TEXT NOT NULL CHECK (kind IN ('CONCESSION', 'TRANSFER_WINDOW')),
    operator_id           TEXT REFERENCES operators (operator_id),
    concession_class      TEXT CHECK (concession_class IS NULL OR concession_class IN ('STUDENT', 'ELDERLY', 'PWD')),
    route_group           TEXT,
    window_minutes        INTEGER CHECK (window_minutes IS NULL OR window_minutes > 0),
    discount_percent      INTEGER NOT NULL CHECK (discount_percent >= 0 AND discount_percent <= 100),
    eligibility_reference TEXT,
    active                BOOLEAN NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Best-fare guarantee: weekly period settlement crediting the difference when
-- a WEEK pass would have been cheaper than accumulated capped spend.
CREATE TABLE IF NOT EXISTS best_fare_adjustments (
    subject_ref         TEXT NOT NULL,
    period_start        DATE NOT NULL,
    product_id          TEXT NOT NULL REFERENCES pass_products (product_id),
    spent_minor         BIGINT NOT NULL CHECK (spent_minor >= 0),
    pass_price_minor    BIGINT NOT NULL CHECK (pass_price_minor > 0),
    adjustment_minor    BIGINT NOT NULL CHECK (adjustment_minor > 0),
    ledger_transfer_id  TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_ref, period_start)
);

-- ---------------------------------------------------------------------------
-- BlueFare accounts (account-based: value lives in the ledger, instruments
-- are mere pointers; losing a card != losing money).
-- cached_balance_minor is a READ-MODEL cache for offline floor distribution
-- and fast UI; TigerBeetle is authoritative (DEBITS_MUST_NOT_EXCEED_CREDITS).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fare_accounts (
    account_id              TEXT PRIMARY KEY,
    owner_ref               TEXT NOT NULL,   -- identity-boundary subject
    owner_digest            TEXT NOT NULL,   -- salted HMAC digest (PII-free)
    status                  TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
    concession_class        TEXT NOT NULL DEFAULT 'STANDARD' CHECK (concession_class IN ('STANDARD', 'STUDENT', 'ELDERLY', 'PWD')),
    concession_reference    TEXT,            -- eligibility evidence reference
    autoload_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    autoload_threshold_minor BIGINT CHECK (autoload_threshold_minor IS NULL OR autoload_threshold_minor >= 0),
    autoload_amount_minor   BIGINT CHECK (autoload_amount_minor IS NULL OR autoload_amount_minor > 0),
    ledger_account_id       TEXT NOT NULL,   -- deterministic TigerBeetle account (hex uint128)
    cached_balance_minor    BIGINT NOT NULL DEFAULT 0 CHECK (cached_balance_minor >= 0),
    balance_as_of           TIMESTAMPTZ,
    version                 BIGINT NOT NULL DEFAULT 1,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS fare_accounts_owner_idx ON fare_accounts (owner_ref);

CREATE TABLE IF NOT EXISTS instruments (
    instrument_id TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES fare_accounts (account_id),
    kind          TEXT NOT NULL CHECK (kind IN ('PHONE_QR', 'NFC_CARD', 'USSD_ALIAS')),
    token_ref     TEXT NOT NULL UNIQUE,  -- opaque instrument token presented at scan time
    status        TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Top-ups: one pending-credit state machine for every rail. Money is credited
-- ONLY on a verified rail webhook (HMAC) or — for AGENT_CASH — through the
-- agent float ledger event. Nothing self-reports success.
CREATE TABLE IF NOT EXISTS topups (
    topup_id          TEXT PRIMARY KEY,
    account_id        TEXT NOT NULL REFERENCES fare_accounts (account_id),
    channel           TEXT NOT NULL CHECK (channel IN ('MOJALOOP', 'NIP_TRANSFER', 'NQR', 'AGENT_CASH', 'USSD')),
    amount_ngn_minor  BIGINT NOT NULL CHECK (amount_ngn_minor > 0),
    state             TEXT NOT NULL CHECK (state IN ('PENDING', 'CREDITED', 'FAILED', 'EXPIRED')),
    -- reference is the unique payer-facing transfer reference (NIP-style
    -- narration / Mojaloop quote ref / NQR bill reference).
    reference         TEXT NOT NULL UNIQUE,
    external_ref      TEXT,            -- rail-side transaction id (webhook dedupe)
    agent_id          TEXT,
    idempotency_key   TEXT NOT NULL UNIQUE,
    ledger_transfer_id TEXT,
    failure_reason    TEXT,
    version           BIGINT NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    credited_at       TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS topups_external_ref_idx ON topups (external_ref) WHERE external_ref IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Conductor store-and-forward (Advisory §4.3/§9.5). Durable per-scan dedupe,
-- first-scan-wins preserved server-side, conflicts -> REVIEW_REQUIRED.
-- device_id is recorded per batch/scan; device identity verification is
-- deferred to the device-management plane (TODO W-FEAT-3) — service-level
-- JWT only for now, no fabricated device auth.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS conductor_batches (
    device_id        TEXT NOT NULL,
    batch_id         TEXT NOT NULL,
    operator_id      TEXT NOT NULL,
    scan_count       INTEGER NOT NULL CHECK (scan_count >= 0),
    admitted         INTEGER NOT NULL DEFAULT 0,
    denied           INTEGER NOT NULL DEFAULT 0,
    review_required  INTEGER NOT NULL DEFAULT 0,
    -- Device-signed batch signature, stored for audit. Verification against a
    -- device key registry is TODO W-FEAT-3 (device-management plane).
    batch_signature  TEXT NOT NULL,
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at     TIMESTAMPTZ,
    PRIMARY KEY (device_id, batch_id)
);

CREATE TABLE IF NOT EXISTS conductor_scans (
    device_id     TEXT NOT NULL,
    scan_id       TEXT NOT NULL,
    batch_id      TEXT NOT NULL,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('TICKET', 'PASS', 'ACCOUNT_DEBIT')),
    subject_id    TEXT NOT NULL DEFAULT '',  -- ticket_id / pass_id / account_id
    operator_id   TEXT NOT NULL,
    result        TEXT NOT NULL CHECK (result IN ('ADMITTED', 'DENIED', 'DUPLICATE', 'REVIEW_REQUIRED')),
    deny_reason   TEXT NOT NULL DEFAULT '',
    scanned_at    TIMESTAMPTZ NOT NULL,
    processed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, scan_id)
);

-- Per-device offline debit caps (Advisory §9.5: caps are revenue-leakage
-- controls; declines-after-sync become the government's loss, never
-- unbounded offline credit).
CREATE TABLE IF NOT EXISTS device_offline_caps (
    device_id         TEXT PRIMARY KEY,
    operator_id       TEXT NOT NULL,
    per_tx_cap_minor  BIGINT NOT NULL CHECK (per_tx_cap_minor > 0),
    daily_cap_minor   BIGINT NOT NULL CHECK (daily_cap_minor > 0),
    active            BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS offline_debits (
    debit_id          TEXT PRIMARY KEY,  -- conductor scan id
    account_id        TEXT NOT NULL REFERENCES fare_accounts (account_id),
    device_id         TEXT NOT NULL,
    operator_id       TEXT NOT NULL,
    amount_ngn_minor  BIGINT NOT NULL CHECK (amount_ngn_minor > 0),
    state             TEXT NOT NULL CHECK (state IN ('SETTLED', 'DECLINED', 'REVIEW')),
    ledger_transfer_id TEXT,
    decline_reason    TEXT NOT NULL DEFAULT '',
    scanned_at        TIMESTAMPTZ NOT NULL,
    settled_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS offline_debits_device_idx ON offline_debits (device_id, created_at);
CREATE INDEX IF NOT EXISTS offline_debits_account_idx ON offline_debits (account_id, created_at);

-- ---------------------------------------------------------------------------
-- Settlement (Leicester-model usage attribution; operator split via ledger
-- linked transfers; platform fee + subsidy transparency).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS operator_settlement_rules (
    operator_id        TEXT PRIMARY KEY REFERENCES operators (operator_id),
    operator_share_bps INTEGER NOT NULL CHECK (operator_share_bps >= 0 AND operator_share_bps <= 10000),
    active             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS settlement_runs (
    run_id               TEXT PRIMARY KEY,
    operator_id          TEXT NOT NULL REFERENCES operators (operator_id),
    period_start         DATE NOT NULL,
    period_end           DATE NOT NULL,
    rides                INTEGER NOT NULL DEFAULT 0,
    gross_ngn_minor      BIGINT NOT NULL DEFAULT 0,
    operator_share_minor BIGINT NOT NULL DEFAULT 0,
    platform_share_minor BIGINT NOT NULL DEFAULT 0,
    subsidy_minor        BIGINT NOT NULL DEFAULT 0,
    ledger_transfer_ids  JSONB NOT NULL DEFAULT '[]',
    created_by           TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (operator_id, period_start, period_end)
);
