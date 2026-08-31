-- Phase-8 met-ocean bridge: advisory-driven departure suspensions.
--
-- A met-ocean advisory (waterways.met_ocean.advisories.v1, consumed by the
-- metocean-bridge) suspends open departures overlapping the advisory window;
-- a CAP Cancel advisory or the window expiry resumes them. SUSPENDED is a
-- distinct, reversible lifecycle state: a suspended trip never departs and
-- never boards until it returns to SCHEDULED.

ALTER TABLE trips DROP CONSTRAINT IF EXISTS trips_status_check;
ALTER TABLE trips ADD CONSTRAINT trips_status_check
    CHECK (status IN ('SCHEDULED', 'BOARDING_PAUSED', 'SUSPENDED', 'DEPARTED', 'CANCELLED'));

-- Passenger-notification events ride the same transactional outbox on their
-- own topic; the publisher allowlist and this CHECK fail closed together.
ALTER TABLE ferry_outbox DROP CONSTRAINT IF EXISTS ferry_outbox_topic_check;
ALTER TABLE ferry_outbox ADD CONSTRAINT ferry_outbox_topic_check
    CHECK (topic IN ('ferries.ticketing.v1', 'ferries.manifest.v1', 'ferries.notifications.v1'));

-- Audit record: which advisory suspended which departure, when, and when it
-- resumed. One row per (trip, advisory); idempotent suspend relies on the
-- primary key, idempotent resume on resumed_at IS NULL.
CREATE TABLE IF NOT EXISTS trip_suspensions (
    trip_id              TEXT NOT NULL REFERENCES trips (trip_id),
    advisory_id          TEXT NOT NULL,
    severity             TEXT NOT NULL,
    phenomenon_code      TEXT NOT NULL,
    zone_id              TEXT NOT NULL,
    effective_from       TIMESTAMPTZ NOT NULL,
    effective_until      TIMESTAMPTZ NOT NULL,
    bulletin_reference   TEXT NOT NULL,
    correlation_id       TEXT NOT NULL,
    suspended_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    resumed_at           TIMESTAMPTZ,
    resume_correlation_id TEXT,
    PRIMARY KEY (trip_id, advisory_id)
);
-- Resume path: every departure still suspended by one advisory.
CREATE INDEX IF NOT EXISTS trip_suspensions_advisory_active_idx
    ON trip_suspensions (advisory_id) WHERE resumed_at IS NULL;
-- Multi-advisory guard: a trip resumes only when no active suspension remains.
CREATE INDEX IF NOT EXISTS trip_suspensions_trip_active_idx
    ON trip_suspensions (trip_id) WHERE resumed_at IS NULL;
