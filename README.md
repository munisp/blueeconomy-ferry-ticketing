# Blue Economy Ferry Ticketing

Workstream B of the NewWave.io BlueEconomy platform: inland waterway
per-passenger e-ticketing, the NIMASA passenger manifest API and the safety
telematics workflow (`FerryTicketWorkflow`).

The service sells NGN-denominated per-passenger tickets with DB-enforced
capacity (no overbooking by construction), settles fares on TigerBeetle with
the two-phase reserve/post pattern, exports FHIR-aligned anonymized passenger
manifests for NIMASA/NIWA oversight, and publishes every state change through
a transactional outbox onto the `ferries.ticketing.v1` /
`ferries.manifest.v1` Kafka topics with the platform envelope.

Every boundary is fail-closed: the process refuses to start or serve without
PostgreSQL, TigerBeetle, the manifest salt, an explicit auth mode and the
completeness KPI. There are no mock endpoints, synthetic data or default
credentials.

## Commands

| Command | Purpose |
|---|---|
| `cmd/ferry-api` | Ticketing, NIMASA manifest and operator portal HTTP API (`/healthz`, `/readyz`). |
| `cmd/ferry-worker` | Temporal worker hosting `FerryTicketWorkflow` and its activities. |
| `cmd/outbox-publisher` | Drains the transactional outbox to Kafka, at-least-once with idempotent keys and `RequireAll` acks. |

## Ticket lifecycle

`RESERVED → PAID → ISSUED → (REFUNDED | EXPIRED | VOID)`

- Purchase (`POST /v1/tickets`) reserves a seat inside a serializable
  transaction (`SELECT … FOR UPDATE` on the trip row plus a
  `seats_reserved <= capacity` CHECK), creates the TigerBeetle pending
  transfer, posts it, and issues the ticket. The `Idempotency-Key` header
  binds the purchase; replays return the original ticket and never
  double-consume capacity or double-charge (the duplicate ledger reserve is
  voided as compensation).
- Agent cash-in (`channel: AGENT_CASH_IN`, `agentId` required) debits the
  agent float account and records a `cash_in_events` ledger event plus the
  `ferry.agent.cash_in_recorded` outbox event.
- Refund posts a compensating TigerBeetle transfer from operator revenue back
  to passenger clearing; void releases the pending reserve.
- Passengers are never stored as raw PII: tickets carry an HMAC-SHA256 salted
  digest (`FERRY_MANIFEST_SALT`) of the tokenized passenger reference.

## NIMASA manifest API

`GET /v1/nimasa/trips/{tripID}/manifest` returns a FHIR-aligned JSON Bundle
(`resourceType: Bundle`, `type: collection`): a `Composition` header for the
voyage plus one `AnonymizedPassengerEntry` per PAID/ISSUED ticket (salted
digest + embarked flag only), matching
`blueeconomy.contracts.v1.PassengerManifestSubmitted` semantics —
`passenger_count` always equals the entry count and any drift fails closed.

Access is enforced at the service layer:

- `niwa-officer`, `nimasa-observer`, `independent-auditor`, `auditor`,
  `state-officer`, `fmmbe-oversight`: any trip.
- `operator`: only trips owned by the principal's `operator_id` claim.

`POST /v1/operator/trips/{id}/manifest/export` persists the manifest record
and emits `ferry.manifest.exported` on `ferries.manifest.v1` in the same
transaction. Manifest completeness (manifested vs expected passengers) is
computed per manifest and aggregated on the operator dashboard; the KPI
threshold (`FERRY_MANIFEST_COMPLETENESS_KPI`, platform target ≥ 0.95) is
reported with every export.

## Operator portal API

All routes require the `operator` role and a non-empty `operator_id` claim;
every query filters by `operator_id` at the database (tenancy is enforced at
the service/DB layer, not only at the edge).

| Route | Purpose |
|---|---|
| `POST /v1/operator/vessels` | Register a vessel (operator-scoped). |
| `GET /v1/operator/vessels`, `GET/PATCH/DELETE /v1/operator/vessels/{id}` | Vessel registry CRUD. Delete fails closed when trips exist. |
| `POST /v1/operator/trips` | Schedule a departure; capacity is snapshotted from the vessel. |
| `GET /v1/operator/trips` | List trips. |
| `POST /v1/operator/tickets/{id}/embark` | Mark an ISSUED ticket boarded. |
| `GET /v1/operator/dashboard` | Tickets sold, revenue (NGN minor), per-corridor stats, manifest completeness vs KPI. |

Ticketing routes: `POST /v1/tickets` (`passenger`, `agent-cashier`),
`GET /v1/tickets/{id}` (owner, owning operator, oversight roles),
`POST /v1/tickets/{id}/refund` (owner or owning operator),
`POST /v1/tickets/{id}/void` (owning operator or `state-officer`).

## FerryTicketWorkflow (Temporal)

`FerryTicketWorkflow` (`internal/workflow`) tracks one issued ticket's trip
from issuance to departure:

- awaits `ferry.manifest-submitted` and `ferry.telemetry-updated` signals
  (malformed signals never mark readiness);
- an `ferry.adverse-weather` signal always emits an `AdverseWeatherAlert`
  event to the NIMASA topic; within 30 minutes of departure it additionally
  pauses boarding (`BOARDING_PAUSED`);
- departure without a manifest fails closed and is audited
  (`ferry.manifest.incomplete`);
- `ferry.status` query exposes phase, readiness flags, boarding state and
  recorded alerts.

The worker (`cmd/ferry-worker`) is environment-configured and fails closed
without Temporal and PostgreSQL. Workflow behaviour is covered by
`go.temporal.io/sdk/testsuite` tests.

## Events and the transactional outbox

Domain mutations write outbox rows in the same PostgreSQL transaction.
`cmd/outbox-publisher` drains unpublished rows, wraps each in the platform
FHIR-aligned envelope and publishes to the row's topic:

```json
{
  "envelopeVersion": "1.0",
  "eventId": "uuid",
  "eventType": "ferries.ticketing.ticket.v1",
  "occurredAt": "RFC3339",
  "producer": "ferry-ticketing",
  "correlationId": "...",
  "fhir": {"resourceType": "Bundle", "type": "message", "entry": [{"resource": {}}]},
  "provenance": {
    "principalId": "keycloak-sub",
    "principalRole": "...",
    "signature": "sha256-content-digest",
    "ledgerCommitHash": "tb-transfer-id"
  },
  "classification": "INTERNAL"
}
```

Delivery is at-least-once; the Kafka message key is the outbox event ID and
the writer requires all-broker acks. Unknown event types or topics fail
closed and halt the drain.

## Configuration (environment, all required — fail-closed)

### `ferry-api`

| Variable | Meaning |
|---|---|
| `FERRY_LISTEN_ADDRESS` | HTTP bind address, e.g. `:8080`. |
| `FERRY_DATABASE_URL` | PostgreSQL DSN. |
| `FERRY_MANIFEST_SALT` | HMAC salt for passenger digests (≥ 16 chars; secret, inject via secret manager). |
| `FERRY_MANIFEST_COMPLETENESS_KPI` | Completeness threshold in `(0, 1]`, e.g. `0.95`. |
| `FERRY_AUTH_MODE` | `jwt` or `trusted_proxy`. |
| `FERRY_OIDC_ISSUER` / `FERRY_OIDC_AUDIENCE` / `FERRY_OIDC_JWKS_URL` | Keycloak RS256 validation (jwt mode; JWKS URL must be HTTPS). |
| `FERRY_OIDC_CA_FILE` | Optional pinned CA for the JWKS endpoint. |
| `FERRY_TRUSTED_PROXY_IDENTITY` / `FERRY_TRUSTED_PROXY_CIDRS` | Edge identity header value and approved proxy networks (trusted_proxy mode). |
| `FERRY_TB_ADDRESS` / `FERRY_TB_CLUSTER_ID` | TigerBeetle replica address and cluster ID. |
| `FERRY_TB_LEDGER` / `FERRY_TB_CODE` | TigerBeetle ledger and transfer/account code (non-zero). |
| `FERRY_TB_PASSENGER_CLEARING_ACCOUNT` / `FERRY_TB_OPERATOR_REVENUE_ACCOUNT` / `FERRY_TB_AGENT_FLOAT_ACCOUNT` | Approved account IDs (hex uint128, distinct, non-zero). |
| `FERRY_TB_PENDING_TIMEOUT_SECONDS` | Pending reserve timeout (non-zero). |

### `ferry-worker`

`FERRY_DATABASE_URL`, `TEMPORAL_ADDRESS`, `TEMPORAL_NAMESPACE`,
`TEMPORAL_TASK_QUEUE` (all required).

### `outbox-publisher`

`FERRY_DATABASE_URL`, `KAFKA_BROKERS` (comma-separated),
`OUTBOX_POLL_INTERVAL_SECONDS`, `OUTBOX_BATCH_SIZE` (all required).

## Security model

- Keycloak RS256 JWT validation against the realm JWKS: only RSA `sig` keys
  ≥ 2048 bits are trusted, issuer and audience are pinned, expiry and
  not-before enforced, JWKS redirects rejected, 5-minute key cache TTL,
  optional pinned CA. Behind the platform edge, the trusted-proxy mode accepts
  identity headers only from approved CIDRs presenting the approved proxy
  identity header.
- Role middleware covers `passenger`, `operator`, `agent-cashier`,
  `niwa-officer`, `state-officer`, `nimasa-observer`, `independent-auditor`,
  `auditor`, `fmmbe-oversight`; operator tenancy is enforced with DB row
  filters.
- Structured JSON logging (`slog`), `/healthz` and `/readyz` (readiness pings
  PostgreSQL), request-size limits and server timeouts.
- OpenTelemetry instrumentation (`internal/telemetry`): a per-request server
  span renamed to the matched route pattern, request count/duration histograms
  served on `GET /metrics`, and span attributes for ticket state transitions
  and operator scope. Tracing is **disabled by default** with an explicit
  no-op tracer and a startup log line; setting `OTEL_EXPORTER_OTLP_ENDPOINT`
  (`host:port`) enables OTLP gRPC export. Telemetry configuration fails closed
  on malformed or contradictory values (`OTEL_SDK_DISABLED`,
  `OTEL_EXPORTER_OTLP_INSECURE`, `OTEL_SERVICE_NAME` are also honoured).
  Metrics are local-only and served from a private Prometheus registry.
- No secrets in code; all configuration is environment-injected and validated
  at startup.

## Data

`db/migrations/0001_ferry_ticketing.sql` creates operators, vessels, trips
(capacity CHECK + `seats_reserved` guard), tickets (state CHECK, optimistic
`version`), purchase idempotency keys, cash-in events, manifests and the
transactional outbox. All queries are parameterized.

## Runbook

1. Apply `db/migrations/0001_ferry_ticketing.sql` to the service database.
2. Provision the three TigerBeetle accounts and set the `FERRY_TB_*` env
   block; `ferry-api` creates them idempotently at startup
   (`EnsureAccounts`).
3. Start `ferry-api`, `ferry-worker`, `outbox-publisher` with their env
   blocks. All three exit non-zero when a dependency is missing.
4. Verify `/healthz` (liveness) and `/readyz` (PostgreSQL reachable).
5. Purchase flow: create operator vessel → schedule trip →
   `POST /v1/tickets` with `Idempotency-Key` → ticket ISSUED.
6. Manifest: `POST /v1/operator/trips/{id}/manifest/export`, then NIMASA/NIWA
   roles read `GET /v1/nimasa/trips/{id}/manifest`.
7. Start `FerryTicketWorkflow` per issued ticket (workflow ID: ticket ID);
   signal `ferry.manifest-submitted` after export and
   `ferry.telemetry-updated` on AIS/telemetry updates; query `ferry.status`.
8. The outbox publisher drains continuously; on Kafka outage it exits
   non-zero and replays safely on restart (idempotent keys).

## Development

```sh
go build ./...
go vet ./...
go test -race ./...
```

PostgreSQL, Kafka and TigerBeetle are behind interfaces; unit tests use
fakes and the Temporal testsuite, so the full suite runs without external
services. The Dockerfile builds per-command distroless non-root images
(`ferry-api`, `ferry-worker`, `outbox-publisher` targets).

### Integration tests

The `-tags integration` suite exercises the production PostgreSQL store
(capacity enforcement under row locks, idempotent purchase, transactional
outbox) and the outbox drain end to end against a real Kafka broker. All
images are digest-pinned. Locally:

```sh
docker compose -f integration/compose.yaml up -d --wait
FERRY_TEST_DATABASE_URL='postgres://blueeconomy:local-only-integration-password@127.0.0.1:55437/blueeconomy_ferries?sslmode=disable' \
FERRY_TEST_KAFKA_BROKERS='127.0.0.1:9092' \
  go test -tags integration -race -count=1 ./internal/...
docker compose -f integration/compose.yaml down -v
```

The suite fails closed when `FERRY_TEST_DATABASE_URL` or
`FERRY_TEST_KAFKA_BROKERS` is absent — it never silently skips. CI
(`.github/workflows/integration.yml`) runs it on every pull request with a
digest-pinned PostgreSQL `services:` container plus the pinned Kafka service
from `integration/compose.yaml`, and uploads service logs as artifacts on
failure.
