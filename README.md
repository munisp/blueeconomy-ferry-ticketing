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

Issued tickets are presented at the gate as **signed artifacts**:
Ed25519-signed, QR-encodable payloads with a TOTP-style rotating window code
(anti-screenshot), verified offline against the public key set and consumed
first-scan-wins in PostgreSQL (see *Signed ticket artifacts* below).

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
| `cmd/ticket-keygen` | One-shot provisioning: generates the Ed25519 ticket signing key file (mode 0600) and prints the public key + kid for verifier distribution. |

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
  to passenger clearing. A boarding-consumed ticket (`boarded_at` set or
  `embarked`) can never be refunded or voided — enforced in the service guard
  and by the `tickets_block_boarded_refund` database trigger, so no code path
  can refund a traveled passenger.
- Void money semantics by state: `RESERVED → VOID` releases the pending
  reserve (the passenger was never charged); `PAID/ISSUED → VOID` issues the
  refund transfer (revenue → clearing) in the same flow, so the fare never
  sits in revenue without a refund entry. Voiding a sold ticket at or above
  `FERRY_VOID_DUAL_CONTROL_THRESHOLD_NGN_MINOR` (kobo; unset = 0, i.e. dual
  control on every sold void) requires maker-checker: the first officer's
  void records a `void_approvals` row (409 `VOID_APPROVAL_REQUIRED`), and
  only a second, distinct officer's void confirms it — self-approval is
  rejected and the approval is consumed exactly once.
- Any terminal transition (`REFUNDED`/`EXPIRED`/`VOID`) releases the seat in
  the same transaction (`seats_reserved` decrement, exactly-once by the state
  graph + optimistic-concurrency guard), so refunded/voided/expired tickets
  never leave a trip reading full.
- The purchase saga cannot strand state: an idempotent replay resumes from
  the stored ticket state, and the `ferry-worker` reconciler sweeps aged
  `RESERVED`/`PAID` tickets against the TigerBeetle reserve state — a posted
  charge is driven to `PAID`/`ISSUED`, a reserve auto-voided by the pending
  timeout expires the ticket (`EXPIRED`) and frees the seat, and a
  paid-but-unissued ticket finishes issuance.
- Passengers are never stored as raw PII: tickets carry an HMAC-SHA256 salted
  digest (`FERRY_MANIFEST_SALT`) of the tokenized passenger reference.

## Signed ticket artifacts (anti-forgery / anti-counterfeit)

Threat model. A DB record alone does not stop (a) photocopied or screenshotted
tickets presented at multiple gangways, (b) forged ticket references, or
(c) double-presentation of one valid ticket. The artifact layer addresses all
three:

1. **Forgery** — the artifact is Ed25519-signed by the service signing key
   (env-injected file, `FERRY_TICKET_SIGNING_KEY_FILE`; the service fails
   closed without it). Authenticity verification is **offline**: a gate or the
   mobile app needs only the public key set — no network or DB call. The
   payload binds ticket id, trip id, seat, validity window, the salted holder
   digest and the signing `kid` + rotation epoch.
2. **Static screenshots** — the artifact trailer carries a TOTP-style
   rotating window code: `HMAC-SHA256(window_secret, floor(unix/30))[0:8]`
   where `window_secret = HMAC-SHA256(FERRY_TICKET_WINDOW_SECRET,
   "BET1-window" || ticket_id)`. The window secret is derived at verification
   time, so no per-ticket secret is stored. A 30-second step with ±1 window
   tolerance caps a screenshot's useful life at ~90 seconds.
3. **Double-presentation** — embark consumes the boarding atomically in
   PostgreSQL (`UPDATE tickets … SET boarded_at … WHERE boarded_at IS NULL`).
   First scan wins; a second presentation at any gangway fails with
   `409 BOARDING_ALREADY_CONSUMED` and emits a
   `ferry.ticket.duplicate_presentation` fraud event.

### Wire format v1 (`internal/ticketproof`, pure Go — embeddable offline)

```
payload (all integers big-endian):
  magic           4 bytes   "BET1"
  kid             8 bytes   SHA-256(ed25519 public key)[0:8]
  ticket_id       u8 length-prefixed UTF-8
  trip_id         u8 length-prefixed UTF-8
  seat            u16       (0 = unassigned)
  issued_at       i64       unix seconds (mint instant)
  expires_at      i64       unix seconds (trip scheduled departure)
  rotation_epoch  u32       signing-key epoch, monotonic per rotation
  holder_digest   32 bytes  raw HMAC-SHA256 salted passenger digest
artifact = payload || ed25519_signature(payload)[64] || window_code[8]
token    = base64url-no-pad(artifact)      -- QR alphabet safe
```

Artifacts are minted on demand by `GET /v1/tickets/{id}/artifact` (owner or
owning operator only — the artifact is a bearer capability); nothing
per-ticket is stored. `expires_at` is the trip's scheduled departure, so
artifacts die with the voyage.

**kid scheme and rotation.** `kid = SHA-256(publicKey)[0:8]`, rendered
base64url in JSON. Rotation mirrors the maritime-intelligence feed pattern:
the current key signs at `FERRY_TICKET_ROTATION_EPOCH`; the immediately
previous key (`FERRY_TICKET_PREVIOUS_SIGNING_KEY_FILE`) is accepted until
`FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL` (RFC3339, required when a previous
key is configured). Unknown kids, expired grace and epoch mismatches fail
closed.

**Key distribution to offline verifiers.** Verifiers (gate scanners, the
mobile inspector app) obtain the public key set from
`GET /v1/tickets/verification-keys` — no out-of-band operations channel is
involved. The route requires an authenticated verifier role (`operator` or
`gate`, the same roles as `POST /v1/tickets/verify`): the keys are public
material, but the platform exposes no unauthenticated surface beyond
health/readiness. The response serves **public keys only** — never private
key material or the HMAC window secret:

```json
{
  "current":  {"kid": "…", "algorithm": "Ed25519", "public_key_hex": "…", "epoch": 2, "grace_until_unix": null},
  "previous": {"kid": "…", "algorithm": "Ed25519", "public_key_hex": "…", "epoch": 1, "grace_until_unix": 1767225600}
}
```

`previous` is `null` when no rotation is configured or once the grace
deadline has passed — the endpoint always reflects exactly what the service
itself would accept, so a fresh fetch never caches a key the server would
reject. Offline verifiers cache the set locally (the mobile inspector caches
`current` + `previous` and refreshes when online); a failed or non-200
refresh keeps the previous cache, and a scan against a kid outside the
cached set fails closed as `unknown_kid`. Rotation runbook: deploy the new
key as `FERRY_TICKET_SIGNING_KEY_FILE` with a bumped
`FERRY_TICKET_ROTATION_EPOCH`, keep the retiring key in
`FERRY_TICKET_PREVIOUS_SIGNING_KEY_FILE` with
`FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL` covering the longest artifact
lifetime (trip departure), and verifiers pick the set up on their next
refresh.

**Fraud telemetry.** Invalid signatures, unknown kids, expired rotation
grace, stale window codes and duplicate presentations emit outbox events on
`ferries.ticketing.v1` (`ferry.ticket.verification_failed` /
`ferry.ticket.duplicate_presentation`) that the publisher wraps in the
platform envelope as `ferries.ticketing.ticket_verification_failed.v1` /
`ferries.ticketing.ticket_duplicate_presentation.v1` with classification
**CONFIDENTIAL** for the security-operations engine. Logs carry the failure
reason, kid and correlation id — never PII.

### Boarding API

| Route | Purpose |
|---|---|
| `GET /v1/tickets/{id}/artifact` | Mint the signed artifact (purchaser or owning operator; ISSUED tickets only). |
| `POST /v1/tickets/verify` | Stateless authenticity + window-code check (`operator`, `gate` roles). `200 {"valid": true, …}` or `401` + fraud event. |
| `GET /v1/tickets/verification-keys` | Public verification key set for offline verifiers (`operator`, `gate` roles): current key + previous key inside its rotation grace window. |
| `POST /v1/operator/tickets/{id}/embark` | Consume boarding with `{"artifact": "…"}`; first-scan-wins, `409 BOARDING_ALREADY_CONSUMED` on replay. |

The embark body is optional: an empty body is the **legacy** raw-ticket-id
path, **deprecated and disabled by default** (`403` —
`ErrLegacyEmbarkDisabled`). An operator deployment may explicitly opt in with
`FERRY_ALLOW_LEGACY_UNSIGNED_EMBARK=true`; even then the path goes through
the same atomic first-scan-wins guard and operator-scope check, every legacy
boarding emits a `ferry.boarding.legacy_unsigned` audit event marked
`boarding_mode: LEGACY_UNSIGNED`, and each use is logged with a deprecation
warning. Sunset: the legacy path is scheduled for removal once all gates
scan signed artifacts; the audit stream tracks the burn-down.


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
| `POST /v1/operator/trips/{id}/cancel` | Cancel an open trip (`SCHEDULED`/`BOARDING_PAUSED` → `CANCELLED`, operator-scoped, audited via `ferry.trip.cancelled`). Ticket refunds for a cancelled trip are a separate explicit flow. |
| `POST /v1/operator/tickets/{id}/embark` | Consume boarding first-scan-wins (signed artifact default; legacy raw-id path deprecated). |
| `GET /v1/operator/dashboard` | Tickets sold, revenue (NGN minor), per-corridor stats, manifest completeness vs KPI. |

Ticketing routes: `POST /v1/tickets` (`passenger`, `agent-cashier`),
`GET /v1/tickets/{id}` (owner, owning operator, oversight roles),
`GET /v1/tickets/{id}/artifact` (owner, owning operator),
`POST /v1/tickets/verify` (`operator`, `gate`),
`GET /v1/tickets/verification-keys` (`operator`, `gate`),
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
- at the departure instant an idempotent activity persists the `DEPARTED`
  trip status, so historical trips never claim `SCHEDULED` forever (operator
  cancellation persists `CANCELLED` via
  `POST /v1/operator/trips/{id}/cancel`);
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
closed and halt the drain. Fraud telemetry (`ferry.ticket.verification_failed`,
`ferry.ticket.duplicate_presentation`) is classified `CONFIDENTIAL`; all other
events are `INTERNAL`.

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
| `FERRY_TICKET_SIGNING_KEY_FILE` | Ed25519 private key file (hex or base64 of the 64-byte key or 32-byte seed; inject via secret manager). |
| `FERRY_TICKET_WINDOW_SECRET` | Server secret for rotating window codes (≥ 16 chars; secret). |
| `FERRY_TICKET_PREVIOUS_SIGNING_KEY_FILE` | Optional previous key, accepted during the rotation grace window. |
| `FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL` | RFC3339 grace deadline; required when a previous key is configured. |
| `FERRY_TICKET_ROTATION_EPOCH` | Signing-key epoch (uint32 ≥ 1; default 1, increment per rotation). |
| `FERRY_VOID_DUAL_CONTROL_THRESHOLD_NGN_MINOR` | Optional. Fare (kobo) at or above which voiding a sold ticket requires a second officer (maker-checker). Unset = 0: dual control on every `PAID`/`ISSUED` void (fail closed). |
| `FERRY_ALLOW_LEGACY_UNSIGNED_EMBARK` | Optional, default `false`. Only an explicit `true` enables the deprecated legacy raw-ticket-id embark path (audited as `LEGACY_UNSIGNED`; scheduled for removal). |

### `ferry-worker`

`FERRY_DATABASE_URL`, `TEMPORAL_ADDRESS`, `TEMPORAL_NAMESPACE`,
`TEMPORAL_TASK_QUEUE` (all required). The worker also hosts the
purchase-saga reconciler, which needs the TigerBeetle topology
(`FERRY_TB_ADDRESS`, `FERRY_TB_CLUSTER_ID`, `FERRY_TB_LEDGER`,
`FERRY_TB_CODE`, `FERRY_TB_PASSENGER_CLEARING_ACCOUNT`,
`FERRY_TB_OPERATOR_REVENUE_ACCOUNT`, `FERRY_TB_AGENT_FLOAT_ACCOUNT`,
`FERRY_TB_PENDING_TIMEOUT_SECONDS` — all required, fail-closed) and
`FERRY_MANIFEST_SALT`. Sweep cadence: `FERRY_SWEEP_INTERVAL_SECONDS`
(default 60) and `FERRY_SWEEP_COMPLETION_AGE_SECONDS` (default 60); the
expiry age is the pending-transfer timeout plus a fixed 30-second grace.

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
- Role middleware covers `passenger`, `operator`, `agent-cashier`, `gate`,
  `niwa-officer`, `state-officer`, `nimasa-observer`, `independent-auditor`,
  `auditor`, `fmmbe-oversight`; operator tenancy is enforced with DB row
  filters.
- Ticket boarding artifacts are Ed25519-signed (`internal/ticketproof`) with
  offline verification, key-rotation grace and rotating window codes; boarding
  consumption is atomic in PostgreSQL and fraud signals are CONFIDENTIAL
  outbox events (see *Signed ticket artifacts*).
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
transactional outbox. `db/migrations/0002_signed_tickets.sql` adds the
first-scan-wins boarding columns (`boarded_at`, `boarded_by`, `artifact_kid`)
and backfills pre-existing embarked tickets so the guard covers them.
`db/migrations/0003_boarded_refund_guard.sql` adds the
`tickets_block_boarded_refund` trigger (a boarding-consumed ticket can never
reach `REFUNDED`/`VOID`, from any code path).
`db/migrations/0004_void_approvals.sql` adds the `void_approvals`
maker-checker table for dual-control voids of sold tickets. All
queries are parameterized.

## Runbook

1. Apply `db/migrations/0001_ferry_ticketing.sql`,
   `db/migrations/0002_signed_tickets.sql`,
   `db/migrations/0003_boarded_refund_guard.sql` and
   `db/migrations/0004_void_approvals.sql` to the service database.
2. Provision the ticket signing key: `ticket-keygen /run/secrets/ticket-signing-key`
   (or generate externally) and set `FERRY_TICKET_SIGNING_KEY_FILE` +
   `FERRY_TICKET_WINDOW_SECRET`. Distribute the printed public key/kid to
   offline verifiers.
3. Provision the three TigerBeetle accounts and set the `FERRY_TB_*` env
   block; `ferry-api` creates them idempotently at startup
   (`EnsureAccounts`).
4. Start `ferry-api`, `ferry-worker`, `outbox-publisher` with their env
   blocks. All three exit non-zero when a dependency is missing.
5. Verify `/healthz` (liveness) and `/readyz` (PostgreSQL reachable).
6. Purchase flow: create operator vessel → schedule trip →
   `POST /v1/tickets` with `Idempotency-Key` → ticket ISSUED.
7. Boarding: passenger (or operator) fetches `GET /v1/tickets/{id}/artifact`;
   the gate optionally checks `POST /v1/tickets/verify`, then
   `POST /v1/operator/tickets/{id}/embark` with `{"artifact": "…"}`.
8. Manifest: `POST /v1/operator/trips/{id}/manifest/export`, then NIMASA/NIWA
   roles read `GET /v1/nimasa/trips/{id}/manifest`.
9. Start `FerryTicketWorkflow` per issued ticket (workflow ID: ticket ID);
   signal `ferry.manifest-submitted` after export and
   `ferry.telemetry-updated` on AIS/telemetry updates; query `ferry.status`.
10. The outbox publisher drains continuously; on Kafka outage it exits
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
