# Met-Ocean Bridge

The met-ocean bridge (`cmd/metocean-bridge`) consumes signed maritime
met-ocean advisories from Kafka and drives ferry operational responses
through per-route Temporal workflows: suspending affected scheduled
departures, notifying passengers through the transactional outbox, and
auto-resuming when an advisory is cancelled or its window expires.

```
waterways.met_ocean.advisories.v1  (Kafka, SASL/TLS)
        |
        v
  metocean-bridge                    -- verify envelope (fail closed)
        |                            -- invalid -> DLQ + metric, never processed
        v
  RouteAdvisoryWorkflow (Temporal, one per route, on ferry-worker)
        |
        v
  trips SUSPENDED <-> SCHEDULED  +  trip_suspensions audit
        +  ferry_outbox notifications (ferries.notifications.v1)
```

## Event contract

- Topic: `waterways.met_ocean.advisories.v1` (the only accepted value of
  `MET_OCEAN_KAFKA_TOPIC`).
- Envelope: `blueeconomy.contracts.v1.EventEnvelope`, `envelopeVersion`
  `1.0`, event type `waterways.met_ocean.advisory.v1`, FHIR message Bundle
  with one `MetoceanAdvisoryIssued` entry (CAP 1.2 profile; `category` is
  fixed to `"Met"`).
- Signature: verified per `blueeconomy-contracts/docs/envelope-signature.md`
  — JWS compact EdDSA (Ed25519) over the RFC 8785 JCS of the envelope minus
  `provenance.signature`. The bridge re-canonicalizes and requires a
  byte-exact payload match before verifying the signature. Rejection is
  terminal: no retry, no unsigned admission path.
- `Cancel` advisories are explicit and must carry
  `referencesAdvisoryId`; there is no silent-absence resumption.

## Configuration (env-only, fail closed)

The bridge refuses to start on any missing or malformed value. There are no
defaults for security paths and no placeholder credentials.

| Variable | Purpose |
| --- | --- |
| `MET_OCEAN_KAFKA_BROKERS` | Comma-separated broker list. |
| `MET_OCEAN_KAFKA_TOPIC` | Advisory topic; must equal `waterways.met_ocean.advisories.v1`. |
| `MET_OCEAN_KAFKA_GROUP_ID` | Consumer group. Offsets commit only after terminal handling. |
| `MET_OCEAN_KAFKA_DLQ_TOPIC` | Dead-letter topic for rejected records; must differ from the advisory topic. |
| `MET_OCEAN_KAFKA_SASL_MECHANISM` | `plain`, `scram-sha-256` or `scram-sha-512`. |
| `MET_OCEAN_KAFKA_SASL_USERNAME` / `MET_OCEAN_KAFKA_SASL_PASSWORD` | SASL credentials (required when a mechanism is set). |
| `MET_OCEAN_KAFKA_TLS_CA_FILE` | PEM CA bundle (appended to system roots). |
| `MET_OCEAN_KAFKA_TLS_CERT_FILE` / `MET_OCEAN_KAFKA_TLS_KEY_FILE` | Mutual-TLS client certificate (must be set together). |
| `KEY_DIRECTORY_PATH` | Fleet public-key directory JSON (`{kid: base64url-ed25519-pubkey}`), mounted as a regular non-symlink file. Loaded once at startup; absent/malformed/empty is a startup error. |
| `TEMPORAL_ADDRESS` / `TEMPORAL_NAMESPACE` | Temporal frontend and namespace. |
| `MET_OCEAN_TEMPORAL_TASK_QUEUE` | Task queue hosting `RouteAdvisoryWorkflow` (the ferry-worker queue). |
| `MET_OCEAN_ZONE_ROUTE_MAP` | JSON map of hazard zone id to ferry route references, e.g. `{"hz-lagos-approach":["lagos-apapa","lagos-ikoyi"]}`. This is the sole source of truth for zone coverage. |
| `MET_OCEAN_SUSPEND_SEVERITIES` | Comma-separated CAP severities that suspend departures. Default `Severe,Extreme`. |
| `MET_OCEAN_METRICS_ADDRESS` | Optional `host:port` for the local Prometheus `/metrics` endpoint. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Optional `host:port` OTLP gRPC endpoint; tracing is disabled (explicit no-op) when unset. `OTEL_SDK_DISABLED`, `OTEL_EXPORTER_OTLP_INSECURE`, `OTEL_SERVICE_NAME` follow the service-wide telemetry rules. |

Transport security is mandatory: a deployment with neither SASL nor TLS is a
startup error (no plaintext admission). There is no
insecure-skip-verify escape hatch.

## Processing semantics

1. **Fetch** one record inside the consumer group; start a consumer span
   (`metocean.consume`) parented to the record's W3C `traceparent` header
   when present.
2. **Verify** the envelope signature. Any rejection carries the normative
   reason code (`malformed-jws`, `unsupported-alg`, `unknown-kid`,
   `payload-mismatch`, `invalid-signature`), is logged and metered
   (`metocean.envelope.rejected{reason}`), and the raw record is published to
   the DLQ with `x-dlq-*` headers before the offset commits. Rejected
   envelopes are never parsed into the domain and never reach Temporal.
3. **Parse** the verified advisory (CAP profile, fail closed). A
   verified-but-malformed advisory is a contract breach: DLQ with reason
   `malformed-advisory`.
4. **Dispatch**: the advisory's `zoneId` resolves to ferry routes via
   `MET_OCEAN_ZONE_ROUTE_MAP`. An unmapped zone is dead-lettered explicitly
   (reason `unmapped-zone`) — never silently dropped, never guessed. Below
   the configured suspend severities, `Alert`/`Update` advisories are
   metered and skipped; `Cancel` advisories always pass (resumption is never
   gated). Each mapped route receives a signal-with-start on workflow id
   `metocean-route-<routeReference>`.
5. **Commit** only after terminal handling. A transient dispatch or DLQ
   failure leaves the offset uncommitted (at-least-once redelivery on
   rebalance/restart); the failure is logged and metered, never dropped.

A `producer` field that differs from `blueeconomy-waterway-safety` is
metered as suspicious (`producer-mismatch-observed`) but is not fatal: the
key directory is the sole source of truth for key resolution.

## RouteAdvisoryWorkflow (on ferry-worker)

One long-lived workflow per route (`RouteAdvisoryWorkflow`, signal
`metocean.advisory`, query `metocean.status`):

- **Alert/Update**: lists the route's open (`SCHEDULED`/`BOARDING_PAUSED`)
  departures whose scheduled departure falls inside
  `[effectiveFrom, effectiveUntil]` and suspends each in one transaction:
  trip -> `SUSPENDED`, `trip_suspensions` audit row, and a
  `ferry.trip.departure_suspended` outbox entry on
  `ferries.notifications.v1`. An `Update` for a tracked advisory first
  releases the previous suspension set, then re-evaluates.
- **Cancel**: resumes every departure still suspended by the referenced
  advisory. A departure suspended by several advisories reopens only when
  the last active advisory ends.
- **Window expiry**: a workflow timer fires at `effectiveUntil` and resumes
  the same way (auto-resume; correlation id `metocean-expiry-<advisoryId>`).
- Resumptions transition trips back to `SCHEDULED`, mark the audit rows
  `resumed_at`, and write `ferry.trip.departure_resumed` outbox entries.
- Suspend and resume activities are idempotent per (trip, advisory): replays
  from at-least-once delivery never double-notify or corrupt state.
- The workflow exits after 24 h without signals and without active
  advisories; the next advisory signal-with-starts a fresh run.
- A `SUSPENDED` trip never departs and never boards: `MarkTripDeparted`
  fails closed on it until the trip resumes.

All workflow/activity spans flow through the Temporal OTel tracing
interceptor (trace context propagates from the Kafka record into the
workflow), active when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.

## Metrics

| Metric | Labels | Meaning |
| --- | --- | --- |
| `metocean.messages.consumed` | `outcome` | Records consumed (`processed`/`rejected`). |
| `metocean.envelope.rejected` | `reason` | Signature/contract rejections by normative reason code. |
| `metocean.dlq.published` | `reason` | Records dead-lettered. |
| `metocean.advisory.dispatched` | `msg_type` | Verified advisories signaled to route workflows. |
| `metocean.advisory.skipped` | `reason` | Below-threshold advisories, producer-mismatch observations. |

Metrics export through the local Prometheus endpoint
(`MET_OCEAN_METRICS_ADDRESS`); there is no telemetry egress other than the
optional OTLP trace exporter.

## Failure modes and runbook

| Symptom | Meaning | Action |
| --- | --- | --- |
| Bridge refuses to start (config error) | Missing/malformed env: brokers, topic, group, DLQ, SASL/TLS, `KEY_DIRECTORY_PATH`, Temporal, zone map. | Fix the environment; the error names the variable. |
| Bridge refuses to start (key directory) | Directory absent, unreadable, symlinked, invalid JSON, malformed key. | Remount the fleet key directory; never run without it. |
| `metocean.envelope.rejected{reason="unknown-kid"}` rising | Producer rotated keys ahead of the directory, or a foreign producer is publishing. | Refresh the key directory; investigate the producer. |
| `...{reason="payload-mismatch"}` / `invalid-signature` | Tampered or non-canonical events on the topic. | Security event: inspect DLQ records (`x-dlq-*` headers carry topic/partition/offset), escalate per incident process. |
| `...{reason="malformed-advisory"}` | Verified producer emitted a contract-breaking advisory. | Escalate to the waterway-safety team with the DLQ record. |
| `...{reason="unmapped-zone"}` | Advisory covers a hazard zone absent from `MET_OCEAN_ZONE_ROUTE_MAP`. Departures are NOT suspended (fail closed, explicit). | Add the zone mapping and redeploy; replay from the DLQ. |
| Dispatch failures logged ("not committed") | Temporal unavailable. | Restore Temporal; redelivery retries automatically (at-least-once). |
| DLQ publish failures logged | Kafka DLQ unavailable; offsets not committed. | Restore Kafka; redelivery retries. |
| Trips stuck `SUSPENDED` | Advisory neither cancelled nor expired (producer feed dark without a Cancel — a producer contract breach). | Verify the advisory state; the producer must emit an explicit `Cancel`. As a last resort, operators can cancel affected trips through the existing operator API (audited). |
| DLQ accumulating | Any of the above. | Inspect `x-dlq-reason`; after fixing the cause, republish records to the advisory topic (verification re-runs on replay; idempotent suspend/resume make replays safe). |

## Database

Migration `0009_metocean_suspensions.sql` adds the `SUSPENDED` trip status,
the `ferries.notifications.v1` outbox topic, and the `trip_suspensions`
audit table (`(trip_id, advisory_id)` primary key, `resumed_at` marker).
Roll-forward only; apply with the existing migration tooling.
