# Reason codes

Status: **draft**, catalog version 0.1.0. Machine-readable form:
[`schema/reason-codes.json`](../schema/reason-codes.json), shape defined by
[`schema/reason-codes.schema.json`](../schema/reason-codes.schema.json). The
tables below are generated from the JSON by `scripts/reason_codes.py --write`;
edit the JSON, not the tables.

A record's `event_type` says what happened. `payload.reason_code` says why
an outcome is what it is: why a job failed, why a broker denied a publish,
why a value is unusable. When every producer uses the same codes, one query
over a mixed journal ("all `error` outcomes last night") works without a
mapping per producer.

## Rules

- `payload.reason_code` is a string `<namespace>.<name>`, lowercase, for
  example `transfer.policy_violation`. One code per record.
- It is RECOMMENDED on records of refused, failed or degraded outcomes and
  MAY be set on successful ones.
- The namespace follows the producer kind (`transfer`, `mqtt`, `source`,
  `ml`); `common` is for conditions every producer can hit: gaps, restarts,
  configuration changes, an unreliable clock.
- Free text belongs next to the code (`error`, `errors`, `detail`), not in
  it. Domain data stays in the payload as before.
- A code keeps its meaning once it is in the catalog. New codes are added by
  a pull request against `schema/reason-codes.json`; a producer that needs a
  code before then uses its own namespace and treats it as provisional.
- **Verifiers do not check reason codes.** `reason_code` is part of
  `payload` and therefore covered by `content_hash` like any other member;
  whether the code is in this catalog has no effect on verification.

## Severity

The severity belongs to the code, not to the verification. A record with an
`error` reason code can sit in a perfectly intact chain.

| Severity | Meaning |
|---|---|
| `info` | The event happened as intended. Nothing to follow up. |
| `warning` | The operation was refused by design, or it completed in a degraded way. The evidence is complete; someone should look. |
| `error` | The operation failed, or facts the producer should have recorded are missing. |

## Codes and finding classes

Two pairs look alike and mean different things:

- `common.gap` is a record the producer writes to declare that events were
  not captured, for example while a source was disconnected. The journal is
  intact. The finding class `seq_gap` means records are missing from the
  journal itself; no producer writes it, the verifier reports it.
- `common.restart` and `common.state_lost` belong on the record that carries
  `chain_restart: true`; the verifier reports that record as the notice
  `restart`. `common.state_lost` is the case where `anchor_hash` is the
  genesis hash because the producer lost its previous state.

## Catalog

The examples show `event_type` and the payload without `reason_code`. Hash
values are shortened to `sha256:…`.

<!-- BEGIN GENERATED: scripts/reason_codes.py --write -->

### `transfer.*`

File transfer jobs (TrailTransfer): results and rejections. Producer kinds: `transfer-worker`.

| Code | Severity | Meaning | Example |
|---|---|---|---|
| `transfer.completed` | info | The job ran to the end and every file reached the target. | `transfer.job.result` with `{"action":"copy","status":"ok","files":1}` |
| `transfer.source_not_found` | error | The source path did not exist when the job ran; nothing was transferred. | `transfer.job.result` with `{"action":"copy","status":"failed","error":"source not found","files":0}` |
| `transfer.target_write_failed` | error | The target refused or failed a write (permission, quota, network); the job stopped. | `transfer.job.result` with `{"action":"copy","status":"failed","error":"s3: AccessDenied","files":0}` |
| `transfer.checksum_mismatch` | error | The checksum of a file read back from the target differs from the source. | `transfer.job.result` with `{"action":"copy","status":"failed","file":"report.csv","source_sha256":"sha256:…","target_sha256":"sha256:…"}` |
| `transfer.partial` | error | Some files reached the target, others did not; the payload lists the failed ones. | `transfer.job.result` with `{"action":"move","status":"failed","files":14,"files_failed":["batch-07/f-09.csv"]}` |
| `transfer.cancelled` | warning | An operator or the scheduler cancelled the job before it finished. | `transfer.job.result` with `{"action":"sync","status":"cancelled","files":3}` |
| `transfer.schema_violation` | warning | The job command did not match the command schema and was rejected before execution. | `transfer.job.rejected` with `{"status":"rejected","errors":["/target: required"]}` |
| `transfer.policy_violation` | warning | The transfer policy does not allow this action, source or target; the job was rejected before execution. | `transfer.job.rejected` with `{"status":"rejected","action":"move","target":"s3://public/…"}` |
| `transfer.duplicate_job_id` | warning | A job with this job_id was already accepted; the second submission was rejected. | `transfer.job.rejected` with `{"status":"rejected","job_id":"job-1002"}` |
| `transfer.too_many_jobs` | warning | The worker's concurrency limit was reached; the job was rejected and may be resubmitted. | `transfer.job.rejected` with `{"status":"rejected","running":8,"limit":8}` |

### `mqtt.*`

Broker access decisions, as written by an export adapter. Producer kinds: `broker`.

| Code | Severity | Meaning | Example |
|---|---|---|---|
| `mqtt.rule_match` | info | A topic rule grants this client the requested action on this topic; the broker allowed it. | `mqtt.decision.allow` with `{"client_id":"sensor-gw-3","topic":"plant/line1/telemetry","action":"publish","access_decision":"allow"}` |
| `mqtt.no_matching_grant` | warning | No topic rule grants this client the requested action on this topic; the broker denied it (default deny). | `mqtt.decision.deny` with `{"client_id":"guest-app","topic":"plant/line1/control","action":"publish","access_decision":"deny"}` |
| `mqtt.explicit_deny` | warning | A topic rule explicitly denies this client the requested action; the broker denied it. | `mqtt.decision.deny` with `{"client_id":"hmi-line2","topic":"plant/line1/control","action":"publish","access_decision":"deny"}` |
| `mqtt.not_authenticated` | warning | The client had no authenticated identity and the requested action needs one; the broker denied it. | `mqtt.decision.deny` with `{"client_id":"anon-7f","topic":"plant/line1/telemetry","action":"subscribe","access_decision":"deny"}` |
| `mqtt.policy_unavailable` | error | The broker could not evaluate its rules (store unreachable, rule set not loaded) and denied the action fail-closed. | `mqtt.decision.deny` with `{"client_id":"sensor-gw-3","topic":"plant/line1/telemetry","action":"publish","access_decision":"deny"}` |
| `mqtt.quota_exceeded` | warning | The action was within the client's grants but exceeded a rate, size or connection limit; the broker denied it. | `mqtt.decision.deny` with `{"client_id":"sensor-gw-3","topic":"plant/line1/telemetry","action":"publish","payload_size":1048577,"access_decision":"deny"}` |

### `source.*`

Source bridges (TrailSource): address space, value quality, connection. Producer kinds: `source-bridge`.

| Code | Severity | Meaning | Example |
|---|---|---|---|
| `source.inventory_initial` | info | First complete browse of the source's address space after the bridge started. | `source.inventory.changed` with `{"inventory_hash":"sha256:…","count":2}` |
| `source.node_added` | info | A node appeared in the address space; the inventory fingerprint changed. | `source.inventory.changed` with `{"inventory_hash":"sha256:…","added":["ns=2;s=Line1.Pressure"]}` |
| `source.node_removed` | warning | A node that values were read from disappeared from the address space; later records cannot refer to it. | `source.inventory.changed` with `{"inventory_hash":"sha256:…","removed":["ns=2;s=Line1.Speed"]}` |
| `source.quality_uncertain` | warning | The source delivered the value with quality uncertain (stale, sensor not calibrated, substituted). | `source.value.observed` with `{"entity_key":"line1/temp","value":"21.5","quality":"uncertain"}` |
| `source.quality_bad` | error | The source delivered the value with quality bad; the value must not be used as a measurement. | `source.value.observed` with `{"entity_key":"line1/temp","value":"0","quality":"bad"}` |
| `source.connection_lost` | error | The bridge lost the connection to the source; values that changed until it reconnects are not observed. | `source.connection.changed` with `{"source_address":"opc.tcp://plc-7:4840","state":"disconnected"}` |
| `source.connection_restored` | info | The bridge reconnected to the source and resumed reading. | `source.connection.changed` with `{"source_address":"opc.tcp://plc-7:4840","state":"connected","down_ms":4200}` |
| `source.queue_overflow` | error | Values arrived faster than the bridge could seal them and were dropped; the payload counts them. | `source.value.dropped` with `{"entity_key":"line1/speed","dropped":37}` |

### `ml.*`

ML pipelines: run lifecycle, acceptance against the recipe, predictions. Producer kinds: `ml-pipeline`.

| Code | Severity | Meaning | Example |
|---|---|---|---|
| `ml.metrics_accepted` | info | The run's metrics meet the acceptance criteria of the recipe named in policy. | `ml.run.completed` with `{"run_id":"run-7f3a","metrics":{"dice":"0.9132"},"decision":{"threshold":"0.9000"}}` |
| `ml.metrics_below_threshold` | warning | The run completed but a metric is below the recipe's acceptance threshold; the model is not released. | `ml.run.completed` with `{"run_id":"run-81c2","metrics":{"dice":"0.8710"},"decision":{"threshold":"0.9000"}}` |
| `ml.recipe_not_approved` | error | The run used a recipe whose policy.status is not approved or active; its results must not be released. | `ml.run.started` with `{"run_id":"run-81c3","recipe_status":"draft"}` |
| `ml.data_fingerprint_mismatch` | error | The fingerprint of the input data differs from the one the recipe declares; the run is not comparable. | `ml.run.started` with `{"run_id":"run-81c4","data_fingerprint":"sha256:…","expected_data_fingerprint":"sha256:…"}` |
| `ml.run_aborted` | error | The run stopped before completion (crash, timeout, operator); no metrics are final. | `ml.run.aborted` with `{"run_id":"run-81c5","after_s":1312,"error":"CUDA out of memory"}` |
| `ml.low_confidence` | warning | A prediction's calibrated probability is below the recipe's confidence threshold and needs review. | `ml.prediction.created` with `{"run_id":"run-7f3a","sample_id":"s-000512","probability":"0.5410","label":"defect"}` |

### `common.*`

Conditions every producer can hit: gaps, restarts, configuration changes, clock problems. Producer kinds: `broker`, `transfer-worker`, `source-bridge`, `ml-pipeline`, `persistence`, `other`.

| Code | Severity | Meaning | Example |
|---|---|---|---|
| `common.gap` | error | The producer knows that events between two points were not recorded (outage, dropped values, lost buffer) and says so. The journal itself stays intact; compare the finding class seq_gap, which means records are missing from the journal. | `source.data.gap` with `{"from":"2026-11-02T07:10:00.000Z","to":"2026-11-02T07:14:12.000Z","cause":"source.connection_lost"}` |
| `common.restart` | info | The producer process restarted and continued the stream with a new segment anchored at the last chain_hash it knew. Belongs on the record with chain_restart: true. | `transfer.worker.restarted` with `{"previous_version":"0.3.0","version":"0.3.1"}` |
| `common.state_lost` | warning | The producer restarted without knowing its previous chain_hash (storage lost or replaced) and anchored the new segment at genesis. | `source.bridge.restarted` with `{"cause":"state directory empty"}` |
| `common.config_changed` | info | The producer loaded a new configuration or policy version; later records name it in policy. | `transfer.policy.changed` with `{"policy_id":"archive-policy","from_version":"6","to_version":"7","to_hash":"sha256:…"}` |
| `common.time_uncertain` | warning | The producer cannot vouch for its clock (no NTP sync, time reconstructed from seq); recorded_at may be off. Records written meanwhile carry time.source unknown or seq-reconstructed. | `source.clock.changed` with `{"time_source":"unknown","last_sync":"2026-11-01T22:00:00.000Z"}` |
| `common.clock_step` | warning | The wall clock jumped forwards or backwards by more than the producer's tolerance; recorded_at values around the step are not monotonic. | `transfer.clock.stepped` with `{"step_ms":-3500,"time_source":"ntp"}` |

36 codes: 8 info, 16 warning, 12 error.

<!-- END GENERATED -->

## Where the codes come from

`transfer.*` follows the job statuses and rejection reasons of TrailTransfer
(`completed`, `failed`, `cancelled`; `schema_violation`, `policy_violation`,
`duplicate_job_id`, `too_many_jobs`) and the failed job in
`examples/transfer-worker.jsonl`. `mqtt.rule_match` and
`mqtt.no_matching_grant` are the codes in `examples/broker-export.jsonl`; the
other `mqtt.*` codes cover the remaining ways a broker reaches a decision
(explicit deny, no identity, rules unavailable, limits). `source.*` and
`ml.*` follow the members of the example journals (`quality`,
`inventory_hash`, `decision.threshold`, `data_fingerprint`). `common.*`
mirrors the record members and finding classes in `SPEC.md` that describe
the same conditions. Each entry's `derived_from` in the JSON names its
source.
