# Trail Evidence Record v1

Status: **v0.1 draft**. The format may still change before 1.0. Changes
within the `trail.evidence/1` schema are additive only once 1.0 is tagged.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119 and RFC 8174.

## 1. Scope

A Trail Evidence Record is one JSON object that describes one event a
producer wants to be able to prove later: a transfer result, an access
decision, an observed value, a completed training run. Records of one
producer form hash chains. A chain can be verified from the records alone,
without the producer, a database or a network service.

This document defines the record shape, the canonicalisation and hashing
rules, the chaining rules, the optional signature, and the verification
algorithm with its finding classes. It does not define storage, transport,
retention or anchoring to external systems.

## 2. Encoding

- A record is a JSON object encoded in UTF-8.
- A **journal** is a JSON Lines file: one record per line, lines separated
  by `\n`, UTF-8, optional trailing newline. Blank lines are ignored.
- All hashes are SHA-256 digests written as the string `sha256:` followed by
  exactly 64 lowercase hexadecimal characters.
- All hashed inputs are the RFC 8785 (JSON Canonicalization Scheme, JCS)
  form of a JSON value. Implementations MUST implement RFC 8785 completely,
  including ES6 number formatting and member sorting by UTF-16 code units.
- The genesis hash is `sha256:` followed by 64 `0` characters.
- Timestamps are RFC 3339 in UTC with the `Z` designator. `time.recorded_at`
  MUST carry at least millisecond precision (`.sss`); up to nine fractional
  digits are allowed. Other timestamps MAY omit the fraction.

## 3. Record members

### 3.1 Required members

| Member | Type | Rule |
|---|---|---|
| `schema` | string | MUST be `"trail.evidence/1"`. |
| `producer` | object | `kind`, `id`, `version`; see 3.3. |
| `stream_id` | string | Non-empty. Names one hash chain. A producer MAY run several streams. |
| `seq` | integer | `>= 0`. Increases by exactly 1 within a stream, except on a restart (4.2). |
| `prev_hash` | hash | `chain_hash` of the previous record of the stream; genesis hash for the first record; equal to `anchor_hash` on a restart. |
| `event_type` | string | `<domain>.<noun>.<verb>`, lowercase, exactly three segments matching `^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*){2}$`. Examples: `transfer.job.result`, `mqtt.decision.deny`, `source.value.observed`, `source.inventory.changed`, `ml.run.completed`. |
| `time` | object | `recorded_at`, `source`; optional `occurred_at`, `read_at`; see 3.3. |
| `actor` | object | `auth`; optional `id`, `roles`; see 3.3. |
| `policy` | object | `id`, `version`, `hash`; optional `status`, `kind`; see 3.3. |
| `payload` | any | Any JSON value. An object is RECOMMENDED. |
| `content_hash` | hash | SHA-256 over JCS(`payload`). |
| `chain_hash` | hash | SHA-256 over JCS(core); see 4.1. |

### 3.2 Optional members

| Member | Type | Rule |
|---|---|---|
| `chain_restart` | boolean | When present it MUST be `true`. Marks the first record of a new segment (4.2). Part of the core. |
| `anchor_hash` | hash | MUST be present if and only if `chain_restart` is present. Last known `chain_hash` of the previous segment, or the genesis hash if unknown. Part of the core. |
| `signature` | object | `alg`, `key_id`, `sig`; see 5. Not part of the core. |
| `correlation_id` | string | Non-empty. Not part of the core. |
| `job_id` | string | Non-empty. Not part of the core. |
| `decision_id` | string | Non-empty. Not part of the core. |
| `context` | object | Informational members of any shape. Never part of any hash. Evidence-relevant facts belong in `payload`, not here. |
| `redaction` | object | `fields` (array of JSON Pointer strings, RFC 6901, relative to `payload`), `method` (non-empty string). Documents which payload members were masked **before** hashing. Not part of the core. |
| `anchor` | object | `kind` (`trailmq`, `tsa`, `worm`, `other`), `ref` (non-empty string). Points to an external anchoring of this record's `chain_hash`. Not part of the core. |

No other top-level members are allowed. Unknown members in the top-level
object or in `producer`, `time`, `actor`, `policy`, `signature`, `redaction`
or `anchor` make a record invalid. `payload` and `context` are free.

### 3.3 Typed sub-objects

`producer`

- `kind` (string): one of `broker`, `transfer-worker`, `source-bridge`,
  `ml-pipeline`, `persistence`, `other`.
- `id` (string, non-empty): stable identifier of the producing instance
  (worker id, bridge id, broker node, run id).
- `version` (string, non-empty): build version of the producer.

`time`

- `recorded_at` (timestamp, required): the moment of sealing.
- `occurred_at` (timestamp): when the fact happened at its source.
- `read_at` (timestamp): when the producer read the fact.
- `source` (string, required): one of `system`, `ntp`, `tsa`,
  `seq-reconstructed`, `unknown`. Describes where `recorded_at` came from.

`actor`

- `auth` (string, required): one of `broker-authenticated`,
  `self-declared`, `operator-token`, `none`.
- `id` (string): identity of the actor.
- `roles` (array of strings).

`policy`

- `id` (string, non-empty), `version` (string, non-empty).
- `hash` (hash): SHA-256 over the canonical form of the policy document.
- `status` (string): one of `draft`, `validated`, `approved`, `active`,
  `retired`.
- `kind` (string): free text, for example `transfer-policy`, `topic-rule`,
  `recipe`, `addressspace`, `config`.
- When no policy applies the producer MUST use
  `{"id":"none","version":"0","hash":"sha256:<64 zeros>"}`.

## 4. Hashing and chaining

### 4.1 Hashes

```
content_hash = "sha256:" + hex( SHA-256( JCS(payload) ) )
core         = { schema, producer, stream_id, seq, prev_hash, event_type,
                 time, actor, policy, content_hash
                 [, chain_restart, anchor_hash  -- when present] }
chain_hash   = "sha256:" + hex( SHA-256( JCS(core) ) )
```

The core contains exactly the listed members, taken from the record as
written (including optional sub-members such as `time.occurred_at` or
`actor.roles` when present) and nothing else. `signature`, `correlation_id`,
`job_id`, `decision_id`, `context`, `redaction` and `anchor` are never
hashed. Two records that differ only in those members have the same
`chain_hash` (vectors `context-absent` and `context-present`).

Member order in the serialised record is irrelevant; JCS sorts.

### 4.2 Chaining and restarts

- The first record of a stream has `seq = 0` and `prev_hash = genesis`.
- Every following record has `seq = previous.seq + 1` and
  `prev_hash = previous.chain_hash`.
- When a producer cannot continue a segment (new process, lost state, new
  storage), it starts a new segment with `chain_restart: true`,
  `anchor_hash` set to the last `chain_hash` it knows from the previous
  segment (or genesis if it knows none), `prev_hash = anchor_hash`, and any
  `seq` (normally 0). A restart is a notice, not a failure, when the anchor
  matches the previous segment or is genesis.
- `seq` and `prev_hash` are judged per `stream_id`. A journal MAY interleave
  records of several streams.

### 4.3 Payload rules

- Secrets MUST be masked before `content_hash` is computed and the masked
  members MUST be listed in `redaction.fields`.
- JCS forces ES6 number semantics: every JSON number is an IEEE-754 double
  and is rendered with the ES6 `Number.prototype.toString` rules. Two
  consequences follow. Integers outside ±2^53 MUST be transported as
  strings inside `payload`; otherwise they are silently rounded (vector
  `jcs-edge-cases`: `9007199254740993` canonicalises to
  `9007199254740992`, and a verifier reports the `number_precision`
  notice). Floating point numbers whose exact decimal rendering matters
  (measurements, probabilities, money) SHOULD be transported as strings as
  well: `1.0` and `1` hash the same, `4.50` becomes `4.5`, and decimal
  fractions pass through binary rounding. Strings keep the bytes the
  producer wrote.
- `payload` MAY be `null`; it MUST be present.

## 5. Signature

- `alg` MUST be `"ed25519"`.
- `sig` is the 64-byte Ed25519 signature (RFC 8032, pure Ed25519, no
  prehash) over the **ASCII bytes of the `chain_hash` string** (71 bytes,
  including the `sha256:` prefix), encoded as base64url without padding
  (86 characters).
- `key_id` is a non-empty string that lets a verifier select the key. It
  SHOULD be `"ed25519:"` followed by the first 16 hex characters of
  SHA-256(32-byte public key).
- Because `chain_hash` commits to the core and the core commits to
  `prev_hash`, a signature on a record also covers the chain up to it.

## 6. Verification

A verifier reads a journal line by line, tracks one state per `stream_id`
(`last_seq`, `last_chain_hash`), and reports **findings**. A finding has a
record index (counting non-empty lines from 0), a class, a severity and a
message. The journal verifies (`ok`) when no finding has severity `error`.

### 6.1 Finding classes

| Class | Severity | Meaning |
|---|---|---|
| `schema_invalid` | error | Not a JSON object, unknown member, wrong type, missing required member, `null` in a typed member, value outside its enumeration or pattern, restart invariants violated. |
| `hash_mismatch` | error | Recomputed `content_hash` or `chain_hash` differs from the recorded one. |
| `chain_break` | error | `prev_hash` does not match the previous `chain_hash` of the stream; first record of a stream is neither genesis nor a restart; restart `anchor_hash` matches neither the previous segment's last `chain_hash` nor genesis. |
| `seq_gap` | error | `seq` is not previous + 1; first record of a stream has `seq != 0` without restart. |
| `restart` | notice | A record with `chain_restart: true`. Reported separately so that breaks and gaps stay distinguishable from intended restarts. |
| `number_precision` | notice | `payload` contains an integer literal outside ±2^53 (no fraction, no exponent). The hashes are still well defined, but the value was rounded by canonicalisation; see 4.3. |
| `signature_invalid` | error | Signature present but malformed or not verifying with the given key; or, when signatures are required, a record without one. |

### 6.2 Algorithm

For each non-empty line, in file order:

1. **Decode.** Parse the line as JSON. If it is not an object, or a typed
   member has the wrong JSON type (for example a string `seq`, a non-object
   `producer`), or an unknown member appears in the top-level object or in a
   typed sub-object, report `schema_invalid` and **skip the record**: it
   takes no part in steps 2 to 6 and does not change the stream state.
2. **Schema.** Report every other structural violation (3.1 to 3.3, 4.2
   invariants) as `schema_invalid`. Continue.
3. **Hashes.** Recompute `content_hash` over JCS(`payload`). Build the core
   from the record's own members, replacing `content_hash` with the
   recomputed value, and recompute `chain_hash`. Report each difference as
   `hash_mismatch`. If `payload` contains integer literals outside ±2^53,
   report one `number_precision` notice for the record.
4. **Chain.** Look up the state of `stream_id`:
   - record has `chain_restart`: report `restart` (notice); if the stream was
     seen before and `anchor_hash` is neither its `last_chain_hash` nor
     genesis, report `chain_break`.
   - stream not seen before: `prev_hash != genesis` is a `chain_break`;
     otherwise `seq != 0` is a `seq_gap`.
   - stream seen before: `prev_hash != last_chain_hash` is a `chain_break`;
     `seq != last_seq + 1` is a `seq_gap`.
   Then set `last_seq = seq` and `last_chain_hash` to the record's
   **declared** `chain_hash`, so that later records are judged against what
   they were actually linked to.
5. **Signature.** If a public key is given and the record carries a
   signature, verify it per section 5; failure is `signature_invalid`. If a
   public key is given, the verifier was told to require signatures, and the
   record has none, report `signature_invalid`. Without a key, signatures are
   counted but not checked.
6. Continue with the next line. Verification does not stop at the first
   error.

The report SHOULD contain: `ok`, number of records, number of errors,
number of notices, number of restarts, number of signed records, number of verified
signatures, a summary per stream (`stream_id`, records, first and last
`seq`, `last_chain_hash`, restarts), and the findings.

### 6.3 What verification does and does not prove

- A record cannot be altered, removed or reordered within a journal without
  a `hash_mismatch`, `chain_break` or `seq_gap`.
- An unsigned journal can be rewritten wholesale by whoever controls the
  file. Signatures bind the chain to a key; anchoring the latest
  `chain_hash` elsewhere (`anchor`) binds it to a point in time. Neither is
  implied by a passing verification without keys.
- Verification says nothing about whether `payload` is true, whether
  `time.recorded_at` is accurate (see `time.source`), or whether the policy
  named in `policy` was the right one.

## 7. Test vectors

`testdata/vectors.json` is produced by the Go reference implementation and
contains, per vector, the record and the expected payload JCS,
`content_hash`, core JCS and `chain_hash`. Every implementation MUST
reproduce these values byte for byte. `testdata/streams/` holds journals
with the findings a verifier MUST report. The signing key in
`testdata/keys/` is a published test key (RFC 8032 test vector 1).

## 8. Mapping notes (informative)

- TrailTransfer journal: `worker_id` → `producer.id` and `stream_id`;
  `issuer` → `actor`; `recorded_at`, `time_source` → `time`;
  `policy_version`, `policy_hash` → `policy`; `command_hash` stays in
  `payload`; `schema_version` → `schema`. The signature changes from
  signing the digest bytes to signing the ASCII `chain_hash` string.
- Source bridge envelope: the `audit` block maps to the core; `data` →
  `payload`; `context` → `context`, except evidence-relevant members
  (`native_node_id`, `entity_key`, `inventory_hash`) which go into
  `payload`; `config_version` → `policy{kind:"config"}`; the inventory
  fingerprint → `policy{kind:"addressspace"}` on value events.
- Broker decision logs: one record per decision with `payload` carrying the
  message and decision fields, `policy` the matched rule, `actor` the
  authenticated client; produced by an export adapter.
- ML pipeline: the audit record of a run becomes the `payload` of
  `ml.run.completed`; the recipe becomes `policy{kind:"recipe"}` with its
  lifecycle `status`.
- Reason codes: producers that explain an outcome put a code from the
  shared catalog into `payload.reason_code` (`docs/REASON_CODES.md`,
  machine-readable in `schema/reason-codes.json`), for example
  TrailTransfer's rejection reason `policy_violation` as
  `transfer.policy_violation`. The catalog is informative; verifiers do not
  check reason codes.

## 9. Versioning

`schema` carries name and major version. Within `trail.evidence/1`, new
optional members MAY be added; existing members, enumerations, hashing and
chaining rules MUST NOT change. Anything else is `trail.evidence/2`.
