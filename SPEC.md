# Trail Evidence Record v1

Status: **v0.2 draft** (format 0.2 of `trail.evidence/1`, released with
trail-evidence 0.2.0 on 2026-11-03). The
format may still change before 1.0. Changes within the `trail.evidence/1`
schema are additive only once 1.0 is tagged. Format 0.2 is not compatible
with 0.1 in both directions: `seq` is a decimal string, records carry a
state, journals a three-valued verdict, and the finding classes changed
(section 9 lists the differences).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119 and RFC 8174.

## 1. Scope

A Trail Evidence Record is one JSON object that describes one event a
producer wants to be able to prove later: a transfer result, an access
decision, an observed value, a completed training run. Records of one
producer form hash chains. A chain can be verified from the records alone,
without the producer, a database or a network service.

This document defines the record shape, the canonicalisation and hashing
rules, the chaining rules, the optional signature, profiles, and the
verification algorithm with its record states and finding classes. It does
not define storage, transport, retention or anchoring to external systems.

Trail Evidence defines the common structure: canonicalisation, chaining and
versioning. A producer defines its domain data (`payload`) as a **profile**
(section 3.4), registered in `profiles/` of this repository. This
repository registers only the test profile `example.measurement/1`.

## 2. Encoding

- A record is a JSON object encoded in UTF-8.
- A **journal** is a JSON Lines file: one record per line, lines separated
  by `\n` (LF), UTF-8, optional trailing newline. A line ends at LF only; a
  carriage return is JSON white space and does not end a line.
- A line is **blank** when it is empty or holds only JSON white space
  (space, tab, carriage return). Blank lines are ignored. Every other line
  is a record line and MUST hold exactly one JSON object (RFC 8259) under
  these **reading rules**, which follow I-JSON (RFC 7493) where RFC 8785
  relies on it:
  - the line is valid UTF-8 and has no byte order mark;
  - no object, at any depth, has two members with the same name. Names are
    compared after their escapes are decoded, so `"a"` and `"\u0061"` are
    the same name;
  - no string and no member name holds an unpaired surrogate escape
    (`"\ud800"`, or a high surrogate not followed by a low one);
  - objects and arrays nest at most 64 levels deep; the record object is
    level 1;
  - nothing but JSON white space precedes or follows the object on the line.

  A record line that breaks a reading rule is `schema_invalid` at step 1 of
  6.3 and takes no part in the chain. The rules close the gaps in which two
  correct JSON parsers read the same bytes differently: one keeps the first
  of two members with the same name, another the last; one replaces bytes
  that are not UTF-8, another rejects them; one stops at the end of the
  object, another reads on. A verifier and the program that later reads the
  journal must see the same record.
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
| `seq` | string | Position in the stream as a decimal string: matches `^(0\|[1-9][0-9]*)$` (no sign, no leading zeros, no fraction or exponent) and its value is at most 18446744073709551615 (2^64 - 1). Increases by exactly 1 within a stream, except on a restart (4.2). See the transition rule below. |
| `prev_hash` | hash | `chain_hash` of the previous record of the stream; genesis hash for the first record; equal to `anchor_hash` on a restart. |
| `event_type` | string | `<domain>.<noun>.<verb>`, lowercase, exactly three segments matching `^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*){2}$`. Examples: `transfer.job.result`, `mqtt.decision.deny`, `source.value.observed`, `source.inventory.changed`, `ml.run.completed`. |
| `time` | object | `recorded_at`, `source`; optional `occurred_at`, `read_at`; see 3.3. |
| `actor` | object | `auth`; optional `id`, `roles`; see 3.3. |
| `policy` | object | `id`, `version`, `hash`; optional `status`, `kind`; see 3.3. |
| `payload` | any | Any JSON value. An object is RECOMMENDED. |
| `content_hash` | hash | SHA-256 over JCS(`payload`). |
| `chain_hash` | hash | SHA-256 over JCS(core); see 4.1. |

Transition rule for `seq` (0.x only): a JSON number is accepted in place of
the string when it is an integer literal of the same form and range, for
example `7`. A verifier reports it with the notice `legacy_integer_seq` and
otherwise treats it like the string `"7"`; journals written in format 0.1
keep verifying. From 1.0 on, a JSON number as `seq` is `schema_invalid`. A
missing, `null` or malformed `seq` (`"07"`, `"-1"`, `"1.0"`, `1.0`, `-0`,
`"18446744073709551616"`) is `schema_invalid` in every version.

`seq` is a string because JCS renders numbers as IEEE-754 doubles (4.3): as a
number, 9007199254740993 would be hashed as 9007199254740992, and any
implementation that parses JSON numbers into doubles cannot tell
9007199254740992 and 9007199254740993 apart.

### 3.2 Optional members

| Member | Type | Rule |
|---|---|---|
| `profile` | string | `<name>/<major>`: the profile that defines the payload (3.4). `name` matches `^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$`, `major` is an integer >= 1 without leading zeros. Part of the core. |
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

### 3.4 Profiles

A profile names the payload schema of a kind of record, for example the
decision records of a broker. The producer defines it; the shared contract
stays the same for every producer.

- `profile` is `<name>/<major>`, for example `example.measurement/1`. The
  name has at least two dot-separated segments; the first SHOULD identify the
  producer or its organisation.
- The schema of a profile is `profiles/<name>/<major>.schema.json` in this
  repository. `profiles/README.md` describes how a producer submits one:
  the schema, example payloads that must be accepted or rejected, and a
  journal written by the producer's own implementation.
- **Versioning.** Only the major version is part of the identifier. Minor
  versions within a major are additive: they MAY add optional members and
  MUST NOT add required members, remove members, change a member's type or
  change its meaning. Anything else is a new major. Because a record of a
  later minor version may carry members an older schema does not name,
  profile schemas allow members they do not name and check only required
  members and types.
- **Schema subset.** A profile schema is a JSON Schema 2020-12 document
  whose top level has `type: "object"`. It uses only the keywords `type`
  (a type name or an array of them), `required`, `properties` and `items`
  (a single schema), plus the annotations `$schema`, `$id`, `$comment`,
  `title`, `description` and `examples`. The keywords have their JSON Schema
  meaning: `integer` is any number without a fractional part (`16.0`
  counts), `required` and `properties` apply to objects only, `items` to
  arrays only. Any other keyword makes the schema unusable as a profile.
- `profile` is part of the core: a record whose profile was changed after
  sealing fails `chain_hash` (vector `profile-valid`, fixture
  `profile-tampered.jsonl`).

How a verifier evaluates a profile and what it reports is in 6.1 and 6.3.

## 4. Hashing and chaining

### 4.1 Hashes

```
content_hash = "sha256:" + hex( SHA-256( JCS(payload) ) )
core         = { schema, producer, stream_id, seq, prev_hash, event_type,
                 time, actor, policy, content_hash
                 [, chain_restart, anchor_hash, profile  -- when present] }
chain_hash   = "sha256:" + hex( SHA-256( JCS(core) ) )
```

The core contains exactly the listed members, taken from the record as
written (including optional sub-members such as `time.occurred_at` or
`actor.roles` when present) and nothing else. Every member is hashed in the
form the record carries it: `"seq":"7"` and the legacy `"seq":7` give
different `chain_hash` values, and a verifier never converts one into the
other before hashing (vector `seq-legacy-integer`). `signature`, `correlation_id`,
`job_id`, `decision_id`, `context`, `redaction` and `anchor` are never
hashed. Two records that differ only in those members have the same
`chain_hash` (vectors `context-absent` and `context-present`).

Member order in the serialised record is irrelevant; JCS sorts.

### 4.2 Chaining and restarts

- The first record of a stream has `seq = "0"` and `prev_hash = genesis`.
- Every following record has `seq = previous.seq + 1` and
  `prev_hash = previous.chain_hash`.
- `seq` values are compared as integers of arbitrary size, never as IEEE-754
  doubles and never as strings. "18446744073709551615" is followed by
  nothing: a producer that reaches it starts a new segment with a restart.
- When a producer cannot continue a segment (new process, lost state, new
  storage), it starts a new segment with `chain_restart: true`,
  `anchor_hash` set to the last `chain_hash` it knows from the previous
  segment (or genesis if it knows none), `prev_hash = anchor_hash`, and any
  `seq` (normally `"0"`). A restart is a notice, not a failure, when the
  anchor matches the previous segment or is genesis.
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

A verifier reads a journal line by line, gives every non-empty line (a
**record**, counted from index 0) a **state** and a **profile state**, and
reports **findings**. A finding has a record index, a class, a severity and
a message. Per `stream_id` the verifier keeps the last checked position
(`last_seq`, `last_chain_hash`) and the state of the record it came from.

### 6.1 Record states and profile states

Every record is in exactly one state:

| State | Definition |
|---|---|
| `valid` | Every check that applies to the record ran and passed: schema, `content_hash`, `chain_hash`, the link to its predecessor, `seq`, the profile if the verifier knows it, and the signature if the record is signed and a key was given. |
| `invalid` | At least one check failed: the record has a finding of an error class (6.2): `schema_invalid` (including a missing or malformed `seq`, or a line that is not a JSON object or has no `schema`), `hash_mismatch`, `chain_break` with the predecessor present, `seq_mismatch` (seq repeated, going backwards, or skipping although `prev_hash` links to the predecessor), `signature_invalid`, `profile_invalid`. |
| `unknown` | The record's own hashes are correct, but its link cannot be checked because its predecessor is not in the journal: the first record after a gap (`seq` ahead of the expected value and `prev_hash` not linking to the last checked record), or the first record of a stream that is neither genesis (`prev_hash` genesis, `seq` `"0"`) nor a restart. The gap itself is the finding `seq_gap`. A record that links correctly to an `unknown` record is `valid` relative to it and carries the notice `after_unknown`. |
| `outside_scope` | The record does not belong to this contract: `schema` is a string of the form `<name>/<major>` (`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*/(0\|[1-9][0-9]*)$`) other than `trail.evidence/1`, naming another format or another major version. It is not checked and does not take part in any chain (6.3, step 2). |

`invalid` takes precedence over `unknown`: a record after a gap whose own
hash is wrong is `invalid`, and its `seq_gap` is reported as well. A state
describes the record, never the options of the verification (6.4).

Four rules of this table are decisions rather than consequences, so they
are stated with their reason:

- **A skipped `seq` on a linked record is `invalid`, not `unknown`.** When
  `prev_hash` links to the predecessor that is present, the producer itself
  says that nothing lies between the two records; a `seq` that skips ahead
  contradicts that. This is what deleting a record and re-sealing its
  successor produces, so it must not be mistaken for a journal that is
  merely incomplete. `unknown` is reserved for a record whose predecessor
  cannot be checked at all (`prev_hash` does not link to any record in the
  journal).
- **`after_unknown` marks only the record directly after an `unknown`
  record.** Every later record of the run is just as relative to the
  unknown record, but repeating the notice on each of them would bury the
  report of a long excerpt; the one notice marks where the relative chain
  begins.
- **A record without a usable position takes no part in the chain.** A
  record without a non-empty `stream_id` or a usable `seq` cannot be placed
  in a chain. It is `invalid` (`schema_invalid`) and does not change any
  stream state, so the next record of the stream is judged against the
  last record that had a position; if it linked to the record without a
  position, its predecessor is missing for the chain and it is `unknown`
  (fixture `seq-missing.jsonl`).
- **`outside_scope` requires a schema identifier.** Only a `schema` of the
  form `<name>/<major>` names another format or major version. A missing
  `schema`, a non-string or a free-form value cannot be told apart from a
  broken record and is `invalid`.

Every record also has a profile state:

| Profile state | Definition |
|---|---|
| `none` | The record has no `profile` member, or it was not evaluated because the record is not a decodable record of this contract (step 1 to 3 of 6.3). |
| `valid` | The verifier knows the profile and the payload satisfies its schema. |
| `invalid` | The verifier knows the profile and the payload violates its schema (`profile_invalid`; the record is `invalid` as well), or the `profile` member itself is malformed (`schema_invalid`). |
| `outside_scope` | The `profile` member is well formed but the verifier does not know the name or does not support the major version (notice `profile_unknown`). The payload is not checked against a profile; the record's state follows from the other checks alone. |

### 6.2 Finding classes

| Class | Severity | Record state | Meaning |
|---|---|---|---|
| `schema_invalid` | error | invalid | Not a JSON object under the reading rules of section 2, unknown member, wrong type, missing required member, `null` in a typed member, value outside its enumeration, pattern or range (including `seq`), a malformed `profile`, restart invariants violated. Reported once per record; the message lists every problem found. |
| `hash_mismatch` | error | invalid | Recomputed `content_hash` or `chain_hash` differs from the recorded one. |
| `chain_break` | error | invalid | `prev_hash` does not link to the predecessor although the predecessor is present: `seq` is the expected one (or lower) but `prev_hash` is not the previous `chain_hash`; the first record of a stream has `seq` `"0"` but no genesis `prev_hash` and no restart; a restart's `anchor_hash` matches neither the previous segment's last `chain_hash` nor genesis. |
| `seq_mismatch` | error | invalid | `seq` contradicts the link: it repeats or goes backwards, or `prev_hash` links to the predecessor but `seq` skips ahead (a record cannot be missing between two linked records; this is what deleting a record and re-sealing its successor looks like). |
| `signature_invalid` | error | invalid | Signature present but malformed or not verifying with the given key; or, when signatures are required, a record without one. |
| `profile_invalid` | error | invalid | The payload violates the schema of a known profile. A class of its own, separate from `schema_invalid`, so that a defect in the shared envelope and a payload that breaks the producer's profile stay distinguishable. |
| `seq_gap` | notice | unknown | `seq` is ahead of the expected value and `prev_hash` does not link to the last checked record of the stream: records are missing from the journal before this one (also at the start of a journal that begins in the middle of a stream). |
| `outside_scope` | notice | outside_scope | The record names another format or major version and was not checked. |
| `profile_unknown` | notice | (unchanged) | The record's profile is not known to this verifier; its payload was not checked against a profile. |
| `restart` | notice | (unchanged) | A record with `chain_restart: true`. Reported separately so that breaks and gaps stay distinguishable from intended restarts. |
| `after_unknown` | notice | (unchanged) | The record links correctly (`prev_hash` and `seq`, or `anchor_hash` of a restart) to a record in state `unknown`. It is valid relative to that record, not relative to the start of the stream. Only the record directly after an `unknown` record carries it. |
| `legacy_integer_seq` | notice | (unchanged) | `seq` is a JSON number (format 0.1). Accepted during 0.x; `schema_invalid` from 1.0 (3.1). |
| `number_precision` | notice | (unchanged) | `payload` contains an integer literal outside ±2^53 (no fraction, no exponent). The hashes are still well defined, but the value was rounded by canonicalisation; see 4.3. |

Severities are fixed per class: a finding has severity error exactly when
its class makes the record `invalid`. Whether `seq_gap`, `outside_scope` or
`profile_unknown` fail the journal is decided by the verdict (6.4), not by
a severity. These classes are verifier output. They are not reason codes: a producer
never writes them into a record, and `docs/REASON_CODES.md` does not list
them.

### 6.3 Algorithm

For each non-empty line, in file order:

1. **Parse.** If the line is not a JSON object under the reading rules of
   section 2 (valid UTF-8, unique member names, no unpaired surrogate, at
   most 64 levels, nothing but white space around the object), report
   `schema_invalid`; the record is `invalid` and takes no part in steps 2
   to 8.
2. **Scope.** If `schema` is a string of the form `<name>/<major>` other
   than `trail.evidence/1`, report `outside_scope`; the record is
   `outside_scope`. It takes no part in steps 3 to 8: it is not hashed, does
   not change any stream state and is not counted as signed or unsigned. A
   line without `schema`, or with any other `schema` value, stays in scope
   and fails step 4.
3. **Decode.** If a typed member has the wrong JSON type (for example a
   non-object `producer`, a non-string `profile`) or an unknown member
   appears in the top-level object or in a typed sub-object, report
   `schema_invalid` and **skip the record**: it is `invalid` and takes no
   part in steps 4 to 8. `seq` is not checked here.
4. **Schema.** Report every other structural violation (3.1 to 3.4, 4.2
   invariants) as one `schema_invalid` finding, including a missing, `null`
   or malformed `seq`. A `seq` written as a JSON number of the allowed form
   is reported as `legacy_integer_seq`.
5. **Hashes.** Recompute `content_hash` over JCS(`payload`). Build the core
   from the record's own members, replacing `content_hash` with the
   recomputed value, and recompute `chain_hash`. Report each difference as
   `hash_mismatch`. If `payload` contains integer literals outside ±2^53,
   report one `number_precision` notice for the record.
6. **Profile.** Without `profile` the profile state is `none`. A malformed
   `profile` was reported in step 4; the profile state is `invalid`. If the
   verifier knows the profile, check `payload` against its schema: a
   violation is `profile_invalid` and the profile state `invalid`, else
   `valid`. If it does not know the profile, report `profile_unknown`; the
   profile state is `outside_scope`.
7. **Chain.** Only a record with a **position** takes part: a non-empty
   string `stream_id` and a usable `seq`. A record without one (for example
   a missing `seq`) is `invalid` from step 4 and does not change the stream
   state, so the next record of the stream is judged against the last record
   that had a position. Otherwise look up the stream:
   - The record has `chain_restart: true` and an `anchor_hash`: report
     `restart`. If the stream was seen before and `anchor_hash` is neither
     its `last_chain_hash` nor genesis, report `chain_break`. If it equals
     the `last_chain_hash` of an `unknown` record, report `after_unknown`.
   - Otherwise the expected predecessor is `last_chain_hash` and the
     expected seq `last_seq + 1`; for a stream not seen before they are the
     genesis hash and `0`. The record is **linked** when `prev_hash` equals
     the expected predecessor. Then:

     | linked | `seq` compared with the expected seq | Result |
     |---|---|---|
     | yes | equal | no finding (`after_unknown` if the previous record is `unknown`) |
     | yes | higher | `seq_mismatch` |
     | yes | lower (repeated or backwards) | `seq_mismatch` |
     | no | equal | `chain_break` |
     | no | higher | `seq_gap`: the predecessor is not in the journal |
     | no | lower | `chain_break` and `seq_mismatch` |

   Then set `last_seq` to the record's `seq`, `last_chain_hash` to its
   **declared** `chain_hash`, so that later records are judged against what
   they were actually linked to, and remember the record's state (step 9)
   for `after_unknown`.
8. **Signature.** For every record that passed step 3: if a public key is
   given and the record carries a signature, verify it per section 5;
   failure is `signature_invalid`. If a public key is given, the verifier
   was told to require signatures, and the record has none, report
   `signature_invalid`. Without a key, signatures are counted but not
   checked.
9. **State.** `invalid` if the record has a finding of an error class,
   otherwise `unknown` if it has `seq_gap`, otherwise `valid`
   (`outside_scope` was decided in step 2).

Verification does not stop at the first error.

### 6.4 Verdict, options and exit codes

The journal gets one of three verdicts, from the states of its records:

| Verdict | Condition | Exit code of `verify` |
|---|---|---|
| `valid` | Every record is `valid`. | 0 |
| `invalid` | At least one record is `invalid`. | 1 |
| `incomplete` | No record is `invalid`, but at least one is `unknown` or `outside_scope`; or the journal has no record at all. | 3 |
| none | The journal cannot be read to its end. | 2 |

`incomplete` is a failure by default. A record removed from the middle of a
journal, or moved out of scope by changing its `schema`, makes the journal
`incomplete`, not `invalid` (6.6); accepting `incomplete` silently would let
such a journal pass.

A journal **without a record** (an empty file, or only blank lines) is
`incomplete`: it shows nothing about any record, and a producer that writes
nothing must not pass a check. It is not `invalid`, because no record in it
is wrong. `allow incomplete` does not accept it (exit code 3).

A journal that **cannot be read** to its end (a missing file, a directory, a
file without read permission, an error while reading) gets **no verdict**
and no report: `verify` exits with 2 and names the error on standard error.
A verifier MUST NOT judge the part it could read before the error. Exit code
2 is otherwise reserved for usage errors.

Two options change what passes, never a record state:

- **allow incomplete** (`--allow-incomplete` on the command line,
  `AllowIncomplete` in Go, `allow_incomplete` in Python, `allowIncomplete`
  in JavaScript, a checkbox on the browser page, off by default, and the
  input `allow-incomplete` of the GitHub Action, default `false`): the
  verdict stays `incomplete`, but the journal passes (exit code 0). It is
  meant for journals that are known to be incomplete: a rotated log that
  starts in the middle of a stream, an excerpt, a file that interleaves
  records of another format. It is not meant for a journal that is supposed
  to be complete, because it also accepts a deleted record.
- **require known profiles** (`--require-known-profiles`,
  `RequireKnownProfiles`, `require_known_profiles`, `requireKnownProfiles`,
  a checkbox, the Action input `require-known-profiles`; off by default): a
  record whose profile state is `outside_scope` counts like a record that is
  not checked, so the verdict becomes `incomplete` (exit code 3).
  `allow incomplete` does not accept this case: whoever requires known
  profiles wants them checked even in an incomplete journal.

Without that option an unknown profile does not affect the verdict: the
core of the record was checked, only its payload was not evaluated against
a profile. A verifier that does not know a producer's profile can therefore
still verify that producer's journals; the notice `profile_unknown` and the
profile state `outside_scope` say what was not checked.

The verdict and the options determine the report member `ok` (the journal
passes) and the exit code:

```
unknown_profiles = require_known_profiles and some profile state is outside_scope
empty   = the journal has no record
verdict = invalid     if some state is invalid
        = incomplete  else if empty, or some state is unknown or outside_scope,
                      or unknown_profiles
        = valid       otherwise
ok      = verdict == valid
          or (verdict == incomplete and allow_incomplete
              and not unknown_profiles and not empty)
exit    = 0 if ok, else 1 if verdict == invalid, else 3
          (2 and no verdict when the journal cannot be read to its end)
```

### 6.5 Report

The report SHOULD contain: `verdict`, `ok`, the options
`allow_incomplete` and `require_known_profiles`, the number of records,
errors, notices and restarts, the number of signed records and of verified
signatures, `states` (records per state), `profile_states` (records per
profile state), a summary per stream (`stream_id`, records with a position,
first and last `seq`, `last_chain_hash`, restarts), `results` (per record:
index, line, `stream_id` and `seq` when known, `state`, `profile` when
present, `profile_state`), and the findings with index, line, `stream_id`,
`seq`, class, severity and message. Reports write `seq` values as decimal
strings, like the records.

### 6.6 What verification does and does not prove

- A record cannot be altered, reordered or removed and its successor
  re-sealed without a `hash_mismatch`, `chain_break` or `seq_mismatch`.
- A record removed from a journal without touching the others, or a record
  whose `schema` was changed to another format, leaves the next record
  `unknown` (`seq_gap`), not `invalid`, and the journal `incomplete`, which
  fails unless incomplete journals are allowed (6.4). With that option a
  passing journal means that no record is provably wrong, not that the
  journal is complete.
- Records removed from the **end** of a journal leave no trace: the
  remaining records still link to each other, and the journal is `valid`
  (fixture `tail-truncated.jsonl`). Only a `chain_hash` or a record count
  kept outside the journal (an anchor, a signed note of the latest record)
  shows that records are missing at the end.
- An unsigned journal can be rewritten wholesale by whoever controls the
  file, and so can every record after a given one. Signatures bind the
  chain to a key; anchoring the latest `chain_hash` elsewhere (`anchor`)
  binds it to a point in time. Neither is implied by a passing verification
  without keys.
- A public key alone checks only the signatures that are present. Without
  `require signatures`, a journal whose signatures were all removed is
  `valid` (fixture `signatures-stripped.jsonl`).
- `signature`, `correlation_id`, `job_id`, `decision_id`, `context`,
  `redaction` and `anchor` are not hashed (4.1). They can be changed, added
  or removed without any finding (fixture `unhashed-members-changed.jsonl`).
  `redaction` states which payload members were masked before hashing, and
  nothing protects that statement; `anchor` points to an anchoring that the
  verifier does not check. Evidence-relevant facts belong in `payload`.
- Two members with the same name in one object, at any depth, make the
  record `schema_invalid` (section 2), so a program that reads the journal
  later cannot be shown a member value other than the one that was hashed,
  whichever of two values its parser keeps.
- A journal without a record never passes, and a journal that cannot be
  read to its end gets no verdict (6.4).
- A `valid` record after an `unknown` one is valid relative to that record:
  nothing in the journal shows what came before it.
- A profile state `valid` says that the payload has the members and types
  the profile requires. It does not say that the values are true, and a
  verifier that does not know the profile says nothing about the payload.
- Verification says nothing about whether `payload` is true, whether
  `time.recorded_at` is accurate (see `time.source`), or whether the policy
  named in `policy` was the right one.

## 7. Test vectors

`testdata/vectors.json` is produced by the Go reference implementation and
contains, per vector, the record and the expected payload JCS,
`content_hash`, core JCS and `chain_hash`, and the state and profile state
of the record on its own. Every implementation MUST reproduce these values
byte for byte. `testdata/streams/` holds journals with the findings and the
state and profile state of every record a verifier MUST report, and the
verdict and exit code, some of them with the options of 6.4. `profiles/` holds the registered profiles with
their example payloads and journals. The signing key in `testdata/keys/` is
a published test key (RFC 8032 test vector 1). Section 10 turns these files
into the conformance criterion.

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
  authenticated client. The broker's producer defines the payload as its own
  profile and registers it (3.4); this repository does not define it.
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
chaining rules MUST NOT change. Anything else is `trail.evidence/2`. This
rule binds from 1.0 on. Until then the format is a draft and versions 0.x
of this repository may change it; each such change is listed in
`CHANGELOG.md`.

Format 0.2 changed, compared with 0.1:

- `seq` is a decimal string (3.1). A JSON number is still accepted during
  0.x with the notice `legacy_integer_seq`; from 1.0 it is `schema_invalid`.
- Every record has a state and a profile state (6.1), every journal a
  verdict `valid`, `invalid` or `incomplete` (6.4). `incomplete` fails with
  exit code 3 unless `allow incomplete` is set; `require known profiles`
  makes unknown profiles count as incomplete. Reports carry `verdict`,
  `allow_incomplete`, `require_known_profiles`, `states`, `profile_states`
  and `results`, and write `seq` as a decimal string.
- The optional core member `profile` (3.2, 3.4).
- New finding classes `seq_mismatch`, `profile_invalid`, `outside_scope`,
  `profile_unknown`, `after_unknown`, `legacy_integer_seq`. `seq_gap` is a
  notice that makes a record `unknown` and the journal `incomplete`; a
  skipped, repeated or backwards `seq` on a linked record is
  `seq_mismatch`. A journal that starts in the middle of a stream is
  `unknown` at its first record and `incomplete` instead of `invalid`
  (`chain_break`).
- `schema_invalid` is reported once per record.
- A record whose `schema` names another format or major version is
  `outside_scope` instead of `schema_invalid`.

Changes after 0.2.1 (not yet released) that make explicit how a journal is
read. No hash changes, and a journal that keeps these rules verifies as
before:

- The reading rules of section 2: a record line is valid UTF-8, has unique
  member names at every depth, no unpaired surrogate, at most 64 levels of
  nesting and nothing but JSON white space around the object; only JSON
  white space makes a line blank. Before, the Go, Python and JavaScript
  verifiers handled such lines differently, and some accepted them.
- A journal without a record is `incomplete` and never passes, also with
  `allow incomplete`; before, it was `valid`. A journal that cannot be read
  to its end gets no verdict and exit code 2 (6.4).

Profiles have their own major versions (3.4). A new minor version of a
profile changes neither the record format nor the profile identifier.

## 10. Conformance

The test data in this repository is the conformance suite for
`trail.evidence/1`. Conformance is defined by these files, not by a
description of the algorithm.

**Producer conformance.** An implementation that seals records conforms
when, for every vector in `testdata/vectors.json`, it computes
`expected_payload_jcs`, `expected_content_hash`, `expected_core_jcs` and
`expected_chain_hash` byte for byte from the vector's `record`.

**Verifier conformance.** An implementation that verifies records conforms
when it meets producer conformance and in addition

1. for every vector, reports the notice classes in `expected_notices` for
   the record on its own, no error for vectors with `expected_valid: true`,
   the class `expected_error` for vectors with `expected_valid: false`, and
   the record's state on its own (`expected_state`: `valid`, `invalid` or
   `outside_scope`) and profile state (`expected_profile_state`);
2. for every case in `testdata/streams/expected.json`, given the case's
   `pubkey`, `require_signatures`, `allow_incomplete` and
   `require_known_profiles`, reaches exactly the listed `verdict`, `ok`,
   `exit_code`, `records` and `restarts`, gives every record exactly the state in
   `states` and the profile state in `profile_states` (by index), and
   reports exactly the listed distinct (`index`, `class`) pairs in the
   listed order of first occurrence. Reporting the same pair more than once
   is allowed (one `hash_mismatch` each for `content_hash` and
   `chain_hash`); an additional or missing pair is not;
3. knows every profile in `profiles/` at the suite revision: it accepts every
   payload under `valid` and rejects every payload under `invalid` in each
   `<major>.examples.json`, and verifies each `<major>.journal.jsonl` with
   `require known profiles` to the verdict `valid`, every record with
   profile state `valid`. A
   verifier that does not know a profile still conforms for everything else,
   but MUST report that profile as `profile_unknown`;
4. for a journal it cannot read (a directory, a missing file, a file
   without read permission), exits with 2 and prints no report, also with
   `allow incomplete` (6.4).

Three cases are named here because implementations most often get them
wrong, and all are mandatory. The first two are part of the vector
`jcs-edge-cases`:

- **Integers beyond 2^53.** The payload literal `9007199254740993`
  (2^53 + 1) canonicalises to `9007199254740992`, and a verifier reports
  `number_precision` for the record (4.3, 6.1). An implementation that keeps
  the exact integer produces a different `content_hash`; one that rejects
  the record fails the vector.
- **Member order.** Members are sorted by UTF-16 code units, not by code
  points or UTF-8 bytes: `"🚀"` (U+1F680, surrogates D83D DE80) sorts before
  `"！"` (U+FF01), and `"Z"` before `"a"`, `"ä"` and `"€"`.
- **seq arithmetic.** `seq` is compared as an integer of arbitrary size
  (fixtures `seq-decimal.jsonl` and `seq-decimal-mismatch.jsonl`):
  "9007199254740993" follows "9007199254740992" and repeating it is a
  `seq_mismatch`, which comparing doubles cannot see; "0" after
  "18446744073709551615" is a `seq_mismatch`, which 64-bit arithmetic that
  wraps around does not see.

A claim of conformance names the suite revision it was tested against: a
release tag or a commit of this repository. New vectors and fixtures within
`trail.evidence/1` only add cases (section 9); an implementation that was
conformant stays conformant for every case that existed at its revision.

`scripts/conformance.sh <command>` runs a verifier against the suite and
reports each vector and fixture. It is informative: it expects the command
to offer `hash <record.json>` (with `state` and `profile_state` in its
output) and `verify <journal.jsonl> [--pubkey <file>]
[--require-signatures] [--allow-incomplete] [--require-known-profiles]
--json` (with `verdict` and `results`, exit codes 0, 1 and 3 as in 6.4, and 2
without a report for a journal it cannot read)
with the output members of the reference CLI (see README.md). The criterion is the data above, not the script; an
implementation without a CLI can check the same files in its own tests, as
the Go, Python and JavaScript implementations here do.
