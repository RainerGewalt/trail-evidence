# Changelog

All notable changes to this repository are documented here. The format
follows Keep a Changelog; versions follow Semantic Versioning once 1.0 is
tagged. Until then the record format is a draft and may change.

## Unreleased

## 0.2.2 - 2026-11-14

Fixes to how the verifiers read a journal and what they report. No hash
changes: a journal whose lines keep the reading rules below verifies as
before, and the journals of the TrailSource demo and interop runs give the
same verdicts as with 0.2.1. Releases 0.2.0 and 0.2.1 are affected by the
fixed behaviour in all three verifiers and in the GitHub Action.

### Fixed

- **Reading rules** (`SPEC.md` section 2). A record line is one JSON object:
  valid UTF-8, no member name twice in one object at any depth (compared
  after decoding escapes), no unpaired surrogate escape, at most 64 levels
  of nesting, and nothing but JSON white space around it; only JSON white
  space makes a line blank, and lines end at a line feed only. A line that
  breaks a rule is `schema_invalid`. Before, the Go, Python and JavaScript
  verifiers read such lines differently and could reach different verdicts
  on the same file, and some lines passed as valid. The Python CLI and the
  browser page now read journals as bytes and decode each line on its own,
  so a line that is not UTF-8 is one invalid record instead of an
  exception or a silently replaced character.
- **Empty journal.** A journal without a record (an empty file, or only
  blank lines) is `incomplete` and fails with exit code 3, also with
  `--allow-incomplete`. Before, it was `valid` with exit code 0.
- **Read errors.** A journal that cannot be read to its end (a directory, a
  missing or unreadable file, an error while reading) gets no verdict and no
  report: exit code 2 and one message. Before, the Go verifier and the
  Action reported a directory as a valid journal. Go: `Report.Err`.
- **Python** no longer ends with a traceback on bytes that are not UTF-8 or
  on deep nesting.
- **Browser page:** Enter on the example links loads the examples (it
  opened the file chooser); the "What this verdict covers" block is correct
  for an empty file, lines that are not a record, a single record and in
  singular and plural; the previous result is hidden when a check cannot
  run; the static text points to section 6.6 instead of 6.3 and no longer
  says that no record was removed.

### Changed

- The summary lines of the three verifiers say what was not checked:
  `signatures not checked (no key)`, `no record is signed`, the number of
  verified signatures whenever a key was given, unsigned records, and
  `with unknown profile (payload not checked)`. The JSON report is
  unchanged.
- The Action's job summary has a column "Signatures verified" ("not checked
  (no key)" without `pubkey`) and a line that says what the verdict does
  not cover.
- `SPEC.md` section 6.6 names records cut off at the end of a journal, the
  members that are not hashed (`redaction` among them), signatures removed
  without `require signatures`, and duplicate member names; README and the
  page say the same.
- Conformance: `testdata/streams/` has fixtures for every reading rule, for
  empty journals and for the documented limits; `scripts/conformance.sh`
  checks that a journal that cannot be read gets exit code 2 and no report
  (`SPEC.md` section 10, item 4); `scripts/crosscheck.sh` compares the
  summary lines of the three verifiers word for word.
- `web/test/browser.mjs` checks the page in headless Chrome (keyboard, file
  input, edge cases) and renews the README screenshots, which now show the
  coverage block.
- Release: the release page starts with a command to try and carries the
  CHANGELOG.md section of the tag as its notes (`scripts/release-notes.sh`,
  which fails when the section is missing); the stale sentence about PyPI
  "once it is set up" is gone. `release.yml` gives `contents: write` only to
  the jobs that create the release and push the module tag.
- CI tests Python 3.10 and 3.11 as well, the versions the package
  classifiers name.

### Since 0.2.1, already on main

- The browser page says what a verdict covers and what it does not (#8).
- README leads with the question and the browser verifier (#6).
- CI runs the Python matrix on ubuntu-24.04, so that Python 3.9 stays
  testable (#7).
- An evaluation report form, an honest support statement and a private
  security path in `SECURITY.md` (#4).

## 0.2.1 - 2026-11-07

A patch release for the reason-code catalog. No change to the record
format, the vectors or the verifiers.

### Changed

- README states the released version, the install paths and which
  producers emit the format today.
- README and docs corrected after a first-use check from a fresh clone:
  TrailSource 0.1.0 is released, the verify examples need a clone of the
  repository, `trail-evidence-py` has no `version` command, the Python
  example in `examples/README.md` uses the right path, and SPEC.md names
  0.2.0 as released.
- The browser verifier has an inline icon, so browsers no longer request a
  missing `favicon.ico`; the page still makes no request besides the two
  example journals.
- The PyPI upload in the release workflow is blocking: a failed upload fails
  the release run. 0.2.0 is on PyPI since 2026-11-03. `docs/RELEASING.md`
  said the opposite and is corrected.
- The Go CLI and the Python package report 0.2.1; a Go build from a
  checkout reports `0.3.0-dev`, the next release, as `docs/RELEASING.md`
  describes.

### Added

- Reason code `source.subscription_stalled` (error), additive: a source
  bridge saw neither data nor keep-alive within the agreed keep-alive
  window while the session still answered; it rebuilds the subscription
  and declares the missed interval with `common.gap`. TrailSource 0.1
  already emits it.
- `scripts/first-use.sh`: walks through the README from a fresh clone, or
  with `RELEASE=x.y.z` against the published tag, release archive,
  `go install`, PyPI and the browser verifier, and stops at the first step
  that does not behave as documented. Testing levels in `docs/TESTING.md`.

## 0.2.0 - 2026-11-03

Format 0.2 of `trail.evidence/1`. It decides two design questions for every
producer that builds on Trail Evidence, among them TrailMQ, whose decision
format is to become a profile of `trail.evidence/1`: `seq` is a decimal
string, and every record gets one of four states. The format stays a draft
(0.x).

### Breaking changes

- **`seq` is a decimal string**, `"0"` to `"18446744073709551615"`, matching
  `^(0|[1-9][0-9]*)$`, compared as an integer of arbitrary size. Producers
  write `"seq":"7"` instead of `"seq":7`. Transition: during 0.x a JSON
  number is still accepted and reported with the new notice
  `legacy_integer_seq`; from 1.0 it is `schema_invalid`. Hashes cover the
  member as written, so 0.1 journals keep verifying, but the same record
  with `"seq":"7"` has a different `chain_hash` than with `"seq":7`. Go:
  `Record.Seq` stays `uint64` and is encoded as a string (`json:"seq,string"`);
  Python: `seal()` writes an int `seq` as its decimal string.
- **Record states and verdict.** Every record is `valid`, `invalid`,
  `unknown` or `outside_scope` (SPEC.md 6.1); every journal gets the verdict
  `valid`, `invalid` or `incomplete` (6.4). `incomplete` (no invalid record,
  but an `unknown` or `outside_scope` one) fails by default with the new
  exit code 3; `invalid` keeps exit code 1. A journal that starts in the
  middle of a stream, or has a record missing, is now `incomplete` (first
  record after the gap `unknown`, `seq_gap` a notice) instead of failing
  with `chain_break` and `seq_gap` as errors.
- **Finding classes.** New error classes `seq_mismatch` (seq repeated,
  backwards, or skipping although `prev_hash` links to the predecessor;
  formerly part of `seq_gap`) and `profile_invalid`. New notices
  `outside_scope`, `profile_unknown`, `after_unknown`, `legacy_integer_seq`.
  `seq_gap` is a notice that makes a record `unknown`. `schema_invalid` is
  reported once per record, its message listing every problem.
- A record whose `schema` names another format or major version
  (`<name>/<major>`, for example `trail.evidence/2`) is `outside_scope`: not
  checked, not part of any chain, instead of `schema_invalid`.
- A record without a usable `seq` or `stream_id` takes no part in the chain
  checks; the next record of its stream is judged against the last record
  that had a position.
- JSON reports gained `verdict`, `allow_incomplete`,
  `require_known_profiles`, `states`, `profile_states` and `results`
  (state and profile state per record) and write `seq`, `first_seq` and
  `last_seq` as decimal strings. `trail-evidence hash` prints `state` and
  `profile_state`.
- Renamed fixtures and examples: the former `seq-gap.jsonl` (a record
  deleted and its successor re-sealed) is now `seq-mismatch.jsonl`;
  `seq-gap.jsonl` is a record deleted without re-sealing (`unknown`).

### Added

- Profiles: optional core member `profile` (`<name>/<major>`), the registry
  `profiles/<name>/<major>.schema.json` with `profiles/README.md` (how a
  producer submits a profile: schema, example payloads, journal), and the
  test profile `example.measurement/1` with examples and a journal. Profile
  schemas use a subset of JSON Schema (type, required, properties, items)
  and allow members they do not name, because minor versions only add
  members. Each record gets a profile state `none`, `valid`, `invalid` or
  `outside_scope`. The verifiers carry the registry: Go embeds it
  (`go:embed`), Python ships it as package data, the browser page loads
  `web/profiles.js`; `scripts/profiles.py --write` generates all three from
  `profiles/`, `--check` and each verifier's tests fail when they differ.
- `--allow-incomplete` (Go and Python CLI; `AllowIncomplete`,
  `allow_incomplete`, `allowIncomplete` in the APIs; a checkbox on the
  browser page, off by default; Action input `allow-incomplete`, default
  `false`) accepts the verdict `incomplete`, for journals known to be
  incomplete such as rotated logs.
- `--require-known-profiles` (likewise everywhere, Action input
  `require-known-profiles`, default `false`) counts records with an unknown
  profile as incomplete. Without it an unknown profile does not affect the
  verdict: the core was checked, only the payload was not evaluated against
  a profile.
- GitHub Action: output `verdict` is `valid`, `invalid` or `incomplete`; the
  step exits like the verifier (1 invalid, 3 incomplete); the job summary
  lists invalid, unknown and outside-scope records per journal.
- `trail-evidence profiles` and `trail-evidence-py profiles` list the known
  profiles. Go: `CheckRecord`, `Profiles`, `ProfileSchema`,
  `ValidateProfilePayload`; Python: `check_record`, `profiles`,
  `profile_schema`, `validate_payload`.
- Browser verifier: a table with the state and profile state of every record
  (colour, symbol and text), counters per state and per profile state, a
  filter for records that need attention, the verdict `incomplete` in its
  own non-green colour, and the two option checkboxes.
- Vectors for decimal `seq` beyond 2^53 and at 2^64 - 1, legacy integer
  `seq`, missing and malformed `seq`, and the profile cases; stream fixtures
  `seq-decimal`, `seq-decimal-mismatch`, `legacy-integer-seq`,
  `seq-missing`, `seq-malformed`, `seq-gap`, `journal-start`,
  `outside-scope`, `profile-valid`, `profile-states`, `profile-unknown` and
  `profile-tampered`, with the expected state and profile state of every
  record, the verdict and exit code, and variants with the options. Vectors
  carry `expected_state` and
  `expected_profile_state`.
- Tampered examples `seq-gap.jsonl` (record deleted) and `outside-scope.jsonl`
  (record moved out of scope), both `incomplete`: they fail by default and
  pass only with `--allow-incomplete`.
- PyPI upload through trusted publishing in `.github/workflows/release.yml`
  (job `pypi`, environment `pypi`). Until the pending publisher is set up on
  pypi.org (docs/RELEASING.md), the job reports why the upload failed and
  does not fail the release.
- `scripts/validate_schema.py` checks payloads against their profile schema
  with the full JSON Schema validator and skips records outside the scope.
- Reason codes, additive: `source.connection_established`,
  `source.connection_failed`, `source.connection_closed`,
  `source.node_changed` and `common.will_published`, taken from the
  connection records, the inventory diff and the health topic of
  TrailSource. No existing code changed its name or meaning.
- Reason code `source.certificate_rejected` (error), additive: a source
  bridge refused the source's certificate (trust list, validity,
  revocation, application URI or pin). The catalog now has 44 codes.

### Changed

- `scripts/crosscheck.sh` compares the complete reports of Go, Python and
  JavaScript (everything but the wording of messages) and their exit codes,
  with and without keys, `--allow-incomplete` and
  `--require-known-profiles`, including the profile journals.
  `scripts/conformance.sh` checks record states, verdicts and exit codes.
- JSON Schema: `seq` as decimal string (exact range by pattern) or legacy
  integer, member `profile`.
- The Python parser rejects `NaN` and `Infinity`, like Go and JavaScript.
- Python package and CLI version 0.2.0; a Go build from a checkout reports
  `0.2.0-dev`.

## 0.1.0 - 2026-11-03

First tagged draft of `trail.evidence/1`. The record format may still change
before 1.0; see the open design decisions in issue #1.

### Added

- Prebuilt binaries: `.goreleaser.yaml` builds `trail-evidence` for Linux,
  macOS and Windows on amd64 and arm64, archives with `LICENSE` and
  `SPEC.md`, and `checksums.txt`. `.github/workflows/release.yml` runs on
  tags `v*`: Go tests, GoReleaser, the Go module tag `go/v*` for
  `go install`, and the Python sdist and wheel as a workflow artifact.
  `docs/RELEASING.md` describes the steps, including the manual PyPI upload.
- `python/pyproject.toml` for the PyPI package `trail-evidence` 0.1.0
  (Apache-2.0, no dependencies, console script `trail-evidence-py`); CI builds
  the sdist and wheel and runs the installed script on every push.
- GitHub Action (`action.yml`, composite): inputs `journal`, `pubkey`,
  `require-signatures`, `version`; outputs `verdict`, `records`, `errors`;
  job summary and annotations per error finding.
  `.github/workflows/self-test.yml` runs it from the checkout on Linux, macOS
  and Windows against the examples and fixtures.
- Reason code catalog: `docs/REASON_CODES.md` and `schema/reason-codes.json`
  with 38 codes for `payload.reason_code` in the namespaces `transfer`,
  `mqtt`, `source`, `ml` and `common`, each with severity, meaning and
  example. `mqtt.*` mirrors the authorization reasons of a reference broker
  plus a generic `mqtt.allowed`; `schema/reason-codes.schema.json` and `scripts/reason_codes.py`
  check the catalog. Documentation only; verifiers do not check reason codes.
- `SPEC.md` section 10, Conformance: producer and verifier conformance
  defined by `testdata/vectors.json` and `testdata/streams/expected.json`,
  with the integer 2^53+1 and UTF-16 member order as named mandatory cases.
  `scripts/conformance.sh <command>` runs any verifier with the reference CLI
  interface against the suite; the crosscheck runs it for Go, Python and
  JavaScript. `web/test/run.mjs` gained `verify` and `hash` modes for this.
- `examples/tampered/`: one manipulated copy of the transfer-worker journal
  per error class (`hash_mismatch`, `chain_break`, `seq_gap`,
  `signature_invalid`) with `expected.json`, checked by the Go, Python and
  JavaScript tests and the crosscheck. The browser verifier offers "load a
  tampered example".
- README sections Install, GitHub Action, For producers (badge) and
  Conformance.

- `SPEC.md`: Trail Evidence Record v1 draft with canonicalisation (RFC 8785),
  hashing, chaining, restart, signature and verification rules, and the
  finding classes `hash_mismatch`, `chain_break`, `seq_gap`, `restart`,
  `signature_invalid`, `schema_invalid`, and the notice `number_precision`
  for payload integers outside ±2^53.
- `schema/trail-evidence-1.schema.json`: JSON Schema 2020-12 for the record.
- Go module `github.com/RainerGewalt/trail-evidence/go` with package
  `evidence` (`Seal`, `Sign`, `VerifyRecord`, `VerifyStream`) and the CLI
  `trail-evidence` (`verify`, `hash`, `vectors`).
- Python package `trail_evidence` (standard library only, Python 3.9+) with
  `seal`, `sign`, `verify_record`, `verify_stream` and the CLI
  `python -m trail_evidence`.
- `testdata/vectors.json` with ten vectors generated by the Go
  implementation and reproduced by Python; stream fixtures with expected
  findings; one example journal per producer kind.
- `scripts/crosscheck.sh` and `scripts/validate_schema.py`; GitHub Actions
  workflow running Go tests, Python tests, the crosscheck and schema
  validation.
- `web/`: browser verifier as a static page (HTML, CSS, vanilla JavaScript,
  no build step, no external scripts). `web/verify.js` implements RFC 8785,
  hashing, chain and Ed25519 signature checks on WebCrypto and runs in
  browsers and Node 18+; `web/test/run.mjs` checks it against the vectors,
  stream fixtures and examples, and `scripts/crosscheck.sh` compares it with
  Go and Python. `.github/workflows/pages.yml` publishes `web/` to GitHub
  Pages.

### Changed

- `trail-evidence version` reports the release version set at build time,
  or the module version for `go install` builds, instead of a fixed string.
- Python package version `0.1.0` (was `0.1.0.dev0`).
- Example journals use catalog reason codes: `mqtt.allowed`,
  `mqtt.acl_role_not_in_topic_scope`, and `transfer.source_not_found` on the
  failed transfer job. Their hashes changed accordingly; the vectors did not.
