# trail-evidence

**Status: v0.1 draft. The format may still change before 1.0.**

A Trail Evidence Record is one JSON object that describes one event a system
wants to be able to prove later, chained to the previous record by a hash
and optionally signed. This repository is the shared contract for that
record: the specification, a JSON Schema, test vectors, and reference
implementations in Go and Python that reproduce each other byte for byte.

## Why one contract

The systems around the Trail ecosystem each keep some kind of evidence:
a transfer worker writes a hash-chained job journal, a source bridge emits
envelopes with an audit block, a broker logs access decisions, an ML
pipeline stores run records with recipe and data fingerprints. Today each
one has its own field names, its own hash encoding and its own idea of
canonical JSON. Four formats mean four verifiers, four mappings in every
downstream tool and four ways to be subtly incompatible.

A single record shape removes that. Whatever produced the record, one
verifier recomputes the hashes, follows the chain, checks the signature and
says what it found. `producer.kind` says where the record came from;
`event_type` says what happened; `payload` carries the domain data
unchanged.

Producers that this contract is written for: `transfer-worker`
(TrailTransfer), `source-bridge` (TrailSource), `broker` (TrailMQ, via an
export adapter), `ml-pipeline`, `persistence`, and `other`. None of them
emits this format yet; the mapping notes in `SPEC.md` describe the intended
migration for each.

## 60-second example

```bash
git clone https://github.com/RainerGewalt/trail-evidence
cd trail-evidence/go && go build -o ../trail-evidence ./cmd/trail-evidence && cd ..

./trail-evidence verify examples/transfer-worker.jsonl
# OK: 4 record(s) in 1 stream(s), hash chain intact

./trail-evidence verify testdata/streams/seq-gap.jsonl
# FAIL: 3 record(s) in 1 stream(s), 1 error(s)
#   error   seq_gap           record #2 (line 3, stream "s", seq 3): seq 3, expected 2

./trail-evidence verify testdata/streams/signed.jsonl \
    --pubkey testdata/keys/test-ed25519.pub --require-signatures
# OK: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), 3 signature(s) verified
```

The same with Python (3.9 or newer, standard library only):

```bash
cd python && python3 -m trail_evidence verify ../examples/transfer-worker.jsonl
```

Or without installing anything: see [Verify in the browser](#verify-in-the-browser).

A journal is JSON Lines: one record per line. The verifier needs nothing but
the file, and a public key if you want signatures checked.

## Verify in the browser

`web/` is a static page that verifies a journal in the browser. Drop a
`.jsonl` file on it, optionally paste the producer's Ed25519 public key (hex,
base64url or PEM), and read the verdict, the counts per finding class, the
findings with line, stream and `seq`, and the last `chain_hash` of every
stream. Nothing is uploaded: the page is plain HTML, CSS and JavaScript
without a build step or external scripts, hashing uses the browser's
WebCrypto, and the only request it makes is for the bundled example journal.

Once GitHub Pages is enabled for this repository (Settings, Pages, Source:
"GitHub Actions"), `.github/workflows/pages.yml` publishes `web/` on every
push to `main` that touches it, at

```
https://rainergewalt.github.io/trail-evidence/
```

Until then, open `web/index.html` from a local checkout or serve the
directory with any static file server (`python3 -m http.server -d web`).

The page uses the same algorithm as Go and Python: `web/verify.js`
implements RFC 8785, the hashing, the chain and signature checks, and
`node web/test/run.mjs` (Node 18 or newer) checks it against
`testdata/vectors.json`, `testdata/streams/expected.json` and the examples;
`scripts/crosscheck.sh` compares all three verifiers on every fixture.
Signature checks need Ed25519 in the browser's WebCrypto (current Chrome,
Firefox and Safari); where that is missing, the page reports signatures as
not checked rather than as failed.

## The record

```json
{
  "schema": "trail.evidence/1",
  "producer": {"kind": "transfer-worker", "id": "worker-01", "version": "0.3.1"},
  "stream_id": "worker-01",
  "seq": 7,
  "prev_hash": "sha256:…",
  "event_type": "transfer.job.result",
  "time": {"recorded_at": "2026-11-02T06:00:12.500Z", "source": "system"},
  "actor": {"auth": "self-declared", "id": "alice"},
  "policy": {"id": "archive-policy", "version": "7", "hash": "sha256:…", "status": "approved", "kind": "transfer-policy"},
  "job_id": "job-1001",
  "payload": {"action": "copy", "source": "sftp://…", "target": "s3://…", "status": "ok"},
  "content_hash": "sha256:…",
  "chain_hash": "sha256:…",
  "signature": {"alg": "ed25519", "key_id": "ed25519:…", "sig": "…"}
}
```

| Member | Hashed | Purpose |
|---|---|---|
| `schema` | core | `trail.evidence/1`; major version in the name |
| `producer` | core | `kind`, `id`, `version` of the producing instance |
| `stream_id`, `seq`, `prev_hash` | core | one hash chain per stream; `seq` counts by 1, `prev_hash` links to the previous `chain_hash` |
| `event_type` | core | `<domain>.<noun>.<verb>`, e.g. `mqtt.decision.deny` |
| `time` | core | `recorded_at` (sealing time, required), `occurred_at`, `read_at`, `source` |
| `actor` | core | `auth` class (`broker-authenticated`, `self-declared`, `operator-token`, `none`), `id`, `roles` |
| `policy` | core | `id`, `version`, `hash` of the rule or recipe that governed the event; `status`, `kind` |
| `payload` | via `content_hash` | the domain data, any JSON |
| `content_hash` | core | SHA-256 over the RFC 8785 canonical payload |
| `chain_hash` | — | SHA-256 over the canonical core; what the next record links to and what a signature covers |
| `chain_restart`, `anchor_hash` | core | mark a new segment and point at the last known hash of the old one |
| `signature` | no | Ed25519 over the `chain_hash` string, base64url |
| `correlation_id`, `job_id`, `decision_id` | no | cross references |
| `context` | no | informational; evidence-relevant facts belong in `payload` |
| `redaction` | no | which payload fields were masked before hashing, and how |
| `anchor` | no | where this `chain_hash` was anchored externally (`trailmq`, `tsa`, `worm`, `other`) |

Hashing: everything is SHA-256 over RFC 8785 (JCS) bytes, written as
`sha256:` plus 64 lowercase hex characters. Genesis `prev_hash` is 64
zeros. The full rules, the verification algorithm and the finding classes
(`hash_mismatch`, `chain_break`, `seq_gap`, `signature_invalid`,
`schema_invalid`, plus the notices `restart` and `number_precision`) are
in [SPEC.md](SPEC.md).

Numbers in `payload`: JCS applies ES6 number semantics, so every number is
an IEEE-754 double. Integers outside ±2^53 must be sent as strings, and
floats whose exact decimal form matters should be. The vector
`jcs-edge-cases` in `testdata/vectors.json` shows what happens otherwise:
`9007199254740993` canonicalises to `9007199254740992`, and `verify`
reports a `number_precision` notice for the record. The hashes stay well
defined; the value you meant is gone.

## What verification tells you

`verify` recomputes every hash and follows every link. A passing run means
no record in the file was altered, removed or reordered relative to the
others. It does not mean the payloads are true, that the clock was right
(`time.source` tells you what the producer knew about that), or that nobody
rewrote the whole file: for that you need signatures (`--pubkey`) or an
external anchor of the latest `chain_hash`. The spec lists these limits
explicitly.

## Repository layout

```
SPEC.md                         normative specification
schema/trail-evidence-1.schema.json   JSON Schema 2020-12
go/                             Go module github.com/RainerGewalt/trail-evidence/go
  evidence/                       package: Seal, Sign, VerifyRecord, VerifyStream
  cmd/trail-evidence/             CLI: verify, hash, vectors
python/trail_evidence/          Python package: seal, sign, verify_record, verify_stream
web/                            browser verifier (static page, GitHub Pages); verify.js + test/run.mjs
testdata/vectors.json           canonicalisation and hashing vectors (generated by Go)
testdata/streams/               journals with the findings a verifier must report
testdata/keys/                  the public TEST key used by signed vectors
examples/                       one verifiable journal per producer kind
scripts/crosscheck.sh           Go output must be reproduced by Python and JavaScript, verifiers must agree
scripts/validate_schema.py      JSON Schema validation of journals
```

## Using the libraries

Go:

```go
import "github.com/RainerGewalt/trail-evidence/go/evidence"

r := evidence.Record{
    Producer:  evidence.Producer{Kind: evidence.ProducerTransferWorker, ID: "worker-01", Version: "0.3.1"},
    StreamID:  "worker-01",
    Seq:       next,
    EventType: "transfer.job.result",
    Time:      evidence.Time{RecordedAt: now.UTC().Format("2006-01-02T15:04:05.000Z"), Source: evidence.TimeSourceSystem},
    Actor:     evidence.Actor{Auth: evidence.AuthSelfDeclared, ID: "alice"},
    Policy:    evidence.NoPolicy,
    Payload:   payloadJSON,
}
if err := evidence.Seal(&r, prevChainHash); err != nil { /* ... */ }
if err := evidence.Sign(&r, privateKey, ""); err != nil { /* ... */ }
line, _ := json.Marshal(&r) // append line + "\n" to the journal

rep := evidence.VerifyStream(file, evidence.Options{PublicKey: pub})
fmt.Println(rep.Summary())
```

Python:

```python
from trail_evidence import seal, sign, verify_stream, GENESIS_HASH, NO_POLICY

record = {
    "producer": {"kind": "ml-pipeline", "id": "run-7f3a", "version": "1.4.0"},
    "stream_id": "run-7f3a", "seq": 0, "event_type": "ml.run.completed",
    "time": {"recorded_at": "2026-11-02T09:42:10.000Z", "source": "system"},
    "actor": {"auth": "operator-token", "id": "ml-ops"},
    "policy": NO_POLICY,
    "payload": {"metrics": {"dice": "0.9132"}},
}
seal(record, GENESIS_HASH)
sign(record, seed_bytes)            # optional
with open("journal.jsonl") as fh:
    report = verify_stream(fh, public_key_bytes)
print(report.summary())
```

## Development

```bash
cd go && go build ./... && go test ./... && cd ..
cd python && python3 -m unittest discover -s tests && cd ..
node web/test/run.mjs
scripts/crosscheck.sh
scripts/validate_schema.py --vectors testdata/vectors.json examples/*.jsonl
```

Vectors, fixtures and examples are generated: edit
`go/internal/vectors/vectors.go`, run `cd go && go run ./internal/gentestdata
-root ..`, and commit the result. `go test` fails when the committed files
are out of date.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).

## License

Apache License 2.0, see [LICENSE](LICENSE). Copyright 2026 Florian Przybylak.
