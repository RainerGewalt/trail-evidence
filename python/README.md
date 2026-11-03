# trail-evidence (Python)

Reference implementation of the Trail Evidence Record contract
(`trail.evidence/1`, format 0.2) in Python: seal, sign and verify
hash-chained JSON evidence records, and check payloads against registered
profiles. Standard library only (RFC 8785 canonicalisation and Ed25519
verification are implemented in the package, the profile registry ships as
package data), Python 3.9 or newer.

A Trail Evidence Record is one JSON object that describes one event a system
wants to be able to prove later, chained to the previous record by a hash and
optionally signed. A journal is JSON Lines, one record per line. The verifier
needs nothing but the file, and a public key if signatures are to be checked.

```bash
pip install trail-evidence

trail-evidence-py verify journal.jsonl
trail-evidence-py verify journal.jsonl --pubkey <64 hex chars or file> --require-signatures
trail-evidence-py verify journal.jsonl --allow-incomplete
trail-evidence-py verify journal.jsonl --json
trail-evidence-py hash record.json
trail-evidence-py profiles
```

Every record gets a state: `valid`, `invalid`, `unknown` (its predecessor is
not in the file) or `outside_scope` (another format or major version), and a
profile state. The journal gets the verdict `valid` (exit code 0), `invalid`
(1) or `incomplete` (3: no record invalid, but one unknown or outside the
scope). `--allow-incomplete` accepts incomplete journals (exit code 0), for
logs known to be incomplete such as rotated ones; `--require-known-profiles`
counts records with an unknown profile as incomplete. Exit code 2 is a usage
or I/O error. `python -m trail_evidence` is the same CLI.

```python
from trail_evidence import seal, sign, verify_stream, GENESIS_HASH, NO_POLICY

record = {
    "producer": {"kind": "ml-pipeline", "id": "run-7f3a", "version": "1.4.0"},
    "stream_id": "run-7f3a", "seq": "0", "event_type": "ml.run.completed",
    "time": {"recorded_at": "2026-11-02T09:42:10.000Z", "source": "system"},
    "actor": {"auth": "operator-token", "id": "ml-ops"},
    "policy": NO_POLICY,
    "payload": {"metrics": {"dice": "0.9132"}},
}
seal(record, GENESIS_HASH)
sign(record, seed_bytes)            # optional
with open("journal.jsonl") as fh:
    report = verify_stream(fh, public_key_bytes)
print(report.summary(), report.verdict, report.exit_code())
print([(r.index, r.state, r.profile_state) for r in report.results])
```

`seq` is a decimal string (`"0"` to `"18446744073709551615"`); `seal()`
also accepts an int and writes the string.

The pure Python Ed25519 code is written for clarity and test use, not for
throughput or side-channel resistance. Producers that sign at volume should
use a vetted library (for example `cryptography`) and keep this module for
verification in tooling and tests.

The Go reference implementation, the browser verifier, the specification
(`SPEC.md`), the JSON Schema and the test vectors live in the repository:
<https://github.com/RainerGewalt/trail-evidence>. Go, Python and the
browser verifier produce identical reports; `scripts/crosscheck.sh`
enforces that.

Development, from a checkout:

```bash
cd python
python3 -m unittest discover -s tests -v
python3 -m trail_evidence verify ../examples/transfer-worker.jsonl
python3 -m trail_evidence check-vectors ../testdata/vectors.json
```
