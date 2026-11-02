# trail_evidence (Python)

Reference implementation of the Trail Evidence Record v1 contract in Python.
It depends on the standard library only: RFC 8785 canonicalisation and
Ed25519 verification are implemented in this package (`jcs.py`,
`ed25519.py`). Minimum Python version: 3.9.

```bash
cd python
python3 -m unittest discover -s tests -v
python3 -m trail_evidence verify ../examples/transfer-worker.jsonl
python3 -m trail_evidence verify ../testdata/streams/signed.jsonl \
    --pubkey ../testdata/keys/test-ed25519.pub --require-signatures
python3 -m trail_evidence hash record.json
python3 -m trail_evidence check-vectors ../testdata/vectors.json
```

The pure Python Ed25519 code is written for clarity and test use, not for
throughput or side-channel resistance. Producers that sign at volume should
use a vetted library (for example `cryptography`) and keep this module for
verification in tooling and tests.

See `../SPEC.md` for the record format and `../README.md` for the project.
