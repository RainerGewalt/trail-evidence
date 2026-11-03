# Contributing

Thanks for taking a look. This repository holds a format specification and
two reference implementations that must agree with each other, so changes
come with a few rules.

## Ground rules

- `SPEC.md` is normative. The implementations follow it; if they disagree
  with the text, the text wins and the code is fixed, unless the change is
  to the spec itself.
- Go, Python and the browser verifier (`web/verify.js`) must stay
  byte-identical on every vector. Any change to hashing, canonicalisation
  or the core member set needs all three implementations, regenerated
  vectors, and a passing `scripts/crosscheck.sh`.
- Within `trail.evidence/1`, only additive changes are allowed: new
  optional members, new enumeration values with a documented meaning. Never
  change what is hashed. Anything else is a new major version.
- Keep the language plain. Describe mechanisms and limits, not benefits.

## Workflow

1. Open an issue for format changes before writing code, so the discussion
   happens on the spec text.
2. Make the change, including `SPEC.md`, the JSON Schema, both
   implementations and `CHANGELOG.md` ("Unreleased").
3. Regenerate the data: `cd go && go run ./internal/gentestdata -root ..`.
4. Run everything:
   ```bash
   cd go && gofmt -l . && go vet ./... && go test ./... && cd ..
   cd python && python3 -m unittest discover -s tests && cd ..
   node web/test/run.mjs
   scripts/crosscheck.sh            # includes scripts/conformance.sh for all three
   scripts/validate_schema.py --vectors testdata/vectors.json examples/*.jsonl examples/tampered/*.jsonl
   scripts/reason_codes.py --check
   ```
5. Commit with a conventional subject: `type(scope): subject`, for example
   `fix(python): reject padded base64url signatures`. Scopes in use: `spec`,
   `schema`, `go`, `python`, `web`, `vectors`, `examples`, `action`, `ci`,
   `release`, `docs`.

New reason codes go into `schema/reason-codes.json`; run
`scripts/reason_codes.py --write` to regenerate the tables in
`docs/REASON_CODES.md`. A code keeps its meaning once it is in the catalog.

## Requirements

- Go 1.22 or newer.
- Python 3.9 or newer; the package has no runtime dependencies. The
  `jsonschema` package is optional for `scripts/validate_schema.py`.
- Node 18 or newer for `web/test/run.mjs` and the crosscheck. The page
  itself has no build step and no dependencies.

## Security

The key under `testdata/keys/` is a published test key (RFC 8032 test
vector 1). Never add a real private key, token or credential to this
repository. If you find a problem in the hashing or signature logic, please
report it privately to the maintainer before opening a public issue.
