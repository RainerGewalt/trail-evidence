# Contributing

Thanks for taking a look. This repository holds a format specification and
two reference implementations that must agree with each other, so changes
come with a few rules.

## Ground rules

- `SPEC.md` is normative. The implementations follow it; if they disagree
  with the text, the text wins and the code is fixed, unless the change is
  to the spec itself.
- Go and Python must stay byte-identical on every vector. Any change to
  hashing, canonicalisation or the core member set needs both
  implementations, regenerated vectors, and a passing
  `scripts/crosscheck.sh`.
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
   scripts/crosscheck.sh
   scripts/validate_schema.py --vectors testdata/vectors.json examples/*.jsonl
   ```
5. Commit with a conventional subject: `type(scope): subject`, for example
   `fix(python): reject padded base64url signatures`. Scopes in use: `spec`,
   `schema`, `go`, `python`, `vectors`, `examples`, `ci`, `docs`.

## Requirements

- Go 1.22 or newer.
- Python 3.9 or newer; the package has no runtime dependencies. The
  `jsonschema` package is optional for `scripts/validate_schema.py`.

## Security

The key under `testdata/keys/` is a published test key (RFC 8032 test
vector 1). Never add a real private key, token or credential to this
repository. If you find a problem in the hashing or signature logic, please
report it privately to the maintainer before opening a public issue.
