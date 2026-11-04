# Single entry point for the tests. docs/TESTING.md says what each layer
# proves and where it runs in CI.
#
#   make test               L1-L2 for Go, Python and JavaScript, plus tooling checks (offline)
#   make test-conformance   L3: the three verifiers against the vectors and each other
#   make test-web           L4: the browser page in headless Chrome
#   make first-use VERSION=<x.y.z> | REF=<git ref>
#                           L5: the published artifacts of a release, or a fresh clone of a ref

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c

GO     ?= go
NODE   ?= node
# The newest python3.x >= 3.9 on PATH; set PYTHON to choose another.
PYTHON ?= $(shell for c in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3; do \
            if command -v $$c >/dev/null 2>&1 && $$c -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then \
              echo $$c; break; fi; done)

# The journals CI validates against the JSON Schema (scripts/validate_schema.py).
SCHEMA_JOURNALS := examples/*.jsonl examples/tampered/*.jsonl profiles/*/*.journal.jsonl \
  testdata/streams/valid-chain.jsonl testdata/streams/restart.jsonl testdata/streams/signed.jsonl \
  testdata/streams/multi-stream.jsonl testdata/streams/seq-decimal.jsonl testdata/streams/legacy-integer-seq.jsonl \
  testdata/streams/seq-gap.jsonl testdata/streams/journal-start.jsonl testdata/streams/outside-scope.jsonl \
  testdata/streams/profile-valid.jsonl testdata/streams/profile-unknown.jsonl

.PHONY: help test test-go test-python test-js test-tooling test-schema test-conformance test-web \
        test-all first-use check-python clean

help:
	@sed -n '1,/^$$/p' Makefile | sed 's/^# \{0,1\}//'

## L1-L2 and tooling: offline, no network, under 60 s
test: test-go test-python test-js test-tooling

test-go:
	cd go && $(GO) test -race -shuffle=on ./...

# The Python unit tests, and the CLI from the checkout as README.md documents it.
test-python: check-python
	cd python && $(PYTHON) -m unittest discover -s tests
	cd python && $(PYTHON) -m trail_evidence verify ../examples/transfer-worker.jsonl
	cd python && $(PYTHON) -m trail_evidence verify ../testdata/streams/signed.jsonl --pubkey ../testdata/keys/test-ed25519.pub --require-signatures
	cd python && $(PYTHON) -m trail_evidence verify ../profiles/example.measurement/1.journal.jsonl --require-known-profiles

# web/verify.js in Node, and its report mode on the same journals.
test-js:
	$(NODE) web/test/run.mjs
	$(NODE) web/test/run.mjs report examples/transfer-worker.jsonl >/dev/null
	$(NODE) web/test/run.mjs report testdata/streams/signed.jsonl --pubkey testdata/keys/test-ed25519.pub --require-signatures >/dev/null
	$(NODE) web/test/run.mjs report profiles/example.measurement/1.journal.jsonl --require-known-profiles >/dev/null

# Checks on the repository's own data, scripts and generated files.
test-tooling: check-python
	test -z "$$(cd go && gofmt -l .)" || { echo "gofmt needed:"; cd go && gofmt -l .; exit 1; }
	cd go && $(GO) vet ./...
	cd go && $(GO) run ./internal/gentestdata -root .. -check
	$(PYTHON) scripts/profiles.py --check
	$(PYTHON) scripts/reason_codes.py --check
	$(PYTHON) scripts/validate_schema.py --vectors testdata/vectors.json $(SCHEMA_JOURNALS)
	for f in scripts/*.sh; do bash -n "$$f"; done

# The schema files against their metaschema, with a full JSON Schema
# validator. Needs: pip install "jsonschema>=4.18" check-jsonschema
test-schema:
	check-jsonschema --check-metaschema schema/trail-evidence-1.schema.json profiles/*/*.schema.json
	check-jsonschema --check-metaschema schema/reason-codes.schema.json
	check-jsonschema --schemafile schema/reason-codes.schema.json schema/reason-codes.json

## L3: Go, Python and JavaScript reproduce every vector, produce identical
## reports and exit codes, and each passes scripts/conformance.sh
test-conformance: check-python
	PYTHON=$(PYTHON) NODE=$(NODE) scripts/crosscheck.sh

## L4: web/ of this checkout in headless Chrome (needs Node 22 and Chrome)
test-web:
	$(NODE) web/test/browser.mjs

test-all: test test-conformance test-web

## L5: first use from outside (docs/TESTING.md)
first-use: check-python
	@if [ -n "$(VERSION)" ] && [ -z "$(REF)" ]; then \
	  PYTHON=$(PYTHON) NODE=$(NODE) scripts/first-use.sh --version "$(VERSION)"; \
	elif [ -n "$(REF)" ] && [ -z "$(VERSION)" ]; then \
	  PYTHON=$(PYTHON) NODE=$(NODE) scripts/first-use.sh --ref "$(REF)"; \
	else \
	  echo "usage: make first-use VERSION=<x.y.z> | REF=<git ref>" >&2; exit 2; \
	fi

check-python:
	@test -n "$(PYTHON)" || { echo "no python3 >= 3.9 found; set PYTHON" >&2; exit 2; }

clean:
	rm -rf .first-use
