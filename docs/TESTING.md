# Testing

This is the binding description of how trail-evidence is tested: which layers
exist, where a test belongs, and how each layer runs locally and in CI. The
`Makefile` is the single entry point; this document explains its targets.

This repository is the contract the producers test against. Its own
conformance layer (L3) is therefore the one that matters most: the Go, Python
and JavaScript verifiers must agree with the vectors and with each other,
and the released verifiers must do so as published, because every producer
runs them.

## Layers

| Layer | What it proves here | Where it lives | Command |
| --- | --- | --- | --- |
| **L1 Unit** | Pure logic of one implementation: RFC 8785 canonicalisation, number formatting, Ed25519, key and `seq` parsing, summary lines, the version string | `go/**/*_test.go`; `python/tests/test_jcs.py`, `test_ed25519.py`; the JCS section of `web/test/run.mjs` | `make test` |
| **L2 Component** | One implementation with its real collaborators, offline: the sealer and verifier on the real files in `testdata/`, `examples/` and `profiles/`; the CLI with its real flag parsing and exit codes; the embedded profile copies; the generated files | `go/evidence/evidence_test.go`, `go/cmd/trail-evidence/main_test.go`, `go/internal/vectors/vectors_test.go`; `python/tests/test_vectors.py` and the CLI from the checkout; `web/test/run.mjs` and its report mode | `make test` |
| **L3 Conformance** | The three verifiers against the shared contract, black box through their CLIs: every vector reproduced byte for byte, the expected findings, states, verdict and exit code for every stream case, and identical reports from Go, Python and JavaScript | `scripts/crosscheck.sh`, which runs `scripts/conformance.sh` for each verifier | `make test-conformance` |
| **L4 Scenario** | The two products a user touches besides the CLI: the GitHub Action (`action.yml`) on Linux, macOS and Windows, and the browser page in headless Chrome with its bundled examples | `.github/workflows/self-test.yml`; `web/test/browser.mjs` | `make test-web`; the Action only in CI |
| **L5 First use** | What README.md tells a first user, run from outside: the published artifacts of a version, or a fresh clone of a ref | `scripts/first-use.sh`, `.github/workflows/first-use.yml` | `make first-use VERSION=<x.y.z>` or `REF=<git ref>` |
| **Tooling** | The repository's own data and scripts: formatting, `go vet`, generated files up to date, profile registry and its copies, reason code catalog, JSON Schema validation of the journals, the schemas against their metaschema, shell syntax | `scripts/profiles.py`, `scripts/reason_codes.py`, `scripts/validate_schema.py`, `go/internal/gentestdata` | `make test-tooling`, `make test-schema` |

Each implementation's own suite also reproduces the vectors and the stream
fixtures in process (`TestVectorsReproduce`, `TestStreamFixtures`,
`Vectors.test_reproduce_all_vectors`, the vector section of `run.mjs`). That
is the fast inner loop of L3 and runs with L2; L3 proper goes through the
command line, exactly as a producer or another implementation would.

### L3 in numbers

`scripts/conformance.sh` checks 21 vectors and 29 stream cases per verifier.
`scripts/crosscheck.sh` first checks that Go regenerates
`testdata/vectors.json` byte for byte and that Python and JavaScript
reproduce it, then compares the full reports (everything but the wording of
messages) and exit codes of all three on 34 journals (`examples/`,
`examples/tampered/`, `testdata/streams/`, the profile journal) in four modes
each: plain, with the test key and `--require-signatures`,
`--allow-incomplete`, and `--require-known-profiles`.

### L3 for producers

TrailTransfer, TrailSource and, once it emits the format, TrailMQ run their
own L3 against this repository's released verifiers and vectors. This
repository does not test their journals; their own `docs/TESTING.md` says
how they do it. What they need from here:

- **One pinned version.** Name the trail-evidence version in one place, for
  example `TRAIL_EVIDENCE_VERSION := 0.2.0` in the Makefile, and derive
  everything else from it:
  - the Go verifier: `go install github.com/RainerGewalt/trail-evidence/go/cmd/trail-evidence@v$(TRAIL_EVIDENCE_VERSION)`,
    or the release archive checked against `checksums.txt`;
  - the Python verifier: `pip install trail-evidence==$(TRAIL_EVIDENCE_VERSION)`
    in a venv, command `trail-evidence-py`;
  - the vectors and `scripts/conformance.sh` from the tag, never from
    `main`: `git clone --depth 1 --branch v$(TRAIL_EVIDENCE_VERSION) https://github.com/RainerGewalt/trail-evidence`.
  A producer that imports the Go package has its pin in `go.mod`
  (`github.com/RainerGewalt/trail-evidence/go v0.2.0`); read the version
  from there (`go list -m -f '{{.Version}}' github.com/RainerGewalt/trail-evidence/go`)
  instead of writing it twice. `uses: RainerGewalt/trail-evidence@v0.2.0`
  cannot read a variable; a producer that uses the Action in CI either
  makes that line its only pin or checks in its tests that the line names
  the pinned version. Never `@latest`, `main` or an unpinned `pip install`.
- **What to run.** Producer conformance: the producer's sealer reproduces
  every vector in `testdata/vectors.json` byte for byte (a Go producer that
  seals with the `evidence` package of the pinned version gets this from the
  package). Then both released verifiers on journals the producer really
  writes, with `--json`, asserting the verdict, the state of every record
  and the notices it expects (for example `legacy_integer_seq` for integer
  `seq`). Then tampered copies of those journals with the documented
  result: an edited payload is `hash_mismatch` on that record, verdict
  `invalid`, exit 1; a record deleted from the middle is `seq_gap` on the
  next one, verdict `incomplete`, exit 3; for a signed journal, with
  `--pubkey` and `--require-signatures`, a re-sealed record is
  `signature_invalid`. With a profile registered here, add
  `--require-known-profiles`.
- **Upgrading** is a change of that one version, followed by the producer's
  L3 and a look at `CHANGELOG.md`, which lists every breaking change of the
  format before 1.0.
- `trail-evidence version` is for people, not for scripts: the 0.2.0
  binary installed with `go install` prints `v0.2.0`, the release archive
  `0.2.0`.

### L4

`self-test.yml` runs the composite action from the checkout (`uses: ./`,
which builds the verifier from it) on Linux, macOS and Windows: passing and
failing journals, its three outputs, `allow-incomplete`,
`require-known-profiles` and signatures. It can only run on GitHub.

`make test-web` serves `web/` of the checkout on a free local port and drives
headless Chrome through the DevTools protocol (`web/test/browser.mjs`, Node
22 and Chrome or Chromium, no npm packages). It clicks "the example journal"
and "a tampered example" and checks the verdict and JSON report the page
shows (VALID with 4 valid records; INVALID, 2 errors, `hash_mismatch` on
record #2), that every request went to the page's own origin and was a GET,
and that the page threw no exception. Pages deploys only after
`web/test/run.mjs` passes (`pages.yml`).

### L5

`make first-use VERSION=<x.y.z>` tests the published artifacts. It clones the
tag `v<x.y.z>` for the examples (README: the examples need a clone), and:

- downloads the release archive for this platform and `checksums.txt`, runs
  `sha256sum --ignore-missing -c checksums.txt` as the README does, and
  checks that the archive holds the binary, `LICENSE` and `SPEC.md`;
- runs `go install …@v<x.y.z>` into an empty `GOPATH`, so that the module
  comes from the module proxy;
- checks that both binaries print `trail-evidence <x.y.z> (schema trail.evidence/1)`
  (`docs/RELEASING.md`, "After the release");
- installs `trail-evidence==<x.y.z>` from PyPI into a fresh venv;
- opens the browser verifier on GitHub Pages in headless Chrome. Pages has
  no versions: it serves `web/` of `main`.

`make first-use REF=<git ref>` clones the ref and uses the ways the README
documents "from a checkout": `go run` and `go build` in `go/`,
`python3 -m trail_evidence` in `python/`, `pip install "git+…@<ref>#subdirectory=python"`,
and the page served with `python3 -m http.server -d web`.

Both modes then run, with every verifier they installed:

- the README's verify examples with the documented first lines and exit
  codes (0 valid, 1 invalid, 3 incomplete), the failure cases
  `--require-signatures` on an unsigned journal (exit 1) and a file that
  does not exist (exit 2);
- an own use case: three records sealed and signed with the Python API of
  the installed package (README, "Produce records"), with the published
  test key, verified by the Go binary and by `trail-evidence-py`;
- the targeted failure cases on that journal: an edited copy is `invalid`
  with `hash_mismatch` on the edited record (exit 1), a copy without the
  middle record is `incomplete` (exit 3);
- `scripts/conformance.sh` of the tested version against each verifier.

A first step checks that the README of the tested version still documents
every output and command the script relies on, so a changed README makes the
script fail at a named line instead of drifting from it. The script prints
PASS, FAIL or SKIP per step, writes `.first-use/first-use-<mode>-<value>.txt`
and the step logs, and exits non-zero on any failure. It needs `git`, `curl`,
Go, a Python 3.9 or newer (`PYTHON`, default the newest `python3.x` on
`PATH`), Node 22 and Chrome, and network access to GitHub, the Go module
proxy, PyPI and GitHub Pages.

The workflow `first-use.yml` runs it by `workflow_dispatch` (input `version`
or `ref`), after every successful run of the release workflow (the version
from its tag), for a release published by hand, and on pull requests that
change the first-use machinery (REF mode on the head commit). In VERSION mode
it also runs the GitHub Action of that tag, as `uses: ...@v<x.y.z>` would:
the examples pass, a tampered journal fails with verdict `invalid`. The
report is uploaded as the artifact `first-use-report-<run id>`.

## Where a new test goes

The lowest layer that can fail for the defect. In this repository that
usually means the shared data, because then all three implementations and
every producer test it at once:

1. A canonicalisation or hashing rule: a vector in
   `go/internal/vectors/vectors.go`, regenerated into
   `testdata/vectors.json` (L3 for every verifier and producer).
2. A verification rule (finding, state, verdict, exit code): a stream
   fixture with its expected result in `testdata/streams/expected.json`,
   generated the same way.
3. Behaviour of one implementation only (flag parsing, key formats, the
   version string): a unit or component test in that language.
4. The page itself (DOM, fetches, requests): `web/test/browser.mjs`. The
   verification logic of `web/verify.js` stays in `web/test/run.mjs`.
5. The Action: a step in `self-test.yml`.
6. A promise the README makes to a first user: `scripts/first-use.sh`.

A defect found at L4 or L5 gets a reproduction at the lowest layer that can
show it.

## Determinism

A test proves a property with a signal that is ordered with it, never by
waiting. There is no sleep in any suite. The signals used here:

| Need | Signal | Where |
| --- | --- | --- |
| Chrome is ready for DevTools | its `DevTools listening on ws://…` line on stderr | `browser.mjs` |
| The page has loaded | the CDP event `Page.loadEventFired` | `browser.mjs` |
| The page has rendered a verdict | a `MutationObserver` in the page, which fires after the synchronous `render()` | `browser.mjs` |
| Chrome has shut down | `Browser.close`, then the process exit | `browser.mjs` |
| The local page server is up | `python3 -m http.server` prints its port before it serves | `first-use.sh` |

Bounded waits remain only as safety nets against a hang and say so in a
comment (60 s per DevTools call in `browser.mjs`, 30 s for the server line in
`first-use.sh`); the bound is never the assertion. The Go suite runs with
`-race -shuffle=on`; the generators are deterministic
(`TestBuildIsDeterministic`).

## Every fix ships with a negative control

A test for a fix has to be shown to fail without the fix: mutate the fixed
code or remove the check under test, run the test, record that it fails,
restore the file and verify that it is identical (for example by its
SHA-256). Record the controls in the pull request description.

## Flaky tests

A flaky test is a defect, in the test or in the product. Reproduce it with
repetition (`go test -count=N`, a loop around the script), find the
unordered assumption and replace it with an ordered signal. Never fix a
flake by rerunning, widening a timeout or adding a sleep.

## Naming

New tests state the property as a sentence: Go
`TestAGoInstallBuildReportsTheModuleVersionWithoutItsLeadingV`, Python
`test_<the_property>`, and each check line of `browser.mjs` and
`first-use.sh` reads as a sentence. Older names stay until the test is
touched.

## Data and artifacts

Synthetic values only. The only key is the published TEST KEY in
`testdata/keys/` (RFC 8032 test vector 1); never add a real key or token.
The own journal of `first-use.sh` uses `example.invalid` hosts. Run
artifacts (`.first-use/`, `python/dist/`, `/dist/`, built binaries) are
ignored by Git.

## Commands

| Command | Layer | Runs |
| --- | --- | --- |
| `make test` | L1–L2, Tooling | `test-go`, `test-python`, `test-js`, `test-tooling`; offline |
| `make test-go` | L1–L2 | `go test -race -shuffle=on ./...` in `go/` |
| `make test-python` | L1–L2 | `unittest` in `python/`, and the CLI from the checkout on three journals |
| `make test-js` | L1–L2 | `node web/test/run.mjs` and its report mode on three journals |
| `make test-tooling` | Tooling | gofmt, `go vet`, generated files, `profiles.py --check`, `reason_codes.py --check`, `validate_schema.py`, `bash -n` |
| `make test-schema` | Tooling | `check-jsonschema` on the schemas (needs `pip install "jsonschema>=4.18" check-jsonschema`) |
| `make test-conformance` | L3 | `scripts/crosscheck.sh` |
| `make test-web` | L4 | `node web/test/browser.mjs` against `web/` of the checkout |
| `make test-all` | L1–L4 | `test`, `test-conformance`, `test-web` |
| `make first-use VERSION=<x.y.z>` | L5 | `scripts/first-use.sh --version <x.y.z>` |
| `make first-use REF=<git ref>` | L5 | `scripts/first-use.sh --ref <git ref>` |

`PYTHON`, `NODE` and `GO` choose the interpreters (`make test PYTHON=python3.12`).
`CHROME` and `CHROME_PORT` are read by `browser.mjs`. Chrome keeps a socket
under `TMPDIR`, which must therefore be short.

## CI mapping

The workflows are authoritative; this table is a reading aid.

| Workflow | Job | Layer | Command |
| --- | --- | --- | --- |
| `ci.yml` | Go 1.22, Go stable | L1–L2 | `make test-go` |
| `ci.yml` | Python 3.9, 3.12, 3.13 | L1–L2 | `make test-python` |
| `ci.yml` | JavaScript verifier (Node 18, 22) | L1–L2 | `make test-js` |
| `ci.yml` | Python package | L2 | build sdist and wheel, install the wheel in a venv, run `trail-evidence-py` |
| `ci.yml` | Tooling | Tooling | `make test-tooling test-schema` |
| `ci.yml` | Go vs Python vs JavaScript crosscheck | L3 | `make test-conformance` |
| `ci.yml` | Browser page in headless Chrome | L4 | `make test-web` |
| `self-test.yml` | action.yml on Linux, macOS, Windows | L4 | `uses: ./` with the fixtures |
| `pages.yml` | Deploy | L2 gate | `node web/test/run.mjs` before publishing `web/` |
| `release.yml` | Go tests, Python distribution | L1–L2 gate | before GoReleaser and the PyPI upload |
| `first-use.yml` | make first-use, GitHub Action | L5 | `make first-use VERSION=…` or `REF=…`; the Action of the tag |

`ci.yml` and `self-test.yml` run on every pull request and push to `main`;
the Action self-test stays under 5 minutes of job time (about 35 s on Linux,
55 s on macOS, 65 s on Windows), plus the wait for a macOS runner.
`first-use.yml` runs as described under L5.

## Budgets

The offline suites (L1, L2 and the tooling checks) stay under 60 s. The
budgets are a review rule; no tooling enforces them. Measured on 2026-11-04
on a Linux laptop (Go 1.23, Python 3.11, Node 22):

| Suite | Budget | Measured |
| --- | --- | --- |
| `make test` (L1, L2, Tooling) | under 60 s | 3.8 s with a warm build cache; the first `-race` build adds about 7 s |
| of which `make test-go` | | 2.0 s |
| of which `make test-python` | | 0.6 s |
| of which `make test-js` | | 0.3 s |
| of which `make test-tooling` | | 0.8 s |
| `make test-conformance` (L3) | under 60 s | 29 s |
| `make test-web` (L4) | under 60 s | 0.8 s |
| `make first-use VERSION=0.2.0` (L5) | none; network bound | 18 s |
| `make first-use REF=…` (L5) | none; network bound | REF_SECONDS s |
