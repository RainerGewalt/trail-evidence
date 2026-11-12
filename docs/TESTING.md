# Testing

How trail-evidence is tested: which levels exist, what each one proves, and
how to run it. `CONTRIBUTING.md` lists the commands for a change;
`docs/RELEASING.md` lists what runs before and after a tag. The levels follow
the testing concept of the Trail projects.

## Levels

**L1 Unit.** Canonicalisation, hashing, sequence parsing, signatures,
profile checks and report wording in each implementation: `go test ./...`
in `go/`, `python3 -m unittest discover -s tests` in `python/`,
`node web/test/run.mjs` for the browser verifier.

**L2 Component.** Each verifier on whole journals: the stream fixtures in
`testdata/streams/` with their expected verdicts in `expected.json`, read by
the Go, Python and JavaScript tests.

**L3 Conformance.** This repository is the reference the other projects
check against. `testdata/vectors.json` has to be reproduced byte for byte by
every implementation, and `scripts/crosscheck.sh` (with
`scripts/conformance.sh`) checks that the Go, Python and browser verifiers
produce identical reports, summary lines, states and exit codes on every
vector and journal. The journals include a differential corpus of malformed
and edge-case input, each case one on which the verifiers once disagreed or
a verdict is easy to misread: duplicate member names at every depth, data
after the object, lines that are not UTF-8, nesting beyond 64 levels,
unpaired surrogates, white space that is not JSON white space, an empty
journal, and the documented limits (a journal cut off at its end, changed
members that are not hashed, signatures removed). `scripts/conformance.sh`
also checks that a journal that cannot be read (a directory, a missing or
unreadable file) gets exit code 2 and no report. `scripts/validate_schema.py`, `scripts/profiles.py --check` and
`scripts/reason_codes.py --check` keep the JSON Schema, the profile copies and
the reason-code tables in step.

**L4 Scenario.** The journals a user meets first: `examples/` (one per
producer kind) and `examples/tampered/` with the verdict each one must reach
(`examples/tampered/expected.json`). `node web/test/browser.mjs` checks the
page itself in headless Chrome with real key and file-input events: the
example links work with Tab and Enter, an empty file, a file that is not
JSON and a line that is not UTF-8 get a verdict that is not green and a
coverage text that says what was checked, and an invalid key hides the
previous result. It needs Node 22 and Chrome, runs in CI (job
`web-browser`) and again by hand before a tag, and renews the README
screenshots with `--screenshots docs/screenshots`.

**L5 First use.** `scripts/first-use.sh` walks through the README as a new
user would and stops at the first step that does not behave as documented:

- the browser verifier on GitHub Pages;
- the Go binary and the Python package installed;
- the documented examples with their verdicts and exit codes (valid,
  `seq_mismatch`, incomplete with exit code 3, `--allow-incomplete`, a
  signed journal with `--require-signatures`), in Go and in Python;
- every case of `examples/tampered/expected.json` with its exit code, in
  both verifiers;
- a journal of your own, sealed and signed with the Python library and
  verified by both CLIs with its public key, an edited copy that both
  report as invalid, and an unsigned journal that fails
  `--require-signatures`.

`scripts/first-use.sh` checks the committed `HEAD` from a fresh clone and
installs from it; this is the check before a tag.
`RELEASE=x.y.z scripts/first-use.sh` checks what was published: the tag, the
release archive against `checksums.txt`, `go install …@vx.y.z` and
`pip install trail-evidence==x.y.z`; this is the check after a tag. The
GitHub Action is not run there; `.github/workflows/self-test.yml` runs it in
this repository.

## Every fix ships with a negative control

A test for a fix has to be shown to fail without it: remove or mutate the
code under test, run the test, record that it fails, restore the file and
check that it is identical.

## CI

`.github/workflows/ci.yml` runs the L1 to L4 checks on every push and pull
request; `.github/workflows/self-test.yml` runs the GitHub Action on the
examples. `scripts/first-use.sh` runs by hand before and after every tag.
