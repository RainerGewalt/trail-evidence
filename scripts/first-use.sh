#!/usr/bin/env bash
# First-user acceptance (L5 in docs/TESTING.md): does what README.md tells a
# first user to do, from outside this checkout, and prints PASS, FAIL or SKIP
# per step.
#
#   scripts/first-use.sh --version <x.y.z>    the published artifacts of a release
#   scripts/first-use.sh --ref <git ref>      a fresh clone of a branch, tag or commit
#
# (make first-use VERSION=<x.y.z> | REF=<git ref> calls this script.)
#
# --version installs the release archive for this platform after checking it
# against checksums.txt, runs go install ...@v<x.y.z> into an empty GOPATH and
# pip install trail-evidence==<x.y.z> into a fresh venv, and opens the browser
# verifier on GitHub Pages. The examples come from a clone of the tag
# v<x.y.z>, as the README says they need a clone.
# --ref clones the ref and uses the ways the README documents "from a
# checkout": go run, go build, python3 -m trail_evidence, pip install
# "git+...@<ref>#subdirectory=python", and the page served with
# python3 -m http.server -d web.
#
# Both modes then run the README's verify examples with every verifier
# (documented output and exit code: 0 valid, 1 invalid, 3 incomplete, 2 for a
# file that does not exist), seal and sign a journal of their own with the
# Python API and verify it with the Go binary, check that an edited and a
# shortened copy of it fail as documented, and run scripts/conformance.sh of
# the tested version against the verifiers.
#
# Environment:
#   REPO         repository to clone (default https://github.com/RainerGewalt/trail-evidence.git)
#   PAGES_URL    browser verifier (default https://rainergewalt.github.io/trail-evidence/)
#   PYTHON       interpreter for the venv, 3.9 or newer (default: newest python3.x >= 3.9 on PATH)
#   NODE         Node 22 or newer for the browser step (default node)
#   CHROME, CHROME_PORT   see web/test/browser.mjs
#   OUT          report and work directory (default .first-use/ in this checkout, git-ignored)
#   KEEP=1       keep the work directory
#
# Writes $OUT/first-use-<mode>-<value>.txt and, in GitHub Actions, the job
# summary. Exit 0: every step passed. 1: a step failed. 2: usage error.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${REPO:-https://github.com/RainerGewalt/trail-evidence.git}"
PAGES_URL="${PAGES_URL:-https://rainergewalt.github.io/trail-evidence/}"
NODE="${NODE:-node}"
OUT="${OUT:-$ROOT/.first-use}"
MODULE="github.com/RainerGewalt/trail-evidence/go/cmd/trail-evidence"

usage() {
  sed -n '2,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
  exit 2
}

MODE="" VALUE=""
case "${1:-}" in
  --version) MODE=version; VALUE="${2:-}" ;;
  --ref)     MODE=ref; VALUE="${2:-}" ;;
  *)         usage ;;
esac
[ -n "$VALUE" ] && [ "$#" -eq 2 ] || usage
if [ "$MODE" = version ] && ! [[ "$VALUE" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "first-use: --version takes x.y.z without the leading v, got '$VALUE'" >&2
  exit 2
fi
if [ "$MODE" = ref ] && ! [[ "$VALUE" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  echo "first-use: --ref '$VALUE' is not a plain branch, tag or commit name" >&2
  exit 2
fi

pick_python() {
  if [ -n "${PYTHON:-}" ]; then echo "$PYTHON"; return; fi
  local c
  for c in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
      command -v "$c"; return
    fi
  done
}
PY="$(pick_python)"
if [ -z "$PY" ]; then
  echo "first-use: no python3 >= 3.9 found (set PYTHON)" >&2
  exit 2
fi

LABEL="$MODE-${VALUE//\//-}"
WORK="$OUT/work-$LABEL"
LOGS="$OUT/logs-$LABEL"
REPORT="$OUT/first-use-$LABEL.txt"
rm -rf "$WORK" "$LOGS"
mkdir -p "$WORK" "$LOGS"
CLONE="$WORK/clone"
VENV="$WORK/venv"
BIN_ARCHIVE="$WORK/archive/trail-evidence"
BIN_GOINSTALL="$WORK/gobin/trail-evidence"
BIN_BUILT="$CLONE/go/trail-evidence"
# go install and go run into an empty GOPATH and module cache, so that the
# module really comes from the module proxy; -modcacherw lets rm remove it.
export GOPATH="$WORK/gopath" GOMODCACHE="$WORK/gopath/pkg/mod" GOFLAGS=-modcacherw

case "$(uname -s)" in
  Linux) OS=linux ;; Darwin) OS=darwin ;; *) OS=windows ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;; arm64|aarch64) ARCH=arm64 ;; *) ARCH="$(uname -m)" ;;
esac
if command -v sha256sum >/dev/null 2>&1; then SHA256=(sha256sum); else SHA256=(shasum -a 256); fi

# ------------------------------------------------------------------ steps

PASSED=" " FAILED=0
LINES=()

# run_step <id> <title> <needs: ids, space separated> <function> [args...]
# Runs the function in a subshell with its output in $LOGS/<id>.log. Lines
# it prints with a leading "> " appear in the report under the step; for a
# failed step, its FAIL lines (or the end of the log) do.
run_step() {
  local id="$1" title="$2" needs="$3"; shift 3
  local log="$LOGS/$id.log" start=$SECONDS rc dep l
  for dep in $needs; do
    if [[ "$PASSED" != *" $dep "* ]]; then
      report_line "SKIP  $title (needs step '$dep')"
      FAILED=1
      return
    fi
  done
  ( set -euo pipefail; "$@" ) >"$log" 2>&1
  rc=$?
  local secs=$((SECONDS - start))
  if [ "$rc" -eq 0 ]; then
    PASSED+="$id "
    report_line "PASS  $title (${secs}s)"
    while IFS= read -r l; do report_line "        ${l#> }"; done < <(grep '^> ' "$log")
  else
    FAILED=1
    report_line "FAIL  $title (${secs}s, exit $rc, log ${log#"$ROOT"/})"
    if grep -q '^FAIL' "$log"; then
      while IFS= read -r l; do report_line "        $l"; done < <(grep -A3 '^FAIL' "$log" | grep -v '^--$' | head -n 30)
    else
      while IFS= read -r l; do report_line "        $l"; done < <(tail -n 15 "$log")
    fi
  fi
}

report_line() {
  LINES+=("$1")
  printf '%s\n' "$1"
}

# expect <exit code> <how> <expected> <command...>
#   how: exact (whole stdout), first (first line), prefix (first line starts
#   with), any (exit code only)
expect() {
  local want_rc="$1" how="$2" want="$3"; shift 3
  local out rc=0 got shown
  out="$("$@" 2>"$WORK/stderr")" || rc=$?
  case "$how" in
    exact)  got="$out" ;;
    first|prefix) got="${out%%$'\n'*}" ;;
    any)    got="" ;;
  esac
  local ok=1
  [ "$rc" -eq "$want_rc" ] || ok=0
  case "$how" in
    exact|first) [ "$got" = "$want" ] || ok=0 ;;
    prefix)      [[ "$got" == "$want"* ]] || ok=0 ;;
  esac
  shown="$(printf '%s' "$*" | sed "s|$WORK/||g")"
  if [ "$ok" -eq 1 ]; then
    echo "ok   exit $rc  $shown"
    return 0
  fi
  echo "FAIL exit $rc (expected $want_rc)  $shown"
  if [ "$how" != any ] && [ "$got" != "$want" ]; then
    echo "       got:      ${got//$'\n'/$'\n'                 }"
    echo "       expected: ${want//$'\n'/$'\n'                 }"
  fi
  sed 's/^/       stderr: /' "$WORK/stderr" | head -n 5
  return 1
}

SEQ_MISMATCH_OUT='INVALID: 3 record(s) in 1 stream(s), 1 error(s)
  error   seq_mismatch      record #2 (line 3, stream "worker-01", seq 3): seq 3, expected 2: prev_hash links to the record with seq 1, so no record can be missing in between'

# readme_examples <dir> <path prefix> <verifier command...>
# The verify examples of README.md ("Verify a journal"), run in <dir> with
# the paths prefixed, plus the documented failure cases.
readme_examples() {
  local dir="$1" p="$2" f=0; shift 2
  cd "$dir"
  expect 0 exact "VALID: 4 record(s) in 1 stream(s), hash chain intact" \
    "$@" verify "${p}examples/transfer-worker.jsonl" || f=1
  expect 1 exact "$SEQ_MISMATCH_OUT" \
    "$@" verify "${p}examples/tampered/seq-mismatch.jsonl" || f=1
  expect 3 first "INCOMPLETE: 3 record(s) in 1 stream(s), no invalid record, 1 unknown" \
    "$@" verify "${p}examples/tampered/seq-gap.jsonl" || f=1
  expect 0 prefix "INCOMPLETE (allowed): " \
    "$@" verify "${p}examples/tampered/seq-gap.jsonl" --allow-incomplete || f=1
  expect 0 exact "VALID: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), 3 signature(s) verified" \
    "$@" verify "${p}testdata/streams/signed.jsonl" --pubkey "${p}testdata/keys/test-ed25519.pub" --require-signatures || f=1
  expect 1 first "INVALID: 4 record(s) in 1 stream(s), 4 error(s)" \
    "$@" verify "${p}examples/transfer-worker.jsonl" --pubkey "${p}testdata/keys/test-ed25519.pub" --require-signatures || f=1
  expect 2 any "" \
    "$@" verify "${p}examples/no-such-journal.jsonl" || f=1
  return "$f"
}

step_clone() {
  if [ "$MODE" = version ]; then
    git clone --quiet --depth 1 --branch "v$VALUE" "$REPO" "$CLONE"
  else
    git init --quiet "$CLONE"
    git -C "$CLONE" remote add origin "$REPO"
    git -C "$CLONE" fetch --quiet --depth 1 origin "$VALUE"
    git -C "$CLONE" checkout --quiet --detach FETCH_HEAD
  fi
  echo "> $(git -C "$CLONE" rev-parse HEAD) from $REPO"
}

# The strings this script checks, and the commands it runs, as README.md of
# the tested version documents them. When the README changes, this step says
# which line the script has to follow.
step_readme() {
  cd "$CLONE"
  local f=0 s doc
  local strings=(
    "# VALID: 4 record(s) in 1 stream(s), hash chain intact"
    "# INVALID: 3 record(s) in 1 stream(s), 1 error(s)"
    '#   error   seq_mismatch      record #2 (line 3, stream "worker-01", seq 3): seq 3, expected 2: prev_hash links to the record with seq 1, so no record can be missing in between'
    "# INCOMPLETE: 3 record(s) in 1 stream(s), no invalid record, 1 unknown"
    "# INCOMPLETE (allowed): "
    "# VALID: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), 3 signature(s) verified"
    "Exit code 2 is a usage or I/O error."
    'Treat unsigned records as `signature_invalid`.'
    "seal(record, GENESIS_HASH)"
  )
  if [ "$MODE" = version ]; then
    strings+=(
      "sha256sum --ignore-missing -c checksums.txt"
      "go install $MODULE@"
      "pip install trail-evidence"
      "${PAGES_URL%/}"
    )
  else
    strings+=(
      "cd go && go run ./cmd/trail-evidence"
      "\`go run\` reports every non-zero exit code as 1"
      "cd go && go build -o trail-evidence ./cmd/trail-evidence"
      "cd python && python3 -m trail_evidence"
      'pip install "git+https://github.com/RainerGewalt/trail-evidence#subdirectory=python"'
      "python3 -m http.server -d web"
    )
  fi
  # Line breaks and runs of spaces do not matter.
  doc="$(tr -s ' \n' ' ' < README.md)"
  for s in "${strings[@]}"; do
    if [[ "$doc" == *"$(tr -s ' ' <<<"$s" | tr -d '\n')"* ]]; then echo "ok   $s"; else echo "FAIL README.md does not contain: $s"; f=1; fi
  done
  if grep -qE 'seq-gap\.jsonl +# exit code 3' README.md; then echo "ok   seq-gap.jsonl  # exit code 3"
  else echo "FAIL README.md does not mark the seq-gap example with '# exit code 3'"; f=1; fi
  return "$f"
}

# ------------------------------------------------------------- version mode

step_archive() {
  local name="trail-evidence_${VALUE}_${OS}_${ARCH}.tar.gz"
  local base="https://github.com/RainerGewalt/trail-evidence/releases/download/v$VALUE"
  mkdir -p "$WORK/archive"
  cd "$WORK/archive"
  curl -fsSLO --retry 3 "$base/$name"
  curl -fsSLO --retry 3 "$base/checksums.txt"
  "${SHA256[@]}" --ignore-missing -c checksums.txt
  grep -q " $name\$" checksums.txt
  local listing
  listing="$(tar -tzf "$name")"
  for member in trail-evidence LICENSE SPEC.md; do
    grep -qx "$member" <<<"$listing" || { echo "FAIL $name has no $member"; return 1; }
  done
  tar -xzf "$name" trail-evidence
  echo "> $name: sha256 ok; holds trail-evidence, LICENSE, SPEC.md"
}

step_goinstall() {
  mkdir -p "$WORK/gobin"
  cd "$WORK"
  GOBIN="$WORK/gobin" go install "$MODULE@v$VALUE"
  echo "> $(go version)"
}

# docs/RELEASING.md: after the release, both print X.Y.Z.
step_versions() {
  local f=0
  expect 0 exact "trail-evidence $VALUE (schema trail.evidence/1)" "$BIN_ARCHIVE" version || f=1
  expect 0 exact "trail-evidence $VALUE (schema trail.evidence/1)" "$BIN_GOINSTALL" version || f=1
  return "$f"
}

make_venv() {
  "$PY" -m venv "$VENV"
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --no-cache-dir "$@"
  echo "> $("$VENV/bin/python" --version) venv; $("$VENV/bin/pip" show trail-evidence | grep -E '^(Name|Version):' | tr '\n' ' ')"
  expect 0 any "" "$VENV/bin/trail-evidence-py" profiles
  "$VENV/bin/trail-evidence-py" profiles | grep -qx 'example.measurement/1' || { echo "FAIL trail-evidence-py profiles does not list example.measurement/1"; return 1; }
}

step_pip() {
  make_venv "trail-evidence==$VALUE"
  local v
  v="$("$VENV/bin/pip" show trail-evidence | sed -n 's/^Version: //p')"
  [ "$v" = "$VALUE" ] || { echo "FAIL pip show reports $v, expected $VALUE"; return 1; }
}

step_pages() {
  "$NODE" "$ROOT/web/test/browser.mjs" "$PAGES_URL"
}

# ----------------------------------------------------------------- ref mode

step_go_run() {
  cd "$CLONE/go"
  local v
  v="$(go run ./cmd/trail-evidence version)"
  echo "> go run ./cmd/trail-evidence version: $v ($(go version))"
  [[ "$v" =~ ^trail-evidence\ [0-9][^\ ]*\ \(schema\ trail\.evidence/1\)$ ]] || { echo "FAIL unexpected version line: $v"; return 1; }
  expect 0 exact "VALID: 4 record(s) in 1 stream(s), hash chain intact" \
    go run ./cmd/trail-evidence verify ../examples/transfer-worker.jsonl
  # go run reports every non-zero exit code of the program as 1.
  expect 1 first "INCOMPLETE: 3 record(s) in 1 stream(s), no invalid record, 1 unknown" \
    go run ./cmd/trail-evidence verify ../examples/tampered/seq-gap.jsonl
}

step_go_build() {
  cd "$CLONE/go"
  go build -o trail-evidence ./cmd/trail-evidence
  echo "> $(./trail-evidence version)"
}

step_pip_git() {
  make_venv "git+$REPO@$VALUE#subdirectory=python"
}

# python3 -m http.server prints the port it bound before it serves; reading
# that line is the signal that the page can be requested.
step_page_local() {
  cd "$CLONE"
  local line port
  coproc SRV { exec "$PY" -u -m http.server -d web --bind 127.0.0.1 0 2>"$LOGS/http.server.log"; }
  local pid="$SRV_PID"
  trap 'kill "$pid" 2>/dev/null' EXIT
  # -t: a safety net against a server that never starts, not the signal.
  IFS= read -r -t 30 line <&"${SRV[0]}"
  port="$(sed -n 's/.* port \([0-9][0-9]*\) .*/\1/p' <<<"$line")"
  [ -n "$port" ] || { echo "FAIL http.server did not report a port: $line"; return 1; }
  echo "> python3 -m http.server -d web on port $port (pid $pid)"
  "$NODE" "$ROOT/web/test/browser.mjs" "http://127.0.0.1:$port/"
}

# ----------------------------------------------------------- both modes

# A journal of this run's own, written with the documented Python API
# (README.md, "Produce records") of the installed package and signed with
# the published TEST KEY, then verified by the Go binary.
step_own() {
  local gobin="$1"
  cd "$WORK"
  "$VENV/bin/python" -I - "$CLONE/testdata/keys/test-ed25519.seed" "$CLONE/testdata/keys/test-ed25519.pub" "$WORK/own.jsonl" <<'PY'
import json, sys
from trail_evidence import seal, sign, verify_stream, GENESIS_HASH, NO_POLICY

seed = bytes.fromhex(open(sys.argv[1]).read().strip())
public_key = bytes.fromhex(open(sys.argv[2]).read().strip())
prev = GENESIS_HASH
lines = []
for i, status in enumerate(["ok", "failed", "ok"]):
    payload = {"action": "copy", "source": "sftp://example.invalid/in/file-%d.csv" % i,
               "target": "s3://example-bucket/archive/", "status": status}
    if status == "failed":
        payload["reason_code"] = "transfer.source_not_found"
    record = {
        "producer": {"kind": "transfer-worker", "id": "first-use", "version": "0.0.0"},
        "stream_id": "first-use", "seq": i, "event_type": "transfer.job.result",
        "time": {"recorded_at": "2026-11-04T08:00:0%d.000Z" % i, "source": "system"},
        "actor": {"auth": "self-declared", "id": "first-user"},
        "policy": NO_POLICY,
        "payload": payload,
    }
    seal(record, prev)
    sign(record, seed)
    prev = record["chain_hash"]
    lines.append(json.dumps(record, separators=(",", ":")))
with open(sys.argv[3], "w") as fh:
    fh.write("\n".join(lines) + "\n")
with open(sys.argv[3]) as fh:
    report = verify_stream(fh, public_key, require_signatures=True)
print("python:", report.summary(), report.verdict, report.exit_code())
sys.exit(report.exit_code())
PY
  local pub="$CLONE/testdata/keys/test-ed25519.pub"
  expect 0 exact "VALID: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), 3 signature(s) verified" \
    "$gobin" verify own.jsonl --pubkey "$pub" --require-signatures
  expect 0 exact "VALID: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), 3 signature(s) verified" \
    "$VENV/bin/trail-evidence-py" verify own.jsonl --pubkey "$pub" --require-signatures
  echo "> own.jsonl: 3 records sealed and signed with the Python package, VALID with the Go binary and trail-evidence-py"
}

# The documented failures on the own journal: an edited record is invalid
# (hash_mismatch, exit 1), a deleted record leaves the journal incomplete
# (seq_gap, exit 3).
step_own_tampered() {
  local gobin="$1"
  cd "$WORK"
  sed '2s/"status":"failed"/"status":"ok"/' own.jsonl > own-edited.jsonl
  sed '2d' own.jsonl > own-shortened.jsonl
  ! cmp -s own.jsonl own-edited.jsonl || { echo "FAIL the edit did not change the journal"; return 1; }
  local f=0 v
  for v in "$gobin" "$VENV/bin/trail-evidence-py"; do
    expect 1 prefix "INVALID: 3 record(s) in 1 stream(s), 2 error(s)" "$v" verify own-edited.jsonl || f=1
    "$v" verify own-edited.jsonl --json > edited.json || true
    "$VENV/bin/python" -I -c 'import json,sys; r=json.load(open(sys.argv[1])); got=sorted({(x["index"], x["class"]) for x in r["findings"]}); sys.exit(0 if got==[(1,"hash_mismatch")] else "findings %s" % got)' edited.json || { echo "FAIL $v: expected hash_mismatch on record #1 only"; f=1; }
    expect 3 prefix "INCOMPLETE: 2 record(s) in 1 stream(s), no invalid record, 1 unknown" "$v" verify own-shortened.jsonl || f=1
  done
  [ "$f" -eq 0 ] && echo "> edited copy: INVALID, hash_mismatch on record #1, exit 1; shortened copy: INCOMPLETE, exit 3"
  return "$f"
}

step_conformance() {
  local f=0 v
  for v in "$@"; do
    echo "== $v"
    if PYTHON="$VENV/bin/python" "$CLONE/scripts/conformance.sh" "$v" > "$WORK/conformance.out"; then
      echo "> $(tail -n 1 "$WORK/conformance.out") <- ${v#"$WORK"/}"
    else
      grep -E '^FAIL|^       ' "$WORK/conformance.out" | head -n 20
      tail -n 1 "$WORK/conformance.out"
      f=1
    fi
  done
  return "$f"
}

# ------------------------------------------------------------------- run

echo "first-use $MODE $VALUE (repository $REPO, python $PY, work directory ${WORK#"$ROOT"/})"
START=$SECONDS
run_step clone "clone of $([ "$MODE" = version ] && echo "tag v$VALUE" || echo "ref $VALUE")" "" step_clone
run_step readme "README.md documents the commands and outputs checked below" "clone" step_readme

if [ "$MODE" = version ]; then
  run_step archive "release archive ${OS}_${ARCH}: checksums.txt verifies it, it holds the binary, LICENSE and SPEC.md" "" step_archive
  run_step goinstall "go install $MODULE@v$VALUE into an empty GOPATH" "" step_goinstall
  run_step versions "the release binary and the go install binary both print 'trail-evidence $VALUE (schema trail.evidence/1)'" "archive goinstall" step_versions
  run_step pip "pip install trail-evidence==$VALUE into a fresh venv: pip show says $VALUE, trail-evidence-py profiles lists example.measurement/1" "" step_pip
  run_step ex-archive "README verify examples and failure cases with the release binary" "clone archive" readme_examples "$CLONE" "" "$BIN_ARCHIVE"
  run_step ex-goinstall "README verify examples and failure cases with the go install binary" "clone goinstall" readme_examples "$CLONE" "" "$BIN_GOINSTALL"
  run_step ex-pip "README verify examples and failure cases with trail-evidence-py from PyPI" "clone pip" readme_examples "$CLONE" "" "$VENV/bin/trail-evidence-py"
  run_step own "own journal sealed and signed with the PyPI package verifies with the release binary" "clone archive pip" step_own "$BIN_ARCHIVE"
  run_step own-tampered "edited and shortened copies of the own journal fail as documented" "own" step_own_tampered "$BIN_ARCHIVE"
  run_step conformance "the released verifiers pass scripts/conformance.sh of v$VALUE" "clone archive goinstall pip" step_conformance "$BIN_ARCHIVE" "$BIN_GOINSTALL" "$VENV/bin/trail-evidence-py"
  run_step pages "browser verifier on GitHub Pages ($PAGES_URL): example VALID, tampered example INVALID" "" step_pages
else
  run_step go-run "go run from the checkout: version, the example journal, and exit code 1 for any failure" "clone" step_go_run
  run_step go-build "go build of the CLI from the checkout" "clone" step_go_build
  run_step ex-go "README verify examples and failure cases with the binary built from the checkout" "go-build" readme_examples "$CLONE" "" "$BIN_BUILT"
  run_step ex-python "README verify examples and failure cases with python3 -m trail_evidence from the checkout" "clone" readme_examples "$CLONE/python" "../" "$PY" -m trail_evidence
  run_step pip "pip install git+…@$VALUE#subdirectory=python into a fresh venv: trail-evidence-py profiles lists example.measurement/1" "" step_pip_git
  run_step ex-pip "README verify examples and failure cases with trail-evidence-py installed from the ref" "clone pip" readme_examples "$CLONE" "" "$VENV/bin/trail-evidence-py"
  run_step own "own journal sealed and signed with the installed package verifies with the binary built from the checkout" "clone go-build pip" step_own "$BIN_BUILT"
  run_step own-tampered "edited and shortened copies of the own journal fail as documented" "own" step_own_tampered "$BIN_BUILT"
  run_step conformance "the built binary and trail-evidence-py pass scripts/conformance.sh of the ref" "clone go-build pip" step_conformance "$BIN_BUILT" "$VENV/bin/trail-evidence-py"
  run_step page "web/ served with python3 -m http.server -d web: example VALID, tampered example INVALID" "clone" step_page_local
fi

pass=0 fail=0 skip=0
for l in "${LINES[@]}"; do
  case "$l" in PASS*) pass=$((pass + 1)) ;; FAIL*) fail=$((fail + 1)) ;; SKIP*) skip=$((skip + 1)) ;; esac
done
summary="first-use $MODE $VALUE: $pass passed, $fail failed, $skip skipped in $((SECONDS - START))s"
echo
echo "$summary"
{
  echo "$summary"
  echo "repository $REPO; $(uname -sm); $("$PY" --version 2>&1); $(go version 2>/dev/null); node $("$NODE" --version 2>/dev/null)"
  echo
  printf '%s\n' "${LINES[@]}"
} > "$REPORT"
echo "report: ${REPORT#"$ROOT"/}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  { echo '```'; cat "$REPORT"; echo '```'; } >> "$GITHUB_STEP_SUMMARY"
fi
if [ "${KEEP:-0}" != 1 ]; then rm -rf "$WORK"; fi
[ "$FAILED" -eq 0 ]
