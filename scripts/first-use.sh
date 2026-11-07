#!/usr/bin/env bash
# First-use check, level L5 in docs/TESTING.md.
#
# Walks through the README the way a new user would and stops at the first
# step that does not behave as documented:
#
#   scripts/first-use.sh                   the committed HEAD, from a fresh clone
#   RELEASE=0.2.1 scripts/first-use.sh     the published release: the tag from
#                                          GitHub, the release archive against
#                                          checksums.txt, go install …@v0.2.1,
#                                          pip install trail-evidence==0.2.1
#
# Both modes also open the browser verifier on GitHub Pages. It needs Git,
# Go 1.22 or newer, Python 3.9 or newer with venv, and curl. The GitHub Action
# is not run here; it runs in this repository's own workflow (self-test.yml).
#
# FIRST_USE_KEEP=1 keeps the working directory for inspection.
set -euo pipefail

RELEASE="${RELEASE:-}"
REPO_URL="https://github.com/RainerGewalt/trail-evidence.git"
PAGES="https://rainergewalt.github.io/trail-evidence"
MODULE="github.com/RainerGewalt/trail-evidence/go/cmd/trail-evidence"

here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/trail-evidence-first-use.XXXXXX")"
clone="$work/trail-evidence"
steps=0

step() { steps=$((steps + 1)); printf '\n==> %s\n' "$*"; }
ok() { printf '    ok: %s\n' "$*"; }
fail() {
	printf '\nFIRST-USE FAILED at step %d: %s\n' "$steps" "$*" >&2
	exit 1
}
cleanup() {
	if [[ ${FIRST_USE_KEEP:-0} == 1 ]]; then echo "kept: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is not installed: $2"; }

# run_cli EXPECTED_EXIT GREP_PATTERN ARGS...: run a command, check its exit
# code and that its output matches the pattern; prints the first matching line.
run_cli() {
	local want=$1 pattern=$2 out code
	shift 2
	if out="$("$@" 2>&1)"; then code=0; else code=$?; fi
	[[ $code == "$want" ]] || fail "$* exited $code, want $want; output: $(head -n 5 <<<"$out")"
	grep -Eq -- "$pattern" <<<"$out" || fail "$* did not print /$pattern/; output: $(head -n 5 <<<"$out")"
	ok "$(grep -Em1 -- "$pattern" <<<"$out")  [exit $code: ${*//$work/<work>}]"
}

# ---------------------------------------------------------------------------
step "Prerequisites from the README"
need git "it is used to get the code"
need go "README, Install: Go 1.22 or newer"
need curl "this check reads the browser verifier with it"
py=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
	if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys, venv; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
		py=$candidate
		break
	fi
done
[[ -n $py ]] || fail "no Python 3.9 or newer with venv (README, Install: Python 3.9 or newer)"
ok "git, $(go env GOVERSION), $("$py" --version), curl"

# ---------------------------------------------------------------------------
step "Try in the browser (README)"
page="$(curl -fsS --max-time 20 "$PAGES/")" || fail "GET $PAGES/ failed"
grep -q '<title>Trail Evidence Verifier</title>' <<<"$page" || fail "$PAGES/ is not the browser verifier"
for asset in verify.js style.css; do
	curl -fsS -o /dev/null --max-time 20 "$PAGES/$asset" || fail "GET $PAGES/$asset failed"
done
ok "$PAGES/ serves the verifier with verify.js and style.css"

# ---------------------------------------------------------------------------
step "Get the code"
if [[ -z $RELEASE ]]; then
	rev="$(git -C "$here" rev-parse HEAD)"
	if [[ -n "$(git -C "$here" status --porcelain)" ]]; then
		echo "    note: uncommitted changes are not part of this check; it runs the committed HEAD ${rev:0:12}"
	fi
	git clone --quiet "$here" "$clone"
	git -C "$clone" checkout --quiet "$rev"
	ok "fresh clone of $(git -C "$clone" describe --tags --always)"
else
	git clone --quiet --depth 1 --branch "v$RELEASE" "$REPO_URL" "$clone" 2>/dev/null ||
		fail "tag v$RELEASE not found on $REPO_URL"
	ok "tag v$RELEASE from GitHub"
fi
cd "$clone"

# ---------------------------------------------------------------------------
step "Install (README, Install)"
mkdir -p "$work/bin"
if [[ -z $RELEASE ]]; then
	(cd go && go build -o "$work/bin/trail-evidence" ./cmd/trail-evidence) || fail "go build ./cmd/trail-evidence"
	ok "Go binary from the checkout: $("$work/bin/trail-evidence" version)"
	"$py" -m venv "$work/venv"
	"$work/venv/bin/pip" install -q ./python || fail "pip install ./python"
	ok "Python package from the checkout"
else
	arch="$(go env GOARCH)"
	archive="trail-evidence_${RELEASE}_linux_${arch}.tar.gz"
	base="https://github.com/RainerGewalt/trail-evidence/releases/download/v$RELEASE"
	(cd "$work/bin" &&
		curl -fsSLO "$base/$archive" && curl -fsSLO "$base/checksums.txt" &&
		sha256sum --ignore-missing -c checksums.txt >/dev/null &&
		tar -xzf "$archive" trail-evidence) || fail "release archive $archive with checksums.txt"
	"$work/bin/trail-evidence" version | grep -q "$RELEASE" || fail "the release binary does not report $RELEASE"
	ok "$archive: checksum matches, reports $("$work/bin/trail-evidence" version)"
	GOBIN="$work/gobin" go install "$MODULE@v$RELEASE" 2>"$work/go-install.log" || fail "go install $MODULE@v$RELEASE"
	"$work/gobin/trail-evidence" version | grep -q "$RELEASE" || fail "go install does not report $RELEASE"
	ok "go install …@v$RELEASE reports $("$work/gobin/trail-evidence" version)"
	"$py" -m venv "$work/venv"
	"$work/venv/bin/pip" install -q "trail-evidence==$RELEASE" || fail "pip install trail-evidence==$RELEASE"
	ok "pip install trail-evidence==$RELEASE"
fi
te="$work/bin/trail-evidence"
tepy="$work/venv/bin/trail-evidence-py"
[[ -x $tepy ]] || fail "the Python package installs no trail-evidence-py command"

# ---------------------------------------------------------------------------
step "Verify a journal (README): the documented examples, Go and Python"
for v in "$te" "$tepy"; do
	run_cli 0 '^VALID: 4 record\(s\) in 1 stream\(s\), hash chain intact' "$v" verify examples/transfer-worker.jsonl
	run_cli 1 '^INVALID: 3 record\(s\).*seq_mismatch|seq_mismatch' "$v" verify examples/tampered/seq-mismatch.jsonl
	run_cli 3 '^INCOMPLETE: 3 record\(s\)' "$v" verify examples/tampered/seq-gap.jsonl
	run_cli 0 '^INCOMPLETE \(allowed\)' "$v" verify examples/tampered/seq-gap.jsonl --allow-incomplete
	run_cli 0 '^VALID: 3 record\(s\).*3 signature\(s\) verified' "$v" verify testdata/streams/signed.jsonl \
		--pubkey testdata/keys/test-ed25519.pub --require-signatures
done

step "Every tampered example reaches the verdict in examples/tampered/expected.json, in Go and Python"
"$py" - "$te" "$tepy" <<'EOF' || fail "a tampered example did not reach its expected verdict"
import json, subprocess, sys
cases = json.load(open("examples/tampered/expected.json"))["cases"]
bad = 0
for case in cases:
    args = ["verify", "examples/tampered/" + case["file"]]
    if case.get("pubkey"):
        args += ["--pubkey", "examples/tampered/" + case["pubkey"]]
    if case.get("require_signatures"):
        args.append("--require-signatures")
    if case.get("allow_incomplete"):
        args.append("--allow-incomplete")
    codes = [subprocess.run([v] + args, capture_output=True).returncode for v in sys.argv[1:]]
    if any(c != case["exit_code"] for c in codes):
        print("    %s: exit codes %s, want %s" % (case["file"], codes, case["exit_code"]))
        bad += 1
if not bad:
    print("    ok: %d cases, the expected exit code in both verifiers" % len(cases))
sys.exit(1 if bad else 0)
EOF

# ---------------------------------------------------------------------------
step "Produce records (README): own journal with the Python library, checked by both verifiers"
seed="$work/key.seed"
"$py" -c 'import os, sys; open(sys.argv[1], "wb").write(os.urandom(32))' "$seed"
"$work/venv/bin/python" - "$work/own.jsonl" "$seed" "$work/own.pub" <<'EOF' || fail "sealing an own journal failed"
import json, sys
from trail_evidence import seal, sign, GENESIS_HASH, NO_POLICY
path, seed_path, pub_path = sys.argv[1:4]
seed = open(seed_path, "rb").read()
prev = GENESIS_HASH
with open(path, "w") as fh:
    for i in range(3):
        record = {
            "producer": {"kind": "other", "id": "first-use", "version": "0.0.0"},
            "stream_id": "first-use", "seq": str(i), "event_type": "test.check.completed",
            "time": {"recorded_at": "2026-11-07T10:00:0%d.000Z" % i, "source": "system"},
            "actor": {"auth": "none"}, "policy": NO_POLICY,
            "payload": {"n": i, "status": "ok"},
        }
        seal(record, prev)
        sign(record, seed)
        prev = record["chain_hash"]
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")
from trail_evidence.ed25519 import public_key
open(pub_path, "w").write(public_key(seed).hex() + "\n")
EOF
for v in "$te" "$tepy"; do
	run_cli 0 '^VALID: 3 record\(s\) in 1 stream\(s\), hash chain intact.*3 signature\(s\) verified' "$v" verify "$work/own.jsonl" \
		--pubkey "$work/own.pub" --require-signatures
done
sed '2s/"status":"ok"/"status":"failed"/' "$work/own.jsonl" >"$work/own-edited.jsonl"
cmp -s "$work/own.jsonl" "$work/own-edited.jsonl" && fail "could not edit a copy of the own journal"
for v in "$te" "$tepy"; do
	run_cli 1 '^INVALID' "$v" verify "$work/own-edited.jsonl"
done
# An unsigned journal must not pass a check that requires signatures.
run_cli 1 '^INVALID' "$te" verify examples/transfer-worker.jsonl --pubkey testdata/keys/test-ed25519.pub --require-signatures

if [[ -n $RELEASE ]]; then
	printf '\nFIRST-USE PASSED: %d steps, published release %s\n' "$steps" "$RELEASE"
else
	printf '\nFIRST-USE PASSED: %d steps, committed HEAD from a fresh clone\n' "$steps"
fi
