#!/usr/bin/env bash
# Cross-check: the Go reference implementation generates the vectors, Python
# and the browser verifier (web/verify.js, run with Node) must reproduce every
# hash byte for byte, all three verifiers must agree on every stream fixture
# and example journal, and each must pass scripts/conformance.sh.
#
# Usage: scripts/crosscheck.sh            (picks the newest python3 >= 3.9)
#        PYTHON=python3.12 NODE=node scripts/crosscheck.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pick_python() {
  if [ -n "${PYTHON:-}" ]; then echo "$PYTHON"; return; fi
  for c in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
      echo "$c"; return
    fi
  done
  echo "crosscheck: no python3 >= 3.9 found" >&2
  exit 2
}
PY="$(pick_python)"
NODE="${NODE:-node}"
if ! command -v "$NODE" >/dev/null 2>&1; then
  echo "crosscheck: node not found (Node 18 or newer is required for web/verify.js)" >&2
  exit 2
fi
echo "python: $PY ($("$PY" --version 2>&1))"
echo "node:   $NODE ($("$NODE" --version))"
echo "go:     $(go version)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== 1. Go generates the vectors"
(cd go && go run ./cmd/trail-evidence vectors) > "$TMP/vectors.go.json"
if ! cmp -s "$TMP/vectors.go.json" testdata/vectors.json; then
  echo "FAIL: go 'vectors' output differs from testdata/vectors.json (run: cd go && go run ./internal/gentestdata -root ..)" >&2
  exit 1
fi
echo "ok: go output is byte-identical to testdata/vectors.json"

echo "== 2. Python reproduces every vector"
PYTHONPATH=python "$PY" -m trail_evidence check-vectors "$TMP/vectors.go.json"

echo "== 3. JavaScript (web/verify.js) reproduces every vector and fixture"
"$NODE" web/test/run.mjs
for copy in transfer-worker.jsonl tampered/hash-mismatch.jsonl; do
  if ! cmp -s "web/examples/$copy" "examples/$copy"; then
    echo "FAIL: web/examples/$copy differs from examples/$copy" >&2
    exit 1
  fi
done

echo "== 4. All verifiers agree on fixtures and examples"
GOBIN="$TMP/trail-evidence"
(cd go && go build -o "$GOBIN" ./cmd/trail-evidence)
PUB=testdata/keys/test-ed25519.pub
mismatch=0
for f in examples/*.jsonl examples/tampered/*.jsonl testdata/streams/*.jsonl; do
  for mode in plain signed; do
    if [ "$mode" = signed ]; then flags=(--pubkey "$PUB" --require-signatures); else flags=(); fi
    set +e
    "$GOBIN" verify "$f" "${flags[@]}" --json > "$TMP/go.json"; gorc=$?
    PYTHONPATH=python "$PY" -m trail_evidence verify "$f" "${flags[@]}" --json > "$TMP/py.json"; pyrc=$?
    "$NODE" web/test/run.mjs report "$f" "${flags[@]}" > "$TMP/js.json"; jsrc=$?
    set -e
    # Compare verdict and the ordered list of (index, class, severity); messages may differ in wording.
    "$PY" - "$TMP/go.json" "$gorc" "$f" "$mode" python "$TMP/py.json" "$pyrc" javascript "$TMP/js.json" "$jsrc" <<'PYEOF' || mismatch=1
import json, sys
g = json.load(open(sys.argv[1])); gorc = sys.argv[2]
f, mode = sys.argv[3], sys.argv[4]
def shape(r):
    return {
        "ok": r["ok"], "records": r["records"], "errors": r["errors"], "restarts": r["restarts"],
        "notices": r["notices"], "signed": r["signed_records"], "verified": r["signatures_verified"], "unsigned": r["unsigned_records"],
        "streams": [(s["stream_id"], s["records"], s["last_seq"], s["last_chain_hash"], s["restarts"]) for s in r["streams"]],
        "findings": [(x["index"], x["class"], x["severity"]) for x in r["findings"]],
    }
sg = shape(g)
bad = False
others = sys.argv[5:]
for i in range(0, len(others), 3):
    label, path, rc = others[i], others[i + 1], others[i + 2]
    so = shape(json.load(open(path)))
    if sg != so or gorc != rc:
        bad = True
        print(f"MISMATCH {f} [{mode}] go rc={gorc} {label} rc={rc}")
        for k in sg:
            if sg[k] != so[k]:
                print(f"  {k}: go={sg[k]} {label}={so[k]}")
if bad:
    sys.exit(1)
print(f"ok: {f} [{mode}] ok={sg['ok']} findings={len(sg['findings'])} rc={gorc} (go, python, javascript)")
PYEOF
  done
done
if [ "$mismatch" -ne 0 ]; then
  echo "FAIL: the verifiers disagree" >&2
  exit 1
fi

echo "== 5. Each verifier passes the conformance suite (scripts/conformance.sh)"
PYTHON="$PY" scripts/conformance.sh "$GOBIN" | tail -n 1
PYTHONPATH=python PYTHON="$PY" scripts/conformance.sh "$PY" -m trail_evidence | tail -n 1
PYTHON="$PY" scripts/conformance.sh "$NODE" web/test/run.mjs | tail -n 1
echo "== crosscheck passed"
