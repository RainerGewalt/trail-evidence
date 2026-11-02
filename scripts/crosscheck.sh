#!/usr/bin/env bash
# Cross-check: the Go reference implementation generates the vectors, Python
# must reproduce every hash byte for byte, and both verifiers must agree on
# every stream fixture and example journal.
#
# Usage: scripts/crosscheck.sh            (picks the newest python3 >= 3.9)
#        PYTHON=python3.12 scripts/crosscheck.sh
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
echo "python: $PY ($("$PY" --version 2>&1))"
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

echo "== 3. Both verifiers agree on fixtures and examples"
GOBIN="$TMP/trail-evidence"
(cd go && go build -o "$GOBIN" ./cmd/trail-evidence)
PUB=testdata/keys/test-ed25519.pub
mismatch=0
for f in examples/*.jsonl testdata/streams/*.jsonl; do
  for mode in plain signed; do
    if [ "$mode" = signed ]; then flags=(--pubkey "$PUB" --require-signatures); else flags=(); fi
    set +e
    "$GOBIN" verify "$f" "${flags[@]}" --json > "$TMP/go.json"; gorc=$?
    PYTHONPATH=python "$PY" -m trail_evidence verify "$f" "${flags[@]}" --json > "$TMP/py.json"; pyrc=$?
    set -e
    # Compare verdict and the ordered list of (index, class, severity); messages may differ in wording.
    "$PY" - "$TMP/go.json" "$TMP/py.json" "$f" "$mode" "$gorc" "$pyrc" <<'PYEOF' || mismatch=1
import json, sys
g = json.load(open(sys.argv[1])); p = json.load(open(sys.argv[2]))
f, mode, gorc, pyrc = sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
def shape(r):
    return {
        "ok": r["ok"], "records": r["records"], "errors": r["errors"], "restarts": r["restarts"],
        "notices": r["notices"], "signed": r["signed_records"], "verified": r["signatures_verified"], "unsigned": r["unsigned_records"],
        "streams": [(s["stream_id"], s["records"], s["last_seq"], s["last_chain_hash"], s["restarts"]) for s in r["streams"]],
        "findings": [(x["index"], x["class"], x["severity"]) for x in r["findings"]],
    }
sg, sp = shape(g), shape(p)
if sg != sp or gorc != pyrc:
    print(f"MISMATCH {f} [{mode}] go rc={gorc} py rc={pyrc}")
    for k in sg:
        if sg[k] != sp[k]:
            print(f"  {k}: go={sg[k]} py={sp[k]}")
    sys.exit(1)
print(f"ok: {f} [{mode}] ok={sg['ok']} findings={len(sg['findings'])} rc={gorc}")
PYEOF
  done
done
if [ "$mismatch" -ne 0 ]; then
  echo "FAIL: Go and Python verifiers disagree" >&2
  exit 1
fi
echo "== crosscheck passed"
