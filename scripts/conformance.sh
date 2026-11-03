#!/usr/bin/env bash
# Conformance suite for trail.evidence/1 (SPEC.md section 10).
#
# Runs any verifier against the shared test data and reports whether it
# conforms: every vector in testdata/vectors.json reproduced byte for byte
# with its expected state, and exactly the expected findings and record
# states for every case in testdata/streams/expected.json.
#
# Usage: scripts/conformance.sh <verifier command...>
#
#   scripts/conformance.sh ./trail-evidence
#   PYTHONPATH=python scripts/conformance.sh python3 -m trail_evidence
#   scripts/conformance.sh node web/test/run.mjs
#   scripts/conformance.sh /path/to/your-verifier
#
# The command must offer two subcommands with the interface of the reference
# CLI (README.md, "Conformance"):
#
#   <cmd> hash <record.json>
#       prints a JSON object with payload_jcs, content_hash, core_jcs,
#       chain_hash, state and profile_state of the record on its own, and,
#       when the record has findings on its own, findings:
#       [{"class": ..., "severity": "error"|"notice"}, ...]
#   <cmd> verify <journal.jsonl> [--pubkey <file>] [--require-signatures] [--strict] --json
#       prints the report as JSON with ok, records, restarts, findings:
#       [{"index": ..., "class": ..., ...}, ...] and results:
#       [{"index": ..., "state": ..., "profile_state": ...}, ...];
#       exit 0 when ok, 1 when not
#
# The script needs python3 (3.6 or newer, standard library only) for its own
# bookkeeping; set PYTHON to choose one. Exit 0: conformant. Exit 1: at least
# one check failed. Exit 2: usage error.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "conformance: $PY not found (set PYTHON)" >&2
  exit 2
fi
SUITE="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo unknown)"

exec "$PY" - "$ROOT" "$SUITE" "$@" <<'PYEOF'
import json
import os
import shutil
import subprocess
import sys
import tempfile

root, suite, cmd = sys.argv[1], sys.argv[2], sys.argv[3:]
vectors_path = os.path.join(root, "testdata", "vectors.json")
streams_dir = os.path.join(root, "testdata", "streams")

# Vectors whose bytes exercise cases an implementation most often gets wrong.
# They are part of the suite like every other vector; a failure is reported
# with this reason.
MANDATORY = {
    "jcs-edge-cases": "integer 2^53+1 -> 9007199254740992 with number_precision notice; member order by UTF-16 code units",
}
MANDATORY_STREAMS = {
    "seq-decimal.jsonl": "seq compared as integers beyond 2^53 and up to 2^64 - 1",
    "seq-decimal-mismatch.jsonl": "repeated seq beyond 2^53 and seq 0 after 2^64 - 1 are seq_mismatch",
}


class Obj(list):
    """JSON object as an ordered list of (key, value) pairs."""


class Lit(str):
    """A JSON number literal exactly as written."""


def raw_dump(v):
    """Serialise without touching number literals, so 9007199254740993 reaches the verifier unrounded."""
    if isinstance(v, Obj):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + raw_dump(x) for k, x in v) + "}"
    if isinstance(v, Lit):
        return str(v)
    if isinstance(v, list):
        return "[" + ",".join(raw_dump(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)


def raw_records(text):
    doc = json.loads(text, object_pairs_hook=Obj, parse_int=Lit, parse_float=Lit)
    out = {}
    for item in dict(doc)["vectors"]:
        d = dict(item)
        out[str(d["name"])] = raw_dump(d["record"])
    return out


def run(args):
    try:
        p = subprocess.run(cmd + args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        print("conformance: cannot run %r: %s" % (" ".join(cmd), exc), file=sys.stderr)
        sys.exit(2)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def first_difference(got, want):
    if not isinstance(got, str):
        return "got %s" % json.dumps(got)[:120]
    i = 0
    while i < min(len(got), len(want)) and got[i] == want[i]:
        i += 1
    lo = max(0, i - 20)
    return "first difference at character %d: got %s, expected %s" % (
        i, json.dumps(got[lo:i + 40], ensure_ascii=False), json.dumps(want[lo:i + 40], ensure_ascii=False))


def parse(out, err, what):
    try:
        return json.loads(out), None
    except ValueError:
        return None, "%s: output is not JSON (%s)" % (what, (err or out).strip()[:200])


failures = []
tmp = tempfile.mkdtemp(prefix="te-conformance-")
try:
    with open(vectors_path, "r", encoding="utf-8") as fh:
        text = fh.read()
    data = json.loads(text)
    raws = raw_records(text)

    print("== vectors (%s)" % os.path.relpath(vectors_path, root))
    for v in data["vectors"]:
        name = v["name"]
        path = os.path.join(tmp, name + ".json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(raws[name])
        rc, out, err = run(["hash", path])
        got, problem = parse(out, err, "hash")
        bad = []
        if problem:
            bad.append(problem)
        else:
            for key in ("payload_jcs", "content_hash", "core_jcs", "chain_hash"):
                if got.get(key) != v["expected_" + key]:
                    bad.append("%s differs, %s" % (key, first_difference(got.get(key), v["expected_" + key])))
            findings = got.get("findings") or []
            errors = [f.get("class") for f in findings if f.get("severity") == "error"]
            notices = [f.get("class") for f in findings if f.get("severity") == "notice"]
            if notices != v.get("expected_notices", []):
                bad.append("notices %s, expected %s" % (notices, v.get("expected_notices", [])))
            if v["expected_valid"] and errors:
                bad.append("unexpected errors %s" % errors)
            if not v["expected_valid"] and v.get("expected_error") not in errors:
                bad.append("missing error %s (got %s)" % (v.get("expected_error"), errors))
            for key in ("state", "profile_state"):
                if "expected_" + key in v and got.get(key) != v["expected_" + key]:
                    bad.append("%s %r, expected %r" % (key, got.get(key), v["expected_" + key]))
        label = name + ("  [mandatory: %s]" % MANDATORY[name] if name in MANDATORY else "")
        if bad:
            failures.append(name)
            print("FAIL " + label)
            for b in bad:
                print("       " + b)
        else:
            print("ok   " + label)

    with open(os.path.join(streams_dir, "expected.json"), "r", encoding="utf-8") as fh:
        index = json.load(fh)
    print("== stream fixtures (%s)" % os.path.relpath(os.path.join(streams_dir, "expected.json"), root))
    for c in index["cases"]:
        name = c["file"] + (" [strict]" if c.get("strict") else "")
        label = name
        if c["file"] in MANDATORY_STREAMS:
            label += "  [mandatory: %s]" % MANDATORY_STREAMS[c["file"]]
        args = ["verify", os.path.join(streams_dir, c["file"])]
        if c.get("pubkey"):
            args += ["--pubkey", os.path.normpath(os.path.join(streams_dir, c["pubkey"]))]
        if c.get("require_signatures"):
            args.append("--require-signatures")
        if c.get("strict"):
            args.append("--strict")
        args.append("--json")
        rc, out, err = run(args)
        rep, problem = parse(out, err, "verify")
        bad = []
        if problem:
            bad.append(problem)
        else:
            want_rc = 0 if c["ok"] else 1
            if rc != want_rc:
                bad.append("exit code %d, expected %d" % (rc, want_rc))
            for key in ("ok", "records", "restarts"):
                if rep.get(key) != c[key]:
                    bad.append("%s %r, expected %r" % (key, rep.get(key), c[key]))
            got = []
            for f in rep.get("findings") or []:
                pair = [f.get("index"), f.get("class")]
                if pair not in got:
                    got.append(pair)
            want = [[f["index"], f["class"]] for f in c["findings"]]
            if got != want:
                bad.append("findings %s, expected %s" % (got, want))
            results = rep.get("results") or []
            for key in ("state", "profile_state"):
                got_states = [r.get(key) for r in results]
                if got_states != c[key + "s"]:
                    bad.append("%ss %s, expected %s" % (key, got_states, c[key + "s"]))
        if bad:
            failures.append(name)
            print("FAIL " + label)
            for b in bad:
                print("       " + b)
        else:
            print("ok   " + label)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

total = len(data["vectors"]) + len(index["cases"])
print()
if failures:
    print("NOT CONFORMANT: %d of %d checks failed (suite %s): %s" % (len(failures), total, suite, ", ".join(failures)))
    sys.exit(1)
print("conformant: %d vectors and %d stream cases of trail.evidence/1, format 0.2 (suite %s)" % (len(data["vectors"]), len(index["cases"]), suite))
PYEOF
