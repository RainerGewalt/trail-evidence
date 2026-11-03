#!/usr/bin/env python3
"""Validate JSON Lines journals (and the vector records) against the schema.

Uses the ``jsonschema`` package when it is installed, preferring its
Draft 2020-12 validator and falling back to Draft 7 (the schema avoids
constructs Draft 7 cannot read, except dependentRequired, which this script
checks by hand). Without ``jsonschema`` it falls back to the structural
checks of the Python reference implementation so that the examples are still
checked everywhere.

A record that names a profile of the registry (profiles/) has its payload
validated against that profile's schema as well, with the same validator.
That is an independent check of the profile subset the verifiers implement.

Usage: validate_schema.py [--vectors testdata/vectors.json] FILE.jsonl ...
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCHEMA = os.path.join(ROOT, "schema", "trail-evidence-1.schema.json")
PROFILES = os.path.join(ROOT, "profiles")
sys.path.insert(0, os.path.join(ROOT, "python"))

from trail_evidence import record as rec  # noqa: E402
from trail_evidence import registry as reg  # noqa: E402


def make_validator(schema):
    try:
        import jsonschema
    except ImportError:
        return None, "jsonschema not installed; structural checks only"
    cls = getattr(jsonschema, "Draft202012Validator", None)
    name = "Draft 2020-12"
    if cls is None:
        cls = jsonschema.Draft7Validator
        name = "Draft 7 (fallback)"
    cls.check_schema(schema)
    try:
        from importlib.metadata import version
        ver = version("jsonschema")
    except Exception:  # Python < 3.8 or a vendored copy
        ver = getattr(jsonschema, "__version__", "?")
    return cls(schema), f"jsonschema {ver}, {name}"


def dependent_required(record):
    problems = []
    if "chain_restart" in record and "anchor_hash" not in record:
        problems.append("chain_restart requires anchor_hash")
    if "anchor_hash" in record and "chain_restart" not in record:
        problems.append("anchor_hash requires chain_restart")
    return problems


def load_profiles(validator):
    """Return {profile id: validate(payload) -> list of messages}."""
    out = {}
    for name in sorted(os.listdir(PROFILES)):
        d = os.path.join(PROFILES, name)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".schema.json"):
                continue
            pid = name + "/" + f[: -len(".schema.json")]
            with open(os.path.join(d, f), "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            if validator is not None:
                v = type(validator)(doc)
                out[pid] = lambda payload, v=v: [e.message for e in sorted(v.iter_errors(payload), key=str)]
            else:
                r = reg.Registry({pid: json.dumps(doc).encode("utf-8")})
                out[pid] = lambda payload, r=r, pid=pid: r.validate(pid, payload)[1]
    return out


def check_record(validator, record, expect_valid=True):
    problems = []
    if validator is not None:
        problems += [e.message for e in sorted(validator.iter_errors(record), key=str)]
        problems += dependent_required(record)
    else:
        problems += rec.decode_problems(record) or rec.validate_structure(record)
    return problems


def check_profile(profiles, record):
    """Problems of the payload against the record's profile, if the registry has it."""
    check = profiles.get(record.get("profile")) if isinstance(record.get("profile"), str) else None
    if check is None or "payload" not in record:
        return []
    return ["profile %s: %s" % (record["profile"], m) for m in check(record["payload"])]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="JSON Lines journals")
    ap.add_argument("--vectors", help="also check the records inside a vectors.json")
    args = ap.parse_args(argv)
    with open(SCHEMA, "r", encoding="utf-8") as fh:
        schema = json.load(fh)
    validator, how = make_validator(schema)
    profiles = load_profiles(validator)
    print(f"schema validation via {how}; profiles: {', '.join(sorted(profiles)) or 'none'}")
    failures = 0
    for path in args.files:
        skipped = 0
        with open(path, "r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                record = json.loads(line)
                if isinstance(record, dict) and rec.foreign_schema(record) is not None:
                    # Names another format or major version: outside the
                    # scope of this schema (SPEC.md section 6.1).
                    skipped += 1
                    continue
                problems = check_record(validator, record) + check_profile(profiles, record)
                if problems:
                    failures += 1
                    print(f"FAIL {path}:{n}: " + "; ".join(problems))
        print(f"ok   {path}" + (f" ({skipped} record(s) outside the scope skipped)" if skipped else ""))
    if args.vectors:
        with open(args.vectors, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for v in data["vectors"]:
            problems = check_record(validator, v["record"])
            profile_problems = check_profile(profiles, v["record"])
            # Vectors that are invalid because of a hash defect are still
            # schema-valid; only vectors flagged schema_invalid may fail the
            # record schema, and only those flagged profile_invalid the
            # profile schema. Both must fail where they are flagged.
            expected = v.get("expected_error")
            if bool(problems) != (expected == "schema_invalid"):
                failures += 1
                print(f"FAIL vector {v['name']}: expected_error {expected}, schema says " + ("; ".join(problems) or "valid"))
            if bool(profile_problems) != (expected == "profile_invalid"):
                failures += 1
                print(f"FAIL vector {v['name']}: expected_error {expected}, profile schema says " + ("; ".join(profile_problems) or "valid"))
        print(f"ok   {args.vectors} ({len(data['vectors'])} records)")
    if failures:
        print(f"{failures} record(s) failed schema validation", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
