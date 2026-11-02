#!/usr/bin/env python3
"""Validate JSON Lines journals (and the vector records) against the schema.

Uses the ``jsonschema`` package when it is installed, preferring its
Draft 2020-12 validator and falling back to Draft 7 (the schema avoids
constructs Draft 7 cannot read, except dependentRequired, which this script
checks by hand). Without ``jsonschema`` it falls back to the structural
checks of the Python reference implementation so that the examples are still
checked everywhere.

Usage: validate_schema.py [--vectors testdata/vectors.json] FILE.jsonl ...
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCHEMA = os.path.join(ROOT, "schema", "trail-evidence-1.schema.json")
sys.path.insert(0, os.path.join(ROOT, "python"))

from trail_evidence import record as rec  # noqa: E402


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
    return cls(schema), f"jsonschema {jsonschema.__version__}, {name}"


def dependent_required(record):
    problems = []
    if "chain_restart" in record and "anchor_hash" not in record:
        problems.append("chain_restart requires anchor_hash")
    if "anchor_hash" in record and "chain_restart" not in record:
        problems.append("anchor_hash requires chain_restart")
    return problems


def check_record(validator, record, expect_valid=True):
    problems = []
    if validator is not None:
        problems += [e.message for e in sorted(validator.iter_errors(record), key=str)]
        problems += dependent_required(record)
    else:
        problems += rec.decode_problems(record) or rec.validate_structure(record)
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="JSON Lines journals")
    ap.add_argument("--vectors", help="also check the records inside a vectors.json")
    args = ap.parse_args(argv)
    with open(SCHEMA, "r", encoding="utf-8") as fh:
        schema = json.load(fh)
    validator, how = make_validator(schema)
    print(f"schema validation via {how}")
    failures = 0
    for path in args.files:
        with open(path, "r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                problems = check_record(validator, json.loads(line))
                if problems:
                    failures += 1
                    print(f"FAIL {path}:{n}: " + "; ".join(problems))
        print(f"ok   {path}")
    if args.vectors:
        with open(args.vectors, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for v in data["vectors"]:
            problems = check_record(validator, v["record"])
            # Vectors that are invalid because of a hash defect are still
            # schema-valid; only vectors flagged schema_invalid may fail here.
            if problems and v.get("expected_error") != "schema_invalid":
                failures += 1
                print(f"FAIL vector {v['name']}: " + "; ".join(problems))
        print(f"ok   {args.vectors} ({len(data['vectors'])} records)")
    if failures:
        print(f"{failures} record(s) failed schema validation", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
