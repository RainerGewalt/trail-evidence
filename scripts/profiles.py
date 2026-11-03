#!/usr/bin/env python3
"""Check the profile registry and keep the verifiers' copies of it in step.

  scripts/profiles.py --check   check profiles/ and fail when a copy is stale
  scripts/profiles.py --write   check profiles/ and regenerate the copies

profiles/<name>/<major>.schema.json is the source. The verifiers read it
from copies, because none of them can load files from the repository root
at run time:

  go/evidence/profiles/<name>/<major>.schema.json             (go:embed)
  python/trail_evidence/profiles/<name>/<major>.schema.json   (package data)
  web/profiles.js                                             (script for the page)

The Go and Python copies are byte-for-byte copies; web/profiles.js holds the
same schemas as one JavaScript object. Each verifier's tests also compare its
copy with profiles/.

The check enforces the rules in profiles/README.md: naming, the JSON Schema
subset (type, required, properties, items and annotations), an examples file
with valid and invalid payloads that the Python verifier classifies as
stated, and a journal whose records all verify with profile state valid.
With the jsonschema package installed, the examples are also checked with a
full JSON Schema 2020-12 validator, which must agree.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REGISTRY = os.path.join(ROOT, "profiles")
GO_COPY = os.path.join(ROOT, "go", "evidence", "profiles")
PY_COPY = os.path.join(ROOT, "python", "trail_evidence", "profiles")
WEB_COPY = os.path.join(ROOT, "web", "profiles.js")
sys.path.insert(0, os.path.join(ROOT, "python"))

from trail_evidence import record as rec  # noqa: E402
from trail_evidence import registry as reg  # noqa: E402

NAME_RE = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$")
FILE_RE = re.compile(r"^([1-9][0-9]*)\.(schema\.json|examples\.json|journal\.jsonl)$")
SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"


def rel(path):
    return os.path.relpath(path, ROOT)


def load_registry(problems):
    """Return {id: schema bytes}, appending rule violations to problems."""
    schemas = {}
    for name in sorted(os.listdir(REGISTRY)):
        path = os.path.join(REGISTRY, name)
        if not os.path.isdir(path):
            if name != "README.md":
                problems.append("unexpected file %s" % rel(path))
            continue
        if not NAME_RE.match(name):
            problems.append("%s: profile name must match %s" % (rel(path), NAME_RE.pattern))
            continue
        majors = {}
        for f in sorted(os.listdir(path)):
            m = FILE_RE.match(f)
            if not m:
                problems.append("unexpected file %s" % rel(os.path.join(path, f)))
                continue
            majors.setdefault(m.group(1), set()).add(m.group(2))
        for major, kinds in sorted(majors.items()):
            pid = "%s/%s" % (name, major)
            for need in ("schema.json", "examples.json", "journal.jsonl"):
                if need not in kinds:
                    problems.append("%s: %s.%s is missing" % (pid, major, need))
            if "schema.json" in kinds:
                with open(os.path.join(path, major + ".schema.json"), "rb") as fh:
                    schemas[pid] = fh.read()
    return schemas


def check_schema(pid, raw, problems):
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        problems.append("%s: schema is not JSON: %s" % (pid, exc))
        return None
    try:
        reg.compile_schema(doc)
    except ValueError as exc:
        problems.append("%s: %s" % (pid, exc))
        return None
    if doc.get("$schema") != SCHEMA_URI:
        problems.append("%s: $schema must be %s" % (pid, SCHEMA_URI))
    if doc.get("title") != pid:
        problems.append("%s: title must be %r" % (pid, pid))
    if doc.get("type") != "object":
        problems.append("%s: the payload of a profile must be an object (type: object)" % pid)
    if not doc.get("description"):
        problems.append("%s: description is missing" % pid)
    return doc


def full_validator(doc):
    try:
        import jsonschema
    except ImportError:
        return None
    cls = getattr(jsonschema, "Draft202012Validator", None)
    if cls is None:
        return None
    cls.check_schema(doc)
    return cls(doc)


def check_examples(pid, doc, registry, problems):
    name, major = pid.split("/")
    path = os.path.join(REGISTRY, name, major + ".examples.json")
    if not os.path.exists(path):
        return 0
    with open(path, "r", encoding="utf-8") as fh:
        ex = rec._loads(fh.read())
    if ex.get("profile") != pid:
        problems.append("%s: profile must be %r" % (rel(path), pid))
    valid, invalid = ex.get("valid") or [], ex.get("invalid") or []
    if not valid or not invalid:
        problems.append("%s: needs at least one valid and one invalid payload" % rel(path))
    full = full_validator(doc) if doc is not None else None
    n = 0
    for want, cases in ((True, valid), (False, invalid)):
        for case in cases:
            n += 1
            known, errs = registry.validate(pid, case.get("payload"))
            if not known or (not errs) != want:
                problems.append("%s: %r is %s by the verifier, expected %s" % (
                    rel(path), case.get("description"), "accepted" if not errs else "rejected", "accepted" if want else "rejected"))
            if full is not None and full.is_valid(case.get("payload")) != want:
                problems.append("%s: %r: a full JSON Schema validator disagrees with the profile subset" % (rel(path), case.get("description")))
    return n


def check_journal(pid, problems):
    name, major = pid.split("/")
    path = os.path.join(REGISTRY, name, major + ".journal.jsonl")
    if not os.path.exists(path):
        return 0
    with open(path, "r", encoding="utf-8") as fh:
        report = rec.verify_stream(fh, strict=True)
    if not report.ok or report.profile_states[rec.VALID] != report.records:
        problems.append("%s: %s, profile states %s" % (rel(path), report.summary(), report.profile_states))
    if any(r.profile != pid for r in report.results):
        problems.append("%s: every record must carry the profile %s" % (rel(path), pid))
    return report.records


def render_web(schemas):
    entries = []
    for pid in sorted(schemas):
        doc = json.loads(schemas[pid].decode("utf-8"))
        body = json.dumps(doc, indent=2, ensure_ascii=False).replace("\n", "\n    ")
        entries.append("    %s: %s" % (json.dumps(pid), body))
    return (
        "/* Generated by scripts/profiles.py from profiles/<name>/<major>.schema.json.\n"
        " * Do not edit: change profiles/ and run scripts/profiles.py --write.\n"
        " * verify.js checks profile payloads against these schemas; in a browser\n"
        " * this script must be loaded before verify.js. */\n"
        "(function (root, factory) {\n"
        "  \"use strict\";\n"
        "  const registry = factory();\n"
        "  if (typeof module === \"object\" && module && module.exports) {\n"
        "    module.exports = registry;\n"
        "  } else {\n"
        "    root.TrailEvidenceProfiles = registry;\n"
        "  }\n"
        "})(typeof globalThis !== \"undefined\" ? globalThis : this, function () {\n"
        "  \"use strict\";\n"
        "  return {\n"
        + ",\n".join(entries) + "\n"
        "  };\n"
        "});\n"
    ).encode("utf-8")


def wanted_copies(schemas):
    files = {}
    for pid, raw in schemas.items():
        name, major = pid.split("/")
        for base in (GO_COPY, PY_COPY):
            files[os.path.join(base, name, major + ".schema.json")] = raw
    files[WEB_COPY] = render_web(schemas)
    return files


def existing_copies():
    found = set()
    for base in (GO_COPY, PY_COPY):
        for dirpath, _, filenames in os.walk(base):
            for f in filenames:
                found.add(os.path.join(dirpath, f))
    if os.path.exists(WEB_COPY):
        found.add(WEB_COPY)
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = ap.parse_args(argv)

    problems = []
    schemas = load_registry(problems)
    docs = {pid: check_schema(pid, raw, problems) for pid, raw in schemas.items()}
    try:
        registry = reg.Registry({pid: raw for pid, raw in schemas.items() if docs[pid] is not None})
    except ValueError as exc:
        problems.append(str(exc))
        registry = reg.Registry({})
    examples = sum(check_examples(pid, docs[pid], registry, problems) for pid in sorted(schemas))
    want = wanted_copies(schemas)
    stale = []
    for path, content in sorted(want.items()):
        try:
            with open(path, "rb") as fh:
                same = fh.read() == content
        except OSError:
            same = False
        if not same:
            stale.append(path)
    extra = sorted(existing_copies() - set(want))
    if args.write:
        for path in stale:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(want[path])
            print("wrote " + rel(path))
        for path in extra:
            os.remove(path)
            print("removed " + rel(path))
        stale, extra = [], []
    for path in stale:
        problems.append("%s is out of date (run scripts/profiles.py --write)" % rel(path))
    for path in extra:
        problems.append("%s is not in profiles/ (run scripts/profiles.py --write)" % rel(path))
    records = 0
    if not stale:
        reg.REGISTRY = registry  # the copies equal profiles/ now
        records = sum(check_journal(pid, problems) for pid in sorted(schemas))
    for p in problems:
        print("FAIL: " + p, file=sys.stderr)
    if problems:
        return 1
    how = "with jsonschema" if full_validator({"type": "object"}) is not None else "without jsonschema"
    print("ok: %d profile(s) (%s), %d example payload(s) %s, %d journal record(s), copies up to date" % (
        len(schemas), ", ".join(sorted(schemas)), examples, how, records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
