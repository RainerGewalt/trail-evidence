#!/usr/bin/env python3
"""Keep docs/REASON_CODES.md in step with schema/reason-codes.json.

  scripts/reason_codes.py --check   validate the catalog and fail if the
                                    generated part of the Markdown is stale
  scripts/reason_codes.py --write   regenerate the tables in the Markdown

The catalog is documentation: no verifier checks payload.reason_code. This
script only checks the catalog itself: JSON Schema (when the jsonschema
package is installed), unique codes, namespace prefix, example reason_code,
and that the Markdown tables match the JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CATALOG = os.path.join(ROOT, "schema", "reason-codes.json")
SCHEMA = os.path.join(ROOT, "schema", "reason-codes.schema.json")
DOC = os.path.join(ROOT, "docs", "REASON_CODES.md")
BEGIN = "<!-- BEGIN GENERATED: scripts/reason_codes.py --write -->"
END = "<!-- END GENERATED -->"


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def problems(cat, schema):
    out = []
    try:
        import jsonschema  # optional
    except ImportError:
        jsonschema = None
    if jsonschema is not None:
        cls = getattr(jsonschema, "Draft202012Validator", None) or jsonschema.Draft7Validator
        for err in sorted(cls(schema).iter_errors(cat), key=lambda e: list(e.path)):
            out.append("schema: /%s: %s" % ("/".join(str(p) for p in err.path), err.message))
    seen = set()
    for c in cat.get("codes", []):
        code = c.get("code", "")
        if code in seen:
            out.append("duplicate code %s" % code)
        seen.add(code)
        if code.split(".", 1)[0] != c.get("namespace"):
            out.append("%s: prefix does not match namespace %r" % (code, c.get("namespace")))
        if c.get("example", {}).get("payload", {}).get("reason_code") != code:
            out.append("%s: example payload.reason_code differs" % code)
        allowed = set(cat.get("namespaces", {}).get(c.get("namespace"), {}).get("producer_kinds", []))
        extra = set(c.get("producer_kinds", [])) - allowed
        if extra:
            out.append("%s: producer kinds %s not listed for namespace" % (code, sorted(extra)))
    if len(seen) < 25:
        out.append("catalog has %d codes, at least 25 expected" % len(seen))
    return out


def compact(payload):
    p = {k: v for k, v in payload.items() if k != "reason_code"}
    return json.dumps(p, ensure_ascii=False, separators=(",", ":"))


def render(cat):
    lines = [BEGIN, ""]
    for ns, meta in cat["namespaces"].items():
        codes = [c for c in cat["codes"] if c["namespace"] == ns]
        lines.append("### `%s.*`" % ns)
        lines.append("")
        lines.append("%s Producer kinds: %s." % (meta["description"], ", ".join("`%s`" % k for k in meta["producer_kinds"])))
        lines.append("")
        lines.append("| Code | Severity | Meaning | Example |")
        lines.append("|---|---|---|---|")
        for c in codes:
            ex = c["example"]
            lines.append("| `%s` | %s | %s | `%s` with `%s` |" % (
                c["code"], c["severity"], c["meaning"].replace("|", "\\|"),
                ex["event_type"], compact(ex["payload"]).replace("|", "\\|")))
        lines.append("")
    lines.append("%d codes: %s." % (len(cat["codes"]), ", ".join(
        "%d %s" % (sum(1 for c in cat["codes"] if c["severity"] == s), s) for s in ("info", "warning", "error"))))
    lines.append("")
    lines.append(END)
    return "\n".join(lines)


def splice(doc, generated):
    if BEGIN not in doc or END not in doc:
        raise SystemExit("docs/REASON_CODES.md lacks the generated-section markers")
    head, rest = doc.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    return head + generated + tail


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = ap.parse_args(argv)

    cat = load(CATALOG)
    errs = problems(cat, load(SCHEMA))
    for e in errs:
        print("FAIL: " + e, file=sys.stderr)
    with open(DOC, "r", encoding="utf-8") as fh:
        doc = fh.read()
    want = splice(doc, render(cat))
    if args.write:
        if want != doc:
            with open(DOC, "w", encoding="utf-8") as fh:
                fh.write(want)
            print("wrote docs/REASON_CODES.md")
        return 1 if errs else 0
    if want != doc:
        print("FAIL: docs/REASON_CODES.md is out of date (run scripts/reason_codes.py --write)", file=sys.stderr)
        errs.append("stale doc")
    if errs:
        return 1
    print("ok: %d reason codes, docs/REASON_CODES.md up to date" % len(cat["codes"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
