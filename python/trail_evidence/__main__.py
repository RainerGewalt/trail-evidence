"""Command line interface: python -m trail_evidence <command> ..."""

from __future__ import annotations

import argparse
import json
import sys

from . import record as rec
from .jcs import canonicalize
from .registry import profiles


def _dump(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


def cmd_verify(args: argparse.Namespace) -> int:
    pub = None
    if args.pubkey:
        try:
            pub = rec.parse_public_key(args.pubkey)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
    if args.require_signatures and pub is None:
        print("--require-signatures needs --pubkey", file=sys.stderr)
        return 2
    try:
        # Binary mode: lines end at a line feed only, and each line is
        # decoded on its own (SPEC.md section 2).
        if args.file == "-":
            report = rec.verify_stream(sys.stdin.buffer, pub, args.require_signatures, args.allow_incomplete, args.require_known_profiles)
        else:
            with open(args.file, "rb") as fh:
                report = rec.verify_stream(fh, pub, args.require_signatures, args.allow_incomplete, args.require_known_profiles)
    except OSError as exc:
        # A journal that cannot be read gets no verdict and no report.
        print(f"cannot read {args.file}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(_dump(report.to_dict()))
    else:
        print(report.summary())
        for f in report.findings:
            seq = "-" if f.seq is None else str(f.seq)
            sid = f.stream_id or ""
            print(f'  {f.severity:<7} {f.cls:<17} record #{f.index} (line {f.line}, stream "{sid}", seq {seq}): {f.message}')
    return report.exit_code()


def cmd_hash(args: argparse.Namespace) -> int:
    try:
        if args.file == "-":
            raw = sys.stdin.buffer.read()
        else:
            with open(args.file, "rb") as fh:
                raw = fh.read()
    except OSError as exc:
        print(exc, file=sys.stderr)
        return 2
    parsed, problem = rec._parse_record(raw.strip(rec.JSON_WHITESPACE.encode()))
    if parsed is None:
        print(problem, file=sys.stderr)
        return 2
    try:
        h = rec.compute_hashes(parsed)
    except (TypeError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2
    c = rec.check_record(raw)
    out = {
        "payload_jcs": h["payload_jcs"].decode("utf-8"),
        "content_hash": h["content_hash"],
        "core_jcs": h["core_jcs"].decode("utf-8"),
        "chain_hash": h["chain_hash"],
        "state": c.state,
        "profile_state": c.profile_state,
    }
    if c.record is not None:
        out["recorded_content_hash"] = c.record.get("content_hash")
        out["recorded_chain_hash"] = c.record.get("chain_hash")
        out["matches"] = c.record.get("content_hash") == h["content_hash"] and c.record.get("chain_hash") == h["chain_hash"]
    if c.findings:
        out["findings"] = [f.to_dict() for f in c.findings]
    print(_dump(out))
    return 1 if out.get("matches") is False else 0


def cmd_check_vectors(args: argparse.Namespace) -> int:
    """Recompute every vector in a vectors.json and compare byte for byte."""
    with open(args.file, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    failures = 0
    for v in data["vectors"]:
        h = rec.compute_hashes(v["record"])
        got = {
            "expected_payload_jcs": h["payload_jcs"].decode("utf-8"),
            "expected_content_hash": h["content_hash"],
            "expected_core_jcs": h["core_jcs"].decode("utf-8"),
            "expected_chain_hash": h["chain_hash"],
        }
        bad = [k for k, val in got.items() if v[k] != val]
        c = rec.check_record(v["record"])
        findings = c.findings
        classes = {f.cls for f in findings if f.severity == rec.ERROR}
        notices = [f.cls for f in findings if f.severity == rec.NOTICE]
        if (c.state, c.profile_state) != (v.get("expected_state"), v.get("expected_profile_state")):
            bad.append(f"state:{c.state}/{c.profile_state}")
        if notices != v.get("expected_notices", []):
            bad.append("notices:" + ",".join(notices))
        if v["expected_valid"] and classes:
            bad.append("findings:" + ",".join(sorted(classes)))
        if not v["expected_valid"] and v.get("expected_error") not in classes:
            bad.append("missing:" + str(v.get("expected_error")))
        status = "ok " if not bad else "BAD"
        print(f"{status} {v['name']}" + (f"  ({', '.join(bad)})" if bad else ""))
        failures += bool(bad)
    pub = bytes.fromhex(data["test_key"]["public_hex"])
    if rec.key_id(pub) != data["test_key"]["key_id"]:
        print("BAD test key id")
        failures += 1
    if failures:
        print(f"{failures} vector(s) failed", file=sys.stderr)
        return 1
    print(f"all {len(data['vectors'])} vectors reproduced")
    return 0


def cmd_canon(args: argparse.Namespace) -> int:
    raw = sys.stdin.read() if args.file == "-" else open(args.file, "r", encoding="utf-8").read()
    sys.stdout.buffer.write(canonicalize(rec._loads(raw)))
    sys.stdout.buffer.write(b"\n")
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    for pid in profiles():
        print(pid)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m trail_evidence",
                                description="Trail Evidence Record v1 tools (Python reference implementation). "
                                            "verify exits 0 for valid (or incomplete with --allow-incomplete), "
                                            "1 for invalid, 2 for usage errors and journals that cannot be read "
                                            "(no verdict, no report), 3 for incomplete, also for a journal without a record.")
    sub = p.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="verify a JSON Lines journal")
    v.add_argument("file", help="journal path, or - for stdin")
    v.add_argument("--pubkey", help="Ed25519 public key as 64 hex characters or a file (hex or PEM)")
    v.add_argument("--require-signatures", action="store_true", help="treat unsigned records as signature_invalid")
    v.add_argument("--allow-incomplete", action="store_true",
                   help="accept the verdict incomplete (unknown or outside_scope records), for journals known to be incomplete")
    v.add_argument("--require-known-profiles", action="store_true",
                   help="count records with a profile this verifier does not know as incomplete")
    v.add_argument("--json", action="store_true", help="print the full report as JSON")
    v.set_defaults(func=cmd_verify)
    h = sub.add_parser("hash", help="recompute the hashes of one record")
    h.add_argument("file", help="record path, or - for stdin")
    h.set_defaults(func=cmd_hash)
    c = sub.add_parser("check-vectors", help="reproduce every vector of a vectors.json")
    c.add_argument("file")
    c.set_defaults(func=cmd_check_vectors)
    pr = sub.add_parser("profiles", help="list the profiles this verifier knows")
    pr.set_defaults(func=cmd_profiles)
    k = sub.add_parser("canon", help="print the JCS form of a JSON document")
    k.add_argument("file", help="JSON path, or - for stdin")
    k.set_defaults(func=cmd_canon)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
