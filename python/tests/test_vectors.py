import json
import os
import unittest

from trail_evidence import (
    GENESIS_HASH,
    MAX_SEQ,
    NO_POLICY,
    check_record,
    compute_hashes,
    key_id,
    parse_public_key,
    seal,
    sign,
    verify_record,
    verify_signature,
    verify_stream,
)
from trail_evidence import record as rec
from trail_evidence import registry

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VECTORS = os.path.join(ROOT, "testdata", "vectors.json")
STREAMS = os.path.join(ROOT, "testdata", "streams")
EXAMPLES = os.path.join(ROOT, "examples")
PROFILES = os.path.join(ROOT, "profiles")


def load_vectors():
    with open(VECTORS, "r", encoding="utf-8") as fh:
        return json.load(fh)


class Vectors(unittest.TestCase):
    def test_reproduce_all_vectors(self):
        data = load_vectors()
        self.assertGreaterEqual(len(data["vectors"]), 8)
        by_name = {}
        for v in data["vectors"]:
            with self.subTest(v["name"]):
                h = compute_hashes(v["record"])
                self.assertEqual(h["payload_jcs"].decode("utf-8"), v["expected_payload_jcs"])
                self.assertEqual(h["content_hash"], v["expected_content_hash"])
                self.assertEqual(h["core_jcs"].decode("utf-8"), v["expected_core_jcs"])
                self.assertEqual(h["chain_hash"], v["expected_chain_hash"])
                c = check_record(json.dumps(v["record"], ensure_ascii=False))
                record, findings = c.record, c.findings
                self.assertIsNotNone(record)
                self.assertEqual((c.state, c.profile_state), (v["expected_state"], v["expected_profile_state"]))
                classes = [f.cls for f in findings if f.severity == rec.ERROR]
                notices = [f.cls for f in findings if f.severity == rec.NOTICE]
                self.assertEqual(notices, v.get("expected_notices", []))
                if v["expected_valid"]:
                    self.assertEqual(classes, [], findings)
                else:
                    self.assertIn(v["expected_error"], classes)
                by_name[v["name"]] = v["expected_chain_hash"]
        self.assertEqual(by_name["context-absent"], by_name["context-present"])
        self.assertNotEqual(by_name["genesis-minimal"], by_name["second-chained"])

    def test_signed_vector(self):
        data = load_vectors()
        seed = bytes.fromhex(data["test_key"]["seed_hex"])
        pub = bytes.fromhex(data["test_key"]["public_hex"])
        self.assertEqual(key_id(pub), data["test_key"]["key_id"])
        signed = next(v for v in data["vectors"] if v["name"] == "signed")
        record = signed["record"]
        self.assertIsNone(verify_signature(pub, record["chain_hash"], record["signature"]))
        self.assertIsNotNone(verify_signature(bytes(32), record["chain_hash"], record["signature"]))
        clone = dict(record)
        sign(clone, seed)
        self.assertEqual(clone["signature"], record["signature"])


class StreamFixtures(unittest.TestCase):
    def test_expected_findings(self):
        self.check_index(STREAMS)

    def test_tampered_examples(self):
        self.check_index(os.path.join(EXAMPLES, "tampered"))

    def check_index(self, directory):
        with open(os.path.join(directory, "expected.json"), "r", encoding="utf-8") as fh:
            index = json.load(fh)
        self.assertTrue(index["cases"])
        for case in index["cases"]:
            allow = case.get("allow_incomplete", False)
            known = case.get("require_known_profiles", False)
            with self.subTest(case["file"], allow_incomplete=allow, require_known_profiles=known):
                pub = None
                if case.get("pubkey"):
                    pub = parse_public_key(os.path.join(directory, case["pubkey"]))
                # Binary mode, like the CLI: lines end at a line feed only and
                # a line that is not UTF-8 is one invalid record (SPEC.md section 2).
                with open(os.path.join(directory, case["file"]), "rb") as fh:
                    report = verify_stream(fh, pub, case.get("require_signatures", False), allow, known)
                self.assertEqual(report.ok, case["ok"], report.summary())
                self.assertEqual(report.verdict, case["verdict"])
                self.assertEqual(report.exit_code(), case["exit_code"])
                self.assertEqual(report.verdict == rec.VERDICT_INVALID, report.errors > 0)
                self.assertEqual((report.allow_incomplete, report.require_known_profiles), (allow, known))
                self.assertEqual(report.records, case["records"])
                self.assertEqual(report.restarts, case["restarts"])
                got = []
                for f in report.findings:
                    pair = (f.index, f.cls)
                    if pair not in got:
                        got.append(pair)
                want = [(f["index"], f["class"]) for f in case["findings"]]
                self.assertEqual(got, want)
                self.assertEqual([r.index for r in report.results], list(range(report.records)))
                self.assertEqual([r.state for r in report.results], case["states"])
                self.assertEqual([r.profile_state for r in report.results], case["profile_states"])
                for state in rec.STATES:
                    self.assertEqual(report.states[state], case["states"].count(state), state)


class Examples(unittest.TestCase):
    def test_examples_verify(self):
        files = sorted(f for f in os.listdir(EXAMPLES) if f.endswith(".jsonl"))
        self.assertGreaterEqual(len(files), 4)
        for name in files:
            with self.subTest(name):
                with open(os.path.join(EXAMPLES, name), "r", encoding="utf-8") as fh:
                    report = verify_stream(fh)
                self.assertTrue(report.ok, report.to_dict())
                self.assertTrue(3 <= report.records <= 5)


class Sealing(unittest.TestCase):
    def base(self):
        return {
            "producer": {"kind": "other", "id": "t", "version": "1"},
            "stream_id": "t",
            "seq": 0,
            "event_type": "test.seal.roundtrip",
            "time": {"recorded_at": "2026-11-02T00:00:00.000Z", "source": "system"},
            "actor": {"auth": "none"},
            "policy": dict(NO_POLICY),
            "payload": {"k": [1, 2.5, "x"]},
            "context": {"ignored": True},
        }

    def test_round_trip_and_context(self):
        r = seal(self.base(), GENESIS_HASH)
        record, findings = verify_record(json.dumps(r))
        self.assertEqual(findings, [])
        r2 = self.base()
        del r2["context"]
        seal(r2, GENESIS_HASH)
        self.assertEqual(r2["chain_hash"], r["chain_hash"])

    def test_restart_rules(self):
        r = seal(self.base(), GENESIS_HASH)
        r3 = self.base()
        r3["chain_restart"] = True
        r3["anchor_hash"] = r["chain_hash"]
        with self.assertRaises(ValueError):
            seal(r3, GENESIS_HASH)
        seal(r3, r["chain_hash"])
        r4 = self.base()
        r4["anchor_hash"] = r["chain_hash"]
        with self.assertRaises(ValueError):
            seal(r4, GENESIS_HASH)

    def test_number_precision_notice(self):
        r = self.base()
        r["payload"] = {"ok": 9007199254740992, "big": 9007199254740993, "neg": -(2**60), "f": 1e21, "s": "9007199254740993"}
        seal(r, GENESIS_HASH)
        _, findings = verify_record(json.dumps(r))
        self.assertEqual([(f.cls, f.severity) for f in findings], [(rec.NUMBER_PRECISION, rec.NOTICE)])
        self.assertIn("2 integer(s)", findings[0].message)

    def test_schema_checks(self):
        r = seal(self.base(), GENESIS_HASH)
        mutations = [
            lambda d: d.__setitem__("extra", 1),
            lambda d: d["producer"].__setitem__("x", 1),
            lambda d: d["time"].__setitem__("source", "wall-clock"),
            lambda d: d.__setitem__("event_type", "Created"),
            lambda d: d.__setitem__("prev_hash", "SHA256:" + "0" * 64),
            lambda d: d["time"].__setitem__("recorded_at", "2026-11-02T00:00:00Z"),
            lambda d: d.__setitem__("seq", -1),
            lambda d: d.__setitem__("seq", 1.0),
            lambda d: d.__setitem__("seq", "-1"),
            lambda d: d.__setitem__("seq", "00"),
            lambda d: d.__setitem__("seq", str(MAX_SEQ + 1)),
            lambda d: d.__setitem__("seq", True),
            lambda d: d.__delitem__("seq"),
            lambda d: d.__setitem__("chain_restart", False),
            lambda d: d.__setitem__("profile", "example.measurement"),
            lambda d: d.__setitem__("profile", 7),
            lambda d: d.__setitem__("schema", "Trail Evidence"),
        ]
        for i, m in enumerate(mutations):
            with self.subTest(i):
                d = json.loads(json.dumps(r))
                m(d)
                _, findings = verify_record(d)
                self.assertIn(rec.SCHEMA_INVALID, [f.cls for f in findings])
        for raw in ("[1,2]", "not json", "", '{"a":NaN}', "Infinity"):
            record, findings = verify_record(raw)
            self.assertIsNone(record)
            self.assertEqual(findings[0].cls, rec.SCHEMA_INVALID)

    def test_seq_forms(self):
        r = seal(self.base(), GENESIS_HASH)
        self.assertEqual(r["seq"], "0")
        text = json.dumps(r)
        cases = [
            ('"0"', True, False), (f'"{MAX_SEQ}"', True, False), ('"9007199254740993"', True, False),
            ('"\\u0037"', True, False), ("7", True, True), (str(MAX_SEQ), True, True),
            (str(MAX_SEQ + 1), False, False), (f'"{MAX_SEQ + 1}"', False, False), ('"007"', False, False),
            ('""', False, False), ('"7.0"', False, False), ("-0", False, False), ("0.0", False, False),
            ("1e2", False, False), ("-1", False, False),
        ]
        for lit, usable, legacy in cases:
            with self.subTest(lit):
                c = check_record(text.replace('"seq": "0"', '"seq": ' + lit, 1))
                classes = [f.cls for f in c.findings]
                self.assertEqual(rec.SCHEMA_INVALID not in classes, usable, classes)
                self.assertEqual(rec.LEGACY_INTEGER_SEQ in classes, legacy, classes)
                self.assertEqual(c.seq.ok, usable)

    def test_seal_normalises_seq(self):
        r = self.base()
        r["seq"] = MAX_SEQ
        seal(r, GENESIS_HASH)
        self.assertEqual(r["seq"], str(MAX_SEQ))
        for bad in (-1, MAX_SEQ + 1, "01", 1.0, True):
            r = self.base()
            r["seq"] = bad
            with self.assertRaises(ValueError):
                seal(r, GENESIS_HASH)


class Profiles(unittest.TestCase):
    def test_package_data_matches_registry(self):
        want = {}
        for name in sorted(os.listdir(PROFILES)):
            d = os.path.join(PROFILES, name)
            if not os.path.isdir(d):
                continue
            for f in os.listdir(d):
                if f.endswith(".schema.json"):
                    with open(os.path.join(d, f), "rb") as fh:
                        want[name + "/" + f[: -len(".schema.json")]] = fh.read()
        self.assertTrue(want)
        self.assertEqual(registry.profiles(), sorted(want))
        for pid, raw in want.items():
            self.assertEqual(registry.profile_schema(pid), raw, f"{pid}: run scripts/profiles.py --write")

    def test_examples(self):
        found = 0
        for name in sorted(os.listdir(PROFILES)):
            d = os.path.join(PROFILES, name)
            if not os.path.isdir(d):
                continue
            for f in sorted(os.listdir(d)):
                if not f.endswith(".examples.json"):
                    continue
                found += 1
                with open(os.path.join(d, f), "r", encoding="utf-8") as fh:
                    ex = rec._loads(fh.read())
                self.assertTrue(ex["valid"] and ex["invalid"])
                for case in ex["valid"]:
                    with self.subTest(ex["profile"], case=case["description"]):
                        self.assertEqual(registry.validate_payload(ex["profile"], case["payload"]), (True, []))
                for case in ex["invalid"]:
                    with self.subTest(ex["profile"], case=case["description"]):
                        known, problems = registry.validate_payload(ex["profile"], case["payload"])
                        self.assertTrue(known)
                        self.assertTrue(problems)
        self.assertGreater(found, 0)
        self.assertEqual(registry.validate_payload("example.measurement/2", {}), (False, []))

    def test_journals(self):
        found = 0
        for name in sorted(os.listdir(PROFILES)):
            d = os.path.join(PROFILES, name)
            if not os.path.isdir(d):
                continue
            for f in sorted(os.listdir(d)):
                if not f.endswith(".journal.jsonl"):
                    continue
                found += 1
                with open(os.path.join(d, f), "r", encoding="utf-8") as fh:
                    report = verify_stream(fh, require_known_profiles=True)
                self.assertTrue(report.ok, report.summary())
                self.assertEqual(report.verdict, rec.VERDICT_VALID)
                self.assertEqual(report.states[rec.VALID], report.records)
                self.assertEqual(report.profile_states[rec.VALID], report.records)
        self.assertGreater(found, 0)

    def test_subset_rejects_other_keywords(self):
        for doc in ({"type": "object", "additionalProperties": False}, {"enum": [1]}, {"type": "date"},
                    {"required": "a"}, {"properties": []}, []):
            with self.assertRaises(ValueError):
                registry.compile_schema(doc)


KEY = parse_public_key(os.path.join(ROOT, "testdata", "keys", "test-ed25519.pub"))
OTHER_KEY = bytes.fromhex("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")  # seed 0x42 repeated; signed no fixture


class Summary(unittest.TestCase):
    def test_lines(self):
        cases = [
            ("valid-chain.jsonl", {}, "VALID: 3 record(s) in 1 stream(s), hash chain intact"),
            ("seq-gap.jsonl", {}, "INCOMPLETE: 4 record(s) in 1 stream(s), no invalid record, 1 unknown"),
            ("seq-gap.jsonl", {"allow_incomplete": True}, "INCOMPLETE (allowed): 4 record(s) in 1 stream(s), no invalid record, 1 unknown"),
            ("outside-scope.jsonl", {}, "INCOMPLETE: 4 record(s) in 1 stream(s), hash chain intact, 2 outside scope"),
            ("seq-mismatch.jsonl", {}, "INVALID: 3 record(s) in 1 stream(s), 1 error(s)"),
            ("profile-unknown.jsonl", {}, "VALID: 3 record(s) in 1 stream(s), hash chain intact, 2 with unknown profile (payload not checked)"),
            ("profile-unknown.jsonl", {"require_known_profiles": True}, "INCOMPLETE: 3 record(s) in 1 stream(s), hash chain intact, 2 with unknown profile (payload not checked)"),
            # What was not checked, word for word as in Go and JavaScript.
            ("signed.jsonl", {}, "VALID: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), signatures not checked (no key)"),
            ("signed.jsonl", {"public_key": KEY, "require_signatures": True}, "VALID: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), 3 signature(s) verified"),
            ("signatures-stripped.jsonl", {"public_key": KEY}, "VALID: 3 record(s) in 1 stream(s), hash chain intact, no record is signed"),
            # Every signature fails with another producer's key: checked, none verified.
            ("signed.jsonl", {"public_key": OTHER_KEY}, "INVALID: 3 record(s) in 1 stream(s), 3 error(s), 3 signed record(s), 0 signature(s) verified"),
            ("signature-invalid.jsonl", {"public_key": KEY, "require_signatures": True}, "INVALID: 3 record(s) in 1 stream(s), 2 error(s), 2 signed record(s), 1 signature(s) verified, 1 unsigned record(s)"),
            ("../../examples/tampered/signature-invalid.jsonl", {}, "VALID: 4 record(s) in 1 stream(s), hash chain intact, 4 signed record(s), signatures not checked (no key)"),
            ("../../examples/tampered/signature-invalid.jsonl", {"public_key": KEY}, "INVALID: 4 record(s) in 1 stream(s), 2 error(s), 4 signed record(s), 2 signature(s) verified"),
        ]
        for name, opts, want in cases:
            with open(os.path.join(STREAMS, name), "rb") as fh:
                self.assertEqual(verify_stream(fh, **opts).summary(), want)

    def test_cli_exit_codes(self):
        from trail_evidence.__main__ import main
        import contextlib
        import io
        for args, want in (
            (["valid-chain.jsonl"], 0), (["seq-mismatch.jsonl"], 1), (["seq-gap.jsonl"], 3),
            (["seq-gap.jsonl", "--allow-incomplete"], 0), (["profile-unknown.jsonl"], 0),
            (["profile-unknown.jsonl", "--require-known-profiles", "--allow-incomplete"], 3),
        ):
            with self.subTest(args):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["verify", os.path.join(STREAMS, args[0])] + args[1:]), want)


class InputErrors(unittest.TestCase):
    """A journal that cannot be read gets no verdict and no report (exit 2);
    an empty journal is incomplete, also with --allow-incomplete (SPEC.md 6.4)."""

    def run_cli(self, args):
        from trail_evidence.__main__ import main
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["verify"] + args)
        return code, out.getvalue(), err.getvalue()

    def test_read_errors(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            unreadable = os.path.join(d, "unreadable.jsonl")
            with open(unreadable, "w") as fh:
                fh.write("{}\n")
            os.chmod(unreadable, 0)
            paths = {"directory": d, "missing file": os.path.join(d, "missing.jsonl")}
            try:
                open(unreadable, "rb").close()  # running as root: permissions do not apply
            except OSError:
                paths["file without read permission"] = unreadable
            for name, path in paths.items():
                for extra in ([], ["--json"], ["--allow-incomplete", "--json"]):
                    with self.subTest(name, extra=extra):
                        code, out, err = self.run_cli([path] + extra)
                        self.assertEqual((code, out), (2, ""))
                        self.assertTrue(err)

    def test_read_error_mid_journal(self):
        def lines():
            with open(os.path.join(EXAMPLES, "transfer-worker.jsonl"), "rb") as fh:
                yield fh.readline()
            raise OSError("disk read failed")
        with self.assertRaises(OSError):
            verify_stream(lines(), allow_incomplete=True)

    def test_empty_journal(self):
        import tempfile
        for content in (b"", b"\n \n\t\r\n"):
            for allow in (False, True):
                with self.subTest(content=content, allow=allow):
                    report = verify_stream(iter(content.splitlines(keepends=True)), allow_incomplete=allow)
                    self.assertEqual((report.ok, report.verdict, report.exit_code()), (False, rec.VERDICT_INCOMPLETE, 3))
                    self.assertEqual(report.summary(), "INCOMPLETE: 0 record(s) in 0 stream(s), no record: nothing was verified")
        with tempfile.TemporaryDirectory() as d:
            empty = os.path.join(d, "empty.jsonl")
            open(empty, "wb").close()
            for extra in ([], ["--allow-incomplete"]):
                code, out, _ = self.run_cli([empty] + extra)
                self.assertEqual(code, 3)
                self.assertTrue(out.startswith("INCOMPLETE: 0 record(s)"), out)


if __name__ == "__main__":
    unittest.main()
