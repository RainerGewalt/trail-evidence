import json
import os
import unittest

from trail_evidence import (
    GENESIS_HASH,
    NO_POLICY,
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

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VECTORS = os.path.join(ROOT, "testdata", "vectors.json")
STREAMS = os.path.join(ROOT, "testdata", "streams")
EXAMPLES = os.path.join(ROOT, "examples")


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
                record, findings = verify_record(json.dumps(v["record"], ensure_ascii=False))
                self.assertIsNotNone(record)
                classes = [f.cls for f in findings]
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
        with open(os.path.join(STREAMS, "expected.json"), "r", encoding="utf-8") as fh:
            index = json.load(fh)
        self.assertTrue(index["cases"])
        for case in index["cases"]:
            with self.subTest(case["file"]):
                pub = None
                if case.get("pubkey"):
                    pub = parse_public_key(os.path.join(STREAMS, case["pubkey"]))
                with open(os.path.join(STREAMS, case["file"]), "r", encoding="utf-8") as fh:
                    report = verify_stream(fh, pub, case.get("require_signatures", False))
                self.assertEqual(report.ok, case["ok"], report.summary())
                self.assertEqual(report.records, case["records"])
                self.assertEqual(report.restarts, case["restarts"])
                got = []
                for f in report.findings:
                    pair = (f.index, f.cls)
                    if pair not in got:
                        got.append(pair)
                want = [(f["index"], f["class"]) for f in case["findings"]]
                self.assertEqual(got, want)


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
            lambda d: d.__setitem__("chain_restart", False),
        ]
        for i, m in enumerate(mutations):
            with self.subTest(i):
                d = json.loads(json.dumps(r))
                m(d)
                _, findings = verify_record(d)
                self.assertIn(rec.SCHEMA_INVALID, [f.cls for f in findings])
        for raw in ("[1,2]", "not json", ""):
            record, findings = verify_record(raw)
            self.assertIsNone(record)
            self.assertEqual(findings[0].cls, rec.SCHEMA_INVALID)


if __name__ == "__main__":
    unittest.main()
