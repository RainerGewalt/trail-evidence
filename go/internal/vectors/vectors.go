// Package vectors builds the test vectors, stream fixtures and example
// journals that the repository commits under testdata/ and examples/. The Go
// reference implementation generates them; the Python implementation (and any
// other) must reproduce every hash byte for byte.
package vectors

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/RainerGewalt/trail-evidence/go/evidence"
)

// TestKeySeedHex is the Ed25519 seed of the TEST KEY used for signed vectors.
// It is test vector 1 of RFC 8032, section 7.1, i.e. a publicly known key.
// Never use it for anything but tests.
const TestKeySeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

// TestKeyPublicHex is the public key that belongs to TestKeySeedHex.
const TestKeyPublicHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

// Vector is one canonicalisation and hashing test case.
type Vector struct {
	Name                string          `json:"name"`
	Description         string          `json:"description"`
	Record              json.RawMessage `json:"record"`
	ExpectedPayloadJCS  string          `json:"expected_payload_jcs"`
	ExpectedContentHash string          `json:"expected_content_hash"`
	ExpectedCoreJCS     string          `json:"expected_core_jcs"`
	ExpectedChainHash   string          `json:"expected_chain_hash"`
	ExpectedValid       bool            `json:"expected_valid"`
	ExpectedError       string          `json:"expected_error,omitempty"`
}

// File is the shape of testdata/vectors.json.
type File struct {
	Schema      string   `json:"schema"`
	GeneratedBy string   `json:"generated_by"`
	Note        string   `json:"note"`
	TestKey     TestKey  `json:"test_key"`
	Vectors     []Vector `json:"vectors"`
}

// TestKey documents the test signing key.
type TestKey struct {
	Note      string `json:"note"`
	SeedHex   string `json:"seed_hex"`
	PublicHex string `json:"public_hex"`
	KeyID     string `json:"key_id"`
}

// ExpectedFinding is one (index, class) pair a verifier must report. A
// fixture lists the distinct pairs in order of first occurrence; a verifier
// may report the same pair several times (for example one hash_mismatch for
// content_hash and one for chain_hash of the same record).
type ExpectedFinding struct {
	Index int    `json:"index"`
	Class string `json:"class"`
}

// StreamCase describes one fixture under testdata/streams.
type StreamCase struct {
	File              string            `json:"file"`
	Description       string            `json:"description"`
	PublicKey         string            `json:"pubkey,omitempty"`
	RequireSignatures bool              `json:"require_signatures,omitempty"`
	OK                bool              `json:"ok"`
	Records           int               `json:"records"`
	Restarts          int               `json:"restarts"`
	Findings          []ExpectedFinding `json:"findings"`
	Lines             []string          `json:"-"`
}

// Journal is one example journal under examples/.
type Journal struct {
	File  string
	Lines []string
}

// Output is everything the generator produces.
type Output struct {
	Vectors  File
	Streams  []StreamCase
	Examples []Journal
}

func mustKey() ed25519.PrivateKey {
	seed, err := hex.DecodeString(TestKeySeedHex)
	if err != nil {
		panic(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != TestKeyPublicHex {
		panic("test key public part does not match")
	}
	return priv
}

func base(kind, id, stream string, seq uint64, eventType, at string, payload string) evidence.Record {
	return evidence.Record{
		Schema:    evidence.Schema,
		Producer:  evidence.Producer{Kind: kind, ID: id, Version: "0.1.0"},
		StreamID:  stream,
		Seq:       seq,
		EventType: eventType,
		Time:      evidence.Time{RecordedAt: at, Source: evidence.TimeSourceSystem},
		Actor:     evidence.Actor{Auth: evidence.AuthNone},
		Policy:    evidence.NoPolicy,
		Payload:   json.RawMessage(payload),
	}
}

func seal(r *evidence.Record, prev string) {
	if err := evidence.Seal(r, prev); err != nil {
		panic(err)
	}
}

func encode(r *evidence.Record) string {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func vector(name, desc string, r *evidence.Record) Vector {
	raw := encode(r)
	return finishVector(name, desc, raw, true, "")
}

func finishVector(name, desc, raw string, valid bool, class string) Vector {
	h, err := evidence.ComputeHashes([]byte(raw))
	if err != nil {
		panic(err)
	}
	return Vector{
		Name:                name,
		Description:         desc,
		Record:              json.RawMessage(raw),
		ExpectedPayloadJCS:  string(h.PayloadJCS),
		ExpectedContentHash: h.ContentHash,
		ExpectedCoreJCS:     string(h.CoreJCS),
		ExpectedChainHash:   h.ChainHash,
		ExpectedValid:       valid,
		ExpectedError:       class,
	}
}

// Build returns the complete, deterministic generator output.
func Build() Output {
	priv := mustKey()
	pub := priv.Public().(ed25519.PublicKey)
	var out Output
	out.Vectors = File{
		Schema:      evidence.Schema,
		GeneratedBy: "github.com/RainerGewalt/trail-evidence/go (reference implementation)",
		Note:        "Every implementation MUST reproduce expected_payload_jcs, expected_content_hash, expected_core_jcs and expected_chain_hash byte for byte. For vectors with expected_valid=false the expected_* values are the correct ones and the record carries the defect.",
		TestKey: TestKey{
			Note:      "TEST KEY ONLY. This is RFC 8032 section 7.1 test vector 1 and is public knowledge. Never sign real evidence with it.",
			SeedHex:   TestKeySeedHex,
			PublicHex: TestKeyPublicHex,
			KeyID:     evidence.KeyID(pub),
		},
	}

	// Vector 1: genesis without optional fields.
	v1 := base(evidence.ProducerOther, "ref-producer", "vectors", 0, "test.record.created",
		"2026-11-02T08:00:00.000Z", `{"b":1,"a":"x"}`)
	seal(&v1, evidence.GenesisHash)
	out.Vectors.Vectors = append(out.Vectors.Vectors, vector("genesis-minimal",
		"First record of a stream: prev_hash is the genesis value, no optional members. Payload keys are given out of order and must be sorted by JCS.", &v1))

	// Vector 2: chained successor with optional sub-members.
	v2 := base(evidence.ProducerOther, "ref-producer", "vectors", 1, "test.record.created",
		"2026-11-02T08:00:01.000Z", `{"message":"second","count":2,"ok":true,"none":null}`)
	v2.Time.OccurredAt = "2026-11-02T08:00:00.950Z"
	v2.Time.ReadAt = "2026-11-02T08:00:00.990Z"
	v2.Actor = evidence.Actor{Auth: evidence.AuthOperatorToken, ID: "operator-7", Roles: []string{"auditor", "operator"}}
	v2.Policy = evidence.Policy{ID: "policy-a", Version: "3", Hash: evidence.HashBytes([]byte("policy-a v3")), Status: evidence.PolicyActive, Kind: "transfer-policy"}
	seal(&v2, v1.ChainHash)
	out.Vectors.Vectors = append(out.Vectors.Vectors, vector("second-chained",
		"Second record: prev_hash equals the chain_hash of genesis-minimal; seq is 1; optional time, actor and policy members are present and therefore part of the core.", &v2))

	// Vector 3: chain restart anchored at v2.
	v3 := base(evidence.ProducerOther, "ref-producer", "vectors", 0, "test.chain.restarted",
		"2026-11-02T09:00:00.000Z", `{"reason":"process restarted"}`)
	v3.ChainRestart = true
	v3.AnchorHash = v2.ChainHash
	seal(&v3, v2.ChainHash)
	out.Vectors.Vectors = append(out.Vectors.Vectors, vector("chain-restart",
		"Restart record: seq returns to 0, chain_restart is true, anchor_hash carries the last chain_hash of the previous segment and prev_hash equals anchor_hash. Both members are part of the core.", &v3))

	// Vectors 4 and 5: identical core, with and without context.
	v4 := base(evidence.ProducerSourceBridge, "bridge-01", "bridge-01/plc-7", 0, "source.value.observed",
		"2026-11-02T10:00:00.000Z", `{"native_node_id":"ns=2;s=Line1.Temp","entity_key":"line1/temp","value":"21.5","quality":"good"}`)
	v4.Time.OccurredAt = "2026-11-02T09:59:59.800Z"
	v4.Time.ReadAt = "2026-11-02T09:59:59.900Z"
	v4.Actor = evidence.Actor{Auth: evidence.AuthSelfDeclared, ID: "bridge-01"}
	v4.Policy = evidence.Policy{ID: "plc-7-addressspace", Version: "2026-10-30", Hash: evidence.HashBytes([]byte("inventory fingerprint")), Kind: "addressspace"}
	seal(&v4, evidence.GenesisHash)
	out.Vectors.Vectors = append(out.Vectors.Vectors, vector("context-absent",
		"Observation record without context. Compare with context-present: both must have the same chain_hash.", &v4))
	v5 := v4
	v5.Context = json.RawMessage(`{"source_type":"opcua","channel":"subscription","source_address":"opc.tcp://plc-7:4840","note":"context is informational and never hashed"}`)
	v5.CorrelationID = "corr-0001"
	v5.JobID = "job-42"
	v5.DecisionID = "dec-9"
	out.Vectors.Vectors = append(out.Vectors.Vectors, vector("context-present",
		"Same record as context-absent plus context, correlation_id, job_id and decision_id. None of these members is part of the core, so content_hash and chain_hash are unchanged.", &v5))

	// Vector 6: redaction.
	v6 := base(evidence.ProducerTransferWorker, "worker-01", "worker-01", 0, "transfer.job.result",
		"2026-11-02T11:00:00.000Z", `{"action":"copy","source":"sftp://files.example/in/report.csv","target":"s3://archive/2026/report.csv","status":"ok","credentials":{"user":"svc-transfer","password":"***"},"command_hash":"sha256:5f2b1b3d8a1c4b0e6b7d3f9a2c8e1d0f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d"}`)
	v6.Actor = evidence.Actor{Auth: evidence.AuthSelfDeclared, ID: "alice"}
	v6.Policy = evidence.Policy{ID: "archive-policy", Version: "7", Hash: evidence.HashBytes([]byte("archive-policy v7")), Status: evidence.PolicyApproved, Kind: "transfer-policy"}
	v6.Redaction = &evidence.Redaction{Fields: []string{"/credentials/password"}, Method: "mask"}
	seal(&v6, evidence.GenesisHash)
	out.Vectors.Vectors = append(out.Vectors.Vectors, vector("redaction",
		"The password was masked before content_hash was computed and the masked pointer is listed in redaction.fields. The redaction member itself is not part of the core.", &v6))

	// Vector 7: JCS edge cases.
	v7 := base(evidence.ProducerOther, "ref-producer", "jcs", 0, "test.jcs.edgecases",
		"2026-11-02T12:00:00.000Z",
		`{"z_last":"z","float_one":1.0,"int_one":1,"exp_big":1e21,"below_exp":123456789012345680000,"small":0.000001,"smaller":1e-7,"neg_zero":-0.0,"upper_exp":1E+2,"beyond_2_53":9007199254740993,"denormal":5e-324,"huge":1.5e300,"tenth":0.1,"neg":-42.25,"empty_obj":{},"empty_arr":[],"empty_str":"","nested":{"y":[1,{"b":2,"a":1}],"x":null},"ctrl":"tab\tnewline\ncr\rbs\bff\fnul\u0000unit\u001fdel\u007fquote\"backslash\\slash/","umlaut":"Füße und Größe","emoji":"🚀 Rakete","mixed":"αβγ 日本語 עברית","！":"fullwidth exclamation U+FF01","🚀":"rocket U+1F680 sorts before U+FF01 in UTF-16","€":"euro U+20AC","ä":"a umlaut U+00E4","Z":"upper Z sorts before lower a","a":"lower a"}`)
	seal(&v7, evidence.GenesisHash)
	out.Vectors.Vectors = append(out.Vectors.Vectors, vector("jcs-edge-cases",
		"Payload exercises RFC 8785: ES6 number formatting (1.0 -> 1, 1e21 -> 1e+21, -0.0 -> 0, 9007199254740993 -> 9007199254740992), minimal string escaping with lowercase \\u00xx, literal non-ASCII, and member sorting by UTF-16 code units (U+1F680 before U+FF01).", &v7))

	// Vector 8: signed.
	v8 := v2
	v8.StreamID = "signed"
	v8.Seq = 0
	seal(&v8, evidence.GenesisHash)
	if err := evidence.Sign(&v8, priv, ""); err != nil {
		panic(err)
	}
	out.Vectors.Vectors = append(out.Vectors.Vectors, vector("signed",
		"Record signed with the TEST KEY: Ed25519 over the ASCII bytes of the chain_hash string, sig as base64url without padding. The signature member is not part of the core.", &v8))

	// Vector 9: wrong chain_hash.
	bad := encode(&v2)
	tampered := strings.Replace(bad, `"chain_hash":"`+v2.ChainHash+`"`, `"chain_hash":"`+flipLast(v2.ChainHash)+`"`, 1)
	if tampered == bad {
		panic("tamper failed")
	}
	out.Vectors.Vectors = append(out.Vectors.Vectors, finishVector("invalid-chain-hash",
		"second-chained with the last hex digit of chain_hash changed. A verifier must report hash_mismatch; expected_chain_hash is the correct value.",
		tampered, false, evidence.ClassHashMismatch))

	// Vector 10: payload tampered after sealing.
	bad = encode(&v6)
	tampered = strings.Replace(bad, `"status":"ok"`, `"status":"failed"`, 1)
	if tampered == bad {
		panic("tamper failed")
	}
	out.Vectors.Vectors = append(out.Vectors.Vectors, finishVector("invalid-content-hash",
		"redaction with the payload altered after sealing. content_hash no longer matches, and because the core carries the recomputed content_hash, chain_hash differs as well. A verifier must report hash_mismatch.",
		tampered, false, evidence.ClassHashMismatch))

	out.Streams = buildStreams(priv)
	out.Examples = buildExamples()
	return out
}

func flipLast(h string) string {
	last := h[len(h)-1]
	if last == '0' {
		return h[:len(h)-1] + "1"
	}
	return h[:len(h)-1] + "0"
}

func chain(kind, id, stream string, eventType string, payloads ...string) []*evidence.Record {
	recs := make([]*evidence.Record, 0, len(payloads))
	prev := evidence.GenesisHash
	for i, p := range payloads {
		r := base(kind, id, stream, uint64(i), eventType, fmt.Sprintf("2026-11-02T13:00:%02d.000Z", i), p)
		seal(&r, prev)
		prev = r.ChainHash
		recs = append(recs, &r)
	}
	return recs
}

func lines(recs ...*evidence.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, encode(r))
	}
	return out
}

func buildStreams(priv ed25519.PrivateKey) []StreamCase {
	var cases []StreamCase
	ev := "test.stream.step"

	valid := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`, `{"n":2}`)
	cases = append(cases, StreamCase{File: "valid-chain.jsonl", Description: "Three correctly chained records.",
		OK: true, Records: 3, Findings: []ExpectedFinding{}, Lines: lines(valid...)})

	// seq gap: third record sealed with seq 3 instead of 2.
	gap := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`)
	g3 := base(evidence.ProducerOther, "p", "s", 3, ev, "2026-11-02T13:00:02.000Z", `{"n":3}`)
	seal(&g3, gap[1].ChainHash)
	cases = append(cases, StreamCase{File: "seq-gap.jsonl", Description: "Third record skips seq 2 but is otherwise correctly linked.",
		OK: false, Records: 3, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassSeqGap}}, Lines: lines(gap[0], gap[1], &g3)})

	// chain break: third record sealed against the wrong predecessor.
	brk := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`)
	b3 := base(evidence.ProducerOther, "p", "s", 2, ev, "2026-11-02T13:00:02.000Z", `{"n":2}`)
	seal(&b3, brk[0].ChainHash)
	cases = append(cases, StreamCase{File: "chain-break.jsonl", Description: "Third record links to record 0 instead of record 1: a record was removed or reordered.",
		OK: false, Records: 3, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassChainBreak}}, Lines: lines(brk[0], brk[1], &b3)})

	// restart: new segment anchored at the previous one.
	rs := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`)
	r0 := base(evidence.ProducerOther, "p", "s", 0, "test.chain.restarted", "2026-11-02T13:10:00.000Z", `{"reason":"restart"}`)
	r0.ChainRestart = true
	r0.AnchorHash = rs[1].ChainHash
	seal(&r0, rs[1].ChainHash)
	r1 := base(evidence.ProducerOther, "p", "s", 1, ev, "2026-11-02T13:10:01.000Z", `{"n":1}`)
	seal(&r1, r0.ChainHash)
	cases = append(cases, StreamCase{File: "restart.jsonl", Description: "A restart record anchored at the last chain_hash of the previous segment, followed by one chained record. Verifies OK with one restart notice.",
		OK: true, Records: 4, Restarts: 1, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassRestart}}, Lines: lines(rs[0], rs[1], &r0, &r1)})

	// restart with genesis anchor (previous segment unknown).
	ug := base(evidence.ProducerOther, "p", "s", 0, "test.chain.restarted", "2026-11-02T13:10:00.000Z", `{"reason":"storage lost"}`)
	ug.ChainRestart = true
	ug.AnchorHash = evidence.GenesisHash
	seal(&ug, evidence.GenesisHash)
	cases = append(cases, StreamCase{File: "restart-unknown-anchor.jsonl", Description: "Previous segment present, restart anchored at genesis because the producer lost its state. Allowed, reported as a restart notice.",
		OK: true, Records: 3, Restarts: 1, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassRestart}}, Lines: lines(rs[0], rs[1], &ug)})

	// restart whose anchor does not match the previous segment.
	ba := base(evidence.ProducerOther, "p", "s", 0, "test.chain.restarted", "2026-11-02T13:10:00.000Z", `{"reason":"restart"}`)
	ba.ChainRestart = true
	ba.AnchorHash = rs[0].ChainHash
	seal(&ba, rs[0].ChainHash)
	cases = append(cases, StreamCase{File: "restart-bad-anchor.jsonl", Description: "Restart anchored at record 0 although record 1 is the last of the previous segment: restart notice plus chain_break.",
		OK: false, Records: 3, Restarts: 1, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassRestart}, {Index: 2, Class: evidence.ClassChainBreak}}, Lines: lines(rs[0], rs[1], &ba)})

	// tampered payload.
	tp := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`, `{"n":2}`)
	tl := lines(tp...)
	tl[1] = strings.Replace(tl[1], `"payload":{"n":1}`, `"payload":{"n":100}`, 1)
	cases = append(cases, StreamCase{File: "tampered-payload.jsonl", Description: "Payload of record 1 changed after sealing: hash_mismatch on record 1 (content and chain hash), while record 2 still links to the declared chain_hash.",
		OK: false, Records: 3, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassHashMismatch}}, Lines: tl})

	// signed chain.
	sg := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`, `{"n":2}`)
	for _, r := range sg {
		if err := evidence.Sign(r, priv, ""); err != nil {
			panic(err)
		}
	}
	cases = append(cases, StreamCase{File: "signed.jsonl", Description: "Three records signed with the TEST KEY.", PublicKey: "../keys/test-ed25519.pub", RequireSignatures: true,
		OK: true, Records: 3, Findings: []ExpectedFinding{}, Lines: lines(sg...)})

	// one invalid signature (signed by another key), one unsigned.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	bs := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`, `{"n":2}`)
	if err := evidence.Sign(bs[0], priv, ""); err != nil {
		panic(err)
	}
	if err := evidence.Sign(bs[1], other, evidence.KeyID(priv.Public().(ed25519.PublicKey))); err != nil {
		panic(err)
	}
	cases = append(cases, StreamCase{File: "signature-invalid.jsonl", Description: "Record 1 is signed by a different key (claiming the test key id), record 2 is unsigned. With the test public key and --require-signatures both are signature_invalid.", PublicKey: "../keys/test-ed25519.pub", RequireSignatures: true,
		OK: false, Records: 3, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSignatureInvalid}, {Index: 2, Class: evidence.ClassSignatureInvalid}}, Lines: lines(bs...)})

	// schema problems.
	sc := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`)
	sc1 := base("unicorn", "p", "s", 1, ev, "2026-11-02T13:00:01.000Z", `{"n":1}`)
	seal(&sc1, sc[0].ChainHash)
	sc2 := base(evidence.ProducerOther, "p", "s", 2, ev, "2026-11-02T13:00:02.000Z", `{"n":2}`)
	seal(&sc2, sc1.ChainHash)
	sl := lines(sc[0], &sc1, &sc2)
	sl = append(sl, `this is not json`)
	sl = append(sl, `{"schema":"trail.evidence/1","seq":"3"}`)
	cases = append(cases, StreamCase{File: "schema-invalid.jsonl", Description: "Record 1 has an unknown producer.kind (schema_invalid, but hashes and links still check out), record 3 is not JSON, record 4 has a string seq and misses most members.",
		OK: false, Records: 5, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSchemaInvalid}, {Index: 3, Class: evidence.ClassSchemaInvalid}, {Index: 4, Class: evidence.ClassSchemaInvalid}}, Lines: sl})

	// two interleaved streams.
	a := chain(evidence.ProducerOther, "p", "a", ev, `{"s":"a","n":0}`, `{"s":"a","n":1}`)
	b := chain(evidence.ProducerOther, "p", "b", ev, `{"s":"b","n":0}`, `{"s":"b","n":1}`)
	cases = append(cases, StreamCase{File: "multi-stream.jsonl", Description: "Two independent streams interleaved in one journal; each chain is verified on its own.",
		OK: true, Records: 4, Findings: []ExpectedFinding{}, Lines: lines(a[0], b[0], a[1], b[1])})

	return cases
}

func buildExamples() []Journal {
	var out []Journal

	// transfer-worker
	tw := func(seq uint64, at, job, payload string) *evidence.Record {
		r := base(evidence.ProducerTransferWorker, "worker-01", "worker-01", seq, "transfer.job.result", at, payload)
		r.Producer.Version = "0.3.1"
		r.Actor = evidence.Actor{Auth: evidence.AuthSelfDeclared, ID: "alice"}
		r.Policy = evidence.Policy{ID: "archive-policy", Version: "7", Hash: evidence.HashBytes([]byte("archive-policy v7")), Status: evidence.PolicyApproved, Kind: "transfer-policy"}
		r.JobID = job
		return &r
	}
	t := []*evidence.Record{
		tw(0, "2026-11-02T06:00:12.500Z", "job-1001", `{"action":"copy","source":"sftp://files.example/in/report-2026-11-01.csv","target":"s3://archive/2026/11/report-2026-11-01.csv","status":"ok","files":1,"bytes":48213,"duration_ms":812,"command_hash":"sha256:2f1c0a6b4d8e9f00112233445566778899aabbccddeeff00112233445566778a"}`),
		tw(1, "2026-11-02T06:05:03.120Z", "job-1002", `{"action":"move","source":"sftp://files.example/in/batch-07/","target":"s3://archive/2026/11/batch-07/","status":"ok","files":14,"bytes":1048576,"duration_ms":4310,"command_hash":"sha256:9a8b7c6d5e4f30211223344556677889900aabbccddeeff0011223344556677b"}`),
		tw(2, "2026-11-02T06:10:00.004Z", "job-1003", `{"action":"copy","source":"sftp://files.example/in/missing.csv","target":"s3://archive/2026/11/missing.csv","status":"failed","error":"source not found","files":0,"bytes":0,"duration_ms":95,"command_hash":"sha256:0c0ffee00ddba11000112233445566778899aabbccddeeff001122334455667c"}`),
		tw(3, "2026-11-02T06:15:44.900Z", "job-1004", `{"action":"copy","source":"sftp://files.example/in/report-2026-11-02.csv","target":"s3://archive/2026/11/report-2026-11-02.csv","status":"ok","files":1,"bytes":49102,"duration_ms":790,"command_hash":"sha256:4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d"}`),
	}
	t[2].Redaction = nil
	sealChain(t)
	out = append(out, Journal{File: "transfer-worker.jsonl", Lines: lines(t...)})

	// source-bridge
	sb := func(seq uint64, at, occurred, ev, payload, ctx string) *evidence.Record {
		r := base(evidence.ProducerSourceBridge, "bridge-01", "bridge-01/plc-7", seq, ev, at, payload)
		r.Producer.Version = "0.2.0"
		r.Time.OccurredAt = occurred
		r.Time.ReadAt = at
		r.Time.Source = evidence.TimeSourceNTP
		r.Actor = evidence.Actor{Auth: evidence.AuthSelfDeclared, ID: "bridge-01"}
		r.Policy = evidence.Policy{ID: "plc-7-addressspace", Version: "2026-10-30", Hash: evidence.HashBytes([]byte("inventory fingerprint 2026-10-30")), Kind: "addressspace"}
		r.Context = json.RawMessage(ctx)
		return &r
	}
	s := []*evidence.Record{
		sb(0, "2026-11-02T07:00:00.000Z", "2026-11-02T06:59:59.000Z", "source.inventory.changed",
			`{"inventory_hash":"sha256:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a","count":2,"nodes":[{"native_node_id":"ns=2;s=Line1.Temp","entity_key":"line1/temp"},{"native_node_id":"ns=2;s=Line1.Speed","entity_key":"line1/speed"}]}`,
			`{"source_type":"opcua","source_address":"opc.tcp://plc-7:4840","channel":"browse"}`),
		sb(1, "2026-11-02T07:00:01.250Z", "2026-11-02T07:00:01.200Z", "source.value.observed",
			`{"native_node_id":"ns=2;s=Line1.Temp","entity_key":"line1/temp","value":"21.5","datatype":"Float","quality":"good","inventory_hash":"sha256:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"}`,
			`{"source_type":"opcua","source_address":"opc.tcp://plc-7:4840","channel":"subscription","source_status":"connected"}`),
		sb(2, "2026-11-02T07:00:01.260Z", "2026-11-02T07:00:01.200Z", "source.value.observed",
			`{"native_node_id":"ns=2;s=Line1.Speed","entity_key":"line1/speed","value":"1480","datatype":"Int32","quality":"good","inventory_hash":"sha256:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"}`,
			`{"source_type":"opcua","source_address":"opc.tcp://plc-7:4840","channel":"subscription","source_status":"connected"}`),
		sb(3, "2026-11-02T07:00:02.500Z", "2026-11-02T07:00:02.400Z", "source.value.observed",
			`{"native_node_id":"ns=2;s=Line1.Temp","entity_key":"line1/temp","value":"21.6","datatype":"Float","quality":"good","inventory_hash":"sha256:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"}`,
			`{"source_type":"opcua","source_address":"opc.tcp://plc-7:4840","channel":"subscription","source_status":"connected"}`),
	}
	sealChain(s)
	out = append(out, Journal{File: "source-bridge.jsonl", Lines: lines(s...)})

	// broker export
	bk := func(seq uint64, at, ev, decision, user string, roles []string, rule, ruleVersion, payload string) *evidence.Record {
		r := base(evidence.ProducerBroker, "broker-node-a", "broker-node-a/decisions", seq, ev, at, payload)
		r.Producer.Version = "export-adapter 0.1.0"
		r.Actor = evidence.Actor{Auth: evidence.AuthBrokerAuthenticated, ID: user, Roles: roles}
		r.Policy = evidence.Policy{ID: rule, Version: ruleVersion, Hash: evidence.HashBytes([]byte(rule + "@" + ruleVersion)), Status: evidence.PolicyActive, Kind: "topic-rule"}
		r.DecisionID = decision
		r.CorrelationID = "corr-" + decision
		return &r
	}
	b := []*evidence.Record{
		bk(0, "2026-11-02T08:00:00.010Z", "mqtt.decision.allow", "d-0001", "sensor-gw-3", []string{"publisher"}, "plant/+/telemetry", "12",
			`{"client_id":"sensor-gw-3","topic":"plant/line1/telemetry","action":"publish","qos":1,"payload_size":212,"payload_hash":"sha256:3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b","access_decision":"allow","reason_code":"rule_match"}`),
		bk(1, "2026-11-02T08:00:00.350Z", "mqtt.decision.deny", "d-0002", "guest-app", []string{"guest"}, "plant/+/control", "12",
			`{"client_id":"guest-app","topic":"plant/line1/control","action":"publish","qos":0,"payload_size":16,"payload_hash":"sha256:7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c","access_decision":"deny","reason_code":"no_matching_grant"}`),
		bk(2, "2026-11-02T08:00:01.000Z", "mqtt.decision.allow", "d-0003", "hmi-line1", []string{"operator"}, "plant/+/control", "12",
			`{"client_id":"hmi-line1","topic":"plant/line1/control","action":"subscribe","qos":1,"access_decision":"allow","reason_code":"rule_match"}`),
	}
	sealChain(b)
	out = append(out, Journal{File: "broker-export.jsonl", Lines: lines(b...)})

	// ml pipeline
	ml := func(seq uint64, at, ev, payload string) *evidence.Record {
		r := base(evidence.ProducerMLPipeline, "unet-train-2026-11-02", "run-7f3a", seq, ev, at, payload)
		r.Producer.Version = "1.4.0"
		r.Actor = evidence.Actor{Auth: evidence.AuthOperatorToken, ID: "ml-ops"}
		r.Policy = evidence.Policy{ID: "recipe-seg-v3", Version: "3.2", Hash: evidence.HashBytes([]byte("recipe-seg-v3 3.2")), Status: evidence.PolicyApproved, Kind: "recipe"}
		r.CorrelationID = "run-7f3a"
		return &r
	}
	m := []*evidence.Record{
		ml(0, "2026-11-02T09:00:00.000Z", "ml.run.started", `{"run_id":"run-7f3a","model_version":"1.4.0","config_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","data_fingerprint":"sha256:2222222222222222222222222222222222222222222222222222222222222222","environment":"validation"}`),
		ml(1, "2026-11-02T09:42:10.000Z", "ml.run.completed", `{"run_id":"run-7f3a","model_version":"1.4.0","config_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","data_fingerprint":"sha256:2222222222222222222222222222222222222222222222222222222222222222","metrics":{"dice":"0.9132","iou":"0.8407","samples":512},"decision":{"threshold":"0.5000"},"note":"floating point metrics are transported as strings so that their decimal rendering is exact"}`),
		ml(2, "2026-11-02T09:45:00.000Z", "ml.prediction.created", `{"run_id":"run-7f3a","sample_id":"s-000417","probability":"0.9731","label":"defect","calibration":"isotonic-2026-10"}`),
	}
	sealChain(m)
	out = append(out, Journal{File: "ml-pipeline.jsonl", Lines: lines(m...)})

	return out
}

func sealChain(recs []*evidence.Record) {
	prev := evidence.GenesisHash
	for _, r := range recs {
		seal(r, prev)
		prev = r.ChainHash
	}
}

// MarshalVectors renders the vectors file with two-space indentation and no
// HTML escaping, terminated by a newline.
func MarshalVectors(f File) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// StreamIndex is the shape of testdata/streams/expected.json.
type StreamIndex struct {
	Note  string       `json:"note"`
	Cases []StreamCase `json:"cases"`
}

// MarshalStreamIndex renders testdata/streams/expected.json.
func MarshalStreamIndex(cases []StreamCase) []byte {
	idx := StreamIndex{
		Note:  "Each case names a JSON Lines fixture and the verdict a verifier must reach. findings lists the distinct (index, class) pairs in order of first occurrence; index counts non-empty lines from 0. pubkey paths are relative to this file.",
		Cases: cases,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(idx); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// Files maps repository-relative paths to the bytes the generator produces.
func Files(out Output) map[string][]byte {
	files := map[string][]byte{
		"testdata/vectors.json":           MarshalVectors(out.Vectors),
		"testdata/streams/expected.json":  MarshalStreamIndex(out.Streams),
		"testdata/keys/test-ed25519.seed": []byte(TestKeySeedHex + "\n"),
		"testdata/keys/test-ed25519.pub":  []byte(TestKeyPublicHex + "\n"),
	}
	for _, c := range out.Streams {
		files["testdata/streams/"+c.File] = []byte(strings.Join(c.Lines, "\n") + "\n")
	}
	for _, j := range out.Examples {
		files["examples/"+j.File] = []byte(strings.Join(j.Lines, "\n") + "\n")
	}
	return files
}
