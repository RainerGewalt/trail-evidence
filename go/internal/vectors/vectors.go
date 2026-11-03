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
	ExpectedNotices     []string        `json:"expected_notices,omitempty"`
	// ExpectedState is the state of the record on its own (valid, invalid
	// or outside_scope); unknown needs a stream and never appears here.
	ExpectedState        string `json:"expected_state"`
	ExpectedProfileState string `json:"expected_profile_state"`
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

// StreamCase describes one fixture under testdata/streams. States and
// ProfileStates list the expected state and profile state of every record,
// by index; Verdict follows from them and the options (SPEC.md section
// 6.4) and is checked against OK. A file may appear in several cases with
// different options.
type StreamCase struct {
	File                 string            `json:"file"`
	Description          string            `json:"description"`
	PublicKey            string            `json:"pubkey,omitempty"`
	RequireSignatures    bool              `json:"require_signatures,omitempty"`
	AllowIncomplete      bool              `json:"allow_incomplete,omitempty"`
	RequireKnownProfiles bool              `json:"require_known_profiles,omitempty"`
	Verdict              string            `json:"verdict"`
	OK                   bool              `json:"ok"`
	ExitCode             int               `json:"exit_code"`
	Records              int               `json:"records"`
	Restarts             int               `json:"restarts"`
	Findings             []ExpectedFinding `json:"findings"`
	States               []string          `json:"states"`
	ProfileStates        []string          `json:"profile_states"`
	Lines                []string          `json:"-"`
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
	// Tampered are manipulated copies of examples/transfer-worker.jsonl,
	// written to examples/tampered/.
	Tampered []StreamCase
	// ProfileJournals are the journals of the profile registry, written to
	// profiles/<name>/<major>.journal.jsonl.
	ProfileJournals []Journal
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
	return finishVector(name, desc, raw, true, "", evidence.ProfileNone)
}

// finishVector computes the expected hashes of raw with the reference
// implementation. The intended verdict (valid, error class, profile state) is
// given by the caller and checked against the implementation, so that a
// generator run fails instead of recording a wrong expectation.
func finishVector(name, desc, raw string, valid bool, class, profileState string) Vector {
	h, err := evidence.ComputeHashes([]byte(raw))
	if err != nil {
		panic(err)
	}
	c := evidence.CheckRecord([]byte(raw))
	var notices []string
	hasClass := false
	for _, f := range c.Findings {
		if f.Severity == evidence.SeverityNotice {
			notices = append(notices, f.Class)
		}
		if f.Class == class {
			hasClass = true
		}
	}
	state := evidence.StateValid
	if !valid {
		state = evidence.StateInvalid
	}
	if c.State != state || c.ProfileState != profileState || (!valid && !hasClass) {
		panic(fmt.Sprintf("vector %s: implementation says state %s, profile state %s, findings %+v; intended %s, %s, %s",
			name, c.State, c.ProfileState, c.Findings, state, profileState, class))
	}
	return Vector{
		ExpectedNotices:      notices,
		Name:                 name,
		Description:          desc,
		Record:               json.RawMessage(raw),
		ExpectedPayloadJCS:   string(h.PayloadJCS),
		ExpectedContentHash:  h.ContentHash,
		ExpectedCoreJCS:      string(h.CoreJCS),
		ExpectedChainHash:    h.ChainHash,
		ExpectedValid:        valid,
		ExpectedError:        class,
		ExpectedState:        state,
		ExpectedProfileState: profileState,
	}
}

// resealRaw applies edit to the encoded record and recomputes content_hash
// and chain_hash over the edited bytes, as a producer that writes that form
// would have. It returns the line and its chain_hash.
func resealRaw(r *evidence.Record, edit func(string) string) (string, string) {
	raw := encode(r)
	edited := edit(raw)
	if edited == raw {
		panic("resealRaw: the edit changed nothing")
	}
	h, err := evidence.ComputeHashes([]byte(edited))
	if err != nil {
		panic(err)
	}
	out := strings.Replace(edited, `"content_hash":"`+r.ContentHash+`"`, `"content_hash":"`+h.ContentHash+`"`, 1)
	out = strings.Replace(out, `"chain_hash":"`+r.ChainHash+`"`, `"chain_hash":"`+h.ChainHash+`"`, 1)
	return out, h.ChainHash
}

// replaceOnce replaces exactly one occurrence of from and panics otherwise.
func replaceOnce(s, from, to string) string {
	if strings.Count(s, from) != 1 {
		panic(fmt.Sprintf("replaceOnce: %q occurs %d times", from, strings.Count(s, from)))
	}
	return strings.Replace(s, from, to, 1)
}

// seqMember is the seq member of a sealed record as the encoder writes it.
func seqMember(r *evidence.Record) string {
	return fmt.Sprintf(`"seq":"%d"`, r.Seq)
}

// states expands a compact state list: v valid, i invalid, u unknown,
// o outside_scope.
func states(s string) []string {
	m := map[rune]string{'v': evidence.StateValid, 'i': evidence.StateInvalid, 'u': evidence.StateUnknown, 'o': evidence.StateOutsideScope}
	return expand(s, m)
}

// profileStates expands a compact profile state list: n none, v valid,
// i invalid, o outside_scope.
func profileStates(s string) []string {
	m := map[rune]string{'n': evidence.ProfileNone, 'v': evidence.StateValid, 'i': evidence.StateInvalid, 'o': evidence.StateOutsideScope}
	return expand(s, m)
}

func expand(s string, m map[rune]string) []string {
	out := make([]string, 0, len(s))
	for _, c := range s {
		v, ok := m[c]
		if !ok {
			panic(fmt.Sprintf("unknown state letter %q", c))
		}
		out = append(out, v)
	}
	return out
}

// none returns n profile states "none".
func none(n int) []string {
	return profileStates(strings.Repeat("n", n))
}

// Build returns the complete, deterministic generator output.
func Build() Output {
	priv := mustKey()
	pub := priv.Public().(ed25519.PublicKey)
	var out Output
	out.Vectors = File{
		Schema:      evidence.Schema,
		GeneratedBy: "github.com/RainerGewalt/trail-evidence/go (reference implementation)",
		Note:        "Every implementation MUST reproduce expected_payload_jcs, expected_content_hash, expected_core_jcs and expected_chain_hash byte for byte. For vectors with expected_valid=false the expected_* values are the correct ones and the record carries the defect. expected_notices lists the notice classes a verifier must report for the record on its own.",
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
		"Payload exercises RFC 8785: ES6 number formatting (1.0 -> 1, 1e21 -> 1e+21, -0.0 -> 0, 9007199254740993 -> 9007199254740992), minimal string escaping with lowercase \\u00xx, literal non-ASCII, and member sorting by UTF-16 code units (U+1F680 before U+FF01). The integer beyond 2^53 must produce a number_precision notice.", &v7))

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
		tampered, false, evidence.ClassHashMismatch, evidence.ProfileNone))

	// Vector 10: payload tampered after sealing.
	bad = encode(&v6)
	tampered = strings.Replace(bad, `"status":"ok"`, `"status":"failed"`, 1)
	if tampered == bad {
		panic("tamper failed")
	}
	out.Vectors.Vectors = append(out.Vectors.Vectors, finishVector("invalid-content-hash",
		"redaction with the payload altered after sealing. content_hash no longer matches, and because the core carries the recomputed content_hash, chain_hash differs as well. A verifier must report hash_mismatch.",
		tampered, false, evidence.ClassHashMismatch, evidence.ProfileNone))

	out.Vectors.Vectors = append(out.Vectors.Vectors, buildSeqVectors()...)
	out.Vectors.Vectors = append(out.Vectors.Vectors, buildProfileVectors()...)

	out.Streams = buildStreams(priv)
	out.Examples = buildExamples()
	out.Tampered = buildTampered(priv)
	out.ProfileJournals = buildProfileJournals()
	return out
}

// measurement is a payload of the test profile example.measurement/1.
func measurement(value string) string {
	return `{"quantity":"temperature","value":"` + value + `","unit":"degC","samples":16,"sensor":{"id":"pt100-line1","calibrated":true}}`
}

func buildSeqVectors() []Vector {
	var out []Vector
	big := base(evidence.ProducerOther, "ref-producer", "seq", 9007199254740993, "test.seq.decimal",
		"2026-11-02T14:00:00.000Z", `{"n":"2^53+1"}`)
	seal(&big, evidence.GenesisHash)
	out = append(out, vector("seq-beyond-2-53",
		"seq is a JSON string in canonical decimal form. 9007199254740993 (2^53 + 1) is hashed exactly as written; as a JSON number JCS would round it to 9007199254740992. Verifiers compare seq values as integers of arbitrary size, never as doubles.", &big))

	top := base(evidence.ProducerOther, "ref-producer", "seq", evidence.MaxSeq, "test.seq.decimal",
		"2026-11-02T14:00:01.000Z", `{"n":"uint64 max"}`)
	seal(&top, evidence.GenesisHash)
	out = append(out, vector("seq-uint64-max",
		"seq at its largest allowed value, 18446744073709551615 (2^64 - 1).", &top))

	legacy := base(evidence.ProducerOther, "ref-producer", "seq", 7, "test.seq.legacy",
		"2026-11-02T14:00:02.000Z", `{"n":7}`)
	seal(&legacy, evidence.GenesisHash)
	raw, _ := resealRaw(&legacy, func(s string) string { return replaceOnce(s, `"seq":"7"`, `"seq":7`) })
	out = append(out, finishVector("seq-legacy-integer",
		"seq written as a JSON number, the form of format 0.1. Accepted during 0.x with the notice legacy_integer_seq; schema_invalid from 1.0. The hashes cover the member as written, so the core carries \"seq\":7, and 0.1 journals keep verifying.",
		raw, true, "", evidence.ProfileNone))

	missing := base(evidence.ProducerOther, "ref-producer", "seq", 1, "test.seq.missing",
		"2026-11-02T14:00:03.000Z", `{"n":1}`)
	seal(&missing, evidence.GenesisHash)
	raw, _ = resealRaw(&missing, func(s string) string { return replaceOnce(s, seqMember(&missing)+",", "") })
	out = append(out, finishVector("seq-missing",
		"No seq member. The hashes are computed over the record as written (a core without seq); the record is schema_invalid and, in a journal, takes no part in the chain checks.",
		raw, false, evidence.ClassSchemaInvalid, evidence.ProfileNone))

	for _, bad := range []struct{ name, value, desc string }{
		{"seq-leading-zero", `"07"`, "seq \"07\" has a leading zero; the canonical form is \"7\". schema_invalid."},
		{"seq-out-of-range", `"18446744073709551616"`, "seq \"18446744073709551616\" is 2^64, one more than the largest allowed value. schema_invalid."},
	} {
		r := base(evidence.ProducerOther, "ref-producer", "seq", 7, "test.seq.malformed",
			"2026-11-02T14:00:04.000Z", `{"n":7}`)
		seal(&r, evidence.GenesisHash)
		raw, _ := resealRaw(&r, func(s string) string { return replaceOnce(s, seqMember(&r), `"seq":`+bad.value) })
		out = append(out, finishVector(bad.name, bad.desc, raw, false, evidence.ClassSchemaInvalid, evidence.ProfileNone))
	}
	return out
}

func buildProfileVectors() []Vector {
	var out []Vector
	pr := func(profile, payload string) evidence.Record {
		r := base(evidence.ProducerOther, "ref-producer", "profiles", 0, "test.measurement.recorded",
			"2026-11-02T15:00:00.000Z", payload)
		r.Profile = profile
		seal(&r, evidence.GenesisHash)
		return r
	}
	ok := pr("example.measurement/1", measurement("21.5"))
	out = append(out, finishVector("profile-valid",
		"Record with profile example.measurement/1 and a payload that satisfies the profile schema. profile is part of the core.",
		encode(&ok), true, "", evidence.StateValid))

	bad := pr("example.measurement/1", `{"quantity":"temperature","value":21.5}`)
	out = append(out, finishVector("profile-payload-invalid",
		"Known profile, payload violates it: unit is missing and value is a number. The hashes are correct; profile_invalid makes the record invalid.",
		encode(&bad), false, evidence.ClassProfileInvalid, evidence.StateInvalid))

	major := pr("example.measurement/2", measurement("21.5"))
	out = append(out, finishVector("profile-major-unknown",
		"Profile name known, major version 2 not in the registry. The core checks pass, so the record is valid; its profile state is outside_scope with the notice profile_unknown.",
		encode(&major), true, "", evidence.StateOutsideScope))

	name := pr("acme.unknown/1", `{"anything":"goes"}`)
	out = append(out, finishVector("profile-name-unknown",
		"Profile name not in the registry. Valid record, profile state outside_scope, notice profile_unknown.",
		encode(&name), true, "", evidence.StateOutsideScope))

	malformed := pr("Example.Measurement/1", measurement("21.5"))
	out = append(out, finishVector("profile-malformed",
		"profile does not match <name>/<major> (upper-case letters). schema_invalid; profile state invalid.",
		encode(&malformed), false, evidence.ClassSchemaInvalid, evidence.StateInvalid))
	return out
}

// buildProfileJournals returns the journal of each profile in the registry:
// records sealed by the producer (here the reference implementation) that
// every verifier must find valid, with profile state valid.
func buildProfileJournals() []Journal {
	recs := []*evidence.Record{}
	for i, v := range []string{"21.5", "21.6", "21.4"} {
		r := base(evidence.ProducerOther, "lab-sensor-01", "lab-sensor-01", uint64(i), "test.measurement.recorded",
			fmt.Sprintf("2026-11-02T16:00:%02d.000Z", i), measurement(v))
		r.Profile = "example.measurement/1"
		r.Time.Source = evidence.TimeSourceNTP
		recs = append(recs, &r)
	}
	sealChain(recs)
	return []Journal{{File: "example.measurement/1.journal.jsonl", Lines: lines(recs...)}}
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
		OK: true, Records: 3, Findings: []ExpectedFinding{}, States: states("vvv"), ProfileStates: none(3), Lines: lines(valid...)})

	// seq mismatch: third record sealed with seq 3 but linked to record 1.
	mm := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`)
	m3 := base(evidence.ProducerOther, "p", "s", 3, ev, "2026-11-02T13:00:02.000Z", `{"n":3}`)
	seal(&m3, mm[1].ChainHash)
	cases = append(cases, StreamCase{File: "seq-mismatch.jsonl", Description: "Third record has seq 3 but its prev_hash links to record 1 (seq 1). The link says nothing is missing, the seq says a record is: seq_mismatch, invalid. This is what deleting a record and re-sealing its successor looks like.",
		OK: false, Records: 3, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassSeqMismatch}}, States: states("vvi"), ProfileStates: none(3), Lines: lines(mm[0], mm[1], &m3)})

	// seq gap: record 2 is not in the journal; record 3 links to it.
	gp := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`, `{"n":2}`, `{"n":3}`, `{"n":4}`)
	gapLines := lines(gp[0], gp[1], gp[3], gp[4])
	gapFindings := []ExpectedFinding{{Index: 2, Class: evidence.ClassSeqGap}, {Index: 3, Class: evidence.ClassAfterUnknown}}
	cases = append(cases, StreamCase{File: "seq-gap.jsonl", Description: "Record with seq 2 is missing from the journal; the record with seq 3 links to it. Its own hashes are correct but its predecessor cannot be checked: seq_gap, state unknown. The next record links correctly to it: valid, with the notice after_unknown. No record is invalid, one is unknown: verdict incomplete, which fails (exit code 3).",
		OK: false, Records: 4, Findings: gapFindings, States: states("vvuv"), ProfileStates: none(4), Lines: gapLines})
	cases = append(cases, StreamCase{File: "seq-gap.jsonl", Description: "The same journal with --allow-incomplete: the verdict stays incomplete, but it is accepted (exit code 0).", AllowIncomplete: true,
		OK: true, Records: 4, Findings: gapFindings, States: states("vvuv"), ProfileStates: none(4), Lines: gapLines})

	// journal start: an excerpt that begins in the middle of a stream, and a
	// second stream that begins with an anchored restart.
	full := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`, `{"n":2}`, `{"n":3}`, `{"n":4}`, `{"n":5}`, `{"n":6}`, `{"n":7}`)
	tr := base(evidence.ProducerOther, "p", "t", 40, "test.chain.restarted", "2026-11-02T13:20:00.000Z", `{"reason":"process restarted"}`)
	tr.ChainRestart = true
	tr.AnchorHash = evidence.HashBytes([]byte("last chain_hash of an earlier segment"))
	seal(&tr, tr.AnchorHash)
	tn := base(evidence.ProducerOther, "p", "t", 41, ev, "2026-11-02T13:20:01.000Z", `{"n":41}`)
	seal(&tn, tr.ChainHash)
	startLines := lines(full[5], &tr, full[6], &tn, full[7])
	startFindings := []ExpectedFinding{{Index: 0, Class: evidence.ClassSeqGap}, {Index: 1, Class: evidence.ClassRestart}, {Index: 2, Class: evidence.ClassAfterUnknown}}
	cases = append(cases, StreamCase{File: "journal-start.jsonl", Description: "Excerpt of stream s that begins at seq 5: the first record is neither genesis nor a restart, so its predecessor is missing (seq_gap, unknown); the records after it are valid, the first with after_unknown. Stream t begins with a restart anchored at an earlier segment: valid with a restart notice. Verdict incomplete.",
		OK: false, Records: 5, Restarts: 1, Findings: startFindings, States: states("uvvvv"), ProfileStates: none(5), Lines: startLines})
	cases = append(cases, StreamCase{File: "journal-start.jsonl", Description: "The same excerpt with --allow-incomplete, as for a rotated log: accepted.", AllowIncomplete: true,
		OK: true, Records: 5, Restarts: 1, Findings: startFindings, States: states("uvvvv"), ProfileStates: none(5), Lines: startLines})

	// chain break: third record sealed against the wrong predecessor.
	brk := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`)
	b3 := base(evidence.ProducerOther, "p", "s", 2, ev, "2026-11-02T13:00:02.000Z", `{"n":2}`)
	seal(&b3, brk[0].ChainHash)
	cases = append(cases, StreamCase{File: "chain-break.jsonl", Description: "Third record has the next seq but links to record 0 instead of record 1: a record was replaced or reordered. chain_break, invalid.",
		OK: false, Records: 3, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassChainBreak}}, States: states("vvi"), ProfileStates: none(3), Lines: lines(brk[0], brk[1], &b3)})

	// restart: new segment anchored at the previous one.
	rs := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`)
	r0 := base(evidence.ProducerOther, "p", "s", 0, "test.chain.restarted", "2026-11-02T13:10:00.000Z", `{"reason":"restart"}`)
	r0.ChainRestart = true
	r0.AnchorHash = rs[1].ChainHash
	seal(&r0, rs[1].ChainHash)
	r1 := base(evidence.ProducerOther, "p", "s", 1, ev, "2026-11-02T13:10:01.000Z", `{"n":1}`)
	seal(&r1, r0.ChainHash)
	cases = append(cases, StreamCase{File: "restart.jsonl", Description: "A restart record anchored at the last chain_hash of the previous segment, followed by one chained record. Verifies OK with one restart notice.",
		OK: true, Records: 4, Restarts: 1, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassRestart}}, States: states("vvvv"), ProfileStates: none(4), Lines: lines(rs[0], rs[1], &r0, &r1)})

	// restart with genesis anchor (previous segment unknown).
	ug := base(evidence.ProducerOther, "p", "s", 0, "test.chain.restarted", "2026-11-02T13:10:00.000Z", `{"reason":"storage lost"}`)
	ug.ChainRestart = true
	ug.AnchorHash = evidence.GenesisHash
	seal(&ug, evidence.GenesisHash)
	cases = append(cases, StreamCase{File: "restart-unknown-anchor.jsonl", Description: "Previous segment present, restart anchored at genesis because the producer lost its state. Allowed, reported as a restart notice.",
		OK: true, Records: 3, Restarts: 1, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassRestart}}, States: states("vvv"), ProfileStates: none(3), Lines: lines(rs[0], rs[1], &ug)})

	// restart whose anchor does not match the previous segment.
	ba := base(evidence.ProducerOther, "p", "s", 0, "test.chain.restarted", "2026-11-02T13:10:00.000Z", `{"reason":"restart"}`)
	ba.ChainRestart = true
	ba.AnchorHash = rs[0].ChainHash
	seal(&ba, rs[0].ChainHash)
	cases = append(cases, StreamCase{File: "restart-bad-anchor.jsonl", Description: "Restart anchored at record 0 although record 1 is the last of the previous segment: restart notice plus chain_break.",
		OK: false, Records: 3, Restarts: 1, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassRestart}, {Index: 2, Class: evidence.ClassChainBreak}}, States: states("vvi"), ProfileStates: none(3), Lines: lines(rs[0], rs[1], &ba)})

	// tampered payload.
	tp := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`, `{"n":2}`)
	tl := lines(tp...)
	tl[1] = strings.Replace(tl[1], `"payload":{"n":1}`, `"payload":{"n":100}`, 1)
	cases = append(cases, StreamCase{File: "tampered-payload.jsonl", Description: "Payload of record 1 changed after sealing: hash_mismatch on record 1 (content and chain hash), while record 2 still links to the declared chain_hash and is valid.",
		OK: false, Records: 3, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassHashMismatch}}, States: states("viv"), ProfileStates: none(3), Lines: tl})

	// signed chain.
	sg := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`, `{"n":2}`)
	for _, r := range sg {
		if err := evidence.Sign(r, priv, ""); err != nil {
			panic(err)
		}
	}
	cases = append(cases, StreamCase{File: "signed.jsonl", Description: "Three records signed with the TEST KEY.", PublicKey: "../keys/test-ed25519.pub", RequireSignatures: true,
		OK: true, Records: 3, Findings: []ExpectedFinding{}, States: states("vvv"), ProfileStates: none(3), Lines: lines(sg...)})

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
		OK: false, Records: 3, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSignatureInvalid}, {Index: 2, Class: evidence.ClassSignatureInvalid}}, States: states("vii"), ProfileStates: none(3), Lines: lines(bs...)})

	// schema problems.
	sc := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`)
	sc1 := base("unicorn", "p", "s", 1, ev, "2026-11-02T13:00:01.000Z", `{"n":1}`)
	seal(&sc1, sc[0].ChainHash)
	sc2 := base(evidence.ProducerOther, "p", "s", 2, ev, "2026-11-02T13:00:02.000Z", `{"n":2}`)
	seal(&sc2, sc1.ChainHash)
	sl := lines(sc[0], &sc1, &sc2)
	sl = append(sl, `this is not json`)
	sl = append(sl, `{"schema":"trail.evidence/1","seq":"3"}`)
	sl = append(sl, `{"stream":"s","note":"a JSON object without a schema member"}`)
	cases = append(cases, StreamCase{File: "schema-invalid.jsonl", Description: "Record 1 has an unknown producer.kind (schema_invalid, but hashes and links still check out, so record 2 is valid), record 3 is not JSON, record 4 misses most members, record 5 is a JSON object without schema. Records without stream_id or a usable seq take no part in the chain checks.",
		OK: false, Records: 6, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSchemaInvalid}, {Index: 3, Class: evidence.ClassSchemaInvalid}, {Index: 4, Class: evidence.ClassSchemaInvalid}, {Index: 5, Class: evidence.ClassSchemaInvalid}}, States: states("viviii"), ProfileStates: none(6), Lines: sl})

	// two interleaved streams.
	a := chain(evidence.ProducerOther, "p", "a", ev, `{"s":"a","n":0}`, `{"s":"a","n":1}`)
	b := chain(evidence.ProducerOther, "p", "b", ev, `{"s":"b","n":0}`, `{"s":"b","n":1}`)
	cases = append(cases, StreamCase{File: "multi-stream.jsonl", Description: "Two independent streams interleaved in one journal; each chain is verified on its own.",
		OK: true, Records: 4, Findings: []ExpectedFinding{}, States: states("vvvv"), ProfileStates: none(4), Lines: lines(a[0], b[0], a[1], b[1])})

	cases = append(cases, buildSeqStreams()...)
	cases = append(cases, buildScopeStreams()...)
	cases = append(cases, buildProfileStreams()...)
	return cases
}

// restartAt seals a restart record anchored at genesis with the given seq,
// followed by chained records with the next seqs.
func restartAt(stream string, seq uint64, n int) []*evidence.Record {
	r := base(evidence.ProducerOther, "p", stream, seq, "test.chain.restarted", "2026-11-02T13:30:00.000Z", `{"reason":"seq test"}`)
	r.ChainRestart = true
	r.AnchorHash = evidence.GenesisHash
	seal(&r, evidence.GenesisHash)
	out := []*evidence.Record{&r}
	for i := 1; i < n; i++ {
		next := base(evidence.ProducerOther, "p", stream, seq+uint64(i), "test.stream.step", fmt.Sprintf("2026-11-02T13:30:%02d.000Z", i), fmt.Sprintf(`{"n":%d}`, i))
		seal(&next, out[i-1].ChainHash)
		out = append(out, &next)
	}
	return out
}

func buildSeqStreams() []StreamCase {
	var cases []StreamCase
	ev := "test.stream.step"

	big := restartAt("big", 9007199254740991, 3)
	top := restartAt("max", evidence.MaxSeq-1, 2)
	cases = append(cases, StreamCase{File: "seq-decimal.jsonl", Description: "Decimal seq strings beyond 2^53 and up to 2^64 - 1. Stream big counts 9007199254740991, ...992, ...993; stream max reaches 18446744073709551615. Each stream begins with a restart anchored at genesis. A verifier that compares seq as doubles reports a false seq_mismatch at ...993.",
		OK: true, Records: 5, Restarts: 2, Findings: []ExpectedFinding{{Index: 0, Class: evidence.ClassRestart}, {Index: 3, Class: evidence.ClassRestart}},
		States: states("vvvvv"), ProfileStates: none(5), Lines: lines(big[0], big[1], big[2], top[0], top[1])})

	dup := restartAt("big", 9007199254740992, 2)
	d2 := base(evidence.ProducerOther, "p", "big", 9007199254740993, ev, "2026-11-02T13:30:05.000Z", `{"n":"again"}`)
	seal(&d2, dup[1].ChainHash)
	wrap := restartAt("max", evidence.MaxSeq, 1)
	w1 := base(evidence.ProducerOther, "p", "max", 0, ev, "2026-11-02T13:30:06.000Z", `{"n":"wrapped"}`)
	seal(&w1, wrap[0].ChainHash)
	cases = append(cases, StreamCase{File: "seq-decimal-mismatch.jsonl", Description: "Traps for seq arithmetic. Stream big repeats seq 9007199254740993 (as doubles both are 9007199254740992, which hides the repetition). Stream max follows 18446744073709551615 with seq 0 (uint64 arithmetic that wraps would expect 0). Both are seq_mismatch.",
		OK: false, Records: 5, Restarts: 2, Findings: []ExpectedFinding{{Index: 0, Class: evidence.ClassRestart}, {Index: 2, Class: evidence.ClassSeqMismatch}, {Index: 3, Class: evidence.ClassRestart}, {Index: 4, Class: evidence.ClassSeqMismatch}},
		States: states("vvivi"), ProfileStates: none(5), Lines: lines(dup[0], dup[1], &d2, wrap[0], &w1)})

	// legacy integer seq, mixed with a decimal string.
	lg := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`, `{"n":2}`)
	l0, h0 := resealRaw(lg[0], func(s string) string { return replaceOnce(s, `"seq":"0"`, `"seq":0`) })
	l1r := base(evidence.ProducerOther, "p", "s", 1, ev, "2026-11-02T13:00:01.000Z", `{"n":1}`)
	seal(&l1r, h0)
	l2r := base(evidence.ProducerOther, "p", "s", 2, ev, "2026-11-02T13:00:02.000Z", `{"n":2}`)
	seal(&l2r, l1r.ChainHash)
	l2, _ := resealRaw(&l2r, func(s string) string { return replaceOnce(s, `"seq":"2"`, `"seq":2`) })
	cases = append(cases, StreamCase{File: "legacy-integer-seq.jsonl", Description: "Records 0 and 2 write seq as a JSON number (format 0.1), record 1 as a decimal string. All are compared as integers and verify; the number form is reported as legacy_integer_seq.",
		OK: true, Records: 3, Findings: []ExpectedFinding{{Index: 0, Class: evidence.ClassLegacyIntegerSeq}, {Index: 2, Class: evidence.ClassLegacyIntegerSeq}},
		States: states("vvv"), ProfileStates: none(3), Lines: []string{l0, encode(&l1r), l2}})

	// missing seq.
	ms := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`)
	m2r := base(evidence.ProducerOther, "p", "s", 2, ev, "2026-11-02T13:00:02.000Z", `{"n":2}`)
	seal(&m2r, ms[1].ChainHash)
	m2, m2hash := resealRaw(&m2r, func(s string) string { return replaceOnce(s, `"seq":"2",`, "") })
	m3r := base(evidence.ProducerOther, "p", "s", 3, ev, "2026-11-02T13:00:03.000Z", `{"n":3}`)
	seal(&m3r, m2hash)
	m4r := base(evidence.ProducerOther, "p", "s", 4, ev, "2026-11-02T13:00:04.000Z", `{"n":4}`)
	seal(&m4r, m3r.ChainHash)
	cases = append(cases, StreamCase{File: "seq-missing.jsonl", Description: "Record 2 has no seq: schema_invalid, invalid, and without a position it takes no part in the chain checks. Record 3 links to record 2, which the chain therefore does not have: seq_gap, unknown. Record 4 is valid with after_unknown.",
		OK: false, Records: 5, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassSchemaInvalid}, {Index: 3, Class: evidence.ClassSeqGap}, {Index: 4, Class: evidence.ClassAfterUnknown}},
		States: states("vviuv"), ProfileStates: none(5), Lines: []string{encode(ms[0]), encode(ms[1]), m2, encode(&m3r), encode(&m4r)}})

	// malformed seq values, each linked to record 0.
	mf := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`)
	mfLines := []string{encode(mf[0])}
	for i, v := range []string{`"01"`, `"18446744073709551616"`, `1.0`, `"-1"`} {
		r := base(evidence.ProducerOther, "p", "s", 1, ev, fmt.Sprintf("2026-11-02T13:00:0%d.000Z", i+1), `{"n":1}`)
		seal(&r, mf[0].ChainHash)
		line, _ := resealRaw(&r, func(s string) string { return replaceOnce(s, `"seq":"1"`, `"seq":`+v) })
		mfLines = append(mfLines, line)
	}
	good := base(evidence.ProducerOther, "p", "s", 1, ev, "2026-11-02T13:00:05.000Z", `{"n":1}`)
	seal(&good, mf[0].ChainHash)
	mfLines = append(mfLines, encode(&good))
	cases = append(cases, StreamCase{File: "seq-malformed.jsonl", Description: "Records 1 to 4 carry seq \"01\", \"18446744073709551616\", 1.0 and \"-1\": schema_invalid each, and none of them changes the chain state. Record 5 has seq \"1\", links to record 0 and is valid.",
		OK: false, Records: 6, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassSchemaInvalid}, {Index: 2, Class: evidence.ClassSchemaInvalid}, {Index: 3, Class: evidence.ClassSchemaInvalid}, {Index: 4, Class: evidence.ClassSchemaInvalid}},
		States: states("viiiiv"), ProfileStates: none(6), Lines: mfLines})
	return cases
}

func buildScopeStreams() []StreamCase {
	ev := "test.stream.step"
	sc := chain(evidence.ProducerOther, "p", "s", ev, `{"n":0}`, `{"n":1}`)
	foreign1 := `{"schema":"trail.evidence/2","stream_id":"s","seq":"1","payload":{"n":"from a future major version"}}`
	foreign2 := `{"schema":"acme.audit/1","event":"login","user":"alice"}`
	ol := []string{encode(sc[0]), foreign1, foreign2, encode(sc[1])}
	of := []ExpectedFinding{{Index: 1, Class: evidence.ClassOutsideScope}, {Index: 2, Class: evidence.ClassOutsideScope}}
	return []StreamCase{
		{File: "outside-scope.jsonl", Description: "Records 1 and 2 name another major version (trail.evidence/2) and another format (acme.audit/1): outside_scope, not checked, no part in any chain. Record 3 is chained against the last checked record of its stream, record 0, and is valid. Verdict incomplete, because two records were not checked.",
			OK: false, Records: 4, Findings: of, States: states("voov"), ProfileStates: none(4), Lines: ol},
		{File: "outside-scope.jsonl", Description: "The same journal with --allow-incomplete: accepted.", AllowIncomplete: true,
			OK: true, Records: 4, Findings: of, States: states("voov"), ProfileStates: none(4), Lines: ol},
	}
}

func buildProfileStreams() []StreamCase {
	var cases []StreamCase
	ev := "test.measurement.recorded"
	pchain := func(stream string, specs ...[2]string) []*evidence.Record {
		var recs []*evidence.Record
		for i, sp := range specs {
			r := base(evidence.ProducerOther, "lab", stream, uint64(i), ev, fmt.Sprintf("2026-11-02T15:00:%02d.000Z", i), sp[1])
			r.Profile = sp[0]
			recs = append(recs, &r)
		}
		sealChain(recs)
		return recs
	}
	const known = "example.measurement/1"

	pv := pchain("m", [2]string{known, measurement("21.5")}, [2]string{known, measurement("21.6")}, [2]string{known, `{"quantity":"temperature","value":"21.7","unit":"degC","extra":"allowed"}`})
	cases = append(cases, StreamCase{File: "profile-valid.jsonl", Description: "Three records with the profile example.measurement/1 whose payloads satisfy it (the third has an extra member, which profiles allow).",
		OK: true, Records: 3, Findings: []ExpectedFinding{}, States: states("vvv"), ProfileStates: profileStates("vvv"), Lines: lines(pv...)})
	cases = append(cases, StreamCase{File: "profile-valid.jsonl", Description: "The same journal with --require-known-profiles: every profile is known and satisfied.", RequireKnownProfiles: true,
		OK: true, Records: 3, Findings: []ExpectedFinding{}, States: states("vvv"), ProfileStates: profileStates("vvv"), Lines: lines(pv...)})

	ps := pchain("m",
		[2]string{known, measurement("21.5")},
		[2]string{known, `{"quantity":"temperature","value":21.5}`},
		[2]string{"example.measurement/2", measurement("21.5")},
		[2]string{"acme.unknown/1", `{"anything":"goes"}`},
		[2]string{"", `{"n":4}`},
	)
	cases = append(cases, StreamCase{File: "profile-states.jsonl", Description: "One record per profile state. 0: known profile, payload satisfies it (valid). 1: known profile, payload violates it (profile_invalid; record invalid). 2: known name, unknown major version 2 and 3: unknown name (profile_unknown; profile state outside_scope, record still valid by its core checks). 4: no profile (none).",
		OK: false, Records: 5, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassProfileInvalid}, {Index: 2, Class: evidence.ClassProfileUnknown}, {Index: 3, Class: evidence.ClassProfileUnknown}},
		States: states("vivvv"), ProfileStates: profileStates("vioon"), Lines: lines(ps...)})

	pu := pchain("m", [2]string{known, measurement("21.5")}, [2]string{"example.measurement/2", measurement("21.6")}, [2]string{"acme.unknown/1", `{"anything":"goes"}`})
	puFindings := []ExpectedFinding{{Index: 1, Class: evidence.ClassProfileUnknown}, {Index: 2, Class: evidence.ClassProfileUnknown}}
	cases = append(cases, StreamCase{File: "profile-unknown.jsonl", Description: "Records 1 and 2 use profiles this verifier does not know. Their core checks pass and an unknown profile does not affect the verdict: valid. The payloads were not checked against a profile (profile_unknown, profile state outside_scope).",
		OK: true, Records: 3, Findings: puFindings, States: states("vvv"), ProfileStates: profileStates("voo"), Lines: lines(pu...)})
	cases = append(cases, StreamCase{File: "profile-unknown.jsonl", Description: "The same journal with --require-known-profiles: records with an unknown profile make it incomplete, which fails (exit code 3).", RequireKnownProfiles: true,
		OK: false, Records: 3, Findings: puFindings, States: states("vvv"), ProfileStates: profileStates("voo"), Lines: lines(pu...)})
	cases = append(cases, StreamCase{File: "profile-unknown.jsonl", Description: "With --require-known-profiles and --allow-incomplete: --allow-incomplete does not accept unknown profiles that --require-known-profiles asks for, so it still fails (exit code 3).", RequireKnownProfiles: true, AllowIncomplete: true,
		OK: false, Records: 3, Findings: puFindings, States: states("vvv"), ProfileStates: profileStates("voo"), Lines: lines(pu...)})

	pt := pchain("m", [2]string{known, measurement("21.5")}, [2]string{known, measurement("21.6")}, [2]string{known, measurement("21.7")}, [2]string{known, measurement("21.8")})
	ptl := lines(pt...)
	ptl[1] = replaceOnce(ptl[1], `"value":"21.6"`, `"value":"25.0"`)
	ptl[2] = replaceOnce(ptl[2], `"profile":"example.measurement/1"`, `"profile":"example.measurement/2"`)
	cases = append(cases, StreamCase{File: "profile-tampered.jsonl", Description: "Record 1: the measured value was edited after sealing; the payload still satisfies the profile, the hashes do not (hash_mismatch, invalid, profile valid). Record 2: the profile member was changed to an unknown major version to avoid the profile check; profile is part of the core, so chain_hash no longer matches (hash_mismatch, invalid, profile_unknown). Record 3 links to the declared chain_hash and is valid.",
		OK: false, Records: 4, Findings: []ExpectedFinding{{Index: 1, Class: evidence.ClassHashMismatch}, {Index: 2, Class: evidence.ClassHashMismatch}, {Index: 2, Class: evidence.ClassProfileUnknown}},
		States: states("viiv"), ProfileStates: profileStates("vvov"), Lines: ptl})
	return cases
}

// transferWorker returns the sealed records of examples/transfer-worker.jsonl.
// Every call builds fresh records, so callers may modify them.
func transferWorker() []*evidence.Record {
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
		tw(2, "2026-11-02T06:10:00.004Z", "job-1003", `{"action":"copy","source":"sftp://files.example/in/missing.csv","target":"s3://archive/2026/11/missing.csv","status":"failed","error":"source not found","reason_code":"transfer.source_not_found","files":0,"bytes":0,"duration_ms":95,"command_hash":"sha256:0c0ffee00ddba11000112233445566778899aabbccddeeff001122334455667c"}`),
		tw(3, "2026-11-02T06:15:44.900Z", "job-1004", `{"action":"copy","source":"sftp://files.example/in/report-2026-11-02.csv","target":"s3://archive/2026/11/report-2026-11-02.csv","status":"ok","files":1,"bytes":49102,"duration_ms":790,"command_hash":"sha256:4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d"}`),
	}
	t[2].Redaction = nil
	sealChain(t)
	return t
}

func buildExamples() []Journal {
	var out []Journal

	// transfer-worker
	out = append(out, Journal{File: "transfer-worker.jsonl", Lines: lines(transferWorker()...)})

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
			`{"client_id":"sensor-gw-3","topic":"plant/line1/telemetry","action":"publish","qos":1,"payload_size":212,"payload_hash":"sha256:3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b","access_decision":"allow","reason_code":"mqtt.allowed"}`),
		bk(1, "2026-11-02T08:00:00.350Z", "mqtt.decision.deny", "d-0002", "guest-app", []string{"guest"}, "plant/+/control", "12",
			`{"client_id":"guest-app","topic":"plant/line1/control","action":"publish","qos":0,"payload_size":16,"payload_hash":"sha256:7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c","access_decision":"deny","reason_code":"mqtt.acl_role_not_in_topic_scope"}`),
		bk(2, "2026-11-02T08:00:01.000Z", "mqtt.decision.allow", "d-0003", "hmi-line1", []string{"operator"}, "plant/+/control", "12",
			`{"client_id":"hmi-line1","topic":"plant/line1/control","action":"subscribe","qos":1,"access_decision":"allow","reason_code":"mqtt.allowed"}`),
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

// The manipulation all tampered examples share: the failed job (record 2 of
// examples/transfer-worker.jsonl) is rewritten to look successful.
const (
	failedJob = `"status":"failed","error":"source not found","reason_code":"transfer.source_not_found","files":0`
	forgedJob = `"status":"ok","reason_code":"transfer.completed","files":1`
)

func forge(s string) string {
	out := strings.Replace(s, failedJob, forgedJob, 1)
	if out == s {
		panic("forge: failed job not found")
	}
	return out
}

// buildTampered derives manipulated journals from the transfer-worker
// example: one per error class (verdict invalid), plus the two
// manipulations that leave a record unknown (verdict incomplete).
func buildTampered(priv ed25519.PrivateKey) []StreamCase {
	var cases []StreamCase

	// hash_mismatch: record 2 edited in the file, hashes left as they were.
	t := transferWorker()
	hl := lines(t...)
	hl[2] = forge(hl[2])
	cases = append(cases, StreamCase{File: "hash-mismatch.jsonl",
		Description: "Record 2, a failed job, was edited in the file to read status ok. Its content_hash and chain_hash were left alone, so both no longer match: hash_mismatch on record 2, invalid. Record 3 still links to the declared chain_hash, so it is valid.",
		OK:          false, Records: 4, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassHashMismatch}}, States: states("vviv"), ProfileStates: none(4), Lines: hl})

	// chain_break: record 2 edited and re-sealed; record 3 still links to the original.
	t = transferWorker()
	forged := *t[2]
	forged.Payload = json.RawMessage(forge(string(t[2].Payload)))
	seal(&forged, t[1].ChainHash)
	cases = append(cases, StreamCase{File: "chain-break.jsonl",
		Description: "Record 2 was edited the same way and then re-sealed: its hashes are recomputed and consistent, so it is valid on its own. Record 3 still carries the prev_hash of the original record 2, so the link from 3 to 2 fails: chain_break on record 3, invalid.",
		OK:          false, Records: 4, Findings: []ExpectedFinding{{Index: 3, Class: evidence.ClassChainBreak}}, States: states("vvvi"), ProfileStates: none(4), Lines: lines(t[0], t[1], &forged, t[3])})

	// seq_mismatch: record 2 deleted, record 3 re-sealed to link to record 1.
	t = transferWorker()
	relinked := *t[3]
	seal(&relinked, t[1].ChainHash)
	cases = append(cases, StreamCase{File: "seq-mismatch.jsonl",
		Description: "Record 2, the failed job, was deleted and record 3 re-sealed so that it links to record 1. Every hash and link checks out, but the record that links to seq 1 has seq 3: seq_mismatch on the record that is now at index 2, invalid.",
		OK:          false, Records: 3, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassSeqMismatch}}, States: states("vvi"), ProfileStates: none(3), Lines: lines(t[0], t[1], &relinked)})

	// signature_invalid: signed journal, record 2 edited, records 2 and 3
	// re-sealed so the chain is intact, the original signatures kept.
	t = transferWorker()
	for _, r := range t {
		if err := evidence.Sign(r, priv, ""); err != nil {
			panic(err)
		}
	}
	sForged := *t[2]
	sForged.Payload = json.RawMessage(forge(string(t[2].Payload)))
	seal(&sForged, t[1].ChainHash)
	sForged.Signature = t[2].Signature
	sNext := *t[3]
	seal(&sNext, sForged.ChainHash)
	sNext.Signature = t[3].Signature
	cases = append(cases, StreamCase{File: "signature-invalid.jsonl",
		Description: "The journal was signed with the TEST KEY. Record 2 was edited and records 2 and 3 were re-sealed, so every hash, link and seq checks out and verification without a key passes. The signatures were copied from the originals and cover the old chain_hash values: with the test public key, signature_invalid on records 2 and 3.",
		PublicKey:   "../../testdata/keys/test-ed25519.pub", RequireSignatures: true,
		OK: false, Records: 4, Findings: []ExpectedFinding{{Index: 2, Class: evidence.ClassSignatureInvalid}, {Index: 3, Class: evidence.ClassSignatureInvalid}}, States: states("vvii"), ProfileStates: none(4), Lines: lines(t[0], t[1], &sForged, &sNext)})

	// seq_gap: record 2 deleted, nothing re-sealed.
	t = transferWorker()
	dl := lines(t[0], t[1], t[3])
	df := []ExpectedFinding{{Index: 2, Class: evidence.ClassSeqGap}}
	cases = append(cases, StreamCase{File: "seq-gap.jsonl",
		Description: "Record 2, the failed job, was deleted and nothing else changed. Record 3 links to the deleted record, which the journal does not have: seq_gap, state unknown. No record is provably invalid, but the journal is incomplete, which fails (exit code 3).",
		OK:          false, Records: 3, Findings: df, States: states("vvu"), ProfileStates: none(3), Lines: dl})
	cases = append(cases, StreamCase{File: "seq-gap.jsonl", AllowIncomplete: true,
		Description: "The same journal with --allow-incomplete: accepted. This is why the option is only for journals known to be incomplete.",
		OK:          true, Records: 3, Findings: df, States: states("vvu"), ProfileStates: none(3), Lines: dl})

	// outside_scope: record 2 edited and its schema changed to another major version.
	t = transferWorker()
	ol := lines(t...)
	ol[2] = replaceOnce(forge(ol[2]), `"schema":"trail.evidence/1"`, `"schema":"trail.evidence/2"`)
	of := []ExpectedFinding{{Index: 2, Class: evidence.ClassOutsideScope}, {Index: 3, Class: evidence.ClassSeqGap}}
	cases = append(cases, StreamCase{File: "outside-scope.jsonl",
		Description: "Record 2 was edited and its schema changed to trail.evidence/2, so that a verifier for trail.evidence/1 does not check it: outside_scope. Record 3 still links to the original record 2, which the chain therefore does not have: seq_gap, unknown. The journal is incomplete (one record outside the scope, one unknown), which fails (exit code 3).",
		OK:          false, Records: 4, Findings: of, States: states("vvou"), ProfileStates: none(4), Lines: ol})
	cases = append(cases, StreamCase{File: "outside-scope.jsonl", AllowIncomplete: true,
		Description: "The same journal with --allow-incomplete: accepted.",
		OK:          true, Records: 4, Findings: of, States: states("vvou"), ProfileStates: none(4), Lines: ol})

	return cases
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
	return marshalIndex("Each case names a JSON Lines fixture, the options (pubkey, require_signatures, allow_incomplete, require_known_profiles) and the verdict (valid, invalid, incomplete), ok and exit code of the verify command a verifier must reach. findings lists the distinct (index, class) pairs in order of first occurrence; states and profile_states list the expected state and profile state of every record; index counts non-empty lines from 0. pubkey paths are relative to this file. A file may appear in several cases with different options.", cases)
}

// MarshalTamperedIndex renders examples/tampered/expected.json.
func MarshalTamperedIndex(cases []StreamCase) []byte {
	return marshalIndex("Manipulated copies of examples/transfer-worker.jsonl and the verdict a verifier must reach. Same format as testdata/streams/expected.json: findings lists the distinct (index, class) pairs in order of first occurrence, states and profile_states the expected state of every record; pubkey paths are relative to this file.", cases)
}

// withVerdicts derives each case's verdict and exit code from its expected
// states and options and panics when the hand-written OK disagrees.
func withVerdicts(cases []StreamCase) []StreamCase {
	out := make([]StreamCase, len(cases))
	for i, c := range cases {
		count := func(list []string, v string) int {
			n := 0
			for _, x := range list {
				if x == v {
					n++
				}
			}
			return n
		}
		unknownProfiles := c.RequireKnownProfiles && count(c.ProfileStates, evidence.StateOutsideScope) > 0
		switch {
		case count(c.States, evidence.StateInvalid) > 0:
			c.Verdict = evidence.VerdictInvalid
		case count(c.States, evidence.StateUnknown)+count(c.States, evidence.StateOutsideScope) > 0 || unknownProfiles:
			c.Verdict = evidence.VerdictIncomplete
		default:
			c.Verdict = evidence.VerdictValid
		}
		ok := c.Verdict == evidence.VerdictValid || (c.Verdict == evidence.VerdictIncomplete && c.AllowIncomplete && !unknownProfiles)
		if ok != c.OK {
			panic(fmt.Sprintf("case %s: ok %v contradicts verdict %s and the options", c.File, c.OK, c.Verdict))
		}
		switch {
		case ok:
			c.ExitCode = evidence.ExitValid
		case c.Verdict == evidence.VerdictInvalid:
			c.ExitCode = evidence.ExitInvalid
		default:
			c.ExitCode = evidence.ExitIncomplete
		}
		out[i] = c
	}
	return out
}

func marshalIndex(note string, cases []StreamCase) []byte {
	cases = withVerdicts(cases)
	idx := StreamIndex{
		Note:  note,
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
	files["examples/tampered/expected.json"] = MarshalTamperedIndex(out.Tampered)
	for _, c := range out.Tampered {
		files["examples/tampered/"+c.File] = []byte(strings.Join(c.Lines, "\n") + "\n")
	}
	// The browser verifier ships copies of two journals next to the page.
	for _, copied := range []string{"examples/transfer-worker.jsonl", "examples/tampered/hash-mismatch.jsonl"} {
		files["web/"+copied] = files[copied]
	}
	for _, j := range out.ProfileJournals {
		files["profiles/"+j.File] = []byte(strings.Join(j.Lines, "\n") + "\n")
	}
	return files
}
