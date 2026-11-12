package evidence_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/RainerGewalt/trail-evidence/go/evidence"
)

const repoRoot = "../.."

type vectorFile struct {
	TestKey struct {
		SeedHex   string `json:"seed_hex"`
		PublicHex string `json:"public_hex"`
		KeyID     string `json:"key_id"`
	} `json:"test_key"`
	Vectors []struct {
		Name                string          `json:"name"`
		Record              json.RawMessage `json:"record"`
		ExpectedPayloadJCS  string          `json:"expected_payload_jcs"`
		ExpectedContentHash string          `json:"expected_content_hash"`
		ExpectedCoreJCS     string          `json:"expected_core_jcs"`
		ExpectedChainHash   string          `json:"expected_chain_hash"`
		ExpectedValid       bool            `json:"expected_valid"`
		ExpectedError       string          `json:"expected_error"`
		ExpectedNotices     []string        `json:"expected_notices"`
		ExpectedState       string          `json:"expected_state"`
		ExpectedProfile     string          `json:"expected_profile_state"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Vectors) < 8 {
		t.Fatalf("expected at least 8 vectors, got %d", len(vf.Vectors))
	}
	return vf
}

func TestVectorsReproduce(t *testing.T) {
	vf := loadVectors(t)
	byName := map[string]string{}
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			h, err := evidence.ComputeHashes(v.Record)
			if err != nil {
				t.Fatal(err)
			}
			if string(h.PayloadJCS) != v.ExpectedPayloadJCS {
				t.Errorf("payload JCS\n got %s\nwant %s", h.PayloadJCS, v.ExpectedPayloadJCS)
			}
			if h.ContentHash != v.ExpectedContentHash {
				t.Errorf("content_hash got %s want %s", h.ContentHash, v.ExpectedContentHash)
			}
			if string(h.CoreJCS) != v.ExpectedCoreJCS {
				t.Errorf("core JCS\n got %s\nwant %s", h.CoreJCS, v.ExpectedCoreJCS)
			}
			if h.ChainHash != v.ExpectedChainHash {
				t.Errorf("chain_hash got %s want %s", h.ChainHash, v.ExpectedChainHash)
			}
			c := evidence.CheckRecord(v.Record)
			rec, findings := c.Record, c.Findings
			if rec == nil {
				t.Fatalf("record did not decode: %v", findings)
			}
			if c.State != v.ExpectedState || c.ProfileState != v.ExpectedProfile {
				t.Errorf("state %s/%s, want %s/%s", c.State, c.ProfileState, v.ExpectedState, v.ExpectedProfile)
			}
			var errs, notices []string
			for _, f := range findings {
				if f.Severity == evidence.SeverityNotice {
					notices = append(notices, f.Class)
				} else {
					errs = append(errs, f.Class)
				}
			}
			if strings.Join(notices, ",") != strings.Join(v.ExpectedNotices, ",") {
				t.Errorf("notices got %v want %v", notices, v.ExpectedNotices)
			}
			if v.ExpectedValid {
				if len(errs) != 0 {
					t.Errorf("unexpected findings: %+v", findings)
				}
			} else {
				found := false
				for _, f := range findings {
					if f.Class == v.ExpectedError {
						found = true
					}
				}
				if !found {
					t.Errorf("expected finding %s, got %+v", v.ExpectedError, findings)
				}
			}
			byName[v.Name] = v.ExpectedChainHash
		})
	}
	if byName["context-absent"] != byName["context-present"] {
		t.Errorf("context must not change chain_hash: %s vs %s", byName["context-absent"], byName["context-present"])
	}
	if byName["genesis-minimal"] == byName["second-chained"] {
		t.Error("distinct records must not share a chain_hash")
	}
}

func TestVectorsSignature(t *testing.T) {
	vf := loadVectors(t)
	pubBytes, err := hex.DecodeString(vf.TestKey.PublicHex)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PublicKey(pubBytes)
	if evidence.KeyID(pub) != vf.TestKey.KeyID {
		t.Errorf("key id got %s want %s", evidence.KeyID(pub), vf.TestKey.KeyID)
	}
	seed, _ := hex.DecodeString(vf.TestKey.SeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		t.Fatal("seed and public key do not belong together")
	}
	for _, v := range vf.Vectors {
		if v.Name != "signed" {
			continue
		}
		rec, findings := evidence.VerifyRecord(v.Record)
		if rec == nil || len(findings) != 0 {
			t.Fatalf("signed vector should be valid: %+v", findings)
		}
		if rec.Signature == nil {
			t.Fatal("signed vector carries no signature")
		}
		if err := evidence.VerifySignature(pub, rec.ChainHash, rec.Signature); err != nil {
			t.Errorf("signature should verify: %v", err)
		}
		// Re-signing must be deterministic (Ed25519 is) and reproduce sig.
		clone := *rec
		if err := evidence.Sign(&clone, priv, ""); err != nil {
			t.Fatal(err)
		}
		if clone.Signature.Sig != rec.Signature.Sig {
			t.Errorf("re-signing produced %s, vector has %s", clone.Signature.Sig, rec.Signature.Sig)
		}
		other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
		if err := evidence.VerifySignature(other, rec.ChainHash, rec.Signature); err == nil {
			t.Error("signature verified with the wrong key")
		}
	}
}

type streamIndex struct {
	Cases []struct {
		File              string   `json:"file"`
		PublicKey         string   `json:"pubkey"`
		RequireSignatures bool     `json:"require_signatures"`
		AllowIncomplete   bool     `json:"allow_incomplete"`
		RequireKnown      bool     `json:"require_known_profiles"`
		Verdict           string   `json:"verdict"`
		ExitCode          int      `json:"exit_code"`
		OK                bool     `json:"ok"`
		Records           int      `json:"records"`
		Restarts          int      `json:"restarts"`
		States            []string `json:"states"`
		ProfileStates     []string `json:"profile_states"`
		Findings          []struct {
			Index int    `json:"index"`
			Class string `json:"class"`
		} `json:"findings"`
	} `json:"cases"`
}

func TestStreamFixtures(t *testing.T) {
	checkIndex(t, filepath.Join(repoRoot, "testdata", "streams"))
}

// TestTamperedExamples checks examples/tampered against its expected.json:
// one manipulated copy of the transfer-worker journal per error class.
func TestTamperedExamples(t *testing.T) {
	checkIndex(t, filepath.Join(repoRoot, "examples", "tampered"))
}

func checkIndex(t *testing.T, dir string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx streamIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Cases) == 0 {
		t.Fatal("no stream cases")
	}
	for _, c := range idx.Cases {
		name := c.File
		if c.AllowIncomplete {
			name += "/allow-incomplete"
		}
		if c.RequireKnown {
			name += "/require-known-profiles"
		}
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join(dir, c.File))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var opts evidence.Options
			if c.PublicKey != "" {
				pub, err := evidence.ParsePublicKey(filepath.Join(dir, c.PublicKey))
				if err != nil {
					t.Fatal(err)
				}
				opts.PublicKey = pub
				opts.RequireSignatures = c.RequireSignatures
			}
			opts.AllowIncomplete = c.AllowIncomplete
			opts.RequireKnownProfiles = c.RequireKnown
			rep := evidence.VerifyStream(f, opts)
			if rep.Verdict != c.Verdict || rep.ExitCode() != c.ExitCode {
				t.Errorf("verdict %s exit %d, want %s exit %d", rep.Verdict, rep.ExitCode(), c.Verdict, c.ExitCode)
			}
			if rep.OK != c.OK {
				t.Errorf("ok got %v want %v: %s", rep.OK, c.OK, rep.Summary())
			}
			if rep.Records != c.Records {
				t.Errorf("records got %d want %d", rep.Records, c.Records)
			}
			if rep.Restarts != c.Restarts {
				t.Errorf("restarts got %d want %d", rep.Restarts, c.Restarts)
			}
			var got []string
			seen := map[string]bool{}
			for _, f := range rep.Findings {
				k := fmt.Sprintf("%d:%s", f.Index, f.Class)
				if !seen[k] {
					seen[k] = true
					got = append(got, k)
				}
			}
			var want []string
			for _, f := range c.Findings {
				want = append(want, fmt.Sprintf("%d:%s", f.Index, f.Class))
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("findings got %v want %v", got, want)
			}
			var gotStates, gotProfiles []string
			for i, r := range rep.Results {
				if r.Index != i {
					t.Errorf("result %d has index %d", i, r.Index)
				}
				gotStates = append(gotStates, r.State)
				gotProfiles = append(gotProfiles, r.ProfileState)
			}
			if strings.Join(gotStates, ",") != strings.Join(c.States, ",") {
				t.Errorf("states got %v want %v", gotStates, c.States)
			}
			if strings.Join(gotProfiles, ",") != strings.Join(c.ProfileStates, ",") {
				t.Errorf("profile states got %v want %v", gotProfiles, c.ProfileStates)
			}
			counts := map[string]int{}
			for _, st := range c.States {
				counts[st]++
			}
			if rep.States.Valid != counts["valid"] || rep.States.Invalid != counts["invalid"] || rep.States.Unknown != counts["unknown"] || rep.States.OutsideScope != counts["outside_scope"] {
				t.Errorf("state counts %+v do not match %v", rep.States, c.States)
			}
			if rep.AllowIncomplete != c.AllowIncomplete || rep.RequireKnownProfiles != c.RequireKnown {
				t.Errorf("report options %v/%v, want %v/%v", rep.AllowIncomplete, rep.RequireKnownProfiles, c.AllowIncomplete, c.RequireKnown)
			}
			if (rep.Verdict == evidence.VerdictInvalid) != (rep.Errors > 0) {
				t.Errorf("verdict %s with %d error(s)", rep.Verdict, rep.Errors)
			}
		})
	}
}

func TestExamplesVerify(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot, "examples", "*.jsonl"))
	if err != nil || len(files) < 4 {
		t.Fatalf("expected at least 4 example journals, got %d (%v)", len(files), err)
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			rep := evidence.VerifyStream(f, evidence.Options{})
			if !rep.OK || rep.Records < 3 || rep.Records > 5 {
				t.Errorf("%s: %s %+v", path, rep.Summary(), rep.Findings)
			}
		})
	}
}

func TestSealRoundTrip(t *testing.T) {
	r := evidence.Record{
		Producer:  evidence.Producer{Kind: evidence.ProducerOther, ID: "t", Version: "1"},
		StreamID:  "t",
		EventType: "test.seal.roundtrip",
		Time:      evidence.Time{RecordedAt: "2026-11-02T00:00:00.000Z", Source: evidence.TimeSourceSystem},
		Actor:     evidence.Actor{Auth: evidence.AuthNone},
		Policy:    evidence.NoPolicy,
		Payload:   json.RawMessage(`{"k": [1, 2.50, "x"]}`),
		Context:   json.RawMessage(`{"ignored": true}`),
	}
	if err := evidence.Seal(&r, evidence.GenesisHash); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(&r)
	if err != nil {
		t.Fatal(err)
	}
	rec, findings := evidence.VerifyRecord(raw)
	if rec == nil || len(findings) != 0 {
		t.Fatalf("sealed record should verify: %+v", findings)
	}
	// Context changes must not change the hashes.
	r2 := r
	r2.Context = nil
	if err := evidence.Seal(&r2, evidence.GenesisHash); err != nil {
		t.Fatal(err)
	}
	if r2.ChainHash != r.ChainHash {
		t.Error("context changed chain_hash")
	}
	// Restart invariants.
	r3 := r
	r3.ChainRestart = true
	r3.AnchorHash = r.ChainHash
	if err := evidence.Seal(&r3, evidence.GenesisHash); err == nil {
		t.Error("restart with prev != anchor should fail")
	}
	if err := evidence.Seal(&r3, r.ChainHash); err != nil {
		t.Error(err)
	}
	r4 := r
	r4.AnchorHash = r.ChainHash
	if err := evidence.Seal(&r4, evidence.GenesisHash); err == nil {
		t.Error("anchor_hash without chain_restart should fail")
	}
}

func TestVerifyRecordSchemaChecks(t *testing.T) {
	vf := loadVectors(t)
	var compact bytes.Buffer
	if err := json.Compact(&compact, vf.Vectors[0].Record); err != nil {
		t.Fatal(err)
	}
	base := compact.Bytes()
	mutate := func(from, to string) []byte {
		out := strings.Replace(string(base), from, to, 1)
		if out == string(base) {
			t.Fatalf("mutation %q not applied", from)
		}
		return []byte(out)
	}
	cases := map[string][]byte{
		"unknown top-level member": mutate(`"schema":`, `"extra":1,"schema":`),
		"unknown producer member":  mutate(`"kind":"other"`, `"kind":"other","x":1`),
		"bad time source":          mutate(`"source":"system"`, `"source":"wall-clock"`),
		"bad event type":           mutate(`"event_type":"test.record.created"`, `"event_type":"Created"`),
		"bad hash pattern":         mutate(`"prev_hash":"sha256:0`, `"prev_hash":"SHA256:0`),
		"seconds only":             mutate(`08:00:00.000Z`, `08:00:00Z`),
		"negative seq":             mutate(`"seq":"0"`, `"seq":"-1"`),
		"seq leading zero":         mutate(`"seq":"0"`, `"seq":"00"`),
		"seq with sign":            mutate(`"seq":"0"`, `"seq":"+0"`),
		"seq with whitespace":      mutate(`"seq":"0"`, `"seq":" 0"`),
		"seq beyond uint64":        mutate(`"seq":"0"`, `"seq":"18446744073709551616"`),
		"seq float literal":        mutate(`"seq":"0"`, `"seq":0.0`),
		"seq negative zero":        mutate(`"seq":"0"`, `"seq":-0`),
		"seq exponent":             mutate(`"seq":"0"`, `"seq":1e2`),
		"seq boolean":              mutate(`"seq":"0"`, `"seq":true`),
		"seq null":                 mutate(`"seq":"0"`, `"seq":null`),
		"seq missing":              mutate(`"seq":"0",`, ``),
		"profile wrong type":       mutate(`"schema":`, `"profile":7,"schema":`),
		"profile no major":         mutate(`"schema":`, `"profile":"example.measurement","schema":`),
		"profile major zero":       mutate(`"schema":`, `"profile":"example.measurement/0","schema":`),
		"profile one segment":      mutate(`"schema":`, `"profile":"measurement/1","schema":`),
		"schema not an identifier": mutate(`"schema":"trail.evidence/1"`, `"schema":"Trail Evidence"`),
		"schema not a string":      mutate(`"schema":"trail.evidence/1"`, `"schema":1`),
		"not an object":            []byte(`[1,2,3]`),
		"trailing garbage":         append(append([]byte{}, base...), []byte(` {}`)...),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, findings := evidence.VerifyRecord(raw)
			hasSchema := false
			for _, f := range findings {
				if f.Class == evidence.ClassSchemaInvalid {
					hasSchema = true
				}
			}
			if !hasSchema {
				t.Errorf("expected schema_invalid, got %+v", findings)
			}
		})
	}
}

func TestCanonicalizeEdgeCases(t *testing.T) {
	cases := map[string]string{
		`{"b":1.0,"a":1e21}`:           `{"a":1e+21,"b":1}`,
		`{"x":-0.0,"y":1E+2,"z":1e-7}`: `{"x":0,"y":100,"z":1e-7}`,
		`{"！":1,"🚀":2}`:                "{\"\U0001F680\":2,\"！\":1}",
		`{"s":"\u0001\u001F\/ä"}`:      "{\"s\":\"\\u0001\\u001f/ä\"}",
		`  [ 1 , "a" , null ]  `:       `[1,"a",null]`,
	}
	for in, want := range cases {
		got, err := evidence.Canonicalize([]byte(in))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
	if _, err := evidence.Canonicalize([]byte(``)); err == nil {
		t.Error("empty input should fail")
	}
}

func TestParsePublicKey(t *testing.T) {
	vf := loadVectors(t)
	pub, err := evidence.ParsePublicKey(vf.TestKey.PublicHex)
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := evidence.ParsePublicKey(filepath.Join(repoRoot, "testdata", "keys", "test-ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, fromFile) {
		t.Error("hex and file keys differ")
	}
	if _, err := evidence.ParsePublicKey("not-a-key"); err == nil {
		t.Error("garbage should not parse")
	}
}

func TestSeqForms(t *testing.T) {
	vf := loadVectors(t)
	var compact bytes.Buffer
	if err := json.Compact(&compact, vf.Vectors[0].Record); err != nil {
		t.Fatal(err)
	}
	base := compact.String()
	cases := []struct {
		seq    string
		ok     bool
		legacy bool
	}{
		{`"0"`, true, false},
		{`"18446744073709551615"`, true, false},
		{`"9007199254740993"`, true, false},
		{`"\u0037"`, true, false},
		{`7`, true, true},
		{`18446744073709551615`, true, true},
		{`18446744073709551616`, false, false},
		{`"18446744073709551616"`, false, false},
		{`"007"`, false, false},
		{`""`, false, false},
		{`"7.0"`, false, false},
		{`"1e3"`, false, false},
		{`-1`, false, false},
	}
	for _, c := range cases {
		raw := strings.Replace(base, `"seq":"0"`, `"seq":`+c.seq, 1)
		rc := evidence.CheckRecord([]byte(raw))
		var classes []string
		for _, f := range rc.Findings {
			classes = append(classes, f.Class)
		}
		hasSchema := strings.Contains(strings.Join(classes, ","), evidence.ClassSchemaInvalid)
		hasLegacy := strings.Contains(strings.Join(classes, ","), evidence.ClassLegacyIntegerSeq)
		if hasSchema == c.ok || hasLegacy != c.legacy {
			t.Errorf("seq %s: findings %v, want usable=%v legacy=%v", c.seq, classes, c.ok, c.legacy)
		}
	}
}

func TestSealWritesDecimalSeq(t *testing.T) {
	r := evidence.Record{
		Producer:  evidence.Producer{Kind: evidence.ProducerOther, ID: "t", Version: "1"},
		StreamID:  "t",
		Seq:       evidence.MaxSeq,
		EventType: "test.seal.seq",
		Time:      evidence.Time{RecordedAt: "2026-11-02T00:00:00.000Z", Source: evidence.TimeSourceSystem},
		Actor:     evidence.Actor{Auth: evidence.AuthNone},
		Policy:    evidence.NoPolicy,
		Profile:   "example.measurement/1",
		Payload:   json.RawMessage(`{"quantity":"q","value":"1","unit":"u"}`),
	}
	if err := evidence.Seal(&r, evidence.GenesisHash); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(&r)
	if !bytes.Contains(raw, []byte(`"seq":"18446744073709551615"`)) {
		t.Errorf("seq is not written as a decimal string: %s", raw)
	}
	c := evidence.CheckRecord(raw)
	if c.State != evidence.StateValid || c.ProfileState != evidence.StateValid || len(c.Findings) != 0 {
		t.Errorf("sealed record: %s/%s %+v", c.State, c.ProfileState, c.Findings)
	}
	var back evidence.Record
	if err := json.Unmarshal(raw, &back); err != nil || back.Seq != evidence.MaxSeq || back.Profile != r.Profile {
		t.Errorf("round trip: %v %d %q", err, back.Seq, back.Profile)
	}
}

type profileExamples struct {
	Profile string `json:"profile"`
	Valid   []struct {
		Description string          `json:"description"`
		Payload     json.RawMessage `json:"payload"`
	} `json:"valid"`
	Invalid []struct {
		Description string          `json:"description"`
		Payload     json.RawMessage `json:"payload"`
	} `json:"invalid"`
}

// TestProfileExamples checks every profile's example payloads against the
// embedded registry.
func TestProfileExamples(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot, "profiles", "*", "*.examples.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no profile examples (%v)", err)
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var ex profileExamples
		if err := json.Unmarshal(raw, &ex); err != nil {
			t.Fatal(err)
		}
		if len(ex.Valid) == 0 || len(ex.Invalid) == 0 {
			t.Errorf("%s: needs valid and invalid examples", path)
		}
		for _, v := range ex.Valid {
			known, problems := evidence.ValidateProfilePayload(ex.Profile, v.Payload)
			if !known || len(problems) != 0 {
				t.Errorf("%s: valid example %q: known=%v %v", ex.Profile, v.Description, known, problems)
			}
		}
		for _, v := range ex.Invalid {
			known, problems := evidence.ValidateProfilePayload(ex.Profile, v.Payload)
			if !known || len(problems) == 0 {
				t.Errorf("%s: invalid example %q passed", ex.Profile, v.Description)
			}
		}
	}
	if known, _ := evidence.ValidateProfilePayload("example.measurement/2", json.RawMessage(`{}`)); known {
		t.Error("example.measurement/2 must not be known")
	}
}

// TestEmbeddedProfilesMatchRegistry: the embedded copy under go/evidence/profiles
// must equal profiles/ at the repository root (scripts/profiles.py --write).
func TestEmbeddedProfilesMatchRegistry(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot, "profiles", "*", "*.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, path := range files {
		name := filepath.Base(filepath.Dir(path))
		major := strings.TrimSuffix(filepath.Base(path), ".schema.json")
		id := name + "/" + major
		want = append(want, id)
		root, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		embedded, ok := evidence.ProfileSchema(id)
		if !ok || !bytes.Equal(root, embedded) {
			t.Errorf("%s: embedded schema differs from profiles/ (run scripts/profiles.py --write)", id)
		}
	}
	sort.Strings(want)
	if strings.Join(want, ",") != strings.Join(evidence.Profiles(), ",") {
		t.Errorf("registry %v, embedded %v", want, evidence.Profiles())
	}
}

// TestProfileJournals: every journal in the registry verifies, strictly, with
// every record valid and every profile valid.
func TestProfileJournals(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot, "profiles", "*", "*.journal.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no profile journals (%v)", err)
	}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		rep := evidence.VerifyStream(f, evidence.Options{RequireKnownProfiles: true})
		f.Close()
		if !rep.OK || rep.Verdict != evidence.VerdictValid || rep.States.Valid != rep.Records || rep.ProfileStates.Valid != rep.Records {
			t.Errorf("%s: %s %+v %+v", path, rep.Summary(), rep.States, rep.ProfileStates)
		}
	}
}

func testKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, err := evidence.ParsePublicKey(filepath.Join(repoRoot, "testdata", "keys", "test-ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// otherKey is the public key of the seed 0x42 repeated, which did not sign
// any fixture.
func otherKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, err := evidence.ParsePublicKey("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestSummaryLines(t *testing.T) {
	cases := []struct {
		file string
		opts evidence.Options
		want string
	}{
		{"valid-chain.jsonl", evidence.Options{}, "VALID: 3 record(s) in 1 stream(s), hash chain intact"},
		{"seq-gap.jsonl", evidence.Options{}, "INCOMPLETE: 4 record(s) in 1 stream(s), no invalid record, 1 unknown"},
		{"seq-gap.jsonl", evidence.Options{AllowIncomplete: true}, "INCOMPLETE (allowed): 4 record(s) in 1 stream(s), no invalid record, 1 unknown"},
		{"outside-scope.jsonl", evidence.Options{}, "INCOMPLETE: 4 record(s) in 1 stream(s), hash chain intact, 2 outside scope"},
		{"seq-mismatch.jsonl", evidence.Options{}, "INVALID: 3 record(s) in 1 stream(s), 1 error(s)"},
		{"profile-unknown.jsonl", evidence.Options{}, "VALID: 3 record(s) in 1 stream(s), hash chain intact, 2 with unknown profile (payload not checked)"},
		{"profile-unknown.jsonl", evidence.Options{RequireKnownProfiles: true}, "INCOMPLETE: 3 record(s) in 1 stream(s), hash chain intact, 2 with unknown profile (payload not checked)"},
		// A summary says which signatures were not checked (rule of 8 November:
		// a verifier says what it does not prove). The same lines in Python and
		// JavaScript; scripts/crosscheck.sh compares them on every fixture.
		{"signed.jsonl", evidence.Options{}, "VALID: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), signatures not checked (no key)"},
		{"signed.jsonl", evidence.Options{PublicKey: testKey(t), RequireSignatures: true}, "VALID: 3 record(s) in 1 stream(s), hash chain intact, 3 signed record(s), 3 signature(s) verified"},
		{"signatures-stripped.jsonl", evidence.Options{PublicKey: testKey(t)}, "VALID: 3 record(s) in 1 stream(s), hash chain intact, no record is signed"},
		// Every signature fails with another producer's key: checked, none verified.
		{"signed.jsonl", evidence.Options{PublicKey: otherKey(t)}, "INVALID: 3 record(s) in 1 stream(s), 3 error(s), 3 signed record(s), 0 signature(s) verified"},
		{"signature-invalid.jsonl", evidence.Options{PublicKey: testKey(t), RequireSignatures: true}, "INVALID: 3 record(s) in 1 stream(s), 2 error(s), 2 signed record(s), 1 signature(s) verified, 1 unsigned record(s)"},
		{"../../examples/tampered/signature-invalid.jsonl", evidence.Options{}, "VALID: 4 record(s) in 1 stream(s), hash chain intact, 4 signed record(s), signatures not checked (no key)"},
		{"../../examples/tampered/signature-invalid.jsonl", evidence.Options{PublicKey: testKey(t)}, "INVALID: 4 record(s) in 1 stream(s), 2 error(s), 4 signed record(s), 2 signature(s) verified"},
	}
	for _, c := range cases {
		f, err := os.Open(filepath.Join(repoRoot, "testdata", "streams", c.file))
		if err != nil {
			t.Fatal(err)
		}
		got := evidence.VerifyStream(f, c.opts).Summary()
		f.Close()
		if got != c.want {
			t.Errorf("%s %+v:\n got %s\nwant %s", c.file, c.opts, got, c.want)
		}
	}
}

// TestVerifyStreamReadError: a journal that cannot be read to its end gets
// no verdict (SPEC.md section 6.4). The records read before the error are
// valid; the report must still not pass.
func TestVerifyStreamReadError(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "examples", "transfer-worker.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	head := bytes.SplitAfter(raw, []byte("\n"))[0]
	failing := errors.New("disk read failed")
	for name, rd := range map[string]io.Reader{
		"after the first record": io.MultiReader(bytes.NewReader(head), iotest.ErrReader(failing)),
		"before any record":      iotest.ErrReader(failing),
	} {
		t.Run(name, func(t *testing.T) {
			rep := evidence.VerifyStream(rd, evidence.Options{AllowIncomplete: true})
			if rep.OK || rep.Verdict != "" || rep.ExitCode() != evidence.ExitUsage {
				t.Fatalf("read error: ok %v, verdict %q, exit %d; want ok false, no verdict, exit %d (%s)", rep.OK, rep.Verdict, rep.ExitCode(), evidence.ExitUsage, rep.Summary())
			}
		})
	}
}

// TestEmptyJournal: no record, nothing verified, never a pass.
func TestEmptyJournal(t *testing.T) {
	for _, in := range []string{"", "\n \n\t\r\n"} {
		for _, allow := range []bool{false, true} {
			rep := evidence.VerifyStream(strings.NewReader(in), evidence.Options{AllowIncomplete: allow})
			if rep.OK || rep.Verdict != evidence.VerdictIncomplete || rep.ExitCode() != evidence.ExitIncomplete {
				t.Errorf("%q allow=%v: ok %v, verdict %q, exit %d; want incomplete, exit 3", in, allow, rep.OK, rep.Verdict, rep.ExitCode())
			}
			if want := "INCOMPLETE: 0 record(s) in 0 stream(s), no record: nothing was verified"; rep.Summary() != want {
				t.Errorf("%q allow=%v: summary %q, want %q", in, allow, rep.Summary(), want)
			}
		}
	}
}
