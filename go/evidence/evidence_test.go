package evidence_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
			rec, findings := evidence.VerifyRecord(v.Record)
			if rec == nil {
				t.Fatalf("record did not decode: %v", findings)
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
		File              string `json:"file"`
		PublicKey         string `json:"pubkey"`
		RequireSignatures bool   `json:"require_signatures"`
		OK                bool   `json:"ok"`
		Records           int    `json:"records"`
		Restarts          int    `json:"restarts"`
		Findings          []struct {
			Index int    `json:"index"`
			Class string `json:"class"`
		} `json:"findings"`
	} `json:"cases"`
}

func TestStreamFixtures(t *testing.T) {
	dir := filepath.Join(repoRoot, "testdata", "streams")
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
		t.Run(c.File, func(t *testing.T) {
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
			rep := evidence.VerifyStream(f, opts)
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
				k := string(rune('0'+f.Index)) + ":" + f.Class
				if !seen[k] {
					seen[k] = true
					got = append(got, k)
				}
			}
			var want []string
			for _, f := range c.Findings {
				want = append(want, string(rune('0'+f.Index))+":"+f.Class)
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("findings got %v want %v", got, want)
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
		"negative seq":             mutate(`"seq":0`, `"seq":-1`),
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
