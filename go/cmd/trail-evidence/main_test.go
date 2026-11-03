package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVerifyCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"verify", "../../../examples/transfer-worker.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.HasPrefix(out.String(), "OK:") {
		t.Errorf("unexpected output %q", out.String())
	}
	out.Reset()
	if code := run([]string{"verify", "../../../testdata/streams/signed.jsonl", "--pubkey", "../../../testdata/keys/test-ed25519.pub", "--require-signatures"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"verify", "../../../testdata/streams/seq-mismatch.jsonl", "--json"}, &out, &errb); code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(out.String(), `"class": "seq_mismatch"`) || !strings.Contains(out.String(), `"seq": "3"`) {
		t.Errorf("json output lacks seq_mismatch or the decimal seq: %s", out.String())
	}
	out.Reset()
	if code := run([]string{"verify", "../../../testdata/streams/seq-gap.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("seq-gap without --strict: expected exit 0, got %d: %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"verify", "../../../testdata/streams/seq-gap.jsonl", "--strict", "--json"}, &out, &errb); code != 1 {
		t.Fatalf("seq-gap with --strict: expected exit 1, got %d", code)
	}
	if !strings.Contains(out.String(), `"strict": true`) || !strings.Contains(out.String(), `"state": "unknown"`) {
		t.Errorf("strict json output: %s", out.String())
	}
	if code := run([]string{"verify"}, &out, &errb); code != 2 {
		t.Errorf("usage error should exit 2, got %d", code)
	}
}

func TestVectorsCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"vectors"}, &out, &errb); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(out.String(), `"name": "genesis-minimal"`) {
		t.Error("vectors output lacks genesis-minimal")
	}
}

func TestHashCommandState(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"hash", "../../../profiles/example.measurement/1.schema.json"}, &out, &errb); code != 2 {
		t.Errorf("a schema without payload should exit 2, got %d", code)
	}
	if code := run([]string{"profiles"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "example.measurement/1") {
		t.Errorf("profiles: %d %s", code, out.String())
	}
	if !strings.HasPrefix(versionString(), "0.2.0-dev") && !strings.HasPrefix(versionString(), "v") {
		t.Errorf("version %q", versionString())
	}
}
