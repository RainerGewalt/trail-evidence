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
	if code := run([]string{"verify", "../../../testdata/streams/seq-gap.jsonl", "--json"}, &out, &errb); code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(out.String(), `"class": "seq_gap"`) {
		t.Errorf("json output lacks seq_gap: %s", out.String())
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
