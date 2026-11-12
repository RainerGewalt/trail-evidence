package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"verify", "../../../examples/transfer-worker.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.HasPrefix(out.String(), "VALID:") {
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
	if code := run([]string{"verify", "../../../testdata/streams/seq-gap.jsonl"}, &out, &errb); code != 3 {
		t.Fatalf("seq-gap: expected exit 3 (incomplete), got %d: %s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), "INCOMPLETE:") {
		t.Errorf("unexpected output %q", out.String())
	}
	out.Reset()
	if code := run([]string{"verify", "../../../testdata/streams/seq-gap.jsonl", "--allow-incomplete", "--json"}, &out, &errb); code != 0 {
		t.Fatalf("seq-gap with --allow-incomplete: expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), `"verdict": "incomplete"`) || !strings.Contains(out.String(), `"state": "unknown"`) {
		t.Errorf("json output: %s", out.String())
	}
	out.Reset()
	if code := run([]string{"verify", "../../../testdata/streams/profile-unknown.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("unknown profiles must not affect the verdict, got exit %d", code)
	}
	if code := run([]string{"verify", "../../../testdata/streams/profile-unknown.jsonl", "--require-known-profiles", "--allow-incomplete"}, &out, &errb); code != 3 {
		t.Fatalf("--require-known-profiles: expected exit 3, got %d", code)
	}
	if code := run([]string{"verify", "../../../testdata/streams/seq-gap.jsonl", "--strict"}, &out, &errb); code != 2 {
		t.Errorf("--strict is not a flag any more: expected exit 2, got %d", code)
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
	if !strings.HasPrefix(versionString(), "0.3.0-dev") && !strings.HasPrefix(versionString(), "v") {
		t.Errorf("version %q", versionString())
	}
}

// TestVerifyInputErrors: a journal that cannot be read gets no verdict and
// no report, only exit code 2 and a message (SPEC.md section 6.4); an empty
// journal is incomplete, also with --allow-incomplete.
func TestVerifyInputErrors(t *testing.T) {
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "unreadable.jsonl")
	if err := os.WriteFile(unreadable, []byte("{}\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{"directory": dir, "missing file": filepath.Join(dir, "missing.jsonl")}
	if f, err := os.Open(unreadable); err == nil {
		f.Close() // running as root: permissions do not apply
	} else {
		cases["file without read permission"] = unreadable
	}
	for name, path := range cases {
		for _, extra := range [][]string{nil, {"--json"}, {"--allow-incomplete", "--json"}} {
			var out, errb bytes.Buffer
			code := run(append([]string{"verify", path}, extra...), &out, &errb)
			if code != 2 || out.Len() != 0 || errb.Len() == 0 {
				t.Errorf("%s %v: exit %d, stdout %q, stderr %q; want exit 2, no report, a message", name, extra, code, out.String(), errb.String())
			}
		}
	}
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{nil, {"--allow-incomplete"}} {
		var out, errb bytes.Buffer
		if code := run(append([]string{"verify", empty}, extra...), &out, &errb); code != 3 || !strings.HasPrefix(out.String(), "INCOMPLETE: 0 record(s)") {
			t.Errorf("empty journal %v: exit %d, output %q; want exit 3, INCOMPLETE", extra, code, out.String())
		}
	}
}
