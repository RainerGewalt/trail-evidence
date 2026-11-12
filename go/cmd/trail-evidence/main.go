// Command trail-evidence verifies Trail Evidence journals, recomputes the
// hashes of a single record and prints the reference test vectors.
//
//	trail-evidence verify <file.jsonl|-> [--pubkey <hex|file>] [--require-signatures] [--allow-incomplete] [--require-known-profiles] [--json]
//	trail-evidence hash <record.json|->
//	trail-evidence profiles
//	trail-evidence vectors
//
// Exit codes of verify: 0 verdict valid (or incomplete with
// --allow-incomplete), 1 verdict invalid, 2 usage error or a journal that
// cannot be read (no verdict, no report), 3 verdict incomplete, also for a
// journal without a record. hash exits 1 when the recorded hashes do not
// match.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/RainerGewalt/trail-evidence/go/evidence"
	"github.com/RainerGewalt/trail-evidence/go/internal/vectors"
)

// version is set by the release build (.goreleaser.yaml:
// -ldflags "-X main.version={{ .Version }}"). A binary installed with
// `go install ...@<version>` reports the module version from its build info
// instead; a plain `go build` from a checkout reports devVersion.
var version = ""

// devVersion names the next release after the last tag (docs/RELEASING.md).
const devVersion = "0.3.0-dev"

func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return devVersion
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	case "hash":
		return cmdHash(args[1:], stdout, stderr)
	case "profiles":
		for _, id := range evidence.Profiles() {
			fmt.Fprintln(stdout, id)
		}
		return 0
	case "vectors":
		_, err := stdout.Write(vectors.MarshalVectors(vectors.Build().Vectors))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "trail-evidence %s (schema %s)\n", versionString(), evidence.Schema)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage:
  trail-evidence verify <file.jsonl|-> [--pubkey <hex|file>] [--require-signatures] [--allow-incomplete] [--require-known-profiles] [--json]
  trail-evidence hash <record.json|->
  trail-evidence profiles
  trail-evidence vectors
  trail-evidence version

verify   checks a JSON Lines journal: schema, content_hash, chain_hash,
         prev_hash links, seq, restarts, profiles and (with --pubkey)
         Ed25519 signatures, gives every record a state (valid, invalid,
         unknown, outside_scope) and the journal a verdict:
           valid       every record valid                       exit 0
           invalid     at least one record invalid              exit 1
           incomplete  no record invalid, but at least one      exit 3
                       unknown or outside_scope, or no record
         A journal that cannot be read (a directory, a missing or
         unreadable file) gets no verdict and no report: exit 2.
         --allow-incomplete accepts incomplete (exit 0), for journals known
         to be incomplete such as rotated logs. --require-known-profiles
         also counts records with a profile this verifier does not know as
         incomplete; --allow-incomplete does not accept those.
hash     recomputes content_hash and chain_hash of one record and prints
         the canonical core, its findings and its state on its own.
profiles lists the profiles this verifier knows.
vectors  prints the reference test vectors (testdata/vectors.json).
`)
}

// splitArgs separates positional arguments from --flags, so flags may follow
// the file name as the README shows them.
func splitArgs(args []string) (positional []string, flags map[string]string, err error) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			flags[name[:eq]] = name[eq+1:]
			continue
		}
		switch name {
		case "pubkey":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("--pubkey needs a value")
			}
			flags[name] = args[i+1]
			i++
		case "json", "require-signatures", "allow-incomplete", "require-known-profiles":
			flags[name] = "true"
		default:
			return nil, nil, fmt.Errorf("unknown flag --%s", name)
		}
	}
	return positional, flags, nil
}

func openInput(name string) (io.ReadCloser, error) {
	if name == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(name)
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	pos, flags, err := splitArgs(args)
	if err != nil || len(pos) != 1 {
		if err != nil {
			fmt.Fprintln(stderr, err)
		}
		fmt.Fprintln(stderr, "usage: trail-evidence verify <file.jsonl|-> [--pubkey <hex|file>] [--require-signatures] [--allow-incomplete] [--require-known-profiles] [--json]")
		return 2
	}
	var opts evidence.Options
	if pk, ok := flags["pubkey"]; ok {
		pub, err := evidence.ParsePublicKey(pk)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		opts.PublicKey = pub
	}
	if flags["require-signatures"] == "true" {
		if opts.PublicKey == nil {
			fmt.Fprintln(stderr, "--require-signatures needs --pubkey")
			return 2
		}
		opts.RequireSignatures = true
	}
	opts.AllowIncomplete = flags["allow-incomplete"] == "true"
	opts.RequireKnownProfiles = flags["require-known-profiles"] == "true"
	in, err := openInput(pos[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer in.Close()
	rep := evidence.VerifyStream(in, opts)
	if err := rep.Err(); err != nil {
		// A journal that cannot be read gets no verdict and no report.
		fmt.Fprintf(stderr, "cannot read %s: %v\n", pos[0], err)
		return rep.ExitCode()
	}
	if flags["json"] == "true" {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	} else {
		fmt.Fprintln(stdout, rep.Summary())
		for _, f := range rep.Findings {
			seq := "-"
			if f.Seq != nil {
				seq = fmt.Sprint(*f.Seq)
			}
			fmt.Fprintf(stdout, "  %-7s %-17s record #%d (line %d, stream %q, seq %s): %s\n",
				f.Severity, f.Class, f.Index, f.Line, f.StreamID, seq, f.Message)
		}
	}
	return rep.ExitCode()
}

func cmdHash(args []string, stdout, stderr io.Writer) int {
	pos, _, err := splitArgs(args)
	if err != nil || len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: trail-evidence hash <record.json|->")
		return 2
	}
	in, err := openInput(pos[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer in.Close()
	raw, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	h, err := evidence.ComputeHashes(raw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	c := evidence.CheckRecord(raw)
	out := map[string]any{
		"payload_jcs":   string(h.PayloadJCS),
		"content_hash":  h.ContentHash,
		"core_jcs":      string(h.CoreJCS),
		"chain_hash":    h.ChainHash,
		"state":         c.State,
		"profile_state": c.ProfileState,
	}
	if c.Record != nil {
		out["recorded_content_hash"] = c.Record.ContentHash
		out["recorded_chain_hash"] = c.Record.ChainHash
		out["matches"] = c.Record.ContentHash == h.ContentHash && c.Record.ChainHash == h.ChainHash
	}
	if len(c.Findings) > 0 {
		out["findings"] = c.Findings
	}
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if m, ok := out["matches"].(bool); ok && !m {
		return 1
	}
	return 0
}
