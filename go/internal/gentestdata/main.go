// Command gentestdata writes the vectors, stream fixtures, test key files and
// example journals into the repository. Run from go/:
//
//	go run ./internal/gentestdata -root ..
//
// With -check it only compares and exits non-zero on any difference.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/RainerGewalt/trail-evidence/go/internal/vectors"
)

func main() {
	root := flag.String("root", "..", "repository root")
	check := flag.Bool("check", false, "compare only, do not write")
	flag.Parse()

	files := vectors.Files(vectors.Build())
	dirty := 0
	for rel, content := range files {
		path := filepath.Join(*root, rel)
		existing, err := os.ReadFile(path)
		same := err == nil && bytes.Equal(existing, content)
		if same {
			continue
		}
		dirty++
		if *check {
			fmt.Fprintf(os.Stderr, "out of date: %s\n", rel)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fail(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			fail(err)
		}
		fmt.Println("wrote", rel)
	}
	if *check && dirty > 0 {
		os.Exit(1)
	}
	if dirty == 0 {
		fmt.Println("all generated files are up to date")
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(err.Error()))
	os.Exit(2)
}
