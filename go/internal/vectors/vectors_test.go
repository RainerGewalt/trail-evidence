package vectors

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestGeneratedFilesUpToDate guarantees that the committed vectors, fixtures
// and examples are exactly what this implementation produces.
func TestGeneratedFilesUpToDate(t *testing.T) {
	for rel, want := range Files(Build()) {
		got, err := os.ReadFile(filepath.Join("../../..", rel))
		if err != nil {
			t.Errorf("%s: %v (run: go run ./internal/gentestdata -root ..)", rel, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is out of date (run: go run ./internal/gentestdata -root ..)", rel)
		}
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	a := Files(Build())
	b := Files(Build())
	for k := range a {
		if !bytes.Equal(a[k], b[k]) {
			t.Errorf("%s differs between two builds", k)
		}
	}
}
