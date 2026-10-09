package kimtest2

import (
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/dirhash"
)

func TestFSContainsPackFiles(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if name != "PulumiPolicy.yaml" && (!strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego")) {
			continue
		}
		if _, err := fs.Stat(FS, name); err != nil {
			t.Errorf("%s is not embedded", name)
		}
	}
}

func TestChecksumMatchesFS(t *testing.T) {
	files, err := fs.Glob(FS, "*")
	if err != nil {
		t.Fatal(err)
	}
	sum, err := dirhash.Hash1(files, func(name string) (io.ReadCloser, error) {
		return FS.Open(name)
	})
	if err != nil {
		t.Fatal(err)
	}
	if sum != Checksum {
		t.Errorf("CHECKSUM is %q, files in FS hash to %q", Checksum, sum)
	}
}
