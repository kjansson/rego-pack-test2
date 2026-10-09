package kimtest2

import (
	"io/fs"
	"os"
	"strings"
	"testing"
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
