package main

import (
	"os"
	"path/filepath"
	"testing"
)

// `spore msg prekeygen` must write key files that the E2 commands can load.
// A literal backslash-n in the output made readHexFile reject every key.
func TestPrekeygenKeyFilesParseBack(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SPORE_CONFIG", filepath.Join(dir, "absent-config.json"))
	id := filepath.Join(dir, "identity.key")
	spk := filepath.Join(dir, "spk.key")
	opk := filepath.Join(dir, "opk.key")
	bundle := filepath.Join(dir, "bundle.json")

	msgPrekeygen([]string{
		"-identity-out", id, "-spk-out", spk, "-opk-out", opk, "-bundle-out", bundle,
	})

	for _, path := range []string{id, spk, opk} {
		if _, err := readHexFile(path, 32); err != nil {
			t.Fatalf("prekeygen output %s does not parse: %v", filepath.Base(path), err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 65 || raw[64] != '\n' {
			t.Fatalf("%s is %d bytes, want 64 hex chars plus a newline", filepath.Base(path), len(raw))
		}
	}
}
