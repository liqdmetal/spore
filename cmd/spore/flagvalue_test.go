package main

import (
	"flag"
	"testing"
)

// TestFlagValueOrMissingFlag: the legacy `msg send` path reuses sendE2Core
// with a flag set that predates e2Common's newer flags. fs.Lookup of a
// missing flag returns nil — Value.String() on that nil dereferenced and
// segfaulted the whole CLI (found by the live soak). The helper must return
// the default instead of panicking.
func TestFlagValueOrMissingFlag(t *testing.T) {
	fs := flag.NewFlagSet("legacy", flag.ContinueOnError)
	fs.String("store", "http://x", "")
	if got := flagValueOr(fs, "relay", ""); got != "" {
		t.Fatalf("missing flag returned %q, want empty default", got)
	}
	if got := flagValueOr(fs, "store", ""); got != "http://x" {
		t.Fatalf("present flag returned %q, want its value", got)
	}
}
