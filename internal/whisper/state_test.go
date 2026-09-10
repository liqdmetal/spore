package whisper

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecvStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st := &RecvState{Cursor: 42, Seen: []string{
		strings.Repeat("aa", 32), // 64-hex sha256 digests, as persisted
		strings.Repeat("bb", 32),
	}}
	if err := SaveRecvState(path, st); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRecvState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cursor != 42 || len(got.Seen) != 2 || got.Seen[0] != strings.Repeat("aa", 32) || got.Seen[1] != strings.Repeat("bb", 32) {
		t.Fatalf("round trip = %#v", got)
	}
	// seenSet must round-trip too: the dedup map on restart is built from Seen.
	set := got.seenSet()
	if !set[string(bytes.Repeat([]byte{0xaa}, 32))] || !set[string(bytes.Repeat([]byte{0xbb}, 32))] || len(set) != 2 {
		t.Fatalf("seenSet = %v", set)
	}
}

func TestLoadRecvStateMissingIsNotAnError(t *testing.T) {
	st, err := LoadRecvState(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing state file must be a fresh start, got %v", err)
	}
	if st.Cursor != 0 || len(st.Seen) != 0 {
		t.Fatalf("fresh state = %#v", st)
	}
	if stNil, err := LoadRecvState(""); err != nil || stNil != nil {
		t.Fatalf("empty path = %#v, %v (want nil, nil)", stNil, err)
	}
}

func TestLoadRecvStateCorruptFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecvState(path); err == nil {
		t.Fatal("corrupt state file must fail loudly, not silently replay history")
	}

	// A seen entry that is not a 64-char hex digest (e.g. what a pre-hex
	// state file would contain after encoding/json mangled raw digest bytes)
	// must also fail closed.
	for name, body := range map[string]string{
		"short":  `{"cursor":1,"seen":["aa"]}`,
		"nonhex": `{"cursor":1,"seen":["zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"]}`,
	} {
		p := filepath.Join(t.TempDir(), "state-"+name+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRecvState(p); err == nil {
			t.Fatalf("%s: accepted a state file with a bad seen entry", name)
		}
	}
}
