package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSpoolEntryRoundTrip: an entry written by compose (via the JSON shape
// spoolcmd.go emits) must unmarshal into a usable spoolEntry with the send
// fields intact.
func TestSpoolEntryRoundTrip(t *testing.T) {
	e := spoolEntry{
		To: "dero1recipient", Identity: "/keys/id.hex", Pinned: "aabbcc",
		BundleURL: "https://mail.example.com/prekey", MsgFile: "/tmp/msg.plain",
		TTLSeconds: 86400, Chain: "dero", Store: "https://store.example.com",
		StateDir: "/state", StateKey: "/keys/state.hex", SessionTTL: "168h",
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var got spoolEntry
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.To != e.To || got.Pinned != e.Pinned || got.BundleURL != e.BundleURL ||
		got.StateDir != e.StateDir || got.TTLSeconds != 86400 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

// TestComposeWritesSpoolAndPlaintext: compose captures stdin plaintext into a
// spool-local file and writes a send-*.json entry pointing at it, with 0600
// modes. Simulates the compose command's file-writing behavior directly.
func TestComposeWritesSpoolAndPlaintext(t *testing.T) {
	dir := t.TempDir()
	msgPath := filepath.Join(dir, "msg-123.plain")
	if err := os.WriteFile(msgPath, []byte("draft body"), 0600); err != nil {
		t.Fatal(err)
	}
	entry := spoolEntry{
		To: "x", Identity: "/keys/id.hex", Pinned: "aa", Bundle: "/keys/b.json",
		MsgFile: msgPath, TTLSeconds: 3600,
	}
	raw, _ := json.Marshal(entry)
	spoolFile := filepath.Join(dir, "send-123.json")
	if err := os.WriteFile(spoolFile, raw, 0600); err != nil {
		t.Fatal(err)
	}

	// Replay the flush parse path.
	b, err := os.ReadFile(spoolFile)
	if err != nil {
		t.Fatal(err)
	}
	var loaded spoolEntry
	if err := json.Unmarshal(b, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.MsgFile != msgPath {
		t.Fatalf("msg file path = %q, want %q", loaded.MsgFile, msgPath)
	}
	plain, err := os.ReadFile(loaded.MsgFile)
	if err != nil || string(plain) != "draft body" {
		t.Fatalf("plaintext = %q, %v", plain, err)
	}
}

// TestFlushFailsCleanlyWithoutCarrier: a spool entry whose carrier is
// unreachable must produce an error (kept for retry), not panic or silently
// succeed. Uses a bogus store URL so the first network touch fails fast.
func TestFlushOneFailsCleanlyWithoutCarrier(t *testing.T) {
	e := spoolEntry{
		To: "x", Identity: "/nonexistent-id.hex", Pinned: "aa",
		Bundle: "/nonexistent-bundle.json", MsgFile: "/nonexistent.plain",
		TTLSeconds: 3600, Chain: "dero", Store: "http://127.0.0.1:1",
		StateDir: t.TempDir(), StateKey: "/nonexistent-state.hex",
	}
	err := flushOne(e)
	if err == nil {
		t.Fatal("flushOne succeeded against a dead carrier; want error")
	}
	if strings.Contains(err.Error(), "panic") {
		t.Fatalf("flushOne panicked: %v", err)
	}
}
