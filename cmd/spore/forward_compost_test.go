package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestLegacySendRefusal keeps the refusal contract for non-DERO legacy
// carriers. DERO aliases are upgraded to E2 and must not use this path.
func TestLegacySendRefusal(t *testing.T) {
	for _, cmd := range []string{"msg send on evm", "msg send on xmr", "msg send on solana"} {
		err := legacySendRefusal(cmd)
		if err == nil {
			t.Fatalf("%s: refusal is nil", cmd)
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, cmd+": REFUSED") {
			t.Errorf("%s: message does not say REFUSED: %q", cmd, msg)
		}
		if !strings.Contains(msg, "not forward-private") || !strings.Contains(msg, "send-e2") {
			t.Errorf("%s: refusal lacks E2 explanation: %q", cmd, msg)
		}
	}
}

func TestDeroAliasesAreNotLegacyRefusals(t *testing.T) {
	for _, args := range [][]string{
		{"-to", "dest", "-identity", "identity.key"},
		{"-to", "dest", "-identity", "identity.key", "-file", "body.bin"},
	} {
		if deroCompatChain(args) != true {
			t.Fatalf("DERO alias not selected: %v", args)
		}
	}
}

// TestWebE2RequiresFullKit: the web E2 server must refuse to start with a
// partial identity kit. A missing state key would make every send/receive
// fail cryptographically at runtime; failing at startup is the honest place.
func TestWebE2RequiresFullKit(t *testing.T) {
	dir := t.TempDir()
	// A directory with one key but not the rest.
	writePrivate(filepath.Join(dir, "identity.key"), make([]byte, 32))
	if _, err := newWebE2(dir, "http://127.0.0.1:1", ""); err == nil {
		t.Fatal("newWebE2 accepted a partial kit")
	}
}

// TestWebE2LoadsRealKit: `spore init -dir` output must be loadable as a web
// E2 kit — the exact onboarding path a user follows.
func TestWebE2LoadsRealKit(t *testing.T) {
	dir := t.TempDir()
	initcmd([]string{"-dir", dir})
	e, err := newWebE2(dir, "http://127.0.0.1:1", "")
	if err != nil {
		t.Fatalf("newWebE2 on a real kit: %v", err)
	}
	if len(e.identity) != 32 || len(e.spk) != 32 || len(e.stateKey) != 32 {
		t.Fatalf("kit keys not loaded: id=%d spk=%d state=%d", len(e.identity), len(e.spk), len(e.stateKey))
	}
	if e.store == nil {
		t.Fatal("body store not built")
	}
	if e.ringSize != 16 {
		t.Fatalf("web E2 default ring = %d, want 16", e.ringSize)
	}
	e8, err := newWebE2(dir, "http://127.0.0.1:1", "", 8)
	if err != nil || e8.ringSize != 8 {
		t.Fatalf("web E2 ring 8: endpoint=%v err=%v", e8, err)
	}
	if _, err := newWebE2(dir, "http://127.0.0.1:1", "", 32); err == nil {
		t.Fatal("web E2 accepted unsupported ring 32")
	}
}
