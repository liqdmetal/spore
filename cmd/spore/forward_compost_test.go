package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestLegacySendRefusal pins the refusal contract: every blocked legacy send
// path must name the 0xE2 replacement and say why. The message is all a user
// of those paths ever sees, so it must stay accurate and actionable.
func TestLegacySendRefusal(t *testing.T) {
	for _, cmd := range []string{"whisper send", "whisper send-long", "msg send", "msg send-long"} {
		err := legacySendRefusal(cmd)
		if err == nil {
			t.Fatalf("%s: refusal is nil", cmd)
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, cmd+": REFUSED") {
			t.Errorf("%s: message does not say REFUSED: %q", cmd, msg)
		}
		if !strings.Contains(msg, "not forward-private") {
			t.Errorf("%s: message does not say why: %q", cmd, msg)
		}
		if !strings.Contains(msg, "send-e2") {
			t.Errorf("%s: message does not point at the replacement: %q", cmd, msg)
		}
		if !strings.Contains(msg, "X3DH") {
			t.Errorf("%s: message does not name the mechanism: %q", cmd, msg)
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
}
