package continuity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestObserverNoticeContainsNoVaultSecretAndVerifies(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	priv, pub, err := NewObserverKey()
	if err != nil {
		t.Fatal(err)
	}
	privBefore := append([]byte(nil), priv...)
	n, err := Observe(v, priv, now+15)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Verify(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyNoticeForVault(v, n); err != nil {
		t.Fatal(err)
	}
	if n.ObserverPub != fmtHex(pub) {
		t.Fatalf("observer pub = %s, want %s", n.ObserverPub, fmtHex(pub))
	}
	raw, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("sealed continuity instructions")) {
		t.Fatal("notice contains vault plaintext")
	}
	if !bytes.Equal(priv, privBefore) {
		t.Fatal("Observe mutated caller-owned observer key")
	}
}

func TestObserverCannotIssueEarlyNotice(t *testing.T) {
	v, _, _ := testVault(t, 1_800_000_000)
	priv, _, _ := NewObserverKey()
	if _, err := Observe(v, priv, 1_800_000_014); !errors.Is(err, ErrNotDue) {
		t.Fatalf("early notice error = %v, want ErrNotDue", err)
	}
}

func TestObserverNoticeTamperAndWrongVaultFailClosed(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	other, _, _ := testVault(t, now)
	priv, _, _ := NewObserverKey()
	n, err := Observe(v, priv, now+15)
	if err != nil {
		t.Fatal(err)
	}
	n.ObservedAt++
	if err := n.Verify(); err == nil {
		t.Fatal("tampered notice verified")
	}
	n, err = Observe(v, priv, now+15)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNoticeForVault(other, n); err == nil {
		t.Fatal("notice verified against wrong vault")
	}
}

func TestNoticeCannotUseMalformedObserverKey(t *testing.T) {
	v, _, _ := testVault(t, time.Now().Unix())
	for _, key := range [][]byte{nil, make([]byte, ed25519.PrivateKeySize-1), make([]byte, ed25519.PrivateKeySize+1)} {
		if _, err := Observe(v, key, v.CreatedAt+15); !errors.Is(err, ErrInvalidNotice) {
			t.Fatalf("malformed observer key returned %v", err)
		}
	}
}

func fmtHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2], out[i*2+1] = hex[v>>4], hex[v&15]
	}
	return string(out)
}
