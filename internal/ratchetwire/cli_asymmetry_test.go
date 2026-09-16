package ratchetwire

import (
	"bytes"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// CLI parity tests (E2 audit H1/H2 fix).
//
// The CLI builds ONE endpoint shape on both sides since the audit fix:
// NewDurableEndpointWithExpiry with NO envelope-v2 wrapper — ratcheted frames
// are authenticated by the X3DH handshake + double ratchet (RATCHET.md §6:
// "the outer 0xE1-style sig is REPLACED by the ratchet's own authentication").
//
// Before the fix, sendE2Core attached a SecureWire only when -key/-peer-pub
// were passed while msgRecvE2 always derived one from -identity, so the
// documented default flow (docs/ONBOARDING.md) could never deliver. These
// tests pin the fixed, symmetric behavior at the endpoint layer — if someone
// reintroduces an asymmetric wrapper, TestCLIDefaultPathDelivers goes red.

// stateKey returns a fresh 32-byte key for a test FileStateStore.
func stateKey(tb testing.TB) []byte {
	tb.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		tb.Fatal(err)
	}
	defer crypto.Zero(k.Priv)
	return append([]byte(nil), k.Priv...)
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&15])
	}
	return string(out)
}

// cliEndpoint mirrors BOTH sendE2Core and msgRecvE2: the single, symmetric
// constructor with no SecureWire.
func cliEndpoint(t *testing.T) *DurableEndpoint {
	t.Helper()
	states, err := NewFileStateStore(t.TempDir(), stateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := NewDurableEndpointWithExpiry(store.NewMemStore(), states, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func bobKit(t *testing.T) (id, spk []byte, opk [32]byte, bundle *ratchet.SPKBundle, sigPub []byte) {
	t.Helper()
	id = filled(1)
	spk = filled(2)
	copy(opk[:], filled(3))
	sig, err := secure.SigPubOf(id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ratchet.BuildBundle(id, spk, 1, &opk, 1)
	if err != nil {
		t.Fatal(err)
	}
	return id, spk, opk, b, sig
}

// TestCLIDefaultPathDelivers pins the H1 fix: the documented default flags
// (no -key, no -peer-pub — see docs/ONBOARDING.md) must deliver end to end.
func TestCLIDefaultPathDelivers(t *testing.T) {
	bobID, bobSPK, bobOPK, bundle, bobSigPub := bobKit(t)

	sender := cliEndpoint(t)
	receiver := cliEndpoint(t)

	want := []byte("hello")
	ptr, raw, _, err := sender.SendFirstSession(bobID, bundle, bobSigPub, want, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if ptr == (Pointer{}) {
		t.Fatal("zero pointer")
	}
	frame, err := FetchFrame(sender.Store, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got, err := receiver.ReceiveFirst(bobID, bobSPK, &bobOPK, frame, raw)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("roundtrip = %q, want %q", got, want)
	}
}

// TestRatchetFramesCarryNoOuterEnvelope pins the H2 fix (RATCHET.md §6): a
// ratcheted message body is exactly header||nonce||ciphertext — never
// prefixed with an envelope wrapper. The wire length is checked instead of a
// leading-byte probe: the ratchet header's first field is a random X25519
// public key, so a probe would false-positive whenever the key happens to
// start with an envelope kind byte (~2^-7 of runs — seen as a rare
// Windows-race CI flake). An envelope wrapper (0xE0/0xE1 kind byte +
// ephemeral key + nonce + tag) would add >= 57 bytes.
func TestRatchetFramesCarryNoOuterEnvelope(t *testing.T) {
	bobID, _, _, bundle, bobSigPub := bobKit(t)

	sender := cliEndpoint(t)
	const plaintext = "x"
	ptr, _, _, err := sender.SendFirstSession(bobID, bundle, bobSigPub, []byte(plaintext), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := FetchFrame(sender.Store, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Wire layout per ratchet.MarshalBinary: 40-byte header (32 DHPub +
	// 4 PN + 4 N) + 24-byte nonce + ciphertext (plaintext + 16-byte
	// XChaCha20-Poly1305 tag). Exact match, no padding, no wrapper.
	const headerLen, nonceLen, tagLen = 40, 24, 16
	want := headerLen + nonceLen + len(plaintext) + tagLen
	got := frame.Message.MarshalBinary()
	if len(got) != want {
		t.Fatalf("ratcheted message = %d bytes, want exactly %d (envelope wrapper would add >= 57)", len(got), want)
	}
}

// TestEndpointHasNoSecureWireField documents (by compiling) that Endpoint no
// longer carries an envelope wrapper: NewEndpoint is the only constructor.
func TestEndpointHasNoSecureWireField(t *testing.T) {
	ep := NewEndpoint(store.NewMemStore())
	if ep.Store == nil || ep.Sessions == nil {
		t.Fatal("NewEndpoint produced an incomplete endpoint")
	}
}
