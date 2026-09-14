package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"testing"
	"time"
)

// TestPaymentIntentDeterminismAndBinding: the same inputs must produce the
// same intent; changing any field must change it.
func TestPaymentIntentDeterminismAndBinding(t *testing.T) {
	raw := []byte("pointer-payload-with-body-cid")
	a := paymentIntent("dero", "dero1to", "25dero", raw, 1234567890)
	b := paymentIntent("dero", "dero1to", "25dero", raw, 1234567890)
	if a != b {
		t.Fatal("intent not deterministic")
	}
	changed := []struct {
		name string
		mut  func() [32]byte
	}{
		{"chain", func() [32]byte { return paymentIntent("evm", "dero1to", "25dero", raw, 1234567890) }},
		{"to", func() [32]byte { return paymentIntent("dero", "dero1to2", "25dero", raw, 1234567890) }},
		{"amount", func() [32]byte { return paymentIntent("dero", "dero1to", "26dero", raw, 1234567890) }},
		{"pointer", func() [32]byte { return paymentIntent("dero", "dero1to", "25dero", []byte("other"), 1234567890) }},
		{"expiry", func() [32]byte { return paymentIntent("dero", "dero1to", "25dero", raw, 1234567891) }},
	}
	for _, c := range changed {
		if c.mut() == a {
			t.Fatalf("intent did not bind %s", c.name)
		}
	}
}

// TestApprovalRoundTrip: a signature made with spore msg approve's primitives
// verifies against the approver pub, and a tampered intent is rejected.
func TestApprovalRoundTrip(t *testing.T) {
	_, approverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approverPub := approverPriv.Public().(ed25519.PublicKey)
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.String("require-approval", hex.EncodeToString(approverPub), "")
	fs.String("approval-sig", "", "")
	fs.String("approval-file", "", "")

	raw := []byte("pointer-raw")
	// gate without a signature must fail loudly and print the intent
	if err := requireApproval(fs, "dero", "dero1to", "25dero", raw); err == nil {
		t.Fatal("missing approval accepted")
	}
	// compute the same intent the gate will use (same inputs + the TTL clock)
	intent := paymentIntent("dero", "dero1to", "25dero", raw, time.Now().Add(ApprovalTTL).Unix())
	sig := ed25519.Sign(approverPriv, intent[:])
	if err := fs.Set("approval-sig", hex.EncodeToString(sig)); err != nil {
		t.Fatal(err)
	}
	if err := requireApproval(fs, "dero", "dero1to", "25dero", raw); err != nil {
		t.Fatalf("valid approval rejected: %v", err)
	}
	// tamper the intent (different amount) -> the gate must reject
	intent2 := paymentIntent("dero", "dero1to", "26dero", raw, time.Now().Add(ApprovalTTL).Unix())
	if err := fs.Set("approval-sig", hex.EncodeToString(ed25519.Sign(approverPriv, intent2[:]))); err != nil {
		t.Fatal(err)
	}
	if err := requireApproval(fs, "dero", "dero1to", "25dero", raw); err == nil {
		t.Fatal("approval for a different amount accepted")
	}
	// no gate configured -> always passes
	fs2 := flag.NewFlagSet("send2", flag.ContinueOnError)
	fs2.String("require-approval", "", "")
	if err := requireApproval(fs2, "dero", "dero1to", "25dero", raw); err != nil {
		t.Fatalf("unconfigured gate must pass: %v", err)
	}
}
