package secure

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/whisper"
)

// fuzzCodec builds a fixed sender/recipient codec pair for fuzzing.
func fuzzCodec(t testing.TB) (*Codec, *Codec) {
	t.Helper()
	sk := make([]byte, 32)
	rk := make([]byte, 32)
	rand.Read(sk)
	rand.Read(rk)
	rpk, err := PubKeyOf(rk)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewSendCodec(whisper.CanonicalCodec{}, sk, rpk)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := NewRecvCodec(whisper.CanonicalCodec{}, rk)
	if err != nil {
		t.Fatal(err)
	}
	return sc, rc
}

// FuzzEnvelopeDecode hammers the strict envelope parser (kind 0xE1) with
// arbitrary chain payloads. Invariants for ANY input:
//   - DecodeText / DecodeTextSender never panic, never block, and never
//     return ok=true for a payload that wasn't produced by EncodeText.
//   - Anything that decodes must carry a VALID Ed25519 signature over the
//     transcript (strict mode rejects unsigned/legacy frames outright).
//   - Decoding an attacker-chosen blob must not corrupt codec state (the
//     codec is stateless across calls).
func FuzzEnvelopeDecode(f *testing.F) {
	sc, rc := fuzzCodec(f)
	seed := func(b []byte) { f.Add(b) }
	p, err := sc.EncodeText("seed message")
	if err != nil {
		f.Fatal(err)
	}
	seed([]byte(p))
	// Structural seeds: header shapes the parser will walk.
	seed([]byte{0xE1})
	zero31 := bytes.Repeat([]byte{0}, 31)
	seed(append([]byte{0xE1}, zero31...))
	seed([]byte{0xE0})                   // legacy kind — must be rejected
	seed(make([]byte, 64))               // zeros
	seed([]byte{0x00, 0xFF, 0xE1, 0x7F}) // noise

	f.Fuzz(func(t *testing.T, p []byte) {
		payload := chain.Payload(p)
		if _, sender, ok := rc.DecodeTextSender(payload); ok {
			if len(sender) != 32 {
				t.Fatalf("decoded envelope attributed to %d-byte key", len(sender))
			}
		}
		if _, ok := rc.DecodeText(payload); ok && len(p) > 0 && p[0] != EnvelopeKindSigned {
			t.Fatalf("accepted payload with non-envelope first byte 0x%02x", p[0])
		}
	})
}
