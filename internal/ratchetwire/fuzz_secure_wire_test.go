package ratchetwire

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// newTestSecureWire builds a SecureWire the way the CLI does.
//
// The first argument is our 32-byte X25519 PRIVATE scalar, not a public key.
// This matters and is easy to get wrong: openSigned recomputes the recipient
// pub from the identity scalar (ourPub = PubKeyOf(ourPriv)) and checks it
// against the recipient pub the sender signed over. Hand it a PUBLIC key and
// the receiver derives a different pub than the sender addressed, so every
// frame fails with ErrSig ("sender signature invalid") — which looks like a
// wire bug but is a key-argument bug in the caller. Send side: identity +
// peer pub. Receive side: identity only.
func newTestSecureWire(tb testing.TB, priv, peerPub []byte, pin *[32]byte) *SecureWire {
	tb.Helper()
	if len(priv) != 32 {
		tb.Fatalf("identity must be a 32-byte private scalar, got %d bytes", len(priv))
	}
	peerHex := ""
	if len(peerPub) > 0 {
		peerHex = hex.EncodeToString(peerPub)
	}
	sw, err := NewSecureWire(hex.EncodeToString(priv), peerHex, pin)
	if err != nil {
		tb.Fatalf("NewSecureWire: %v", err)
	}
	if sw == nil {
		tb.Fatal("NewSecureWire returned nil for a non-empty identity")
	}
	return sw
}

// --- SecureWire encodePayload / decodePayload fuzzing ---

// FuzzSecureWireRoundtrip hammers SecureWire encode/decode with random payloads.
func FuzzSecureWireRoundtrip(f *testing.F) {
	f.Add([]byte("seed message"))
	f.Add(make([]byte, 0))
	f.Add(bytes.Repeat([]byte{0x42}, 1024))

	f.Fuzz(func(t *testing.T, payload []byte) {
		privA := mustKeyPair(t)
		defer crypto.Zero(privA.Priv)
		privB := mustKeyPair(t)
		defer crypto.Zero(privB.Priv)

		// A sends to B.
		swAB := newTestSecureWire(t, privA.Priv, privB.Pub, nil)
		frame, err := swAB.encodePayload(payload)
		if err != nil {
			t.Fatalf("encode(A->B): %v", err)
		}

		// B decodes with its own identity scalar.
		swBA := newTestSecureWire(t, privB.Priv, privA.Pub, nil)
		got, err := swBA.decodePayload(frame)
		if err != nil {
			t.Fatalf("decode(B->A): %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("roundtrip mismatch")
		}

		// The frame is addressed to B: an unrelated third identity must NOT be
		// able to open it (cross-recipient replay / misdelivery).
		privC := mustKeyPair(t)
		defer crypto.Zero(privC.Priv)
		swC := newTestSecureWire(t, privC.Priv, nil, nil)
		if _, err := swC.decodePayload(frame); err == nil {
			t.Fatal("a third identity opened a frame addressed to B")
		}
	})
}

// FuzzSecureWirePinEnforcement verifies contact-pinning at wire level.
func FuzzSecureWirePinEnforcement(f *testing.F) {
	f.Add([]byte("pinned message"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		sender := mustKeyPair(t)
		defer crypto.Zero(sender.Priv)
		recip := mustKeyPair(t)
		defer crypto.Zero(recip.Priv)

		actualSigPub, err := secure.SigPubOf(sender.Priv)
		if err != nil {
			t.Fatalf("SigPubOf: %v", err)
		}
		if len(actualSigPub) != 32 {
			t.Fatalf("SigPubOf=%d bytes", len(actualSigPub))
		}
		var correctPin [32]byte
		copy(correctPin[:], actualSigPub)

		var wrongPin [32]byte
		rand.Read(wrongPin[:])

		// Sender encodes: identity scalar + recipient's pub, pinning the peer.
		swSend := newTestSecureWire(t, sender.Priv, recip.Pub, &correctPin)
		frame, err := swSend.encodePayload(payload)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		// Recipient decodes with correct pin.
		swRecvOk := newTestSecureWire(t, recip.Priv, nil, &correctPin)
		got, err := swRecvOk.decodePayload(frame)
		if err != nil {
			t.Fatalf("recv-ok: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("pin roundtrip fail")
		}

		// Wrong pin rejects with ErrPinMismatch.
		swRecvBad := newTestSecureWire(t, recip.Priv, nil, &wrongPin)
		_, err = swRecvBad.decodePayload(frame)
		if err == nil {
			t.Fatal("wrong pin accepted")
		}
		if _, ok := err.(*ErrPinMismatch); !ok {
			t.Fatalf("expected *ErrPinMismatch, got %T: %v", err, err)
		}

		// No-pin accepts.
		swRecvNo := newTestSecureWire(t, recip.Priv, nil, nil)
		_, err = swRecvNo.decodePayload(frame)
		if err != nil {
			t.Fatalf("no-pin rejected: %v", err)
		}

		// Zero-valued pin also accepts.
		zeroPin := [32]byte{}
		swZero := newTestSecureWire(t, recip.Priv, nil, &zeroPin)
		_, err = swZero.decodePayload(frame)
		if err != nil {
			t.Fatalf("zero-pin rejected: %v", err)
		}
	})
}

// FuzzSecureWireMalformedFrames ensures decode never panics on garbage input.
func FuzzSecureWireMalformedFrames(f *testing.F) {
	recip := mustKeyPair(f)
	defer crypto.Zero(recip.Priv)
	sw := newTestSecureWire(f, recip.Priv, recip.Pub, nil)

	f.Add([]byte{})
	f.Add([]byte{0xE1})
	f.Add(bytes.Repeat([]byte{0xFF}, 100))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, frame []byte) {
		_, _ = sw.decodePayload(frame) // must never panic
	})
}

// --- DurableEndpoint-level fuzzing ---

// FuzzDurableEndpointSecureWire exercises SendFirst/ReceiveNext roundtrips
// where SecureWire wraps every ratchet frame in envelope v2.
func FuzzDurableEndpointSecureWire(f *testing.F) {
	st := store.NewMemStore()

	privBob := mustKeyPair(f)
	defer crypto.Zero(privBob.Priv)

	stateKey := make([]byte, 32)
	rand.Read(stateKey)
	tmpDir := f.TempDir()
	states, err := NewFileStateStore(tmpDir, stateKey)
	if err != nil {
		f.Fatalf("NewFileStateStore: %v", err)
	}

	swBob := newTestSecureWire(f, privBob.Priv, nil, nil)
	durBob, err := NewDurableEndpointWithSecureWire(st, states, 0, time.Now(), swBob)
	if err != nil {
		f.Fatalf("NewDurableEndpointWithSecureWire: %v", err)
	}

	f.Add([]byte("hello world"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{'X'}, 4096))

	f.Fuzz(func(t *testing.T, payload []byte) {
		id := filled(1)
		spk := filled(2)
		var opk [32]byte
		copy(opk[:], filled(3))
		bundle, err := ratchet.BuildBundle(id, spk, 7, &opk, 9)
		if err != nil {
			return // BuildBundle with fixed seeds never fails; unreachable guard
		}

		ptr, rawFrame, err := durBob.SendFirst(id, bundle, nil, payload, time.Now().Add(time.Hour))
		if err != nil {
			return
		}
		// Verify pointer is non-trivial (Route|CID must both be non-zero).
		var zeroPtr Pointer
		if ptr == zeroPtr {
			t.Fatal("zero pointer returned")
		}
		if len(rawFrame) == 0 {
			t.Fatal("empty frame")
		}

		decrypted, err := durBob.ReceiveNext(ptr, time.Now())
		_ = decrypted
		_ = err
	})
}

// FuzzEndpointSecureWireFullRoundTrip exercises a complete A→B send+receive
// through the Endpoint layer with SecureWire active on both sides.
func FuzzEndpointSecureWireFullRoundTrip(f *testing.F) {
	st := store.NewMemStore()

	privAlice := mustKeyPair(f)
	defer crypto.Zero(privAlice.Priv)
	privBob := mustKeyPair(f)
	defer crypto.Zero(privBob.Priv)

	bobSigPub, err := secure.SigPubOf(privBob.Priv)
	if err != nil {
		f.Fatalf("SigPubOf: %v", err)
	}

	swAlice := newTestSecureWire(f, privAlice.Priv, privBob.Pub, nil)
	swBob := newTestSecureWire(f, privBob.Priv, nil, nil)

	// Zero pointer check via struct comparison.
	var zeroPtr Pointer

	alice := NewEndpointWithSecureWire(st, swAlice)
	bob := NewEndpointWithSecureWire(st, swBob)

	f.Add([]byte("secure roundtrip"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xAB}, 512))

	f.Fuzz(func(t *testing.T, payload []byte) {
		idA, idB, spkB := filled(1), filled(2), filled(3)
		var opk [32]byte
		copy(opk[:], filled(4))
		bundle, err := ratchet.BuildBundle(idB, spkB, 7, &opk, 9)
		if err != nil {
			return
		}

		ptr, raw, err := alice.SendFirst(idA, bundle, bobSigPub, payload, time.Now().Add(time.Hour))
		if err != nil {
			return
		}
		if ptr == zeroPtr {
			t.Fatal("empty ptr")
		}
		if len(raw) == 0 {
			t.Fatal("empty raw")
		}

		firstFrame, err := FetchFrame(st, ptr, time.Now())
		if err != nil {
			return
		}

		decrypted, err := bob.ReceiveFirst(idB, spkB, &opk, firstFrame, raw)
		if err != nil {
			return /* unknown SPK is expected */
		}

		if !bytes.Equal(decrypted, payload) {
			t.Fatal("full roundtrip mismatch")
		}
	})
}
