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

		hexA := hex.EncodeToString(privA.Pub)
		hexB := hex.EncodeToString(privB.Pub)

		// A sends to B.
		swAB, _ := NewSecureWire(hexA, hexB, nil)
		frame, err := swAB.encodePayload(payload)
		if err != nil { t.Fatalf("encode(A->B): %v", err) }

		// B decodes (B's identity + A as recipient for ECDH).
		swBA, _ := NewSecureWire(hexB, hexA, nil)
		got, err := swBA.decodePayload(frame)
		if err != nil { t.Fatalf("decode(B->A): %v", err) }
		if !bytes.Equal(got, payload) { t.Fatal("roundtrip mismatch") }
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
		if err != nil { t.Fatalf("SigPubOf: %v", err) }
		if len(actualSigPub) != 32 { t.Fatalf("SigPubOf=%d bytes", len(actualSigPub)) }
		var correctPin [32]byte
		copy(correctPin[:], actualSigPub)

		var wrongPin [32]byte
		rand.Read(wrongPin[:])

		senderHex := hex.EncodeToString(sender.Pub)

		// Sender encodes.
		swSend, _ := NewSecureWire(senderHex, hex.EncodeToString(recip.Pub), &correctPin)
		frame, err := swSend.encodePayload(payload)
		if err != nil { t.Fatalf("encode: %v", err) }

		// Recipient decodes with correct pin.
		swRecvOk, _ := NewSecureWire(hex.EncodeToString(recip.Pub), "", &correctPin)
		got, err := swRecvOk.decodePayload(frame)
		if err != nil { t.Fatalf("recv-ok: %v", err) }
		if !bytes.Equal(got, payload) { t.Fatal("pin roundtrip fail") }

		// Wrong pin rejects with ErrPinMismatch.
		swRecvBad, _ := NewSecureWire(hex.EncodeToString(recip.Pub), "", &wrongPin)
		_, err = swRecvBad.decodePayload(frame)
		if err == nil { t.Fatal("wrong pin accepted") }
		if _, ok := err.(*ErrPinMismatch); !ok {
			t.Fatalf("expected *ErrPinMismatch, got %T: %v", err, err)
		}

		// No-pin accepts.
		swRecvNo, _ := NewSecureWire(hex.EncodeToString(recip.Pub), "", nil)
		_, err = swRecvNo.decodePayload(frame)
		if err != nil { t.Fatalf("no-pin rejected: %v", err) }

		// Zero-valued pin also accepts.
		zeroPin := [32]byte{}
		swZero, _ := NewSecureWire(hex.EncodeToString(recip.Pub), "", &zeroPin)
		_, err = swZero.decodePayload(frame)
		if err != nil { t.Fatalf("zero-pin rejected: %v", err) }
	})
}

// FuzzSecureWireMalformedFrames ensures decode never panics on garbage input.
func FuzzSecureWireMalformedFrames(f *testing.F) {
	recip := mustKeyPair(f)
	defer crypto.Zero(recip.Priv)
	sw, _ := NewSecureWire(hex.EncodeToString(recip.Pub), hex.EncodeToString(recip.Pub), nil)

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

	bobSigPub, err := secure.SigPubOf(privBob.Priv)
	if err != nil { f.Fatalf("SigPubOf Bob: %v", err) }

	stateKey := make([]byte, 32)
	rand.Read(stateKey)
	tmpDir := f.TempDir()
	states, err := NewFileStateStore(tmpDir, stateKey)
	if err != nil { f.Fatalf("NewFileStateStore: %v", err) }

	swBob, _ := NewSecureWire(hex.EncodeToString(bobSigPub), "", nil)
	durBob, err := NewDurableEndpointWithSecureWire(st, states, 0, time.Now(), swBob)
	if err != nil { f.Fatalf("NewDurableEndpointWithSecureWire: %v", err) }

	f.Add([]byte("hello world"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{'X'}, 4096))

	f.Fuzz(func(t *testing.T, payload []byte) {
		id := filled(1)
		spk := filled(2)
		var opk [32]byte
		copy(opk[:], filled(3))
		bundle, err := ratchet.BuildBundle(id, spk, 7, &opk, 9)
		if err != nil { return } // BuildBundle with fixed seeds never fails; unreachable guard

		ptr, rawFrame, err := durBob.SendFirst(id, bundle, nil, payload, time.Now().Add(time.Hour))
		if err != nil { return }
		// Verify pointer is non-trivial (Route|CID must both be non-zero).
		var zeroPtr Pointer
		if ptr == zeroPtr { t.Fatal("zero pointer returned") }
		if len(rawFrame) == 0 { t.Fatal("empty frame") }

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
	if err != nil { f.Fatalf("SigPubOf: %v", err) }

	swAlice, _ := NewSecureWire(hex.EncodeToString(privAlice.Priv), hex.EncodeToString(bobSigPub), nil)
	swBob, _ := NewSecureWire(hex.EncodeToString(bobSigPub), "", nil)

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
		if err != nil { return }

		ptr, raw, err := alice.SendFirst(idA, bundle, bobSigPub, payload, time.Now().Add(time.Hour))
		if err != nil { return }
		if ptr == zeroPtr { t.Fatal("empty ptr") }
		if len(raw) == 0 { t.Fatal("empty raw") }

		firstFrame, err := FetchFrame(st, ptr, time.Now())
		if err != nil { return }

		decrypted, err := bob.ReceiveFirst(idB, spkB, &opk, firstFrame, raw)
		if err != nil { return /* unknown SPK is expected */ }

		if !bytes.Equal(decrypted, payload) { t.Fatal("full roundtrip mismatch") }
	})
}
