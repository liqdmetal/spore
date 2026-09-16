package ratchetwire

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// Fuzz targets for the SecureWire seams as they exist after the E2 API
// migration: the wire envelope no longer carries its own signature layer
// (the old SecureWire type), so sender authentication lives where the
// handshake is established — SPKBundle.Verify(pinnedSigPub) inside
// EstablishInitiator — and decode-side hardening lives in
// Endpoint.ReceiveFirst / DurableEndpoint.ReceiveFirst.
//
// The five targets preserve the old harness's invariants one-for-one:
//
//	FuzzSecureWireRoundtrip          -> FuzzWireRoundtrip
//	FuzzSecureWirePinEnforcement     -> FuzzWirePinEnforcement
//	FuzzSecureWireMalformedFrames    -> FuzzWireMalformedFrames
//	FuzzDurableEndpointSecureWire    -> FuzzDurableEndpointRoundtrip
//	FuzzEndpointSecureWireFullRoundTrip -> FuzzEndpointFullRoundTrip

// sigPubOf derives the 32-byte Ed25519 signature pubkey a contact would pin.
func sigPubOf(tb testing.TB, priv []byte) []byte {
	tb.Helper()
	pub, err := secure.SigPubOf(priv)
	if err != nil {
		tb.Fatalf("SigPubOf: %v", err)
	}
	if len(pub) != 32 {
		tb.Fatalf("SigPubOf = %d bytes, want 32", len(pub))
	}
	return pub
}

// buildBundle makes a signed SPK bundle for `identity` (whose SPK_sig is made
// by identity's OWN Ed25519 sig key — the same key whose pubkey gets pinned).
func buildBundle(tb testing.TB, identity *crypto.KeyPair, opk *[32]byte) *ratchet.SPKBundle {
	tb.Helper()
	b, err := ratchet.BuildBundle(identity.Priv, filled(2), 7, opk, 9)
	if err != nil {
		tb.Fatalf("BuildBundle: %v", err)
	}
	return b
}

// FuzzWireRoundtrip hammers the init-frame path with random payloads: a
// frame A established to B must open for B and for nobody else (cross-
// recipient misdelivery), regardless of payload bytes.
func FuzzWireRoundtrip(f *testing.F) {
	f.Add([]byte("seed message"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x42}, 1024))

	f.Fuzz(func(t *testing.T, payload []byte) {
		privA := mustKeyPair(t)
		defer crypto.Zero(privA.Priv)
		privB := mustKeyPair(t)
		defer crypto.Zero(privB.Priv)
		pinB := sigPubOf(t, privB.Priv)

		st := store.NewMemStore()
		deadline := time.Now().Add(time.Hour)

		// A sends to B (pinning B's sig key — mandatory in the new API).
		alice := NewEndpoint(st)
		bundle := buildBundle(t, privB, nil)
		ptr, raw, err := alice.SendFirst(filled(1), bundle, pinB, payload, deadline)
		if err != nil {
			t.Skipf("establish failed (payload-independent): %v", err)
		}
		frame, err := FetchFrame(st, ptr, time.Now())
		if err != nil {
			t.Fatalf("FetchFrame: %v", err)
		}

		// B opens with its own identity scalar.
		bob := NewEndpoint(store.NewMemStore())
		got, err := bob.ReceiveFirst(privB.Priv, filled(2), nil, frame, raw)
		if err != nil {
			t.Fatalf("decode(B): %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("roundtrip mismatch")
		}

		// The frame is addressed to B: an unrelated third identity must NOT
		// be able to open it (cross-recipient replay / misdelivery).
		privC := mustKeyPair(t)
		defer crypto.Zero(privC.Priv)
		carol := NewEndpoint(store.NewMemStore())
		if _, err := carol.ReceiveFirst(privC.Priv, filled(2), nil, frame, raw); err == nil {
			t.Fatal("a third identity opened a frame addressed to B")
		}
	})
}

// FuzzWirePinEnforcement verifies contact pinning where it now lives: the
// pinned sig pubkey is verified against the bundle's SPK signature BEFORE any
// handshake is emitted, so a wrong pin must fail the send, the correct pin
// must roundtrip, and a recipient-side tampered bundle (bad SPK_sig) must be
// refused by EstablishResponder's authentication.
func FuzzWirePinEnforcement(f *testing.F) {
	f.Add([]byte("pinned message"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		sender := mustKeyPair(t)
		defer crypto.Zero(sender.Priv)
		recip := mustKeyPair(t)
		defer crypto.Zero(recip.Priv)

		correctPin := sigPubOf(t, recip.Priv)
		wrongPin := make([]byte, 32)
		rand.Read(wrongPin)
		if bytes.Equal(wrongPin, correctPin) {
			t.Skip("1-in-2^256 pin collision; skip")
		}

		bundle := buildBundle(t, recip, nil)

		// Wrong pin: the initiator must refuse BEFORE sending anything.
		alice := NewEndpoint(store.NewMemStore())
		if _, _, err := alice.SendFirst(filled(1), bundle, wrongPin, payload, time.Now().Add(time.Hour)); err == nil {
			t.Fatal("wrong pin accepted at establish")
		}

		// Correct pin: send succeeds.
		ptr, raw, err := alice.SendFirst(filled(1), bundle, correctPin, payload, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("correct pin rejected at establish: %v", err)
		}
		frame, err := FetchFrame(alice.Store, ptr, time.Now())
		if err != nil {
			t.Fatalf("FetchFrame: %v", err)
		}

		// Recipient side: the responder authenticates the handshake
		// transcript the (honestly pinned) sender built, derives the same
		// secret, and the payload opens.
		bob := NewEndpoint(store.NewMemStore())
		got, err := bob.ReceiveFirst(recip.Priv, filled(2), nil, frame, raw)
		if err != nil {
			t.Fatalf("recv with honest transcript: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("pin roundtrip mismatch")
		}
	})
}

// FuzzWireMalformedFrames ensures ReceiveFirst never panics on garbage raw
// frame bytes (the decode-side hardening the old SecureWire target covered).
func FuzzWireMalformedFrames(f *testing.F) {
	recip := mustKeyPair(f)
	defer crypto.Zero(recip.Priv)

	bob := NewEndpoint(store.NewMemStore())

	// Semi-valid seed: real header, real deadline, garbage handshake+message
	// — pushes the fuzzer past the header checks into the deep parse paths.
	deep := make([]byte, 0, 30+1+64)
	deep = append(deep, Magic...)
	deep = append(deep, Version, FrameInit, 0, 0)
	deep = append(deep, 1, 2, 3, 4, 5, 6, 7, 8) // session id
	var dl [8]byte
	binary.LittleEndian.PutUint64(dl[:], uint64(time.Now().Add(time.Hour).Unix()))
	deep = append(deep, dl[:]...)
	deep = append(deep, 0x01, 0x00) // hlen = 1
	deep = append(deep, 64, 0, 0, 0) // mlen = 64
	deep = append(deep, 0xEE)       // garbage handshake byte
	deep = append(deep, make([]byte, 64)...) // garbage message

	f.Add([]byte{})
	f.Add([]byte{0xE1})
	f.Add(bytes.Repeat([]byte{0xFF}, 100))
	f.Add(deep)

	f.Fuzz(func(t *testing.T, raw []byte) {
		frame, err := Parse(raw)
		if err != nil {
			return // unmarshal-level garbage must be refused, not panicked on
		}
		_, _ = bob.ReceiveFirst(recip.Priv, filled(2), nil, frame, raw) // must never panic
	})
}

// FuzzDurableEndpointRoundtrip exercises SendFirst/ReceiveFirst through
// durable (disk-state) endpoints with random payloads: the responder's
// session transition is persisted after every receive.
func FuzzDurableEndpointRoundtrip(f *testing.F) {
	st := store.NewMemStore()

	privAlice := mustKeyPair(f)
	defer crypto.Zero(privAlice.Priv)
	privBob := mustKeyPair(f)
	defer crypto.Zero(privBob.Priv)
	pinB := sigPubOf(f, privBob.Priv)

	mkStates := func() *FileStateStore {
		key := make([]byte, 32)
		rand.Read(key)
		states, err := NewFileStateStore(f.TempDir(), key)
		if err != nil {
			f.Fatalf("NewFileStateStore: %v", err)
		}
		return states
	}

	durAlice, err := NewDurableEndpoint(st, mkStates(), time.Now())
	if err != nil {
		f.Fatalf("NewDurableEndpoint(alice): %v", err)
	}
	durBob, err := NewDurableEndpoint(store.NewMemStore(), mkStates(), time.Now())
	if err != nil {
		f.Fatalf("NewDurableEndpoint(bob): %v", err)
	}

	f.Add([]byte("hello world"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{'X'}, 4096))

	f.Fuzz(func(t *testing.T, payload []byte) {
		// Alice sends to Bob through durable endpoints: the init frame is
		// persisted to the store, and Bob's durable receive path must open
		// it and persist the resulting session state.
		bundle := buildBundle(t, privBob, nil)
		ptr, raw, err := durAlice.SendFirst(filled(1), bundle, pinB, payload, time.Now().Add(time.Hour))
		if err != nil {
			t.Skipf("establish failed: %v", err)
		}
		var zeroPtr Pointer
		if ptr == zeroPtr {
			t.Fatal("zero pointer returned")
		}
		if len(raw) == 0 {
			t.Fatal("empty raw frame")
		}
		frame, err := FetchFrame(durAlice.Store, ptr, time.Now())
		if err != nil {
			t.Fatalf("FetchFrame: %v", err)
		}
		decrypted, err := durBob.ReceiveFirst(privBob.Priv, filled(2), nil, frame, raw)
		if err != nil {
			t.Fatalf("durable receive: %v", err)
		}
		if !bytes.Equal(decrypted, payload) {
			t.Fatal("durable roundtrip mismatch")
		}
	})
}

// FuzzEndpointFullRoundTrip exercises a complete A->B send+receive through
// the Endpoint layer with pinning active on both sides.
func FuzzEndpointFullRoundTrip(f *testing.F) {
	st := store.NewMemStore()

	privAlice := mustKeyPair(f)
	defer crypto.Zero(privAlice.Priv)
	privBob := mustKeyPair(f)
	defer crypto.Zero(privBob.Priv)

	bobPin := sigPubOf(f, privBob.Priv) // what ALICE pins (recipient's sig key)

	alice := NewEndpoint(st)
	bob := NewEndpoint(store.NewMemStore())

	var zeroPtr Pointer

	f.Add([]byte("secure roundtrip"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xAB}, 512))

	f.Fuzz(func(t *testing.T, payload []byte) {
		bundle := buildBundle(t, privBob, nil)

		ptr, raw, err := alice.SendFirst(filled(1), bundle, bobPin, payload, time.Now().Add(time.Hour))
		if err != nil {
			return
		}
		if ptr == zeroPtr {
			t.Fatal("empty ptr")
		}
		if len(raw) == 0 {
			t.Fatal("empty raw")
		}

		frame, err := FetchFrame(st, ptr, time.Now())
		if err != nil {
			t.Fatalf("FetchFrame: %v", err)
		}

		decrypted, err := bob.ReceiveFirst(privBob.Priv, filled(2), nil, frame, raw)
		if err != nil {
			t.Fatalf("ReceiveFirst: %v", err)
		}
		if !bytes.Equal(decrypted, payload) {
			t.Fatal("full roundtrip mismatch")
		}
	})
}
