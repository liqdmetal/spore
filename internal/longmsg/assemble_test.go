package longmsg

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/liqdmetal/compost/internal/rendezvous"
	"github.com/liqdmetal/compost/internal/store"
	"github.com/liqdmetal/compost/internal/whisper"
)

// TestAssembledNobodyButUs is the end-to-end assembled flow: Alice encrypts a
// long body to Bob (holding it on her store), builds a pointer-whisper, Bob
// parses the pointer from payload args, fetches the body over the peer
// transport, and decrypts with his persistent key. This proves whisper +
// longmsg + rendezvous connect into one working nobody-but-us path.
func TestAssembledNobodyButUs(t *testing.T) {
	// Bob's persistent key (created once, reused across restarts).
	bobStore := store.NewMemStore()
	bob, err := NewEndpoint(bobStore)
	if err != nil {
		t.Fatal(err)
	}
	bobPriv := bob.PrivKey() // persisted

	// Alice sends a long message to Bob's long-term pub.
	aliceStore := store.NewMemStore()
	alice, err := NewEndpoint(aliceStore)
	if err != nil {
		t.Fatal(err)
	}
	longText := bytes.Repeat([]byte("a secret long message that never rides a block "), 30)
	ptr, err := alice.SendBody(bob.PublicKey(), longText, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Alice builds the pointer-whisper payload and posts/serves the body.
	args := whisper.BuildPointerArgs(ptr.EphemeralPub, ptr.CID)
	eph, cid, isPtr := whisper.ParsePointer(args)
	if !isPtr || eph != ptr.EphemeralPub || cid != ptr.CID {
		t.Fatal("pointer whisper roundtrip failed")
	}

	// Alice's body is served on the peer transport (her node answering Bob).
	transport := rendezvous.NewMemTransport()
	body, _ := alice.Store().Get(ptr.CID)
	transport.Put(ptr.CID, body)

	// Bob (restored from persisted key) fetches + decrypts.
	bob2, err := NewEndpointFromPriv(store.NewMemStore(), bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := bob2.ReceiveBody(&Pointer{EphemeralPub: eph, CID: cid},
		func(c [32]byte) ([]byte, error) { return transport.Fetch(context.Background(), c) })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fetched, longText) {
		t.Fatal("decrypted body mismatch")
	}
}
