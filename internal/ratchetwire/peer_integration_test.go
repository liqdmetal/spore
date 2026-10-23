package ratchetwire

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/peerstore"
	"github.com/liqdmetal/spore/internal/store"
)

func TestE2FirstAndNextRoundTripOverDirectPeer(t *testing.T) {
	senderStore, err := store.NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- peerstore.Serve(ctx, ln, senderStore) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("peer server shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			_ = ln.Close()
			t.Error("peer server did not stop")
		}
	})

	receiverStore := &peerstore.PeerStore{Addr: ln.Addr().String()}
	sender := NewEndpoint(senderStore)
	receiver := NewEndpoint(receiverStore)
	bundle, aliceID, bobID, opk := adversarialFixture(t)
	now := time.Now().Truncate(time.Second)
	deadline := now.Add(time.Hour)

	ptr, _, sessionID, err := sender.SendFirstSession(aliceID, bundle, mustSig(t, bobID), []byte("first peer E2 message"), deadline)
	if err != nil {
		t.Fatalf("SendFirstSession(): %v", err)
	}
	frame, err := FetchFrame(receiverStore, ptr, now)
	if err != nil {
		t.Fatalf("FetchFrame() over peer: %v", err)
	}
	body, err := receiverStore.Get(ptr.CID)
	if err != nil {
		t.Fatalf("peer body Get(): %v", err)
	}
	plain, err := receiver.ReceiveFirst(bobID, filled(3), opk, frame, body)
	if err != nil || string(plain) != "first peer E2 message" {
		t.Fatalf("ReceiveFirst() = %q, %v", plain, err)
	}

	next, _, err := sender.SendNext(sessionID, []byte("next peer E2 message"), deadline)
	if err != nil {
		t.Fatalf("SendNext(): %v", err)
	}
	plain, err = receiver.ReceiveNext(next, now)
	if err != nil || string(plain) != "next peer E2 message" {
		t.Fatalf("ReceiveNext() = %q, %v", plain, err)
	}
}
