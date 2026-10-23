package peer

import (
	"context"
	"crypto/sha256"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/peerstore"
	"github.com/liqdmetal/spore/internal/store"
)

func TestFetchUsesSporePeerCLIWithoutPrecreatingOutput(t *testing.T) {
	binary := os.Getenv("SPORE_PEER_BIN")
	if binary == "" {
		binary = "spore-peer"
	}
	if _, err := exec.LookPath(binary); err != nil {
		t.Skip("spore-peer binary not found; set SPORE_PEER_BIN to run CLI interop")
	}

	bodyStore, err := store.NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("synthetic E2 ciphertext for wrapper test")
	cid := sha256.Sum256(body)
	if err := bodyStore.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- peerstore.Serve(ctx, listener, bodyStore) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("peer server shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			_ = listener.Close()
			t.Error("peer server did not stop")
		}
	})

	got, err := Fetch(context.Background(), binary, listener.Addr().String(), cid)
	if err != nil {
		t.Fatalf("Fetch(): %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body mismatch: got %q, want byte-exact ciphertext", got)
	}
}
