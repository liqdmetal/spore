package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/peerstore"
	"github.com/liqdmetal/spore/internal/store"
)

func TestFetchWritesCiphertextAndNeverOverwrites(t *testing.T) {
	bodyStore, err := store.NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("synthetic encrypted peer body")
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

	out := filepath.Join(t.TempDir(), "received.body")
	args := []string{"--addr", listener.Addr().String(), "--cid", hex.EncodeToString(cid[:]), "--out", out}
	if err := fetch(args); err != nil {
		t.Fatalf("fetch(): %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("fetch wrote %q, want exact ciphertext", got)
	}

	if err := fetch(args); err == nil {
		t.Fatal("fetch overwrote an existing file")
	}
	gotAfter, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotAfter) != string(body) {
		t.Fatal("existing output changed after rejected overwrite")
	}
}
