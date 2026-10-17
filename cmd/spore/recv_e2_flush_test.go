package main

// Flush on exit for `msg recv-e2`: rejection counts are throttled, so a count
// can still be pending when the receiver returns. msgRecvE2 defers the cleanup
// from openE2Receiver on every return, including the return after an interrupt
// (Ctrl-C / SIGTERM cancels its context). This test drives that cleanup.

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/peerstore"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
)

func TestRecvE2CleanupFlushesPendingRejectionCounts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SPORE_CONFIG", filepath.Join(dir, "absent-config.json"))

	recvID, recvSPK := make([]byte, 32), make([]byte, 32)
	for i := range recvID {
		recvID[i], recvSPK[i] = 0x41, 0x42
	}
	recvSig, err := secure.SigPubOf(recvID)
	if err != nil {
		t.Fatal(err)
	}
	holdDir := filepath.Join(dir, "hold")
	hold, err := peerstore.NewSporePeerStore(peerstore.SporePeerConfig{Dir: holdDir, Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	senderIK := make([]byte, 32)
	for i := range senderIK {
		senderIK[i] = 0x51
	}
	senderEP := ratchetwire.NewEndpoint(hold)

	// A handshake whose OPK id 77 is not in the receiver's pool. Every attempt
	// is a lookup rejection, and none of them consumes state.
	var strangerOPK [32]byte
	for i := range strangerOPK {
		strangerOPK[i] = 0x61
	}
	bundle, err := ratchet.BuildBundle(recvID, recvSPK, 1, &strangerOPK, 77)
	if err != nil {
		t.Fatal(err)
	}
	ptr, _, err := senderEP.SendFirst(senderIK, bundle, recvSig, []byte("bootstrap"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	initFrame, err := ratchetwire.FetchFrame(hold, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	initBody, err := ratchetwire.GetBody(hold, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}

	poolPath := filepath.Join(dir, "opk-pool.json")
	fs, _ := newRecvE2Flagset()
	if err := fs.Parse([]string{
		"-identity", fenceHexFile(t, dir, "identity.key", recvID),
		"-spk", fenceHexFile(t, dir, "spk.key", recvSPK),
		"-store", "sporepeer://127.0.0.1:1", "-store-dir", holdDir,
		"-state-dir", filepath.Join(dir, "state"),
		"-state-key", fenceHexFile(t, dir, "statekey.hex", make([]byte, 32)),
		"-opk-pool", poolPath,
		"-receipts", filepath.Join(dir, "receipts.json"),
	}); err != nil {
		t.Fatal(err)
	}
	ing, cleanup, err := openE2Receiver(fs, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if ing.pool == nil {
		t.Fatal("receiver opened without its OPK pool")
	}

	// Two rejections back to back. The first is written at once; the second
	// falls inside the throttle window and stays pending.
	for i := 0; i < 2; i++ {
		_, err := ing.ep.ReceiveFirstFromOPKPool(recvID, recvSPK, ing.pool, initFrame, initBody)
		var pre *ratchetwire.PrekeyRejectedError
		if !errors.As(err, &pre) || pre.Stage != ratchetwire.StageLookup {
			t.Fatalf("attempt %d: want lookup rejection, got %v", i+1, err)
		}
	}
	if got := onDiskLookup(t, poolPath); got != 1 {
		t.Fatalf("before cleanup on disk lookup=%d, want 1 (second count should still be pending)", got)
	}

	// Return path of recv-e2: the deferred cleanup runs.
	cleanup()

	if got := onDiskLookup(t, poolPath); got != 2 {
		t.Fatalf("after cleanup on disk lookup=%d, want 2: pending count was not flushed on exit", got)
	}
}

func onDiskLookup(t *testing.T, poolPath string) uint64 {
	t.Helper()
	counts, err := ratchetwire.ReadOnlyPrekeyRejections(poolPath)
	if err != nil {
		t.Fatal(err)
	}
	return counts[ratchetwire.StageLookup]
}
