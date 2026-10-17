package ratchetwire

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// Rejection counts are written with the pool file, so a separate process (such
// as `spore status`) can read them, and they survive a restart of the pool.
func TestPrekeyRejectionCountsPersistAcrossRestart(t *testing.T) {
	aliceID, bobID, spk := filled(1), filled(2), filled(3)
	var opk [32]byte
	copy(opk[:], filled(4))
	bundle, err := ratchet.BuildBundle(bobID, spk, 7, &opk, 9)
	if err != nil {
		t.Fatal(err)
	}
	bobSig, err := secure.SigPubOf(bobID)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemStore()
	alice := NewEndpoint(st)
	bob := NewEndpoint(st)
	path := filepath.Join(t.TempDir(), "opk-pool.json")
	pool, err := NewPersistentOPKPool(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(9, opk); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	ptr, _, err := alice.SendFirst(aliceID, bundle, bobSig, []byte("first"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := FetchFrame(st, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tampered := frame
	tampered.Message.Ciphertext = append([]byte(nil), frame.Message.Ciphertext...)
	tampered.Message.Ciphertext[len(tampered.Message.Ciphertext)-1] ^= 1
	if _, err := bob.ReceiveFirstFromOPKPool(bobID, spk, pool, tampered, mustFrameBytes(tampered)); err == nil {
		t.Fatal("tampered init accepted")
	}

	// Counts are throttled, so the rejection that follows a recent write is
	// held until Flush. The reader then sees it without loading the pool.
	if err := pool.Flush(); err != nil {
		t.Fatal(err)
	}
	got, err := ReadOnlyPrekeyRejections(path)
	if err != nil {
		t.Fatal(err)
	}
	if got[StageAuthenticate] != 1 || got[StageLookup] != 0 || got[StageValidate] != 0 || got[StageCommit] != 0 {
		t.Fatalf("read-only counts = %v, want authenticate=1 only", got)
	}

	// A restarted pool keeps the count and still holds the unspent prekey.
	restarted, err := NewPersistentOPKPool(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := restarted.RejectedCounts()[StageAuthenticate]; n != 1 {
		t.Fatalf("restarted authenticate count=%d, want 1", n)
	}
	if _, err := restarted.Peek(9); err != nil {
		t.Fatalf("rejection counting consumed OPK 9: %v", err)
	}

	// A missing pool file is reported as absent, not as zero rejections.
	if _, err := ReadOnlyPrekeyRejections(filepath.Join(t.TempDir(), "absent.json")); !os.IsNotExist(err) {
		t.Fatalf("missing pool: err=%v, want not-exist", err)
	}
}
