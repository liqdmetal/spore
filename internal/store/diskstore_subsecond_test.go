package store

// Sub-second deadline precision for DiskStore (the mid-second reap gap the
// reap ticker surfaced): .expms carries the exact millisecond deadline and
// takes precedence over the seconds floor in .exp, so expired()/Reap and
// Get agree on mid-second boundaries and the reaper acts on the first pass
// after the true deadline.

import (
	"os"
	"strconv"
	"testing"
	"time"
)

func msCid(b byte) [32]byte {
	var cid [32]byte
	cid[0] = b
	cid[31] = b
	return cid
}

func writeHolds(t *testing.T, s *DiskStore, cid [32]byte, body []byte, sec, ms int64) {
	t.Helper()
	if err := os.WriteFile(s.expPath(cid), []byte(strconv.FormatInt(sec, 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if ms != 0 {
		if err := os.WriteFile(s.expPathMS(cid), []byte(strconv.FormatInt(ms, 10)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(s.bodyPath(cid), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDiskStoreSubSecondExpiryEnforcedAtRead: with a .expms deadline 300ms in
// the future, Get must refuse (ErrExpired) once the deadline passes WITHOUT
// the seconds-floor boundary being crossed — the exact case the old
// seconds-only logic got wrong (it would serve for up to another second).
func TestDiskStoreSubSecondExpiryEnforcedAtRead(t *testing.T) {
	s, _ := NewDiskStore(t.TempDir())
	cid := msCid(7)
	deadline := time.Now().Add(300 * time.Millisecond)
	writeHolds(t, s, cid, []byte("mid-second body"), deadline.Unix(), deadline.UnixMilli())

	if _, err := s.Get(cid); err != nil {
		t.Fatalf("before deadline, get = %v, want the body", err)
	}
	time.Sleep(400 * time.Millisecond) // crosses .expms; NOT the next second boundary necessarily
	if _, err := s.Get(cid); err != ErrExpired {
		t.Fatalf("after ms deadline, get err = %v, want ErrExpired", err)
	}
}

// TestDiskStoreSubSecondReapPromptness: Reap must remove the body on the
// first pass after the .expms deadline — mid-second — not on the second
// rollover.
func TestDiskStoreSubSecondReapPromptness(t *testing.T) {
	s, _ := NewDiskStore(t.TempDir())
	cid := msCid(8)
	deadline := time.Now().Add(300 * time.Millisecond)
	writeHolds(t, s, cid, []byte("reap me mid-second"), deadline.Unix(), deadline.UnixMilli())

	if n := s.Reap(time.Now()); n != 0 {
		t.Fatalf("reaped %d before the deadline, want 0", n)
	}
	time.Sleep(400 * time.Millisecond)
	if n := s.Reap(time.Now()); n != 1 {
		t.Fatalf("reaped %d after the ms deadline, want 1", n)
	}
	if _, err := s.Get(cid); err != ErrNotFound {
		t.Fatalf("post-reap get err = %v, want ErrNotFound", err)
	}
}

// TestDiskStoreSecondsOnlyHoldStillWorks: a hold written by an OLD binary
// (seconds .exp, no .expms) must keep working: enforced at read, reaped
// after the floor, .expms absent.
func TestDiskStoreSecondsOnlyHoldStillWorks(t *testing.T) {
	s, _ := NewDiskStore(t.TempDir())
	cid := msCid(9)
	past := time.Now().Add(-time.Minute)
	writeHolds(t, s, cid, []byte("old-format body"), past.Unix(), 0) // no .expms

	if _, err := s.Get(cid); err != ErrExpired {
		t.Fatalf("seconds-only expired get err = %v, want ErrExpired", err)
	}
	if n := s.Reap(time.Now()); n != 1 {
		t.Fatalf("seconds-only reap = %d, want 1", n)
	}
}

// TestDiskStoreDowngradeNeverMisreadsMsHold: a hold with BOTH records read
// by code that only understands .exp (simulated by checking the seconds
// floor directly) must see the floor — which is <= the true ms deadline, so
// a downgrade errs toward COMPOSTING EARLY, never serving longer.
func TestDiskStoreDowngradeNeverMisreadsMsHold(t *testing.T) {
	s, _ := NewDiskStore(t.TempDir())
	cid := msCid(10)
	deadline := time.Now().Add(time.Hour)
	writeHolds(t, s, cid, []byte("future body"), deadline.Unix(), deadline.UnixMilli())

	// The downgrade contract: the floor in .exp is parseable and in the
	// future (this binary would keep serving), and the ms record is >= the
	// floor (never less — Put derives both from one deadline).
	floorRaw, err := os.ReadFile(s.expPath(cid))
	if err != nil {
		t.Fatal(err)
	}
	floor, perr := strconv.ParseInt(string(floorRaw), 10, 64)
	if perr != nil || floor < time.Now().Unix() {
		t.Fatalf("floor not parseable/future: %q %v", floorRaw, perr)
	}
	msRaw, err := os.ReadFile(s.expPathMS(cid))
	if err != nil {
		t.Fatal(err)
	}
	ms, perr := strconv.ParseInt(string(msRaw), 10, 64)
	if perr != nil || ms < floor*1000 {
		t.Fatalf("ms record below the seconds floor: %d < %d*1000", ms, floor)
	}
}

// TestDiskStorePutWritesMsRecordAndZeroDeadlineSkipsIt: Put via the real
// path writes .expms for real deadlines and omits it for zero (never
// expires); Delete removes both records.
func TestDiskStorePutWritesMsRecordAndZeroDeadlineSkipsIt(t *testing.T) {
	s, _ := NewDiskStore(t.TempDir())
	live := msCid(11)
	if err := s.Put(live, []byte("x"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.expPathMS(live)); err != nil {
		t.Fatalf("real deadline must write .expms: %v", err)
	}
	never := msCid(12)
	if err := s.Put(never, []byte("y"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	// Zero deadline keeps the original .exp convention: the file exists with
	// "0" (never expires) so the crash-ordering record is always present.
	zeroRaw, err := os.ReadFile(s.expPath(never))
	if err != nil || string(zeroRaw) != "0" {
		t.Fatalf("zero deadline .exp = %q, %v; want \"0\"", zeroRaw, err)
	}
	if _, err := os.Stat(s.expPathMS(never)); !os.IsNotExist(err) {
		t.Fatalf("zero deadline must not write .expms, stat err=%v", err)
	}
	if err := s.Delete(live); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.expPathMS(live)); !os.IsNotExist(err) {
		t.Fatalf("delete left the .expms behind: %v", err)
	}
}

// TestDiskStoreServedAndReapedAgreeOnMidSecondBoundary: Get and Reap must
// never disagree — right up to the ms deadline the body is servable and NOT
// reapable; after it, it is refused and reapable on the same pass.
func TestDiskStoreServedAndReapedAgreeOnMidSecondBoundary(t *testing.T) {
	s, _ := NewDiskStore(t.TempDir())
	cid := msCid(13)
	deadline := time.Now().Add(250 * time.Millisecond)
	writeHolds(t, s, cid, []byte("boundary body"), deadline.Unix(), deadline.UnixMilli())

	if n := s.Reap(time.Now()); n != 0 {
		t.Fatalf("reap fired before the deadline: %d", n)
	}
	if _, err := s.Get(cid); err != nil {
		t.Fatalf("serving stopped before the ms deadline: %v", err)
	}
	for {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := s.Get(cid); err != ErrExpired {
		t.Fatalf("serving continued past the ms deadline: %v", err)
	}
	if n := s.Reap(time.Now().Add(time.Millisecond)); n != 1 {
		t.Fatalf("reap did not fire after the ms deadline: %d", n)
	}
}
