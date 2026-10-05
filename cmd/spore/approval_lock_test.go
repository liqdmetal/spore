package main

// Tests for the per-request signing lock: concurrent approver stations on the
// same queue must never double-sign a nonce, stale locks must be broken by
// atomic rename, and release must never delete a lock it does not own.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/derosim"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
)

func lockTestRequest(t *testing.T, dir, name string, createdAt time.Time) (requestPath, identityPath string) {
	t.Helper()
	requesterPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPublic, _ := approvalFixtureKeys(t)
	var sessionID [8]byte
	copy(sessionID[:], []byte(name))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(createdAt.Add(10 * time.Minute).Unix())}.MarshalBinary()
	envelope, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, 1_000, pointer, sessionID, requesterPrivate, approverPublic, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	requestPath = filepath.Join(dir, name+".json")
	writeApprovalTestFile(t, requestPath, envelope)
	identityPath = filepath.Join(t.TempDir(), "approver.key")
	if err := os.WriteFile(identityPath, []byte(strings.Repeat("52", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	return requestPath, identityPath
}

// TestApprovalBatchConcurrentStationsNeverDoubleSign races many stations over
// one queue: exactly one station may sign; the rest must skip (lock held or
// already signed) and never fail on the output.
func TestApprovalBatchConcurrentStationsNeverDoubleSign(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "outbox")
	requestPath, identityPath := lockTestRequest(t, dir, "race", time.Now())

	const stations = 8
	results := make([][]approvalBatchResult, stations)
	var wg sync.WaitGroup
	var mu sync.Mutex
	start := make(chan struct{})
	for i := 0; i < stations; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all stations at once for maximum contention
			r := runApprovalBatch([]string{requestPath}, identityPath, outDir, "", true)
			mu.Lock()
			results[i] = r
			mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()

	signed, lockSkipped, alreadySigned, failed := 0, 0, 0, 0
	for _, rs := range results {
		for _, r := range rs {
			switch {
			case r.Status == approvalBatchSigned:
				signed++
			case r.Status == approvalBatchSkipped && strings.Contains(r.Reason, "signing lock held"):
				lockSkipped++
			case r.Status == approvalBatchSkipped && r.Reason == "already signed":
				alreadySigned++
			default:
				failed++
				t.Errorf("unexpected result %+v", r)
			}
		}
	}
	if signed != 1 {
		t.Fatalf("exactly one station must sign, got signed=%d lockSkipped=%d alreadySigned=%d failed=%d", signed, lockSkipped, alreadySigned, failed)
	}
	if lockSkipped+alreadySigned != stations-1 {
		t.Fatalf("every loser must skip via lock or already-signed, got lockSkipped=%d alreadySigned=%d failed=%d", lockSkipped, alreadySigned, failed)
	}
	// Exactly one output on disk, and it verifies against the approver key.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".signed.json") {
		t.Fatalf("outbox must hold exactly one signed approval, got %v", entries)
	}
	approverPublic, _ := approvalFixtureKeys(t)
	approved, err := decodeCapabilityFile(filepath.Join(outDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCapabilityApproval(approved, hex.EncodeToString(approverPublic), time.Now()); err != nil {
		t.Fatalf("winner's approval does not verify: %v", err)
	}
	// No lock files may survive the run.
	locks, err := filepath.Glob(filepath.Join(dir, "*.lock*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) != 0 {
		t.Fatalf("lock files leaked: %v", locks)
	}
	// A follow-up batch run (no watch-mode pre-filter) is idempotent over its
	// own output: it skips as already signed via the same under-lock check the
	// race losers hit, and the outbox still holds exactly one approval.
	follow := runApprovalBatch([]string{requestPath}, identityPath, outDir, "", true)
	if len(follow) != 1 || follow[0].Status != approvalBatchSkipped || follow[0].Reason != "already signed" {
		t.Fatalf("follow-up run must skip as already signed, got: %+v", follow)
	}
	entries, err = os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".signed.json") {
		t.Fatalf("outbox must still hold exactly one signed approval, got %v", entries)
	}
}

func TestApprovalLockStaleBreakBusyAndOwnership(t *testing.T) {
	dir := t.TempDir()
	requestPath, _ := lockTestRequest(t, dir, "lock", time.Now())
	lockPath := requestPath + ".lock"
	now := time.Now()

	// Busy: a fresh lock naming a live holder blocks acquisition with the
	// holder PID in the reason. Own hostname + own PID = provably live.
	if err := os.WriteFile(lockPath, []byte(lockOwnerForTest()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, busy, err := lockApprovalRequest(requestPath, now)
	if err != nil || release != nil || busy == "" || !strings.Contains(busy, "pid "+pidForTest()) {
		t.Fatalf("fresh live lock must be busy, got release!=nil=%v busy=%q err=%v", release != nil, busy, err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("busy path must leave the lock in place: %v", err)
	}

	// Stale: the same lock with an old mtime is broken by atomic rename and
	// ownership is taken.
	if err := os.Chtimes(lockPath, now.Add(-2*approvalLockTTL), now.Add(-2*approvalLockTTL)); err != nil {
		t.Fatal(err)
	}
	release, busy, err = lockApprovalRequest(requestPath, now)
	if err != nil || busy != "" || release == nil {
		t.Fatalf("stale lock must be broken and taken, got busy=%q err=%v", busy, err != nil)
	}
	if b, rerr := os.ReadFile(lockPath); rerr != nil || strings.TrimSpace(string(b)) != lockOwnerForTest() {
		t.Fatalf("lock must now name us, got %q err=%v", b, rerr)
	}
	// Contention marker: a stale break must never leave delete-recreate races
	// — verify no second .broken file lingers.
	broken, _ := filepath.Glob(lockPath + ".broken*")
	if len(broken) != 0 {
		t.Fatalf("broken lock markers must be cleaned up: %v", broken)
	}

	// Release ownership: our release removes our lock.
	release()
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("release must remove our lock, stat err=%v", err)
	}

	// Release must never delete a lock we do not own: take the lock, then
	// overwrite its content as if a stale-breaker replaced it (legacy pid-only
	// body — never ours), and release.
	release, _, err = lockApprovalRequest(requestPath, now)
	if err != nil || release == nil {
		t.Fatalf("reacquire after release failed: %v", err != nil)
	}
	if err := os.WriteFile(lockPath, []byte("9999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("release must not delete a foreign lock: %v", err)
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
}

// TestApprovalLockBreaksDeadLocalHolderOnly pins liveness breaking: a lock
// whose holder is provably dead on this host breaks ahead of the TTL, while
// another host's lock stays TTL-only even with a locally dead PID.
func TestApprovalLockBreaksDeadLocalHolderOnly(t *testing.T) {
	dir := t.TempDir()
	requestPath, _ := lockTestRequest(t, dir, "dead", time.Now())
	lockPath := requestPath + ".lock"
	now := time.Now()

	// Dead local holder (a PID no live process can carry): broken at once,
	// ownership taken by the breaker.
	if err := os.WriteFile(lockPath, []byte(approvalLockHostname+" 4194303\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, busy, err := lockApprovalRequest(requestPath, now)
	if err != nil || release == nil || busy != "" {
		t.Fatalf("dead local holder must be broken immediately, got busy=%q err=%v", busy, err)
	}
	if b, rerr := os.ReadFile(lockPath); rerr != nil || strings.TrimSpace(string(b)) != lockOwnerForTest() {
		t.Fatalf("breaker must own the lock after the break, got %q err=%v", b, rerr)
	}
	release()
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("release must remove our lock, stat err=%v", err)
	}

	// Another host's lock is never broken by liveness, even though its PID
	// is dead locally: TTL stays the only remote break trigger.
	if err := os.WriteFile(lockPath, []byte("other-host-9 4194303\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, busy, err = lockApprovalRequest(requestPath, now)
	if err != nil || release != nil || !strings.Contains(busy, "pid 4194303") {
		t.Fatalf("remote lock must stay busy until TTL, got busy=%q err=%v", busy, err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("busy path must leave a remote lock in place: %v", err)
	}
}

// TestApprovalBatchSkipsOnLiveForeignLock pins the batch-core behavior for a
// request whose lock is held by a live station: quiet skip, no signature.
func TestApprovalBatchSkipsOnLiveForeignLock(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "outbox")
	requestPath, identityPath := lockTestRequest(t, dir, "held", time.Now())
	if err := os.WriteFile(requestPath+".lock", []byte(lockOwnerForTest()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := runApprovalBatch([]string{requestPath}, identityPath, outDir, "", true)
	if len(results) != 1 || results[0].Status != approvalBatchSkipped || !strings.Contains(results[0].Reason, "signing lock held by another approver (pid "+pidForTest()+")") {
		t.Fatalf("live foreign lock must be a quiet skip, got: %+v", results)
	}
	if _, err := os.Stat(filepath.Join(outDir, "held.signed.json")); !os.IsNotExist(err) {
		t.Fatalf("no signature may be written under a foreign lock")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".signed.json") {
			t.Fatalf("unexpected signed output %s", e.Name())
		}
	}
	// And the one-shot CLI path refuses the same way (no lock file left).
	if err := approveCapabilityFile(requestPath, identityPath, filepath.Join(dir, "manual.signed.json"), true); err == nil || !strings.Contains(err.Error(), "pid "+pidForTest()) {
		t.Fatalf("one-shot approve must refuse a live foreign lock, got: %v", err)
	}
}

// TestApprovalBatchSkipsRequestVanishedMidScan pins the filesystem race: a
// request present at scan time but deleted before its read is a quiet skip
// the next scan re-checks — never a failure, never a signature.
func TestApprovalBatchSkipsRequestVanishedMidScan(t *testing.T) {
	requestPath, identityPath := lockTestRequest(t, t.TempDir(), "vanished", time.Now())
	outDir := filepath.Join(t.TempDir(), "outbox")
	if err := os.Remove(requestPath); err != nil {
		t.Fatal(err)
	}
	results := runApprovalBatch([]string{requestPath}, identityPath, outDir, "", true)
	if len(results) != 1 || results[0].Status != approvalBatchSkipped || !strings.Contains(results[0].Reason, "request vanished mid-scan") {
		t.Fatalf("vanished request must be a quiet skip, got: %+v", results)
	}
	// The outbox is created lazily on the first signature; a full-skip batch
	// never creates it, and a missing dir holds zero signatures.
	entries, err := os.ReadDir(outDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("no signature may be written for a vanished request, got %v", entries)
	}
}

// TestApprovalBatchRerunIsIdempotentOnOwnOutput pins the under-lock output
// check: a rerun that finds its own valid approval at the output path skips
// as already signed (the race-loser case on Linux CI), while a foreign or
// corrupt file at that path keeps the loud exclusive-create backstop.
func TestApprovalBatchRerunIsIdempotentOnOwnOutput(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "outbox")
	requestPath, identityPath := lockTestRequest(t, dir, "rerun", time.Now())
	first := runApprovalBatch([]string{requestPath}, identityPath, outDir, "", true)
	if len(first) != 1 || first[0].Status != approvalBatchSigned {
		t.Fatalf("first run must sign, got: %+v", first)
	}
	second := runApprovalBatch([]string{requestPath}, identityPath, outDir, "", true)
	if len(second) != 1 || second[0].Status != approvalBatchSkipped || second[0].Reason != "already signed" {
		t.Fatalf("rerun over own output must skip as already signed, got: %+v", second)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("rerun must not write a second output, got %v", entries)
	}

	// A foreign file squatting on the output path keeps the loud backstop:
	// it is not this request's approval, and the rerun must fail, not skip.
	collidePath, collideIdentity := lockTestRequest(t, dir, "collide", time.Now())
	collideOut := filepath.Join(dir, "outbox2")
	if err := os.MkdirAll(collideOut, 0o700); err != nil {
		t.Fatal(err)
	}
	squat := filepath.Join(collideOut, "collide.signed.json")
	if err := os.WriteFile(squat, []byte(`{"not":"an approval"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	third := runApprovalBatch([]string{collidePath}, collideIdentity, collideOut, "", true)
	if len(third) != 1 || third[0].Status != approvalBatchFailed || !strings.Contains(third[0].Reason, "file exists") {
		t.Fatalf("foreign squatter must keep the exclusive-create failure, got: %+v", third)
	}
}

func pidForTest() string {
	return strconv.Itoa(os.Getpid())
}

func lockOwnerForTest() string {
	return approvalLockHostname + " " + pidForTest()
}
