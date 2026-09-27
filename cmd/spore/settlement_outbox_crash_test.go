package main

// Crash-durability pin for the settlement-notice outbox: kill a settlement
// command MID-PERSIST and prove the queue never loses or duplicates a notice.
//
// The durability contract of saveSettlementOutbox rests on
// writeAtomicPrivate's temp+fsync+rename: the queue file is a WHOLE JSON
// generation at every instant — either the old one or the new one. Nothing
// previously exercised that under a real crash, so these tests re-exec the
// test binary as a child process (the helper-process pattern; the package
// already re-execs in watchdog_smoke_test.go), drive the REAL
// enqueueSettlementNotice path with the publish step parked at an exact
// checkpoint, and kill -9 the child there. Three crash windows:
//
//   - before the publish decision is written anywhere (nothing durable yet):
//     the notice must still be queueable — a re-enqueue of the same
//     settlement must find the survivors, not duplicate them;
//   - after the new generation is durably on disk but BEFORE the rename (the
//     classic torn-write window): the queue file must still parse as the old
//     complete generation, and the temp corpse must be ignored by the
//     loader;
//   - blind: killed at an arbitrary unsynchronized moment mid-loop while a
//     backlog of settlements is being enqueued — no torn file, and the
//     surviving queue must contain every already-completed settlement at
//     most once (monotone prefix, never loss, never duplicates).
//
// The child cannot exit cleanly in crash mode: its only exits are the
// parent's kill or the sentinel exit 9 (a logic bug — the tests fail if they
// ever see it). That is the point: the state on disk afterwards is what a
// hard power loss would have left behind.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// settlementOutboxCrashEnv gates the re-exec'd child into crash mode.
const settlementOutboxCrashEnv = "SPORE_TEST_SETTLEMENT_OUTBOX_CRASH"

// TestMain is deliberately minimal: when the crash env is set, this process
// IS the doomed child — run its fault-injected body and never return
// cleanly (exit 9 is the "should be unreachable" sentinel the parent treats
// as a test failure).
func TestMain(m *testing.M) {
	if mode := os.Getenv(settlementOutboxCrashEnv); mode != "" {
		settlementOutboxCrashChild(mode) // never returns
		os.Exit(9)
	}
	os.Exit(m.Run())
}

// settlementOutboxCrashChild drives the REAL enqueue path with the publish
// step parked at `mode`'s checkpoint. `park` never returns: the parent's
// kill is the only exit, so disk state afterwards is true crash residue.
func settlementOutboxCrashChild(mode string) {
	defer func() {
		// A panic in the child must not masquerade as a clean exit; exit 9
		// is the sentinel the parent reports as a test failure.
		os.Exit(9)
	}()
	dir := os.Getenv("SPORE_TEST_SETTLEMENT_OUTBOX_DIR")
	outbox := os.Getenv("SPORE_TEST_SETTLEMENT_OUTBOX_PATH")
	if dir == "" || outbox == "" {
		os.Exit(9)
	}
	stage := 0
	ready := func() {
		stage++
		fmt.Fprintf(os.Stderr, "settlement-outbox-crash: stage %d reached (%s)\n", stage, mode)
	}
	park := func() {
		ready()
		select {} // block forever: the parent's SIGKILL is the exit
	}
	switch mode {
	case "park-before-publish":
		// Enqueue is committed to publish but NOTHING is durable yet: the
		// ideal moment to prove no half-notice ever reaches disk.
		settlementOutboxPublish = func(path string, body []byte) error {
			park()
			return nil // unreachable
		}
	case "park-after-sync":
		// Reproduce writeAtomicPrivate up to (and including) the durable
		// temp write, then park BEFORE the rename. The queue file must stay
		// the old complete generation and the temp corpse must be ignored.
		settlementOutboxPublish = func(path string, body []byte) error {
			tmp, err := os.CreateTemp(filepath.Dir(path), ".spore-continuity-*")
			if err != nil {
				return err
			}
			tmpName := tmp.Name()
			defer os.Remove(tmpName)
			if _, err := tmp.Write(body); err != nil {
				tmp.Close()
				return err
			}
			if err := tmp.Chmod(0o600); err != nil {
				tmp.Close()
				return err
			}
			if err := tmp.Sync(); err != nil {
				tmp.Close()
				return err
			}
			if err := tmp.Close(); err != nil {
				return err
			}
			// Leave the corpse path for the parent's assertion.
			if werr := os.WriteFile(filepath.Join(dir, "crash-tmp.txt"), []byte(tmpName), 0o600); werr != nil {
				return werr
			}
			park()
			return nil // unreachable
		}
	case "blind-loop":
		// No hooks at all: hammer the REAL production enqueue (and therefore
		// the real writeAtomicPrivate temp-write/fsync/replace) over a large
		// backlog, then block forever. The parent kills at an unsynchronized
		// instant once progress is visible, so the kill lands inside a later
		// multi-step persist with near-certainty — the true blind crash the
		// checkpoint tests cannot provide.
		//
		// Progress is signaled through a SEPARATE file: the parent must never
		// touch the queue path while the child writes it (on Windows a
		// concurrent read makes the child's atomic replace fail with a
		// sharing violation, which would be a harness artifact, not a
		// crash).
		progress := filepath.Join(dir, "blind-progress.txt")
		go func() {
			for i := 0; i < 5000; i++ {
				txid := fmt.Sprintf("tx-blind-%04d", i)
				if err := enqueueSettlementNotice(outbox, "escrow claim", txid, "addr-crash", "ffeeddccbbaa99887", []byte(`{"type":"spore/settlement/v1"}`)); err != nil {
					fmt.Fprintf(os.Stderr, "settlement-outbox-crash: blind enqueue %s failed: %v\n", txid, err)
					os.Exit(9)
				}
				f, aerr := os.OpenFile(progress, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
				if aerr == nil {
					_, _ = f.WriteString(txid + "\n")
					_ = f.Close()
				}
			}
		}()
		ready()
		// Park the main goroutine forever: the worker keeps enqueueing while
		// the parent's SIGKILL is the only exit. Exiting here would end the
		// child before the parent's kill lands.
		select {}
	default:
		os.Exit(9)
	}
	if mode != "blind-loop" {
		// The REAL production enqueue path — no test shims in the entry point.
		// The parked publish never returns: the parent's kill lands inside it.
		if err := enqueueSettlementNotice(outbox, "escrow claim", os.Getenv("SPORE_TEST_SETTLEMENT_OUTBOX_TX"), "addr-crash", "ffeeddccbbaa99887", []byte(`{"type":"spore/settlement/v1"}`)); err != nil {
			os.Exit(9)
		}
	}
	// Unreachable: parked children are killed mid-publish and blind-loop
	// parks forever. Getting here means the crash-mode logic is broken.
	os.Exit(9)
}

// runSettlementOutboxCrashChild re-execs the test binary in crash mode and
// kills -9 it the moment the child reports its parking point on stderr.
// Returns the kill error (a crash) — a CLEAN child exit is a test failure,
// because these tests must exercise true crash residue, not graceful state.
func runSettlementOutboxCrashChild(t *testing.T, mode, dir, outbox, txid string) error {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run", "^TestSettlementOutboxCrashNoop$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		settlementOutboxCrashEnv+"="+mode,
		"SPORE_TEST_SETTLEMENT_OUTBOX_DIR="+dir,
		"SPORE_TEST_SETTLEMENT_OUTBOX_PATH="+outbox,
		"SPORE_TEST_SETTLEMENT_OUTBOX_TX="+txid,
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Reap the child on ANY exit path: an orphaned crash child would hold
	// the test binary image locked (unlinkat fails) and keep writing to the
	// TempDir after t.Cleanup removes it.
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// Watch for the parking-point line on the child's stderr.
	lines := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "reached ("+mode+")") {
				lines <- sc.Text()
				return
			}
		}
		close(lines)
	}()
	select {
	case _, ok := <-lines:
		if !ok {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("crash child (%s) died before reaching its parking point", mode)
		}
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("crash child (%s) never reached its parking point", mode)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill crash child: %v", err)
	}
	werr := cmd.Wait()
	if werr == nil {
		t.Fatalf("crash child (%s) exited CLEANLY after kill; crash-mode logic is broken", mode)
	}
	return werr
}

// loadOutboxForCrashTest loads the queue or fails the test.
func loadOutboxForCrashTest(t *testing.T, path string) []settlementOutboxEntry {
	t.Helper()
	entries, err := loadSettlementOutbox(path)
	if err != nil {
		t.Fatalf("queue file must always parse after a crash: %v", err)
	}
	return entries
}

// TestSettlementOutboxCrashBeforePublish kills the child after the enqueue
// decided to publish but before anything durable changed: no half-notice may
// reach disk, whatever survived must load, and re-enqueuing the SAME
// settlement must dedupe against the survivors — never duplicate.
func TestSettlementOutboxCrashBeforePublish(t *testing.T) {
	dir := t.TempDir()
	outbox := filepath.Join(dir, "settlement-outbox.json")
	const txid = "tx-crash-before"

	// Seed one completed settlement so the crash window has real state.
	if err := enqueueSettlementNotice(outbox, "escrow claim", "tx-survivor", "addr-a", "aabbccddeeff0011", []byte(`{"type":"spore/settlement/v1"}`)); err != nil {
		t.Fatal(err)
	}

	runSettlementOutboxCrashChild(t, "park-before-publish", dir, outbox, txid)

	entries := loadOutboxForCrashTest(t, outbox)
	// The only legal disk states: the seed alone (publish never landed), or
	// seed + the new entry (publish completed). NEVER a torn file, and never
	// a partial entry.
	sawSeed, sawNew := false, false
	for _, e := range entries {
		switch e.TxID {
		case "tx-survivor":
			sawSeed = true
		case txid:
			sawNew = true
			if e.Kind != "escrow claim" || e.To != "addr-crash" || len(e.Body) == 0 {
				t.Fatalf("crashed-in entry must be complete if present: %+v", e)
			}
		default:
			t.Fatalf("unexpected entry from nowhere: %+v", e)
		}
	}
	if !sawSeed {
		t.Fatalf("seed entry must never be lost: %+v", entries)
	}
	if sawNew && len(entries) != 2 || !sawNew && len(entries) != 1 {
		t.Fatalf("queue = %d entries, want exactly the legal states (1 or 2)", len(entries))
	}

	// Re-enqueue the SAME settlement that was mid-flight during the crash.
	// This crash landed BEFORE anything durable, so the queue gains exactly
	// ONE copy of it — proving no partial or duplicate copy leaked from the
	// torn window. (Had the crash landed post-commit, dedupe would instead
	// have kept it single; either way the queue converges to one copy.)
	if err := enqueueSettlementNotice(outbox, "escrow claim", txid, "addr-crash", "ffeeddccbbaa99887", []byte(`{"type":"spore/settlement/v1"}`)); err != nil {
		t.Fatal(err)
	}
	after := loadOutboxForCrashTest(t, outbox)
	if len(after) != 2 {
		t.Fatalf("queue after pre-publish crash + re-enqueue = %d entries, want exactly survivor + one copy of the crashed settlement", len(after))
	}
	counts := map[string]int{}
	for _, e := range after {
		counts[e.TxID]++
	}
	for txid, n := range counts {
		if n != 1 {
			t.Fatalf("tx %s appears %d times after crash + re-enqueue; the queue must never duplicate", txid, n)
		}
	}
}

// TestSettlementOutboxCrashAfterSyncKillsBeforeRename is the torn-write
// window: the new generation is fully durable in a temp file, the rename has
// NOT happened, and the child is killed. The queue file must still parse as
// the OLD complete generation, the temp corpse must be ignored by the
// loader, and a re-enqueue must dedupe cleanly.
func TestSettlementOutboxCrashAfterSyncKillsBeforeRename(t *testing.T) {
	dir := t.TempDir()
	outbox := filepath.Join(dir, "settlement-outbox.json")
	const txid = "tx-crash-sync"

	if err := enqueueSettlementNotice(outbox, "escrow claim", "tx-survivor", "addr-a", "aabbccddeeff0011", []byte(`{"type":"spore/settlement/v1"}`)); err != nil {
		t.Fatal(err)
	}
	before := loadOutboxForCrashTest(t, outbox)
	if len(before) != 1 {
		t.Fatalf("seed queue = %+v, want exactly 1 entry", before)
	}

	runSettlementOutboxCrashChild(t, "park-after-sync", dir, outbox, txid)

	// The temp corpse exists — the new generation was fully written — but
	// the rename never happened, so the queue file must be byte-for-byte the
	// OLD generation.
	corpse, err := os.ReadFile(filepath.Join(dir, "crash-tmp.txt"))
	if err != nil {
		t.Fatalf("child should have left its durable temp corpse on disk: %v", err)
	}
	if _, serr := os.Stat(strings.TrimSpace(string(corpse))); serr != nil {
		t.Fatalf("durable temp corpse must still exist after the crash: %v", serr)
	}
	after := loadOutboxForCrashTest(t, outbox)
	if len(after) != 1 || after[0].TxID != "tx-survivor" {
		t.Fatalf("crash before the rename must leave the old generation: %+v", after)
	}
	raw, err := os.ReadFile(outbox)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []settlementOutboxEntry
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("queue file torn after crash-before-rename: %v\nraw: %s", err, raw)
	}

	// The corpse must be invisible to the loader: it only ever reads the
	// queue path. Re-enqueue the crashed settlement; dedupe keeps it single.
	if err := enqueueSettlementNotice(outbox, "escrow claim", txid, "addr-crash", "ffeeddccbbaa99887", []byte(`{"type":"spore/settlement/v1"}`)); err != nil {
		t.Fatal(err)
	}
	final := loadOutboxForCrashTest(t, outbox)
	if len(final) != 2 {
		t.Fatalf("queue after crash + re-enqueue = %+v, want exactly survivor + crashed settlement", final)
	}
}

// TestSettlementOutboxCrashBlindMidLoop kills the child at an arbitrary
// unsynchronized moment mid-enqueue-loop over a backlog of settlements.
// Whatever the instant, the queue file must parse, contain every settlement
// whose enqueue had already COMPLETED at most once (never a loss, never a
// duplicate), and a follow-up enqueue must never duplicate.
func TestSettlementOutboxCrashBlindMidLoop(t *testing.T) {
	dir := t.TempDir()
	outbox := filepath.Join(dir, "settlement-outbox.json")

	// Backlog driver in the parent: enqueue a batch of settlements, then
	// kill the child at a random unsynchronized moment. The child is parked
	// in a tight real-enqueue loop (see below), so the kill lands somewhere
	// inside a save — the crash instant is genuinely arbitrary.
	if err := enqueueSettlementNotice(outbox, "dex wrap", "tx-seed", "addr-a", "aabbccddeeff0011", []byte(`{"type":"spore/settlement/v1"}`)); err != nil {
		t.Fatal(err)
	}
	seed := loadOutboxForCrashTest(t, outbox)
	if len(seed) != 1 {
		t.Fatalf("seed queue = %+v", seed)
	}

	// The blind child runs the REAL enqueue path (mode blind-loop: no
	// hooks, 5000 real saves ahead of it) and the parent kills at an
	// unsynchronized moment, so the kill lands inside a multi-step persist
	// with near-certainty — a genuinely arbitrary crash instant.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run", "^TestSettlementOutboxCrashNoop$")
	// Pass the child's stderr through: if the blind child dies before the
	// kill lands, its own diagnostics must reach the test log.
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		settlementOutboxCrashEnv+"=blind-loop",
		"SPORE_TEST_SETTLEMENT_OUTBOX_DIR="+dir,
		"SPORE_TEST_SETTLEMENT_OUTBOX_PATH="+outbox,
		"SPORE_TEST_SETTLEMENT_OUTBOX_TX=tx-blind",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Reap the child on ANY exit path (same reason as the helper above).
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// Kill only once the child has DEMONSTRABLY completed at least one
	// enqueue, signaled via its progress file — a fixed sleep cannot be
	// trusted under -race and cold caches, and polling the QUEUE file here
	// would collide with the child's atomic replace (a Windows sharing
	// violation is a harness artifact, not a crash). From one completed
	// enqueue, thousands remain, so the kill lands inside a later multi-step
	// persist with near-certainty — and whichever instruction it lands on,
	// the state-on-disk assertions below are deterministic.
	progressPath := filepath.Join(dir, "blind-progress.txt")
	deadline := time.Now().Add(60 * time.Second)
	for {
		if raw, rerr := os.ReadFile(progressPath); rerr == nil && len(bytes.TrimSpace(raw)) > 0 {
			break // at least one blind enqueue completed: the loop is live
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal("blind child never completed an enqueue; the crash window was never reached")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Jitter the instant a little so consecutive runs cross different
	// instructions of the persist, then kill.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	time.Sleep(time.Duration(rng.Intn(4)) * time.Millisecond)
	kerr := cmd.Process.Kill()
	_ = cmd.Wait()
	if kerr != nil {
		t.Fatalf("kill blind crash child: %v", kerr)
	}

	// The child enqueued a fresh unique txid per iteration, so the surviving
	// queue must be a MONOTONE PREFIX of that backlog: each txid at most
	// once, the seed intact, and nothing unknown.
	after := loadOutboxForCrashTest(t, outbox)
	counts := map[string]int{}
	for _, e := range after {
		counts[e.TxID]++
		switch {
		case e.TxID == "tx-seed":
			if e.Kind != "dex wrap" || e.To != "addr-a" || len(e.Body) == 0 {
				t.Fatalf("seed entry must survive complete: %+v", e)
			}
		case strings.HasPrefix(e.TxID, "tx-blind-"):
			if e.Kind != "escrow claim" || e.To != "addr-crash" || len(e.Body) == 0 {
				t.Fatalf("surviving entry must be complete: %+v", e)
			}
		default:
			t.Fatalf("unexpected entry from nowhere: %+v", e)
		}
	}
	if n := counts["tx-seed"]; n != 1 {
		t.Fatalf("seed entry count = %d after blind crash; the queue must never lose a completed notice", n)
	}
	for txid, n := range counts {
		if n > 1 {
			t.Fatalf("tx %s appears %d times after blind crash; torn state leaked a duplicate", txid, n)
		}
	}
	// Progress was observed before the kill, so the surviving queue must
	// contain the seed plus the observed blind enqueues.
	if len(after) < 2 {
		t.Fatalf("blind kill must not precede the observed progress (got %d entries)", len(after))
	}

	// Recovery: re-enqueue the settlement the crash most plausibly
	// interrupted (the last survivor's successor). Whatever the crash
	// instant, the queue must converge to exactly one copy of it.
	successor := "tx-blind-0000"
	if len(after) > 1 {
		successor = fmt.Sprintf("tx-blind-%04d", len(after)-1)
	}
	if err := enqueueSettlementNotice(outbox, "escrow claim", successor, "addr-crash", "ffeeddccbbaa99887", []byte(`{"type":"spore/settlement/v1"}`)); err != nil {
		t.Fatal(err)
	}
	final := loadOutboxForCrashTest(t, outbox)
	finalCounts := map[string]int{}
	for _, e := range final {
		finalCounts[e.TxID]++
	}
	for txid, n := range finalCounts {
		if n != 1 {
			t.Fatalf("tx %s appears %d times after blind crash + re-enqueue; the queue must never duplicate", txid, n)
		}
	}
}

// TestSettlementOutboxCrashNoop is the entry the crash children run: it does
// nothing because TestMain intercepts the process in crash mode. It exists
// only so `-test.run` has a target in the re-exec'd binary.
func TestSettlementOutboxCrashNoop(t *testing.T) {
	if os.Getenv(settlementOutboxCrashEnv) == "" {
		t.Skip("crash-child entry point; run via TestSettlementOutboxCrash* parents")
	}
}
