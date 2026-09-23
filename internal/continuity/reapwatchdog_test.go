package continuity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// parseLine pins the log contract against both daemons' exact heartbeat
// formats — the Rust port is operator-identical on purpose, and these lines
// are byte-shaped like the real ones (spore serve / spore-peer serve).
func TestParseReapStatusLineBothDaemons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		line   string
		want   ReapStatus
		wantOK bool
	}{{
		name:   "go daemon full line",
		line:   "spore serve: reaper status: 14 passes, 3 bodies composted total, last pass removed 2 at 10:48:49 (cadence 2s)",
		want:   ReapStatus{Passes: 14, Removed: 3, Cadence: "2s", Source: "spore"},
		wantOK: true,
	}, {
		name:   "rust daemon full line",
		line:   "spore-peer serve: reaper status: 14 passes, 3 bodies composted total, last pass removed 2 at 10:48:49 (cadence 2s)",
		want:   ReapStatus{Passes: 14, Removed: 3, Cadence: "2s", Source: "spore-peer"},
		wantOK: true,
	}, {
		name:   "go daemon never-ran line",
		line:   "spore serve: reaper status: 0 passes, no pass completed yet (cadence 10m0s)",
		want:   ReapStatus{Passes: 0, Removed: 0, Cadence: "10m0s", Source: "spore"},
		wantOK: true,
	}, {
		name:   "rust daemon never-ran line",
		line:   "spore-peer serve: reaper status: 5 passes, no pass completed yet (cadence 1s)",
		want:   ReapStatus{Passes: 5, Removed: 0, Cadence: "1s", Source: "spore-peer"},
		wantOK: true,
	}, {
		name:   "counter garbage",
		line:   "spore serve: reaper status: many passes, 0 bodies composted total (cadence 2s)",
		wantOK: false,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseReapStatusLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				return
			}
			if got.Passes != tc.want.Passes || got.Source != tc.want.Source || got.Cadence != tc.want.Cadence || got.Removed != tc.want.Removed {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLastReapStatusTakesNewestAndSurvivesCRLF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.log")
	log := "spore serve: started\n" +
		"spore serve: reaper status: 1 passes, 0 bodies composted total, last pass removed 0 at 10:00:01 (cadence 2s)\r\n" +
		"noise without a heartbeat\r\n" +
		"spore serve: reaper status: 2 passes, 1 bodies composted total, last pass removed 1 at 10:00:03 (cadence 2s)\r\n"
	if err := os.WriteFile(path, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LastReapStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if st == nil || st.Passes != 2 || st.Removed != 1 {
		t.Fatalf("newest line not selected: %+v", st)
	}

	// A log with no heartbeat lines at all.
	empty := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(empty, []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := LastReapStatus(empty); err != nil || st != nil {
		t.Fatalf("empty log: st=%v err=%v, want nil/nil", st, err)
	}
}

// The core operator contract: a frozen pass counter is the dead-reaper signal
// (heartbeat prints even when idle, so equality IS the fault), an advancing
// counter is alive, and the latch makes the alert fire once per freeze with
// re-arm on recovery.
func TestCheckReaperFreezeLivenessAndLatch(t *testing.T) {
	const now = int64(1_000_000)

	// Fresh watch: baseline, never an alert.
	res := CheckReaper(&ReapStatus{Passes: 10, Source: "spore"}, nil, 0, now)
	if res.Outcome != WatchdogBaseline || res.Memory.Passes != 10 {
		t.Fatalf("baseline: %+v", res)
	}
	mem := res.Memory

	// Same count on the next watch => freeze => alert.
	res = CheckReaper(&ReapStatus{Passes: 10, Removed: 3, Cadence: "2s", Source: "spore"}, &mem, 0, now+60)
	if res.Outcome != WatchdogFrozenAlert {
		t.Fatalf("first freeze should alert, got %+v", res)
	}
	if res.Memory.Frozen != 1 || res.Detail == "" {
		t.Fatalf("alert memory/detail: %+v", res)
	}

	// Latched: still frozen at the alerted count => no re-alert.
	latched := ApplyAlertLatch(res.Memory, 10)
	res = CheckReaper(&ReapStatus{Passes: 10, Source: "spore"}, &latched, 0, now+120)
	if res.Outcome != WatchdogAlreadyQueued {
		t.Fatalf("latched freeze should not re-alert, got %+v", res)
	}

	// Recovery: counter advances => OK and latch cleared.
	res = CheckReaper(&ReapStatus{Passes: 11, Source: "spore"}, &latched, 0, now+180)
	if res.Outcome != WatchdogOK || res.Memory.Alerted {
		t.Fatalf("recovery: %+v", res)
	}

	// A NEW freeze after recovery alerts again.
	recovered := res.Memory
	res = CheckReaper(&ReapStatus{Passes: 11, Source: "spore"}, &recovered, 0, now+240)
	if res.Outcome != WatchdogFrozenAlert {
		t.Fatalf("second freeze should alert again, got %+v", res)
	}
}

func TestCheckReaperGraceWindow(t *testing.T) {
	const now = int64(2_000_000)
	mem := &ReapMemory{Passes: 5, Source: "spore"}

	// grace=2: two frozen observations tolerated, third alerts.
	for i := 1; i <= 2; i++ {
		res := CheckReaper(&ReapStatus{Passes: 5, Source: "spore"}, mem, 2, now+int64(i)*60)
		if res.Outcome != WatchdogWithinGrace {
			t.Fatalf("frozen #%d should be within grace, got %+v", i, res)
		}
		m := res.Memory
		mem = &m
	}
	res := CheckReaper(&ReapStatus{Passes: 5, Source: "spore"}, mem, 2, now+180)
	if res.Outcome != WatchdogFrozenAlert {
		t.Fatalf("frozen past grace should alert, got %+v", res)
	}
}

func TestCheckReaperRebaselineOnCounterRegression(t *testing.T) {
	const now = int64(3_000_000)
	// Counter went backwards: log rotation or a restart with a fresh log.
	// Re-baseline (never alert on regression), clearing any latch.
	mem := &ReapMemory{Passes: 50, Alerted: true, AlertPasses: 50, Source: "spore"}
	res := CheckReaper(&ReapStatus{Passes: 3, Source: "spore"}, mem, 0, now)
	if res.Outcome != WatchdogRebaselined {
		t.Fatalf("regression should re-baseline, got %+v", res)
	}
	if res.Memory.Alerted || res.Memory.Passes != 3 || res.Memory.Frozen != 0 {
		t.Fatalf("re-baselined memory: %+v", res.Memory)
	}
}

// A never-run reaper's "no pass completed yet" line parses to Passes=0, and a
// baseline of 0 compared against 0 is a FREEZE — a reaper that has never
// completed a pass under a hold that should have bodies is dead in exactly
// the way worth alerting. (A fresh daemon whose reaper simply has not fired
// yet is protected by the baseline pass and/or grace.)
func TestCheckReaperNeverRanReaperIsStillADeadReaper(t *testing.T) {
	const now = int64(4_000_000)
	res := CheckReaper(&ReapStatus{Passes: 0, Cadence: "10m0s", Source: "spore-peer"}, nil, 0, now)
	if res.Outcome != WatchdogBaseline {
		t.Fatalf("baseline: %+v", res)
	}
	mem := res.Memory
	res = CheckReaper(&ReapStatus{Passes: 0, Source: "spore-peer"}, &mem, 0, now+60)
	if res.Outcome != WatchdogFrozenAlert {
		t.Fatalf("never-ran reaper observed twice should alert, got %+v", res)
	}
}

func TestLoadReapMemoryMissingVsCorrupt(t *testing.T) {
	dir := t.TempDir()

	// Missing file: fresh watch, no error.
	if m, err := LoadReapMemory(filepath.Join(dir, "absent.json")); err != nil || m != nil {
		t.Fatalf("missing file: m=%v err=%v, want nil/nil", m, err)
	}

	// Corrupt file: hard error — silently re-baselining would turn "state
	// directory broke" into "watchdog stopped alerting".
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReapMemory(broken); err == nil {
		t.Fatal("corrupt state must error, not silently re-baseline")
	}

	// Round-trip.
	good := filepath.Join(dir, "good.json")
	raw, _ := json.Marshal(ReapMemory{Passes: 9, ObservedAt: 42, Source: "spore"})
	if err := os.WriteFile(good, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadReapMemory(good)
	if err != nil || m == nil || m.Passes != 9 || m.ObservedAt != 42 {
		t.Fatalf("round-trip: %+v err=%v", m, err)
	}
}
