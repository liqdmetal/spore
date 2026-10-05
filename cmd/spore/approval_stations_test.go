package main

// Live two-station drill: two real OS processes (re-exec'd test binaries,
// same pattern as the settlement outbox crash test) run the actual watch
// cycle over one shared queue + outbox, racing on the same requests. The
// signing lock must yield exactly one signature per request with the loser
// skipping quietly; this is the cross-process harness the in-process race
// test cannot fully reach (real PIDs, real cross-process file-sharing
// semantics). The only tolerated failure is the documented exclusive-create
// output backstop ("file exists"): a loser whose stat raced the winner's
// write can acquire the freed lock a moment too late and hits the output
// that is already there.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWatchStationSelfMetricsLive drives the REAL binary as a -watch station
// with -metrics-every and proves the self-metrics heartbeat reaches stdout
// through the actual CLI in both render modes: the human summary and the
// -metrics-json JSON-lines mode. Build once, run over an empty queue for a
// few fast periods per mode, then read the logs. Skips when the go tool is
// unavailable.
func TestWatchStationSelfMetricsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("real-binary watch smoke skipped in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool unavailable; skipping real-binary watch smoke")
	}
	exe := filepath.Join(t.TempDir(), "spore-smoke.exe")
	build := exec.Command("go", "build", "-o", exe, ".")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build spore: %v\n%s", err, out)
	}
	for _, tc := range []struct {
		name        string
		metricsJSON bool
	}{{"text", false}, {"json", true}} {
		t.Run(tc.name, func(t *testing.T) {
			watchStationSelfMetricsSmoke(t, exe, tc.metricsJSON)
		})
	}
}

// watchStationSelfMetricsSmoke runs one real station for a couple of
// heartbeat periods and asserts on its log according to the render mode.
func watchStationSelfMetricsSmoke(t *testing.T, exe string, metricsJSON bool) {
	t.Helper()
	dir := t.TempDir()
	queue := filepath.Join(dir, "queue")
	if err := os.MkdirAll(queue, 0o755); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(dir, "approver.key")
	if err := os.WriteFile(identityPath, []byte(strings.Repeat("52", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"msg", "approve",
		"-request-dir", queue, "-identity", identityPath,
		"-out-dir", filepath.Join(dir, "out"), "-state-dir", filepath.Join(dir, "state"),
		"-watch", "-confirm", "-every", "500ms", "-metrics-every", "500ms"}
	if metricsJSON {
		args = append(args, "-metrics-json")
	}
	logPath := filepath.Join(dir, "station.log")
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logf.Close()
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	time.Sleep(2200 * time.Millisecond)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logBytes)
	if !strings.Contains(logText, "approve: watching") {
		t.Fatalf("station log missing startup line:\n%s", logText)
	}
	if metricsJSON {
		// Every heartbeat is one scrapeable JSON line; the human summary
		// must be entirely absent from stdout.
		if got := strings.Count(logText, "self-metrics at"); got != 0 {
			t.Fatalf("-metrics-json must silence the human summary, got %d text heartbeats:\n%s", got, logText)
		}
		var heartbeats int
		for _, line := range strings.Split(logText, "\n") {
			if !strings.HasPrefix(line, `{"at":`) {
				continue
			}
			heartbeats++
			var hb watchMetricsEnvelope
			if err := json.Unmarshal([]byte(line), &hb); err != nil {
				t.Fatalf("heartbeat line must parse as JSON: %v\nraw: %s", err, line)
			}
			if _, err := time.Parse(time.RFC3339, hb.At); err != nil {
				t.Fatalf("heartbeat at must be RFC3339: %v (%q)", err, hb.At)
			}
			if hb.Metrics == nil || hb.Metrics.QueueDir != queue {
				t.Fatalf("heartbeat metrics must describe this station's queue (%s): %+v", queue, hb.Metrics)
			}
			// The station field must name the real OS process that emitted
			// the line: the re-exec'd binary's PID, and a non-empty host.
			if hb.Station.PID != cmd.Process.Pid {
				t.Fatalf("heartbeat station pid must be the station process (want %d): %+v", cmd.Process.Pid, hb.Station)
			}
			if hb.Station.Host == "" {
				t.Fatalf("heartbeat station host must name the station host: %+v", hb.Station)
			}
		}
		if heartbeats < 2 {
			t.Fatalf("want >=2 JSON heartbeats in ~2s of 500ms periods, got %d:\n%s", heartbeats, logText)
		}
		return
	}
	if got := strings.Count(logText, "self-metrics at"); got < 2 {
		t.Fatalf("want >=2 self-metrics heartbeats in ~2s of 500ms periods, got %d:\n%s", got, logText)
	}
	if !strings.Contains(logText, "queue: 0 request(s)") {
		t.Fatalf("heartbeat missing the queue line:\n%s", logText)
	}
}

// stationDrillEnv marks a re-exec'd test binary as a drill station process.
const stationDrillEnv = "SPORE_STATION_DRILL"

// TestApprovalStationDrillChild is not a test: it is the body each drill
// station process executes, running the REAL watch cycle in a tight poll
// until its deadline. Without the drill env it skips instantly, so ordinary
// `go test` runs are unaffected.
func TestApprovalStationDrillChild(t *testing.T) {
	queue := os.Getenv("SPORE_STATION_QUEUE")
	if queue == "" || os.Getenv(stationDrillEnv) == "" {
		t.Skip("station process: only runs under the two-station drill")
	}
	identityPath := os.Getenv("SPORE_STATION_IDENTITY")
	outDir := os.Getenv("SPORE_STATION_OUT")
	stateDir := os.Getenv("SPORE_STATION_STATE")
	deadline := time.Now().Add(10 * time.Second)
	seen := make(map[string]string)
	for time.Now().Before(deadline) {
		if _, _, err := runApprovalWatchCycle(queue, identityPath, outDir, stateDir, true, seen); err != nil {
			fmt.Printf("STATION-ERR pid=%d: %v\n", os.Getpid(), err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestApprovalTwoStationDrillNeverDoubleSign races two real station
// processes over one queue: each dropped request must be signed exactly once
// across both stations, the loser must skip (lock held or already signed),
// and the shared outbox must end with exactly one verifiable approval per
// request and no leaked locks.
func TestApprovalTwoStationDrillNeverDoubleSign(t *testing.T) {
	if testing.Short() {
		t.Skip("two-station drill skipped in -short mode")
	}
	dir := t.TempDir()
	outDir := filepath.Join(dir, "outbox")
	queue := filepath.Join(dir, "queue")
	stateDir := filepath.Join(dir, "state")
	for _, d := range []string{outDir, queue, stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Two independent requests sharing the approver identity; built in dir,
	// moved into the queue only after the stations are already cycling.
	req1, identityPath := lockTestRequest(t, dir, "warm", time.Now())
	req2, _ := lockTestRequest(t, dir, "drill2", time.Now())

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var openLogs []*os.File
	spawn := func(logPath string) *exec.Cmd {
		cmd := exec.Command(exe, "-test.run=^TestApprovalStationDrillChild$", "-test.timeout=60s")
		cmd.Env = append(os.Environ(),
			stationDrillEnv+"=1",
			"SPORE_STATION_QUEUE="+queue,
			"SPORE_STATION_IDENTITY="+identityPath,
			"SPORE_STATION_OUT="+outDir,
			"SPORE_STATION_STATE="+stateDir,
		)
		logf, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		openLogs = append(openLogs, logf) // parent's handle: close before TempDir cleanup
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	station1 := spawn(filepath.Join(dir, "station1.log"))
	station2 := spawn(filepath.Join(dir, "station2.log"))
	stop := func(cmd *exec.Cmd) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	defer func() {
		stop(station1)
		stop(station2)
		for _, f := range openLogs {
			_ = f.Close()
		}
	}()

	time.Sleep(600 * time.Millisecond) // stations settle on an empty queue
	if err := os.Rename(req1, filepath.Join(queue, filepath.Base(req1))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if err := os.Rename(req2, filepath.Join(queue, filepath.Base(req2))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	stop(station1)
	stop(station2)

	// Exactly one SIGNED line per request across both stations, and any
	// FAILED line must be the documented exclusive-create backstop.
	for _, name := range []string{"warm", "drill2"} {
		signed := 0
		for _, log := range []string{filepath.Join(dir, "station1.log"), filepath.Join(dir, "station2.log")} {
			b, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(b), "\n") {
				switch {
				case strings.Contains(line, "SIGNED") && strings.Contains(line, name):
					signed++
				case strings.Contains(line, "FAILED") && !strings.Contains(line, "file exists"):
					t.Fatalf("unexpected station failure: %s", line)
				}
			}
		}
		if signed != 1 {
			t.Fatalf("request %s must be signed exactly once across stations, got %d", name, signed)
		}
	}

	// Shared outbox: exactly one verifiable approval per request, no locks.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("shared outbox must hold exactly one approval per request, got %v", entries)
	}
	approverPublic, _ := approvalFixtureKeys(t)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".signed.json") {
			t.Fatalf("unexpected non-approval in outbox: %s", e.Name())
		}
		approved, err := decodeCapabilityFile(filepath.Join(outDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyCapabilityApproval(approved, hex.EncodeToString(approverPublic), time.Now()); err != nil {
			t.Fatalf("approval %s does not verify: %v", e.Name(), err)
		}
	}
	for _, d := range []string{queue, outDir} {
		locks, err := filepath.Glob(filepath.Join(d, "*.lock*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(locks) != 0 {
			t.Fatalf("lock files leaked in %s: %v", d, locks)
		}
	}
}
