package main

// Watchdog smoke: the freeze→alert→recover arc from scripts/escrow_dex_soak.sh
// flow 4, pinned as a Go test against the REAL binary surface.
//
//   1. a real `spore serve` subprocess (built here the way the soak and the
//      release build it) reaps on a 1s cadence and prints reaper-status
//      heartbeats,
//   2. the real `continuity watch-reaper` command walks the full state
//      machine: baseline → ok (alive) → within-grace after the daemon is
//      killed → durable alert on freeze (exit 1 with the outbox row present,
//      because the webhook is deliberately unroutable) → TxID dedupe →
//      recovery re-arm after a restart with a fresh log.
//
// The outbox file is asserted directly (JSONL, Go field names) — no jq, no
// shell. Runs in the package's default gate set, including -race.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// buildSporeBinary builds the real CLI binary once per test (the same shape
// scripts/escrow_dex_soak.sh and the release pipeline build).
func buildSporeBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "spore-watchdog-smoke"+exeSuffixForTests())
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build of ./cmd/spore failed: %v\n%s", err, out)
	}
	return bin
}

func exeSuffixForTests() string {
	if strings.HasSuffix(os.Args[0], ".exe") {
		return ".exe"
	}
	return ""
}

// runWatchReaper runs the real `continuity watch-reaper` subcommand, returning
// combined output and the exit error (if any). Nothing shells out to a shell.
func runWatchReaper(t *testing.T, sporeBin string, extra ...string) (string, error) {
	t.Helper()
	args := append([]string{"continuity", "watch-reaper"}, extra...)
	cmd := exec.Command(sporeBin, args...)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func parseLastPasses(log string) int {
	last := -1
	for _, line := range strings.Split(log, "\n") {
		if !strings.Contains(line, "reaper status:") {
			continue
		}
		// "spore serve: reaper status: 14 passes, ..."
		var passes int
		if _, err := fmt.Sscanf(line, "spore serve: reaper status: %d passes", &passes); err == nil && passes >= 0 {
			last = passes
		}
	}
	return last
}

func readFileOrEmpty(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(raw)
}

type serveProc struct {
	cmd *exec.Cmd
	log *os.File
}

func startServe(t *testing.T, sporeBin, dir, logPath string) *serveProc {
	t.Helper()
	hold := filepath.Join(dir, "hold")
	if err := os.MkdirAll(hold, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sporeBin, "serve", "-dir", hold, "-listen", "127.0.0.1:0", "-reap-every", "1s")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sp := &serveProc{cmd: cmd, log: log}
	t.Cleanup(func() {
		_ = sp.cmd.Process.Kill()
		_, _ = sp.cmd.Process.Wait()
		_ = sp.log.Close()
	})
	return sp
}

// waitReady waits for serve's startup lines (which precede any heartbeat) and
// fails fast if the process dies before printing them.
func (sp *serveProc) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(readFileOrEmpty(t, sp.logName()), "listening on") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("serve never became ready; log:\n%s", tailForTest(readFileOrEmpty(t, sp.logName()), 2000))
}

func (sp *serveProc) logName() string { return sp.log.Name() }

func (sp *serveProc) kill(t *testing.T) {
	t.Helper()
	if err := sp.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill serve: %v", err)
	}
	_, _ = sp.cmd.Process.Wait()
}

func tailForTest(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func outboxCount(t *testing.T, path, txid string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			TxID string `json:"TxID"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err == nil && rec.TxID == txid {
			n++
		}
	}
	return n
}

// deadWebhook runs an HTTP listener that accepts connections and answers
// 503 to everything. "Down" the honest way: a real server that is refusing
// delivery, not an unroutable port — so the outbox's failed-delivery path
// runs in milliseconds, deterministically, on every platform (a firewalled
// or unroutable port is OS- and firewall-dependent; some hang past the
// client timeout). Delivery failures leave the alert durably queued, which
// is exactly what the assertions observe.
type deadWebhook struct {
	ln  net.Listener
	srv *http.Server
	wg  sync.WaitGroup
}

func startDeadWebhook(t *testing.T) *deadWebhook {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dw := &deadWebhook{ln: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	dw.srv = &http.Server{Handler: mux}
	dw.wg.Add(1)
	go func() {
		defer dw.wg.Done()
		_ = dw.srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = dw.srv.Close()
		dw.wg.Wait()
	})
	return dw
}

func TestWatchReaperFreezeRecoverSmoke(t *testing.T) {
	sporeBin := buildSporeBinary(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "serve.log")
	statePath := filepath.Join(dir, "watchdog-state.json")
	outboxPath := filepath.Join(dir, "outbox.jsonl")
	// The webhook is a live listener that REFUSES delivery (503) on purpose:
	// with delivery failing deterministically, the durable path is what the
	// test observes (exit 1 + outbox row), never fire-and-forget.
	webhook := "http://" + startDeadWebhook(t).ln.Addr().String() + "/notifier"

	watch := func(extra ...string) (string, error) {
		args := []string{
			"-log", logPath,
			"-state", statePath,
			"-node", "spore",
			"-outbox", outboxPath,
			"-webhook", webhook,
		}
		return runWatchReaper(t, sporeBin, append(args, extra...)...)
	}
	aliveOK := func() bool { // watch reports the re-armed/alive state
		out, err := watch()
		return err == nil && strings.Contains(out, "ok passes=")
	}

	// --- live daemon: baseline → alive ------------------------------------
	serve := startServe(t, sporeBin, dir, logPath)
	serve.waitReady(t)
	// Wait for the FIRST heartbeat before the first watch: the watchdog
	// deliberately treats a heartbeat-less log as a dead node (silence is
	// not health — the soak asserts that separately via its killed-daemon
	// no-heartbeat case). Mirrors the soak's wait_for_node_status.
	firstBeat := time.Now().Add(15 * time.Second)
	for parseLastPasses(readFileOrEmpty(t, logPath)) < 0 {
		if time.Now().After(firstBeat) {
			t.Fatalf("serve never printed a reaper heartbeat; log:\n%s", tailForTest(readFileOrEmpty(t, logPath), 2000))
		}
		time.Sleep(100 * time.Millisecond)
	}

	out, err := watch()
	if err != nil || !strings.Contains(out, "baseline") {
		t.Fatalf("first watch: want baseline success, got err=%v out=%q", err, out)
	}

	// Alive: poll until a watch reports an advanced counter (bounded — a
	// 1s reaper advances within a couple of beats).
	deadline := time.Now().Add(15 * time.Second)
	for !aliveOK() {
		if time.Now().After(deadline) {
			out, err = watch()
			t.Fatalf("alive watch never reported ok: err=%v out=%q\nlog:\n%s", err, out, tailForTest(readFileOrEmpty(t, logPath), 2000))
		}
		time.Sleep(300 * time.Millisecond)
	}

	// --- freeze ------------------------------------------------------------
	serve.kill(t)
	// The daemon is dead, so the last heartbeat's counter is frozen forever —
	// the exact precondition every following watch relies on.
	deadline = time.Now().Add(5 * time.Second)
	for {
		if p := parseLastPasses(readFileOrEmpty(t, logPath)); p >= 0 {
			t.Logf("counter frozen at %d", p)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no heartbeat ever appeared to freeze")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Grace 1: one frozen watch is tolerated.
	out, err = watch("-grace", "1")
	if err != nil || !strings.Contains(out, "within grace") {
		t.Fatalf("frozen watch 1: want within-grace, got err=%v out=%q", err, out)
	}

	// Grace exceeded: the alert queues durably and the watch exits non-zero
	// (delivery fails on purpose). This is the load-bearing assertion: a
	// fire-and-forget alert with no durable record would pass a webhook-up
	// test and lose the alert in production.
	out, err = watch("-grace", "1")
	if err == nil {
		t.Fatalf("frozen watch 2: want exit 1 (delivery failing), got success: %q", out)
	}
	if n := outboxCount(t, outboxPath, "watchdog/reaper/stale reaper"); n != 1 {
		t.Fatalf("frozen watch 2: want exactly 1 durable alert, got %d (out=%q)", n, out)
	}

	// Still frozen: the outbox dedupes by TxID — no alert storm.
	if _, err := watch("-grace", "1"); err == nil {
		t.Fatal("still-frozen watch: want exit 1 while delivery keeps failing")
	}
	if n := outboxCount(t, outboxPath, "watchdog/reaper/stale reaper"); n != 1 {
		t.Fatalf("outbox dedupe: want exactly 1 stale-reaper alert, got %d", n)
	}

	// --- recover -----------------------------------------------------------
	// Fresh log (truncation), fresh daemon: the counter regresses →
	// re-baseline, then advances → ok again. The arc is re-armed.
	// (No os.Remove here: Windows refuses to delete a file this test still
	// holds open; startServe's os.Create truncates it in place, which is the
	// same log-rotation event the watchdog must re-baseline over.)
	serve = startServe(t, sporeBin, dir, logPath)
	serve.waitReady(t)
	deadline = time.Now().Add(20 * time.Second)
	for !aliveOK() {
		if time.Now().After(deadline) {
			out, err = watch()
			t.Fatalf("recovery watch never re-armed: err=%v out=%q", err, out)
		}
		time.Sleep(300 * time.Millisecond)
	}
}
