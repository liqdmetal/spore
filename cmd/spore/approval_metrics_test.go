package main

// Tests for `spore msg approval-metrics`: volumes, skip-reason breakdown, and
// approval/post latency percentiles derived from the queue, outbox, and
// approval-spent artifacts with deterministic timestamps.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/derosim"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
)

// metricsTestEnvelope builds a requester-signed envelope with explicit
// created/expires times: newCapabilityEnvelope hardcodes the 15-minute TTL,
// and the metrics scenarios need older requests that were still valid when
// they were signed.
func metricsTestEnvelope(t *testing.T, requesterPrivate ed25519.PrivateKey, approverPublic ed25519.PublicKey, tag string, createdAt, expiresAt time.Time) CapabilityEnvelope {
	t.Helper()
	var sessionID [8]byte
	copy(sessionID[:], []byte(tag))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(expiresAt.Add(30 * time.Minute).Unix())}.MarshalBinary()
	envelope, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, 1_000, pointer, sessionID, requesterPrivate, approverPublic, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	envelope.ExpiresAt = expiresAt.Unix()
	signRequesterForTest(t, &envelope)
	return envelope
}

func TestApprovalMetricsVolumesSkipReasonsAndLatency(t *testing.T) {
	base := time.Now()
	queueDir := filepath.Join(t.TempDir(), "queue")
	outDir := filepath.Join(t.TempDir(), "outbox")
	stateDir := filepath.Join(t.TempDir(), "state")
	for _, d := range []string{queueDir, outDir, stateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	requesterPrivate, err := secure.SigKeypairOf(bytes_Repeat(0x31))
	if err != nil {
		t.Fatal(err)
	}
	approverPublic, approverPrivate := approvalFixtureKeys(t)

	// pairA: request created 10m ago, signed 8m ago (2m before expiry),
	// posted (spent) 6m ago. Sign latency 120s, post latency 120s.
	pairA := metricsTestEnvelope(t, requesterPrivate, approverPublic, "metrA", base.Add(-10*time.Minute), base.Add(5*time.Minute))
	requestAPath := filepath.Join(queueDir, "a.json")
	writeApprovalTestFile(t, requestAPath, pairA)
	signedAPath := filepath.Join(outDir, "a.signed.json")
	if err := approveCapabilityFile(requestAPath, approverKeyFile(t), signedAPath, true); err != nil {
		t.Fatal(err)
	}
	setTestMtime(t, signedAPath, base.Add(-8*time.Minute))
	if err := consumeCapabilityNonce(stateDir, pairA); err != nil {
		t.Fatal(err)
	}
	setTestMtime(t, filepath.Join(stateDir, "approval-spent", pairA.Nonce+".spent"), base.Add(-6*time.Minute))

	// pairB: request created 14m ago, signed 6m ago (5m before expiry),
	// posted 3m ago. Sign latency 480s, post latency 180s.
	pairB := metricsTestEnvelope(t, requesterPrivate, approverPublic, "metrB", base.Add(-14*time.Minute), base.Add(1*time.Minute))
	requestBPath := filepath.Join(queueDir, "b.json")
	writeApprovalTestFile(t, requestBPath, pairB)
	signedBPath := filepath.Join(outDir, "b.signed.json")
	if err := approveCapabilityFile(requestBPath, approverKeyFile(t), signedBPath, true); err != nil {
		t.Fatal(err)
	}
	setTestMtime(t, signedBPath, base.Add(-6*time.Minute))
	if err := consumeCapabilityNonce(stateDir, pairB); err != nil {
		t.Fatal(err)
	}
	setTestMtime(t, filepath.Join(stateDir, "approval-spent", pairB.Nonce+".spent"), base.Add(-3*time.Minute))

	// One pending request created 2m ago (still inside its TTL: the oldest
	// pending).
	pending := metricsTestEnvelope(t, requesterPrivate, approverPublic, "metrP", base.Add(-2*time.Minute), base.Add(13*time.Minute))
	writeApprovalTestFile(t, filepath.Join(queueDir, "p.json"), pending)

	// One expired request: expired 110m ago (15m TTL long gone).
	expired := metricsTestEnvelope(t, requesterPrivate, approverPublic, "metrE", base.Add(-125*time.Minute), base.Add(-110*time.Minute))
	writeApprovalTestFile(t, filepath.Join(queueDir, "e.json"), expired)

	// One request signed in place but never moved to the outbox (queue
	// hygiene): still SIGNED, skip reason "already signed".
	inPlace := metricsTestEnvelope(t, requesterPrivate, approverPublic, "metrS", base.Add(-12*time.Minute), base.Add(3*time.Minute))
	transcript, err := capabilityTranscript(inPlace)
	if err != nil {
		t.Fatal(err)
	}
	inPlace.Signature = hex.EncodeToString(ed25519.Sign(approverPrivate, transcript))
	writeApprovalTestFile(t, filepath.Join(queueDir, "s.json"), inPlace)

	// Queue hygiene noise the classifier must count but never classify.
	if err := os.WriteFile(filepath.Join(queueDir, "notes.txt"), []byte("operator notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(queueDir, "junk.json"), []byte(`{"not":"an envelope"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Live signing lock on the oldest pending request: held by station
	// web1/4242 for ~30s. The stale-break marker next to it is residue from
	// a past break and must never count as a live lock (it does count as
	// ignored-file hygiene noise).
	lockPath := filepath.Join(queueDir, "p.json.lock")
	if err := os.WriteFile(lockPath, []byte("web1 4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setTestMtime(t, lockPath, base.Add(-30*time.Second))
	if err := os.WriteFile(filepath.Join(queueDir, "p.json.lock.broken-777-42"), []byte("999 4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := buildApprovalMetrics(queueDir, outDir, stateDir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if m.Requests != 5 || m.IgnoredFiles != 3 {
		t.Fatalf("volumes: requests=%d ignored=%d, want 5/3 (the broken lock marker is hygiene noise)", m.Requests, m.IgnoredFiles)
	}
	wantStatus := map[string]int{"SPENT": 2, "PENDING": 1, "EXPIRED": 1, "SIGNED": 1}
	for status, want := range wantStatus {
		if m.Status[status] != want {
			t.Fatalf("status %s = %d, want %d (all: %v)", status, m.Status[status], want, m.Status)
		}
	}
	wantReasons := map[string]int{
		"nonce already consumed; replay refused": 2,
		"approval envelope: expired":             1,
		"already signed":                         1,
	}
	for reason, want := range wantReasons {
		if m.SkipReasons[reason] != want {
			t.Fatalf("skip reason %q = %d, want %d (all: %v)", reason, m.SkipReasons[reason], want, m.SkipReasons)
		}
	}
	if m.Chains["dero"] != 5 {
		t.Fatalf("chains = %v, want dero=5", m.Chains)
	}
	if m.Actions[capabilityDeroTransfer] != 5 {
		t.Fatalf("actions = %v, want %s=5", m.Actions, capabilityDeroTransfer)
	}
	if m.SpentNonces != 2 {
		t.Fatalf("spent nonces = %d, want 2", m.SpentNonces)
	}
	if m.Locks == nil || m.Locks.Live != 1 || len(m.Locks.Entries) != 1 {
		t.Fatalf("locks = %+v, want exactly 1 live (broken markers are residue, not locks)", m.Locks)
	}
	lk := m.Locks.Entries[0]
	if !strings.HasSuffix(lk.Request, "p.json") || lk.HolderHost != "web1" || lk.HolderPID != "4242" || lk.Orphaned {
		t.Fatalf("lock entry = %+v, want p.json held by web1/4242", lk)
	}
	if lk.AgeSeconds < 25 || lk.AgeSeconds > 35 {
		t.Fatalf("lock age = %v, want ~30s", lk.AgeSeconds)
	}
	if m.Locks.OldestAge < 25 || m.Locks.OldestAge > 35 {
		t.Fatalf("oldest lock age = %v, want ~30s", m.Locks.OldestAge)
	}
	if m.OldestPending == nil || !strings.HasSuffix(m.OldestPending.Path, "p.json") {
		t.Fatalf("oldest pending = %+v, want p.json", m.OldestPending)
	}
	if m.OldestPending.AgeSeconds < 115 || m.OldestPending.AgeSeconds > 135 {
		t.Fatalf("oldest pending age = %v, want ~120s", m.OldestPending.AgeSeconds)
	}

	// Outbox: both pairs matched; sign latencies {600s, 5400s}, post {300s, 120s}.
	o := m.Outbox
	if o == nil || o.SignedOutputs != 2 || o.UnspentSigned != 0 || o.MatchedRequests != 2 {
		t.Fatalf("outbox metrics = %+v", o)
	}
	sl := o.SignLatency
	if sl == nil || sl.Matched != 2 || sl.Min != 120 || sl.P50 != 120 || sl.P95 != 480 || sl.Max != 480 || sl.Mean != 300 {
		t.Fatalf("sign latency = %+v, want nearest-rank over [120,480]", sl)
	}
	pl := o.PostLatency
	if pl == nil || pl.Matched != 2 || pl.Min != 120 || pl.P50 != 120 || pl.P95 != 180 || pl.Max != 180 || pl.Mean != 150 {
		t.Fatalf("post latency = %+v, want nearest-rank over [120,180]", pl)
	}

	// JSON surface: same numbers through the CLI flag path.
	out := captureApprovalTestOutput(t, func() {
		msgApprovalMetrics([]string{"-dir", queueDir, "-out-dir", outDir, "-state-dir", stateDir, "-json"})
	})
	var jm approvalMetrics
	if err := json.Unmarshal([]byte(out), &jm); err != nil {
		t.Fatalf("unmarshal metrics json: %v; raw:\n%s", err, out)
	}
	if jm.Requests != 5 || jm.Status["SPENT"] != 2 || jm.Outbox == nil || jm.Outbox.SignLatency == nil || jm.Outbox.SignLatency.P95 != 480 {
		t.Fatalf("json metrics mismatch: %+v", jm)
	}
	if jm.Locks == nil || jm.Locks.Live != 1 || len(jm.Locks.Entries) != 1 || jm.Locks.Entries[0].HolderPID != "4242" {
		t.Fatalf("json locks mismatch: %+v", jm.Locks)
	}

	// Text surface: deterministic ordering (skip reasons by count desc) and
	// duration formatting.
	text := captureApprovalTestOutput(t, func() {
		msgApprovalMetrics([]string{"-dir", queueDir, "-out-dir", outDir, "-state-dir", stateDir})
	})
	for _, want := range []string{
		"approval metrics (queue ",
		"queue: 5 request(s), 3 ignored file(s)",
		"status: EXPIRED=1 PENDING=1 SIGNED=1 SPENT=2",
		"2 x nonce already consumed; replay refused",
		"1 x approval envelope: expired",
		"oldest pending: ",
		"ledger: 2 spent nonce(s)",
		"outbox: 2 signed output(s), 0 signed-but-unspent",
		"approval latency (request -> signed), 2 matched: min 2m0s  p50 2m0s  p95 8m0s  max 8m0s  mean 5m0s",
		"post latency (signed -> spent), 2 matched: min 2m0s  p50 2m0s  p95 3m0s  max 3m0s  mean 2m30s",
		"locks: 1 live",
		"p.json: held by web1/4242 for ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text output missing %q, got:\n%s", want, text)
		}
	}
	if idx2 := strings.Index(text, "2 x nonce"); idx2 >= 0 {
		if idx1 := strings.Index(text, "1 x approval envelope"); idx1 >= 0 && idx1 < idx2 {
			t.Errorf("skip reasons must be ordered by count desc, got:\n%s", text)
		}
	}

	// Without -out-dir: no outbox section, no latencies.
	bare, err := buildApprovalMetrics(queueDir, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if bare.Outbox != nil || bare.SpentNonces != 0 {
		t.Fatalf("bare metrics must omit outbox and ledger, got: %+v", bare)
	}

	// Missing queue dir is an error (a typo'd -dir must not silently report zeros).
	if _, err := buildApprovalMetrics(filepath.Join(queueDir, "missing"), outDir, stateDir, time.Now()); err == nil {
		t.Fatal("missing queue dir must error")
	}
}

func approverKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approver.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(bytes_Repeat(0x52))), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func bytes_Repeat(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func setTestMtime(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

// TestApprovalMetricsMarksOrphanedLocks pins the ghost-lock annotation: a
// lock whose guarded request file is gone is flagged orphaned in both the
// JSON entry and the text render — residue a TTL stale-break will clear.
// TestApprovalMetricsEnvelopeOneShot pins `msg approval-metrics -envelope`:
// exactly one compact stdout line in the watch heartbeat shape (at, station,
// metrics) describing the same artifacts the summary renders.
func TestApprovalMetricsEnvelopeOneShot(t *testing.T) {
	queueDir, _ := lockTestRequest(t, t.TempDir(), "oneshotenv", time.Now())
	queueDir = filepath.Dir(queueDir)
	stateDir := filepath.Join(t.TempDir(), "state")
	out := captureApprovalTestOutput(t, func() {
		msgApprovalMetrics([]string{"-dir", queueDir, "-state-dir", stateDir, "-envelope"})
	})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Fatalf("envelope mode must be exactly one stdout line, got %d:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], `{"at":`) {
		t.Fatalf("envelope line must start with the at field, got: %s", lines[0])
	}
	var heartbeat watchMetricsEnvelope
	if err := json.Unmarshal([]byte(lines[0]), &heartbeat); err != nil {
		t.Fatalf("envelope line must parse: %v\nraw: %s", err, lines[0])
	}
	if _, err := time.Parse(time.RFC3339, heartbeat.At); err != nil {
		t.Fatalf("envelope at must be RFC3339: %v (%q)", err, heartbeat.At)
	}
	if heartbeat.Station.Host != approvalLockHostname || heartbeat.Station.PID != os.Getpid() {
		t.Fatalf("envelope station must identify this process (host %q, pid %d), got %+v",
			approvalLockHostname, os.Getpid(), heartbeat.Station)
	}
	m := heartbeat.Metrics
	if m == nil || m.QueueDir != queueDir || m.Requests != 1 || m.Status["PENDING"] != 1 {
		t.Fatalf("envelope metrics do not describe the queue: %+v", m)
	}
}

// TestValidateApprovalMetricsOutputFlags pins the output-format rule: -json,
// -envelope, and -prometheus are alternative renderings, never layers.
func TestValidateApprovalMetricsOutputFlags(t *testing.T) {
	for _, tc := range []struct {
		name       string
		asJSON     bool
		envelope   bool
		prometheus bool
	}{
		{"summary", false, false, false},
		{"json only", true, false, false},
		{"envelope only", false, true, false},
		{"prometheus only", false, false, true},
	} {
		if err := validateApprovalMetricsOutputFlags(tc.asJSON, tc.envelope, tc.prometheus); err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
	}
	for _, tc := range []struct {
		name       string
		asJSON     bool
		envelope   bool
		prometheus bool
		want       string
	}{
		{"json+envelope", true, true, false, "-json, -envelope"},
		{"json+prometheus", true, false, true, "-json, -prometheus"},
		{"envelope+prometheus", false, true, true, "-envelope, -prometheus"},
		{"all three", true, true, true, "-json, -envelope, -prometheus"},
	} {
		err := validateApprovalMetricsOutputFlags(tc.asJSON, tc.envelope, tc.prometheus)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error naming %q, got: %v", tc.name, tc.want, err)
		}
	}
}

// TestApprovalMetricsPrometheusExposition pins `msg approval-metrics
// -prometheus`: the text exposition format with deterministic, sorted series
// over the same artifacts the human summary reads — including the orphaned
// lock count and the oldest-pending age the station health gate keys on.
func TestApprovalMetricsPrometheusExposition(t *testing.T) {
	queueDir, _ := lockTestRequest(t, t.TempDir(), "promone", time.Now())
	queueDir = filepath.Dir(queueDir)
	if err := os.WriteFile(filepath.Join(queueDir, "ghost.lock"), []byte("ghost 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	// Lock and pending ages are wall-clock values that legitimately tick
	// between scrapes; determinism means the same families, labels, and
	// ordering, so compare with the trailing series values stripped.
	norm := func(s string) string {
		lines := strings.Split(s, "\n")
		for i, l := range lines {
			if !strings.HasPrefix(l, "#") {
				if idx := strings.LastIndex(l, " "); idx > 0 {
					lines[i] = l[:idx]
				}
			}
		}
		return strings.Join(lines, "\n")
	}
	var first string
	for run := 0; run < 2; run++ {
		out := captureApprovalTestOutput(t, func() {
			msgApprovalMetrics([]string{"-dir", queueDir, "-state-dir", stateDir, "-prometheus"})
		})
		if run == 0 {
			first = out
			continue
		}
		if norm(out) != norm(first) {
			t.Fatalf("prometheus output must be deterministic across scrapes (modulo wall-clock ages):\nfirst:\n%s\nsecond:\n%s", first, out)
		}
	}
	for _, want := range []string{
		"# TYPE spore_approval_queue_requests gauge",
		"spore_approval_queue_requests 1",
		`spore_approval_requests_by_status{status="PENDING"} 1`,
		"spore_approval_spent_nonces 0",
		"spore_approval_locks_live 1",
		"spore_approval_locks_orphaned 1",
		`spore_approval_oldest_pending_age_seconds{path="`,
	} {
		if !strings.Contains(first, want) {
			t.Errorf("prometheus exposition missing %q, got:\n%s", want, first)
		}
	}
	for _, unwanted := range []string{
		"spore_approval_outbox", // no -out-dir: the outbox family must be absent
		"spore_approval_sign_latency",
	} {
		if strings.Contains(first, unwanted) {
			t.Errorf("prometheus exposition must not contain %q without -out-dir, got:\n%s", unwanted, first)
		}
	}
	// Series within a family must be sorted by label value (determinism).
	statusBlock := first[strings.Index(first, "# HELP spore_approval_requests_by_status"):]
	statusBlock = statusBlock[:strings.Index(statusBlock, "# HELP")]
	lines := strings.Split(strings.TrimSpace(statusBlock), "\n")
	var series []string
	for _, l := range lines {
		if strings.HasPrefix(l, "spore_approval_requests_by_status{") {
			series = append(series, l)
		}
	}
	for i := 1; i < len(series); i++ {
		if series[i-1] > series[i] {
			t.Errorf("status family series not sorted: %v", series)
			break
		}
	}
}

func TestApprovalMetricsMarksOrphanedLocks(t *testing.T) {
	queueDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(queueDir, "ghost.json.lock"), []byte("web1 4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := buildApprovalMetrics(queueDir, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if m.Locks == nil || m.Locks.Live != 1 || len(m.Locks.Entries) != 1 {
		t.Fatalf("orphaned lock must still count as live, got %+v", m.Locks)
	}
	if !m.Locks.Entries[0].Orphaned || m.Locks.Entries[0].Request != "ghost.json" {
		t.Fatalf("lock entry = %+v, want ghost.json marked orphaned", m.Locks.Entries[0])
	}
	out := captureApprovalTestOutput(t, func() {
		renderApprovalMetrics(m)
	})
	if !strings.Contains(out, "ghost.json: held by web1/4242 for ") || !strings.Contains(out, "(request gone)") {
		t.Fatalf("orphaned lock not annotated in text output:\n%s", out)
	}
}
