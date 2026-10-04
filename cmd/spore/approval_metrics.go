// approval-metrics: operator summary over one approval pipeline's artifacts.
// It reads only files the workflow already produces — the request queue, the
// signed-approval outbox, and the approval-spent replay ledger — so metrics
// need no new state and can never disagree with what approve/list-approvals
// would do next.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// approvalMetricsLatency summarizes matched stage-to-stage delays in seconds
// (nearest-rank percentiles over the matched samples).
type approvalMetricsLatency struct {
	Matched int     `json:"matched"`
	Min     float64 `json:"min_seconds"`
	P50     float64 `json:"p50_seconds"`
	P95     float64 `json:"p95_seconds"`
	Max     float64 `json:"max_seconds"`
	Mean    float64 `json:"mean_seconds"`
}

// approvalOldestPending flags the request that has been waiting longest.
type approvalOldestPending struct {
	Path       string  `json:"path"`
	AgeSeconds float64 `json:"age_seconds"`
}

// approvalOutboxMetrics covers the signed-approval outbox: how many approvals
// exist, how many are still unspent (waiting on the requester's send), and
// the stage latencies measurable from the exclusive-create artifacts.
type approvalOutboxMetrics struct {
	SignedOutputs   int                     `json:"signed_outputs"`
	UnspentSigned   int                     `json:"signed_unspent"`
	MatchedRequests int                     `json:"matched_requests"`
	SignLatency     *approvalMetricsLatency `json:"approval_latency,omitempty"`
	PostLatency     *approvalMetricsLatency `json:"post_latency,omitempty"`
}

// approvalMetrics is the full operator summary.
type approvalMetrics struct {
	QueueDir      string                 `json:"queue_dir"`
	OutboxDir     string                 `json:"outbox_dir,omitempty"`
	StateDir      string                 `json:"state_dir,omitempty"`
	Requests      int                    `json:"requests"`
	IgnoredFiles  int                    `json:"ignored_files"`
	Status        map[string]int         `json:"status_counts"`
	SkipReasons   map[string]int         `json:"skip_reasons"`
	Chains        map[string]int         `json:"chains"`
	Actions       map[string]int         `json:"actions"`
	OldestPending *approvalOldestPending `json:"oldest_pending,omitempty"`
	SpentNonces   int                    `json:"spent_nonces"`
	Outbox        *approvalOutboxMetrics `json:"outbox,omitempty"`
}

// msgApprovalMetrics summarizes one approval pipeline for operators: volumes
// (requests by status, chain, action), the skip-reason breakdown of anything
// not signable right now, and — when -out-dir is given — approval latency
// (request created -> approval signed) and post latency (approval signed ->
// nonce burned) from the exclusive-create artifacts. Read-only; makes a
// metrics summary out of files the workflow already produces.
//
//	spore msg approval-metrics [-dir QUEUE] [-out-dir OUTBOX] [-state-dir D] [-json]
func msgApprovalMetrics(args []string) {
	fs := flag.NewFlagSet("msg approval-metrics", flag.ExitOnError)
	dir := fs.String("dir", "", "approval request queue directory to summarize (defaults to -state-dir or the current dir)")
	outDir := fs.String("out-dir", "", "signed-approval outbox directory to include (enables the approval/post latency summaries)")
	stateDir := fs.String("state-dir", "", "encrypted endpoint session state directory whose approval-spent ledger marks consumed nonces")
	asJSON := fs.Bool("json", false, "emit metrics in machine-readable JSON format")
	_ = fs.Parse(args)
	if *stateDir == "" {
		_ = loadConfigForFlags(fs)
		if f := fs.Lookup("state-dir"); f != nil && f.Value.String() != "" {
			*stateDir = f.Value.String()
		}
	}
	queueDir := *dir
	if queueDir == "" {
		if *stateDir != "" {
			queueDir = *stateDir
		} else {
			queueDir = "."
		}
	}
	m, err := buildApprovalMetrics(queueDir, *outDir, *stateDir, time.Now())
	check(err)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(m))
		return
	}
	renderApprovalMetrics(m)
}

// buildApprovalMetrics walks the pipeline artifacts and assembles the
// summary. queueDir must exist; a missing -out-dir or approval-spent ledger
// is reported as empty rather than fatal (fresh pipelines have neither).
func buildApprovalMetrics(queueDir, outDir, stateDir string, now time.Time) (*approvalMetrics, error) {
	m := &approvalMetrics{
		QueueDir:    queueDir,
		Status:      map[string]int{},
		SkipReasons: map[string]int{},
		Chains:      map[string]int{},
		Actions:     map[string]int{},
	}
	if outDir != "" {
		m.OutboxDir = outDir
		m.Outbox = &approvalOutboxMetrics{}
	}
	if stateDir != "" {
		m.StateDir = stateDir
	}

	// Ledger first: spent nonces gate both the queue classification and the
	// post-latency matching.
	spentAt := map[string]time.Time{}
	if stateDir != "" {
		entries, err := os.ReadDir(filepath.Join(stateDir, "approval-spent"))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("approval-metrics: scan ledger %s: %w", stateDir, err)
			}
		} else {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".spent") {
					continue
				}
				nonce := strings.TrimSuffix(entry.Name(), ".spent")
				if info, err := entry.Info(); err == nil {
					spentAt[nonce] = info.ModTime()
				} else {
					spentAt[nonce] = now
				}
			}
		}
		m.SpentNonces = len(spentAt)
	}

	// Queue walk: classify every capability envelope; everything else in the
	// dir is queue hygiene noise worth counting.
	type queueEntry struct {
		createdAt int64
	}
	requestsByKey := map[string]queueEntry{}
	entries, err := os.ReadDir(queueDir)
	if err != nil {
		return nil, fmt.Errorf("approval-metrics: scan queue %s: %w", queueDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(queueDir, entry.Name())
		e, err := decodeCapabilityFile(path)
		if err != nil || e.Protocol != capabilityProtocol {
			m.IgnoredFiles++
			continue
		}
		m.Requests++
		cls := classifyApprovalEnvelope(e, now, stateDir)
		m.Status[cls.Status]++
		if cls.SkipReason != "" {
			m.SkipReasons[cls.SkipReason]++
		}
		m.Chains[strings.ToLower(e.Chain)]++
		m.Actions[e.Action]++
		key := strings.TrimSuffix(entry.Name(), ".json")
		requestsByKey[key] = queueEntry{createdAt: e.CreatedAt}
		if cls.Status == "PENDING" {
			age := float64(now.Unix() - e.CreatedAt)
			if m.OldestPending == nil || age > m.OldestPending.AgeSeconds {
				m.OldestPending = &approvalOldestPending{Path: path, AgeSeconds: age}
			}
		}
	}

	// Outbox walk: signed outputs, their unspent count, and the stage
	// latencies matched by artifact naming and nonce.
	if m.Outbox != nil {
		outEntries, err := os.ReadDir(outDir)
		if err != nil {
			return nil, fmt.Errorf("approval-metrics: scan outbox %s: %w", outDir, err)
		}
		var signSeconds, postSeconds []float64
		for _, entry := range outEntries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".signed.json") {
				continue
			}
			path := filepath.Join(outDir, entry.Name())
			e, err := decodeCapabilityFile(path)
			if err != nil || e.Protocol != capabilityProtocol {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			signedAt := info.ModTime()
			m.Outbox.SignedOutputs++
			if _, spent := spentAt[e.Nonce]; !spent {
				m.Outbox.UnspentSigned++
			}
			// Approval latency: request CreatedAt -> approval file written.
			key := strings.TrimSuffix(entry.Name(), ".signed.json")
			if req, ok := requestsByKey[key]; ok {
				latency := float64(signedAt.Unix() - req.createdAt)
				if latency < 0 {
					latency = 0 // clock skew: clamp rather than report negative
				}
				signSeconds = append(signSeconds, latency)
			}
			// Post latency: approval file written -> nonce burned.
			if spent, ok := spentAt[e.Nonce]; ok {
				latency := spent.Sub(signedAt).Seconds()
				if latency < 0 {
					latency = 0
				}
				postSeconds = append(postSeconds, latency)
			}
		}
		m.Outbox.MatchedRequests = len(signSeconds)
		m.Outbox.SignLatency = summarizeLatency(signSeconds)
		m.Outbox.PostLatency = summarizeLatency(postSeconds)
	}
	return m, nil
}

// summarizeLatency reduces matched delays to nearest-rank percentiles.
func summarizeLatency(seconds []float64) *approvalMetricsLatency {
	if len(seconds) == 0 {
		return nil
	}
	sorted := append([]float64(nil), seconds...)
	sort.Float64s(sorted)
	pick := func(q float64) float64 {
		idx := int(math.Ceil(q*float64(len(sorted)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return sorted[idx]
	}
	sum := 0.0
	for _, v := range sorted {
		sum += v
	}
	return &approvalMetricsLatency{
		Matched: len(sorted),
		Min:     sorted[0],
		P50:     pick(0.50),
		P95:     pick(0.95),
		Max:     sorted[len(sorted)-1],
		Mean:    sum / float64(len(sorted)),
	}
}

// renderApprovalMetrics prints the human-readable summary. Counts are
// deterministic (sorted) so operators can diff runs and tests can assert.
func renderApprovalMetrics(m *approvalMetrics) {
	head := fmt.Sprintf("approval metrics (queue %s", m.QueueDir)
	if m.OutboxDir != "" {
		head += fmt.Sprintf("; outbox %s", m.OutboxDir)
	}
	if m.StateDir != "" {
		head += fmt.Sprintf("; ledger %s", m.StateDir)
	}
	fmt.Println(head + ")")
	fmt.Printf("  queue: %d request(s), %d ignored file(s)\n", m.Requests, m.IgnoredFiles)
	if m.Requests > 0 {
		fmt.Printf("  status: %s\n", formatMetricCounts(m.Status))
		fmt.Printf("  chains: %s\n", formatMetricCounts(m.Chains))
		fmt.Printf("  actions: %s\n", formatMetricCounts(m.Actions))
		if len(m.SkipReasons) > 0 {
			fmt.Println("  skip reasons (why requests are not signable now):")
			for _, line := range formatSkipReasons(m.SkipReasons) {
				fmt.Printf("    %s\n", line)
			}
		}
	}
	if m.OldestPending != nil {
		fmt.Printf("  oldest pending: %s (%s old)\n", m.OldestPending.Path, formatMetricSeconds(m.OldestPending.AgeSeconds))
	}
	if m.StateDir != "" {
		fmt.Printf("  ledger: %d spent nonce(s)\n", m.SpentNonces)
	}
	if o := m.Outbox; o != nil {
		fmt.Printf("  outbox: %d signed output(s), %d signed-but-unspent\n", o.SignedOutputs, o.UnspentSigned)
		if l := o.SignLatency; l != nil {
			fmt.Printf("  approval latency (request -> signed), %d matched: %s\n", l.Matched, formatMetricLatency(l))
		}
		if l := o.PostLatency; l != nil {
			fmt.Printf("  post latency (signed -> spent), %d matched: %s\n", l.Matched, formatMetricLatency(l))
		}
	}
}

func formatMetricCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " ")
}

// formatSkipReasons orders reasons by frequency (then alphabetically for
// ties) so the loudest problem is always the first line.
func formatSkipReasons(reasons map[string]int) []string {
	keys := make([]string, 0, len(reasons))
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if reasons[keys[i]] != reasons[keys[j]] {
			return reasons[keys[i]] > reasons[keys[j]]
		}
		return keys[i] < keys[j]
	})
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%d x %s", reasons[k], k))
	}
	return lines
}

func formatMetricLatency(l *approvalMetricsLatency) string {
	return fmt.Sprintf("min %s  p50 %s  p95 %s  max %s  mean %s",
		formatMetricSeconds(l.Min), formatMetricSeconds(l.P50), formatMetricSeconds(l.P95), formatMetricSeconds(l.Max), formatMetricSeconds(l.Mean))
}

func formatMetricSeconds(seconds float64) string {
	return time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
}
