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
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// approvalLockEntry is one live signing lock in the queue dir.
type approvalLockEntry struct {
	Request    string  `json:"request"`
	HolderHost string  `json:"holder_host,omitempty"`
	HolderPID  string  `json:"holder_pid"`
	AgeSeconds float64 `json:"age_seconds"`
	// Orphaned: the request file the lock guards no longer exists — the
	// holder crashed (or the request was cleaned up) and the lock is residue
	// until the TTL stale-break.
	Orphaned bool `json:"orphaned,omitempty"`
}

// approvalLockMetrics covers the per-request signing locks currently visible
// in the queue: how many stations are mid-sign right now, who holds what,
// and the oldest age — an age approaching approvalLockTTL means the holder
// crashed and the next scan breaks the lock.
type approvalLockMetrics struct {
	Live      int                 `json:"live"`
	OldestAge float64             `json:"oldest_age_seconds"`
	Entries   []approvalLockEntry `json:"entries,omitempty"`
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
	Locks         *approvalLockMetrics   `json:"locks"`
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
//	spore msg approval-metrics [-dir QUEUE] [-out-dir OUTBOX] [-state-dir D] -envelope
//	spore msg approval-metrics [-dir QUEUE] [-out-dir OUTBOX] [-state-dir D] -prometheus
//	spore msg approval-metrics -dir Q1 -dir Q2 ... -prometheus   (one exposition, per-queue labels)
func msgApprovalMetrics(args []string) {
	fs := flag.NewFlagSet("msg approval-metrics", flag.ExitOnError)
	var dirs approvalDirList
	fs.Var(&dirs, "dir", "approval request queue directory to summarize (defaults to -state-dir or the current dir; repeatable with -prometheus for one labeled multi-queue exposition)")
	outDir := fs.String("out-dir", "", "signed-approval outbox directory to include (enables the approval/post latency summaries)")
	stateDir := fs.String("state-dir", "", "encrypted endpoint session state directory whose approval-spent ledger marks consumed nonces")
	asJSON := fs.Bool("json", false, "emit metrics in machine-readable JSON format")
	envelope := fs.Bool("envelope", false, "emit one compact JSON heartbeat line (the -watch -metrics-json format: at, station, metrics) instead of a summary")
	prom := fs.Bool("prometheus", false, "emit metrics in the Prometheus text exposition format (scraper or node_exporter textfile collector)")
	_ = fs.Parse(args)
	if err := validateApprovalMetricsOutputFlags(*asJSON, *envelope, *prom); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	if err := validateApprovalMetricsDirs([]string(dirs), *outDir, *stateDir, *prom); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	if len(dirs) > 1 {
		// Multi-queue scrape: one exposition, every series labeled with
		// its queue, so several stations share one textfile.
		check(renderPrometheusMetricsMulti([]string(dirs)))
		return
	}
	queueDir := ""
	if len(dirs) == 1 {
		queueDir = dirs[0]
	}
	if *stateDir == "" {
		_ = loadConfigForFlags(fs)
		if f := fs.Lookup("state-dir"); f != nil && f.Value.String() != "" {
			*stateDir = f.Value.String()
		}
	}
	if queueDir == "" {
		if *stateDir != "" {
			queueDir = *stateDir
		} else {
			queueDir = "."
		}
	}
	m, err := buildApprovalMetrics(queueDir, *outDir, *stateDir, time.Now())
	check(err)
	if *envelope {
		// One compact line, shape-identical to a -watch -metrics-json
		// heartbeat, so a cron scrape appends to the same JSONL file the
		// live station tees into and one parser serves both.
		enc := json.NewEncoder(os.Stdout)
		check(enc.Encode(newWatchMetricsEnvelope(time.Now(), m)))
		return
	}
	if *prom {
		renderPrometheusMetrics(m)
		return
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(m))
		return
	}
	renderApprovalMetrics(m)
}

// validateApprovalMetricsOutputFlags refuses contradictory output-format
// selections: -json (indented raw metrics), -envelope (one compact heartbeat
// line), and -prometheus (text exposition) are alternative renderings of the
// same summary, not layers that compose.
func validateApprovalMetricsOutputFlags(asJSON, envelope, prometheus bool) error {
	var chosen []string
	if asJSON {
		chosen = append(chosen, "-json")
	}
	if envelope {
		chosen = append(chosen, "-envelope")
	}
	if prometheus {
		chosen = append(chosen, "-prometheus")
	}
	if len(chosen) > 1 {
		return fmt.Errorf("approval-metrics: %s are alternative output formats; choose one (-envelope wraps the metrics in the watch heartbeat shape; -prometheus renders the text exposition format)", strings.Join(chosen, ", "))
	}
	return nil
}

// approvalDirList collects repeated -dir values in invocation order.
type approvalDirList []string

func (d *approvalDirList) String() string { return strings.Join(*d, ",") }
func (d *approvalDirList) Set(v string) error {
	*d = append(*d, v)
	return nil
}

// validateApprovalMetricsDirs pins the multi-queue rules: repeating -dir is
// a -prometheus scraping feature; the other renderings stay single-queue,
// and so do the outbox and ledger sections — their latencies belong to one
// pipeline and would be misattributed across queues.
func validateApprovalMetricsDirs(dirs []string, outDir, stateDir string, prometheus bool) error {
	if len(dirs) <= 1 {
		return nil
	}
	if !prometheus {
		return errors.New("approval-metrics: multiple -dir values are only supported with -prometheus (one labeled queue per -dir)")
	}
	if outDir != "" {
		return errors.New("approval-metrics: -out-dir cannot be combined with multiple -dir values: outbox latencies belong to one pipeline; run one invocation per pipeline")
	}
	if stateDir != "" {
		return errors.New("approval-metrics: -state-dir cannot be combined with multiple -dir values: the approval-spent ledger belongs to one pipeline; run one invocation per pipeline")
	}
	return nil
}

// buildApprovalLockMetrics reports the per-request signing locks currently
// visible in the queue dir: live count, oldest age, and per-holder entries
// (os.ReadDir order, so the output is deterministic). Only files ending in
// ".lock" count — stale-break markers end in the breaker pid/nanos and are
// residue, never live locks.
func buildApprovalLockMetrics(queueDir string, now time.Time) *approvalLockMetrics {
	m := &approvalLockMetrics{Entries: []approvalLockEntry{}}
	entries, err := os.ReadDir(queueDir)
	if err != nil {
		// The queue walk already surfaced the real error; report no locks.
		return m
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".lock") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		host, pid := parseLockOwner(filepath.Join(queueDir, entry.Name()))
		age := now.Sub(info.ModTime()).Seconds()
		if age < 0 {
			age = 0 // clock skew: never report a future lock as negative age
		}
		m.Live++
		if age > m.OldestAge {
			m.OldestAge = age
		}
		request := strings.TrimSuffix(entry.Name(), ".lock")
		orphaned := false
		if _, serr := os.Stat(filepath.Join(queueDir, request)); serr != nil {
			orphaned = true // the guarded request file is gone: residue
		}
		m.Entries = append(m.Entries, approvalLockEntry{
			Request:    request,
			HolderHost: host,
			HolderPID:  pid,
			AgeSeconds: age,
			Orphaned:   orphaned,
		})
	}
	return m
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

	// Locks section: live signing locks are active pipeline state, not
	// hygiene noise, so they are reported separately from ignored files.
	m.Locks = buildApprovalLockMetrics(queueDir, now)

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
		if strings.HasSuffix(entry.Name(), ".lock") {
			continue // active signing plumbing, reported in the locks section
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
	if l := m.Locks; l != nil {
		fmt.Printf("  locks: %d live\n", l.Live)
		for _, e := range l.Entries {
			holder := e.HolderPID
			if e.HolderHost != "" {
				holder = e.HolderHost + "/" + e.HolderPID
			}
			line := fmt.Sprintf("    %s: held by %s for %ds", e.Request, holder, int(e.AgeSeconds+0.5))
			if e.Orphaned {
				line += " (request gone)"
			}
			fmt.Println(line)
		}
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

// promLabelEscaper escapes a label value per the exposition format:
// backslash, double quote, newline.
var promLabelEscaper = strings.NewReplacer(`\`, `\`, "\n", `\n`, `"`, `\"`)

func promEscapeLabel(s string) string { return promLabelEscaper.Replace(s) }

func promFormatValue(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

// promSeries renders one series line: name, optional labels, value.
func promSeries(name, label, value string) string {
	if label == "" {
		return name + " " + value
	}
	return name + "{" + label + "} " + value
}

// joinPromLabels combines the per-queue label with a series-specific label.
func joinPromLabels(queueLabel, extra string) string {
	if queueLabel == "" {
		return extra
	}
	return queueLabel + "," + extra
}

// promFamilySet accumulates exposition output grouped by metric family so
// # HELP/# TYPE is emitted exactly once per family even when several queues
// contribute series to the same family (multi-queue mode). Families print
// in first-seen order; empty families never print at all.
type promFamilySet struct {
	order []string
	help  map[string]string
	lines map[string][]string
}

func (p *promFamilySet) ensure(name, help string) {
	if p.lines == nil {
		p.help = map[string]string{}
		p.lines = map[string][]string{}
	}
	if _, ok := p.lines[name]; !ok {
		p.order = append(p.order, name)
		p.help[name] = help
		p.lines[name] = nil
	}
}

func (p *promFamilySet) scalar(name, help string, value float64, label string) {
	p.ensure(name, help)
	p.lines[name] = append(p.lines[name], promSeries(name, label, promFormatValue(value)))
}

func (p *promFamilySet) counts(name, help, labelName string, counts map[string]int, queueLabel string) {
	if len(counts) == 0 {
		return
	}
	p.ensure(name, help)
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.lines[name] = append(p.lines[name], promSeries(name, joinPromLabels(queueLabel, labelName+`="`+promEscapeLabel(k)+`"`), strconv.Itoa(counts[k])))
	}
}

func (p *promFamilySet) latency(name, help string, l *approvalMetricsLatency, queueLabel string) {
	if l == nil {
		return
	}
	p.ensure(name, help)
	for _, stat := range []struct {
		key   string
		value float64
	}{{"min", l.Min}, {"p50", l.P50}, {"p95", l.P95}, {"max", l.Max}, {"mean", l.Mean}} {
		p.lines[name] = append(p.lines[name], promSeries(name, joinPromLabels(queueLabel, `stat="`+stat.key+`"`), promFormatValue(stat.value)))
	}
}

func (p *promFamilySet) printTo(w io.Writer) {
	for _, name := range p.order {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, p.help[name], name)
		for _, line := range p.lines[name] {
			fmt.Fprintln(w, line)
		}
	}
}

// emitPrometheusQueue adds one pipeline's summary to the set. queueLabel is
// "" for the single-queue rendering (byte-compatible with v0.8.5) or
// `queue="<dir>"` in multi-queue mode.
func emitPrometheusQueue(p *promFamilySet, m *approvalMetrics, queueLabel string) {
	p.scalar("spore_approval_queue_requests", "Requests currently visible in the approval queue.", float64(m.Requests), queueLabel)
	p.scalar("spore_approval_ignored_files", "Non-envelope files in the queue directory (queue hygiene noise).", float64(m.IgnoredFiles), queueLabel)
	p.counts("spore_approval_requests_by_status", "Requests in the queue by classification status.", "status", m.Status, queueLabel)
	p.counts("spore_approval_requests_by_skip_reason", "Requests by the reason they are not signable right now.", "reason", m.SkipReasons, queueLabel)
	p.counts("spore_approval_requests_by_chain", "Requests in the queue by chain.", "chain", m.Chains, queueLabel)
	p.counts("spore_approval_requests_by_action", "Requests in the queue by requested action.", "action", m.Actions, queueLabel)
	if m.StateDir != "" {
		p.scalar("spore_approval_spent_nonces", "Nonces burned in the approval-spent replay ledger.", float64(m.SpentNonces), queueLabel)
	}
	p.scalar("spore_approval_locks_live", "Signing locks currently live in the queue.", float64(m.Locks.Live), queueLabel)
	p.scalar("spore_approval_locks_oldest_age_seconds", "Age of the oldest live signing lock; at approvalLockTTL (60s) the next scan stale-breaks it.", m.Locks.OldestAge, queueLabel)
	orphaned := 0
	for _, e := range m.Locks.Entries {
		if e.Orphaned {
			orphaned++
		}
	}
	p.scalar("spore_approval_locks_orphaned", "Live locks whose guarded request file is gone (holder crashed; residue until the stale-break).", float64(orphaned), queueLabel)
	if m.OldestPending != nil {
		name := "spore_approval_oldest_pending_age_seconds"
		p.ensure(name, "Age of the longest-waiting pending request; at the 15-minute approval TTL it can never be signed.")
		p.lines[name] = append(p.lines[name], promSeries(name, joinPromLabels(queueLabel, `path="`+promEscapeLabel(m.OldestPending.Path)+`"`), promFormatValue(m.OldestPending.AgeSeconds)))
	}
	if o := m.Outbox; o != nil {
		p.scalar("spore_approval_outbox_signed_outputs", "Signed approvals in the outbox.", float64(o.SignedOutputs), queueLabel)
		p.scalar("spore_approval_outbox_signed_unspent", "Signed approvals still waiting on the requester's send.", float64(o.UnspentSigned), queueLabel)
		p.scalar("spore_approval_outbox_matched_requests", "Signed approvals matched back to a queue request for latency math.", float64(o.MatchedRequests), queueLabel)
		p.latency("spore_approval_sign_latency_seconds", "Request created -> approval signed, nearest-rank percentiles over matched samples.", o.SignLatency, queueLabel)
		p.latency("spore_approval_post_latency_seconds", "Approval signed -> nonce burned, nearest-rank percentiles over matched samples.", o.PostLatency, queueLabel)
	}
}

// renderPrometheusMetrics prints one pipeline's summary in the Prometheus
// text exposition format, for a scraper or the node_exporter textfile
// collector (`spore msg approval-metrics ... -prometheus > textfile.prom`
// from cron). Every series is a gauge over the same artifacts the human
// summary reads; map families are sorted by label value so the output is
// deterministic and diffable across scrapes. Unlabeled: byte-compatible
// with v0.8.5. Multi-queue mode (repeated -dir) adds a per-queue label.
func renderPrometheusMetrics(m *approvalMetrics) {
	var p promFamilySet
	emitPrometheusQueue(&p, m, "")
	p.printTo(os.Stdout)
}

// renderPrometheusMetricsMulti renders several queues into one exposition,
// every series labeled queue="<dir>" so several stations can share one
// textfile while staying attributable. -out-dir and -state-dir are refused
// in this mode: outbox and ledger latencies belong to one pipeline.
func renderPrometheusMetricsMulti(dirs []string) error {
	var p promFamilySet
	for _, dir := range dirs {
		if dir == "" {
			dir = "."
		}
		m, err := buildApprovalMetrics(dir, "", "", time.Now())
		if err != nil {
			return err
		}
		emitPrometheusQueue(&p, m, `queue="`+promEscapeLabel(dir)+`"`)
	}
	p.printTo(os.Stdout)
	return nil
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
