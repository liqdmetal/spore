package roster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tmpRoster(t *testing.T) *Roster {
	t.Helper()
	r, err := Open(filepath.Join(t.TempDir(), "roster.json"), "offgrid")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAddListRemove(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	r := tmpRoster(t)

	if _, err := r.Add("dero1alice", "aa", "alice", 12, time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("dero1bob", "bb", "bob", -1, time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	if r.Count() != 2 {
		t.Fatalf("count = %d", r.Count())
	}

	send, skipped := r.Recipients(now)
	if len(send) != 2 || len(skipped) != 0 {
		t.Fatalf("send=%d skipped=%v", len(send), skipped)
	}
	// Deterministic order matters for reproducible sends.
	if send[0].Addr != "dero1alice" || send[1].Addr != "dero1bob" {
		t.Fatalf("recipients not sorted: %s, %s", send[0].Addr, send[1].Addr)
	}

	if err := r.Remove("dero1alice"); err != nil {
		t.Fatal(err)
	}
	if r.Count() != 1 {
		t.Fatalf("after remove count = %d", r.Count())
	}
	if err := r.Remove("dero1alice"); err == nil {
		t.Fatal("removing a non-subscriber should error")
	}
}

func TestAddRequiresPinnedSig(t *testing.T) {
	r := tmpRoster(t)
	now := time.Now()
	if _, err := r.Add("dero1x", "", "", 5, time.Time{}, now); err == nil {
		t.Fatal("Add accepted an empty pinned-sig: there would be no trust anchor for sending")
	}
	if _, err := r.Add("", "aa", "", 5, time.Time{}, now); err == nil {
		t.Fatal("Add accepted an empty address")
	}
	if _, err := r.Add("dero1x", "aa", "", 0, time.Time{}, now); err == nil {
		t.Fatal("Add accepted a zero grant (ambiguous: lapsed or unlimited?)")
	}
}

// TestRepinRefused: silently accepting a new key for an existing subscriber
// would let an attacker who can write to the roster redirect a subscription.
func TestRepinRefused(t *testing.T) {
	r := tmpRoster(t)
	now := time.Now()
	if _, err := r.Add("dero1alice", "key-one", "alice", 5, time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	_, err := r.Add("dero1alice", "key-TWO", "alice", 5, time.Time{}, now)
	if err == nil {
		t.Fatal("re-pinning an existing subscriber to a different key was allowed silently")
	}
	if !strings.Contains(err.Error(), "DIFFERENT key") {
		t.Fatalf("error should name the re-pin problem: %v", err)
	}
}

// TestRenewalAddsRatherThanReplaces: a renewal must never shorten a
// subscription.
func TestRenewalAddsRatherThanReplaces(t *testing.T) {
	r := tmpRoster(t)
	now := time.Now()
	if _, err := r.Add("dero1a", "aa", "", 10, time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	s, err := r.Add("dero1a", "aa", "", 5, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.IssuesLeft != 15 {
		t.Fatalf("renewal gave %d issues, want 10+5=15", s.IssuesLeft)
	}
	// Unlimited must not be downgraded by a finite renewal.
	if _, err := r.Add("dero1b", "bb", "", -1, time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	s2, err := r.Add("dero1b", "bb", "", 3, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if s2.IssuesLeft != -1 {
		t.Fatalf("unlimited subscriber downgraded to %d", s2.IssuesLeft)
	}
}

func TestLapsedAndExpiredSubscribersSkipped(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	r := tmpRoster(t)

	// Paid up.
	if _, err := r.Add("dero1ok", "aa", "", 2, time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	// Time-expired.
	if _, err := r.Add("dero1old", "bb", "", 5, now.Add(-24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	// Count-exhausted: grant 1 then consume it.
	sub, err := r.Add("dero1spent", "cc", "", 1, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CommitIssue(1, []*Sub{sub}); err != nil {
		t.Fatal(err)
	}

	send, skipped := r.Recipients(now)
	if len(send) != 1 || send[0].Addr != "dero1ok" {
		t.Fatalf("send = %v", send)
	}
	if !strings.Contains(skipped["dero1old"], "expired") {
		t.Fatalf("expired reason = %q", skipped["dero1old"])
	}
	if !strings.Contains(skipped["dero1spent"], "lapsed") {
		t.Fatalf("lapsed reason = %q", skipped["dero1spent"])
	}
}

// TestCommitIssueConsumesExactlyOnePerSubscriber and advances the sequence.
func TestCommitIssueConsumesAndAdvances(t *testing.T) {
	now := time.Now()
	r := tmpRoster(t)
	a, err := r.Add("dero1a", "aa", "", 3, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Add("dero1b", "bb", "", -1, time.Time{}, now) // unlimited
	if err != nil {
		t.Fatal(err)
	}
	if r.NextSeq != 1 {
		t.Fatalf("fresh roster NextSeq = %d, want 1", r.NextSeq)
	}
	if err := r.CommitIssue(1, []*Sub{a, b}); err != nil {
		t.Fatal(err)
	}
	if r.NextSeq != 2 {
		t.Fatalf("NextSeq = %d, want 2", r.NextSeq)
	}
	ga, _ := r.Get("dero1a")
	if ga.IssuesLeft != 2 {
		t.Fatalf("finite subscriber has %d issues left, want 2", ga.IssuesLeft)
	}
	gb, _ := r.Get("dero1b")
	if gb.IssuesLeft != -1 {
		t.Fatalf("unlimited subscriber was decremented to %d", gb.IssuesLeft)
	}
}

// TestRosterSurvivesRestart: the list is the only copy, so persistence is the
// product.
func TestRosterSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	now := time.Now()

	r1, err := Open(path, "chan")
	if err != nil {
		t.Fatal(err)
	}
	s, err := r1.Add("dero1a", "aa", "alice", 7, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r1.CommitIssue(4, []*Sub{s}); err != nil {
		t.Fatal(err)
	}

	r2, err := Open(path, "chan")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Count() != 1 {
		t.Fatalf("reloaded count = %d", r2.Count())
	}
	if r2.NextSeq != 5 {
		t.Fatalf("reloaded NextSeq = %d, want 5", r2.NextSeq)
	}
	got, ok := r2.Get("dero1a")
	if !ok || got.IssuesLeft != 6 || got.Nick != "alice" {
		t.Fatalf("reloaded sub = %+v", got)
	}
}

func TestOpenRejectsWrongChannelAndCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	if _, err := Open(path, "alpha"); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("a", "aa", "", 1, time.Time{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Opening the same file as a different channel must fail loudly.
	if _, err := Open(path, "beta"); err == nil {
		t.Fatal("roster opened under the wrong channel name")
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad, "x"); err == nil {
		t.Fatal("corrupt roster opened silently — the subscriber list would appear empty")
	}
}

// ---- subscriber-side channel state ----

func TestChannelTracksLastSeq(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ch.json")
	c, err := OpenChannel(p, "offgrid", "pubkey-hex")
	if err != nil {
		t.Fatal(err)
	}
	if c.Seq() != 0 {
		t.Fatalf("fresh channel seq = %d", c.Seq())
	}
	if err := c.Accept(1); err != nil {
		t.Fatal(err)
	}
	if err := c.Accept(2); err != nil {
		t.Fatal(err)
	}
	// Replay / reorder must be refused.
	if err := c.Accept(2); err == nil {
		t.Fatal("accepted the same issue twice")
	}
	if err := c.Accept(1); err == nil {
		t.Fatal("accepted an older issue")
	}

	// And it must survive a restart, or replay protection resets to zero.
	c2, err := OpenChannel(p, "offgrid", "pubkey-hex")
	if err != nil {
		t.Fatal(err)
	}
	if c2.Seq() != 2 {
		t.Fatalf("reloaded seq = %d, want 2", c2.Seq())
	}
	if err := c2.Accept(2); err == nil {
		t.Fatal("replay accepted after restart — LastSeq was not persisted")
	}
}

// TestChannelRefusesPublisherKeyChange: a publisher key that changes without
// warning is indistinguishable from impersonation.
func TestChannelRefusesPublisherKeyChange(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ch.json")
	if _, err := OpenChannel(p, "ch", "key-ORIGINAL"); err != nil {
		t.Fatal(err)
	}
	_, err := OpenChannel(p, "ch", "key-ATTACKER")
	if err == nil {
		t.Fatal("channel accepted a different publisher key silently")
	}
	if !strings.Contains(err.Error(), "impersonation") {
		t.Fatalf("error should warn about impersonation: %v", err)
	}
	// Re-opening with the same key, or with none, is fine.
	if _, err := OpenChannel(p, "ch", "key-ORIGINAL"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenChannel(p, "ch", ""); err != nil {
		t.Fatal(err)
	}
}

func TestOpenChannelNeedsAKeyForNewChannels(t *testing.T) {
	p := filepath.Join(t.TempDir(), "new.json")
	if _, err := OpenChannel(p, "ch", ""); err == nil {
		t.Fatal("a brand-new channel was created with no pinned publisher key")
	}
}

func TestParseUntil(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	z, err := ParseUntil("", now)
	if err != nil || !z.IsZero() {
		t.Fatalf("empty: %v %v", z, err)
	}
	d, err := ParseUntil("720h", now)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Equal(now.Add(720 * time.Hour)) {
		t.Fatalf("duration parse = %v", d)
	}
	abs, err := ParseUntil("2027-06-01T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	if abs.Year() != 2027 {
		t.Fatalf("absolute parse = %v", abs)
	}
	if _, err := ParseUntil("next tuesday", now); err == nil {
		t.Fatal("garbage expiry accepted")
	}
}

// TestRosterStoresNoPaymentData is the privacy claim, checked on disk.
func TestRosterStoresNoPaymentData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	r, err := Open(path, "ch")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 14, 33, 7, 0, time.UTC)
	if _, err := r.Add("dero1alice", "aa", "alice", 12, time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	disk := string(raw)
	for _, forbidden := range []string{"amount", "invoice", "txid", "paid", "price", "14:33"} {
		if strings.Contains(strings.ToLower(disk), forbidden) {
			t.Fatalf("roster stores %q — entitlement should be a counter, not a payment record:\n%s", forbidden, disk)
		}
	}
	if !strings.Contains(disk, "2026-09-09") {
		t.Fatalf("expected a coarse day bucket, got:\n%s", disk)
	}
}
