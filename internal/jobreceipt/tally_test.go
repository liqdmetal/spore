package jobreceipt

import (
	"strings"
	"testing"
)

func tallyRecord(provider, client, finished string, rating int) *Record {
	rec := baseRecord()
	rec.Parties.ProviderPub = provider
	rec.Parties.ClientPub = client
	rec.Work.FinishedAt = finished
	if rating > 0 {
		rec.ClientVerdict = &ClientVerdict{Accepted: true, Rating: rating}
	} else {
		rec.ClientVerdict = nil
	}
	return rec
}

const (
	provA = "1111111111111111111111111111111111111111111111111111111111111111"
	provB = "2222222222222222222222222222222222222222222222222222222222222222"
	cliA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cliB  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// §8 rule 1: a client counts once however many jobs they book.
func TestTallyCountsOnePerPair(t *testing.T) {
	entries := []TallyEntry{
		{Record: tallyRecord(provA, cliA, "2026-10-01T10:00:00Z", 5), ReceiptID: "r1"},
		{Record: tallyRecord(provA, cliA, "2026-10-05T10:00:00Z", 3), ReceiptID: "r2"},
		{Record: tallyRecord(provA, cliB, "2026-10-07T10:00:00Z", 4), ReceiptID: "r3"},
	}
	got := TallyEntries(entries)
	if len(got) != 1 {
		t.Fatalf("one provider produced %d tallies", len(got))
	}
	if got[0].Records != 3 || got[0].Pairs != 2 {
		t.Fatalf("records/pairs = %d/%d, want 3/2", got[0].Records, got[0].Pairs)
	}
	// The pair's most recent record (rating 3) is the one that counts, so the
	// mean is (3+4)/2 — a client cannot lift a provider by booking again.
	if got[0].Rated != 2 || got[0].Mean != 3.5 {
		t.Fatalf("rated/mean = %d/%v, want 2/3.5", got[0].Rated, got[0].Mean)
	}
	// The window covers every counted receipt, including the superseded first job.
	if got[0].Oldest != "2026-10-01T10:00:00Z" || got[0].Newest != "2026-10-07T10:00:00Z" {
		t.Fatalf("window = %s..%s", got[0].Oldest, got[0].Newest)
	}
	if got[0].OldestReceipt != "r1" || got[0].NewestReceipt != "r3" {
		t.Fatalf("window receipts = %s..%s", got[0].OldestReceipt, got[0].NewestReceipt)
	}
}

func TestTallyMeanIgnoresUnratedPairs(t *testing.T) {
	entries := []TallyEntry{
		{Record: tallyRecord(provA, cliA, "2026-10-01T10:00:00Z", 5), ReceiptID: "r1"},
		{Record: tallyRecord(provA, cliB, "2026-10-02T10:00:00Z", 0), ReceiptID: "r2"},
	}
	got := TallyEntries(entries)[0]
	if got.Pairs != 2 {
		t.Fatalf("pairs = %d, want 2 (an unrated client still counts as a pair)", got.Pairs)
	}
	if got.Rated != 1 || got.Mean != 5 {
		t.Fatalf("rated/mean = %d/%v, want 1/5", got.Rated, got.Mean)
	}
}

func TestTallySkipsProviderOnlyAndGroupsProviders(t *testing.T) {
	solo := tallyRecord(provA, "", "2026-10-01T10:00:00Z", 0)
	solo.Parties.ClientPub = ""
	solo.Coverage = CoverageProviderOnly
	entries := []TallyEntry{
		{Record: solo, ReceiptID: "solo"},
		{Record: tallyRecord(provB, cliA, "2026-10-02T10:00:00Z", 4), ReceiptID: "b1"},
		{Record: tallyRecord(provA, cliA, "2026-10-03T10:00:00Z", 2), ReceiptID: "a1"},
		{Record: nil},
	}
	got := TallyEntries(entries)
	if len(got) != 2 {
		t.Fatalf("got %d tallies, want 2 providers", len(got))
	}
	if got[0].ProviderPub != provA || got[1].ProviderPub != provB {
		t.Fatalf("providers not sorted: %s, %s", got[0].ProviderPub, got[1].ProviderPub)
	}
	if got[0].Pairs != 1 || got[0].Records != 1 {
		t.Fatalf("provider A counted a provider-only record: %+v", got[0])
	}
	if got[0].Mean != 2 || got[1].Mean != 4 {
		t.Fatalf("means = %v, %v", got[0].Mean, got[1].Mean)
	}
}

// Nothing in the aggregation may weight, decay, or round: the same entries in a
// different order must produce the same numbers.
func TestTallyIsOrderIndependent(t *testing.T) {
	base := []TallyEntry{
		{Record: tallyRecord(provA, cliA, "2026-10-01T10:00:00Z", 5), ReceiptID: "r1"},
		{Record: tallyRecord(provA, cliA, "2026-10-09T10:00:00Z", 2), ReceiptID: "r2"},
		{Record: tallyRecord(provA, cliB, "2026-10-03T10:00:00Z", 4), ReceiptID: "r3"},
	}
	first := TallyEntries(base)[0]
	shuffled := []TallyEntry{base[2], base[0], base[1]}
	second := TallyEntries(shuffled)[0]
	if first != second {
		t.Fatalf("order changed the tally:\n%+v\n%+v", first, second)
	}
	if strings.TrimSpace(first.ProviderPub) == "" {
		t.Fatal("provider key lost")
	}
}
