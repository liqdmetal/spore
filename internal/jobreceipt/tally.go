package jobreceipt

// The §8 aggregation (docs/JOB_RECEIPT_V1.md).
//
// The rules exist to stop a sum from lying, so they are implemented here rather
// than left to whoever writes the report:
//
//   1. one count per (provider, client) pair — a tenth job for the same client
//      does not move the number,
//   2. no weighting of any kind: no decay, no recency fudge, no paid tier,
//   3. the mean score is over RATED PAIRS only, with the rated client count
//      beside it, because a mean over three clients is not a reputation,
//   4. the window (oldest and newest record) is always shown.
//
// The caller decides which receipts are admissible — dual-signed, payment-backed
// — because that is I/O and chain checking. This file does no I/O and cannot be
// talked into counting something it was not handed.

import "sort"

// TallyEntry is one admissible receipt: the caller has already verified both
// signatures and whatever payment evidence the viewer demands.
type TallyEntry struct {
	Record    *Record
	ReceiptID string
}

// Tally is one provider's reputation as far as this set of receipts supports.
type Tally struct {
	ProviderPub string
	// Records is how many admissible receipts the provider produced; Pairs is how
	// many distinct clients they came from, and is the number that counts.
	Records int
	Pairs   int
	// Rated is how many pairs carry a client verdict with a score. Mean is over
	// those pairs only.
	Rated int
	Mean  float64
	// Window is the oldest and newest counted work, by finished_at.
	Oldest        string
	Newest        string
	OldestReceipt string
	NewestReceipt string
}

// TallyEntries groups by provider, deduplicates by client, and computes the
// view. One pair contributes once: its most recent record decides the rating,
// so a client cannot improve a provider's mean by booking again.
func TallyEntries(entries []TallyEntry) []Tally {
	byProvider := map[string][]TallyEntry{}
	for _, e := range entries {
		if e.Record == nil {
			continue
		}
		// provider-only records are not reputation entries (§3).
		if e.Record.Parties.ClientPub == "" {
			continue
		}
		byProvider[e.Record.Parties.ProviderPub] = append(byProvider[e.Record.Parties.ProviderPub], e)
	}

	providers := make([]string, 0, len(byProvider))
	for p := range byProvider {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	out := make([]Tally, 0, len(providers))
	for _, provider := range providers {
		all := byProvider[provider]
		// One entry per pair: the most recent record decides that client's
		// contribution, so booking again cannot improve a mean.
		perClient := map[string]TallyEntry{}
		for _, e := range all {
			client := e.Record.Parties.ClientPub
			if prev, seen := perClient[client]; !seen || prev.Record.Work.FinishedAt < e.Record.Work.FinishedAt {
				perClient[client] = e
			}
		}

		t := Tally{ProviderPub: provider, Records: len(all), Pairs: len(perClient)}
		// The window covers every counted record, not just the pair
		// representatives: §8 asks for the oldest and newest receipt, and hiding
		// a client's first job because a later one took its pair slot would make
		// the history look shorter than it is.
		for _, e := range all {
			if t.Oldest == "" || e.Record.Work.FinishedAt < t.Oldest {
				t.Oldest = e.Record.Work.FinishedAt
				t.OldestReceipt = e.ReceiptID
			}
			if t.Newest == "" || e.Record.Work.FinishedAt > t.Newest {
				t.Newest = e.Record.Work.FinishedAt
				t.NewestReceipt = e.ReceiptID
			}
		}
		ratingSum := 0
		for _, e := range perClient {
			if v := e.Record.ClientVerdict; v != nil && v.Rating > 0 {
				t.Rated++
				ratingSum += v.Rating
			}
		}
		if t.Rated > 0 {
			t.Mean = float64(ratingSum) / float64(t.Rated)
		}
		out = append(out, t)
	}
	return out
}
