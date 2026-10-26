package jobreceipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func baseRecord() *Record {
	return &Record{
		Protocol: Protocol,
		Version:  Version,
		Kind:     KindAttested,
		Service:  Service{Category: "plumbing.emergency", Summary: "replace valve"},
		Parties: Parties{
			ProviderPub: strings.Repeat("ab", 32),
			ClientPub:   strings.Repeat("cd", 32),
		},
		Work: Work{StartedAt: "2026-10-24T15:00:00Z", FinishedAt: "2026-10-24T16:00:00Z"},
		Settlement: []Settlement{{
			Rail: "dero", Network: "dero-mainnet", Asset: "dero",
			AmountAtomic: "2500000000000",
			TxID:         strings.Repeat("ef", 32),
			SettledAt:    "2026-10-24T16:04:00Z",
		}},
	}
}

// Canonical must sort keys regardless of struct declaration order, because two
// implementations printing the same record have to produce identical bytes.
func TestCanonicalSortsKeysAndIsStable(t *testing.T) {
	rec := baseRecord()
	body, err := rec.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	lines := strings.Split(string(body), "\n")
	if !strings.HasPrefix(lines[1], `  "kind":`) {
		t.Fatalf("first key is not the alphabetically first field:\n%s", body)
	}
	if !bytes.HasSuffix(body, []byte("}\n")) || bytes.ContainsRune(body, '\r') {
		t.Fatalf("canonical form must end with one newline and carry no CR:\n%q", body[len(body)-4:])
	}

	second, err := rec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, second) {
		t.Fatal("two encodes of one record differ")
	}
	if ID(body) != ID(second) {
		t.Fatal("receipt id is not deterministic")
	}

	var generic map[string]any
	if err := json.Unmarshal(body, &generic); err != nil {
		t.Fatal(err)
	}
	back, err := Canonical(generic)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, body) {
		t.Fatalf("canonical() is not idempotent through a generic decode:\n%s", back)
	}
}

func TestParseRejectsNonCanonicalAndUnknownFields(t *testing.T) {
	body, err := baseRecord().Encode()
	if err != nil {
		t.Fatal(err)
	}

	// Same record, minified: same fields, different bytes. A v1 reader rejects it
	// because the signatures cover bytes, not meaning.
	var generic any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	minified, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(minified); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("minified record accepted, err = %v", err)
	}

	// An extra field is signed content this reader does not understand, so it
	// must not be ignored.
	withExtra := bytes.Replace(body, []byte(`  "version": 1,`),
		[]byte("  \"version\": 1,\n  \"notes\": \"hello\","), 1)
	if bytes.Equal(withExtra, body) {
		t.Fatal("test replacement did not apply")
	}
	if _, err := Parse(withExtra); err == nil || !strings.Contains(err.Error(), "notes") {
		t.Fatalf("unknown field accepted, err = %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Record)
		wantSub string
	}{
		{"float amount", func(r *Record) { r.Settlement[0].AmountAtomic = "0.25" }, "amount_atomic"},
		{"signed amount", func(r *Record) { r.Settlement[0].AmountAtomic = "-1" }, "amount_atomic"},
		{"uppercase pub", func(r *Record) { r.Parties.ProviderPub = strings.Repeat("AB", 32) }, "provider_pub"},
		{"client equals provider", func(r *Record) { r.Parties.ClientPub = r.Parties.ProviderPub }, "must differ"},
		{"no settlement", func(r *Record) { r.Settlement = nil }, "settlement"},
		{"fractional stamp", func(r *Record) { r.Work.StartedAt = "2026-10-24T15:00:00.500Z" }, "started_at"},
		{"offset stamp", func(r *Record) { r.Work.StartedAt = "2026-10-24T15:00:00+02:00" }, "started_at"},
		{"finish before start", func(r *Record) { r.Work.FinishedAt = "2026-10-24T14:00:00Z" }, "precedes"},
		{"rating without acceptance", func(r *Record) {
			r.ClientVerdict = &ClientVerdict{Accepted: false, Rating: 4}
		}, "rating"},
		{"rating out of range", func(r *Record) {
			r.ClientVerdict = &ClientVerdict{Accepted: true, Rating: 9}
		}, "1..5"},
		{"bad deliverable digest", func(r *Record) {
			r.Deliverables = []Deliverable{{Label: "before", Digest: "sha256:xyz", Bytes: 1}}
		}, "digest"},
		{"provider-only with client key", func(r *Record) { r.Coverage = CoverageProviderOnly }, "must not name a client key"},
		{"provider-only with verdict", func(r *Record) {
			r.Coverage = CoverageProviderOnly
			r.Parties.ClientPub = ""
			r.ClientVerdict = &ClientVerdict{Accepted: true}
		}, "client verdict"},
		{"unknown coverage", func(r *Record) { r.Coverage = "partial" }, "coverage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := baseRecord()
			tc.mutate(rec)
			err := rec.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestProviderOnlyRecordIsValidAndRolelessForClient(t *testing.T) {
	rec := baseRecord()
	rec.Coverage = CoverageProviderOnly
	rec.Parties.ClientPub = ""
	if err := rec.Validate(); err != nil {
		t.Fatalf("provider-only record rejected: %v", err)
	}
	body, err := rec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("client_pub")) || bytes.Contains(body, []byte("client_verdict")) {
		t.Fatalf("provider-only record leaks client fields:\n%s", body)
	}
	parsed, err := Parse(body)
	if err != nil {
		t.Fatalf("parse provider-only: %v", err)
	}
	if _, err := parsed.RoleOf(rec.Parties.ProviderPub); err != nil {
		t.Fatalf("provider key should hold the provider role: %v", err)
	}
	if _, err := parsed.PubFor(RoleClient); err == nil {
		t.Fatal("a provider-only record must not name a client signing key")
	}
	if role, err := parsed.RoleOf(strings.Repeat("cd", 32)); err == nil {
		t.Fatalf("a key that is not a party was given the %s role", role)
	}
}

func TestSortSettlementsIsTotalOrdering(t *testing.T) {
	lines := []Settlement{
		{SettledAt: "2026-10-24T16:00:03Z", TxID: strings.Repeat("bb", 32)},
		{SettledAt: "2026-10-24T16:00:01Z", TxID: strings.Repeat("cc", 32)},
		{SettledAt: "2026-10-24T16:00:03Z", TxID: strings.Repeat("aa", 32)},
	}
	SortSettlements(lines)
	if lines[0].TxID != strings.Repeat("cc", 32) || lines[1].TxID != strings.Repeat("aa", 32) || lines[2].TxID != strings.Repeat("bb", 32) {
		t.Fatalf("unexpected order: %+v", lines)
	}
}

func TestIDIsSHA256OfBytes(t *testing.T) {
	body, err := baseRecord().Encode()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if got, want := ID(body), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("ID = %s, want %s", got, want)
	}
}
