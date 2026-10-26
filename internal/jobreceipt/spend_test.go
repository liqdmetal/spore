package jobreceipt

import (
	"bytes"
	"strings"
	"testing"
)

func spendRecord() *SpendRecord {
	return &SpendRecord{
		Protocol:  SpendProtocol,
		Version:   Version,
		Kind:      KindSpend,
		ClientPub: strings.Repeat("cd", 32),
		Service:   Service{Category: "plumbing.emergency", Summary: "replace valve"},
		Settlement: []Settlement{{
			Rail: "dero", Network: "dero-mainnet", Asset: "dero",
			AmountAtomic: "2500000000000",
			TxID:         strings.Repeat("ef", 32),
			SettledAt:    "2026-10-24T16:04:00Z",
		}},
		Evidence: EvidenceChain,
	}
}

func TestSpendRecordIsProviderBlind(t *testing.T) {
	rec := spendRecord()
	providerPub := strings.Repeat("ab", 32)
	salt := bytes.Repeat([]byte{0x11}, 32)
	value, err := CommitmentFor(providerPub, salt)
	if err != nil {
		t.Fatal(err)
	}
	rec.ProviderCommitment = &ProviderCommitment{Scheme: CommitmentScheme, Value: value}

	body, err := rec.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if bytes.Contains(body, []byte(providerPub)) {
		t.Fatalf("spend receipt leaks the provider's key:\n%s", body)
	}
	if bytes.Contains(body, []byte("client_verdict")) || bytes.Contains(body, []byte("parties")) {
		t.Fatalf("spend receipt carries attested-receipt fields:\n%s", body)
	}

	// The commitment opens only with the salt that made it.
	ok, err := OpensCommitment(providerPub, salt, value)
	if err != nil || !ok {
		t.Fatalf("the kept salt does not open its own commitment: ok=%v err=%v", ok, err)
	}
	ok, err = OpensCommitment(providerPub, bytes.Repeat([]byte{0x22}, 32), value)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a different salt opened the commitment")
	}
	ok, err = OpensCommitment(strings.Repeat("99", 32), salt, value)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a different provider opened the commitment")
	}

	if _, err := ParseSpend(body); err != nil {
		t.Fatalf("parse own output: %v", err)
	}
}

func TestCommitmentIsSaltedNotGuessable(t *testing.T) {
	pub := strings.Repeat("ab", 32)
	a, err := CommitmentFor(pub, bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CommitmentFor(pub, bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two salts produced the same commitment; the salt is not doing anything")
	}
	if _, err := CommitmentFor("nope", bytes.Repeat([]byte{0x01}, 32)); err == nil {
		t.Fatal("commitment accepted a malformed provider key")
	}
	if _, err := CommitmentFor(pub, []byte{0x01}); err == nil {
		t.Fatal("commitment accepted a short salt")
	}
}

func TestSpendEvidenceIsDerivedNotClaimed(t *testing.T) {
	if got := DeriveEvidence(spendRecord().Settlement); got != EvidenceChain {
		t.Fatalf("a line with a txid derived %q", got)
	}
	noTx := spendRecord().Settlement
	noTx[0].TxID = ""
	if got := DeriveEvidence(noTx); got != EvidenceSelf {
		t.Fatalf("a line without a txid derived %q", got)
	}

	rec := spendRecord()
	rec.Settlement[0].TxID = ""
	rec.Evidence = EvidenceChain // the lie
	if err := rec.Validate(); err == nil || !strings.Contains(err.Error(), "contradicts") {
		t.Fatalf("a record claiming chain backing without a txid was accepted, err=%v", err)
	}

	rec.Evidence = EvidenceSelf
	if err := rec.Validate(); err != nil {
		t.Fatalf("self-declared row rejected: %v", err)
	}
	body, err := rec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(`"txid"`)) {
		t.Fatalf("a self-declared row must omit the txid entirely:\n%s", body)
	}
}

func TestSpendValidateRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*SpendRecord)
		wantSub string
	}{
		{"float amount", func(r *SpendRecord) { r.Settlement[0].AmountAtomic = "12.5" }, "amount_atomic"},
		{"bad txid", func(r *SpendRecord) { r.Settlement[0].TxID = "deadbeef" }, "txid"},
		{"missing settled_at", func(r *SpendRecord) { r.Settlement[0].SettledAt = "" }, "settled_at"},
		{"no settlement", func(r *SpendRecord) { r.Settlement = nil }, "settlement"},
		{"period reversed", func(r *SpendRecord) {
			r.Period = &Period{From: "2026-10-31T00:00:00Z", To: "2026-10-01T00:00:00Z"}
		}, "precedes"},
		{"bad client key", func(r *SpendRecord) { r.ClientPub = strings.Repeat("CD", 32) }, "client_pub"},
		{"wrong kind", func(r *SpendRecord) { r.Kind = KindAttested }, "kind"},
		{"wrong protocol", func(r *SpendRecord) { r.Protocol = Protocol }, "protocol"},
		{"unknown commitment scheme", func(r *SpendRecord) {
			r.ProviderCommitment = &ProviderCommitment{Scheme: "other", Value: "sha256:" + strings.Repeat("aa", 32)}
		}, "scheme"},
		{"malformed commitment value", func(r *SpendRecord) {
			r.ProviderCommitment = &ProviderCommitment{Scheme: CommitmentScheme, Value: "sha256:xyz"}
		}, "provider_commitment.value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := spendRecord()
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

func TestProtocolOfDispatches(t *testing.T) {
	attested, err := baseRecord().Encode()
	if err != nil {
		t.Fatal(err)
	}
	spend, err := spendRecord().Encode()
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"attested": attested, "spend": spend} {
		got, err := ProtocolOf(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := map[string]string{"attested": Protocol, "spend": SpendProtocol}[name]
		if got != want {
			t.Fatalf("%s: protocol = %q, want %q", name, got, want)
		}
	}
	if _, err := ProtocolOf([]byte("not json")); err == nil {
		t.Fatal("ProtocolOf accepted a non-JSON body")
	}
}
