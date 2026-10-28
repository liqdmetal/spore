package jobreceipt

import (
	"bytes"
	"strings"
	"testing"
)

// xmrProofRecord settles on the one rail v1 can prove, so a tx_proof on it is
// legal in shape. What these tests are about is the binding: a proof must be
// evidence for THIS record and no other.
func xmrProofRecord() *Record {
	r := baseRecord()
	r.Settlement[0].Rail = "xmr"
	r.Settlement[0].Network = "monero-mainnet"
	r.Settlement[0].Asset = "xmr"
	r.Settlement[0].AmountAtomic = "181978330000"
	return r
}

func testProof(message string) *TxProof {
	return &TxProof{
		Scheme:    SchemeMoneroTxProofV1,
		Address:   "4AseVYawZMf7mfeYqbLvKbKfXAVDZLM3c2XC8j6j12xpDvrkhMX4CQw3hUqa3i5L2se8YZ3ztgeMA5yU2DNEsP8cHF8VNDo",
		Message:   message,
		Signature: "InProofV2synthetic-signature-material",
	}
}

// The binding cannot be the digest of a document that contains the proof —
// attaching the block would change that digest. So it is the record's identity
// with every proof stripped, and attaching one must not move the message.
func TestProofBindingIsToTheRecordWithoutItsProofs(t *testing.T) {
	rec := xmrProofRecord()
	before, err := ProofMessage(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(before, ProofPrefix) {
		t.Errorf("proof message %q does not begin with %q", before, ProofPrefix)
	}
	if !reHex64.MatchString(strings.TrimPrefix(before, ProofPrefix)) {
		t.Errorf("proof message %q does not end in a 64-hex digest", before)
	}

	rec.Settlement[0].TxProof = testProof(before)
	after, err := ProofMessage(rec)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("attaching a proof moved its own binding: %q -> %q", before, after)
	}
	if _, err := rec.Encode(); err != nil {
		t.Fatalf("a correctly bound proof must validate: %v", err)
	}
}

// A record carrying a proof still has to round-trip: the block is inside the
// signed bytes, so a reader that drops it changes the receipt id.
func TestRecordWithProofRoundTripsByteForByte(t *testing.T) {
	rec := xmrProofRecord()
	msg, err := ProofMessage(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.Settlement[0].TxProof = testProof(msg)
	body, err := rec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(body)
	if err != nil {
		t.Fatalf("parse a record with a proof: %v", err)
	}
	got := parsed.Settlement[0].TxProof
	if got == nil {
		t.Fatal("the tx_proof block did not survive the round trip")
	}
	if got.Scheme != testProof(msg).Scheme || got.Signature != testProof(msg).Signature || got.Message != msg {
		t.Errorf("proof changed across the round trip: %+v", got)
	}
	if reencoded, err := parsed.Encode(); err != nil || !bytes.Equal(reencoded, body) {
		t.Errorf("re-encoding is not stable (err=%v)", err)
	}
}

// The attack the binding exists to stop: a real proof, taken for one record,
// attached to a record that describes a different payment.
func TestProofTakenForAnotherRecordIsRejected(t *testing.T) {
	first := xmrProofRecord()
	msg, err := ProofMessage(first)
	if err != nil {
		t.Fatal(err)
	}
	second := xmrProofRecord()
	second.Settlement[0].AmountAtomic = "1" // a different payment
	second.Settlement[0].TxProof = testProof(msg)

	err = second.Validate()
	if err == nil {
		t.Fatal("a proof bound to another record must be rejected")
	}
	if !strings.Contains(err.Error(), "not this record's binding") {
		t.Errorf("want a binding failure, got: %v", err)
	}
}

// Editing an amount after the proof was taken invalidates it, and it fails at
// Parse time — before anything can count the receipt.
func TestEditingAnAmountInvalidatesTheAttachedProof(t *testing.T) {
	rec := xmrProofRecord()
	msg, err := ProofMessage(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.Settlement[0].TxProof = testProof(msg)
	body, err := rec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(body, []byte("181978330000"), []byte("181978330001"), 1)
	if bytes.Equal(tampered, body) {
		t.Fatal("the tamper did not apply")
	}
	_, err = Parse(tampered)
	if err == nil {
		t.Fatal("an edited amount must invalidate the proof it carries")
	}
	if !strings.Contains(err.Error(), "binding") {
		t.Errorf("want a binding failure, got: %v", err)
	}
}

func TestProofRejectsUnknownScheme(t *testing.T) {
	rec := xmrProofRecord()
	msg, err := ProofMessage(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.Settlement[0].TxProof = testProof(msg)
	rec.Settlement[0].TxProof.Scheme = "sha512-of-a-vibe"

	err = rec.Validate()
	if err == nil || !strings.Contains(err.Error(), "is not defined") {
		t.Errorf("want an unknown-scheme failure, got: %v", err)
	}
}

// A scheme names its chain, so it cannot be evidence on a line that settles
// somewhere else.
func TestProofSchemeMustMatchTheLinesRail(t *testing.T) {
	rec := xmrProofRecord()
	rec.Settlement[0].Rail = "dero"
	msg, err := ProofMessage(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.Settlement[0].TxProof = testProof(msg)

	err = rec.Validate()
	if err == nil {
		t.Fatal("a Monero proof on a DERO line must be rejected")
	}
	if !strings.Contains(err.Error(), `the line settles on rail "dero"`) {
		t.Errorf("want a rail mismatch, got: %v", err)
	}
}

// A spend receipt may cite no txid (§4). A proof then has nothing to be about,
// so it is refused rather than kept as decoration.
func TestProofWithoutATxidIsNotEvidence(t *testing.T) {
	err := checkSettlementLine("settlement[0]", Settlement{
		Rail: "xmr", Network: "monero-mainnet", Asset: "xmr",
		AmountAtomic: "1", SettledAt: "2026-10-24T16:04:00Z",
		TxProof: testProof("m"),
	}, false, "m")
	if err == nil {
		t.Fatal("a proof with no txid must be rejected")
	}
	if !strings.Contains(err.Error(), "no txid") {
		t.Errorf("want a missing-txid failure, got: %v", err)
	}
}

func TestProofRequiresAddressAndSignatureAndAnExactMessage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(p *TxProof)
		want   string
	}{
		{"no address", func(p *TxProof) { p.Address = "" }, "tx_proof.address is required"},
		{"no signature", func(p *TxProof) { p.Signature = "" }, "tx_proof.signature is required"},
		{"message paraphrased", func(p *TxProof) { p.Message = p.Message + " " }, "not this record's binding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := xmrProofRecord()
			msg, err := ProofMessage(rec)
			if err != nil {
				t.Fatal(err)
			}
			p := testProof(msg)
			tc.mutate(p)
			rec.Settlement[0].TxProof = p
			err = rec.Validate()
			if err == nil {
				t.Fatal("want a rejection")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want %q, got: %v", tc.want, err)
			}
		})
	}
}

// The rail→scheme pairing has exactly one source of truth, so the command layer
// can ask rather than hard-code it.
func TestSchemeRailKnowsItsOneScheme(t *testing.T) {
	rail, ok := SchemeRail(SchemeMoneroTxProofV1)
	if !ok || rail != "xmr" {
		t.Errorf("SchemeRail(%q) = %q, %v; want \"xmr\", true", SchemeMoneroTxProofV1, rail, ok)
	}
	if _, ok := SchemeRail("nope"); ok {
		t.Error("an unknown scheme must not report a rail")
	}
}
