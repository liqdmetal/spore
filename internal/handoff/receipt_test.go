package handoff

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchetwire"
)

func TestReceiveQueuesReceiptAtomicallyAndIdempotently(t *testing.T) {
	e, _, provider := fixtures(t)
	receiver, path := openTestStore(t)
	session := "0011223344556677"
	must(t, receiver.Receive(e, e.Message.Recipient(), session, provider, time.Now()))
	must(t, receiver.Receive(e, e.Message.Recipient(), session, provider, time.Now()))
	r, err := receiver.Get(e.Message.Terms.ID, time.Now())
	must(t, err)
	if len(r.Events) != 1 || len(r.Receipts) != 1 || len(r.Outbox) != 1 || r.Outbox[0].EventHash != r.Receipts[0].Hash() {
		t.Fatal("receive/receipt not atomic or idempotent")
	}
	if !r.Receipts[0].Matches(e, session) || r.Receipts[0].Receipt.Status != "persisted" {
		t.Fatal("wrong receipt bindings")
	}
	must(t, os.WriteFile(path+".lock", []byte("blocked"), 0600))
	other := e
	other.Message.Terms.ID, err = NewID()
	must(t, err)
	_, buyer, _ := fixtures(t)
	other, err = Sign(other.Message, buyer)
	must(t, err)
	if receiver.Receive(other, other.Message.Recipient(), session, provider, time.Now()) == nil {
		t.Fatal("failed persistence issued receipt")
	}
	must(t, os.Remove(path+".lock"))
	rows, err := receiver.List(time.Now())
	must(t, err)
	if len(rows) != 1 {
		t.Fatal("failed transaction partially applied")
	}
}

func TestSignedApplicationReceiptBothDirectionsAndDecisions(t *testing.T) {
	for _, kind := range []string{"accept", "reject"} {
		t.Run(kind, func(t *testing.T) {
			brief, a, b := fixtures(t)
			deliver := next(t, brief, "deliver", b)
			decision := next(t, deliver, kind, a)
			buyer, _ := openTestStore(t)
			provider, _ := openTestStore(t)
			session := "0011223344556677"
			for _, e := range []Envelope{brief, deliver, decision} {
				sending, receiving, key := buyer, provider, b
				if e.Message.Kind == "deliver" {
					sending, receiving, key = provider, buyer, a
				}
				must(t, sending.Apply(e, e.Message.Sender(), session, true, time.Now()))
				must(t, receiving.Receive(e, e.Message.Recipient(), session, key, time.Now()))
				receipt, err := SignReceipt(e, session, key)
				must(t, err)
				must(t, sending.ReceiveReceipt(receipt, e.Message.Sender(), session, time.Now()))
				must(t, sending.ReceiveReceipt(receipt, e.Message.Sender(), session, time.Now()))
				r, err := sending.Get(e.Message.Terms.ID, time.Now())
				must(t, err)
				found := false
				for _, d := range r.Outbox {
					if d.EventHash == e.Hash() {
						found = d.ApplicationReceived
					}
				}
				if !found || r.Status() != e.Message.Kind {
					t.Fatal("receipt did not confirm persistence or altered human state")
				}
			}
			for _, s := range []*Store{buyer, provider} {
				r, err := s.Get(brief.Message.Terms.ID, time.Now())
				must(t, err)
				if len(r.Events) != 3 || len(r.Receipts) != 3 || len(r.Outbox) != 3 {
					t.Fatalf("unexpected event/receipt counts: %d/%d/%d", len(r.Events), len(r.Receipts), len(r.Outbox))
				}
			}
		})
	}
}

func TestReceiptRejectsForgeryWrongEventSessionTermsAndExpiry(t *testing.T) {
	e, a, b := fixtures(t)
	session := "0011223344556677"
	receipt, err := SignReceipt(e, session, b)
	must(t, err)
	if _, err := SignReceipt(e, session, a); err == nil {
		t.Fatal("sender self-receipted")
	}
	cases := map[string]func() SignedReceipt{
		"signature":                     func() SignedReceipt { r := receipt; r.Signature = strings.Repeat("0", 128); return r },
		"signature case":                func() SignedReceipt { r := receipt; r.Signature = strings.ToUpper(r.Signature); return r },
		"event hash":                    func() SignedReceipt { r := receipt; r.Receipt.EventHash = Commitment([]byte("other")); return r },
		"status upgrade":                func() SignedReceipt { r := receipt; r.Receipt.Status = "accepted"; return r },
		"wrong session valid signature": func() SignedReceipt { r, err := SignReceipt(e, "8899aabbccddeeff", b); must(t, err); return r },
		"wrong event valid signature": func() SignedReceipt {
			changed := e
			changed.Message.EventID, err = NewID()
			must(t, err)
			changed, err = Sign(changed.Message, a)
			must(t, err)
			r, err := SignReceipt(changed, session, b)
			must(t, err)
			return r
		},
		"wrong terms valid signature": func() SignedReceipt {
			changed := e
			changed.Message.Terms.Registration.Objective.ObjectiveID = "other"
			changed, err = Sign(changed.Message, a)
			must(t, err)
			r, err := SignReceipt(changed, session, b)
			must(t, err)
			return r
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := openTestStore(t)
			must(t, s.Apply(e, e.Message.Sender(), session, true, time.Now()))
			if s.ReceiveReceipt(change(), e.Message.Sender(), session, time.Now()) == nil {
				t.Fatal("accepted invalid receipt")
			}
			r, err := s.Get(e.Message.Terms.ID, time.Now())
			must(t, err)
			if len(r.Receipts) != 0 || r.Outbox[0].ApplicationReceived {
				t.Fatal("invalid receipt changed state")
			}
		})
	}
	s, _ := openTestStore(t)
	must(t, s.Apply(e, e.Message.Sender(), session, true, time.Now()))
	if s.ReceiveReceipt(receipt, e.Message.Sender(), session, time.Unix(e.Message.Terms.ExpiresAt, 0)) == nil {
		t.Fatal("expired receipt accepted")
	}
	unknown, _ := openTestStore(t)
	if unknown.ReceiveReceipt(receipt, e.Message.Sender(), session, time.Now()) == nil {
		t.Fatal("unknown event acknowledged")
	}
}

func TestReceiptStatusSeparatesPostedPersistedAndHumanReview(t *testing.T) {
	e, _, b := fixtures(t)
	s, _ := openTestStore(t)
	must(t, s.Apply(e, e.Message.Sender(), "0011223344556677", true, time.Now()))
	r, err := s.Get(e.Message.Terms.ID, time.Now())
	must(t, err)
	if !strings.Contains(NextAction(r), "flush") || !strings.Contains(r.DeliveryStatus(r.Outbox[0]), "queued") {
		t.Fatal("missing queued action")
	}
	r.Outbox[0].Sent = true
	if !strings.Contains(NextAction(r), "awaiting signed") || strings.Contains(r.DeliveryStatus(r.Outbox[0]), "peer-persisted") {
		t.Fatal("post implied persistence")
	}
	r.Outbox[0].ApplicationReceived = true
	if r.DeliveryStatus(r.Outbox[0]) != "peer-persisted" || !strings.Contains(NextAction(r), "provider deliverable") {
		t.Fatal("persistence implied result/acceptance")
	}
	receipt, err := SignReceipt(e, r.Session, b)
	must(t, err)
	r.Receipts = []SignedReceipt{receipt}
	r.Outbox = []Delivery{{EventHash: receipt.Hash(), Sent: true}}
	if !strings.Contains(r.DeliveryStatus(r.Outbox[0]), "no acknowledgement required") {
		t.Fatal("receipt loop suggested")
	}
}

func TestReceiptStrictDecodeAndNoAcknowledgementLoop(t *testing.T) {
	e, _, b := fixtures(t)
	receipt, err := SignReceipt(e, "0011223344556677", b)
	must(t, err)
	raw, err := EncodeReceipt(receipt)
	must(t, err)
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"status":"persisted"`), []byte(`"status":"persisted","status":"persisted"`), 1), append(append([]byte{}, raw...), []byte(`{}`)...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"extra":true`), 1)} {
		if _, err := DecodeReceipt(bad); err == nil {
			t.Fatal("ambiguous receipt accepted")
		}
	}
	if !IsReceipt(raw) || IsEnvelope(raw) {
		t.Fatal("receipt routed as work event")
	}
}

func TestReceiptDeliveryRetryUsesExactPointerAndCannotSelfConfirm(t *testing.T) {
	e, a, b := fixtures(t)
	buyer, provider, sid := endpoints(t, a, b)
	session := hex.EncodeToString(sid[:])
	s, path := openTestStore(t)
	must(t, s.Receive(e, e.Message.Recipient(), session, b, time.Now()))
	var first []byte
	if err := s.Flush(context.Background(), provider, e.Message.Recipient(), func(Peer, string) error { return nil }, func(_ context.Context, to string, p []byte) error {
		first = append([]byte{}, p...)
		return errors.New("offline")
	}); err == nil {
		t.Fatal("receipt delivery failure hidden")
	}
	s, err := Open(path, bytes.Repeat([]byte{9}, 32))
	must(t, err)
	sender, _ := openTestStore(t)
	must(t, sender.Apply(e, e.Message.Sender(), session, true, time.Now()))
	must(t, s.Flush(context.Background(), provider, e.Message.Recipient(), func(Peer, string) error { return nil }, func(_ context.Context, to string, p []byte) error {
		if to != e.Message.Sender().Address || !bytes.Equal(first, p) {
			t.Fatal("receipt target/pointer changed")
		}
		ptr, err := ratchetwire.ParsePointerPayload(p)
		must(t, err)
		plain, err := buyer.ReceiveNext(ptr.Pointer(), time.Now())
		must(t, err)
		receipt, err := DecodeReceipt(plain)
		must(t, err)
		return sender.ReceiveReceipt(receipt, e.Message.Sender(), session, time.Now())
	}))
	r, err := sender.Get(e.Message.Terms.ID, time.Now())
	must(t, err)
	if !r.Outbox[0].ApplicationReceived || len(r.Outbox) != 1 || len(r.Events) != 1 {
		t.Fatal("receipt loop or false work transition")
	}
	must(t, sender.Flush(context.Background(), buyer, e.Message.Sender(), func(Peer, string) error { t.Fatal("confirmed event need not repost"); return nil }, func(context.Context, string, []byte) error { t.Fatal("posted confirmed event"); return nil }))
}
