package handoff

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/sporrelay"
	"github.com/liqdmetal/spore/internal/store"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func fixtures(t *testing.T) (Envelope, []byte, []byte) {
	t.Helper()
	a, b := bytes.Repeat([]byte{11}, 32), bytes.Repeat([]byte{22}, 32)
	ap, err := secure.SigPubOf(a)
	must(t, err)
	bp, err := secure.SigPubOf(b)
	must(t, err)
	id, err := NewID()
	must(t, err)
	eid, err := NewID()
	must(t, err)
	brief, policy := []byte("private brief\n"), []byte("buyer reviews the exact result\n")
	m := Message{Version: 1, Terms: Terms{ID: id, Registration: Registration{Version: 1, RelayURL: "http://127.0.0.1:8720", ActorID: "did:relay:" + strings.Repeat("a", 40), ObservedAt: time.Now().Add(-time.Minute).Unix(), Objective: sporrelay.WorkOrder{ObjectiveID: "objective:handoff-test", OwnerPseudonym: "actor:buyer", DescriptionCommitment: Commitment(brief), PolicyHash: Commitment(policy)}}, Buyer: Peer{"buyer", hex.EncodeToString(ap)}, Provider: Peer{"provider", hex.EncodeToString(bp)}, ExpiresAt: time.Now().Add(time.Hour).Unix()}, EventID: eid, Kind: "brief", Sequence: 1, Content: brief, Policy: policy}
	e, err := Sign(m, a)
	must(t, err)
	return e, a, b
}

func next(t *testing.T, prior Envelope, kind string, key []byte) Envelope {
	t.Helper()
	id, err := NewID()
	must(t, err)
	m := Message{Version: 1, Terms: prior.Message.Terms, EventID: id, Kind: kind, Sequence: prior.Message.Sequence + 1, Previous: prior.Hash()}
	if kind == "deliver" {
		m.Content = []byte("private deliverable\x00\xff")
		m.ResultHash = Commitment(m.Content)
	} else {
		m.ResultHash = prior.Message.ResultHash
	}
	e, err := Sign(m, key)
	must(t, err)
	return e
}

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "handoffs.enc")
	s, err := Open(p, bytes.Repeat([]byte{9}, 32))
	must(t, err)
	return s, p
}

func TestHandoffAtomicBatchRejectsPartialQueue(t *testing.T) {
	e, a, _ := fixtures(t)
	s, _ := openTestStore(t)
	other := e
	var err error
	other.Message.Terms.ID, err = NewID()
	must(t, err)
	other.Message.EventID, err = NewID()
	must(t, err)
	other, err = Sign(other.Message, a)
	must(t, err)
	if s.ApplyBatch([]Envelope{e, other}, e.Message.Sender(), []string{"0011223344556677", "bad"}, time.Now()) == nil {
		t.Fatal("invalid batch accepted")
	}
	rows, err := s.List(time.Now())
	must(t, err)
	if len(rows) != 0 {
		t.Fatal("partial batch persisted")
	}
	// Both events pass prevalidation, but the second conflicts inside the
	// transaction after the first has already been added to its working copy.
	conflict := e
	conflict.Message.EventID = other.Message.EventID
	conflict, err = Sign(conflict.Message, a)
	must(t, err)
	if s.ApplyBatch([]Envelope{e, conflict}, e.Message.Sender(), []string{"0011223344556677", "0011223344556677"}, time.Now()) == nil {
		t.Fatal("conflicting batch accepted")
	}
	rows, err = s.List(time.Now())
	must(t, err)
	if len(rows) != 0 {
		t.Fatal("transaction failure persisted the first invitation")
	}
	must(t, s.ApplyBatch([]Envelope{e, other}, e.Message.Sender(), []string{"0011223344556677", "8899aabbccddeeff"}, time.Now()))
	rows, err = s.List(time.Now())
	must(t, err)
	if len(rows) != 2 {
		t.Fatal("valid batch not atomic")
	}
}

func TestHandoffLifecycleBothDecisionsAndRestart(t *testing.T) {
	for _, decision := range []string{"accept", "reject"} {
		t.Run(decision, func(t *testing.T) {
			brief, a, b := fixtures(t)
			deliver := next(t, brief, "deliver", b)
			decide := next(t, deliver, decision, a)
			buyer, p := openTestStore(t)
			provider, _ := openTestStore(t)
			now := time.Now()
			session := "0011223344556677"
			for _, e := range []Envelope{brief, deliver, decide} {
				must(t, buyer.Apply(e, e.Message.Terms.Buyer, session, e.Message.Sender() == e.Message.Terms.Buyer, now))
				must(t, provider.Apply(e, e.Message.Terms.Provider, session, e.Message.Sender() == e.Message.Terms.Provider, now))
				must(t, buyer.Apply(e, e.Message.Terms.Buyer, session, e.Message.Sender() == e.Message.Terms.Buyer, now))
			}
			buyer, err := Open(p, bytes.Repeat([]byte{9}, 32))
			must(t, err)
			r, err := buyer.Get(brief.Message.Terms.ID, now)
			must(t, err)
			if len(r.Events) != 3 || len(r.Outbox) != 2 || r.Status() != decision {
				t.Fatalf("bad final state: %+v", r)
			}
			conflict := decide
			conflict.Message.Kind = "reject"
			if decision == "reject" {
				conflict.Message.Kind = "accept"
			}
			conflict, err = Sign(conflict.Message, a)
			must(t, err)
			if buyer.Apply(conflict, r.Local, session, true, now) == nil {
				t.Fatal("conflicting final decision accepted")
			}
		})
	}
}

func TestHandoffRejectsAdversarialTransitions(t *testing.T) {
	brief, a, b := fixtures(t)
	deliver := next(t, brief, "deliver", b)
	cases := map[string]func() Envelope{
		"wrong previous": func() Envelope {
			m := deliver.Message
			m.Previous = Commitment([]byte("wrong"))
			e, err := Sign(m, b)
			must(t, err)
			return e
		},
		"changed policy": func() Envelope {
			m := deliver.Message
			m.Terms.Registration.Objective.PolicyHash = Commitment([]byte("other"))
			e, err := Sign(m, b)
			must(t, err)
			return e
		},
		"reused event id": func() Envelope {
			m := deliver.Message
			m.EventID = brief.Message.EventID
			e, err := Sign(m, b)
			must(t, err)
			return e
		},
		"wrong signature":             func() Envelope { e := deliver; e.Signature = brief.Signature; return e },
		"signature case malleability": func() Envelope { e := deliver; e.Signature = strings.ToUpper(e.Signature); return e },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := openTestStore(t)
			must(t, s.Apply(brief, brief.Message.Terms.Buyer, "0011223344556677", true, time.Now()))
			if s.Apply(change(), brief.Message.Terms.Buyer, "0011223344556677", false, time.Now()) == nil {
				t.Fatal("accepted attack")
			}
			r, err := s.Get(brief.Message.Terms.ID, time.Now())
			must(t, err)
			if len(r.Events) != 1 {
				t.Fatal("failed apply mutated history")
			}
		})
	}
	s, _ := openTestStore(t)
	if s.Apply(deliver, brief.Message.Terms.Buyer, "0011223344556677", false, time.Now()) == nil {
		t.Fatal("out of order delivery accepted")
	}
	must(t, s.Apply(brief, brief.Message.Terms.Buyer, "0011223344556677", true, time.Now()))
	if s.Apply(deliver, brief.Message.Terms.Buyer, "8899aabbccddeeff", false, time.Now()) == nil {
		t.Fatal("changed session accepted")
	}
	if _, err := Sign(deliver.Message, a); err == nil {
		t.Fatal("buyer signed provider result")
	}
	if _, err := Sign(brief.Message, b); err == nil {
		t.Fatal("provider signed buyer brief")
	}
	must(t, s.Apply(deliver, brief.Message.Terms.Buyer, "0011223344556677", false, time.Now()))
	decision := next(t, deliver, "accept", a)
	decision.Message.ResultHash = Commitment([]byte("different result"))
	decision, err := Sign(decision.Message, a)
	must(t, err)
	if s.Apply(decision, brief.Message.Terms.Buyer, "0011223344556677", true, time.Now()) == nil {
		t.Fatal("decision accepted different result")
	}
	if s.Apply(deliver, brief.Message.Terms.Provider, "0011223344556677", false, time.Now()) == nil {
		t.Fatal("wrong local identity accepted")
	}
}

func TestHandoffStrictDecodingAndCommitments(t *testing.T) {
	e, a, _ := fixtures(t)
	raw, err := Encode(e)
	must(t, err)
	for name, bad := range map[string][]byte{
		"duplicate":  bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"case alias": bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1),
		"unknown":    bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"untrusted":true`), 1),
		"null":       bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":null`), 1),
		"trailing":   append(append([]byte{}, raw...), []byte(` {}`)...),
		"oversize":   bytes.Repeat([]byte{' '}, MaxMessage+1),
		"tamper":     bytes.Replace(raw, []byte(`objective:handoff-test`), []byte(`objective:attacker`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(bad); err == nil {
				t.Fatal("accepted ambiguous/malformed envelope")
			}
		})
	}
	m := e.Message
	m.Content = []byte("changed brief")
	if _, err := Sign(m, a); err == nil {
		t.Fatal("brief commitment not enforced")
	}
	m = e.Message
	m.Policy = []byte("changed policy")
	if _, err := Sign(m, a); err == nil {
		t.Fatal("policy commitment not enforced")
	}
	m = e.Message
	m.Terms.Provider = m.Terms.Buyer
	if _, err := Sign(m, a); err == nil {
		t.Fatal("self review allowed")
	}
	if !IsEnvelope(raw) || IsEnvelope([]byte("ordinary message")) || IsEnvelope([]byte("documentation for "+Domain)) {
		t.Fatal("bad routing")
	}
	var out any
	if DecodeJSON([]byte(strings.Repeat("[", 34)+"1"+strings.Repeat("]", 34)), &out, 100) == nil {
		t.Fatal("deep JSON accepted")
	}
}

func TestHandoffEncryptedRetentionAndFailClosedState(t *testing.T) {
	e, _, _ := fixtures(t)
	s, p := openTestStore(t)
	now := time.Now()
	must(t, s.Apply(e, e.Message.Terms.Buyer, "0011223344556677", true, now))
	raw, err := os.ReadFile(p)
	must(t, err)
	if bytes.Contains(raw, e.Message.Content) || bytes.Contains(raw, []byte(e.Message.Terms.ID)) {
		t.Fatal("store leaks plaintext")
	}
	if _, err := Open(p, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("wrong key accepted")
	}
	raw[len(raw)-1] ^= 1
	must(t, os.WriteFile(p, raw, 0600))
	if _, err := Open(p, bytes.Repeat([]byte{9}, 32)); err == nil {
		t.Fatal("tampered store accepted")
	}
	raw[len(raw)-1] ^= 1
	must(t, os.WriteFile(p, raw, 0600))
	must(t, os.WriteFile(p+".lock", []byte("another writer"), 0600))
	if _, err := s.List(now); err == nil {
		t.Fatal("ignored transaction lock")
	}
	must(t, os.Remove(p+".lock"))
	rows, err := s.List(time.Unix(e.Message.Terms.ExpiresAt, 0))
	must(t, err)
	if len(rows) != 0 {
		t.Fatal("expiry did not prune")
	}
	s, err = Open(p, bytes.Repeat([]byte{9}, 32))
	must(t, err)
	if _, err := s.Get(e.Message.Terms.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned row recovered: %v", err)
	}
}

func endpoints(t *testing.T, a, b []byte) (*ratchetwire.DurableEndpoint, *ratchetwire.DurableEndpoint, [8]byte) {
	t.Helper()
	body := store.NewMemStore()
	spk := bytes.Repeat([]byte{33}, 32)
	bundle, err := ratchet.BuildBundle(b, spk, 1, nil, 0)
	must(t, err)
	pin, err := secure.SigPubOf(b)
	must(t, err)
	newEP := func() *ratchetwire.DurableEndpoint {
		states, err := ratchetwire.NewFileStateStore(t.TempDir(), bytes.Repeat([]byte{9}, 32))
		must(t, err)
		ep, err := ratchetwire.NewDurableEndpoint(body, states, time.Now())
		must(t, err)
		return ep
	}
	alice, bob := newEP(), newEP()
	p, _, sid, err := alice.SendFirstSession(a, bundle, pin, []byte("bootstrap"), time.Now().Add(time.Hour))
	must(t, err)
	frame, err := ratchetwire.FetchFrame(body, p, time.Now())
	must(t, err)
	raw, err := ratchetwire.GetBody(body, p, time.Now())
	must(t, err)
	_, err = bob.ReceiveFirst(b, spk, nil, frame, raw)
	must(t, err)
	return alice, bob, sid
}

func TestHandoffExactPointerRetrySurvivesRestart(t *testing.T) {
	e, a, b := fixtures(t)
	ep, recv, sid := endpoints(t, a, b)
	s, p := openTestStore(t)
	session := hex.EncodeToString(sid[:])
	must(t, s.Apply(e, e.Message.Terms.Buyer, session, true, time.Now()))
	auth := func(Peer, string) error { return nil }
	var first []byte
	err := s.Flush(context.Background(), ep, e.Message.Terms.Buyer, auth, func(_ context.Context, to string, p []byte) error {
		if to != "provider" {
			t.Fatal(to)
		}
		first = append([]byte{}, p...)
		return errors.New("carrier offline")
	})
	if err == nil {
		t.Fatal("carrier failure hidden")
	}
	r, err := s.Get(e.Message.Terms.ID, time.Now())
	must(t, err)
	if r.Outbox[0].Sent || !r.Outbox[0].Accounted || len(r.Outbox[0].Pointer) == 0 {
		t.Fatal("missing saved retry state")
	}
	before, err := ep.Sessions.Get(sid).Export()
	must(t, err)
	s, err = Open(p, bytes.Repeat([]byte{9}, 32))
	must(t, err)
	must(t, s.Flush(context.Background(), ep, e.Message.Terms.Buyer, auth, func(_ context.Context, _ string, p []byte) error {
		if !bytes.Equal(p, first) {
			t.Fatal("retry pointer changed")
		}
		parsed, err := ratchetwire.ParsePointerPayload(p)
		must(t, err)
		plain, err := recv.ReceiveNext(parsed.Pointer(), time.Now())
		must(t, err)
		got, err := Decode(plain)
		must(t, err)
		if got.Hash() != e.Hash() {
			t.Fatal("changed payload")
		}
		return nil
	}))
	after, err := ep.Sessions.Get(sid).Export()
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("retry advanced ratchet")
	}
	ledger, ok := ratchetwire.LedgerEntry(ep.StateDir(), sid)
	if !ok || ledger.MySends != 1 {
		t.Fatalf("retry double-counted: %+v", ledger)
	}
	must(t, s.Flush(context.Background(), ep, e.Message.Terms.Buyer, auth, func(context.Context, string, []byte) error { t.Fatal("resent completed event"); return nil }))
}

func TestHandoffInterruptedPreparationBlocksWithoutRatchetAdvance(t *testing.T) {
	e, a, b := fixtures(t)
	ep, _, sid := endpoints(t, a, b)
	s, p := openTestStore(t)
	must(t, s.Apply(e, e.Message.Terms.Buyer, hex.EncodeToString(sid[:]), true, time.Now()))
	must(t, s.UpdateDelivery(e.Message.Terms.ID, e.Hash(), "begin", nil, time.Now()))
	s, err := Open(p, bytes.Repeat([]byte{9}, 32))
	must(t, err)
	before, err := ep.Sessions.Get(sid).Export()
	must(t, err)
	err = s.Flush(context.Background(), ep, e.Message.Terms.Buyer, func(Peer, string) error { return nil }, func(context.Context, string, []byte) error { t.Fatal("posted interrupted event"); return nil })
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("wrong error: %v", err)
	}
	after, err := ep.Sessions.Get(sid).Export()
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("interrupted preparation advanced ratchet")
	}
	if err := s.UpdateDelivery(e.Message.Terms.ID, e.Hash(), "begin", nil, time.Now()); err == nil {
		t.Fatal("preparation marker reset")
	}
}

func TestHandoffAuthorizationFailureCannotPrepareOrPost(t *testing.T) {
	e, a, b := fixtures(t)
	ep, _, sid := endpoints(t, a, b)
	s, _ := openTestStore(t)
	must(t, s.Apply(e, e.Message.Terms.Buyer, hex.EncodeToString(sid[:]), true, time.Now()))
	if s.Flush(context.Background(), ep, e.Message.Terms.Buyer, func(Peer, string) error { return errors.New("pin changed") }, func(context.Context, string, []byte) error { t.Fatal("posted unauthorized event"); return nil }) == nil {
		t.Fatal("authorization error hidden")
	}
	r, err := s.Get(e.Message.Terms.ID, time.Now())
	must(t, err)
	if r.Outbox[0].Preparing || len(r.Outbox[0].Pointer) != 0 {
		t.Fatal("prepared before authorization")
	}
	release, err := s.LockDelivery()
	must(t, err)
	defer release()
	if s.Flush(context.Background(), ep, e.Message.Terms.Buyer, func(Peer, string) error { return nil }, func(context.Context, string, []byte) error { return nil }) == nil {
		t.Fatal("concurrent flusher allowed")
	}
}

func TestHandoffMaximumBriefFitsBodyTransport(t *testing.T) {
	e, a, b := fixtures(t)
	m := e.Message
	m.Content = bytes.Repeat([]byte{255}, MaxContent)
	m.Policy = bytes.Repeat([]byte{254}, MaxPolicy)
	m.Terms.Registration.Objective.DescriptionCommitment = Commitment(m.Content)
	m.Terms.Registration.Objective.PolicyHash = Commitment(m.Policy)
	e, err := Sign(m, a)
	must(t, err)
	raw, err := Encode(e)
	must(t, err)
	ep, recv, sid := endpoints(t, a, b)
	p, _, err := ep.SendNext(sid, raw, time.Unix(m.Terms.ExpiresAt, 0))
	must(t, err)
	body, err := ratchetwire.GetBody(ep.Store, p, time.Now())
	must(t, err)
	if len(body) > 64<<10 {
		t.Fatalf("body exceeds HTTP store cap: %d", len(body))
	}
	plain, err := recv.ReceiveNext(p, time.Now())
	must(t, err)
	decoded, err := Decode(plain)
	must(t, err)
	if !bytes.Equal(decoded.Message.Content, m.Content) {
		t.Fatal("max content not intact")
	}
	m.Content = append(m.Content, 1)
	m.Terms.Registration.Objective.DescriptionCommitment = Commitment(m.Content)
	if _, err := Sign(m, a); err == nil {
		t.Fatal("content over cap accepted")
	}
}

func TestHandoffStaleStoreHandlesMergeInsteadOfClobber(t *testing.T) {
	e, _, _ := fixtures(t)
	s, p := openTestStore(t)
	s2, err := Open(p, bytes.Repeat([]byte{9}, 32))
	must(t, err)
	must(t, s.Apply(e, e.Message.Terms.Buyer, "0011223344556677", true, time.Now()))
	other := e
	other.Message.Terms.ID, err = NewID()
	must(t, err)
	_, a, _ := fixtures(t)
	other, err = Sign(other.Message, a)
	must(t, err)
	must(t, s2.Apply(other, other.Message.Terms.Buyer, "0011223344556677", true, time.Now()))
	rows, err := s.List(time.Now())
	must(t, err)
	if len(rows) != 2 {
		t.Fatal("stale store handle overwrote another writer")
	}
	// Returned records must not alias the store's subsequent reads.
	rows[0].Events[0].Message.Content[0] ^= 1
	_, err = s.List(time.Now())
	must(t, err)
	_, err = json.Marshal(rows)
	must(t, err)
}
