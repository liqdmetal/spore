package ratchetwire

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
)

type adversarialBodyStore struct{ bodies map[[32]byte][]byte }

func newAdversarialBodyStore() *adversarialBodyStore {
	return &adversarialBodyStore{bodies: make(map[[32]byte][]byte)}
}
func (s *adversarialBodyStore) Put(cid [32]byte, body []byte, _ time.Time) error {
	s.bodies[cid] = append([]byte(nil), body...)
	return nil
}
func (s *adversarialBodyStore) Delete(cid [32]byte) error { delete(s.bodies, cid); return nil }
func (s *adversarialBodyStore) Reap(time.Time) int        { return 0 }
func (s *adversarialBodyStore) Len() int                  { return len(s.bodies) }
func (s *adversarialBodyStore) Get(cid [32]byte) ([]byte, error) {
	b, ok := s.bodies[cid]
	if !ok {
		return nil, errors.New("missing body")
	}
	return append([]byte(nil), b...), nil
}

type oneShotBodyStore struct {
	*adversarialBodyStore
	reapCID [32]byte
}

func (s *oneShotBodyStore) Get(cid [32]byte) ([]byte, error) {
	b, err := s.adversarialBodyStore.Get(cid)
	if err == nil && cid == s.reapCID {
		delete(s.bodies, cid)
	}
	return b, err
}
func (s *adversarialBodyStore) tamper(cid [32]byte) { s.bodies[cid][len(s.bodies[cid])-1] ^= 0x80 }

type adversarialCarrier struct{ payloads []chain.Payload }

func (c *adversarialCarrier) Name() string                            { return "fake" }
func (c *adversarialCarrier) Address(context.Context) (string, error) { return "fake-address", nil }
func (c *adversarialCarrier) Height(context.Context) (uint64, error)  { return 1, nil }
func (c *adversarialCarrier) PostPayload(_ context.Context, _ string, p chain.Payload, _ uint64) (chain.PostResult, error) {
	c.payloads = append(c.payloads, append([]byte(nil), p...))
	return chain.PostResult{TxID: "fake-tx"}, nil
}
func (c *adversarialCarrier) ListIncoming(context.Context, uint64) ([]chain.Incoming, error) {
	return nil, nil
}

func adversarialFixture(t *testing.T) (*ratchet.SPKBundle, []byte, []byte, *[32]byte) {
	t.Helper()
	identity := filled(1)
	bobID := filled(2)
	spk := filled(3)
	opkBytes := filled(4)
	var opk [32]byte
	copy(opk[:], opkBytes)
	bundle, err := ratchet.BuildBundle(bobID, spk, 7, &opk, 9)
	if err != nil {
		t.Fatal(err)
	}
	_, err = secure.SigPubOf(bobID)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, identity, bobID, &opk
}

func TestAdversarialE2LifecycleUsesOpaqueCarrierAndDurableRestart(t *testing.T) {
	store := newAdversarialBodyStore()
	bundle, aliceID, bobID, opk := adversarialFixture(t)
	key := filled(9)
	now := time.Now().Truncate(time.Second)
	deadline := now.Add(time.Hour)
	aliceStates, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	bobStates, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewDurableEndpoint(store, aliceStates, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewDurableEndpoint(store, bobStates, now)
	if err != nil {
		t.Fatal(err)
	}
	ptr, raw, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("first secret"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	carrier := &adversarialCarrier{}
	cc := ChainCarrier{Chain: carrier, Codec: CanonicalChainCodec{}}
	if _, err = cc.PostPointer(context.Background(), "bob", raw, 1); err != nil {
		t.Fatal(err)
	}
	if len(carrier.payloads) != 1 || hasBytes(carrier.payloads[0], []byte("first secret")) || hasBytes(carrier.payloads[0], mustBody(t, store, ptr)) {
		t.Fatal("carrier carried plaintext or serialized frame")
	}
	frame, err := FetchFrame(store, ptr, now)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := bob.ReceiveFirst(bobID, filled(3), opk, frame, mustBody(t, store, ptr))
	if err != nil || string(plain) != "first secret" {
		t.Fatalf("first decrypt: %q, %v", plain, err)
	}
	// Re-open the receiver from its durable state, then decrypt the next frame.
	bob, err = NewDurableEndpoint(store, bobStates, now)
	if err != nil {
		t.Fatal(err)
	}
	next, _, err := alice.SendNext(frame.SessionID, []byte("after restart"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = bob.ReceiveNext(next, now)
	if err != nil || string(plain) != "after restart" {
		t.Fatalf("restart decrypt: %q, %v", plain, err)
	}
}

func TestDurableReceiveNextSucceedsWhenBodyIsReapedAfterFirstFetch(t *testing.T) {
	base := newAdversarialBodyStore()
	store := &oneShotBodyStore{adversarialBodyStore: base}
	bundle, aliceID, bobID, opk := adversarialFixture(t)
	now := time.Now().Truncate(time.Second)
	key := filled(10)
	as, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewDurableEndpoint(base, as, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewDurableEndpoint(store, bs, now)
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(time.Hour)
	initPtr, _, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("init"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	initFrame, err := FetchFrame(base, initPtr, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bob.ReceiveFirst(bobID, filled(3), opk, initFrame, mustBody(t, base, initPtr)); err != nil {
		t.Fatal(err)
	}
	bob, err = NewDurableEndpoint(store, bs, now)
	if err != nil {
		t.Fatal(err)
	}
	next, _, err := alice.SendNext(initFrame.SessionID, []byte("one shot"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	store.reapCID = next.CID
	plain, err := bob.ReceiveNext(next, now)
	if err != nil || string(plain) != "one shot" {
		t.Fatalf("one-shot decrypt: %q, %v", plain, err)
	}
}

func mustSig(t *testing.T, id []byte) []byte {
	t.Helper()
	s, err := secure.SigPubOf(id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func mustBody(t *testing.T, s *adversarialBodyStore, p Pointer) []byte {
	t.Helper()
	b, err := s.Get(p.CID)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAdversarialE2RejectsExpiredAndTamperedFramesWithoutAdvancing(t *testing.T) {
	store := newAdversarialBodyStore()
	bundle, aliceID, bobID, opk := adversarialFixture(t)
	key := filled(8)
	now := time.Now().Truncate(time.Second)
	as, _ := NewFileStateStore(t.TempDir(), key)
	bs, _ := NewFileStateStore(t.TempDir(), key)
	alice, _ := NewDurableEndpoint(store, as, now)
	bob, _ := NewDurableEndpoint(store, bs, now)
	p, _, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("init"), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f, err := FetchFrame(store, p, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bob.ReceiveFirst(bobID, filled(3), opk, f, mustBody(t, store, p)); err != nil {
		t.Fatal(err)
	}
	next, _, err := alice.SendNext(f.SessionID, []byte("protected"), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	before, err := bob.Sessions.Export(f.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	store.tamper(next.CID)
	if _, err = bob.ReceiveNext(next, now); err == nil {
		t.Fatal("tampered frame accepted")
	}
	after, err := bob.Sessions.Export(f.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("tampered frame advanced ratchet state")
	}
	expired, _, err := alice.SendNext(f.SessionID, []byte("expires"), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bob.ReceiveNext(expired, now.Add(2*time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired frame error = %v", err)
	}
}
