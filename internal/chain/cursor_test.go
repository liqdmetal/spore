package chain

import (
	"context"
	"testing"
	"time"
)

type identityChain struct {
	list []Incoming
}

func (f *identityChain) Name() string                            { return "identity" }
func (f *identityChain) Address(context.Context) (string, error) { return "", nil }
func (f *identityChain) Height(context.Context) (uint64, error)  { return 0, nil }
func (f *identityChain) PostPayload(context.Context, string, Payload, uint64) (PostResult, error) {
	return PostResult{}, nil
}
func (f *identityChain) ListIncoming(context.Context, uint64) ([]Incoming, error) { return f.list, nil }

func TestIncomingIdentitySeparatesSameTxID(t *testing.T) {
	a := Incoming{TxID: "same", ScanHeight: 10, TopoHeight: 11, Payload: []byte("a")}
	b := Incoming{TxID: "same", ScanHeight: 10, TopoHeight: 11, Payload: []byte("b")}
	if incomingIdentity(a) == incomingIdentity(b) {
		t.Fatal("distinct payloads collapsed into one identity")
	}
	if incomingIdentity(a) == incomingIdentity(Incoming{}) {
		t.Fatal("empty incoming received an identity")
	}
}

func TestWatchRejectsEmptyTxIDAndDoesNotCollapseSameTxIDPayloads(t *testing.T) {
	c := &identityChain{list: []Incoming{
		{TxID: "", ScanHeight: 1, Payload: []byte("empty")},
		{TxID: "same", ScanHeight: 2, TopoHeight: 2, Payload: []byte("a")},
		{TxID: "same", ScanHeight: 2, TopoHeight: 2, Payload: []byte("b")},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, errs := Watch(ctx, c, WatchOpts{Interval: time.Millisecond})
	var got []string
	deadline := time.After(time.Second)
	for len(got) < 2 {
		select {
		case inc, ok := <-out:
			if !ok {
				t.Fatalf("watch closed with %d deliveries", len(got))
			}
			got = append(got, string(inc.Payload))
		case err := <-errs:
			t.Fatalf("watch error: %v", err)
		case <-deadline:
			t.Fatalf("got %v", got)
		}
	}
	if got[0] != "a" || got[1] != "b" {
		t.Fatalf("got %v", got)
	}
}
