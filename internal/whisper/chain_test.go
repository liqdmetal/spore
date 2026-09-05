package whisper

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/mycelium/internal/chain"
)

// mockChain is a chain.Chain that stores payloads in memory (no DERO). It
// proves the whisper core can run against ANY backend implementing the seam.
type mockChain struct {
	mu    sync.Mutex
	next  uint64
	items []chain.Incoming
	addr  string
}

func (m *mockChain) Name() string                                { return "mock" }
func (m *mockChain) Address(ctx context.Context) (string, error) { return m.addr, nil }
func (m *mockChain) Height(ctx context.Context) (uint64, error)  { return m.next, nil }
func (m *mockChain) PostPayload(ctx context.Context, to string, p chain.Payload, amt uint64) (chain.PostResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	// mock: the sender's own list is not where a recipient reads; to emulate a
	// real chain we store to a shared outbox the receiver will see. For this
	// test both sides share one mockChain instance.
	m.items = append(m.items, chain.Incoming{TxID: "tx-" + itoa(m.next), TopoHeight: int64(m.next), Sender: m.addr, Payload: p})
	return chain.PostResult{TxID: "tx-" + itoa(m.next)}, nil
}
func (m *mockChain) ListIncoming(ctx context.Context, minHeight uint64) ([]chain.Incoming, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []chain.Incoming
	for _, it := range m.items {
		if uint64(it.TopoHeight) >= minHeight {
			out = append(out, it)
		}
	}
	return out, nil
}

func itoa(n uint64) string {
	return string(rune('0' + (n % 10)))
}

// TestSendRecvChainAgnostic: send a text whisper through the chain.Chain seam
// (mock backend) and receive it back — proving the core has no DERO dependency.
func TestSendRecvChainAgnostic(t *testing.T) {
	mc := &mockChain{addr: "mockaddr"}
	codec := DeroCodec{} // DERO payload codec, but transport is any chain

	_, err := SendChain(context.Background(), mc, codec, "bob", "hello multi-chain")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ch, _ := RecvChain(ctx, mc, codec, chain.WatchOpts{MinHeight: 0, Interval: 20 * time.Millisecond})
	var got string
	for m := range ch {
		got = m.Text
		break
	}
	if got != "hello multi-chain" {
		t.Fatalf("got %q", got)
	}
}

// TestSendLongChainAgnostic: pointer whisper round-trips via the seam.
func TestSendLongChainAgnostic(t *testing.T) {
	mc := &mockChain{addr: "a"}
	codec := DeroCodec{}
	eph := [32]byte{1}
	cid := [32]byte{2}
	if _, err := SendLongChain(context.Background(), mc, codec, "b", eph, cid); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ch, _ := RecvChain(ctx, mc, codec, chain.WatchOpts{Interval: 20 * time.Millisecond})
	for m := range ch {
		if !m.HasPointer || m.EphPub != eph || m.BodyCID != cid {
			t.Fatalf("pointer mismatch: %+v", m)
		}
		return
	}
	t.Fatal("no pointer received")
}
