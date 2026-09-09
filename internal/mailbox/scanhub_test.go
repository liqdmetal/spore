package mailbox

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/whisper"
)

// hubChain is a controllable chain.Chain: the test pushes payloads in by
// hand and counts how many times the hub polled it. The poll count is the
// whole point — it must stay O(1) in the number of subscribers.
// (Named hubChain, not fakeChain: mailbox_test.go already has a fakeChain.)
type hubChain struct {
	mu      sync.Mutex
	polls   int
	burned  []string
	burnErr error
	emit    chan chain.Incoming
}

func newHubChain() *hubChain {
	return &hubChain{emit: make(chan chain.Incoming, 64)}
}

func (f *hubChain) Name() string { return "fake" }

func (f *hubChain) Address(context.Context) (string, error) { return "fakeaddr", nil }

func (f *hubChain) Height(context.Context) (uint64, error) { return 1, nil }

func (f *hubChain) PostPayload(context.Context, string, chain.Payload, uint64) (chain.PostResult, error) {
	return chain.PostResult{TxID: "posted"}, nil
}

// ListIncoming is what chain.Watch polls. Every call is a chain-node RPC in
// production, so the count matters.
func (f *hubChain) ListIncoming(ctx context.Context, minHeight uint64) ([]chain.Incoming, error) {
	f.mu.Lock()
	f.polls++
	f.mu.Unlock()
	select {
	case inc := <-f.emit:
		return []chain.Incoming{inc}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(20 * time.Millisecond):
		return nil, nil
	}
}

func (f *hubChain) Burn(ctx context.Context, burnKey string) error {
	f.mu.Lock()
	f.burned = append(f.burned, burnKey)
	err := f.burnErr
	f.mu.Unlock()
	return err
}

func (f *hubChain) pollCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls
}

func (f *hubChain) burnKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.burned...)
}

// canonicalCodec is the plain (non-DERO) codec: payloads are length-prefixed
// text, so any mailbox decodes them. That makes fan-out easy to assert.
func canonicalCodec() whisper.Codec { return whisper.CanonicalCodec{} }

func TestScanHubOnePollerForManySubscribers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fc := newHubChain()
	hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: 5 * time.Millisecond})
	defer hub.Close()

	const n = 12
	var mboxes []*Mailbox
	var errcs []chan error
	for i := 0; i < n; i++ {
		m, err := Open(t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		mboxes = append(mboxes, m)
		errc := make(chan error, 16)
		errcs = append(errcs, errc)
		hub.Subscribe(ctx, m, canonicalCodec(), nil, nil, errc, false, 16)
	}

	// Give the hub a moment to settle, then compare poll counts against what
	// N independent watchers would have produced.
	time.Sleep(150 * time.Millisecond)
	polls := fc.pollCount()

	// With N independent mailboxes each polling every 5ms over ~150ms we would
	// expect roughly N * 30 = 360 polls. The hub must be ~30 (one watcher).
	// Allow generous slack for CI timing but keep the assertion meaningful:
	// it must be far below N*30 and roughly independent of N.
	if polls > 120 {
		t.Fatalf("hub polled the chain %d times in ~150ms with %d subscribers; expected ~30 (one shared watcher), got a per-subscriber polling pattern", polls, n)
	}
	if st := hub.Stats(); st.Subscribers != n {
		t.Fatalf("Stats().Subscribers = %d, want %d", st.Subscribers, n)
	}
}

func TestScanHubDeliversToEverySubscriber(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fc := newHubChain()
	hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: 5 * time.Millisecond})
	defer hub.Close()

	const n = 4
	var got []chan Message
	for i := 0; i < n; i++ {
		m, err := Open(t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		ch := make(chan Message, 8)
		got = append(got, ch)
		hub.Subscribe(ctx, m, canonicalCodec(), nil, func(msg Message) { ch <- msg }, make(chan error, 8), false, 8)
	}

	// One payload, offered to all four. Canonical codec means every mailbox
	// accepts it (in production each mailbox filters by its own key).
	payload, err := canonicalCodec().EncodeText("broadcast hello")
	if err != nil {
		t.Fatal(err)
	}
	fc.emit <- chain.Incoming{TxID: "tx-broadcast", Payload: payload, TopoHeight: 5}

	for i, ch := range got {
		select {
		case msg := <-ch:
			if msg.Text != "broadcast hello" {
				t.Fatalf("subscriber %d got %q", i, msg.Text)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("subscriber %d never received the fanned-out payload", i)
		}
	}
}

func TestScanHubSlowSubscriberDoesNotBlockOthers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fc := newHubChain()
	hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: 2 * time.Millisecond})
	defer hub.Close()

	// Subscriber A: a STUCK mailbox — its on() callback blocks forever. With a
	// queue of 1 this fills immediately and then must drop, not block.
	stuck := make(chan struct{})
	mA, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	errcA := make(chan error, 256)
	hub.Subscribe(ctx, mA, canonicalCodec(), nil, func(Message) { <-stuck }, errcA, false, 1)

	// Subscriber B: healthy, must keep receiving despite A being wedged.
	mB, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gotB := make(chan Message, 64)
	hub.Subscribe(ctx, mB, canonicalCodec(), nil, func(m Message) { gotB <- m }, make(chan error, 64), false, 64)

	payload, err := canonicalCodec().EncodeText("still flowing")
	if err != nil {
		t.Fatal(err)
	}
	// Push several payloads: the first wedges A's single worker, the rest must
	// still reach B (and A must drop them with a backlog error, not stall).
	for i := 0; i < 6; i++ {
		fc.emit <- chain.Incoming{TxID: "tx-" + string(rune('a'+i)), Payload: payload, TopoHeight: int64(i + 1)}
	}

	seen := 0
	deadline := time.After(4 * time.Second)
loop:
	for seen < 6 {
		select {
		case <-gotB:
			seen++
		case <-deadline:
			break loop
		}
	}
	if seen < 6 {
		t.Fatalf("healthy subscriber only got %d/6 payloads while another subscriber was stuck — fan-out blocked", seen)
	}

	// A must have reported backlog drops rather than silently stalling.
	select {
	case e := <-errcA:
		if e == nil {
			t.Fatal("expected a backlog error from the stuck subscriber")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stuck subscriber never reported a backlog drop")
	}

	close(stuck)
}

func TestScanHubBurnIsPerAcceptingSubscriberNotHubLevel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fc := newHubChain()
	hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: 5 * time.Millisecond})
	defer hub.Close()

	// Two subscribers, both autoBurn. The payload carries a BurnKey.
	mA, _ := Open(t.TempDir(), nil)
	mB, _ := Open(t.TempDir(), nil)
	gotA := make(chan Message, 4)
	gotB := make(chan Message, 4)
	hub.Subscribe(ctx, mA, canonicalCodec(), nil, func(m Message) { gotA <- m }, make(chan error, 8), true, 8)
	hub.Subscribe(ctx, mB, canonicalCodec(), nil, func(m Message) { gotB <- m }, make(chan error, 8), true, 8)

	payload, err := canonicalCodec().EncodeText("burn me")
	if err != nil {
		t.Fatal(err)
	}
	fc.emit <- chain.Incoming{TxID: "tx-burn", Payload: payload, BurnKey: "slot-1", TopoHeight: 9}

	// Both must accept BEFORE either burns, otherwise the second mailbox would
	// be reading an already-erased chain slot. This is the bug the hub design
	// exists to avoid.
	for i, ch := range []chan Message{gotA, gotB} {
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatalf("subscriber %d did not receive the payload", i)
		}
	}

	// Wait for both workers to finish burning.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(fc.burnKeys()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	keys := fc.burnKeys()
	if len(keys) != 2 {
		t.Fatalf("burn called %d times, want 2 (once per ACCEPTING subscriber): %v", len(keys), keys)
	}
	for _, k := range keys {
		if k != "slot-1" {
			t.Fatalf("burned unexpected key %q", k)
		}
	}
}

func TestScanHubForcesAutoBurnOffAtWatchLevel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fc := newHubChain()
	// Caller asks for AutoBurn; the hub MUST override it to false, because
	// chain.Watch burns after emitting to its single consumer — which under
	// fan-out would erase the slot after the first subscriber only.
	hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: 5 * time.Millisecond, AutoBurn: true})
	defer hub.Close()

	// A subscriber that does NOT accept (nil fetch, payload it cannot decode)
	// must not cause any burn. Use a payload that is not a valid whisper so
	// Deliver returns no messages.
	m, _ := Open(t.TempDir(), nil)
	hub.Subscribe(ctx, m, canonicalCodec(), nil, nil, make(chan error, 8), false, 8)

	fc.emit <- chain.Incoming{TxID: "tx-notours", Payload: chain.Payload("not a valid whisper"), BurnKey: "slot-2", TopoHeight: 3}

	time.Sleep(400 * time.Millisecond)
	if keys := fc.burnKeys(); len(keys) != 0 {
		t.Fatalf("hub burned %v even though no subscriber accepted the payload (hub-level AutoBurn must be forced off)", keys)
	}
}

func TestScanHubUnsubscribeStopsWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fc := newHubChain()
	hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: 5 * time.Millisecond})
	defer hub.Close()

	m, _ := Open(t.TempDir(), nil)
	sub := hub.Subscribe(ctx, m, canonicalCodec(), nil, nil, make(chan error, 8), false, 8)
	if got := hub.Stats().Subscribers; got != 1 {
		t.Fatalf("subscribers = %d, want 1", got)
	}

	sub.Unsubscribe()
	if got := hub.Stats().Subscribers; got != 0 {
		t.Fatalf("after Unsubscribe subscribers = %d, want 0", got)
	}
	// Idempotent: a second call must not panic on a closed queue.
	sub.Unsubscribe()

	// Payloads after unsubscribe must not panic or resurrect the subscriber.
	payload, _ := canonicalCodec().EncodeText("after unsub")
	fc.emit <- chain.Incoming{TxID: "tx-after", Payload: payload, TopoHeight: 4}
	time.Sleep(150 * time.Millisecond)
}

func TestScanHubSubscribeAfterCloseDoesNotLeakWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fc := newHubChain()
	hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: 5 * time.Millisecond})
	hub.Close()

	before := numGoroutine()
	m, _ := Open(t.TempDir(), nil)
	sub := hub.Subscribe(ctx, m, canonicalCodec(), nil, nil, make(chan error, 1), false, 4)
	// The subscription must be born dead: its worker is never started and its
	// done channel is already closed, so nothing leaks. (Queues are NEVER
	// closed by design — see ScanHub.shutdownInternal — so assert on done.)
	select {
	case <-sub.done:
	default:
		t.Fatal("subscription from a closed hub should have done already closed")
	}
	// It must not be registered either.
	if got := hub.Stats().Subscribers; got != 0 {
		t.Fatalf("Subscribe on a closed hub registered %d subscribers, want 0", got)
	}
	time.Sleep(100 * time.Millisecond)
	if after := numGoroutine(); after > before+1 {
		t.Fatalf("Subscribe after Close leaked goroutines: before=%d after=%d", before, after)
	}
}

func TestScanHubCloseIsIdempotentAndJoinsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fc := newHubChain()
	hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: 5 * time.Millisecond})
	for i := 0; i < 5; i++ {
		m, _ := Open(t.TempDir(), nil)
		hub.Subscribe(ctx, m, canonicalCodec(), nil, nil, make(chan error, 4), false, 4)
	}
	before := numGoroutine()
	hub.Close()
	hub.Close() // must not panic
	time.Sleep(200 * time.Millisecond)
	if after := numGoroutine(); after >= before {
		t.Fatalf("Close did not reap worker goroutines: before=%d after=%d", before, after)
	}
	if got := hub.Stats().Subscribers; got != 0 {
		t.Fatalf("after Close subscribers = %d, want 0", got)
	}
}

func TestScanHubContextCancelStopsEverything(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fc := newHubChain()
	hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: 5 * time.Millisecond})
	m, _ := Open(t.TempDir(), nil)
	hub.Subscribe(ctx, m, canonicalCodec(), nil, nil, make(chan error, 4), false, 4)

	before := numGoroutine()
	cancel()
	time.Sleep(300 * time.Millisecond)
	if after := numGoroutine(); after >= before {
		t.Fatalf("ctx cancel did not stop the hub/workers: before=%d after=%d", before, after)
	}
}

// numGoroutine returns a stable-ish goroutine count, giving the scheduler a
// moment to settle so leak assertions are not racing an in-flight spawn.
func numGoroutine() int {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	return runtime.NumGoroutine()
}
