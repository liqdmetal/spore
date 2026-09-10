package mailbox

import (
	"context"
	"fmt"
	"sync"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/whisper"
)

// ScanHub multiplexes ONE chain watcher across MANY mailboxes.
//
// Why this exists: `mailbox run` is one process per user, and each calls
// chain.Watch, which polls ListIncoming on its own interval. With N users that
// is N independent pollers hammering the same derod/EVM node — at 10k users and
// a 3s interval that is ~3,333 RPC calls/second against one chain node, which
// dies long before RAM or CPU does. The hub reads each new payload ONCE and
// fans it out in-process, so chain load is independent of subscriber count.
//
// Measured cost of one mailbox process is ~5.2 MB RSS and 4 threads; the hub
// does not change that, but it removes the per-mailbox polling goroutine and
// its RPC traffic, which is the part that does not scale.
//
// Fan-out semantics (all deliberate, all tested):
//
//   - EVERY payload is offered to EVERY subscriber. A mailbox decides for itself
//     whether a payload is its own: Deliver returns (nil, nil) when the payload
//     does not decode to this mailbox's key. That is the filter — no extra
//     routing table, and no way for the hub to mis-attribute a message.
//   - A slow or stuck subscriber NEVER blocks the others. Each subscriber has
//     its own buffered channel and its own worker goroutine; the hub loop only
//     ever performs a non-blocking send. If a subscriber's buffer fills, that
//     payload is dropped FOR THAT SUBSCRIBER ONLY and reported on its errc as a
//     backlog error. Losing one mailbox's delivery is strictly better than
//     stalling every mailbox on the node.
//   - One subscriber's delivery error cannot affect another's, and cannot stop
//     the hub.
//   - AutoBurn is DISABLED at the hub and re-implemented per subscriber: a
//     subscriber burns a payload's chain state only after IT accepted the
//     message. Burning at the hub level (the single-consumer behaviour of
//     chain.Watch) would erase the on-chain slot after the first mailbox saw
//     it, silently breaking every other mailbox and the compost guarantee.
//
// Honest limitation: the hub has ONE cursor, set from the WatchOpts passed to
// NewScanHub. A subscriber that joins later cannot start scanning from its own
// height — it sees what the hub sees from then on. Per-user MinHeight would
// need per-user cursors, i.e. per-user polling, which is exactly what this
// removes. Use one hub per chain+height policy.
type ScanHub struct {
	in   <-chan chain.Incoming
	errs <-chan error
	ch   chain.Chain

	mu   sync.Mutex
	subs map[*Subscription]struct{}
	// isClosed guards Subscribe-after-Close: without it a subscriber added
	// after shutdown would start a worker that nothing ever closes, leaking
	// the goroutine permanently.
	isClosed bool

	// closed signals the fan-out loop to stop.
	closed chan struct{}
	// loopDone is closed BY THE LOOP when it has fully exited. Close waits on
	// it before tearing subscribers down, because the loop is the only
	// goroutine that sends on a subscriber queue: once it has exited, no send
	// can race with teardown.
	loopDone chan struct{}
	// closeOnce guards the external Close path; subsOnce guards subscriber
	// teardown. They MUST be separate: a single sync.Once shared between
	// Close and the loop deadlocks, because Close would wait for the loop
	// while the loop blocked re-entering the same Once.
	closeOnce sync.Once
	subsOnce  sync.Once

	// delivered counts payloads offered to subscribers (diagnostics/tests).
	deliveredMu sync.Mutex
	delivered   int
	dropped     int
}

// Subscription is one mailbox attached to the hub.
type Subscription struct {
	hub   *ScanHub
	mbox  *Mailbox
	codec whisper.Codec
	fetch FetchFunc
	on    func(Message)
	errc  chan<- error

	// autoBurn erases this mailbox's own on-chain slot after it accepts a
	// message. Only the accepting subscriber burns — see ScanHub docs.
	autoBurn bool

	queue chan chain.Incoming

	// done signals this subscriber's worker to exit. Workers select on it
	// alongside the queue; NOTHING closes `queue` from outside, because a
	// close racing with fanout's send is a data race (and a send on a closed
	// channel panics). Signalling exit and joining on wg is race-free.
	done chan struct{}
	// wg tracks this subscriber's worker goroutine so Unsubscribe and hub
	// shutdown can join it deterministically instead of leaking it.
	wg sync.WaitGroup

	// Stats for tests/operators: accepted and dropped payload counts.
	mu       sync.Mutex
	accepted int
	dropped  int
}

// HubStats reports fan-out counters. Delivered is the number of payloads handed
// to at least one subscriber queue; Dropped is the number of per-subscriber
// drops caused by a full queue (backpressure), summed across subscribers.
type HubStats struct {
	Subscribers int
	Delivered   int
	Dropped     int
}

// NewScanHub starts ONE chain.Watch and returns a hub that mailboxes subscribe
// to. opts.AutoBurn is FORCED OFF regardless of what the caller passes: burn is
// per-subscriber (see Subscription.AutoBurn), because hub-level burn would
// erase a slot after the first subscriber consumed it.
func NewScanHub(ctx context.Context, c chain.Chain, opts chain.WatchOpts) *ScanHub {
	opts.AutoBurn = false
	in, errs := chain.Watch(ctx, c, opts)
	h := &ScanHub{
		in:       in,
		errs:     errs,
		ch:       c,
		subs:     map[*Subscription]struct{}{},
		closed:   make(chan struct{}),
		loopDone: make(chan struct{}),
	}
	go h.loop(ctx)
	return h
}

// Subscribe attaches a mailbox. queueSize bounds how many payloads may be
// pending for THIS subscriber before new ones are dropped for it; 0 means a
// sensible default (64). errc receives delivery errors and backlog warnings for
// this subscriber only.
func (h *ScanHub) Subscribe(ctx context.Context, m *Mailbox, codec whisper.Codec, fetch FetchFunc, on func(Message), errc chan<- error, autoBurn bool, queueSize int) *Subscription {
	if queueSize <= 0 {
		queueSize = 64
	}
	s := &Subscription{
		hub:      h,
		mbox:     m,
		codec:    codec,
		fetch:    fetch,
		on:       on,
		errc:     errc,
		autoBurn: autoBurn,
		queue:    make(chan chain.Incoming, queueSize),
		done:     make(chan struct{}),
	}
	h.mu.Lock()
	alive := h.subs != nil && !h.isClosed
	if alive {
		h.subs[s] = struct{}{}
	}
	h.mu.Unlock()
	if !alive {
		// Hub already shut down; hand back a dead subscription whose worker is
		// never started, rather than leaking a goroutine that nothing will ever
		// join. Signal done so any accidental read unblocks; do NOT close the
		// queue (nothing may ever close a queue another goroutine can send on).
		close(s.done)
		return s
	}
	s.wg.Add(1)
	go s.run(ctx)
	return s
}

// Unsubscribe detaches a mailbox and stops its worker. Safe to call twice.
func (s *Subscription) Unsubscribe() {
	if s == nil {
		return
	}
	s.hub.remove(s)
}

func (h *ScanHub) remove(s *Subscription) {
	h.mu.Lock()
	_, live := h.subs[s]
	if live {
		delete(h.subs, s)
	}
	h.mu.Unlock()
	if !live {
		return
	}
	// Signal exit, then join. The worker may be mid-Deliver; wg.Wait gives it
	// time to finish so no callback runs after Unsubscribe returns.
	close(s.done)
	s.wg.Wait()
}

// Stats returns current fan-out counters.
func (h *ScanHub) Stats() HubStats {
	h.mu.Lock()
	n := len(h.subs)
	h.mu.Unlock()
	h.deliveredMu.Lock()
	defer h.deliveredMu.Unlock()
	return HubStats{Subscribers: n, Delivered: h.delivered, Dropped: h.dropped}
}

// Counts returns this subscriber's accepted and dropped payload counts.
func (s *Subscription) Counts() (accepted, dropped int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted, s.dropped
}

// loop is the single fan-out pump. It never blocks on a subscriber.
func (h *ScanHub) loop(ctx context.Context) {
	defer func() {
		// Announce exit FIRST, then tear subscribers down from a separate
		// goroutine. Doing teardown inline here would block this goroutine
		// while a concurrent Close waits on loopDone — and Close's own
		// teardown call would then block on subsOnce held by us. Spawning
		// breaks that cycle: the loop exits promptly, teardown is idempotent.
		close(h.loopDone)
		go h.teardownSubs()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.closed:
			return
		case inc, ok := <-h.in:
			if !ok {
				return
			}
			h.fanout(ctx, inc)
		case err, ok := <-h.errs:
			if !ok {
				// Watcher finished; keep serving until ctx is done so
				// subscribers can drain what is already queued.
				h.errs = nil
				continue
			}
			if err == nil {
				continue
			}
			h.broadcastError(ctx, err)
		}
	}
}

func (h *ScanHub) fanout(ctx context.Context, inc chain.Incoming) {
	h.mu.Lock()
	subs := make([]*Subscription, 0, len(h.subs))
	for s := range h.subs {
		subs = append(subs, s)
	}
	h.mu.Unlock()

	if len(subs) == 0 {
		return
	}
	h.deliveredMu.Lock()
	h.delivered++
	h.deliveredMu.Unlock()

	for _, s := range subs {
		// NON-BLOCKING. A subscriber that cannot keep up drops its own copy
		// and is told about it; nobody else is affected.
		select {
		case s.queue <- inc:
		default:
			s.mu.Lock()
			s.dropped++
			s.mu.Unlock()
			h.deliveredMu.Lock()
			h.dropped++
			h.deliveredMu.Unlock()
			s.report(ctx, fmt.Errorf("mailbox scan hub: subscriber backlog full, dropped tx %s (increase queue size or check the mailbox is not stuck)", inc.TxID))
		}
	}
}

func (h *ScanHub) broadcastError(ctx context.Context, err error) {
	h.mu.Lock()
	subs := make([]*Subscription, 0, len(h.subs))
	for s := range h.subs {
		subs = append(subs, s)
	}
	h.mu.Unlock()
	for _, s := range subs {
		s.report(ctx, err)
	}
}

// teardownSubs signals every subscriber worker to exit and joins them. It is
// idempotent (guarded by subsOnce) and safe to call from both Close and the
// loop's exit path.
//
// Subscriber queues are NEVER closed: a worker exits via its own done channel.
// Closing a channel that another goroutine may still send on is both a data
// race and a panic, which is exactly what the -race detector caught here.
func (h *ScanHub) teardownSubs() {
	h.subsOnce.Do(func() {
		h.mu.Lock()
		h.isClosed = true
		subs := make([]*Subscription, 0, len(h.subs))
		for s := range h.subs {
			subs = append(subs, s)
			delete(h.subs, s)
		}
		h.mu.Unlock()

		// Two passes: signal everyone, then join everyone. Signalling all
		// first means one worker blocked mid-Deliver cannot delay the others'
		// exit notification.
		for _, s := range subs {
			close(s.done)
		}
		for _, s := range subs {
			s.wg.Wait()
		}
	})
}

// Close stops the hub and all subscriber workers. Idempotent, and safe to call
// concurrently with the loop ending on its own.
func (h *ScanHub) Close() {
	h.closeOnce.Do(func() {
		close(h.closed)  // tell the loop to stop
		<-h.loopDone     // wait until it has (no sends can be in flight now)
		h.teardownSubs() // then, and only then, tear subscribers down
	})
}

// run is one subscriber's worker: it owns Deliver for its mailbox so a slow
// decrypt cannot affect the hub or any other subscriber.
func (s *Subscription) run(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case inc := <-s.queue:
			s.handle(ctx, inc)
		}
	}
}

func (s *Subscription) handle(ctx context.Context, inc chain.Incoming) {
	msgs, err := s.mbox.Deliver(ctx, inc, s.codec, s.fetch)
	if err != nil {
		s.report(ctx, fmt.Errorf("mailbox: deliver tx %s: %w", inc.TxID, err))
		return
	}
	// Deliver returns no messages when the payload is not ours. Only an
	// ACCEPTING subscriber may burn: burning at hub level would erase the
	// on-chain slot after the first mailbox saw it and break every other
	// mailbox on this node.
	if len(msgs) == 0 {
		return
	}
	s.mu.Lock()
	s.accepted++
	s.mu.Unlock()

	if s.autoBurn && inc.BurnKey != "" {
		if b, ok := s.hub.ch.(chain.Burner); ok {
			// Best-effort, exactly like chain.Watch: a failed burn never
			// blocks or fails delivery, it just means chain state did not
			// rot on schedule.
			if berr := b.Burn(ctx, inc.BurnKey); berr != nil {
				s.report(ctx, fmt.Errorf("mailbox: burn %s: %v", inc.TxID, berr))
			}
		}
	}
	for _, msg := range msgs {
		if s.on != nil {
			s.on(msg)
		}
	}
}

// report sends an error to this subscriber's channel without ever blocking the
// worker (a full errc must not stall delivery).
func (s *Subscription) report(ctx context.Context, err error) {
	if s.errc == nil {
		return
	}
	select {
	case s.errc <- err:
	case <-ctx.Done():
	default:
		// errc is full or nobody is reading: drop the error rather than
		// blocking delivery. Losing a diagnostic is acceptable; stalling a
		// mailbox worker is not.
	}
}
