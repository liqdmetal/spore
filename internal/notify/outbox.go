package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Outbox is a durable, at-least-once notification queue. It stores only Event
// metadata; provider credentials remain in memory/environment and never enter
// the queue file. A provider failure leaves the event queued for retry.
type Outbox struct {
	path     string
	dispatch *Dispatcher
	retry    time.Duration
	wake     chan struct{}
	done     chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	sendMu   sync.Mutex
	pending  []Event
	closed   bool
}

// NewOutbox opens or creates a 0600 JSON-lines queue and starts its retry
// worker. Retry is the minimum delay between failed delivery attempts.
func NewOutbox(path string, dispatch *Dispatcher, retry time.Duration) (*Outbox, error) {
	if path == "" {
		return nil, errors.New("notify outbox: empty path")
	}
	if dispatch == nil {
		return nil, errors.New("notify outbox: nil dispatcher")
	}
	if retry <= 0 {
		retry = 30 * time.Second
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("notify outbox: create parent: %w", err)
	}
	if f, err := os.OpenFile(path, os.O_CREATE, 0o600); err != nil {
		return nil, fmt.Errorf("notify outbox: create: %w", err)
	} else {
		_ = f.Close()
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("notify outbox: chmod: %w", err)
		}
	}
	pending, err := readEvents(path)
	if err != nil {
		return nil, err
	}
	o := &Outbox{path: path, dispatch: dispatch, retry: retry, pending: pending, wake: make(chan struct{}, 1), done: make(chan struct{})}
	o.wg.Add(1)
	go o.run()
	select {
	case o.wake <- struct{}{}:
	default:
	}
	return o, nil
}

// Enqueue durably appends an event before returning. It is safe for concurrent
// callers. Delivery is asynchronous and does not hold the queue lock while a
// provider network request runs.
func (o *Outbox) Enqueue(e Event) error {
	if o == nil {
		return errors.New("notify outbox: nil outbox")
	}
	if err := validateEvent(e); err != nil {
		return err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("notify outbox: encode: %w", err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return errors.New("notify outbox: closed")
	}
	for _, pending := range o.pending {
		if pending.TxID == e.TxID {
			return nil
		}
	}
	f, err := os.OpenFile(o.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("notify outbox: open: %w", err)
	}
	_, werr := f.Write(append(raw, '\n'))
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("notify outbox: append: %w", werr)
	}
	if cerr != nil {
		return fmt.Errorf("notify outbox: close: %w", cerr)
	}
	o.pending = append(o.pending, e)
	select {
	case o.wake <- struct{}{}:
	default:
	}
	return nil
}

// Close stops the retry worker. Queued events remain on disk for a later
// process start; an event may be delivered more than once across a crash.
// Flush synchronously attempts queued events in order until the queue is empty,
// the context is canceled, or a provider rejects an event. Failed events remain
// durable for the background retry worker or a later process start.
func (o *Outbox) Flush(ctx context.Context) error {
	if o == nil {
		return errors.New("notify outbox: nil outbox")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	o.sendMu.Lock()
	defer o.sendMu.Unlock()
	for {
		o.mu.Lock()
		if o.closed {
			o.mu.Unlock()
			return errors.New("notify outbox: closed")
		}
		if len(o.pending) == 0 {
			o.mu.Unlock()
			return nil
		}
		e := o.pending[0]
		o.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := o.dispatch.Send(e); err != nil {
			return err
		}
		o.mu.Lock()
		if len(o.pending) > 0 {
			o.pending = o.pending[1:]
			if err := writeEvents(o.path, o.pending); err != nil {
				o.pending = append([]Event{e}, o.pending...)
				o.mu.Unlock()
				return fmt.Errorf("notify outbox: compact: %w", err)
			}
		}
		o.mu.Unlock()
	}
}

func (o *Outbox) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	if !o.closed {
		o.closed = true
		close(o.done)
	}
	o.mu.Unlock()
	o.wg.Wait()
	return nil
}

func (o *Outbox) run() {
	defer o.wg.Done()
	t := time.NewTicker(o.retry)
	defer t.Stop()
	for {
		select {
		case <-o.wake:
			o.drain()
		case <-t.C:
			o.drain()
		case <-o.done:
			return
		}
	}
}

func (o *Outbox) drain() {
	o.sendMu.Lock()
	defer o.sendMu.Unlock()
	o.mu.Lock()
	if o.closed || len(o.pending) == 0 {
		o.mu.Unlock()
		return
	}
	e := o.pending[0]
	o.mu.Unlock()

	if err := o.dispatch.Send(e); err != nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.pending) == 0 {
		return
	}
	// One worker is the only sender, so the head is still the event sent.
	o.pending = o.pending[1:]
	if err := writeEvents(o.path, o.pending); err != nil {
		// Keep the event in memory and on disk if compaction fails. It may
		// be delivered again, which is safer than losing an alert.
		o.pending = append([]Event{e}, o.pending...)
	}
}

func validateEvent(e Event) error {
	if e.TxID == "" {
		return errors.New("notify outbox: empty txid")
	}
	if len(e.TxID) > 256 || len(e.Subject) > 256 {
		return errors.New("notify outbox: event metadata too long")
	}
	if strings.ContainsAny(e.TxID, "\r\n") || strings.ContainsAny(e.Subject, "\r\n") {
		return errors.New("notify outbox: metadata contains CR/LF")
	}
	return nil
}

func readEvents(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("notify outbox: corrupt queue: %w", err)
		}
		if err := validateEvent(e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func writeEvents(path string, events []Event) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
