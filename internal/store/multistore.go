package store

// MultiStore mirrors bodies across SEVERAL independent substrates so an
// archive survives any one of them dying.
//
// WHY NOT JUST IPFS
//
// Every single substrate has a failure mode that kills an archive on its own:
//
//	disk store    dies with the machine
//	HTTP mailbox  dies with its operator (and is seizable)
//	nostr relays  cap bodies at ~192 KB after base64 inflation, and relays
//	              expire or refuse content at will
//	spore-peer    needs the publisher's node reachable
//	IPFS          pin != permanence; if the pinning node dies and nobody else
//	              pinned the CID, the body is gone
//
// Pinning to one IPFS node is not durability, it is a single point of failure
// with extra steps. So a MultiStore writes to N substrates and reads from
// whichever still answers. Durability comes from DIVERSITY, not from trusting
// any one network — the same invariant RelayOS's substrate fabric is built on:
// "infrastructure may disappear; commitments and verifiable evidence must
// survive."
//
// WRITE AND READ SEMANTICS (chosen deliberately)
//
//   - Put succeeds if AT LEAST ONE substrate accepted the body, and reports
//     which ones failed. Requiring all would make the slowest or flakiest
//     backend able to block publishing; requiring none would silently publish
//     into a void. A partial write is a real, reported state.
//   - Get returns the FIRST substrate that yields a body whose SHA-256 matches
//     the requested CID. Every returned body is verified locally, so a lying
//     or buggy backend cannot poison a read — it is skipped and the next
//     substrate is tried.
//   - Delete and Reap are BEST-EFFORT by nature. They remove what we control.
//     A body another node already fetched is beyond our reach, and pretending
//     otherwise would be a false compost promise.
//
// The integrity guarantee is ours, not the network's: a body is accepted only
// if sha256(body) == cid. That is what makes it safe to read from an untrusted
// public substrate at all.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Substrate is one named backing store in a MultiStore.
type Substrate struct {
	// Name identifies the substrate in errors and reports (e.g. "ipfs",
	// "disk", "qdn"). It exists so a partial failure is actionable.
	Name string
	// Store is the backend.
	Store Store
	// ReadOnly excludes this substrate from writes while still serving reads.
	// Useful for a public mirror you can fetch from but not publish to.
	ReadOnly bool
}

// MultiStore fans writes out to every writable substrate and reads from the
// first that returns a CID-verified body.
type MultiStore struct {
	mu   sync.RWMutex
	subs []Substrate
}

// NewMultiStore builds a MultiStore. At least one substrate is required, and
// names must be unique so a report can be traced back to a backend.
func NewMultiStore(subs ...Substrate) (*MultiStore, error) {
	if len(subs) == 0 {
		return nil, errors.New("store: a MultiStore needs at least one substrate")
	}
	seen := map[string]bool{}
	for i, s := range subs {
		if s.Name == "" {
			return nil, fmt.Errorf("store: substrate %d has no name", i)
		}
		if s.Store == nil {
			return nil, fmt.Errorf("store: substrate %q has a nil Store", s.Name)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("store: duplicate substrate name %q", s.Name)
		}
		seen[s.Name] = true
	}
	cp := make([]Substrate, len(subs))
	copy(cp, subs)
	return &MultiStore{subs: cp}, nil
}

// PutReport records exactly which substrates accepted a body and which did
// not. Publishing blind is how an "archive" turns out to be one flaky node.
type PutReport struct {
	// Accepted lists substrates that stored the body.
	Accepted []string
	// Failed maps substrate name to the error it returned.
	Failed map[string]error
}

// Durable reports whether the body landed on more than one substrate, which is
// the only state that actually survives losing a backend.
func (r PutReport) Durable() bool { return len(r.Accepted) > 1 }

// String renders the report for operators.
func (r PutReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "accepted=%d [%s]", len(r.Accepted), strings.Join(r.Accepted, " "))
	if len(r.Failed) > 0 {
		names := make([]string, 0, len(r.Failed))
		for n := range r.Failed {
			names = append(names, n)
		}
		fmt.Fprintf(&b, " failed=%d [%s]", len(r.Failed), strings.Join(names, " "))
	}
	if !r.Durable() {
		b.WriteString(" WARNING: single substrate — not durable")
	}
	return b.String()
}

// PutWithReport stores a body on every writable substrate, in parallel, and
// returns which ones took it.
//
// It errors only when NO substrate accepted the body. A partial success is a
// success with a warning, because refusing to publish because one backend is
// down would hand any single substrate a veto over the publisher.
func (m *MultiStore) PutWithReport(cid [32]byte, body []byte, deadline time.Time) (PutReport, error) {
	// Verify the caller's CID before writing anything. Storing a body under
	// the wrong address would make it unfetchable everywhere at once.
	if sum := sha256.Sum256(body); sum != cid {
		return PutReport{}, fmt.Errorf("store: body does not match cid %s (got %s)",
			hex.EncodeToString(cid[:8]), hex.EncodeToString(sum[:8]))
	}

	m.mu.RLock()
	subs := make([]Substrate, len(m.subs))
	copy(subs, m.subs)
	m.mu.RUnlock()

	type result struct {
		name string
		err  error
	}
	var wg sync.WaitGroup
	results := make(chan result, len(subs))
	writable := 0
	for _, s := range subs {
		if s.ReadOnly {
			continue
		}
		writable++
		wg.Add(1)
		go func(s Substrate) {
			defer wg.Done()
			results <- result{s.Name, s.Store.Put(cid, body, deadline)}
		}(s)
	}
	wg.Wait()
	close(results)

	if writable == 0 {
		return PutReport{}, errors.New("store: every substrate is read-only; nothing can be published")
	}

	rep := PutReport{Failed: map[string]error{}}
	for r := range results {
		if r.err != nil {
			rep.Failed[r.name] = r.err
			continue
		}
		rep.Accepted = append(rep.Accepted, r.name)
	}
	if len(rep.Accepted) == 0 {
		return rep, fmt.Errorf("store: no substrate accepted the body (%d failed)", len(rep.Failed))
	}
	return rep, nil
}

// Put satisfies Store. It discards the report, so prefer PutWithReport when
// publishing anything that matters — a silent single-substrate write looks
// identical to a durable one.
func (m *MultiStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	_, err := m.PutWithReport(cid, body, deadline)
	return err
}

// Get returns the first CID-verified body from any substrate.
//
// A substrate that returns the wrong bytes is SKIPPED, not fatal: reading from
// public infrastructure means assuming some of it lies. The local hash check
// is what makes that safe.
func (m *MultiStore) Get(cid [32]byte) ([]byte, error) {
	m.mu.RLock()
	subs := make([]Substrate, len(m.subs))
	copy(subs, m.subs)
	m.mu.RUnlock()

	var (
		sawExpired  bool
		corrupted   []string
		lastErr     error
		anyAttempts bool
	)
	for _, s := range subs {
		anyAttempts = true
		body, err := s.Store.Get(cid)
		if err != nil {
			if errors.Is(err, ErrExpired) {
				sawExpired = true
			}
			lastErr = err
			continue
		}
		if sum := sha256.Sum256(body); sum != cid {
			// Byzantine or buggy substrate. Record and keep going.
			corrupted = append(corrupted, s.Name)
			continue
		}
		return body, nil
	}

	switch {
	case !anyAttempts:
		return nil, ErrNotFound
	case len(corrupted) > 0:
		return nil, fmt.Errorf("store: no substrate returned a valid body; %d served CONTENT THAT DID NOT MATCH THE CID [%s]: %w",
			len(corrupted), strings.Join(corrupted, " "), ErrNotFound)
	case sawExpired:
		return nil, ErrExpired
	case lastErr != nil:
		return nil, lastErr
	default:
		return nil, ErrNotFound
	}
}

// Delete removes a body from every substrate that will accept the request.
//
// It returns an error only if NO substrate could delete it. Best-effort is the
// honest semantic: a public network cannot be made to forget.
func (m *MultiStore) Delete(cid [32]byte) error {
	m.mu.RLock()
	subs := make([]Substrate, len(m.subs))
	copy(subs, m.subs)
	m.mu.RUnlock()

	deleted := 0
	var lastErr error
	for _, s := range subs {
		if s.ReadOnly {
			continue
		}
		if err := s.Store.Delete(cid); err != nil {
			lastErr = err
			continue
		}
		deleted++
	}
	if deleted == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

// Reap evicts expired bodies everywhere and returns the total evicted. The sum
// can exceed the logical body count, since the same body is reaped on each
// substrate that held it.
func (m *MultiStore) Reap(now time.Time) int {
	m.mu.RLock()
	subs := make([]Substrate, len(m.subs))
	copy(subs, m.subs)
	m.mu.RUnlock()

	n := 0
	for _, s := range subs {
		if s.ReadOnly {
			continue
		}
		n += s.Store.Reap(now)
	}
	return n
}

// Len reports the LARGEST count any single substrate holds — the best local
// estimate of distinct bodies. Summing would multiply-count mirrors.
func (m *MultiStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	max := 0
	for _, s := range m.subs {
		if n := s.Store.Len(); n > max {
			max = n
		}
	}
	return max
}

// Names lists the substrates in order.
func (m *MultiStore) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.subs))
	for _, s := range m.subs {
		n := s.Name
		if s.ReadOnly {
			n += " (ro)"
		}
		out = append(out, n)
	}
	return out
}

// Availability reports, per substrate, whether a CID is retrievable AND
// CID-verified there. It answers the only question that matters for an
// archive: how many independent places is this actually recoverable from?
func (m *MultiStore) Availability(cid [32]byte) map[string]bool {
	m.mu.RLock()
	subs := make([]Substrate, len(m.subs))
	copy(subs, m.subs)
	m.mu.RUnlock()

	out := map[string]bool{}
	for _, s := range subs {
		body, err := s.Store.Get(cid)
		if err != nil {
			out[s.Name] = false
			continue
		}
		out[s.Name] = sha256.Sum256(body) == cid
	}
	return out
}

var _ Store = (*MultiStore)(nil)
