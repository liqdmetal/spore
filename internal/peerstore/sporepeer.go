package peerstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

// SporePeerStore is the bidirectional spore-peer backend for `-store
// sporepeer://addr`: the sender's node holds and SERVES bodies; the receiver
// FETCHES them by CID. It closes the roadmap's serverless loop for long
// bodies — no mailbox operator, no relay commons: the sender's always-on node
// is the store, and only sender and receiver ever hold the bytes (PEER_SETUP /
// README: "long bodies are encrypted, held by the sender, and fetched
// peer-to-peer; then keys rot").
//
// Wire: exactly the JSON subset of docs/WIRE_SPEC.md §5, the protocol the
// reference Rust `spore-peer serve` already speaks — so this store
// interoperates in BOTH directions:
//
//   - as a SERVER it is a drop-in Go replacement for `spore-peer serve
//     --dir` (same status-byte frames, same 64 MiB cap, same error strings),
//     so a Rust `spore-peer fetch --addr` can pull from a Go-served node;
//   - as a CLIENT it fetches from either a Go-served node or a Rust
//     `spore-peer serve`, with an old-server fallback (WIRE_SPEC §5: a
//     server that replies with the RAW body and no status byte is accepted
//     when sha256(whole frame payload) == cid).
//
// Semantics per side:
//
//   - SENDER (Put): bodies are content-addressed into a local DiskStore with
//     the burn deadline — the "held by the sender" half. Serve reaps expired
//     bodies on access, so compost happens on the sender's disk, not just in
//     the receiver's ratchet.
//   - RECEIVER (Get): first tries the remote peer by CID (works from either
//     endpoint's config), then falls back to the local hold — that makes one
//     store type correct for both `send-e2` and `recv-e2` invocations, since
//     each side stores what it produces and fetches what the other holds.
//
// AUTH HONEST LIMIT: the JSON subset has no authentication — anyone who can
// reach addr can fetch whatever bodies the node still holds. That is the
// reference protocol's own posture (ciphertext-by-CID on a public port); the
// ratchet's per-message keys are what make a leaked body inert after first
// read. Bind the serve listener to loopback or a firewall-protected interface
// when that posture is not acceptable.

// SporePeerConfig configures a SporePeerStore.
type SporePeerConfig struct {
	// Dir is where bodies this endpoint produces are held (DiskStore layout).
	// Required — it is the "held by the sender" half of the model.
	Dir string
	// Addr is the peer address (host:port) this store fetches from, and the
	// address advertised as sporepeer://Addr to the other endpoint. Empty is
	// allowed only for a pure-server endpoint that never fetches remotely.
	Addr string
	// Listen, when non-empty, runs a spore-peer JSON-subset server on that
	// bind address (e.g. ":8099" or "127.0.0.1:8099"). Bodies in Dir are
	// served by CID until their burn deadline.
	Listen string
	// ReapEvery, when > 0, runs a background ticker that reaps expired
	// bodies from the hold on that interval — AUDIT-SPOREPEER recommendation
	// 3: the serve path reaps only on access to an expired CID, so bodies
	// nobody ever asks for would linger on disk forever. A long-lived node
	// sets this to a fraction of the smallest TTL it issues (e.g. 10m for
	// hour-long holds). Zero (the default) leaves the on-access behavior;
	// negative is treated as zero. Expiry itself is ALWAYS enforced by
	// DiskStore.Get on every access — the ticker only affects when expired
	// bytes leave the disk, never whether they are served.
	ReapEvery time.Duration
}

// SporePeerStore implements store.Store over the spore-peer transport: a
// local hold (DiskStore) for bodies this endpoint produces, a serve listener
// for what remote peers fetch from us, and a remote fetch for what they hold.
type SporePeerStore struct {
	Addr   string // remote peer; "" = fetch falls back to local hold only
	hold   *store.DiskStore
	listen string

	mu     sync.Mutex
	ln     net.Listener
	closed bool
	wg     sync.WaitGroup

	// stop is closed exactly once by Close to end the reap ticker (the
	// serve loop exits via ln.Close + closed instead).
	stop     chan struct{}
	stopOnce sync.Once

	// reapEvery records the effective reap cadence (0 = on-access only).
	reapEvery time.Duration

	// reapTicks counts completed reap passes (one per ticker fire). Tests
	// observe it to distinguish "the background loop was never scheduled"
	// (scheduler starvation under parallel load — an environmental flake
	// source, not a product bug) from "the loop ran and failed to compost"
	// (a real bug). Atomic so the loop goroutine and a test goroutine can
	// read it without additional locking.
	reapTicks atomic.Uint64
}

// NewSporePeerStore opens the local hold and, if Listen is set, starts
// serving the spore-peer JSON subset on it. When cfg.ReapEvery > 0 it also
// starts the periodic reap ticker.
func NewSporePeerStore(cfg SporePeerConfig) (*SporePeerStore, error) {
	if cfg.Dir == "" {
		return nil, errors.New("peerstore: SporePeerConfig.Dir is required (the sender's node must hold the bodies it serves)")
	}
	hold, err := store.NewDiskStore(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("peerstore: open hold: %w", err)
	}
	if cfg.ReapEvery < 0 {
		cfg.ReapEvery = 0
	}
	s := &SporePeerStore{Addr: cfg.Addr, hold: hold, listen: cfg.Listen, reapEvery: cfg.ReapEvery, stop: make(chan struct{})}
	if cfg.Listen != "" {
		if err := s.serve(); err != nil {
			return nil, err
		}
	}
	if cfg.ReapEvery > 0 {
		s.wg.Add(1)
		go s.reapLoop(cfg.ReapEvery)
	}
	return s, nil
}

// reapOnce is one pass of the ticker's body: a best-effort Reap of the
// hold at the current wall clock. Best-effort by design — a reap error
// (transient fs trouble) is never worth killing the node over, and the next
// tick retries. Safe alongside Get/Put — DiskStore reap is glob-read-remove
// over the .exp files, and expiry enforcement on access is independent of
// whether the bytes are still on disk.
//
// Extracted from reapLoop so tests can drive a pass synchronously: the
// compost PROPERTY is then asserted without any goroutine scheduling in
// the way, while the counter records each pass for the wiring tests.
func (s *SporePeerStore) reapOnce() {
	s.reapTicks.Add(1)
	_ = s.hold.Reap(time.Now())
}

// reapLoop composts expired bodies on a fixed cadence.
func (s *SporePeerStore) reapLoop(every time.Duration) {
	defer s.wg.Done()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.reapOnce()
		case <-s.stop:
			return
		}
	}
}

// LocalAddr returns the serve listener's resolved address ("127.0.0.1:8099"
// when bound with :0), or "" when not serving. The CLI prints it so the user
// knows the exact sporepeer:// address to give their contact.
func (s *SporePeerStore) LocalAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Close stops the serve listener and the reap ticker, if any, and waits
// for in-flight connections and loops to finish. Safe to call more than
// once.
func (s *SporePeerStore) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	s.stopOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
	return nil
}

// --- Store seam -------------------------------------------------------

// Put holds body under cid locally until deadline. The sender runs this; the
// serve listener then answers fetches for it.
func (s *SporePeerStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	return s.hold.Put(cid, body, deadline)
}

// Get fetches a body: remote peer first (that is where the other endpoint
// held it), then the local hold. Both paths verify sha256 == cid.
func (s *SporePeerStore) Get(cid [32]byte) ([]byte, error) {
	if s.Addr != "" {
		ctx, cancel := context.WithTimeout(context.Background(), ioTO)
		body, err := Fetch(ctx, s.Addr, cid)
		cancel()
		switch {
		case err == nil:
			return body, nil
		case errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExpired):
			return nil, err // definitive from the peer: stop, don't mask with local state
		default:
			// Transport-level failure (peer down, RST, timeout): fall
			// through to the local hold before giving up.
		}
	}
	return s.hold.Get(cid)
}

// Delete removes a body from the local hold. The remote peer's copy is out
// of reach by design — the owner of that node composts their own hold.
func (s *SporePeerStore) Delete(cid [32]byte) error { return s.hold.Delete(cid) }

// Reap evicts expired bodies from the local hold.
func (s *SporePeerStore) Reap(now time.Time) int { return s.hold.Reap(now) }

// Len reports how many bodies the local hold contains.
func (s *SporePeerStore) Len() int { return s.hold.Len() }

var _ store.Store = (*SporePeerStore)(nil)

// --- serve (spore-peer JSON subset, WIRE_SPEC §5) ----------------------

// maxServeRequest caps a served REQUEST frame. A legitimate request is the
// 76-byte {"cid":"<64hex>"} JSON object; 64 KiB leaves orders of magnitude
// of headroom while making the response to anything larger constant-cost.
// (The 64 MiB maxFrame cap exists for RESPONSE frames — bodies — not
// requests; pre-allocating attacker-declared request buffers was a remote
// memory-exhaustion vector: N idle connections x 64 MiB each.)
const maxServeRequest = 64 << 10

// readServeFrame reads one request frame, refusing — BEFORE any payload
// allocation — a length prefix that exceeds maxServeRequest. One request per
// connection means framing does not need to be preserved past a rejection:
// the handler answers and closes, so the declared-length bytes never have to
// be drained.
func readServeFrame(conn net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("peerstore: read length: %w", err)
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxServeRequest {
		return nil, fmt.Errorf("peerstore: bad request frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("peerstore: read payload: %w", err)
	}
	return buf, nil
}

func (s *SporePeerStore) serve() error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("peerstore: listen %s: %w", s.listen, err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return errors.New("peerstore: store already closed")
	}
	s.ln = ln
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				s.mu.Lock()
				closed := s.closed
				s.mu.Unlock()
				if closed {
					return
				}
				// Transient accept failures (fd pressure, connection
				// aborted before accept) must not kill the listener:
				// back off briefly and keep serving. A hostile client can
				// only ever cost us the backoff, not the endpoint.
				time.Sleep(100 * time.Millisecond)
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleConn(conn)
			}()
		}
	}()
	return nil
}

// handleConn answers ONE request frame with ONE response frame, then closes —
// the reference serve's one-request-per-connection shape.
//
// Concurrency posture: one goroutine per connection (cheap; an idle conn
// blocks in a 4-byte read on a ~8 KB stack — the 64 MiB pre-alloc is gone via
// maxServeRequest), each hard-deadlined at ioTO, so a slowloris holds only
// its own goroutine for at most ioTO. File-descriptor exhaustion is the
// remaining bound and is the OS's to enforce; accept failures are tolerated
// (see serve) rather than fatal.
func (s *SporePeerStore) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTO))

	payload, err := readServeFrame(conn)
	if err != nil {
		writeFrameErr(conn, "400 bad frame")
		return // malformed or abandoned request: nothing useful to answer
	}
	cid, ok := parseCIDRequest(payload)
	if !ok {
		writeFrameErr(conn, "400 bad cid")
		return
	}
	// DiskStore.Get enforces the burn deadline itself (expired -> ErrExpired),
	// so an expired body composts and reports "410 gone" — it is never served.
	body, err := s.hold.Get(cid)
	switch {
	case err == nil:
		// Status byte 0x00 || body — never a raw body without the status
		// byte, and never a body whose sha256 != cid (DiskStore keys bodies
		// by their own hash, so the check below is a belt-and-braces
		// re-verification on the way out).
		if sha256.Sum256(body) != cid {
			writeFrameErr(conn, "500 cid mismatch")
			return
		}
		out := make([]byte, 0, 1+len(body))
		out = append(out, 0x00)
		out = append(out, body...)
		_, _ = conn.Write(frameBytes(out))
	case errors.Is(err, store.ErrExpired):
		writeFrameErr(conn, "410 gone")
	case errors.Is(err, store.ErrNotFound):
		writeFrameErr(conn, "404 not found")
	default:
		writeFrameErr(conn, "500 fetch error")
	}
}

// parseCIDRequest validates the {"cid":"<64hex>"} request. Only the exact
// documented shape is accepted — a hostile client cannot make us fetch or
// serve anything but a well-formed content address.
func parseCIDRequest(payload []byte) ([32]byte, bool) {
	var cid [32]byte
	s := string(payload)
	if !strings.HasPrefix(s, `{"cid":"`) || !strings.HasSuffix(s, `"}`) {
		return cid, false
	}
	hexCID := strings.TrimSuffix(strings.TrimPrefix(s, `{"cid":"`), `"}`)
	if len(hexCID) != 64 {
		return cid, false
	}
	raw, err := hex.DecodeString(hexCID)
	if err != nil {
		return cid, false
	}
	copy(cid[:], raw)
	return cid, true
}

func writeFrameErr(conn net.Conn, msg string) {
	_, _ = conn.Write(frameBytes(append([]byte{0x01}, msg...)))
}

// --- old-server fallback (WIRE_SPEC §5) --------------------------------

// classifyWithLegacyFallback accepts a response from an OLD spore-peer
// server that replies with the RAW body and no status byte: accepted only
// when sha256(whole frame payload) == cid. New servers carry the status byte
// and are handled by classify. This exists so a Go client can fetch from any
// spore-peer distribution it meets on the wire.
func classifyWithLegacyFallback(payload []byte, cid [32]byte) ([]byte, error) {
	if len(payload) > 0 && (payload[0] == 0x00 || payload[0] == 0x01) {
		return classify(payload, cid)
	}
	if sha256.Sum256(payload) == cid {
		return payload, nil
	}
	// Neither a valid status-byte frame nor a raw body matching the CID.
	return nil, fmt.Errorf("peerstore: peer: unrecognizable response (%d bytes)", len(payload))
}
