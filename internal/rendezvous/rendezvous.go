// Package rendezvous is the transport seam for Model A long-message delivery:
// the sender holds the encrypted body on their own node until the recipient is
// available, then the recipient fetches it peer-to-peer — nobody but sender and
// receiver ever holds the bytes.
//
// The pointer (which message to fetch) rides a whisper / on-chain anchor. The
// body itself never goes on-chain and never sits on a third-party store. The
// fetch happens over an authenticated peer connection; the transport is
// pluggable so it can be tested in-memory and ride the node's existing P2P
// channel in production (no new open port — DERO nodes are already reachable
// for P2P sync).
package rendezvous

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/liqdmetal/compost/internal/crypto"
	"github.com/liqdmetal/compost/internal/store"
)

// Server is the sender side: holds bodies and serves fetch requests over a
// transport. Each body is encrypted to a specific recipient, so a fetch is
// only honored for the peer that the body was encrypted to (enforced by the
// caller checking decryption success, not by the server knowing who can read).
type Server struct {
	store store.Store
}

// NewServer wraps the sender's durable body store as a rendezvous server.
func NewServer(st store.Store) *Server { return &Server{store: st} }

// ServeBody publishes a body for peer retrieval. It is the "advertise that CID
// is available" side; the actual whisper-pointer is the caller's job.
func (s *Server) ServeBody(cid [32]byte, deadline time.Time) bool {
	// Body already stored by session.Send; this just needs to confirm it's
	// present and not yet reaped. Return whether the store still has it.
	_, err := s.store.Get(cid)
	return err == nil
}

// Fetch is the recipient side: dial the peer and pull body by cid over a
// pluggable transport. The caller supplies a function that performs the actual
// network round-trip and returns the raw body bytes; the rendezvous layer
// verifies the CID matches and hands it back for decryption.
type FetchFunc func(ctx context.Context, cid [32]byte) ([]byte, error)

// FetchByCID pulls a body from a peer. cid is checked against sha256(body) so
// a tampered/forged response is rejected before the caller tries to decrypt.
func FetchByCID(ctx context.Context, fetch FetchFunc, cid [32]byte) ([]byte, error) {
	body, err := fetch(ctx, cid)
	if err != nil {
		return nil, err
	}
	got := crypto.CID(body)
	if got != cid {
		return nil, errors.New("rendezvous: body CID mismatch (tampered or wrong body)")
	}
	return body, nil
}

// --- in-memory transport (tests + local same-process) ---

// MemTransport is an in-memory peer: server holds bodies in a map, client
// fetches from it. Proves the rendezvous protocol offline.
type MemTransport struct {
	mu    sync.RWMutex
	bodies map[[32]byte][]byte
}

// NewMemTransport builds an empty in-memory transport.
func NewMemTransport() *MemTransport {
	return &MemTransport{bodies: map[[32]byte][]byte{}}
}

// Put registers a body as available on the (virtual) peer.
func (m *MemTransport) Put(cid [32]byte, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies[cid] = body
}

// Fetch implements FetchFunc against the in-memory map.
func (m *MemTransport) Fetch(ctx context.Context, cid [32]byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.bodies[cid]
	if !ok {
		return nil, store.ErrNotFound
	}
	return b, nil
}
