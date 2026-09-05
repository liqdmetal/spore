// Package relay implements a store-and-forward hop for the relay fabric: an
// anonymous middle node a phone can route a body through so the destination
// mailbox sees the relay's IP rather than the phone's, and no single operator
// sees the full phone<->mailbox association.
//
// The relay holds only opaque, content-addressed ciphertext (bodies never
// touch it as plaintext, and it never holds keys), retransmitting each held
// body to the destination mailbox it was pushed for. It is chain-agnostic and
// transport-only: it never decrypts, never inspects a payload, and forgets a
// body once forwarded or past its burn deadline.
package relay

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/liqdmetal/mycelium/internal/crypto"
	"github.com/liqdmetal/mycelium/internal/store"
)

// bearerScheme is the Authorization scheme accepted by an auth-gated relay.
const bearerScheme = "Bearer "

// maxBodyBytes caps a pushed body. Bodies are opaque ciphertext addressed by
// sha256; a realistic envelope is a few KB. 64 MiB is generous headroom and
// bounds the memory a single request can force us to read and hash.
var maxBodyBytes = 64 << 20

// defaultRetention is the hold time given to a pushed body that carries no
// X-Burn-Deadline header: the relay keeps it long enough to retry forwarding,
// then drops it rather than hoarding ciphertext indefinitely.
const defaultRetention = 24 * time.Hour

// pending is the forwarding index the relay keeps alongside the body store:
// which destination each held cid is bound for and by when it must be gone.
// The store.Store interface is content-addressed and exposes no key iteration,
// so the relay tracks this metadata itself (bodies live in the store).
type pending struct {
	dest     string
	deadline time.Time
}

// Relay is a store-and-forward hop over a content-addressed, TTL-bound body
// store. It accepts opaque bodies bound for a destination mailbox, holds them,
// and best-effort retransmits them to that destination's /put route until
// success or the burn deadline.
type Relay struct {
	st      store.Store
	client  *http.Client
	mu      sync.Mutex
	pending map[[32]byte]*pending
}

// New wraps an underlying store with a relay node. Pass store.NewMemStore() for
// an ephemeral node or store.NewDiskStore(dir) for durability across restarts.
func New(st store.Store) *Relay {
	return &Relay{
		st:      st,
		client:  &http.Client{Timeout: 30 * time.Second},
		pending: make(map[[32]byte]*pending),
	}
}

// Handler returns the HTTP surface for a relay node:
//
//	POST/PUT /relay/{cidhex}   sender pushes an opaque body bound for the
//	                           destination mailbox named by the
//	                           `X-Relay-Dest: <base-url>` header. The body must
//	                           hash to cid. Optional `X-Burn-Deadline: unix sec`
//	                           sets how long the relay holds it. 202 accepted |
//	                           400 bad cid / missing dest / sha256 mismatch.
//	GET      /relay/{cidhex}   pull the held body (content-addressed) 200 | 404
//	DELETE   /relay/{cidhex}   drop a held body now
func (r *Relay) Handler() http.Handler {
	return r.handler("")
}

// HandlerToken returns the same surface gated behind a shared-secret Bearer
// token, for when the relay itself is a paid hop. The token is compared in
// constant time (crypto/subtle). An empty token means "no auth" (open) —
// Handler() is that case.
func (r *Relay) HandlerToken(secret string) http.Handler {
	return r.handler(secret)
}

func (r *Relay) handler(secret string) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path
		if !strings.HasPrefix(path, "/relay/") {
			http.NotFound(w, req)
			return
		}
		cid, ok := parseCID(w, strings.TrimPrefix(path, "/relay/"))
		if !ok {
			return
		}
		switch req.Method {
		case http.MethodPost, http.MethodPut:
			r.handlePush(w, req, cid)
		case http.MethodGet:
			r.handlePull(w, cid)
		case http.MethodDelete:
			r.handleDrop(w, cid)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	if secret == "" {
		return inner
	}
	want := []byte(secret)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		auth := req.Header.Get("Authorization")
		if !strings.HasPrefix(auth, bearerScheme) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, bearerScheme)), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, req)
	})
}

func parseCID(w http.ResponseWriter, hexcid string) ([32]byte, bool) {
	raw, err := hex.DecodeString(hexcid)
	if err != nil || len(raw) != 32 {
		http.Error(w, "bad cid", http.StatusBadRequest)
		return [32]byte{}, false
	}
	var cid [32]byte
	copy(cid[:], raw)
	return cid, true
}

// handlePush receives an opaque body for onward relay. Content-addressed: the
// body must hash to the requested cid or it is rejected (400), so nobody can
// plant a wrong body under a cid a recipient's pointer will reference. The
// destination mailbox base URL is taken from X-Relay-Dest; the relay never
// forwards synchronously — it holds the body (202) and retries in the
// background forwarder, so a momentarily-down mailbox doesn't drop the push.
func (r *Relay) handlePush(w http.ResponseWriter, req *http.Request, cid [32]byte) {
	dest := strings.TrimSpace(req.Header.Get("X-Relay-Dest"))
	if dest == "" {
		http.Error(w, "missing X-Relay-Dest header", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(dest)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		http.Error(w, "bad X-Relay-Dest URL", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(&io.LimitedReader{R: req.Body, N: int64(maxBodyBytes) + 1})
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	if len(body) > maxBodyBytes {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if crypto.CID(body) != cid {
		http.Error(w, "body sha256 != cid", http.StatusBadRequest)
		return
	}
	deadline := time.Now().Add(defaultRetention)
	if hdr := req.Header.Get("X-Burn-Deadline"); hdr != "" {
		if sec, perr := strconv.ParseInt(hdr, 10, 64); perr == nil {
			deadline = time.Unix(sec, 0)
		}
	}
	if err := r.st.Put(cid, body, deadline); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.mu.Lock()
	r.pending[cid] = &pending{dest: dest, deadline: deadline}
	r.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (r *Relay) handlePull(w http.ResponseWriter, cid [32]byte) {
	body, err := r.st.Get(cid)
	switch err {
	case nil:
		_, _ = w.Write(body)
	case store.ErrNotFound, store.ErrExpired:
		http.NotFound(w, nil)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (r *Relay) handleDrop(w http.ResponseWriter, cid [32]byte) {
	r.drop(cid)
	w.WriteHeader(http.StatusOK)
}

// drop removes a held body from both the body store and the forwarding index.
func (r *Relay) drop(cid [32]byte) {
	_ = r.st.Delete(cid)
	r.mu.Lock()
	delete(r.pending, cid)
	r.mu.Unlock()
}

// ForwardOnce performs one best-effort pass: drop every held body past its
// burn deadline (it is not forwarded), and retransmit every still-valid body to
// its destination. Returns the number forwarded and dropped. Successful
// forwards (2xx from the destination) drop the body; failures are left to be
// retried on the next pass.
func (r *Relay) ForwardOnce(ctx context.Context) (forwarded, dropped int) {
	r.mu.Lock()
	items := make(map[[32]byte]*pending, len(r.pending))
	for cid, p := range r.pending {
		items[cid] = p
	}
	r.mu.Unlock()

	now := time.Now()
	for cid, p := range items {
		if ctx.Err() != nil {
			return forwarded, dropped
		}
		if !p.deadline.IsZero() && now.After(p.deadline) {
			r.drop(cid)
			dropped++
			continue
		}
		if r.forwardOne(ctx, cid, p) {
			r.drop(cid)
			forwarded++
		}
	}
	return forwarded, dropped
}

// forwardOne attempts one hop: push the held body to the destination mailbox's
// /put/{cid} route. Any 2xx counts as success. store.ErrNotFound / ErrExpired
// mean the body is already gone, which the caller treats as a drop.
func (r *Relay) forwardOne(ctx context.Context, cid [32]byte, p *pending) bool {
	body, err := r.st.Get(cid)
	if err != nil {
		return err == store.ErrNotFound || err == store.ErrExpired
	}
	endpoint := strings.TrimSuffix(p.dest, "/") + "/put/" + hex.EncodeToString(cid[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if !p.deadline.IsZero() {
		req.Header.Set("X-Burn-Deadline", strconv.FormatInt(p.deadline.Unix(), 10))
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// ForwardLoop reaps expired bodies and retries forwarding every interval until
// ctx is cancelled. It is the always-on driver a relay node runs in the
// background.
func (r *Relay) ForwardLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.ForwardOnce(ctx)
		}
	}
}

// Reap drops every held body whose burn deadline has passed, without attempting
// to forward it. Returns the number dropped. Called on a slower background
// cadence so expired ciphertext is evicted promptly even when the forwarder
// interval is long.
func (r *Relay) Reap(now time.Time) int {
	r.mu.Lock()
	var gone [][32]byte
	for cid, p := range r.pending {
		if !p.deadline.IsZero() && now.After(p.deadline) {
			gone = append(gone, cid)
		}
	}
	r.mu.Unlock()
	for _, cid := range gone {
		r.drop(cid)
	}
	return len(gone)
}

// Len reports the number of bodies currently held for onward relay.
func (r *Relay) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}
