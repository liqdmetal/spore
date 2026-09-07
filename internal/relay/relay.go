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
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/store"
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

// Hardening defaults (audit C3): the relay used to be an open SSRF engine —
// attacker-chosen destination, attacker-chosen (unbounded) retention, no auth,
// no quotas. The defaults below close each vector; operators can relax the
// quotas via the Set* methods.
const (
	// DefaultMaxPending bounds concurrent held bodies. A push beyond this is
	// refused (429) instead of silently filling the disk.
	DefaultMaxPending = 1024
	// DefaultMaxTotalBytes bounds total ciphertext held across all bodies.
	DefaultMaxTotalBytes = 256 << 20 // 256 MiB
	// DefaultMaxDeadline caps an attacker-supplied X-Burn-Deadline: anything
	// further out than this is clamped, so no permanent retry loop.
	DefaultMaxDeadline = 7 * 24 * time.Hour
	// DefaultPushRatePerMin bounds pushes per client IP per minute.
	DefaultPushRatePerMin = 30
)

// ipWindow is a fixed-window per-IP push counter.
type ipWindow struct {
	start int64 // unix sec of window start
	count int
}

// rateLimiter is a minimal fixed-window per-IP limiter (bounded memory: stale
// windows are evicted lazily).
type rateLimiter struct {
	mu   sync.Mutex
	max  int
	win  time.Duration
	hits map[string]*ipWindow
}

func newRateLimiter(max int, win time.Duration) *rateLimiter {
	return &rateLimiter{max: max, win: win, hits: map[string]*ipWindow{}}
}

// allow reports whether one more push from ip is permitted in this window.
func (r *rateLimiter) allow(ip string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hits) > 65536 { // hard memory bound; hostile IP diversity
		r.hits = map[string]*ipWindow{}
	}
	w, ok := r.hits[ip]
	sec := now.Unix()
	if !ok || sec-w.start >= int64(r.win/time.Second) {
		r.hits[ip] = &ipWindow{start: sec, count: 1}
		return true
	}
	w.count++
	return w.count <= r.max
}

// pending is the forwarding index the relay keeps alongside the body store:
// which destination each held cid is bound for and by when it must be gone.
// The store.Store interface is content-addressed and exposes no key iteration,
// so the relay tracks this metadata itself (bodies live in the store).
type pending struct {
	dest     string
	deadline time.Time
	bodyLen  int64 // for the total-bytes quota
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

	// allowedDests is the SSRF allowlist (audit C3): forwarding destinations
	// NOT on this list are refused at push time (403) and skipped at forward
	// time. Default is EMPTY = deny all forwarding — an operator must name the
	// mailboxes this relay serves (relaycmd -allow-dest). That kills the
	// "relay PUTs attacker-chosen bytes at attacker-chosen URLs" primitive.
	allowed map[string]bool
	// quotas.
	maxPending     int
	maxTotalBytes  int64
	maxDeadline    time.Duration
	pushLimiter    *rateLimiter
	heldBytes      int64
}

// New wraps an underlying store with a relay node. Pass store.NewMemStore() for
// an ephemeral node or store.NewDiskStore(dir) for durability across restarts.
// Forwarding destinations are DENIED until SetAllowedDests names them.
func New(st store.Store) *Relay {
	return &Relay{
		st:            st,
		client:        &http.Client{Timeout: 30 * time.Second},
		pending:       make(map[[32]byte]*pending),
		allowed:       map[string]bool{},
		maxPending:    DefaultMaxPending,
		maxTotalBytes: DefaultMaxTotalBytes,
		maxDeadline:   DefaultMaxDeadline,
		pushLimiter:   newRateLimiter(DefaultPushRatePerMin, time.Minute),
	}
}

// SetAllowedDests configures the forwarding allowlist. Each entry is a base
// URL (e.g. "https://mail.example.com"); it is normalized (scheme://host,
// trailing slash dropped) before storage. Calling this REPLACES the list.
func (r *Relay) SetAllowedDests(urls []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowed = map[string]bool{}
	for _, u := range urls {
		if key, ok := normalizeDest(u); ok {
			r.allowed[key] = true
		}
	}
}

// SetQuotas overrides the hardening defaults (0 keeps the default; a negative
// value means unlimited for bytes/pending and no cap for deadline).
func (r *Relay) SetQuotas(maxPending int, maxTotalBytes int64, maxDeadline time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if maxPending > 0 {
		r.maxPending = maxPending
	} else if maxPending < 0 {
		r.maxPending = 0 // 0 = unlimited (checked as <= 0 skip)
	}
	if maxTotalBytes != 0 {
		r.maxTotalBytes = maxTotalBytes
	}
	if maxDeadline != 0 {
		r.maxDeadline = maxDeadline
	}
}

// normalizeDest reduces a dest URL to scheme://host[:port][/path] so trivial
// variations (trailing slash, case of scheme/host) cannot smuggle past the
// allowlist.
func normalizeDest(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	key := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	if p := strings.TrimSuffix(u.Path, "/"); p != "" && p != "." {
		key += p
	}
	return key, true
}

// destAllowed reports whether the normalized dest is on the allowlist.
func (r *Relay) destAllowed(dest string) bool {
	key, ok := normalizeDest(dest)
	if !ok {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allowed[key]
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
	// SSRF allowlist (audit C3): only operator-named destinations are
	// forwardable. Deny-by-default — an unconfigured relay forwards nothing.
	if !r.destAllowed(dest) {
		http.Error(w, "relay: destination not allowed (operator must allow this mailbox via -allow-dest)", http.StatusForbidden)
		return
	}
	// Per-IP push rate limit.
	ip, _, err2 := net.SplitHostPort(req.RemoteAddr)
	if err2 != nil {
		ip = req.RemoteAddr
	}
	if !r.pushLimiter.allow(ip, time.Now()) {
		http.Error(w, "relay: push rate limit exceeded", http.StatusTooManyRequests)
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
	// Deadline cap (audit C3): a pusher can no longer set a years-out deadline
	// that turns the relay into a permanent retry loop.
	if cap := time.Now().Add(r.maxDeadline); deadline.After(cap) {
		deadline = cap
	}
	// Quotas (audit C3): bounded held-body count and total held bytes.
	r.mu.Lock()
	if r.maxPending > 0 && len(r.pending) >= r.maxPending {
		r.mu.Unlock()
		http.Error(w, "relay: hold quota exceeded (too many pending bodies)", http.StatusTooManyRequests)
		return
	}
	if r.maxTotalBytes > 0 && r.heldBytes+int64(len(body)) > r.maxTotalBytes {
		r.mu.Unlock()
		http.Error(w, "relay: byte quota exceeded", http.StatusTooManyRequests)
		return
	}
	r.mu.Unlock()
	if err := r.st.Put(cid, body, deadline); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.mu.Lock()
	r.pending[cid] = &pending{dest: dest, deadline: deadline, bodyLen: int64(len(body))}
	r.heldBytes += int64(len(body))
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
	if p, ok := r.pending[cid]; ok {
		r.heldBytes -= p.bodyLen
		if r.heldBytes < 0 {
			r.heldBytes = 0
		}
		delete(r.pending, cid)
	}
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
	// Defense in depth: re-check the allowlist at forward time too, so a body
	// accepted under one policy can never be forwarded under a stricter one.
	if !r.destAllowed(p.dest) {
		return true // treat as dropped: never forward to a non-allowed dest
	}
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
