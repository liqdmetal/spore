package fabric

// cover.go — slice F4b (docs/RELAY_FABRIC_F4.md §2): Poisson cover traffic
// for the publish path.
//
// The attack: a first-hop relay sees a handle's fput times, and every real
// fput is a high-information event. Cover inserts decoy fputs so the relay's
// view of the handle is a stream whose dense part hides the sparse real
// sends. The design laws this file implements, each traceable to the
// addendum:
//
//	Real handle only.  A decoy handle is a beacon — it exists only for
//	    cover and is observable as such. Cover fput's the REAL handle with
//	    the same verb and the same 74-byte pointer size as real sends.
//	Per-pointer decoy bodies.  The decoy pointer is a real pointer to a
//	    real body the sender holds (freshly minted, random bytes, short
//	    TTL). The CID must NOT be a global constant: a shared "decoy CID"
//	    repeated across every spore user's stream would be the single most
//	    recognizable byte pattern on the network. Content addressing makes
//	    every decoy CID genuine.
//	Only the recipient distinguishes cover from real.  The recipient's
//	    ratchet fails the decoy closed — decoys are bound to a route no
//	    frame will ever bind to (DecoyRoute below), so FetchFrame's
//	    route-binding check rejects them before ratchet state is touched.
//	    This is the covert channel, and it is free.
//	Three independent clocks.  Cover is drawn from an exponential
//	    distribution (mean 1/rate), seeded independently of the send path,
//	    the drain ticker, and the drain jitter (jitter.go). Cover on a
//	    ±jittered timer would be periodicity wearing a wig; clock
//	    correlation is itself a fingerprint.
//	Fold, honestly.  -fabric-cover-fold lets a sender delay a real publish
//	    up to one cover interval so it lands inside the cover stream —
//	    hiding the send time at the price of up to a full interval of
//	    latency. Off by default; it is a conscious anonymity/latency trade.
//
// What cover does NOT do (the fence): it does not hide the sender IP (cover
// fputs come from the same IP — the goal is unlinking sends from meaning,
// not hiding the actor), and it does not help the recipient at all (drain
// dials are unchanged; the always-on jittered drain cadence is already
// drain-side cover).

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"strings"
	"time"
)

// DecoyRoute is the pointer route every decoy binds to. A frame's route is
// RouteKey(sid) — a 32-byte derivation of the session id — so a cover
// pointer pointing at this constant can never bind to a real frame:
// FetchFrame fails it closed at the pointer-binding check (wire.go) BEFORE
// any ratchet state is touched. The only cost a decoy ever imposes on the
// recipient is the pre-fetch filter hit in the drain loop (fabriccmd.go),
// which never reaches the body store.
//
// The constant is derived once from the string "spore fabric cover v1" so
// the value is stable across binaries and implementations (Go client,
// future Rust client) without being a magic literal anyone could confuse
// with a real route.
var DecoyRoute = sha256.Sum256([]byte("spore fabric cover v1"))

// DecoyBodyTTL is how long the sender holds a minted decoy body. It bounds
// the window in which a recipient's ratchet-bound fetch of a stale decoy
// could return 410 instead of junk — after this the store reaps it. Short,
// so the sender's disk cost is a rounding error, and longer than the fabric
// drain union keeps a consumed CID, so a re-drain finds the body gone
// rather than re-processing it.
const DecoyBodyTTL = 10 * time.Minute

// CoverScheduler draws cover-fire wait times from an exponential
// distribution with rate λ = rph covers/hour. One instance per publish
// loop.
type CoverScheduler struct {
	rph float64
	rng *rand.Rand
	now func() time.Time
}

// randReader adapts *rand.Rand to io.Reader for crypto-free bounded draws.
type randReader struct{ r *rand.Rand }

func (x randReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(x.r.Int63() >> 56)
	}
	return len(p), nil
}

// NewCoverScheduler builds a scheduler at rph covers/hour. rph <= 0
// disables cover (Wait returns false forever); values above 720 (one cover
// every 5 seconds, sustained) are refused — at rates like that "cover" is
// indistinguishable from a denial-of-service self-own and the operator
// almost certainly meant a different unit than hours.
func NewCoverScheduler(rph float64, rng *rand.Rand, now func() time.Time) (*CoverScheduler, error) {
	if rph < 0 {
		return nil, fmt.Errorf("cover rate must be >= 0 (got %v)", rph)
	}
	if rph > 720 {
		return nil, fmt.Errorf("cover rate %v/h is implausible (max 720 = one cover / 5s sustained); did you mean a different unit?", rph)
	}
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	if now == nil {
		now = time.Now
	}
	return &CoverScheduler{rph: rph, rng: rng, now: now}, nil
}

// Enabled reports whether cover traffic is configured on.
func (s *CoverScheduler) Enabled() bool { return s != nil && s.rph > 0 }

// Wait returns the delay until the next cover event and whether one is due.
// The delay is a single draw from Exp(λ): mean 1/λ, the memoryless waiting
// time of a Poisson process. Deterministic under an injected rng+clock for
// the shape tests; real callers pass nil, nil.
func (s *CoverScheduler) Wait() (time.Duration, bool) {
	if !s.Enabled() {
		return 0, false
	}
	// Inverse-transform sampling of the exponential distribution: U ~
	// Uniform(0,1), T = -ln(U)/λ. Int63() spans [0, 2^63), so dividing by
	// 2^63 gives U ∈ [0,1); the +1 keeps U > 0 (ln(0) = -Inf) at the cost
	// of a 2^-63 relative bias, and U = 1 exactly has probability 2^-63
	// (T = 0 — cover firing in the same instant as the send that armed it
	// would correlate the clocks the design keeps independent).
	const scale = float64(1 << 63)
	u := (float64(s.rng.Int63()) + 1) / scale
	mean := time.Duration(math.MaxInt64)
	if s.rph > 0 {
		mean = time.Duration(float64(time.Hour) / s.rph)
	}
	d := time.Duration(-math.Log(u) * float64(mean))
	if d < 0 {
		d = 0
	}
	return d, true
}

// MaxFold returns the fold delay cap: one full cover interval (the mean),
// matching the addendum's "up to one cover interval of latency" contract.
func (s *CoverScheduler) MaxFold() time.Duration {
	if !s.Enabled() {
		return 0
	}
	return time.Duration(float64(time.Hour) / s.rph)
}

// FoldDelay draws the delay a real publish waits before fput so it lands
// inside the cover stream: Uniform[0, one cover interval). Disabled or
// non-positive return zero (publish immediately). Drawn from the cover
// scheduler's own rng — folding is part of the same publish-side stream,
// not a fourth clock.
func (s *CoverScheduler) FoldDelay() time.Duration {
	if !s.Enabled() {
		return 0
	}
	return time.Duration(s.rng.Int63n(int64(s.MaxFold()) + 1))
}

// MintDecoy builds one decoy publish: a fresh random body, content-
// addressed under the same sha256 convention as every body store (BodyCID),
// wrapped as a 74-byte PointerV1 bound to DecoyRoute with the given burn
// deadline. Each call mints a NEW CID; the only repeated byte pattern
// across the network's cover streams is the pointer's route field, which
// is exactly the field that makes the recipient's filter O(1).
func MintDecoy(now time.Time, bodyTTL time.Duration) (pointer [74]byte, cid [32]byte, body []byte, deadline time.Time, err error) {
	// 128 random bytes from crypto/rand — NOT the scheduler's math/rand
	// stream: the decoy body's entropy must not be correlated with
	// anything else the scheduler emits (its draws are observable timing,
	// however indirectly).
	body = make([]byte, 128)
	if _, err = io.ReadFull(crand.Reader, body); err != nil {
		return
	}
	cid = sha256.Sum256(body)
	deadline = now.Add(bodyTTL)
	// The 74-byte PointerV1 layout, built natively: [0]=version 1,
	// [1]=reserved 0, [2:34]=route, [34:66]=CID, [66:74]=burn deadline
	// (little-endian unix seconds). This package cannot import
	// internal/ratchetwire in NON-test code (it would close a test-only
	// import cycle through internal/secure's vector generator), so this
	// package's own tests pin the layout through the real parser instead:
	// every minted decoy is round-tripped via ParsePointerPayload and
	// BodyCID in cover_test.go, and cmd/spore's real fan-out verifies
	// them again at the drain.
	pointer[0] = 1
	pointer[1] = 0
	copy(pointer[2:34], DecoyRoute[:])
	copy(pointer[34:66], cid[:])
	binary.LittleEndian.PutUint64(pointer[66:74], uint64(deadline.Unix()))
	return
}

// CoverTarget is one (relay, handle) fan-out destination. Cover MUST
// mirror the real send path's fan-out — same handles (seed-derived, both
// rotation epochs), same relays, same verb, same 74-byte size — so the
// relay cannot separate the streams by shape. Publishing cover to a
// separate "beacon" handle would be a double failure: a handle that
// exists only for cover is observable as such, and the real handle's
// fingerprint would remain naked.
type CoverTarget struct {
	Addr   string
	Handle string
}

// CoverPutter is the minimal surface the cover loop needs from a body
// store: hold the decoy body and reap on demand. Satisfied by
// internal/store's Store and DiskStore.
type CoverPutter interface {
	Put(cid [32]byte, body []byte, deadline time.Time) error
	Reap(now time.Time) int
}

// CoverLoop fires decoy fputs at the configured rate against the real
// handle fan-out (Targets). Wait times come from the scheduler's
// exponential clock — never a ticker — and each firing mints a fresh decoy
// body (Store.Put) before publishing the pointer. A relay that refuses
// is logged and skipped for that event only; the next draw stands.
type CoverLoop struct {
	Sched   *CoverScheduler
	Targets []CoverTarget
	Store   CoverPutter
	BodyTTL time.Duration
	// Log receives one line per publish/refusal; nil discards.
	Log func(format string, args ...any)
}

// Run blocks until ctx is cancelled, firing cover events at Poisson-drawn
// intervals. Cancellation is honored between draws and during publishes.
func (l *CoverLoop) Run(ctx context.Context) error {
	if !l.Sched.Enabled() {
		<-ctx.Done()
		return ctx.Err()
	}
	for {
		wait, ok := l.Sched.Wait()
		if !ok {
			<-ctx.Done()
			return ctx.Err()
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if err := l.FireOnce(ctx); err != nil {
			return err
		}
	}
}

// FireOnce mints and publishes ONE decoy event: fresh random body →
// Store.Put → fput to every relay. Publishes are best-effort per relay
// (refusals are logged, not fatal); a store failure skips the event
// entirely — publishing a pointer to a body we never held would leave the
// 410-vs-junk oracle open.
func (l *CoverLoop) FireOnce(ctx context.Context) error {
	logf := l.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	now := time.Now()
	ptr, cid, body, deadline, err := MintDecoy(now, l.BodyTTL)
	if err != nil {
		logf("fabric cover: mint: %v", err)
		return nil
	}
	if l.Store != nil {
		if err := l.Store.Put(cid, body, deadline); err != nil {
			logf("fabric cover: store: %v", err)
			return nil
		}
	}
	published := 0
	for _, tgt := range l.Targets {
		if err := PublishAs(ctx, tgt.Addr, tgt.Handle, ptr[:], deadline); err != nil {
			logf("fabric cover %s: %v", tgt.Addr, err)
			continue
		}
		published++
	}
	if published > 0 {
		logf("fabric cover: %d relay(s), cid %s, burns %s", published, hex.EncodeToString(cid[:8]), deadline.Format("15:04:05"))
	}
	return nil
}

// ReadDecoySkipFile loads the optional drain-side decoy-route filter
// (lines of 64-hex route values). Missing file = default filter
// (DecoyRoute only).
func ReadDecoySkipFile(path string) (map[[32]byte]bool, error) {
	out := map[[32]byte]bool{DecoyRoute: true}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := hex.DecodeString(line)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("decoy-skip file %s: line %q is not 64 hex chars", path, line)
		}
		var r [32]byte
		copy(r[:], raw)
		out[r] = true
	}
	return out, sc.Err()
}
