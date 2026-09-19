package fabric

// Distribution-shape tests for the F4b cover scheduler
// (docs/RELAY_FABRIC_F4.md §2, slice-plan gate: "distribution-shape tests
// (no periodicity), drain-union interplay, recipient-cost bound").
//
// The property under test is the SHAPE, not the values: cover waits must be
// exponential (memoryless Poisson inter-arrivals), NOT the ±N% uniform the
// drain jitter uses — cover on a jittered timer would be periodicity
// wearing a wig. A fixed-seed rng makes every assertion deterministic.

import (
	"encoding/hex"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/store"
)

// TestCoverWaitIsExponentialNotJitteredUniform pins the exponential CDF by
// bucket occupancy. Edges chosen so the jitter-uniform (base 5s ±20% →
// [4s,6s]) would put ~ALL mass in one bucket while Exp(mean 5s) spreads it
// — the two shapes cannot be confused at n=20000.
func TestCoverWaitIsExponentialNotJitteredUniform(t *testing.T) {
	const rph = 720.0 // mean = 5s
	s, err := NewCoverScheduler(rph, rand.New(rand.NewSource(1)), nil)
	if err != nil {
		t.Fatal(err)
	}
	const n = 20000
	edges := []time.Duration{
		1 * time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second,
		5 * time.Second, 6 * time.Second, 8 * time.Second, 12 * time.Second,
	}
	counts := make([]int, len(edges)+1) // last bucket is [12s, ∞)
	for i := 0; i < n; i++ {
		d, ok := s.Wait()
		if !ok {
			t.Fatal("scheduler disabled")
		}
		if d < 0 {
			t.Fatalf("negative wait %v", d)
		}
		b := len(edges)
		for j, e := range edges {
			if d < e {
				b = j
				break
			}
		}
		counts[b]++
	}
	// Exact Exp(mean=5s) PER-BUCKET mass: the CDF difference across each
	// edge pair (occupancy, not the cumulative CDF — e.g. [6,8) holds
	// e^(-6/5) - e^(-8/5) ≈ 0.099 of the mass).
	want := []float64{
		1 - math.Exp(-1.0/5),                 // [0,1)
		math.Exp(-1.0/5) - math.Exp(-2.0/5),  // [1,2)
		math.Exp(-2.0/5) - math.Exp(-3.0/5),  // [2,3)
		math.Exp(-3.0/5) - math.Exp(-4.0/5),  // [3,4)
		math.Exp(-4.0/5) - math.Exp(-5.0/5),  // [4,5)
		math.Exp(-5.0/5) - math.Exp(-6.0/5),  // [5,6)
		math.Exp(-6.0/5) - math.Exp(-8.0/5),  // [6,8)
		math.Exp(-8.0/5) - math.Exp(-12.0/5), // [8,12)
		math.Exp(-12.0 / 5),                  // [12,∞)
	}
	tol := 0.02
	for i, c := range counts {
		got := float64(c) / n
		if math.Abs(got-want[i]) > tol {
			t.Errorf("bucket %d: occupancy %.4f, exponential CDF wants %.4f (±%.2f)", i, got, want[i], tol)
		}
	}
	// The anti-wig check: under the drain-jitter uniform [4s,6s], the
	// fraction below 2.5s is exactly 0; under Exp(mean 5s) it is
	// 1-exp(-0.5) ≈ 0.39. If cover ever drifts to a jittered timer, this
	// fails loudly.
	below := 0
	s2, _ := NewCoverScheduler(rph, rand.New(rand.NewSource(2)), nil)
	for i := 0; i < n; i++ {
		d, _ := s2.Wait()
		if d < 2500*time.Millisecond {
			below++
		}
	}
	wantBelow := 1 - math.Exp(-0.5)
	if got := float64(below) / n; math.Abs(got-wantBelow) > tol {
		t.Errorf("fraction of waits < 2.5s = %.4f, exponential wants %.4f — shape is not memoryless Poisson", got, wantBelow)
	}
}

// TestCoverSchedulerIndependentOfJitter pins clock independence: seeded
// IDENTICALLY to the drain jitter's rng, the cover stream's shape still
// differs from the jitter's (shared seeds would make correlated clocks
// undetectable). This is the test that would catch someone "simplifying"
// cover onto JitteredInterval.
func TestCoverSchedulerIndependentOfJitter(t *testing.T) {
	seed := int64(7)
	s, _ := NewCoverScheduler(720, rand.New(rand.NewSource(seed)), nil)
	const n = 20000
	below := 0
	for i := 0; i < n; i++ {
		d, _ := s.Wait()
		if d < 2500*time.Millisecond {
			below++
		}
	}
	if got := float64(below) / n; math.Abs(got-(1-math.Exp(-0.5))) > 0.02 {
		t.Fatalf("cover shape moved: %.4f below 2.5s", got)
	}
	// The same-seeded jitter stream concentrates in [4s,6s]: zero mass
	// below 2.5s. Distinct distributions from the same seed = independent
	// derivations, which is the property the three-clocks law needs.
	jr := rand.New(rand.NewSource(seed))
	jBelow := 0
	for i := 0; i < n; i++ {
		if JitteredInterval(5*time.Second, 20, jr) < 2500*time.Millisecond {
			jBelow++
		}
	}
	if jBelow != 0 {
		t.Errorf("jitter stream has %d/%d waits below 2.5s — the uniform lost its bounds", jBelow, n)
	}
}

// TestCoverFoldDelayWithinOneInterval pins the fold contract: delay is
// Uniform[0, one cover interval) — "hides the send time within the cover
// distribution at the price of up to a full cover interval of latency".
func TestCoverFoldDelayWithinOneInterval(t *testing.T) {
	s, err := NewCoverScheduler(720, rand.New(rand.NewSource(3)), nil) // mean interval 5s (720 is the cap)
	if err != nil {
		t.Fatal(err)
	}
	const n = 5000
	var sum time.Duration
	for i := 0; i < n; i++ {
		d := s.FoldDelay()
		if d < 0 || d > s.MaxFold() {
			t.Fatalf("fold delay %v outside [0, %v]", d, s.MaxFold())
		}
		sum += d
	}
	mean := sum / n
	if mean < 2*time.Second || mean > 3*time.Second {
		t.Errorf("fold mean %s, uniform[0,5s] wants ~2.5s — not a uniform draw", mean)
	}
}

// TestSchedulerDisabledAndValidation: rph=0 is a clean off (zero delay,
// zero folds), negative and implausible rates are refused, and the nil
// scheduler is safe to call.
func TestSchedulerDisabledAndValidation(t *testing.T) {
	s, err := NewCoverScheduler(0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled() || s.FoldDelay() != 0 || s.MaxFold() != 0 {
		t.Error("rph=0 must be fully disabled")
	}
	if d, ok := s.Wait(); d != 0 || ok {
		t.Error("rph=0 Wait must return (0, false)")
	}
	if _, err := NewCoverScheduler(-1, nil, nil); err == nil {
		t.Error("negative rph must be refused")
	}
	if _, err := NewCoverScheduler(721, nil, nil); err == nil {
		t.Error("implausible rph must be refused")
	}
	var nilS *CoverScheduler
	if nilS.Enabled() || nilS.FoldDelay() != 0 || nilS.MaxFold() != 0 {
		t.Error("nil scheduler must be inert, not panicking")
	}
	if d, ok := nilS.Wait(); d != 0 || ok {
		t.Error("nil scheduler Wait must return (0, false)")
	}
}

// TestMintDecoyFreshCIDEachCall pins the addendum's hardest rule: the decoy
// CID is never a global constant. Every mint must produce a distinct CID,
// pointer, and body, and the body's CID must follow the same sha256 body
// convention the real stores use (BodyCID).
func TestMintDecoyFreshCIDEachCall(t *testing.T) {
	now := time.Unix(1700000000, 0)
	seen := map[[32]byte]bool{}
	for i := 0; i < 8; i++ {
		ptr, cid, body, deadline, err := MintDecoy(now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if seen[cid] {
			t.Fatalf("mint %d reused CID %s — a shared decoy CID would be the most recognizable byte pattern on the network", i, hex.EncodeToString(cid[:]))
		}
		seen[cid] = true
		if got := ratchetwire.BodyCID(body); got != cid {
			t.Fatalf("decoy CID is not the body's sha256 (got %x want %x) — must ride the real content-address convention", got, cid)
		}
		if len(ptr) != 74 {
			t.Fatalf("decoy pointer is %d bytes, want 74 (fput shape check)", len(ptr))
		}
		if !deadline.After(now) {
			t.Fatal("decoy deadline must be in the future")
		}
		pp, err := ratchetwire.ParsePointerPayload(ptr[:])
		if err != nil {
			t.Fatalf("decoy pointer must round-trip the real parser: %v", err)
		}
		if pp.Route != DecoyRoute {
			t.Fatal("decoy pointer must bind DecoyRoute")
		}
		if pp.CID != cid {
			t.Fatal("decoy pointer must carry its own CID")
		}
	}
}

// TestDecoyPointerFailsFetchFrameClosed pins the recipient-cost bound:
// FetchFrame must reject the decoy BEFORE any ratchet state is touched —
// and, because the store Get happens before the binding check, the test
// also documents WHY the drain loop needs the DecoyRoute pre-filter: a
// decoy pointer pointed at a real store would otherwise burn a fetch
// (the Get succeeds) before failing closed at the binding check.
func TestDecoyPointerFailsFetchFrameClosed(t *testing.T) {
	dir := t.TempDir()
	st, err := store.NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ptr, cid, body, deadline, err := MintDecoy(time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(cid, body, deadline); err != nil {
		t.Fatal(err)
	}
	pp, err := ratchetwire.ParsePointerPayload(ptr[:])
	if err != nil {
		t.Fatal(err)
	}
	// The body IS fetchable — this is exactly the fetch the pre-filter
	// must prevent.
	if got, err := st.Get(pp.CID); err != nil || string(got) != string(body) {
		t.Fatalf("decoy body not stored: %v", err)
	}
	if _, err := ratchetwire.FetchFrame(st, pp.Pointer(), time.Now()); err == nil {
		t.Fatal("decoy pointer must fail FetchFrame closed (route binding)")
	}
}

// TestCoverTargetsMirrorRealFanOut pins the addendum's real-handle law at
// the loop level: CoverTarget is derived by the CALLER from the same seed
// the real send path uses, and this test constructs targets the way
// cmd/spore does — FabricHandle over the contact seed for every drain
// epoch — then asserts the cover fan-out equals the real one. A beacon
// handle here would be observable as such AND leave the real handle naked.
func TestCoverTargetsMirrorRealFanOut(t *testing.T) {
	seed := [32]byte{9}
	var sid [8]byte = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	// The construction cmd/spore performs (identical to the real publish
	// fan-out in fabricPublishPointer):
	var targets []CoverTarget
	for _, addr := range []string{"relay-a:9000", "relay-b:9000"} {
		for _, e := range []uint32{2, 1} { // epochs n and n-1
			h, err := FabricHandle(seed, e, sid)
			if err != nil {
				t.Fatal(err)
			}
			targets = append(targets, CoverTarget{Addr: addr, Handle: hex.EncodeToString(h[:])})
		}
	}
	if len(targets) != 4 {
		t.Fatalf("expected 2 relays x 2 epochs = 4 targets, got %d", len(targets))
	}
	// Every cover handle must be byte-identical to the REAL handle for the
	// same (epoch, sid) — that equality IS the cover property.
	for i, tgt := range targets {
		e := uint32(2)
		if i%2 == 1 {
			e = 1
		}
		real, err := FabricHandle(seed, e, sid)
		if err != nil {
			t.Fatal(err)
		}
		if tgt.Handle != hex.EncodeToString(real[:]) {
			t.Fatalf("target %d handle differs from the real epoch-%d handle — cover must ride the real handle", i, e)
		}
	}
}

// TestReadDecoySkipFile: missing file = default filter; entries extend it;
// malformed lines are refused loudly rather than silently narrowing the
// filter.
func TestReadDecoySkipFile(t *testing.T) {
	m, err := ReadDecoySkipFile("")
	if err != nil || !m[DecoyRoute] || len(m) != 1 {
		t.Fatalf("default filter must be {DecoyRoute}, got %v / %v", m, err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "skip.txt")
	if err := os.WriteFile(p, []byte("# comment\n\n"+hex.EncodeToString(DecoyRoute[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err = ReadDecoySkipFile(p)
	if err != nil || !m[DecoyRoute] || len(m) != 1 {
		t.Fatalf("explicit DecoyRoute entry must dedupe, got %v / %v", m, err)
	}
	bad := filepath.Join(dir, "bad.txt")
	_ = os.WriteFile(bad, []byte("nothex\n"), 0o600)
	if _, err := ReadDecoySkipFile(bad); err == nil {
		t.Fatal("malformed skip file must be refused")
	}
}
