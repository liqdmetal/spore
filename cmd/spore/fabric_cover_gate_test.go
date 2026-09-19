package main

// F4b interplay tests (docs/RELAY_FABRIC_F4.md §2 slice-plan gate: "drain-
// union interplay, recipient-cost bound"). The shape tests live in
// internal/fabric; these pin the cmd/spore WIRING: the drain loop's decoy
// pre-filter (which must precede the drain union so decoys never consume
// seen-state or a body fetch) and the -fabric-cover-fold send-path hook.

import (
	"context"
	"flag"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/fabric"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// TestDecoyPreFilterSkipsBeforeDrainUnion pins the recipient-cost bound:
// a decoy pointer is skipped BEFORE the drain union, so Observe is never
// called on it (no seen-state consumed, no fetch, no ratchet touch), while
// a REAL pointer flows through to Observe. isDecoy is the exact predicate
// the drain loop applies first.
func TestDecoyPreFilterSkipsBeforeDrainUnion(t *testing.T) {
	routes, err := fabric.ReadDecoySkipFile("")
	if err != nil {
		t.Fatal(err)
	}
	if !routes[fabric.DecoyRoute] {
		t.Fatal("default filter must contain the shipped cover route")
	}
	decoy, _, _, _, err := fabric.MintDecoy(time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !isDecoy(decoy[:], routes) {
		t.Fatal("a minted decoy must be skipped by the drain pre-filter")
	}
	// A real-shaped pointer (same bytes, route swapped for a session
	// route) must NOT be skipped — only the decoy route filters.
	real := decoy
	var route [32]byte
	copy(route[:], real[2:34])
	_ = route
	routeKey := ratchetwire.RouteKey([8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33})
	copy(real[2:34], routeKey[:])
	if isDecoy(real[:], routes) {
		t.Fatal("a session-routed pointer must never match the decoy filter")
	}
	// Malformed pointers are not decoys — ingest reports them; the filter
	// must not eat them.
	if isDecoy([]byte{0x01, 0x02}, routes) {
		t.Fatal("malformed pointers must not be classified as decoys")
	}
}

// TestFoldDisabledByDefault: without -fabric-cover-fold the publish path
// must not wait at all — the fold hook is a conscious trade, never ambient.
func TestFoldDisabledByDefault(t *testing.T) {
	route := &fabricSendRoute{seed: [32]byte{}, relays: []string{"127.0.0.1:1"}, epochs: []uint32{1}}
	waits := 0
	route.waitFold = func(context.Context, time.Duration) { waits++ }
	if route.fold || route.coverSched != nil {
		t.Fatal("a default-constructed route must not fold")
	}
	// Publishing with fold=false must not invoke the wait hook even when
	// a scheduler is attached.
	route.fold = false
	route.coverSched, _ = fabric.NewCoverScheduler(720, nil, nil)
	fabricPublishPointer(context.Background(), route, [8]byte{}, realShapedPointerForTest(t))
	if waits != 0 {
		t.Fatalf("fold=false must not wait (got %d waits)", waits)
	}
}

// TestFoldWaitsOncePerCall: with fold on, the hook fires exactly once per
// publish call (one shared draw — the dual-publish copies move together),
// and the delay stays within one cover interval.
func TestFoldWaitsOncePerCall(t *testing.T) {
	sched, err := fabric.NewCoverScheduler(720, nil, nil) // interval 5s
	if err != nil {
		t.Fatal(err)
	}
	route := &fabricSendRoute{
		seed: [32]byte{}, relays: []string{"127.0.0.1:1"}, epochs: []uint32{1},
		fold: true, coverSched: sched,
	}
	var got time.Duration
	waits := 0
	route.waitFold = func(_ context.Context, d time.Duration) {
		waits++
		got = d
	}
	fabricPublishPointer(context.Background(), route, [8]byte{}, realShapedPointerForTest(t))
	if waits != 1 {
		t.Fatalf("fold=true must wait exactly once per call, got %d", waits)
	}
	if got <= 0 || got > sched.MaxFold() {
		t.Fatalf("fold delay %s outside (0, %v]", got, sched.MaxFold())
	}
}

// TestFoldCancelledWaitPublishes: a cancelled context during the fold wait
// publishes immediately — cancellation must never silently drop the
// message. Driven against a dead relay address with the production wait.
func TestFoldCancelledWaitPublishes(t *testing.T) {
	sched, _ := fabric.NewCoverScheduler(720, nil, nil)
	route := &fabricSendRoute{
		seed: [32]byte{}, relays: []string{"127.0.0.1:1"}, epochs: []uint32{1},
		fold: true, coverSched: sched,
	}
	route.waitFold = waitFoldReal
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Must return (not hang, not panic): the cancelled fold publishes
	// immediately, the publish fails best-effort against the dead relay,
	// and the function returns normally.
	fabricPublishPointer(ctx, route, [8]byte{}, realShapedPointerForTest(t))
}

// TestCoverFlagsRegisteredOnFabricFlagsets pins flag-namespace hygiene:
// -fabric-cover-fold must exist on the send flagset and -fabric-cover-rph
// on the cover flagset (and fold's rate on the shared set), so a config
// file setting them never errors on one command and works on the other.
func TestCoverFlagsRegisteredOnFabricFlagsets(t *testing.T) {
	sendFS := flag.NewFlagSet("send", flag.ContinueOnError)
	e2Common(sendFS)
	registerFabricFlags(sendFS)
	if sendFS.Lookup("fabric-cover-fold") == nil || sendFS.Lookup("fabric-cover-rph") == nil {
		t.Fatal("send path: fabric cover flags missing from flagset")
	}
	coverFS := flag.NewFlagSet("cover", flag.ContinueOnError)
	e2Common(coverFS)
	registerFabricFlags(coverFS)
	coverFS.String("cover-session", "", "") // fabricCover's own flag
	if coverFS.Lookup("fabric-cover-rph") == nil || coverFS.Lookup("cover-session") == nil {
		t.Fatal("cover command: required flags missing")
	}
}

// --- helpers ---

// realShapedPointerForTest builds a pointer whose route is a real session
// route (not DecoyRoute), for fold-path tests that bypass the decoy filter.
func realShapedPointerForTest(t *testing.T) []byte {
	t.Helper()
	pp := ratchetwire.PointerPayload{
		Version:      ratchetwire.PointerV1,
		Route:        ratchetwire.RouteKey([8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33}),
		CID:          [32]byte{0xC1, 0xD0},
		BurnDeadline: uint64(time.Now().Add(24 * time.Hour).Unix()),
	}
	return pp.MarshalBinary()
}
