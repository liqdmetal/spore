package peerstore

// Cross-binary fabric over the rpc2/CBOR encoding (F4a): the Go client's
// full verb set — freg, fput, fpop — rides CBORTransport against the REAL
// `spore-peer serve -fabric` binary. The legacy-JSON cross-binary tests in
// fabric_smoke_interop_test.go prove the semantic contract; this one proves
// the SECOND encoding end to end, against the byte-exact vector family in
// docs/interop-vectors.json fabric_v1.rpc2_*. Skips when SPORE_PEER_BIN is
// absent (plain `go test ./...` stays hermetic; gates.sh sets the env var).

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/fabric"
)

func TestGoFabricCBORClientAgainstRustRelay(t *testing.T) {
	exe := fabricRustBin(t)
	dir := t.TempDir()
	relay := startRustFabricRelay(t, exe, dir)
	t.Cleanup(func() { relay.Stop(t) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The client derives its handle and token from a fixed seed (the relay
	// holds none — possession is proven by presenting the derived token).
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(0xC0 + i)
	}
	c, err := fabric.NewCBORClient(relay.addr, seed, 1, [8]byte{0xFE, 0xED, 0xFA, 0xCE, 1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// freg over CBOR: the relay registers the handle and echoes the token.
	if err := c.Register(ctx, seed, time.Hour); err != nil {
		t.Fatalf("CBOR freg: %v", err)
	}

	// fput over CBOR: queue a real 74-byte pointer.
	ptr := smokePointer(t, uint64(time.Now().Add(time.Hour).Unix()), 7)
	if err := c.Publish(ctx, mustHexT(t, ptr), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CBOR fput: %v", err)
	}

	// fpop over CBOR: the queue must hand back exactly that pointer — the
	// full publish→queue→drain round trip rode the CBOR encoding end to end.
	ptrs, err := c.Drain(ctx, 8)
	if err != nil {
		t.Fatalf("CBOR fpop: %v", err)
	}
	if len(ptrs) != 1 || hex.EncodeToString(ptrs[0]) != ptr {
		t.Fatalf("CBOR drain returned %d pointers, want exactly the published one", len(ptrs))
	}

	// Drain is compost-on-read: a second fpop must come back empty.
	again, err := c.Drain(ctx, 8)
	if err != nil {
		t.Fatalf("CBOR re-fpop: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second CBOR drain returned %d pointers, want 0 (compost-on-read)", len(again))
	}
}

// mustHexT is the peerstore-side hex helper (mustHex lives in the fabric
// package's test scope; tests don't cross package boundaries).
func mustHexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}
