package derosim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

// TestZeroAddressPassesSporesValidator pins the address the simulator hands
// out: it must pass spore's own client-side ValidateAddress, or every send
// fails before the RPC layer.
func TestZeroAddressPassesSporesValidator(t *testing.T) {
	if _, err := dero.ValidateAddress(ZeroAddress); err != nil {
		t.Fatalf("simulated address rejected by spore's own validator: %v", err)
	}
}

func newTestSim(t *testing.T) (*Sim, *httptest.Server, *dero.Client, *dero.Client) {
	t.Helper()
	s := New("aaa1", "bbb2", "ccc3")
	s.AddWallet("alice")
	s.AddWallet("bob")
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	alice := dero.NewClient(srv.URL+"/w/alice", "", "")
	bob := dero.NewClient(srv.URL+"/w/bob", "", "")
	return s, srv, alice, bob
}

func TestWalletBasicsThroughRealClient(t *testing.T) {
	s, srv, alice, bob := newTestSim(t)
	ctx := context.Background()
	if got, err := alice.GetAddress(ctx); err != nil || got != s.Address("alice") {
		t.Fatalf("getaddress = %q, %v (want the wallet's own derived address)", got, err)
	}
	bal, unlocked, err := alice.GetBalance(ctx)
	if err != nil || bal == 0 || unlocked != bal {
		t.Fatalf("getbalance = %d/%d, %v", bal, unlocked, err)
	}
	if h, err := alice.GetHeight(ctx); err != nil || h != 0 {
		t.Fatalf("getheight = %d, %v", h, err)
	}
	// A payload transfer must land in the RECIPIENT's history with the
	// payload intact (this is the pointer path), and the addresses must be
	// distinct per wallet.
	bobAddr, err := bob.GetAddress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bobAddr == ZeroAddress {
		t.Fatal("wallet address is the shared ZeroAddress; per-party routing would be ambiguous")
	}
	args := anchor.Arguments{{Name: "K", DataType: anchor.DataHash, Value: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}}
	txid, err := alice.PostPayload(ctx, bobAddr, args, 16)
	if err != nil {
		t.Fatal(err)
	}
	if txid == "" {
		t.Fatal("empty txid")
	}
	ok := WaitUntil(context.Background(), 2*time.Second, func() bool {
		entries, err := bob.GetTransfers(ctx, dero.GetTransfersParams{In: true})
		if err != nil {
			t.Fatal(err)
		}
		return len(entries) == 1 && entries[0].TXID == txid
	})
	if !ok {
		t.Fatal("transfer never appeared in the recipient's get_transfers")
	}
	if _, err := alice.GetHeight(ctx); err != nil {
		t.Fatal(err)
	}
	_ = srv.Close
}

func TestHTLCFullLifecycle(t *testing.T) {
	s, _, alice, bob := newTestSim(t)
	ctx := context.Background()
	bobAddr, err := bob.GetAddress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bobBalance := s.Balance("bob")
	preimage := make([]byte, 32)
	if _, err := rand.Read(preimage); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(preimage)
	hashHex, preHex := hex.EncodeToString(hash[:]), hex.EncodeToString(preimage)

	balBefore := s.Balance("alice")

	// Fund: value rides the invoke deposit; the funder's balance drops.
	txid, err := alice.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
		{Name: "recipient", DataType: anchor.DataString, Value: bobAddr},
		{Name: "exp", DataType: anchor.DataUint64, Value: uint64(10)},
	}, 500_000, 0, 16, 0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}
	if txid == "" {
		t.Fatal("empty fund txid")
	}
	if got := s.Balance("alice"); got != balBefore-500_000 {
		t.Fatalf("funder balance = %d, want %d", got, balBefore-500_000)
	}
	if claimed, refunded, ok := s.HTLCSettled(hashHex); !ok || claimed || refunded {
		t.Fatalf("fresh HTLC settled state wrong: %v/%v/%v", claimed, refunded, ok)
	}

	// Claim with a WRONG preimage must be refused by the contract.
	if _, err := alice.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
		{Name: "pre", DataType: anchor.DataHash, Value: hex.EncodeToString(make([]byte, 32))},
		{Name: "recipient", DataType: anchor.DataString, Value: ZeroAddress},
	}, 0, 0, 16, 0); err == nil {
		t.Fatal("claim with wrong preimage accepted")
	}
	if claimed, _, _ := s.HTLCSettled(hashHex); claimed {
		t.Fatal("wrong-preimage claim settled the HTLC")
	}

	// Claim with the right preimage pays the recipient.
	if _, err := alice.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
		{Name: "pre", DataType: anchor.DataHash, Value: preHex},
		{Name: "recipient", DataType: anchor.DataString, Value: ZeroAddress},
	}, 0, 0, 16, 0); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed, refunded, _ := s.HTLCSettled(hashHex); !claimed || refunded {
		t.Fatal("claim did not settle")
	}
	if got := s.Balance("bob"); got != bobBalance+500_000 {
		t.Fatalf("claim credited recipient balance %d, want %d", got, bobBalance+500_000)
	}
	// Double-claim is refused.
	if _, err := alice.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
		{Name: "pre", DataType: anchor.DataHash, Value: preHex},
	}, 0, 0, 16, 0); err == nil {
		t.Fatal("double claim accepted")
	}
}

func TestHTLCRefundGatedOnExpiry(t *testing.T) {
	s, _, funder, _ := newTestSim(t)
	ctx := context.Background()
	preimage := make([]byte, 32)
	hash := sha256.Sum256(preimage)
	hashHex := hex.EncodeToString(hash[:])
	expiry := uint64(2)

	fundArgs := anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
		{Name: "recipient", DataType: anchor.DataString, Value: ZeroAddress},
		{Name: "exp", DataType: anchor.DataUint64, Value: expiry},
	}
	if _, err := funder.InvokeSC(ctx, "aaa1", fundArgs, 250_000, 0, 16, 0); err != nil {
		t.Fatal(err)
	}
	// Refund BEFORE expiry must refuse.
	if _, err := funder.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
	}, 0, 0, 16, 0); err == nil {
		t.Fatal("refund before expiry accepted")
	}
	// Advance past expiry with plain payload transfers (each bumps the
	// height), then refund succeeds and returns funds to the funder.
	filler := anchor.Arguments{{Name: "K", DataType: anchor.DataHash, Value: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}}
	for i := 0; i < 3; i++ {
		if _, err := funder.PostPayload(ctx, ZeroAddress, filler, 16); err != nil {
			t.Fatal(err)
		}
	}
	balBefore := s.Balance("alice")
	if _, err := funder.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
	}, 0, 0, 16, 0); err != nil {
		t.Fatalf("refund after expiry: %v", err)
	}
	if got := s.Balance("alice"); got != balBefore+250_000 {
		t.Fatalf("balance after refund = %d, want %d", got, balBefore+250_000)
	}
}

func TestDEXSwapMinOutEnforced(t *testing.T) {
	s, _, trader, _ := newTestSim(t)
	c := context.Background()
	a0, b0 := s.PoolReserves()
	// A well-bounded swap succeeds and moves the reserves.
	if _, err := trader.InvokeSC(c, "bbb2", anchor.Arguments{
		{Name: "ta", DataType: anchor.DataString, Value: "tA"},
		{Name: "tb", DataType: anchor.DataString, Value: "tB"},
		{Name: "mo", DataType: anchor.DataUint64, Value: uint64(1)},
	}, 0, 100_000, 16, 0); err != nil {
		t.Fatalf("swap: %v", err)
	}
	a1, b1 := s.PoolReserves()
	if a1 != a0+100_000 || b1 >= b0 {
		t.Fatalf("reserves did not move as expected: %d/%d -> %d/%d", a0, b0, a1, b1)
	}
	// An impossible min-out must be refused by the contract.
	if _, err := trader.InvokeSC(c, "bbb2", anchor.Arguments{
		{Name: "ta", DataType: anchor.DataString, Value: "tA"},
		{Name: "tb", DataType: anchor.DataString, Value: "tB"},
		{Name: "mo", DataType: anchor.DataUint64, Value: a1 * b1},
	}, 0, 100_000, 16, 0); err == nil {
		t.Fatal("impossible min-out accepted")
	}
}

func TestWDEROWrapUnwrap(t *testing.T) {
	s, _, w, _ := newTestSim(t)
	c := context.Background()
	if _, err := w.InvokeSC(c, "ccc3", anchor.Arguments{}, 100_000, 0, 16, 0); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if got := s.WDEROSupply(); got != 100_000 {
		t.Fatalf("supply after wrap = %d, want 100_000", got)
	}
	if _, err := w.InvokeSC(c, "ccc3", anchor.Arguments{}, 0, 100_000, 16, 0); err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if got := s.WDEROSupply(); got != 0 {
		t.Fatalf("supply after unwrap = %d, want 0", got)
	}
	// Unwrapping more than the caller's token balance is refused.
	if _, err := w.InvokeSC(c, "ccc3", anchor.Arguments{}, 0, 5, 16, 0); err == nil {
		t.Fatal("over-supply unwrap accepted")
	}
}

func TestUnknownContractRefused(t *testing.T) {
	_, _, alice, _ := newTestSim(t)
	if _, err := alice.InvokeSC(context.Background(), "ffff", anchor.Arguments{}, 1, 0, 16, 0); err == nil {
		t.Fatal("invoke against unknown contract accepted")
	}
}
