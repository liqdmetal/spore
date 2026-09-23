package derosim

import (
	"context"
	"math"
	"reflect"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

func swapArgs(ta, tb string, minOut uint64) anchor.Arguments {
	return anchor.Arguments{
		{Name: "ta", DataType: anchor.DataString, Value: ta},
		{Name: "tb", DataType: anchor.DataString, Value: tb},
		{Name: "mo", DataType: anchor.DataUint64, Value: minOut},
	}
}

func TestSwapRefusalsAreAtomic(t *testing.T) {
	s, _, alice, _ := newTestSim(t)
	ctx := context.Background()

	// Snapshot the full observable state before each refusal.
	expectUnchanged := func(label string, before State) {
		t.Helper()
		if after := s.State(); !reflect.DeepEqual(after, before) {
			t.Fatalf("%s mutated simulator state:\nbefore=%+v\nafter=%+v", label, before, after)
		}
	}

	setTokenBalance(s, "alice", "tA", 1_000)
	before := s.State()
	if _, err := alice.InvokeSC(ctx, "bbb2", swapArgs("tA", "tB", 1), 0, 2_000, 16, 0); err == nil {
		t.Fatal("swap exceeding the wallet's token balance was accepted")
	}
	expectUnchanged("source-of-funds refusal", before)

	setTokenBalance(s, "alice", "tA", 1_000_000*100_000)
	before = s.State()
	if _, err := alice.InvokeSC(ctx, "bbb2", swapArgs("tX", "tB", 1), 0, 100, 16, 0); err == nil {
		t.Fatal("unsupported pair accepted")
	}
	expectUnchanged("unsupported-pair refusal", before)

	before = s.State()
	if _, err := alice.InvokeSC(ctx, "bbb2", swapArgs("tA", "tB", 1), 100, 100, 16, 0); err == nil {
		t.Fatal("swap with a DERO deposit accepted")
	}
	expectUnchanged("dero-deposit refusal", before)

	setReserves(s, math.MaxUint64-50, 1_000_000*100_000)
	before = s.State()
	if _, err := alice.InvokeSC(ctx, "bbb2", swapArgs("tA", "tB", 1), 0, 100, 16, 0); err == nil {
		t.Fatal("reserve-overflowing swap accepted")
	}
	expectUnchanged("reserve-overflow refusal", before)
}

func TestSwapFeeAndTokenAccounting(t *testing.T) {
	s, _, alice, _ := newTestSim(t)
	ctx := context.Background()
	const seed = uint64(1_000_000 * 100_000)

	if _, err := alice.InvokeSC(ctx, "bbb2", swapArgs("tA", "tB", 1), 0, 500, 16, 0); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if got := feeUnits(s); got != 1 {
		t.Fatalf("fee units = %d, want 1 (0.3%% of 500, rounded down)", got)
	}
	if got := s.TokenBalance("alice", "tA"); got != seed-500 {
		t.Fatalf("tA balance = %d, want %d", got, seed-500)
	}
	// floor(seed*499/(seed+499)) = 498.
	if got, want := s.TokenBalance("alice", "tB"), seed+498; got != want {
		t.Fatalf("tB balance = %d, want %d", got, want)
	}
}

func TestSwapBidirectional(t *testing.T) {
	s, _, alice, _ := newTestSim(t)
	ctx := context.Background()
	const seed = uint64(1_000_000 * 100_000)

	if _, err := alice.InvokeSC(ctx, "bbb2", swapArgs("tB", "tA", 1), 0, 10_000, 16, 0); err != nil {
		t.Fatalf("tB->tA swap: %v", err)
	}
	a, b := s.PoolReserves()
	if b != seed+10_000 || a >= seed {
		t.Fatalf("reverse swap reserves = %d/%d, want poolB +10000 and poolA lower than %d", a, b, seed)
	}
	if ta, tb := s.TokenBalance("alice", "tA"), s.TokenBalance("alice", "tB"); ta <= seed || tb != seed-10_000 {
		t.Fatalf("reverse swap token legs wrong: tA=%d tB=%d", ta, tb)
	}
}

func TestWDEROWrapUnwrapUsesWalletTokenBalance(t *testing.T) {
	s, _, alice, bob := newTestSim(t)
	ctx := context.Background()
	const amount = uint64(100_000)

	if _, err := alice.InvokeSC(ctx, "ccc3", anchor.Arguments{}, amount, 0, 16, 0); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if got := s.Balance("alice"); got != 1_000_000*100_000-amount {
		t.Fatalf("alice DERO after wrap = %d", got)
	}
	if got := s.WDEROSupply(); got != amount {
		t.Fatalf("supply after wrap = %d, want %d", got, amount)
	}
	if got := s.TokenBalance("alice", "wDERO"); got != amount {
		t.Fatalf("alice wDERO after wrap = %d, want %d", got, amount)
	}

	before := s.State()
	if _, err := bob.InvokeSC(ctx, "ccc3", anchor.Arguments{}, 0, amount, 16, 0); err == nil {
		t.Fatal("bob unwrapped tokens owned by alice")
	}
	if after := s.State(); !reflect.DeepEqual(after, before) {
		t.Fatalf("refused cross-wallet unwrap mutated state:\nbefore=%+v\nafter=%+v", before, after)
	}

	if _, err := alice.InvokeSC(ctx, "ccc3", anchor.Arguments{}, 0, amount, 16, 0); err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if got := s.WDEROSupply(); got != 0 {
		t.Fatalf("supply after unwrap = %d, want 0", got)
	}
	if got := s.TokenBalance("alice", "wDERO"); got != 0 {
		t.Fatalf("alice wDERO after unwrap = %d, want 0", got)
	}
	if got := s.Balance("alice"); got != 1_000_000*100_000 {
		t.Fatalf("alice DERO after unwrap = %d, want original balance", got)
	}
}

func TestGetTransfersDirectionFilter(t *testing.T) {
	_, _, alice, bob := newTestSim(t)
	ctx := context.Background()
	bobAddr, err := bob.GetAddress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.PostPayloadAmount(ctx, bobAddr, anchor.Arguments{{Name: "K", DataType: anchor.DataHash, Value: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}}, 100); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		client *dero.Client
		params dero.GetTransfersParams
		want   int
	}{{"sender in", alice, dero.GetTransfersParams{In: true}, 0},
		{"sender out", alice, dero.GetTransfersParams{Out: true}, 1},
		{"recipient in", bob, dero.GetTransfersParams{In: true}, 1},
		{"recipient out", bob, dero.GetTransfersParams{Out: true}, 0}} {
		entries, err := tc.client.GetTransfers(ctx, tc.params)
		if err != nil || len(entries) != tc.want {
			t.Errorf("%s entries = %d, %v; want %d", tc.name, len(entries), err, tc.want)
		}
	}
}

func TestZeroAddressTransferAdvancesHeightWithoutMisrouting(t *testing.T) {
	s, _, alice, _ := newTestSim(t)
	ctx := context.Background()
	beforeAlice, beforeBob := s.Balance("alice"), s.Balance("bob")
	if _, err := alice.PostPayloadAmount(ctx, ZeroAddress, anchor.Arguments{{Name: "K", DataType: anchor.DataHash, Value: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}}, 100); err != nil {
		t.Fatal(err)
	}
	if got := s.Balance("alice"); got != beforeAlice-100 {
		t.Fatalf("alice after transfer to unknown address = %d, want %d", got, beforeAlice-100)
	}
	if got := s.Balance("bob"); got != beforeBob {
		t.Fatalf("unknown destination credited bob: %d -> %d", beforeBob, got)
	}
	if got := heightOf(s); got != 1 {
		t.Fatalf("height = %d, want 1", got)
	}
}

func TestAddWalletIsIdempotent(t *testing.T) {
	s, _, _, _ := newTestSim(t)
	before := s.State()
	s.AddWallet("alice")
	s.AddWallet("")
	s.AddWallet("  ")
	if after := s.State(); !reflect.DeepEqual(after, before) {
		t.Fatalf("AddWallet changed simulator state:\nbefore=%+v\nafter=%+v", before, after)
	}
}
