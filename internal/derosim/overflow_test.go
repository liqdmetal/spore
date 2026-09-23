package derosim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

// The tests here cover derosim's hardening contract: refused invocations are
// ATOMIC (no balance, height, ledger, or contract-state side effects) and
// every uint64 credit/debit path refuses to overflow rather than wrapping —
// the failure modes a soak must never inherit from its simulator.

func heightOf(s *Sim) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.height
}

func setBalance(s *Sim, route string, bal uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.balances[route].balance = bal
}

func setReserves(s *Sim, a, b uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.poolA, s.poolB = a, b
}

func setTokenBalance(s *Sim, route, token string, balance uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.balances[route].tokens[strings.ToLower(token)] = balance
}

func setFeeUnits(s *Sim, fee uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.feeDS = fee
}

func feeUnits(s *Sim) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.feeDS
}

// twoWallets wires a sim with alice and bob behind one HTTP server and
// returns a client for each.
func twoWallets(t *testing.T) (*Sim, *dero.Client, *dero.Client) {
	t.Helper()
	s := New("aaa1", "bbb2", "ccc3")
	s.AddWallet("alice")
	s.AddWallet("bob")
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s,
		dero.NewClient(srv.URL+"/w/alice", "", ""),
		dero.NewClient(srv.URL+"/w/bob", "", "")
}

func TestTransferCreditOverflowRefused(t *testing.T) {
	s, alice, _ := twoWallets(t)
	ctx := context.Background()

	filler := anchor.Arguments{{Name: "K", DataType: anchor.DataHash, Value: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}}

	// bob sits at the uint64 ceiling; any credit would wrap.
	setBalance(s, "bob", math.MaxUint64)
	// alice can afford exactly the amount we will try to send.
	setBalance(s, "alice", math.MaxUint64-10)
	amount := uint64(math.MaxUint64) - 10

	h0 := heightOf(s)
	_, err := alice.PostPayloadAmount(ctx, s.Address("bob"), filler, amount)
	if err == nil {
		t.Fatal("transfer that would overflow the recipient's balance was accepted")
	}
	if got := s.Balance("bob"); got != math.MaxUint64 {
		t.Fatalf("refused transfer mutated bob's balance: %d", got)
	}
	if got := s.Balance("alice"); got != math.MaxUint64-10 {
		t.Fatalf("refused transfer debited the sender: %d", got)
	}
	if h := heightOf(s); h != h0 {
		t.Fatalf("refused transfer consumed a block: height %d -> %d", h0, h)
	}

	// A modest transfer still works after the refusal: the state machine is
	// not wedged by the rejected call. (Bob keeps the ceiling here, so give
	// him headroom first — the point is that transfers still LAND.)
	setBalance(s, "bob", 1000)
	aliceBal := s.Balance("alice")
	if _, err := alice.PostPayloadAmount(ctx, s.Address("bob"), filler, 5); err != nil {
		t.Fatalf("small transfer after refused one: %v", err)
	}
	if got := s.Balance("bob"); got != 1005 {
		t.Fatalf("bob balance after small transfer = %d, want 1005", got)
	}
	if got := s.Balance("alice"); got != aliceBal-5 {
		t.Fatalf("alice balance after small transfer = %d, want %d", got, aliceBal-5)
	}
}

func TestTransferBatchRollsBackAtomicallyOnRefusal(t *testing.T) {
	cases := []struct {
		name         string
		aliceBalance uint64
		bobBalance   uint64
		amounts      [2]uint64
		wantError    string
	}{
		{name: "later leg exceeds sender balance", aliceBalance: 15, bobBalance: 1000, amounts: [2]uint64{10, 10}, wantError: "insufficient funds"},
		{name: "recipient credit overflows", aliceBalance: 1_000_000, bobBalance: math.MaxUint64, amounts: [2]uint64{10, 20}, wantError: "would overflow"},
		{name: "combined sender debit overflows", aliceBalance: math.MaxUint64, bobBalance: 0, amounts: [2]uint64{math.MaxUint64, 1}, wantError: "insufficient funds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, alice, bob := twoWallets(t)
			ctx := context.Background()
			setBalance(s, "alice", tc.aliceBalance)
			setBalance(s, "bob", tc.bobBalance)
			before := s.State()
			bobAddr, err := bob.GetAddress(ctx)
			if err != nil {
				t.Fatal(err)
			}

			payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":"1","method":"transfer","params":{"transfers":[
				{"destination":%q,"amount":%d},
				{"destination":%q,"amount":%d}
			]}}`, bobAddr, tc.amounts[0], bobAddr, tc.amounts[1])
			res := postJSON(t, s, "alice", payload)
			if !strings.Contains(res, tc.wantError) {
				t.Fatalf("expected %q refusal, got: %s", tc.wantError, res)
			}
			if after := s.State(); !reflect.DeepEqual(after, before) {
				t.Fatalf("refused batch mutated simulator state:\nbefore=%+v\nafter=%+v", before, after)
			}
			for _, query := range []struct {
				name   string
				client *dero.Client
				params dero.GetTransfersParams
			}{{"recipient incoming", bob, dero.GetTransfersParams{In: true}}, {"sender outgoing", alice, dero.GetTransfersParams{Out: true}}} {
				entries, err := query.client.GetTransfers(ctx, query.params)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatalf("refused batch leaked %d %s ledger entries", len(entries), query.name)
				}
			}
		})
	}
}

func postJSON(t *testing.T, s *Sim, route, payload string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/w/"+route+"/json_rpc", io.NopCloser(bytes.NewReader([]byte(payload))))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Body.String()
}

func TestHTLCClaimPayoutOverflowRefused(t *testing.T) {
	s, alice, _ := twoWallets(t)
	ctx := context.Background()

	preimage := make([]byte, 32)
	hash := sha256.Sum256(preimage)
	hashHex, preHex := hex.EncodeToString(hash[:]), hex.EncodeToString(preimage)

	setBalance(s, "bob", math.MaxUint64) // any payout would wrap
	var events []Entry
	s.Poster = func(route, kind string, entry Entry) {
		// The observer may query the simulator; callbacks must run outside mu.
		_ = s.State()
		events = append(events, entry)
	}
	if _, err := alice.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
		{Name: "recipient", DataType: anchor.DataString, Value: s.Address("bob")},
		{Name: "exp", DataType: anchor.DataUint64, Value: uint64(1_000_000)},
	}, 100, 0, 16, 0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	a0 := s.Balance("alice")

	beforeRefused := s.State()
	if _, err := alice.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
		{Name: "pre", DataType: anchor.DataHash, Value: preHex},
	}, 0, 0, 16, 0); err == nil {
		t.Fatal("claim whose payout would overflow the recipient was accepted")
	}
	if afterRefused := s.State(); !reflect.DeepEqual(afterRefused, beforeRefused) {
		t.Fatalf("refused claim mutated simulator state:\nbefore=%+v\nafter=%+v", beforeRefused, afterRefused)
	}
	if len(events) != 1 {
		t.Fatalf("refused claim triggered a poster callback: %d events", len(events)-1)
	}
	if claimed, refunded, ok := s.HTLCSettled(hashHex); !ok || claimed || refunded {
		t.Fatalf("refused claim settled the HTLC: claimed=%v refunded=%v ok=%v", claimed, refunded, ok)
	}
	if got := s.Balance("bob"); got != math.MaxUint64 {
		t.Fatalf("refused claim credited the recipient: %d", got)
	}
	if got := s.Balance("alice"); got != a0 {
		t.Fatalf("refused claim changed the funder: %d -> %d", a0, got)
	}

	// With headroom the same claim succeeds — the refusal is conditional on
	// the overflow, not on the claim itself.
	setBalance(s, "bob", 0)
	h0 := heightOf(s)
	if _, err := alice.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
		{Name: "pre", DataType: anchor.DataHash, Value: preHex},
	}, 0, 0, 16, 0); err != nil {
		t.Fatalf("claim with headroom: %v", err)
	}
	if got := s.Balance("bob"); got != 100 {
		t.Fatalf("bob balance after claim = %d, want 100", got)
	}
	if got := heightOf(s); got != h0+1 {
		t.Fatalf("valid claim after rejected claim did not consume one block: %d -> %d", h0, got)
	}
	if len(events) != 2 || events[0].TXID != "sim-tx-00000001" || events[1].TXID != "sim-tx-00000002" {
		t.Fatalf("poster should observe only the committed fund and claim, got %+v", events)
	}
}

func TestHTLCRefundPaysRecordedFunder(t *testing.T) {
	s, alice, bob := twoWallets(t)
	ctx := context.Background()

	preimage := make([]byte, 32)
	hash := sha256.Sum256(preimage)
	hashHex := hex.EncodeToString(hash[:])

	if _, err := alice.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
		{Name: "recipient", DataType: anchor.DataString, Value: s.Address("bob")},
		{Name: "exp", DataType: anchor.DataUint64, Value: uint64(1)},
	}, 250_000, 0, 16, 0); err != nil {
		t.Fatal(err)
	}
	// Expire the HTLC, then have BOB (not the funder) attempt the refund:
	// the funds must return to the RECORDED funder, never to the caller.
	s.Bump(5)
	b0 := s.Balance("bob")
	if _, err := bob.InvokeSC(ctx, "aaa1", anchor.Arguments{
		{Name: "h", DataType: anchor.DataHash, Value: hashHex},
	}, 0, 0, 16, 0); err != nil {
		t.Fatalf("refund after expiry: %v", err)
	}
	if got := s.Balance("bob"); got != b0 {
		t.Fatalf("refund paid the caller: bob %d -> %d", b0, got)
	}
	if got := s.Balance("alice"); got != 1_000_000*100_000 {
		t.Fatalf("refund did not return funds to the recorded funder: alice = %d", got)
	}
	if claimed, refunded, _ := s.HTLCSettled(hashHex); claimed || !refunded {
		t.Fatalf("refund settlement flags wrong: claimed=%v refunded=%v", claimed, refunded)
	}
}

func TestSwapRejectsReserveOverflowAndUsesBigMath(t *testing.T) {
	s, alice, _ := twoWallets(t)
	ctx := context.Background()
	swap := func(mo, deposit uint64) error {
		_, err := alice.InvokeSC(ctx, "bbb2", anchor.Arguments{
			{Name: "ta", DataType: anchor.DataString, Value: "tA"},
			{Name: "tb", DataType: anchor.DataString, Value: "tB"},
			{Name: "mo", DataType: anchor.DataUint64, Value: mo},
		}, 0, deposit, 16, 0)
		return err
	}

	a0, b0 := s.PoolReserves()
	f0 := feeUnits(s)
	if err := swap(1, math.MaxUint64); err == nil {
		t.Fatal("swap input that would overflow the pool reserve was accepted")
	}
	if a, b := s.PoolReserves(); a != a0 || b != b0 {
		t.Fatalf("refused swap mutated reserves: %d/%d -> %d/%d", a0, b0, a, b)
	}
	if f := feeUnits(s); f != f0 {
		t.Fatalf("refused swap accumulated fee: %d -> %d", f0, f)
	}

	// Big.Int is required when reserveOut*input exceeds uint64 even though
	// the final output and both resulting reserves still fit.
	setReserves(s, 1_000_000, 1<<63)
	setTokenBalance(s, "alice", "ta", 1<<63)
	deposit := uint64(1) << 63
	if err := swap(1, deposit); err != nil {
		t.Fatalf("big-math swap refused: %v", err)
	}
	fee := deposit/1000*3 + deposit%1000*3/1000
	inAfterFee := deposit - fee
	num := new(big.Int).Mul(big.NewInt(0).SetUint64(1<<63), big.NewInt(0).SetUint64(inAfterFee))
	den := big.NewInt(0).Add(big.NewInt(0).SetUint64(1_000_000), big.NewInt(0).SetUint64(inAfterFee))
	wantOut := num.Quo(num, den).Uint64()
	a1, b1 := s.PoolReserves()

	if a1 != 1_000_000+deposit {
		t.Fatalf("poolA = %d, want %d", a1, 1_000_000+deposit)
	}
	if b1 != (1<<63)-wantOut {
		t.Fatalf("poolB = %d, want %d (constant-product output drifted)", b1, (1<<63)-wantOut)
	}
}

func TestHeightExhaustionRefusesAndBumpCaps(t *testing.T) {
	s, alice, _ := twoWallets(t)
	ctx := context.Background()

	// Bump past the cap: height must clamp, never wrap.
	s.Bump(maxSimHeight + 10)
	if got := heightOf(s); got != maxSimHeight {
		t.Fatalf("Bump overflowed the sim height: %d", got)
	}
	s2, _, _ := twoWallets(t)
	s2.Bump(maxSimHeight - 1)
	s2.Bump(10)
	if got := heightOf(s2); got != maxSimHeight {
		t.Fatalf("Bump near the cap wrapped instead of clamping: %d", got)
	}
	if _, err := alice.InvokeSC(ctx, "aaa1", anchor.Arguments{}, 1, 0, 16, 0); err == nil {
		t.Fatal("invoke accepted with the chain at max height")
	}
	if _, err := alice.PostPayloadAmount(ctx, ZeroAddress, anchor.Arguments{}, 1); err == nil {
		t.Fatal("transfer accepted with the chain at max height")
	}
	if h := heightOf(s); h != maxSimHeight {
		t.Fatalf("refused calls at max height still consumed height: %d", h)
	}
}
