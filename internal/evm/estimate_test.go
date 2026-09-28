// Tests for the MyceliumMailbox gas-cost estimator (estimate.go).
//
// The stub node quotes deterministic gas per operation shape and can be told
// to revert the burn estimate — the situation every real node hits against a
// fresh deployment, since burn(to,seq) on a missing message reverts. The
// assertions pin the three honesty properties: exact param shapes, the
// labeled burn fallback, and pricing that respects a price override instead
// of trusting the node.
package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type estimateStub struct {
	mu       sync.Mutex
	burnErr  bool
	lastData map[string]string // method -> calldata/data param seen
}

func (s *estimateStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		defer s.mu.Unlock()
		var res interface{}
		switch req.Method {
		case "eth_chainId":
			res = "0x2105" // Base mainnet
		case "eth_gasPrice":
			res = "0x3b9aca00" // 1 gwei
		case "eth_estimateGas":
			var p map[string]interface{}
			_ = json.Unmarshal(req.Params[0], &p)
			data, _ := p["data"].(string)
			to, _ := p["to"].(string)
			from, _ := p["from"].(string)
			if s.lastData == nil {
				s.lastData = map[string]string{}
			}
			s.lastData["from"] = from
			switch {
			case to == "": // creation estimate (no `to` field at all)
				if _, has := p["to"]; has {
					res = "0x0"
					break
				}
				s.lastData["deploy"] = data
				res = "0x3d0900" // 4000000
			case to == mailboxFixtureAddr:
				if len(data) >= 10 && data[:10] == "0x"+hex.EncodeToString(burnSelector[:]) {
					if s.burnErr {
						w.WriteHeader(http.StatusOK)
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"jsonrpc": "2.0", "id": 1,
							"error": map[string]interface{}{"code": -32000, "message": "execution reverted: mailbox: only recipient"},
						})
						return
					}
					res = "0x88b8" // 35000 — would only happen on a funded slot
					break
				}
				s.lastData["deliver"] = data
				res = "0xb686" // 46726
			default:
				res = "0x5208"
			}
		default:
			res = nil
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "result": res,
		})
	})
}

// mailboxFixtureAddr is any syntactically valid 20-byte address; the stub
// keys its selector routing off it.
const mailboxFixtureAddr = "0x1111111111111111111111111111111111111111"

func TestEstimateMyceliumCostsPricedShapesAndFallback(t *testing.T) {
	s := &estimateStub{burnErr: true}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	b := NewBackend(srv.URL, "evm-test", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	est, err := b.EstimateMyceliumCostsPriced(
		context.Background(), SyntheticRecipient, mailboxFixtureAddr, "6080604052", EstimatePayloadBytes, nil)
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}

	if est.ChainID == nil || est.ChainID.Int64() != 0x2105 {
		t.Fatalf("chainid = %v, want 0x2105", est.ChainID)
	}
	if est.GasPriceWei == nil || est.GasPriceWei.Int64() != 1_000_000_000 {
		t.Fatalf("gas price = %v, want 1 gwei", est.GasPriceWei)
	}
	if est.DeployGas != 4_000_000 {
		t.Fatalf("deploy gas = %d, want 4000000", est.DeployGas)
	}
	if est.DeliverGas != 46_726 {
		t.Fatalf("deliver gas = %d, want 46726", est.DeliverGas)
	}
	if est.BurnGas != BurnGasFallback || est.BurnMode == "" {
		t.Fatalf("burn gas/mode = %d/%q, want the labeled fallback", est.BurnGas, est.BurnMode)
	}
	if est.From != "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("estimates must be quoted for the backend's from, got %q", est.From)
	}

	// The deploy estimate must be a creation tx: data present, no `to`.
	// The stub asserts the missing `to` by construction (4000000 only comes
	// from the no-to branch), so here we pin the calldata shapes.
	if got := s.lastData["deploy"]; got == "" || len(got) < 10 {
		t.Fatalf("deploy estimate carried no creation data: %q", got)
	}
	deliver := s.lastData["deliver"]
	wantSel := "0x" + hex.EncodeToString(deliverSelector[:])
	if len(deliver) < 10 || deliver[:10] != wantSel {
		t.Fatalf("deliver calldata selector = %q, want %s…", deliver, wantSel)
	}
	// Payload sizing: selector + 3 head words (100 bytes) + the 116-byte
	// payload + 8 bytes padding — encodeDeliver pads the whole buffer to a
	// 32-byte boundary, and this is exactly the calldata PostPayload sends.
	if got, want := (len(deliver)-2)/2, 100+116+8; got != want {
		t.Fatalf("deliver calldata = %d bytes, want %d (116-byte payload)", got, want)
	}
}

func TestEstimateBurnFallbackNote(t *testing.T) {
	s := &estimateStub{burnErr: true}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	b := NewBackend(srv.URL, "evm-test", "")
	est, err := b.EstimateMyceliumCostsPriced(
		context.Background(), SyntheticRecipient, mailboxFixtureAddr, "6080", EstimatePayloadBytes, nil)
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	found := false
	for _, n := range est.Notes {
		if len(n) > 22 && n[:22] == "burn eth_estimateGas r" {
			found = true
		}
	}
	if !found {
		t.Fatalf("burn refusal must be surfaced in Notes, got %v", est.Notes)
	}
	if est.BurnMode == "" || est.BurnGas != BurnGasFallback {
		t.Fatalf("fallback must be labeled: gas=%d mode=%q", est.BurnGas, est.BurnMode)
	}
}

func TestEstimateWithoutMailboxSkipsRounds(t *testing.T) {
	s := &estimateStub{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	b := NewBackend(srv.URL, "evm-test", "")
	est, err := b.EstimateMyceliumCostsPriced(
		context.Background(), SyntheticRecipient, "", "6080604052", EstimatePayloadBytes, nil)
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if est.DeployGas == 0 {
		t.Fatal("deploy row must still be priced")
	}
	if est.DeliverGas != 0 || est.BurnGas != 0 {
		t.Fatalf("deliver/burn must stay zero without a mailbox: %d/%d", est.DeliverGas, est.BurnGas)
	}
	if est.TotalWei(12) != nil {
		t.Fatal("funding total must be nil when deliver/burn were never priced")
	}
}

func TestEstimatePriceOverride(t *testing.T) {
	s := &estimateStub{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()

	b := NewBackend(srv.URL, "evm-test", "")
	override := big.NewInt(2_000_000_000) // 2 gwei — node says 1
	est, err := b.EstimateMyceliumCostsPriced(
		context.Background(), SyntheticRecipient, mailboxFixtureAddr, "6080", EstimatePayloadBytes, override)
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if !est.GasPriceOverride {
		t.Fatal("GasPriceOverride must be true when a price override is given")
	}
	if est.GasPriceWei.Cmp(override) != 0 {
		t.Fatalf("price = %s, want the override %s", est.GasPriceWei, override)
	}
	// burn estimate succeeds in this stub → all rows live → total exists.
	if est.TotalWei(1) == nil {
		t.Fatal("funding total must exist when all rows are priced")
	}
}

func TestFormatWei(t *testing.T) {
	cases := []struct {
		wei  *big.Int
		want string
	}{
		{big.NewInt(0), "0 ETH"},
		{new(big.Int).Mul(big.NewInt(1), weiPerEth), "1 ETH"},
		{new(big.Int).Div(weiPerEth, big.NewInt(2)), "0.5 ETH"},
		{big.NewInt(1_050_000), "0.00000000000105 ETH"},
		{new(big.Int).Mul(big.NewInt(123), weiPerEth), "123 ETH"},
	}
	for _, c := range cases {
		if got := FormatWei(c.wei); got != c.want {
			t.Errorf("FormatWei(%s) = %q, want %q", c.wei, got, c.want)
		}
	}
}
