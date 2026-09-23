package sap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

// stubWallet answers sc_invoke with a fixed txid and records the decoded
// params so tests can assert the exact payload spore sends.
type stubWallet struct {
	invoke       int
	scid         string
	depositDero  uint64
	depositToken uint64
	args         anchor.Arguments
}

func newStubWallet(t *testing.T) (*dero.Client, *stubWallet) {
	t.Helper()
	st := &stubWallet{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("stub: decode request: %v", err)
			return
		}
		switch req.Method {
		case "sc_invoke":
			st.invoke++
			var p struct {
				SCID             string           `json:"scid"`
				SC_RPC           anchor.Arguments `json:"sc_rpc"`
				SC_DERO_Deposit  uint64           `json:"sc_dero_deposit"`
				SC_TOKEN_Deposit uint64           `json:"sc_token_deposit"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				t.Errorf("stub: decode sc_invoke params: %v", err)
				return
			}
			st.scid = p.SCID
			st.args = p.SC_RPC
			st.depositDero = p.SC_DERO_Deposit
			st.depositToken = p.SC_TOKEN_Deposit
			w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"txid":"stub-txid"}}`))
		default:
			t.Errorf("stub: unexpected method %q", req.Method)
		}
	}))
	t.Cleanup(srv.Close)
	return dero.NewClient(srv.URL, "", ""), st
}

func TestUnconfiguredContractRefusesBeforeAnyRPC(t *testing.T) {
	// Empty IDs must refuse LOCALLY: no sc_invoke hits the wallet. The old
	// behavior sent an empty-SCID invoke that the wallet rejects opaquely —
	// the exact failure mode the contract guard replaced.
	client, st := newStubWallet(t)

	if _, err := HTLCFund(context.Background(), client, [32]byte{1}, "dero1q recipient", 1000, 5, 16); err == nil {
		t.Fatal("HTLCFund with unconfigured contract must refuse")
	}
	if _, err := HTLCClaim(context.Background(), client, [32]byte{1}, [32]byte{2}, "dero1q recipient", 16); err == nil {
		t.Fatal("HTLCClaim with unconfigured contract must refuse")
	}
	if _, err := HTLCRefund(context.Background(), client, [32]byte{1}, 16); err == nil {
		t.Fatal("HTLCRefund with unconfigured contract must refuse")
	}
	if _, err := DEXSwap(context.Background(), client, "ta", "tb", 100, 16); err == nil {
		t.Fatal("DEXSwap with unconfigured contract must refuse")
	}
	if _, err := WrapDERO(context.Background(), client, 5, 16); err == nil {
		t.Fatal("WrapDERO with unconfigured contract must refuse")
	}
	if _, err := UnwrapDERO(context.Background(), client, 5, 16); err == nil {
		t.Fatal("UnwrapDERO with unconfigured contract must refuse")
	}
	if st.invoke != 0 {
		t.Fatalf("refusals must not touch the wallet: %d invokes fired", st.invoke)
	}
	// The refusal must say WHICH contract and WHICH env var, so the operator
	// can fix it in one step.
	_, err := WrapDERO(context.Background(), client, 5, 16)
	for _, want := range []string{"RelayWrappedDero", EnvWrappedDeroName} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q must mention %q", err, want)
		}
	}
}

func TestHTLCFundInvokeShape(t *testing.T) {
	client, st := newStubWallet(t)
	SetContractIDs("abc123", "", "")
	t.Cleanup(func() { SetContractIDs("", "", "") })

	if _, err := HTLCFund(context.Background(), client, [32]byte{1}, "dero1q recipient", 1000, 5, 16); err != nil {
		t.Fatalf("HTLCFund: %v", err)
	}
	if st.invoke != 1 {
		t.Fatalf("invoke count = %d, want 1", st.invoke)
	}
	if st.scid != "abc123" {
		t.Fatalf("scid = %q, want the configured HTLC ID", st.scid)
	}
	if st.depositDero != 5 {
		t.Fatalf("sc_dero_deposit = %d, want the escrowed amount 5", st.depositDero)
	}
	// The DVM argument names are the wire contract — assert all three.
	want := map[string]bool{"h": false, "recipient": false, "exp": false}
	for _, a := range st.args {
		if _, ok := want[a.Name]; ok {
			want[a.Name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("sc_invoke args missing DVM argument %q: %+v", name, st.args)
		}
	}
}

func TestDEXSwapInvokeShape(t *testing.T) {
	client, st := newStubWallet(t)
	SetContractIDs("", "dexid", "")
	t.Cleanup(func() { SetContractIDs("", "", "") })

	if _, err := DEXSwap(context.Background(), client, "tokA", "tokB", 250, 16); err != nil {
		t.Fatalf("DEXSwap: %v", err)
	}
	if st.scid != "dexid" || st.depositDero != 0 || st.depositToken != 0 {
		t.Fatalf("swap deposit/scid wrong: scid=%q dero=%d token=%d", st.scid, st.depositDero, st.depositToken)
	}
	want := map[string]struct {
		name string
		val  interface{}
	}{
		"ta": {"ta", "tokA"},
		"tb": {"tb", "tokB"},
		"mo": {"mo", uint64(250)},
	}
	seen := map[string]bool{}
	for _, a := range st.args {
		switch a.Name {
		case "ta", "tb":
			if a.Value != want[a.Name].val {
				t.Fatalf("%s = %v, want %v", a.Name, a.Value, want[a.Name].val)
			}
		case "mo":
			// The stub re-decodes the JSON number as float64; the wire form is
			// the same integer. Compare numerically.
			got, ok := a.Value.(float64)
			if !ok || got != 250 {
				t.Fatalf("mo = %v (%T), want 250", a.Value, a.Value)
			}
		}
		seen[a.Name] = true
	}
	for _, n := range []string{"ta", "tb", "mo"} {
		if !seen[n] {
			t.Fatalf("swap args missing %q: %+v", n, st.args)
		}
	}
}

func TestWrapUnwrapDeposits(t *testing.T) {
	client, st := newStubWallet(t)
	SetContractIDs("", "", "wdid")
	t.Cleanup(func() { SetContractIDs("", "", "") })

	if _, err := WrapDERO(context.Background(), client, 7, 16); err != nil {
		t.Fatalf("WrapDERO: %v", err)
	}
	if st.depositDero != 7 || st.depositToken != 0 {
		t.Fatalf("wrap: dero deposit = %d token = %d, want 7/0", st.depositDero, st.depositToken)
	}
	before := st.invoke
	if _, err := UnwrapDERO(context.Background(), client, 7, 16); err != nil {
		t.Fatalf("UnwrapDERO: %v", err)
	}
	if st.invoke != before+1 {
		t.Fatalf("unwrap invoke count %d, want %d", st.invoke, before+1)
	}
	if st.depositDero != 0 || st.depositToken != 7 {
		t.Fatalf("unwrap: dero deposit = %d token = %d, want 0/7", st.depositDero, st.depositToken)
	}
	// Zero amounts are refused locally — a zero-value invoke is never what
	// the operator meant.
	if _, err := WrapDERO(context.Background(), client, 0, 16); err == nil {
		t.Fatal("WrapDERO(0) must refuse")
	}
	if _, err := UnwrapDERO(context.Background(), client, 0, 16); err == nil {
		t.Fatal("UnwrapDERO(0) must refuse")
	}
}

func TestEnvSeeding(t *testing.T) {
	t.Setenv(EnvHTLCSignature, "htlc-from-env")
	t.Setenv(EnvDEXSignature, "dex-from-env")
	t.Setenv(EnvWrappedDeroName, "wd-from-env")

	LoadContractIDsFromEnv()
	t.Cleanup(func() { SetContractIDs("", "", "") })

	h, d, w := ContractIDs()
	if h != "htlc-from-env" || d != "dex-from-env" || w != "wd-from-env" {
		t.Fatalf("env seeding: htlc=%q dex=%q wdero=%q", h, d, w)
	}
	// Trimmed values: an operator pasting a trailing space must not mint a
	// different contract ID.
	t.Setenv(EnvDEXSignature, "  dex-trimmed  ")
	LoadContractIDsFromEnv()
	if _, d, _ := ContractIDs(); d != "dex-trimmed" {
		t.Fatalf("env value not trimmed: %q", d)
	}
	// Unset env leaves current values (no clobbering of SetContractIDs).
	t.Setenv(EnvHTLCSignature, "")
	SetContractIDs("preset", "", "")
	LoadContractIDsFromEnv()
	if h, _, _ := ContractIDs(); h != "preset" {
		t.Fatalf("empty env clobbered a preset: %q", h)
	}
}
