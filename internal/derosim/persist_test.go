package derosim

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

const (
	testHTLCSC  = "sim-htlc-00000000000000000000000000000000000000000000000000000000000001"
	testDEXSC   = "sim-dex-000000000000000000000000000000000000000000000000000000000000002"
	testWDEROSC = "sim-wdero-0000000000000000000000000000000000000000000000000000000003"
)

// rpcCall posts one wallet RPC to the route and returns the decoded envelope.
func rpcCall(t *testing.T, s *Sim, route, method string, params any) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "0", "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/w/"+route+"/json_rpc", bytes.NewReader(body))
	s.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: bad response %q: %v", method, rec.Body.String(), err)
	}
	return out
}

func transferParams(dest string, amount uint64, text string) map[string]any {
	return map[string]any{
		"transfers": []any{map[string]any{
			"destination": dest,
			"amount":      amount,
			"payload_rpc": []any{
				map[string]any{"name": "W", "datatype": "U", "value": 1393},
				map[string]any{"name": "T", "datatype": "S", "value": text},
			},
		}},
		"ringsize": 16,
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenState(path, testHTLCSC, testDEXSC, testWDEROSC)
	if err != nil {
		t.Fatal(err)
	}
	s.AddWallet("alice")
	s.AddWallet("bob")
	bob := s.Address("bob")

	rpcCall(t, s, "alice", "transfer", transferParams(bob, 7, "first"))
	second := rpcCall(t, s, "alice", "transfer", transferParams(bob, 9, "second"))
	s.Bump(5)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	r, err := OpenState(path, testHTLCSC, testDEXSC, testWDEROSC)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	r.AddWallet("alice")
	r.AddWallet("bob")

	if got, want := r.Balance("alice"), s.Balance("alice"); got != want {
		t.Fatalf("alice balance after restart = %d, want %d", got, want)
	}
	if got, want := r.Balance("bob"), s.Balance("bob"); got != want {
		t.Fatalf("bob balance after restart = %d, want %d", got, want)
	}
	if got, want := r.State().Height, s.State().Height; got != want {
		t.Fatalf("height after restart = %d, want %d", got, want)
	}

	// Bob's history holds both payloads, with the text intact.
	got := rpcCall(t, r, "bob", "get_transfers", map[string]any{"in": true})
	entries, _ := got["result"].(map[string]any)["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("bob incoming entries after restart = %d, want 2", len(entries))
	}
	last := entries[1].(map[string]any)
	if last["txid"] != second["result"].(map[string]any)["txid"] {
		t.Fatalf("second entry txid = %v, want %v", last["txid"], second["result"].(map[string]any)["txid"])
	}
	payload := last["payload_rpc"].([]any)
	if text := payload[1].(map[string]any)["value"]; text != "second" {
		t.Fatalf("payload text after restart = %v, want second", text)
	}
	if w := payload[0].(map[string]any)["value"]; w != float64(1393) {
		t.Fatalf("whisper marker after restart = %v, want 1393", w)
	}

	// The txid sequence continues rather than restarting at 1.
	next := rpcCall(t, r, "alice", "transfer", transferParams(bob, 1, "third"))
	if txid := next["result"].(map[string]any)["txid"]; txid != "sim-tx-00000003" {
		t.Fatalf("txid after restart = %v, want sim-tx-00000003", txid)
	}
}

func TestStateRestoresHTLC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenState(path, testHTLCSC, testDEXSC, testWDEROSC)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("secret"))
	var key [32]byte
	copy(key[:], hash[:])
	s.htlcs[key] = &htlcState{amount: 42, funder: "alice", recipient: "bob", expiry: 100, claimed: true}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	r, err := OpenState(path, testHTLCSC, testDEXSC, testWDEROSC)
	if err != nil {
		t.Fatal(err)
	}
	claimed, refunded, ok := r.HTLCSettled(hex.EncodeToString(key[:]))
	if !ok || !claimed || refunded {
		t.Fatalf("HTLC after restart: claimed=%v refunded=%v ok=%v, want claimed and found", claimed, refunded, ok)
	}
}

func TestOpenStateRefusesOtherContracts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenState(path, testHTLCSC, testDEXSC, testWDEROSC)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(path, testHTLCSC, "sim-dex-other", testWDEROSC); err == nil {
		t.Fatal("expected refusal for a state file written under different contract IDs")
	}
}

func TestOpenStateMissingFileStartsFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	s, err := OpenState(path, testHTLCSC, testDEXSC, testWDEROSC)
	if err != nil {
		t.Fatalf("missing file should start fresh, got %v", err)
	}
	if s.Address("alice") != "" {
		t.Fatal("fresh state should have no wallets until AddWallet")
	}
	if _, err := OpenState("", testHTLCSC, testDEXSC, testWDEROSC); err == nil {
		t.Fatal("expected error for empty state path")
	}
}
