package xmr

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testTxID      = "c7128110b5442bca7b20f3f921a154749e76f89c35022c9201e270763b8ac438"
	testAddress   = "4AseVYawZMf7mfeYqbLvKbKfXAVDZLM3c2XC8j6j12xpDvrkhMX4CQw3hUqa3i5L2se8YZ3ztgeMA5yU2DNEsP8cHF8VNDo"
	testMessage   = "spore.job-receipt/v1 tx-proof 9d0bca3490a0ae0e1e5c4a0e5a0e5a0e"
	testSignature = "InProofV2synthetic"
)

// The request must carry the proof verbatim, and the answer is read field by
// field — a verifier that misreads `received` cannot check the amount the record
// claims, which is the whole point of asking.
func TestCheckTxProofSendsTheProofAndReadsTheAnswer(t *testing.T) {
	var method string
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("mock wallet got an undecodable request: %v", err)
		}
		method, got = req.Method, req.Params
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"good":true,"received":181978330000,"in_pool":false,"confirmations":30845}}`))
	}))
	defer srv.Close()

	chk, err := CheckTxProof(context.Background(), srv.URL, "", testTxID, testAddress, testMessage, testSignature)
	if err != nil {
		t.Fatalf("CheckTxProof: %v", err)
	}
	if method != "check_tx_proof" {
		t.Errorf("called %q, want check_tx_proof", method)
	}
	for k, want := range map[string]string{
		"txid": testTxID, "address": testAddress, "message": testMessage, "signature": testSignature,
	} {
		if got[k] != want {
			t.Errorf("the wallet was asked %s=%v, want %q", k, got[k], want)
		}
	}
	if !chk.Good || chk.Received != 181978330000 || chk.Confirmations != 30845 || chk.InPool {
		t.Errorf("answer misread: %+v", chk)
	}
}

// A wallet that verifies the proof and finds it good for nothing is answering
// the question — it is the caller's job (tally) to call that a failed proof.
func TestCheckTxProofGoodFalseIsAnAnswerNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"good":false,"received":0,"in_pool":false,"confirmations":0}}`))
	}))
	defer srv.Close()

	chk, err := CheckTxProof(context.Background(), srv.URL, "", testTxID, testAddress, testMessage, testSignature)
	if err != nil {
		t.Fatalf("good:false is a verdict, not a failure to check: %v", err)
	}
	if chk.Good {
		t.Error("good:false came back true")
	}
}

// The distinction the caller depends on: a wallet that REFUSES the proof
// ("Signature decoding error", "Invalid address") is a verdict about the proof.
func TestCheckTxProofRejectionIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"Signature decoding error"}}`))
	}))
	defer srv.Close()

	_, err := CheckTxProof(context.Background(), srv.URL, "", testTxID, testAddress, testMessage, testSignature)
	if err == nil {
		t.Fatal("a rejected proof must be an error")
	}
	if !errors.Is(err, ErrProofRejected) {
		t.Fatalf("want ErrProofRejected, got %v", err)
	}
	if !strings.Contains(err.Error(), "Signature decoding error") {
		t.Errorf("the wallet's own reason should survive: %v", err)
	}
}

// "Could not ask" is not "no": an unreachable wallet must never be read as a
// rejected proof, or a tally would silently refuse every honest receipt.
func TestCheckTxProofUnreachableIsNotARejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := CheckTxProof(context.Background(), url, "", testTxID, testAddress, testMessage, testSignature)
	if err == nil {
		t.Fatal("an unreachable wallet must be an error")
	}
	if errors.Is(err, ErrProofRejected) {
		t.Errorf("an unreachable wallet read as a rejected proof: %v", err)
	}
}

// A malformed response is a failure to check, not a verdict either.
func TestCheckTxProofGarbageBodyIsNotARejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>a proxy, probably</html>`))
	}))
	defer srv.Close()

	_, err := CheckTxProof(context.Background(), srv.URL, "", testTxID, testAddress, testMessage, testSignature)
	if err == nil {
		t.Fatal("a non-JSON answer must be an error")
	}
	if errors.Is(err, ErrProofRejected) {
		t.Errorf("a garbled answer read as a rejected proof: %v", err)
	}
}

// The signing half of the pair: the wallet must be asked for a proof with the
// caller's message verbatim, and the signature it returns is the whole point.
// A request that dropped or rewrote the message would produce a proof about
// something else, which would then verify against nothing.
func TestGetTxProofSendsTheMessageAndReturnsTheSignature(t *testing.T) {
	var method string
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("mock wallet got an undecodable request: %v", err)
		}
		method, got = req.Method, req.Params
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"signature":"InProofV2synthetic"}}`))
	}))
	defer srv.Close()

	sig, err := GetTxProof(context.Background(), srv.URL, "", testTxID, testAddress, testMessage)
	if err != nil {
		t.Fatalf("GetTxProof: %v", err)
	}
	if method != "get_tx_proof" {
		t.Errorf("called %q, want get_tx_proof", method)
	}
	for k, want := range map[string]string{"txid": testTxID, "address": testAddress, "message": testMessage} {
		if got[k] != want {
			t.Errorf("the wallet was asked %s=%v, want %q", k, got[k], want)
		}
	}
	if sig != "InProofV2synthetic" {
		t.Errorf("signature = %q", sig)
	}
}

// An empty signature is not a proof, and passing the empty string on would let a
// record look evidenced while verifying against nothing.
func TestGetTxProofEmptySignatureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"signature":""}}`))
	}))
	defer srv.Close()

	if _, err := GetTxProof(context.Background(), srv.URL, "", testTxID, testAddress, testMessage); err == nil {
		t.Fatal("an empty signature was accepted as a proof")
	}
}

// A wallet that will not sign (a txid it does not hold, an address that is not
// its own) is a verdict the caller must be able to tell apart from an unreachable
// wallet: the first means no evidence exists here, the second means nobody asked.
func TestGetTxProofRejectionIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"Transaction not found"}}`))
	}))
	defer srv.Close()

	_, err := GetTxProof(context.Background(), srv.URL, "", testTxID, testAddress, testMessage)
	if err == nil {
		t.Fatal("a refused get_tx_proof must be an error")
	}
	if !errors.Is(err, ErrProofRejected) {
		t.Fatalf("want ErrProofRejected, got %v", err)
	}
	if !strings.Contains(err.Error(), "Transaction not found") {
		t.Errorf("the wallet's own reason should survive: %v", err)
	}
}
