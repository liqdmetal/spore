package main

// End-to-end tests for the optional tx_proof block and `tally -proofs`
// (docs/JOB_RECEIPT_V1.md §7, docs/MONERO_SETTLEMENT.md §4).
//
// The wallet here is a mock in the shape of monero-wallet-rpc's check_tx_proof:
// it verifies the proof it was told to expect and refuses anything else with the
// error a real wallet answers. That matters, because the failure this feature
// exists to rule out is a receipt that LOOKS chain-backed — a proof taken for
// another payment, an amount edited after the proof was made, or a check that
// never reached a wallet at all.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/liqdmetal/spore/internal/jobreceipt"
)

const (
	txProofTxID    = "c7128110b5442bca7b20f3f921a154749e76f89c35022c9201e270763b8ac438"
	txProofAddress = "4AseVYawZMf7mfeYqbLvKbKfXAVDZLM3c2XC8j6j12xpDvrkhMX4CQw3hUqa3i5L2se8YZ3ztgeMA5yU2DNEsP8cHF8VNDo"
	txProofSig     = "InProofV2synthetic-signature"
	txProofAmount  = "181978330000"
)

// txProofWalletMock stands in for the wallet that RECEIVED the payment. It
// refuses a proof that is not the one it was told about — a different
// signature, a message bound to another record — in the wallet's own words.
func txProofWalletMock(t *testing.T, wantMessage, wantSig string, good bool, received uint64) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
			Params struct {
				TxID      string `json:"txid"`
				Address   string `json:"address"`
				Message   string `json:"message"`
				Signature string `json:"signature"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.Method != "check_tx_proof" {
			t.Errorf("mock wallet got method %q body %s", req.Method, body)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"unsupported method"}}`))
			return
		}
		calls.Add(1)
		p := req.Params
		if p.TxID != txProofTxID || p.Address != txProofAddress || p.Message != wantMessage || p.Signature != wantSig {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"Signature decoding error"}}`))
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"good":%v,"received":%d,"in_pool":false,"confirmations":30845}}`, good, received)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestReceiptTxProofIsCarriedAndCheckedOnChain(t *testing.T) {
	bin := buildSporeBinary(t)
	clientKey, providerKey, _ := receiptSeedKeys(t)
	clientPub := signerFor(t, bin, clientKey)
	providerPub := signerFor(t, bin, providerKey)

	base := []string{"sign", "receipt", "create",
		"-service-category", "plumbing.emergency",
		"-service-summary", "replace valve",
		"-provider-pub", providerPub, "-client-pub", clientPub,
		"-started-at", "2026-10-27T15:00:00Z",
		"-finished-at", "2026-10-27T15:30:00Z",
		"-settlement", "rail=xmr,network=monero-mainnet,asset=xmr,amount=" + txProofAmount + ",txid=" + txProofTxID + ",settled=2026-10-27T15:29:00Z",
	}
	// runCreate is the one entry point: every record in these tests is built
	// from the same facts, so they all share one proof binding.
	runCreate := func(dir, name string, extra ...string) (string, error) {
		t.Helper()
		rec := filepath.Join(dir, name+".json")
		args := append(append([]string{}, base...), "-out", rec)
		args = append(args, extra...)
		return runSpore(t, bin, args...)
	}
	mustCreate := func(dir, name string, extra ...string) string {
		t.Helper()
		rec := filepath.Join(dir, name+".json")
		if out, err := runCreate(dir, name, extra...); err != nil {
			t.Fatalf("create %s: %v\n%s", name, err, out)
		}
		return rec
	}
	// A receipt counts only once both roles have signed it.
	signJob := func(rec string) {
		t.Helper()
		for role, key := range map[string]string{"provider": providerKey, "client": clientKey} {
			if out, err := runSpore(t, bin, "sign", "receipt", "sign", "-role", role, "-identity", key, "-file", rec); err != nil {
				t.Fatalf("sign %s as %s: %v\n%s", rec, role, err, out)
			}
		}
	}

	// Step 1: with no proof, create must print the exact message the wallet has
	// to sign. The binding is needed BEFORE the final record exists, because
	// attaching a proof changes the file.
	hintDir := t.TempDir()
	hintRec := mustCreate(hintDir, "job")
	hintBody, err := os.ReadFile(hintRec)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jobreceipt.Parse(hintBody)
	if err != nil {
		t.Fatalf("the record create wrote does not parse: %v", err)
	}
	binding, err := jobreceipt.ProofMessage(parsed)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: the wallet signs that message, and the proof goes INTO the record.
	srv, calls := txProofWalletMock(t, binding, txProofSig, true, 181978330000)
	proofDir := t.TempDir()
	proofed := mustCreate(proofDir, "job", "-txproof", "txid="+txProofTxID+",address="+txProofAddress+",signature="+txProofSig)
	body, err := os.ReadFile(proofed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := jobreceipt.Parse(body)
	if err != nil {
		t.Fatalf("a record carrying a proof must parse: %v", err)
	}
	p := got.Settlement[0].TxProof
	if p == nil {
		t.Fatal("the proof is not in the record")
	}
	if p.Message != binding {
		t.Errorf("create bound the proof to %q, want the record's own message %q", p.Message, binding)
	}
	if p.Scheme != jobreceipt.SchemeMoneroTxProofV1 || p.Address != txProofAddress || p.Signature != txProofSig {
		t.Errorf("proof block came out wrong: %+v", p)
	}
	// The binding must survive the attachment, or nothing could ever verify it.
	if again, err := jobreceipt.ProofMessage(got); err != nil {
		t.Fatal(err)
	} else if again != binding {
		t.Errorf("attaching the proof moved the binding: %q -> %q", binding, again)
	}

	signJob(proofed)
	tallyOut, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", proofDir, "-proofs", "-rpc", srv.URL)
	if err != nil {
		t.Fatalf("tally -proofs: %v\n%s", err, tallyOut)
	}
	for _, want := range []string{
		"pairs       1 distinct client(s) from 1 record(s)",
		"verified in the wallet (1 line(s): good, and received == amount_atomic)",
	} {
		if !strings.Contains(tallyOut, want) {
			t.Errorf("tally output missing %q:\n%s", want, tallyOut)
		}
	}
	if calls.Load() == 0 {
		t.Error("tally counted the receipt without asking any wallet")
	}

	t.Run("create prints the binding to ask the wallet for", func(t *testing.T) {
		out, err := runCreate(t.TempDir(), "hint")
		if err != nil {
			t.Fatalf("create: %v\n%s", err, out)
		}
		if !strings.Contains(out, binding) {
			t.Errorf("create did not print the message the wallet must sign:\n%s", out)
		}
		if !strings.Contains(out, "none attached") || !strings.Contains(out, "-txproof") {
			t.Errorf("create should say the evidence is optional, absent, and how to add it:\n%s", out)
		}
	})

	t.Run("a receipt with no proof does not count", func(t *testing.T) {
		dir := t.TempDir()
		signJob(mustCreate(dir, "job"))
		out, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", dir, "-proofs", "-rpc", srv.URL)
		if err == nil {
			t.Fatalf("an unproven receipt was counted anyway:\n%s", out)
		}
		if !strings.Contains(out, "no tx proof") {
			t.Errorf("want the missing-proof reason, got:\n%s", out)
		}
	})

	t.Run("a proof the wallet refuses does not count", func(t *testing.T) {
		dir := t.TempDir()
		signJob(mustCreate(dir, "job", "-txproof", "txid="+txProofTxID+",address="+txProofAddress+",signature=not-the-signature"))
		out, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", dir, "-proofs", "-rpc", srv.URL)
		if err == nil {
			t.Fatalf("a proof the wallet refused was counted:\n%s", out)
		}
		if !strings.Contains(out, "proof rejected by the wallet") {
			t.Errorf("want the wallet's rejection in the reason, got:\n%s", out)
		}
	})

	t.Run("a proof for a different amount does not count", func(t *testing.T) {
		// The substitution this check exists to catch: a real, valid proof for a
		// payment that is not the sum the record claims.
		cheap, _ := txProofWalletMock(t, binding, txProofSig, true, 999)
		dir := t.TempDir()
		signJob(mustCreate(dir, "job", "-txproof", "txid="+txProofTxID+",address="+txProofAddress+",signature="+txProofSig))
		out, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", dir, "-proofs", "-rpc", cheap.URL)
		if err == nil {
			t.Fatalf("a proof for another amount was counted:\n%s", out)
		}
		if !strings.Contains(out, "proof amount mismatch") {
			t.Errorf("want an amount mismatch in the reason, got:\n%s", out)
		}
	})

	t.Run("a proof that verifies false does not count", func(t *testing.T) {
		refusing, _ := txProofWalletMock(t, binding, txProofSig, false, 181978330000)
		dir := t.TempDir()
		signJob(mustCreate(dir, "job", "-txproof", "txid="+txProofTxID+",address="+txProofAddress+",signature="+txProofSig))
		out, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", dir, "-proofs", "-rpc", refusing.URL)
		if err == nil {
			t.Fatalf("good:false was counted:\n%s", out)
		}
		if !strings.Contains(out, "proof did not verify") {
			t.Errorf("want a failed verification in the reason, got:\n%s", out)
		}
	})

	t.Run("an unreachable wallet fails the tally instead of counting nothing", func(t *testing.T) {
		dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		deadURL := dead.URL
		dead.Close()
		dir := t.TempDir()
		signJob(mustCreate(dir, "job", "-txproof", "txid="+txProofTxID+",address="+txProofAddress+",signature="+txProofSig))
		out, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", dir, "-proofs", "-rpc", deadURL)
		if err == nil {
			t.Fatalf("an unreachable wallet was reported as a result:\n%s", out)
		}
		if strings.Contains(out, "pairs ") {
			t.Errorf("a failed check still produced a tally:\n%s", out)
		}
	})

	t.Run("a proof must answer for a payment the record already claims", func(t *testing.T) {
		stray := strings.Repeat("a", 64)
		out, err := runCreate(t.TempDir(), "stray", "-txproof", "txid="+stray+",address="+txProofAddress+",signature="+txProofSig)
		if err == nil {
			t.Fatalf("a proof for a txid no settlement line cites was accepted:\n%s", out)
		}
		if !strings.Contains(out, "which no -settlement line carries") {
			t.Errorf("want the stray-txid reason, got:\n%s", out)
		}
	})

	t.Run("mode flags are refused when they disagree", func(t *testing.T) {
		list := filepath.Join(t.TempDir(), "txids.txt")
		if err := os.WriteFile(list, []byte(txProofTxID+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", proofDir, "-proofs", "-rpc", srv.URL, "-verified-txids", list); err == nil {
			t.Errorf("-proofs and -verified-txids were accepted together:\n%s", out)
		}
		if out, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", proofDir, "-proofs"); err == nil {
			t.Errorf("-proofs without -rpc was accepted, but a proof needs a wallet:\n%s", out)
		}
	})
}
