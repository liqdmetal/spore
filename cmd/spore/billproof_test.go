package main

// Tests for the evidence `bill watch` writes into its own outbox receipt
// (docs/MONERO_SETTLEMENT.md §4 and §8 step 4).
//
// The property under test is not "a proof block appears". It is that the record
// is checkable on its own: the wallet signs a message bound to the bill's claim,
// the poller makes that wallet verify the proof before anything is written, and
// anyone holding `<user>.receipt.json` can recompute the message from the fields
// in front of them. A record whose proof cannot be re-derived from the record is
// a decoration, so the end-to-end test re-derives it.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/liqdmetal/spore/internal/jobreceipt"
)

// xmrProofFixtureAmount is xmrTransfersFixture's amount (2.5 XMR in piconero),
// and the price bill watch is given, so the fixture's payment is billable.
const xmrProofFixtureAmount = 2500000000000

// billProofWallet is a wallet RPC that answers everything the Monero branch can
// ask: the transfers it polls, the proof it signs, and the check-back that must
// follow. The proof calls are recorded, because the assertion that matters is
// that the message the wallet SIGNED is the message the receipt CLAIMS.
type billProofWallet struct {
	srv *httptest.Server

	mu          sync.Mutex
	signed      map[string]any // params of get_tx_proof
	checked     map[string]any // params of check_tx_proof
	transferN   int
	proofCalls  int
	proofServed int
	// What this wallet answers about the payment: a live-shaped wallet that
	// confirms exactly what was received, or one that proves a different sum.
	received  uint64
	good      bool
	signature string
	signErr   string // non-empty: get_tx_proof answers with this RPC error
}

func newBillProofWallet(t *testing.T, received uint64, good bool) *billProofWallet {
	t.Helper()
	w := &billProofWallet{received: received, good: good, signature: "InProofV2mock"}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("mock wallet: undecodable request: %v", err)
			return
		}
		w.mu.Lock()
		switch req.Method {
		case "get_transfers":
			w.transferN++
		case "get_tx_proof":
			w.proofCalls++
			w.signed = req.Params
		case "check_tx_proof":
			w.proofCalls++
			w.checked = req.Params
		}
		w.mu.Unlock()

		switch req.Method {
		case "get_transfers":
			_, _ = rw.Write([]byte(xmrTransfersFixture))
		case "get_tx_proof":
			if w.signErr != "" {
				_, _ = rw.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"` + w.signErr + `"}}`))
				return
			}
			w.mu.Lock()
			w.proofServed++
			w.mu.Unlock()
			_, _ = rw.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"signature":"` + w.signature + `"}}`))
		case "check_tx_proof":
			_, _ = rw.Write([]byte(fmt.Sprintf(
				`{"jsonrpc":"2.0","id":1,"result":{"good":%t,"received":%d,"in_pool":false,"confirmations":12}}`,
				w.good, w.received)))
		default:
			t.Errorf("mock wallet: unexpected method %q", req.Method)
		}
	}))
	t.Cleanup(w.srv.Close)
	return w
}

// xmrProofFixtureAddress is the receiving address in xmrTransfersFixture, read
// off the fixture rather than copied, so the two cannot drift.
func xmrProofFixtureAddress(t *testing.T) string {
	t.Helper()
	var f struct {
		Result struct {
			In []xmrTransferEntry `json:"in"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(xmrTransfersFixture), &f); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if len(f.Result.In) == 0 || f.Result.In[0].Address == "" {
		t.Fatal("fixture carries no receiving address")
	}
	return f.Result.In[0].Address
}

// billWatchXMRProvisioningArgs is billWatchXMRBase without -dry-run. A dry run
// never provisions, and the receipt this test is about is written by a real one.
func billWatchXMRProvisioningArgs(dir, rpcURL, out string) []string {
	base := billWatchXMRBase(dir, rpcURL, out)
	args := make([]string, 0, len(base))
	for _, a := range base {
		if a != "-dry-run" {
			args = append(args, a)
		}
	}
	return args
}

// writePrekeyBatch places a syntactically valid public batch where provisioning
// expects it (<batch-dir>/<user>.json). Provisioning refuses a mailbox without
// one, and the bytes are zeros because nothing in the bill path reads a prekey:
// this test is about the receipt, not the handshake.
func writePrekeyBatch(t *testing.T, dir, user string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "batches"), 0o700); err != nil {
		t.Fatal(err)
	}
	zeros := strings.TrimSuffix(strings.Repeat("0,", 32), ",") // [32]byte as JSON
	batch := `{"bundles":[{"ik_pub":[` + zeros + `]}]}`
	if err := os.WriteFile(filepath.Join(dir, "batches", user+".json"), []byte(batch), 0o600); err != nil {
		t.Fatal(err)
	}
}

// billProofFixtureClaim is the claim the fixture payment produces, for the unit
// tests and for re-deriving the message from a written receipt.
func billProofFixtureClaim() billClaim {
	return billClaim{
		Asset: "xmr", TXID: xmrTransferFixtureTXID, Height: 3156002,
		AmountAtomic: xmrProofFixtureAmount, User: "cc4f19a2",
		Mailbox: billMailbox("cc4f19a2"),
	}
}

// The binding must be deterministic (two pollers, one message) and it must move
// when any fact in the claim moves. If a field could change without changing the
// message, a proof would survive an edit to the receipt it is evidence for.
func TestBillProofMessageBindsEveryFactItCovers(t *testing.T) {
	base := billProofFixtureClaim()
	msg, err := billProofMessage(base)
	if err != nil {
		t.Fatalf("billProofMessage: %v", err)
	}
	if !strings.HasPrefix(msg, billProofPrefix) {
		t.Errorf("message %q does not begin with %q", msg, billProofPrefix)
	}
	digest := strings.TrimPrefix(msg, billProofPrefix)
	if len(digest) != 64 {
		t.Errorf("the binding should be a 64-hex digest, got %q", digest)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		t.Errorf("the binding is not hex: %q", digest)
	}
	again, err := billProofMessage(billProofFixtureClaim())
	if err != nil {
		t.Fatalf("billProofMessage: %v", err)
	}
	if again != msg {
		t.Errorf("the same claim produced two messages: %q and %q", msg, again)
	}
	for name, mutate := range map[string]func(c *billClaim){
		"asset":   func(c *billClaim) { c.Asset = "dero" },
		"txid":    func(c *billClaim) { c.TXID = strings.Repeat("0", 64) },
		"height":  func(c *billClaim) { c.Height++ },
		"amount":  func(c *billClaim) { c.AmountAtomic++ },
		"user":    func(c *billClaim) { c.User = "deadbeef" },
		"mailbox": func(c *billClaim) { c.Mailbox = billMailbox("deadbeef") },
	} {
		c := base
		mutate(&c)
		got, err := billProofMessage(c)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == msg {
			t.Errorf("changing %s left the proof message unchanged — a proof would survive that edit", name)
		}
	}
}

// The signing step asks the receiving wallet, then makes it confirm what it just
// signed. Both halves matter: the guard is worth nothing if the signed message is
// not the claim, or if the signature is written without ever being checked.
func TestBillXMRProvePaymentSignsAndChecksBack(t *testing.T) {
	w := newBillProofWallet(t, xmrProofFixtureAmount, true)
	addr := xmrProofFixtureAddress(t)
	p := paymentPlan{TXID: xmrTransferFixtureTXID, Height: 3156002, Amount: xmrProofFixtureAmount, User: "cc4f19a2", Address: addr}

	ev := billXMRProvePayment(w.srv.URL, "spore:secret", "xmr", p)
	if ev.Proof == nil {
		t.Fatalf("no proof produced: %s", ev.Err)
	}
	if ev.Err != "" {
		t.Errorf("evidence carries both a proof and a complaint: %q", ev.Err)
	}
	if ev.Proof.Scheme != jobreceipt.SchemeMoneroTxProofV1 {
		t.Errorf("scheme = %q, want %q", ev.Proof.Scheme, jobreceipt.SchemeMoneroTxProofV1)
	}
	if ev.Proof.Address != addr {
		t.Errorf("address = %q, want the address the wallet said it was paid at (%q)", ev.Proof.Address, addr)
	}
	if ev.Proof.Signature != w.signature {
		t.Errorf("signature = %q, want the wallet's", ev.Proof.Signature)
	}
	want, err := billProofMessage(billProofFixtureClaim())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Proof.Message != want {
		t.Errorf("message = %q, want the claim's binding %q", ev.Proof.Message, want)
	}

	w.mu.Lock()
	signed, checked, calls := w.signed, w.checked, w.proofCalls
	w.mu.Unlock()
	if calls != 2 || signed == nil || checked == nil {
		t.Fatalf("proof calls = %d (signed %v, checked %v): the proof must be made AND checked", calls, signed != nil, checked != nil)
	}
	if signed["message"] != want || checked["message"] != want {
		t.Errorf("the wallet signed %q and checked %q, want the claim's binding", signed["message"], checked["message"])
	}
	if checked["signature"] != w.signature {
		t.Errorf("the check-back carried signature %v, want the one just made", checked["signature"])
	}
	if signed["txid"] != xmrTransferFixtureTXID || signed["address"] != addr {
		t.Errorf("signed for txid=%v address=%v", signed["txid"], signed["address"])
	}
}

// A proof for a different sum is not evidence for this bill: the wallet quite
// honestly confirms a payment, and the amount is the one field the record must
// never get wrong.
func TestBillXMRProvePaymentRefusesAProofForAnotherAmount(t *testing.T) {
	w := newBillProofWallet(t, 16090800000, true) // a real smaller payment
	p := paymentPlan{TXID: xmrTransferFixtureTXID, Height: 3156002, Amount: xmrProofFixtureAmount, User: "cc4f19a2", Address: xmrProofFixtureAddress(t)}

	ev := billXMRProvePayment(w.srv.URL, "", "xmr", p)
	if ev.Proof != nil {
		t.Fatalf("a valid proof for a different amount was attached: %+v", ev.Proof)
	}
	// Both sums, named: "the proof covers 0.0160908 xmr at that address, not the
	// 2.5 xmr this bill claims".
	for _, want := range []string{"0.0160908 xmr", "not the 2.5 xmr"} {
		if !strings.Contains(ev.Err, want) {
			t.Errorf("the reason should contain %q, got %q", want, ev.Err)
		}
	}
}

// A wallet that cannot make the proof is a reason, not a crash, and no proof
// block is written. The wallet's own words survive into the receipt.
func TestBillXMRProvePaymentReportsAWalletThatWillNotSign(t *testing.T) {
	w := newBillProofWallet(t, xmrProofFixtureAmount, true)
	w.signErr = "Transaction not found"
	p := paymentPlan{TXID: xmrTransferFixtureTXID, Height: 3156002, Amount: xmrProofFixtureAmount, User: "cc4f19a2", Address: xmrProofFixtureAddress(t)}

	ev := billXMRProvePayment(w.srv.URL, "", "xmr", p)
	if ev.Proof != nil {
		t.Fatal("a refused get_tx_proof produced a proof")
	}
	if !strings.Contains(ev.Err, "Transaction not found") {
		t.Errorf("the wallet's reason should survive: %q", ev.Err)
	}
}

// And a wallet that reports its own proof as not verifying gets the same
// treatment: the proof is not written, and the record says why.
func TestBillXMRProvePaymentRefusesAProofThatDoesNotVerify(t *testing.T) {
	w := newBillProofWallet(t, xmrProofFixtureAmount, false)
	p := paymentPlan{TXID: xmrTransferFixtureTXID, Height: 3156002, Amount: xmrProofFixtureAmount, User: "cc4f19a2", Address: xmrProofFixtureAddress(t)}

	ev := billXMRProvePayment(w.srv.URL, "", "xmr", p)
	if ev.Proof != nil {
		t.Fatal("a proof the wallet reported as not good was attached")
	}
	if !strings.Contains(ev.Err, "not verifying") {
		t.Errorf("reason = %q", ev.Err)
	}
}

// A proof answers for a payment TO an address. Without the wallet's address there
// is nothing to ask about, and asking anyway would burn an RPC to learn it.
func TestBillXMRProvePaymentNeedsTheReceivingAddress(t *testing.T) {
	w := newBillProofWallet(t, xmrProofFixtureAmount, true)
	p := paymentPlan{TXID: xmrTransferFixtureTXID, Height: 3156002, Amount: xmrProofFixtureAmount, User: "cc4f19a2"}

	ev := billXMRProvePayment(w.srv.URL, "", "xmr", p)
	if ev.Proof != nil || ev.Err == "" {
		t.Fatalf("want a reason and no proof, got proof=%v err=%q", ev.Proof != nil, ev.Err)
	}
	w.mu.Lock()
	calls := w.proofCalls
	w.mu.Unlock()
	if calls != 0 {
		t.Errorf("asked the wallet %d time(s) with no address to prove", calls)
	}
}

// The receipt is the artifact, so it must say what rail the atomic amount is
// denominated in, carry the proof when there is one, and say plainly when there
// is not. Both at once would be a lie in one direction or the other.
func TestBillReceiptRecordCarriesTheEvidenceOrSaysWhyNot(t *testing.T) {
	p := paymentPlan{TXID: xmrTransferFixtureTXID, Height: 3156002, Amount: xmrProofFixtureAmount, User: "cc4f19a2", Address: xmrProofFixtureAddress(t)}
	proof := &jobreceipt.TxProof{Scheme: jobreceipt.SchemeMoneroTxProofV1, Address: p.Address, Message: "spore.bill-receipt/v1 tx-proof deadbeef", Signature: "InProofV2mock"}

	withProof := billReceiptRecord("xmr", p, billMailbox(p.User), "2026-10-28T00:00:00Z", billEvidence{Proof: proof})
	if withProof["asset"] != "xmr" {
		t.Errorf("asset = %v: atomic units mean nothing without the rail", withProof["asset"])
	}
	raw, err := json.Marshal(withProof)
	if err != nil {
		t.Fatal(err)
	}
	var round struct {
		TxProof      *jobreceipt.TxProof `json:"tx_proof"`
		TxProofError string              `json:"tx_proof_error"`
	}
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("the record does not round-trip: %v", err)
	}
	if round.TxProof == nil || round.TxProof.Signature != proof.Signature {
		t.Fatalf("tx_proof did not survive the JSON: %s", raw)
	}
	if round.TxProofError != "" {
		t.Errorf("a proven record also carries an error: %q", round.TxProofError)
	}

	unevidenced := billReceiptRecord("xmr", p, billMailbox(p.User), "2026-10-28T00:00:00Z", billEvidence{Err: "the wallet would not sign"})
	if _, ok := unevidenced["tx_proof"]; ok {
		t.Error("an unevidenced record carries a tx_proof key")
	}
	if unevidenced["tx_proof_error"] != "the wallet would not sign" {
		t.Errorf("the reason should be in the record, got %v", unevidenced["tx_proof_error"])
	}

	// The DERO rail has no proof scheme, so its records say neither.
	dero := billReceiptRecord("dero", paymentPlan{TXID: strings.Repeat("a", 64), Height: 9, Amount: 2500000, User: "cabcd"}, billMailbox("cabcd"), "2026-10-28T00:00:00Z", billEvidence{})
	if _, ok := dero["tx_proof"]; ok {
		t.Error("a DERO record claims a proof, and v1 defines no DERO proof scheme")
	}
	if _, ok := dero["tx_proof_error"]; ok {
		t.Error("a DERO record reports a proof failure it could never have had")
	}
}

// The whole path through the real binary: a payment is billed, a mailbox is
// provisioned, and the receipt in the outbox carries the wallet's proof — with a
// message that can be re-derived from the receipt's own fields by anyone holding
// it. That last assertion is the point of the feature.
func TestBillWatchWritesTheProofIntoTheOutboxReceipt(t *testing.T) {
	exe := buildSporeBinary(t)
	addr := xmrProofFixtureAddress(t)
	w := newBillProofWallet(t, xmrProofFixtureAmount, true)

	dir, labels := billWatchFixtureDirs(t)
	out := filepath.Join(dir, "out")
	// The customer's device supplies the batch; provisioning refuses without it.
	writePrekeyBatch(t, dir, "cc4f19a2")

	args := append(billWatchXMRProvisioningArgs(dir, w.srv.URL, out), "-xmr-unverified", "-xmr-subaddresses", labels)
	logs, err := runBillWatch(t, exe, args...)
	if err != nil {
		t.Fatalf("bill watch exited non-zero: %v\n%s", err, logs)
	}
	if !strings.Contains(logs, "provisioned 1 mailbox") {
		t.Errorf("the fixture payment should have provisioned a mailbox:\n%s", logs)
	}

	raw, err := os.ReadFile(filepath.Join(out, "cc4f19a2.receipt.json"))
	if err != nil {
		t.Fatalf("outbox receipt: %v\n%s", err, logs)
	}
	var rec struct {
		Asset        string              `json:"asset"`
		TXID         string              `json:"txid"`
		Height       uint64              `json:"height"`
		AmountAtomic uint64              `json:"amount_atomic"`
		User         string              `json:"user"`
		Mailbox      string              `json:"mailbox"`
		TxProof      *jobreceipt.TxProof `json:"tx_proof"`
		TxProofError string              `json:"tx_proof_error"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("receipt is not JSON: %v\n%s", err, raw)
	}
	if rec.TxProofError != "" {
		t.Fatalf("the receipt reports no proof: %s\n%s", rec.TxProofError, raw)
	}
	if rec.TxProof == nil {
		t.Fatalf("the receipt cites a payment without the chain's evidence:\n%s", raw)
	}
	if rec.Asset != "xmr" || rec.TXID != xmrTransferFixtureTXID || rec.AmountAtomic != xmrProofFixtureAmount {
		t.Errorf("receipt facts = %+v", rec)
	}
	if rec.TxProof.Scheme != jobreceipt.SchemeMoneroTxProofV1 || rec.TxProof.Address != addr || rec.TxProof.Signature != w.signature {
		t.Errorf("tx_proof = %+v", rec.TxProof)
	}

	// Re-derive the binding from the receipt alone, the way any reader would.
	want, err := billProofMessage(billClaim{
		Asset: rec.Asset, TXID: rec.TXID, Height: rec.Height,
		AmountAtomic: rec.AmountAtomic, User: rec.User, Mailbox: rec.Mailbox,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.TxProof.Message != want {
		t.Errorf("the proof's message (%q) is not the binding of the receipt in front of it (%q)", rec.TxProof.Message, want)
	}
	w.mu.Lock()
	signed, checked := w.signed, w.checked
	w.mu.Unlock()
	if signed == nil || signed["message"] != want || checked == nil || checked["message"] != want {
		t.Errorf("the wallet was asked to prove %v / check %v, want the receipt's binding %q", signed["message"], checked["message"], want)
	}

	// And the same receipt with one fact changed no longer matches its proof.
	tampered := want
	edited, err := billProofMessage(billClaim{
		Asset: rec.Asset, TXID: rec.TXID, Height: rec.Height,
		AmountAtomic: rec.AmountAtomic + 1, User: rec.User, Mailbox: rec.Mailbox,
	})
	if err != nil {
		t.Fatal(err)
	}
	if edited == tampered {
		t.Error("bumping the receipt's amount by one piconero left the binding unchanged")
	}
}

// The other half of the same path: a wallet that cannot prove the payment still
// gets the customer their mailbox, and the receipt says in its own bytes why it
// carries no proof. Silence here would be the worst outcome — an unevidenced
// record that looks like an evidenced one.
func TestBillWatchRecordsWhyAReceiptHasNoProof(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newBillProofWallet(t, 16090800000, true) // proves a different sum

	dir, labels := billWatchFixtureDirs(t)
	out := filepath.Join(dir, "out")
	writePrekeyBatch(t, dir, "cc4f19a2")

	args := append(billWatchXMRProvisioningArgs(dir, w.srv.URL, out), "-xmr-unverified", "-xmr-subaddresses", labels)
	logs, err := runBillWatch(t, exe, args...)
	if err != nil {
		t.Fatalf("bill watch exited non-zero: %v\n%s", err, logs)
	}
	if !strings.Contains(logs, "NO CHAIN PROOF ATTACHED") {
		t.Errorf("an unevidenced receipt must be shouted about, not merely written:\n%s", logs)
	}
	raw, err := os.ReadFile(filepath.Join(out, "cc4f19a2.receipt.json"))
	if err != nil {
		t.Fatalf("outbox receipt: %v\n%s", err, logs)
	}
	var rec struct {
		TxProof      *jobreceipt.TxProof `json:"tx_proof"`
		TxProofError string              `json:"tx_proof_error"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("receipt is not JSON: %v\n%s", err, raw)
	}
	if rec.TxProof != nil {
		t.Fatalf("a proof for a different amount was written into the receipt:\n%s", raw)
	}
	if !strings.Contains(rec.TxProofError, "not the 2.5 xmr") {
		t.Errorf("the receipt should carry the reason, got %q", rec.TxProofError)
	}
}
