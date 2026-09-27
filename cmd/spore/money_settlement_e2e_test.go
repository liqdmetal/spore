package main

// Go-driven end-to-end settlement test: the REAL escrow/DEX command paths
// (runEscrowClaim, msgDEXSwap) execute against internal/derosim in-process,
// money actually moves in the simulated contracts, and each settlement notice
// rides a real ratcheted session over a real mailbox body store. Failure
// injection (a body store that refuses the notice PUT, a wallet that refuses
// the pointer transfer) pins the money-first durability contract: the
// settlement tx may succeed while the in-thread notice fails, the command
// must still report success, and the counterparty's full recv-e2 ingest
// pipeline must render the envelope and ledger it when the path is healthy.
//
// derosim is a contract-shaped simulator, not the DVM; the bash soak remains
// the live-chain story. This test pins the CLI↔session↔store↔ingest seam that
// the soak exercised only through shell plumbing.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/derosim"
	"github.com/liqdmetal/spore/internal/mailbox"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/receipts"
	"github.com/liqdmetal/spore/internal/sap"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// ---------------------------------------------------------------- fixtures

func e2eRandKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func e2eHexFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// settlementEnv wires a derosim chain (alice/bob wallets), a shared mailbox
// body store, and the sap contract IDs to the simulated contracts. Sap
// globals are package state: saved on entry, restored on cleanup. The mailbox
// wrapper counts body PUTs and can refuse the Nth one (failure injection).
type settlementEnv struct {
	t        *testing.T
	sim      *derosim.Sim
	aliceRPC string
	bobRPC   string
	storeURL string
	token    string
	bodyPuts atomic.Int64
	refuseAt atomic.Int64
	saved    [3]string
}

func newSettlementEnv(t *testing.T) *settlementEnv {
	t.Helper()
	const htlcSC, dexSC, wderoSC = "sim-htlc-sc", "sim-dex-sc", "sim-wdero-sc"
	sim := derosim.New(htlcSC, dexSC, wderoSC)
	sim.AddWallet("alice")
	sim.AddWallet("bob")
	chainSrv := httptest.NewServer(sim.Handler())
	t.Cleanup(chainSrv.Close)

	mb, err := mailbox.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	const token = "settlement-e2e-mailbox-token"
	inner := mb.HandlerToken(token)
	e := &settlementEnv{t: t, sim: sim,
		aliceRPC: chainSrv.URL + "/w/alice",
		bobRPC:   chainSrv.URL + "/w/bob",
		token:    token,
		saved:    [3]string{sap.HTLCContractID, sap.DEXContractID, sap.WrappedDeroContractID},
	}
	mbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isPut := r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/body/")
		if isPut && e.refuseAt.Load() > 0 && e.bodyPuts.Add(1) == e.refuseAt.Load() {
			http.Error(w, "injected body-store outage (settlement notice refused)", http.StatusServiceUnavailable)
			return
		}
		if isPut {
			e.bodyPuts.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(mbSrv.Close)
	e.storeURL = mbSrv.URL

	sap.SetContractIDs(htlcSC, dexSC, wderoSC)
	t.Cleanup(func() { sap.SetContractIDs(e.saved[0], e.saved[1], e.saved[2]) })
	return e
}

// armStoreRefusal refuses the NEXT body PUT (which, after the thread opener,
// is exactly the settlement notice's frame).
func (e *settlementEnv) armStoreRefusal() {
	e.refuseAt.Store(e.bodyPuts.Load() + 1)
}

// refusingWalletRPC serves the sim with every wallet-`transfer` on the given
// route refused while sc_invoke still passes. Pointing a settlement command's
// -rpc at it reproduces a chain that accepts the contract call but refuses
// the pointer post.
func (e *settlementEnv) refusingWalletRPC(route string) string {
	t := e.t
	inner := e.sim.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/w/"+route) {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req struct {
				Method string `json:"method"`
			}
			if err := json.Unmarshal(body, &req); err == nil && req.Method == "transfer" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","error":{"code":-1,"message":"injected transfer refusal"}}`))
				return
			}
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/w/" + route
}

// settlementFlags builds a parsed flag set carrying every flag the settlement
// commands touch. Callers override state-dir/state-key/session per case.
func (e *settlementEnv) settlementFlags(rpc, dir string) *flag.FlagSet {
	t := e.t
	t.Helper()
	fs := flag.NewFlagSet("settlement-e2e", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	e2Common(fs)
	for name, value := range map[string]string{
		"chain":       "dero",
		"ringsize":    "16",
		"rpc":         rpc,
		"store":       e.storeURL,
		"store-token": e.token,
		"store-dir":   filepath.Join(dir, "hold"),
		"state-dir":   filepath.Join(dir, "state"),
		"state-key":   e2eHexFile(t, dir, "default-state.key", e2eRandKey(t)),
		"config":      filepath.Join(dir, "absent-config.json"),
		"session-ttl": "0s",
	} {
		if err := fs.Set(name, value); err != nil {
			t.Fatalf("set -%s: %v", name, err)
		}
	}
	return fs
}

// threadKeys are the bundle-owner (thread peer) keys: whoever RECEIVES the
// opener. The receiver's ingest pipeline is opened over exactly these.
type threadKeys struct{ id, spk, opk []byte }

// openThread performs the X3DH bootstrap: the wallet at senderRPC sends the
// init to the peer wallet at peerRPC over the shared store. The sender's
// durable state lives in dir (state-dir + state.key) so the SAME session can
// be restored by the settlement command's flag surface. Returns the peer's
// sim address (also the settlement -to), the live session id, and the peer's
// receiver keys.
func (e *settlementEnv) openThread(senderRPC, peerRPC, dir string) (peerAddr string, session [8]byte, keys threadKeys, opener ratchetwire.Pointer) {
	t := e.t
	t.Helper()

	senderID, peerID, peerSPK := e2eRandKey(t), e2eRandKey(t), e2eRandKey(t)
	opk := e2eRandKey(t)
	var opkArr [32]byte
	copy(opkArr[:], opk)

	bundle, err := ratchet.BuildBundle(peerID, peerSPK, 7, &opkArr, 19)
	if err != nil {
		t.Fatal(err)
	}
	peerAddr = e.walletAddr(peerRPC)
	st, err := store.NewHTTPStoreWithToken(e.storeURL, e.token)
	if err != nil {
		t.Fatal(err)
	}
	stateKey := e2eRandKey(t)
	states, err := ratchetwire.NewFileStateStore(filepath.Join(dir, "state"), stateKey)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := ratchetwire.NewDurableEndpoint(st, states, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	peerSig, err := secure.SigPubOf(peerID)
	if err != nil {
		t.Fatal(err)
	}
	var rawOpener []byte
	opener, rawOpener, session, err = sender.SendFirstSession(senderID, bundle, peerSig,
		[]byte("settlement thread opener"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Post the opener pointer exactly like `msg send-e2` would: the peer's
	// chain scan must see it as the thread's first payload tx.
	carrier := ratchetwire.ChainCarrier{Chain: dero.NewBackend(dero.NewClient(senderRPC, "", "")), Codec: ratchetwire.DeroChainCodec{}}
	if _, err := carrier.PostPointer(context.Background(), peerAddr, rawOpener, 1); err != nil {
		t.Fatalf("post opener pointer: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.key"),
		[]byte(hex.EncodeToString(stateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return peerAddr, session, threadKeys{id: peerID, spk: peerSPK, opk: opk}, opener
}

// seedResponder is intentionally absent: the receiver's responder session is
// installed by the REAL ingest pipeline when it processes the opener (history
// order: opener first, continuations after), exactly as a live `msg recv-e2`
// would persist it.

func (e *settlementEnv) walletAddr(rpc string) string {
	t := e.t
	t.Helper()
	addr, err := dero.NewClient(rpc, "", "").GetAddress(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

// receiverFlagSet builds the peer's recv-e2 flag surface over the shared
// store, so the notice ingest runs through the SAME pipeline `spore msg
// recv-e2` uses (openE2Receiver + e2Ingestor.ingest).
func (e *settlementEnv) receiverFlagSet(keys threadKeys, receiptsPath, dir string, stateKey []byte) *flag.FlagSet {
	t := e.t
	t.Helper()
	fs, _ := newRecvE2Flagset()
	fs.SetOutput(new(bytes.Buffer))
	for name, value := range map[string]string{
		"chain":       "dero",
		"ringsize":    "16",
		"rpc":         e.bobRPC,
		"store":       e.storeURL,
		"store-token": e.token,
		"store-dir":   filepath.Join(dir, "hold"),
		"state-dir":   filepath.Join(dir, "recv-state"),
		"state-key":   e2eHexFile(t, dir, "recv-state.key", stateKey),
		"identity":    e2eHexFile(t, dir, "identity.hex", keys.id),
		"spk":         e2eHexFile(t, dir, "spk.hex", keys.spk),
		"opk":         e2eHexFile(t, dir, "opk.hex", keys.opk),
		"receipts":    receiptsPath,
		"config":      filepath.Join(dir, "absent-config.json"),
		"session-ttl": "0s",
	} {
		if err := fs.Set(name, value); err != nil {
			t.Fatalf("set -%s: %v", name, err)
		}
	}
	return fs
}

func (e *settlementEnv) openReceiver(fs *flag.FlagSet) *e2Ingestor {
	t := e.t
	t.Helper()
	ing, cleanup, err := openE2Receiver(fs, "", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return ing
}

// fundHTLC locks atomicAmt DERO from Alice's wallet behind hash for
// recipientAddr at the simulated HTLC, before any claim.
func (e *settlementEnv) fundHTLC(recipientAddr string, hash [32]byte, atomicAmt uint64) {
	e.fundHTLCFrom(e.aliceRPC, recipientAddr, hash, atomicAmt, 10_000)
}

// fundHTLCFrom locks atomicAmt DERO from the wallet at senderRPC behind hash
// for recipientAddr, with an explicit expiry height — the knob the refund
// test drives to exercise the contract's expiry gate end to end.
func (e *settlementEnv) fundHTLCFrom(senderRPC, recipientAddr string, hash [32]byte, atomicAmt, expiry uint64) {
	t := e.t
	t.Helper()
	fundFS := e.settlementFlags(senderRPC, t.TempDir())
	client, _, err := escrowClient(fundFS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sap.HTLCFund(context.Background(), client, hash, recipientAddr, expiry, atomicAmt, 16); err != nil {
		t.Fatalf("HTLCFund: %v", err)
	}
}

// peerIncoming lists the peer wallet's payload-bearing incoming transfers —
// what a recv-e2 poll would see on scan.
func (e *settlementEnv) peerIncoming(rpc string) []chain.Incoming {
	t := e.t
	t.Helper()
	c := dero.NewClient(rpc, "", "")
	entries, err := c.GetTransfers(context.Background(), dero.GetTransfersParams{In: true, MinHeight: 0})
	if err != nil {
		t.Fatal(err)
	}
	var out []chain.Incoming
	for _, en := range entries {
		payload, err := dero.EntryPayload(en)
		if err != nil {
			continue
		}
		out = append(out, chain.Incoming{TxID: en.TXID, Payload: payload})
	}
	return out
}

// deliverIngestible runs every pointer tx through the receiver pipeline in
// history order, like a recv-e2 poll that just came online (opener first, then
// continuations). Returns the number of pointers delivered.
func (e *settlementEnv) deliverIngestible(g *e2Ingestor, rpc string) int {
	t := e.t
	t.Helper()
	c := dero.NewClient(rpc, "", "")
	carrier := ratchetwire.ChainCarrier{Chain: dero.NewBackend(c), Codec: ratchetwire.DeroChainCodec{}}
	n := 0
	for _, inc := range e.peerIncoming(rpc) {
		frame, p, err := carrier.FetchIncomingE2(g.st, inc, time.Now())
		if err != nil {
			continue
		}
		g.ingest(inc, frame, p, false)
		n++
	}
	return n
}

// e2eCaptureStdout redirects os.Stdout for the duration of fn (the CLI paths
// print their settlement lines with fmt.Printf).
func e2eCaptureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	os.Stdout = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// ---------------------------------------------------------------- tests

// TestEscrowClaimNoticeE2E is the money-first acceptance: the sim contract
// funds, runEscrowClaim executes the REAL claim + SendNext + PostPointer
// sequence, and the peer's real ingest pipeline renders "ESCROW CLAIMED" and
// ledgers the received settlement.
func TestEscrowClaimNoticeE2E(t *testing.T) {
	env := newSettlementEnv(t)
	dir := t.TempDir()
	recvKey := e2eRandKey(t)
	aliceAddr, session, keys, _ := env.openThread(env.bobRPC, env.aliceRPC, dir)
	bobAddr := env.walletAddr(env.bobRPC)

	preimage := e2eRandKey(t)
	hash := sha256.Sum256(preimage)
	hashHex, preHex := hex.EncodeToString(hash[:]), hex.EncodeToString(preimage)

	const fundAtomic = 5 * 100_000
	env.fundHTLC(bobAddr, hash, fundAtomic)
	balBefore := env.sim.Balance("bob")

	ledger := filepath.Join(dir, "bob-receipts.json")
	sessionHex := hex.EncodeToString(session[:])
	claimFS := env.settlementFlags(env.bobRPC, dir)
	if err := claimFS.Set("state-key", filepath.Join(dir, "state.key")); err != nil {
		t.Fatal(err)
	}
	var claimErr error
	_ = e2eCaptureStdout(t, func() {
		claimErr = runEscrowClaim(claimFS, hashHex, preHex, aliceAddr, sessionHex, "deal closed", fundAtomic, ledger)
	})
	if claimErr != nil {
		t.Fatalf("runEscrowClaim: %v", claimErr)
	}

	claimed, refunded, ok := env.sim.HTLCSettled(hashHex)
	if !ok || !claimed || refunded {
		t.Fatalf("HTLC settled state wrong: claimed=%v refunded=%v ok=%v", claimed, refunded, ok)
	}
	if got := env.sim.Balance("bob"); got != balBefore+fundAtomic-1 {
		// -1: the notice pointer's 1-atomic postage rides out of the same
		// wallet right after the claim pays out.
		t.Fatalf("bob balance = %d, want %d (claim payout minus notice postage)", got, balBefore+fundAtomic-1)
	}

	// Alice's real ingest pipeline: opener + notice, in history order. The
	// receiver state dir + key are the ones recvKey names, so this ingest
	// run restores exactly what its own earlier ingest persisted.
	aliceLedger := filepath.Join(dir, "alice-receipts.json")
	ing := env.openReceiver(env.receiverFlagSet(keys, aliceLedger, dir, recvKey))
	out := e2eCaptureStdout(t, func() {
		if n := env.deliverIngestible(ing, env.aliceRPC); n != 2 {
			t.Fatalf("delivered %d pointers, want 2 (opener + notice)", n)
		}
	})
	if !strings.Contains(out, "ESCROW CLAIMED") || !strings.Contains(out, "preimage revealed") {
		t.Fatalf("ingest output missing claim rendering: %q", out)
	}
	recs, err := receipts.List(aliceLedger, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Kind != "escrow-claim" || recs[0].Direction != "received" || recs[0].Atomic != fundAtomic {
		t.Fatalf("alice ledger = %+v, want one received escrow-claim of %d", recs, fundAtomic)
	}
}

// TestSettlementNoticeFailureReportedNotFatal injects failure at each link of
// the notice path — the body store refusing the frame PUT, and the chain
// refusing the pointer transfer. In both cases the settlement tx already
// moved the money, so the command must still succeed and the peer must NOT
// receive a notice.
func TestSettlementNoticeFailureReportedNotFatal(t *testing.T) {
	t.Run("notice-body-store-refused", func(t *testing.T) {
		runNoticeFailureCase(t, func(env *settlementEnv) string {
			env.armStoreRefusal()
			return env.bobRPC
		})
	})
	t.Run("pointer-post-refused", func(t *testing.T) {
		runNoticeFailureCase(t, func(env *settlementEnv) string {
			return env.refusingWalletRPC("bob")
		})
	})
}

// runNoticeFailureCase is the shared body of both failure injections; the
// hook returns the -rpc the claim should run with (and arms store refusal).
func runNoticeFailureCase(t *testing.T, hook func(*settlementEnv) string) {
	t.Helper()
	env := newSettlementEnv(t)
	dir := t.TempDir()
	aliceAddr, session, _, _ := env.openThread(env.bobRPC, env.aliceRPC, dir)
	bobAddr := env.walletAddr(env.bobRPC)

	preimage := e2eRandKey(t)
	hash := sha256.Sum256(preimage)
	hashHex, preHex := hex.EncodeToString(hash[:]), hex.EncodeToString(preimage)

	const fundAtomic = 3 * 100_000
	env.fundHTLC(bobAddr, hash, fundAtomic)
	balBefore := env.sim.Balance("bob")

	rpc := hook(env)

	ledger := filepath.Join(dir, "bob-receipts.json")
	sessionHex := hex.EncodeToString(session[:])
	claimFS := env.settlementFlags(rpc, dir)
	if err := claimFS.Set("state-key", filepath.Join(dir, "state.key")); err != nil {
		t.Fatal(err)
	}
	var claimErr error
	_ = e2eCaptureStdout(t, func() {
		claimErr = runEscrowClaim(claimFS, hashHex, preHex, aliceAddr, sessionHex, "deal closed", fundAtomic, ledger)
	})
	// Money-first: a failed notice must not fail the command.
	if claimErr != nil {
		t.Fatalf("claim must succeed even when the notice fails; got %v", claimErr)
	}

	claimed, refunded, ok := env.sim.HTLCSettled(hashHex)
	if !ok || !claimed || refunded {
		t.Fatalf("settlement tx must be authoritative: claimed=%v refunded=%v ok=%v", claimed, refunded, ok)
	}
	if got := env.sim.Balance("bob"); got != balBefore+fundAtomic {
		// Exactly the payout: the failed notice spent no postage.
		t.Fatalf("bob balance = %d, want %d (payout only; a failed notice spends no postage)", got, balBefore+fundAtomic)
	}

	// The notice never arrived: the peer's scan shows exactly the opener,
	// nothing new.
	if n := len(env.peerIncoming(env.aliceRPC)); n != 1 {
		t.Fatalf("peer scan shows %d payload txs, want exactly the 1 opener", n)
	}
}

// TestDexSwapAnnouncesInThreadE2E runs the REAL msgDEXSwap flag parsing and
// announce path against the sim pool, then verifies the peer's ingest
// pipeline renders the swap and ledgers it.
func TestDexSwapAnnouncesInThreadE2E(t *testing.T) {
	env := newSettlementEnv(t)
	dir := t.TempDir()
	recvKey := e2eRandKey(t)
	aliceAddr, session, keys, _ := env.openThread(env.bobRPC, env.aliceRPC, dir)

	poolA, poolB := env.sim.PoolReserves()

	ledger := filepath.Join(dir, "bob-receipts.json")
	sessionHex := hex.EncodeToString(session[:])
	swapStdout := e2eCaptureStdout(t, func() {
		msgDEXSwap([]string{
			"-ta", "tA", "-tb", "tB",
			"-amount", "10tA",
			"-min-out", "1",
			"-to", aliceAddr,
			"-session", sessionHex,
			"-rpc", env.bobRPC,
			"-store", env.storeURL,
			"-store-token", env.token,
			"-store-dir", filepath.Join(dir, "hold"),
			"-state-dir", filepath.Join(dir, "state"),
			"-state-key", filepath.Join(dir, "state.key"),
			"-receipts", ledger,
			"-config", filepath.Join(dir, "absent-config.json"),
		})
	})
	if !strings.Contains(swapStdout, "DEX SWAPPED") || !strings.Contains(swapStdout, "min-out 1") {
		t.Fatalf("swap stdout missing settlement line: %q", swapStdout)
	}

	a, b := env.sim.PoolReserves()
	if a == poolA || b == poolB {
		t.Fatalf("pool reserves did not move: %d/%d -> %d/%d", poolA, poolB, a, b)
	}

	aliceLedger := filepath.Join(dir, "alice-receipts.json")
	ing := env.openReceiver(env.receiverFlagSet(keys, aliceLedger, dir, recvKey))
	out := e2eCaptureStdout(t, func() {
		if n := env.deliverIngestible(ing, env.aliceRPC); n != 2 {
			t.Fatalf("delivered %d pointers, want 2 (opener + notice)", n)
		}
	})
	if !strings.Contains(out, "DEX SWAPPED tA->tB") {
		t.Fatalf("ingest output missing dex rendering: %q", out)
	}
	recs, err := receipts.List(aliceLedger, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Kind != "dex-swap" || recs[0].Direction != "received" || recs[0].Atomic != 10*100_000 {
		t.Fatalf("alice ledger = %+v, want one received dex-swap of %d", recs, 10*100_000)
	}
}

// TestDexWrapUnwrapAnnounceInThreadE2E runs the REAL msgDEXWrap and
// msgDEXUnwrap flag parsing and announce paths against the simulated
// RelayWrappedDero contract on one ratcheted session, verifies the mint/burn
// moved the sim's supply and wallet, then verifies the peer's ingest pipeline
// renders both notices and ledgers them in order.
func TestDexWrapUnwrapAnnounceInThreadE2E(t *testing.T) {
	env := newSettlementEnv(t)
	dir := t.TempDir()
	recvKey := e2eRandKey(t)
	aliceAddr, session, keys, _ := env.openThread(env.bobRPC, env.aliceRPC, dir)

	if supply, tok := env.sim.WDEROSupply(), env.sim.TokenBalance("bob", "wdero"); supply != 0 || tok != 0 {
		t.Fatalf("fresh sim must mint no wDERO: supply=%d bob token=%d", supply, tok)
	}
	bobBalBefore := env.sim.Balance("bob")

	dexArgs := func(extra ...string) []string {
		return append([]string{
			"-to", aliceAddr,
			"-session", hex.EncodeToString(session[:]),
			"-rpc", env.bobRPC,
			"-store", env.storeURL,
			"-store-token", env.token,
			"-store-dir", filepath.Join(dir, "hold"),
			"-state-dir", filepath.Join(dir, "state"),
			"-state-key", filepath.Join(dir, "state.key"),
			"-receipts", filepath.Join(dir, "bob-receipts.json"),
			"-config", filepath.Join(dir, "absent-config.json"),
		}, extra...)
	}

	wrapStdout := e2eCaptureStdout(t, func() {
		msgDEXWrap(dexArgs("-amount", "5dero", "-note", "wrapping before the swap"))
	})
	if !strings.Contains(wrapStdout, "WDERO WRAPPED 5 ") {
		t.Fatalf("wrap stdout missing settlement line: %q", wrapStdout)
	}
	if got := env.sim.WDEROSupply(); got != 500_000 {
		t.Fatalf("wDERO supply after wrap = %d, want 500000", got)
	}
	if got := env.sim.TokenBalance("bob", "wdero"); got != 500_000 {
		t.Fatalf("bob wDERO after wrap = %d, want 500000", got)
	}
	if got := env.sim.Balance("bob"); got != bobBalBefore-500_000-1 {
		// -1: the notice pointer's 1-atomic postage rides out of the same
		// wallet right after the wrap mints.
		t.Fatalf("bob balance after wrap = %d, want %d (mint minus notice postage)", got, bobBalBefore-500_000-1)
	}

	unwrapStdout := e2eCaptureStdout(t, func() {
		msgDEXUnwrap(dexArgs("-amount", "2.5wdero", "-note", "unwrapping the remainder"))
	})
	if !strings.Contains(unwrapStdout, "WDERO UNWRAPPED 2.5 ") {
		t.Fatalf("unwrap stdout missing settlement line: %q", unwrapStdout)
	}
	if got := env.sim.WDEROSupply(); got != 250_000 {
		t.Fatalf("wDERO supply after unwrap = %d, want 250000", got)
	}
	if got := env.sim.TokenBalance("bob", "wdero"); got != 250_000 {
		t.Fatalf("bob wDERO after unwrap = %d, want 250000", got)
	}
	if got := env.sim.Balance("bob"); got != bobBalBefore-250_002 {
		t.Fatalf("bob balance after both = %d, want %d (-500000 wrap +250000 unwrap -2 notice postage)", got, bobBalBefore-250_002)
	}

	// Bob's own ledger: two sent settlements, newest first.
	sent, err := receipts.List(filepath.Join(dir, "bob-receipts.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[0].Kind != "dex-unwrap" || sent[0].Atomic != 250_000 ||
		sent[1].Kind != "dex-wrap" || sent[1].Atomic != 500_000 {
		t.Fatalf("bob ledger = %+v, want sent dex-wrap 500000 then dex-unwrap 250000 (newest first)", sent)
	}

	// Alice's real ingest pipeline: opener + two notices, in history order.
	aliceLedger := filepath.Join(dir, "alice-receipts.json")
	ing := env.openReceiver(env.receiverFlagSet(keys, aliceLedger, dir, recvKey))
	out := e2eCaptureStdout(t, func() {
		if n := env.deliverIngestible(ing, env.aliceRPC); n != 3 {
			t.Fatalf("delivered %d pointers, want 3 (opener + wrap + unwrap)", n)
		}
	})
	if !strings.Contains(out, "WRAPPED 5 dero -> wdero") || !strings.Contains(out, "UNWRAPPED 2.5 wdero -> dero") {
		t.Fatalf("ingest output missing wrap/unwrap rendering: %q", out)
	}
	recs, err := receipts.List(aliceLedger, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 ||
		recs[0].Kind != "dex-unwrap" || recs[0].Direction != "received" || recs[0].Atomic != 250_000 ||
		recs[1].Kind != "dex-wrap" || recs[1].Direction != "received" || recs[1].Atomic != 500_000 {
		t.Fatalf("alice ledger = %+v, want received dex-wrap 500000 then dex-unwrap 250000 (newest first)", recs)
	}
}

// TestEscrowRefundE2EWithExpiryGate runs the REAL runEscrowRefund against the
// simulated HTLC and pins the contract's expiry gate end to end: a refund
// before expiry is refused by the contract (height rolls back, no postage
// spent), and after the simulated chain advances past expiry the same command
// returns the escrow to the FUNDER and the peer's ingest pipeline renders the
// refund notice and ledgers it.
func TestEscrowRefundE2EWithExpiryGate(t *testing.T) {
	env := newSettlementEnv(t)
	dir := t.TempDir()
	recvKey := e2eRandKey(t)
	aliceAddr, session, keys, _ := env.openThread(env.bobRPC, env.aliceRPC, dir)

	preimage := e2eRandKey(t)
	hash := sha256.Sum256(preimage)
	hashHex := hex.EncodeToString(hash[:])

	const (
		fundAtomic = 2 * 100_000
		expiry     = uint64(50)
	)
	// Bob funds the escrow, so the refunding party owns the thread's sender
	// state in dir/state and the refund returns the escrow to him.
	env.fundHTLCFrom(env.bobRPC, aliceAddr, hash, fundAtomic, expiry)
	balBefore := env.sim.Balance("bob")

	refundFS := env.settlementFlags(env.bobRPC, dir)
	if err := refundFS.Set("state-key", filepath.Join(dir, "state.key")); err != nil {
		t.Fatal(err)
	}
	sessionHex := hex.EncodeToString(session[:])
	ledger := filepath.Join(dir, "bob-receipts.json")

	// Before expiry the contract refuses the refund outright.
	heightBefore := env.sim.State().Height
	var refundErr error
	_ = e2eCaptureStdout(t, func() {
		refundErr = runEscrowRefund(refundFS, hashHex, aliceAddr, sessionHex, "deal fell through", fundAtomic, ledger)
	})
	if refundErr == nil || !strings.Contains(refundErr.Error(), "not yet expired") {
		t.Fatalf("pre-expiry refund must be refused by the contract; got %v", refundErr)
	}
	if claimed, refunded, ok := env.sim.HTLCSettled(hashHex); !ok || claimed || refunded {
		t.Fatalf("refused refund must not settle the HTLC: claimed=%v refunded=%v ok=%v", claimed, refunded, ok)
	}
	if got := env.sim.State().Height; got != heightBefore {
		t.Fatalf("refused invoke consumed a block: height %d -> %d (failed calls must roll back)", heightBefore, got)
	}
	if got := env.sim.Balance("bob"); got != balBefore {
		t.Fatalf("bob balance moved on a refused refund: %d, want %d (no postage spent)", got, balBefore)
	}

	// Advance the simulated chain past expiry and refund for real.
	env.sim.Bump(expiry + 1)
	var refundStdout string
	refundErr = nil
	refundStdout = e2eCaptureStdout(t, func() {
		refundErr = runEscrowRefund(refundFS, hashHex, aliceAddr, sessionHex, "deal fell through", fundAtomic, ledger)
	})
	if refundErr != nil {
		t.Fatalf("post-expiry runEscrowRefund: %v", refundErr)
	}
	if !strings.Contains(refundStdout, "ESCROW REFUNDED") {
		t.Fatalf("refund stdout missing settlement line: %q", refundStdout)
	}
	if claimed, refunded, ok := env.sim.HTLCSettled(hashHex); !ok || claimed || !refunded {
		t.Fatalf("HTLC settled state wrong: claimed=%v refunded=%v ok=%v", claimed, refunded, ok)
	}
	if got := env.sim.State().Height; got != heightBefore+expiry+3 {
		// +expiry+1: the bump past expiry; +1 the settled refund invoke; +1 the
		// notice pointer's postage transfer after it.
		t.Fatalf("height after refund = %d, want %d (bump + settled invoke + notice postage)", got, heightBefore+expiry+3)
	}
	// The refund pays the FUNDER (bob funded, bob refunds himself); the
	// notice pointer's 1-atomic postage rides out of the same wallet.
	if got := env.sim.Balance("bob"); got != balBefore+fundAtomic-1 {
		t.Fatalf("bob balance = %d, want %d (escrow returned minus notice postage)", got, balBefore+fundAtomic-1)
	}
	sent, err := receipts.List(ledger, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].Kind != "escrow-refund" || sent[0].Direction != "sent" || sent[0].Atomic != fundAtomic {
		t.Fatalf("bob ledger = %+v, want one sent escrow-refund of %d", sent, fundAtomic)
	}

	// Alice's real ingest pipeline: opener + refund notice, in history order.
	aliceLedger := filepath.Join(dir, "alice-receipts.json")
	ing := env.openReceiver(env.receiverFlagSet(keys, aliceLedger, dir, recvKey))
	out := e2eCaptureStdout(t, func() {
		if n := env.deliverIngestible(ing, env.aliceRPC); n != 2 {
			t.Fatalf("delivered %d pointers, want 2 (opener + refund notice)", n)
		}
	})
	if !strings.Contains(out, "ESCROW REFUNDED") || !strings.Contains(out, "funds returned") {
		t.Fatalf("ingest output missing refund rendering: %q", out)
	}
	recs, err := receipts.List(aliceLedger, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Kind != "escrow-refund" || recs[0].Direction != "received" || recs[0].Atomic != fundAtomic {
		t.Fatalf("alice ledger = %+v, want one received escrow-refund of %d", recs, fundAtomic)
	}
}

// ---------------------------------------------------------------- outbox

// TestSettlementOutboxQueueLifecycle pins the queue's file contract: enqueue
// dedupes by kind+txid, save/load round-trips, an empty queue removes the
// file, and a corrupt file is an error (never a silent empty queue — that
// would drop settlement notices without a trace).
func TestSettlementOutboxQueueLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settlement-outbox.json")

	if entries, err := loadSettlementOutbox(path); err != nil || len(entries) != 0 {
		t.Fatalf("missing file: entries=%v err=%v, want empty/nil", entries, err)
	}
	body := []byte(`{"type":"spore/settlement/v1"}`)
	if err := enqueueSettlementNotice(path, "escrow claim", "tx-a", "addr-a", "sess-a", body); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Dedupe: the same settlement must never queue twice.
	if err := enqueueSettlementNotice(path, "escrow claim", "tx-a", "addr-a", "sess-a", body); err != nil {
		t.Fatalf("dedup enqueue: %v", err)
	}
	if err := enqueueSettlementNotice(path, "dex wrap", "tx-b", "addr-b", "sess-b", body); err != nil {
		t.Fatalf("enqueue 2: %v", err)
	}
	entries, err := loadSettlementOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Kind != "escrow claim" || entries[0].TxID != "tx-a" ||
		entries[1].Kind != "dex wrap" || entries[1].TxID != "tx-b" || string(entries[0].Body) != string(body) {
		t.Fatalf("round-trip: %+v", entries)
	}
	if entries[0].QueuedAt == 0 || entries[0].ID == "" {
		t.Fatalf("entry bookkeeping: %+v", entries[0])
	}

	// Empty queue removes the file: a fully delivered queue leaves nothing.
	if err := saveSettlementOutbox(path, nil); err != nil {
		t.Fatalf("save empty: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty queue must remove the file, got stat err=%v", err)
	}

	// Corrupt file: hard error, never a silent empty queue.
	broken := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(broken, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSettlementOutbox(broken); err == nil {
		t.Fatal("corrupt outbox must error, not silently deliver nothing")
	}
}

// TestSettlementOutboxFlushDeliversAndRetains pins flush bookkeeping against
// the REAL announce path: with the body store refusing, every entry fails,
// stays queued, and accumulates Attempts/LastErr; with the store healthy,
// the same entries deliver in queue order and the file disappears.
func TestSettlementOutboxFlushDeliversAndRetains(t *testing.T) {
	env := newSettlementEnv(t)
	dir := t.TempDir()
	aliceAddr, session, keys, _ := env.openThread(env.bobRPC, env.aliceRPC, dir)
	recvKey := e2eRandKey(t)
	sessionHex := hex.EncodeToString(session[:])

	path := filepath.Join(dir, "settlement-outbox.json")
	bodies := [][]byte{
		marshalEscrowNoticeForTest(t, "claim", "aa", "11", "tx-claim", "", 100_000),
		marshalEscrowNoticeForTest(t, "refund", "bb", "", "tx-refund", "", 200_000),
	}
	for i, txid := range []string{"tx-claim", "tx-refund"} {
		if err := enqueueSettlementNotice(path, "escrow", txid, aliceAddr, sessionHex, bodies[i]); err != nil {
			t.Fatalf("enqueue %s: %v", txid, err)
		}
	}

	// Flush with the wallet refusing the pointer post (the body store still
	// accepts): both entries fail and stay queued with bookkeeping.
	stuckRPC := env.refusingWalletRPC("bob")
	fs := env.settlementFlags(stuckRPC, dir)
	if err := fs.Set("state-key", filepath.Join(dir, "state.key")); err != nil {
		t.Fatal(err)
	}
	notice, err := prepareEscrowNotice(fs, aliceAddr, sessionHex)
	if err != nil {
		t.Fatal(err)
	}
	defer notice.close()
	if n, err := flushSettlementOutbox(path, mustLoadOutboxForTest(t, path), notice); err != nil || n != 0 {
		t.Fatalf("stuck flush: delivered=%d err=%v, want 0/nil", n, err)
	}
	stuck, err := loadSettlementOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(stuck) != 2 || stuck[0].Attempts != 1 || stuck[0].LastErr == "" || stuck[1].Attempts != 1 {
		t.Fatalf("stuck entries must retain bookkeeping: %+v", stuck)
	}

	// Healthy flush: both deliver in queue order and the file is removed.
	healthyFS := env.settlementFlags(env.bobRPC, dir)
	if err := healthyFS.Set("state-key", filepath.Join(dir, "state.key")); err != nil {
		t.Fatal(err)
	}
	healthy, err := prepareEscrowNotice(healthyFS, aliceAddr, sessionHex)
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.close()
	delivered, err := flushSettlementOutbox(path, mustLoadOutboxForTest(t, path), healthy)
	if err != nil || delivered != 2 {
		t.Fatalf("healthy flush: delivered=%d err=%v, want 2/nil", delivered, err)
	}
	if _, serr := os.Stat(path); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("delivered queue must remove the file, stat err=%v", serr)
	}

	// The receiver's real ingest pipeline sees both notices in queue order.
	aliceLedger := filepath.Join(dir, "alice-receipts.json")
	ing := env.openReceiver(env.receiverFlagSet(keys, aliceLedger, dir, recvKey))
	out := e2eCaptureStdout(t, func() {
		if n := env.deliverIngestible(ing, env.aliceRPC); n != 3 {
			t.Fatalf("delivered %d pointers, want 3 (opener + 2 retried notices)", n)
		}
	})
	if !strings.Contains(out, "ESCROW CLAIMED") || !strings.Contains(out, "ESCROW REFUNDED") {
		t.Fatalf("ingest output missing retried notice rendering: %q", out)
	}
	recs, err := receipts.List(aliceLedger, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Kind != "escrow-refund" || recs[1].Kind != "escrow-claim" {
		t.Fatalf("alice ledger = %+v, want escrow-claim then escrow-refund (newest first)", recs)
	}
}

// TestSettlementOutboxRetriedByNextCommand closes the failure window the
// failure-injection tests pin, through the REAL command surface: a claim
// whose notice fails (body store 503) queues durably and still exits 0
// (money-first), and the NEXT real settlement command on the same state — a
// dex wrap — flushes the queued claim notice BEFORE its own settlement, so
// alice's history-order ingest renders the claim first and the wrap second,
// exactly the order the sender produced.
func TestSettlementOutboxRetriedByNextCommand(t *testing.T) {
	env := newSettlementEnv(t)
	dir := t.TempDir()
	recvKey := e2eRandKey(t)
	aliceAddr, session, keys, _ := env.openThread(env.bobRPC, env.aliceRPC, dir)
	bobAddr := env.walletAddr(env.bobRPC)
	sessionHex := hex.EncodeToString(session[:])

	preimage := e2eRandKey(t)
	hash := sha256.Sum256(preimage)
	hashHex, preHex := hex.EncodeToString(hash[:]), hex.EncodeToString(preimage)
	const fundAtomic = 4 * 100_000
	env.fundHTLC(bobAddr, hash, fundAtomic)
	balBefore := env.sim.Balance("bob")

	ledger := filepath.Join(dir, "bob-receipts.json")
	// The default outbox lives next to the ratchet state it depends on.
	outboxPath := filepath.Join(dir, "state", "settlement-outbox.json")

	// --- run 1: the claim, with the store refusing the notice PUT ----------
	env.armStoreRefusal()
	claimFS := env.settlementFlags(env.bobRPC, dir)
	if err := claimFS.Set("state-key", filepath.Join(dir, "state.key")); err != nil {
		t.Fatal(err)
	}
	var claimErr error
	claimOut := e2eCaptureStdout(t, func() {
		claimErr = runEscrowClaim(claimFS, hashHex, preHex, aliceAddr, sessionHex, "deal closed", fundAtomic, ledger)
	})
	if claimErr != nil {
		t.Fatalf("claim must succeed even when the notice fails; got %v", claimErr)
	}
	_ = claimOut // the queue-burden report rides stderr; the queue file below is the assertion
	if claimed, _, ok := env.sim.HTLCSettled(hashHex); !ok || !claimed {
		t.Fatalf("claim must have settled: ok=%v claimed=%v", ok, claimed)
	}
	entries, err := loadSettlementOutbox(outboxPath)
	if err != nil || len(entries) != 1 || entries[0].Kind != "escrow claim" {
		t.Fatalf("claim failure must durably queue the notice: entries=%+v err=%v", entries, err)
	}
	if got := env.sim.Balance("bob"); got != balBefore+fundAtomic {
		t.Fatalf("bob balance = %d, want %d (failed notice spends no postage)", got, balBefore+fundAtomic)
	}

	// --- run 2: a REAL dex wrap flushes the queued claim notice first ------
	wrapStdout := e2eCaptureStdout(t, func() {
		msgDEXWrap([]string{
			"-amount", "1dero",
			"-to", aliceAddr,
			"-session", sessionHex,
			"-rpc", env.bobRPC,
			"-store", env.storeURL,
			"-store-token", env.token,
			"-store-dir", filepath.Join(dir, "hold"),
			"-state-dir", filepath.Join(dir, "state"),
			"-state-key", filepath.Join(dir, "state.key"),
			"-receipts", ledger,
			"-config", filepath.Join(dir, "absent-config.json"),
		})
	})
	if !strings.Contains(wrapStdout, "notice retry: delivered queued escrow claim") {
		t.Fatalf("wrap run must flush the queued claim notice: %q", wrapStdout)
	}
	if !strings.Contains(wrapStdout, "WDERO WRAPPED") {
		t.Fatalf("wrap itself must still settle: %q", wrapStdout)
	}
	if _, err := os.Stat(outboxPath); !errors.Is(err, os.ErrNotExist) {
		// The wrap's OWN notice could still be in flight-OK, but the store is
		// healthy so the queue must be empty (wrap notice went direct).
		entries, _ := loadSettlementOutbox(outboxPath)
		t.Fatalf("healthy wrap must leave the queue empty, stat err=%v entries=%+v", err, entries)
	}

	// --- alice's history-order ingest: opener, claim retry, wrap -----------
	aliceLedger := filepath.Join(dir, "alice-receipts.json")
	ing := env.openReceiver(env.receiverFlagSet(keys, aliceLedger, dir, recvKey))
	out := e2eCaptureStdout(t, func() {
		if n := env.deliverIngestible(ing, env.aliceRPC); n != 3 {
			t.Fatalf("delivered %d pointers, want 3 (opener + claim retry + wrap)", n)
		}
	})
	if !strings.Contains(out, "ESCROW CLAIMED") || !strings.Contains(out, "WRAPPED 1 dero -> wdero") {
		t.Fatalf("ingest output missing retried claim + wrap rendering: %q", out)
	}
	recs, err := receipts.List(aliceLedger, "")
	if err != nil {
		t.Fatal(err)
	}
	// Newest first: the wrap notice arrived after the retried claim notice.
	if len(recs) != 2 || recs[0].Kind != "dex-wrap" || recs[0].Atomic != 100_000 ||
		recs[1].Kind != "escrow-claim" || recs[1].Atomic != fundAtomic {
		t.Fatalf("alice ledger = %+v, want received escrow-claim then dex-wrap (newest first)", recs)
	}
}

// TestSettlementOutboxFlushedByRecvE2Receiver pins the RECEIVER-side retry
// cadence: a claim whose notice failed queues durably on the SENDER's state
// (money-first, exit 0), and then `msg recv-e2` itself flushes it — via the
// receiver-flush helper wired into msgRecvE2's startup and poll tick — so
// retries happen at receive cadence even if the sender never settles again.
// The receiver-style ingestor is opened over the SENDER's state-dir with
// fresh prekey files: NewDurableEndpoint restores ALL sessions from the
// state store regardless of identity keys, so its endpoint owns the session
// and can SendNext the retry exactly like the real recv-e2 would. Alice's
// real ingest pipeline must render the flushed claim and ledger it.
func TestSettlementOutboxFlushedByRecvE2Receiver(t *testing.T) {
	env := newSettlementEnv(t)
	dir := t.TempDir()
	recvKey := e2eRandKey(t)
	aliceAddr, session, keys, _ := env.openThread(env.bobRPC, env.aliceRPC, dir)
	bobAddr := env.walletAddr(env.bobRPC)
	sessionHex := hex.EncodeToString(session[:])

	preimage := e2eRandKey(t)
	hash := sha256.Sum256(preimage)
	hashHex, preHex := hex.EncodeToString(hash[:]), hex.EncodeToString(preimage)
	const fundAtomic = 3 * 100_000
	env.fundHTLC(bobAddr, hash, fundAtomic)

	ledger := filepath.Join(dir, "bob-receipts.json")
	outboxPath := filepath.Join(dir, "state", "settlement-outbox.json")

	// --- the claim, with the store refusing the notice PUT ----------------
	env.armStoreRefusal()
	claimFS := env.settlementFlags(env.bobRPC, dir)
	if err := claimFS.Set("state-key", filepath.Join(dir, "state.key")); err != nil {
		t.Fatal(err)
	}
	var claimErr error
	_ = e2eCaptureStdout(t, func() {
		claimErr = runEscrowClaim(claimFS, hashHex, preHex, aliceAddr, sessionHex, "deal closed", fundAtomic, ledger)
	})
	if claimErr != nil {
		t.Fatalf("claim must succeed even when the notice fails; got %v", claimErr)
	}
	entries, err := loadSettlementOutbox(outboxPath)
	if err != nil || len(entries) != 1 || entries[0].Kind != "escrow claim" {
		t.Fatalf("claim failure must durably queue the notice: entries=%+v err=%v", entries, err)
	}

	// --- the receiver-side flush: bob's state-dir, fresh prekey files -----
	// Same flag surface recv-e2 parses (no -notice-outbox flag: the default
	// location next to the state-dir must resolve on its own).
	receiverFS := env.receiverFlagSet(keys, "", dir, recvKey)
	for name, value := range map[string]string{
		"state-dir": filepath.Join(dir, "state"),
		"state-key": filepath.Join(dir, "state.key"),
	} {
		if err := receiverFS.Set(name, value); err != nil {
			t.Fatalf("set -%s: %v", name, err)
		}
	}
	fling := env.openReceiver(receiverFS)
	// openE2Receiver returns a zero carrier (the fabric path never posts);
	// the flush posts through a real bob-side carrier, as msgRecvE2 builds.
	flushCarrier := ratchetwire.ChainCarrier{
		Chain: dero.NewBackend(dero.NewClient(env.bobRPC, "", "")),
		Codec: ratchetwire.DeroChainCodec{},
	}
	flushOut := e2eCaptureStdout(t, func() {
		flushPendingSettlementNoticesForEndpoint(receiverFS, fling.ep, flushCarrier)
	})
	if !strings.Contains(flushOut, "notice retry: delivered queued escrow claim") {
		t.Fatalf("receiver flush must deliver the queued claim notice: %q", flushOut)
	}
	if _, serr := os.Stat(outboxPath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("delivered queue must remove the file, stat err=%v", serr)
	}

	// --- alice's real ingest pipeline renders the flushed claim -----------
	aliceLedger := filepath.Join(dir, "alice-receipts.json")
	ing := env.openReceiver(env.receiverFlagSet(keys, aliceLedger, dir, recvKey))
	out := e2eCaptureStdout(t, func() {
		if n := env.deliverIngestible(ing, env.aliceRPC); n != 2 {
			t.Fatalf("delivered %d pointers, want 2 (opener + flushed claim retry)", n)
		}
	})
	if !strings.Contains(out, "ESCROW CLAIMED") {
		t.Fatalf("ingest output missing flushed claim rendering: %q", out)
	}
	recs, err := receipts.List(aliceLedger, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Kind != "escrow-claim" || recs[0].Atomic != fundAtomic {
		t.Fatalf("alice ledger = %+v, want the received escrow-claim", recs)
	}
}

// marshalEscrowNoticeForTest builds a real escrow envelope for outbox tests.
func marshalEscrowNoticeForTest(t *testing.T, action, hashHex, preimageHex, txid, note string, atomic uint64) []byte {
	t.Helper()
	raw, err := marshalEscrowNotice(action, hashHex, preimageHex, txid, note, atomic)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// mustLoadOutboxForTest loads the queue or fails the test.
func mustLoadOutboxForTest(t *testing.T, path string) []settlementOutboxEntry {
	t.Helper()
	entries, err := loadSettlementOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}
