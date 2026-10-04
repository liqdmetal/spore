package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/derosim"
	"github.com/liqdmetal/spore/internal/mailbox"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
	solanaBackend "github.com/liqdmetal/spore/internal/solana"
)

func approvalFixture(t *testing.T) (CapabilityEnvelope, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	requesterIdentity := bytes.Repeat([]byte{0x31}, 32)
	requesterPrivate, err := secure.SigKeypairOf(requesterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	approverIdentity := bytes.Repeat([]byte{0x52}, 32)
	approverPrivate, err := secure.SigKeypairOf(approverIdentity)
	if err != nil {
		t.Fatal(err)
	}
	approverPublic := approverPrivate.Public().(ed25519.PublicKey)
	var sessionID [8]byte
	copy(sessionID[:], []byte("session1"))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
	envelope, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, 25_000, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := capabilityTranscript(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = hex.EncodeToString(ed25519.Sign(approverPrivate, transcript))
	return envelope, approverPrivate, approverPublic
}

func writeApprovalTestFile(t *testing.T, path string, envelope CapabilityEnvelope) {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCapabilityApprovalRoundTripAndRejections(t *testing.T) {
	envelope, _, approver := approvalFixture(t)
	wantApprover := hex.EncodeToString(approver)
	if err := verifyCapabilityApproval(envelope, wantApprover, time.Now()); err != nil {
		t.Fatalf("valid explicit approval rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CapabilityEnvelope)
	}{
		{"tampered amount", func(e *CapabilityEnvelope) { e.AmountAtomic++ }},
		{"tampered pointer", func(e *CapabilityEnvelope) { e.Pointer = strings.Repeat("00", 74) }},
		{"wrong action", func(e *CapabilityEnvelope) { e.Action = "dero.transfer-anything" }},
		{"wrong protocol version", func(e *CapabilityEnvelope) { e.Version++ }},
		{"wrong approver", func(e *CapabilityEnvelope) { e.Approver = strings.Repeat("00", ed25519.PublicKeySize) }},
		{"wrong sender", func(e *CapabilityEnvelope) { e.SenderAddress = "invalid" }},
		{"bad requester signature", func(e *CapabilityEnvelope) { e.RequesterSignature = strings.Repeat("00", ed25519.SignatureSize*2) }},
		{"reused requester approver", func(e *CapabilityEnvelope) { e.Requester = e.Approver }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			changed := envelope
			tc.mutate(&changed)
			if err := verifyCapabilityApproval(changed, wantApprover, time.Now()); err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
		})
	}
	if err := verifyCapabilityApproval(envelope, hex.EncodeToString(make([]byte, ed25519.PublicKeySize)), time.Now()); err == nil {
		t.Fatal("approval signed by another device accepted")
	}
	expired := envelope
	expired.ExpiresAt = time.Now().Add(-time.Second).Unix()
	if err := verifyCapabilityApproval(expired, wantApprover, time.Now()); err == nil {
		t.Fatal("expired approval accepted")
	}
	tooLong := envelope
	tooLong.ExpiresAt = tooLong.CreatedAt + int64(ApprovalTTL.Seconds()) + 1
	if err := validateCapabilityEnvelope(tooLong, time.Now(), true); err == nil {
		t.Fatal("overlong capability accepted")
	}
	if err := verifyCapabilityApproval(envelope, wantApprover, time.Now().Add(ApprovalTTL)); err == nil {
		t.Fatal("approval accepted after expiry")
	}
}

func TestCapabilityApprovalExplicitHumanConfirmation(t *testing.T) {
	envelope, approverPrivate, approverPublic := approvalFixture(t)
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request.json")
	approvedPath := filepath.Join(dir, "approved.json")
	identityPath := filepath.Join(dir, "approver.key")
	envelope.Signature = ""
	writeApprovalTestFile(t, requestPath, envelope)
	identitySeed := bytes.Repeat([]byte{0x52}, 32)
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(identitySeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := approveCapabilityFile(requestPath, identityPath, approvedPath, false); err == nil || !strings.Contains(err.Error(), "explicit human approval required") {
		t.Fatalf("approval without explicit confirmation error = %v", err)
	}
	if _, err := os.Stat(approvedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("approval without confirmation created a signature: stat error=%v", err)
	}
	if err := approveCapabilityFile(requestPath, identityPath, approvedPath, true); err != nil {
		t.Fatalf("confirmed approval failed: %v", err)
	}
	approved, err := decodeCapabilityFile(approvedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCapabilityApproval(approved, hex.EncodeToString(approverPublic), time.Now()); err != nil {
		t.Fatalf("CLI-generated approval signature did not verify: %v", err)
	}
	if !bytes.Equal(approverPrivate.Public().(ed25519.PublicKey), approverPublic) {
		t.Fatal("test approver keys inconsistent")
	}
}

func TestCapabilityNonceIsOneShotAcrossRestart(t *testing.T) {
	envelope, _, _ := approvalFixture(t)
	stateDir := t.TempDir()
	if err := consumeCapabilityNonce(stateDir, envelope); err != nil {
		t.Fatal(err)
	}
	// A repeated CLI invocation sharing the same state dir must refuse before
	// broadcasting; the exclusive-create ledger is the replay boundary.
	if err := consumeCapabilityNonce(stateDir, envelope); err == nil || !strings.Contains(err.Error(), "replay refused") {
		t.Fatalf("replayed capability error = %v", err)
	}
	if err := consumeCapabilityNonce("", envelope); err == nil {
		t.Fatal("approval without durable replay state accepted")
	}
}

func TestApprovedCapabilityPostsExactPointerOnceOnRealDeroSurface(t *testing.T) {
	envelope, _, approver := approvalFixture(t)
	sim := derosim.New("htlc", "dex", "wdero")
	sim.AddWallet("sender")
	sim.AddWallet("recipient")
	server := httptest.NewServer(sim.Handler())
	defer server.Close()
	senderRPC := server.URL + "/w/sender"
	recipientRPC := server.URL + "/w/recipient"
	senderAddress, err := dero.NewClient(senderRPC, "", "").GetAddress(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recipientAddress, err := dero.NewClient(recipientRPC, "", "").GetAddress(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	envelope.SenderAddress = senderAddress
	envelope.Recipient = recipientAddress
	signRequesterForTest(t, &envelope)
	transcript, err := capabilityTranscript(envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, private := approvalFixtureKeys(t)
	envelope.Signature = hex.EncodeToString(ed25519.Sign(private, transcript))

	identitySeed := bytes.Repeat([]byte{0x31}, 32)
	identityPath := filepath.Join(t.TempDir(), "sender.key")
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(identitySeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	approvalPath := filepath.Join(t.TempDir(), "approved.json")
	writeApprovalTestFile(t, approvalPath, envelope)
	stateDir := t.TempDir()
	stateKey := make([]byte, 32)
	stateKeyPath := filepath.Join(t.TempDir(), "state.key")
	if err := os.WriteFile(stateKeyPath, []byte(hex.EncodeToString(stateKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := newSendApprovalFlags(t, senderRPC, identityPath, stateDir, stateKeyPath, approvalPath, hex.EncodeToString(approver))
	bodyStore, err := mailbox.Open(filepath.Join(t.TempDir(), "body-store"), nil)
	if err != nil {
		t.Fatal(err)
	}
	bodyServer := httptest.NewServer(bodyStore.Handler())
	defer bodyServer.Close()
	if err := fs.Set("store", bodyServer.URL); err != nil {
		t.Fatal(err)
	}
	balanceBefore := sim.Balance("sender")
	if err := postApprovedCapability(fs, recipientAddress, "0.25dero", approvalPath); err != nil {
		t.Fatalf("real DERO approval post failed: %v", err)
	}
	if got := sim.Balance("sender"); got != balanceBefore-25_000 {
		t.Fatalf("sender balance=%d want=%d", got, balanceBefore-25_000)
	}
	entries, err := dero.NewClient(recipientRPC, "", "").GetTransfers(context.Background(), dero.GetTransfersParams{In: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("recipient got %d transfer entries, want exactly one", len(entries))
	}
	posted, err := dero.EntryPayload(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	wantPointer, _ := hex.DecodeString(envelope.Pointer)
	gotPointer, ok := (ratchetwire.DeroChainCodec{}).DecodePointer(posted)
	if !ok || !bytes.Equal(gotPointer.MarshalBinary(), wantPointer) {
		t.Fatalf("posted pointer=%x, want exact approved pointer %x", gotPointer.MarshalBinary(), wantPointer)
	}
	if err := postApprovedCapability(fs, recipientAddress, "0.25dero", approvalPath); err == nil || !strings.Contains(err.Error(), "replay refused") {
		t.Fatalf("same approved capability replay error = %v", err)
	}
	if got := sim.Balance("sender"); got != balanceBefore-25_000 {
		t.Fatalf("replay moved funds: sender balance=%d want=%d", got, balanceBefore-25_000)
	}
}

func TestApprovedCapabilityRejectsAmountRecipientAndWalletMismatchBeforePost(t *testing.T) {
	envelope, _, approver := approvalFixture(t)
	sim := derosim.New("htlc", "dex", "wdero")
	sim.AddWallet("sender")
	sim.AddWallet("recipient")
	server := httptest.NewServer(sim.Handler())
	defer server.Close()
	identitySeed := bytes.Repeat([]byte{0x31}, 32)
	identityPath := filepath.Join(t.TempDir(), "sender.key")
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(identitySeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	recipient := sim.Address("recipient")
	otherRecipient := derosim.ZeroAddress
	if otherRecipient == recipient {
		t.Fatal("sim test addresses unexpectedly match")
	}
	envelope.SenderAddress = sim.Address("sender")
	envelope.Recipient = recipient
	signRequesterForTest(t, &envelope)
	transcript, err := capabilityTranscript(envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, private := approvalFixtureKeys(t)
	envelope.Signature = hex.EncodeToString(ed25519.Sign(private, transcript))
	approvalPath := filepath.Join(t.TempDir(), "approved.json")
	writeApprovalTestFile(t, approvalPath, envelope)
	stateKeyPath := filepath.Join(t.TempDir(), "state.key")
	if err := os.WriteFile(stateKeyPath, []byte(hex.EncodeToString(make([]byte, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := newSendApprovalFlags(t, server.URL+"/w/sender", identityPath, t.TempDir(), stateKeyPath, approvalPath, hex.EncodeToString(approver))
	balance := sim.Balance("sender")
	for _, tc := range []struct{ to, amount string }{{recipient, "0.26dero"}, {otherRecipient, "0.25dero"}} {
		if err := postApprovedCapability(fs, tc.to, tc.amount, approvalPath); err == nil {
			t.Fatalf("mismatched action to=%s amount=%s accepted", tc.to, tc.amount)
		}
	}
	if got := sim.Balance("sender"); got != balance {
		t.Fatalf("rejected mismatched capability moved funds: %d -> %d", balance, got)
	}
}

func newSendApprovalFlags(t *testing.T, rpc, identity, stateDir, stateKey, approvalPath, approver string) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("approved-send", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	e2Common(fs)
	fs.String("identity", "", "")
	fs.String("require-approval", "", "")
	fs.String("approval-request", "", "")
	fs.String("approval-file", "", "")
	for name, value := range map[string]string{
		"chain": "dero", "rpc": rpc, "identity": identity, "from": "", "store": "http://127.0.0.1:1", "state-dir": stateDir,
		"state-key": stateKey, "require-approval": approver, "approval-file": approvalPath,
		"config": filepath.Join(t.TempDir(), "missing-config.json"), "session-ttl": "0s",
	} {
		if err := fs.Set(name, value); err != nil {
			t.Fatalf("set -%s: %v", name, err)
		}
	}
	return fs
}

func signRequesterForTest(t *testing.T, envelope *CapabilityEnvelope) {
	t.Helper()
	private, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := capabilityTranscript(*envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope.RequesterSignature = hex.EncodeToString(ed25519.Sign(private, transcript))
}

func approvalFixtureKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	private, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return private.Public().(ed25519.PublicKey), private
}

func TestEVMCapabilityApprovalRoundTripAndDeliverPost(t *testing.T) {
	requesterIdentity := bytes.Repeat([]byte{0x31}, 32)
	requesterPrivate, err := secure.SigKeypairOf(requesterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	approverIdentity := bytes.Repeat([]byte{0x52}, 32)
	approverPrivate, err := secure.SigKeypairOf(approverIdentity)
	if err != nil {
		t.Fatal(err)
	}
	approverPublic := approverPrivate.Public().(ed25519.PublicKey)
	var sessionID [8]byte
	copy(sessionID[:], []byte("sess-evm"))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()

	senderAddress := "0x1111111111111111111111111111111111111111"
	recipientAddress := "0x2222222222222222222222222222222222222222"
	mailboxAddress := "0x3333333333333333333333333333333333333333"

	envelope, err := newCapabilityEnvelope("evm", senderAddress, recipientAddress, 0, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
	if err != nil {
		t.Fatalf("new EVM capability: %v", err)
	}
	if envelope.Action != capabilityEVMDeliver || envelope.Chain != "evm" {
		t.Fatalf("wrong action=%q chain=%q", envelope.Action, envelope.Chain)
	}
	transcript, err := capabilityTranscript(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = hex.EncodeToString(ed25519.Sign(approverPrivate, transcript))

	wantApprover := hex.EncodeToString(approverPublic)
	if err := verifyCapabilityApproval(envelope, wantApprover, time.Now()); err != nil {
		t.Fatalf("valid EVM capability rejected: %v", err)
	}

	// EVM deliver() is non-payable; any nonzero amount must be rejected
	envelopeNonzero := envelope
	envelopeNonzero.AmountAtomic = 100
	if err := validateCapabilityEnvelope(envelopeNonzero, time.Now(), true); err == nil {
		t.Fatal("payable EVM capability unexpectedly accepted")
	}

	// Mock node that captures the eth_sendTransaction deliver() call
	var postedParams map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string        `json:"method"`
			Params []interface{} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "eth_sendTransaction" && len(req.Params) > 0 {
			if m, ok := req.Params[0].(map[string]interface{}); ok {
				postedParams = m
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "result": "0xfeedbeef00000000000000000000000000000000000000000000000000000001",
		})
	}))
	defer srv.Close()

	identityPath := filepath.Join(t.TempDir(), "sender.key")
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(requesterIdentity)), 0o600); err != nil {
		t.Fatal(err)
	}
	approvalPath := filepath.Join(t.TempDir(), "evm-approved.json")
	writeApprovalTestFile(t, approvalPath, envelope)
	stateDir := t.TempDir()
	stateKeyPath := filepath.Join(t.TempDir(), "state.key")
	if err := os.WriteFile(stateKeyPath, []byte(hex.EncodeToString(make([]byte, 32))), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := flag.NewFlagSet("evm-approved-send", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	e2Common(fs)
	fs.String("identity", "", "")
	fs.String("require-approval", "", "")
	fs.String("approval-request", "", "")
	fs.String("approval-file", "", "")
	for name, value := range map[string]string{
		"chain": "evm", "rpc": srv.URL, "identity": identityPath, "from": senderAddress, "mailbox": mailboxAddress,
		"store": "http://127.0.0.1:1", "state-dir": stateDir, "state-key": stateKeyPath,
		"require-approval": wantApprover, "approval-file": approvalPath,
		"config": filepath.Join(t.TempDir(), "missing-config.json"), "session-ttl": "0s",
	} {
		if err := fs.Set(name, value); err != nil {
			t.Fatalf("set -%s: %v", name, err)
		}
	}

	if err := postApprovedCapability(fs, recipientAddress, "", approvalPath); err != nil {
		t.Fatalf("postApprovedCapability EVM failed: %v", err)
	}

	if postedParams == nil {
		t.Fatal("no transaction was posted to the EVM node")
	}
	if to, ok := postedParams["to"].(string); !ok || !strings.EqualFold(to, mailboxAddress) {
		t.Fatalf("posted to=%v, want mailbox=%v", to, mailboxAddress)
	}
	if from, ok := postedParams["from"].(string); !ok || !strings.EqualFold(from, senderAddress) {
		t.Fatalf("posted from=%v, want sender=%v", from, senderAddress)
	}

	// Replay must be refused immediately
	if err := postApprovedCapability(fs, recipientAddress, "", approvalPath); err == nil || !strings.Contains(err.Error(), "replay refused") {
		t.Fatalf("replayed EVM capability error = %v", err)
	}
}

func TestSolanaCapabilityApprovalRoundTripAndDeliverPost(t *testing.T) {
	requesterIdentity := bytes.Repeat([]byte{0x41}, 32)
	requesterPrivate, err := secure.SigKeypairOf(requesterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	approverIdentity := bytes.Repeat([]byte{0x62}, 32)
	approverPrivate, err := secure.SigKeypairOf(approverIdentity)
	if err != nil {
		t.Fatal(err)
	}
	approverPublic := approverPrivate.Public().(ed25519.PublicKey)
	var sessionID [8]byte
	copy(sessionID[:], []byte("sess-sol"))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()

	senderKey, err := solanaBackend.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	senderAddress := senderKey.PublicKey().String()

	recipientKey, err := solanaBackend.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientAddress := recipientKey.PublicKey().String()

	// Verify PDA derivation helper works for recipient
	expectedInboxPDA, err := solanaBackend.DeriveInboxPDA(solanaBackend.DefaultProgramID, recipientKey.PublicKey())
	if err != nil {
		t.Fatalf("derive inbox PDA: %v", err)
	}

	envelope, err := newCapabilityEnvelope("solana", senderAddress, recipientAddress, 0, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
	if err != nil {
		t.Fatalf("new Solana capability: %v", err)
	}
	if envelope.Action != capabilitySolanaDeliver || envelope.Chain != "solana" {
		t.Fatalf("wrong action=%q chain=%q", envelope.Action, envelope.Chain)
	}
	transcript, err := capabilityTranscript(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = hex.EncodeToString(ed25519.Sign(approverPrivate, transcript))

	wantApprover := hex.EncodeToString(approverPublic)
	if err := verifyCapabilityApproval(envelope, wantApprover, time.Now()); err != nil {
		t.Fatalf("valid Solana capability rejected: %v", err)
	}

	// Solana deliver() is non-payable; any nonzero amount must be rejected
	envelopeNonzero := envelope
	envelopeNonzero.AmountAtomic = 50
	if err := validateCapabilityEnvelope(envelopeNonzero, time.Now(), true); err == nil {
		t.Fatal("payable Solana capability unexpectedly accepted")
	}

	// Mock node that captures the RPC calls
	var sentTxPayload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "getLatestBlockhash" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{
					"context": map[string]any{"slot": 42},
					"value": map[string]any{
						"blockhash":            "11111111111111111111111111111111",
						"lastValidBlockHeight": 1000,
					},
				},
			})
			return
		}
		if req.Method == "sendTransaction" {
			if len(req.Params) > 0 {
				sentTxPayload = fmt.Sprint(req.Params[0])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUc",
			})
			return
		}
	}))
	defer srv.Close()

	identityPath := filepath.Join(t.TempDir(), "sender.key")
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(requesterIdentity)), 0o600); err != nil {
		t.Fatal(err)
	}
	keyfilePath := filepath.Join(t.TempDir(), "solana-sender.json")
	senderKeyBytes, err := json.Marshal([]byte(senderKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyfilePath, senderKeyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	approvalPath := filepath.Join(t.TempDir(), "solana-approved.json")
	writeApprovalTestFile(t, approvalPath, envelope)
	stateDir := t.TempDir()
	stateKeyPath := filepath.Join(t.TempDir(), "state.key")
	if err := os.WriteFile(stateKeyPath, []byte(hex.EncodeToString(make([]byte, 32))), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := flag.NewFlagSet("solana-approved-send", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	e2Common(fs)
	fs.String("identity", "", "")
	fs.String("require-approval", "", "")
	fs.String("approval-request", "", "")
	fs.String("approval-file", "", "")
	for name, value := range map[string]string{
		"chain": "solana", "rpc": srv.URL, "identity": identityPath, "keyfile": keyfilePath,
		"store": "http://127.0.0.1:1", "state-dir": stateDir, "state-key": stateKeyPath,
		"require-approval": wantApprover, "approval-file": approvalPath,
		"config": filepath.Join(t.TempDir(), "missing-config.json"), "session-ttl": "0s",
	} {
		if err := fs.Set(name, value); err != nil {
			t.Fatalf("set -%s: %v", name, err)
		}
	}

	if err := postApprovedCapability(fs, recipientAddress, "", approvalPath); err != nil {
		t.Fatalf("postApprovedCapability Solana failed: %v", err)
	}

	if sentTxPayload == "" {
		t.Fatal("no transaction was posted to the Solana RPC")
	}
	_ = expectedInboxPDA

	// Replay must be refused immediately
	if err := postApprovedCapability(fs, recipientAddress, "", approvalPath); err == nil || !strings.Contains(err.Error(), "replay refused") {
		t.Fatalf("replayed Solana capability error = %v", err)
	}

	// Test approveCapabilityFile human confirmation for Solana
	requestPath := filepath.Join(t.TempDir(), "solana-request.json")
	approvedOutPath := filepath.Join(t.TempDir(), "solana-out.json")
	approverKeyPath := filepath.Join(t.TempDir(), "approver.key")
	if err := os.WriteFile(approverKeyPath, []byte(hex.EncodeToString(approverIdentity)), 0o600); err != nil {
		t.Fatal(err)
	}
	envelopeUnsigned := envelope
	envelopeUnsigned.Signature = ""
	writeApprovalTestFile(t, requestPath, envelopeUnsigned)

	// Refusal without -confirm
	if err := approveCapabilityFile(requestPath, approverKeyPath, approvedOutPath, false); err == nil || !strings.Contains(err.Error(), "explicit human approval required") {
		t.Fatalf("approval without -confirm unexpectedly succeeded: %v", err)
	}
	// Success with -confirm
	if err := approveCapabilityFile(requestPath, approverKeyPath, approvedOutPath, true); err != nil {
		t.Fatalf("approval with -confirm failed: %v", err)
	}
	decodedApproved, err := decodeCapabilityFile(approvedOutPath)
	if err != nil {
		t.Fatalf("decode approved: %v", err)
	}
	if err := verifyCapabilityApproval(decodedApproved, wantApprover, time.Now()); err != nil {
		t.Fatalf("verify signed approval: %v", err)
	}
}

func TestMsgInspectApprovalOutputAndReplayStatus(t *testing.T) {
	envelope, _, approverPublic := approvalFixture(t)
	dir := t.TempDir()
	approvedPath := filepath.Join(dir, "approved.json")
	writeApprovalTestFile(t, approvedPath, envelope)

	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 1. Unspent check
	var buf bytes.Buffer
	captureOutput := func(fn func()) string {
		origStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var b bytes.Buffer
			_, _ = b.ReadFrom(r)
			outC <- b.String()
		}()
		fn()
		_ = w.Close()
		os.Stdout = origStdout
		return <-outC
	}

	outUnspent := captureOutput(func() {
		msgInspectApproval([]string{"-file", approvedPath, "-state-dir", stateDir})
	})
	if !strings.Contains(outUnspent, "dero.transfer-with-pointer") {
		t.Errorf("expected action in output, got:\n%s", outUnspent)
	}
	if !strings.Contains(outUnspent, "UNSPENT") {
		t.Errorf("expected UNSPENT status, got:\n%s", outUnspent)
	}
	if !strings.Contains(outUnspent, "Approver Sig:   VALID") {
		t.Errorf("expected valid approver sig, got:\n%s", outUnspent)
	}
	if !strings.Contains(outUnspent, "Overall Validity: VALID") {
		t.Errorf("expected valid overall status, got:\n%s", outUnspent)
	}

	// 2. Consume nonce and inspect again -> SPENT
	if err := consumeCapabilityNonce(stateDir, envelope); err != nil {
		t.Fatalf("consume nonce: %v", err)
	}
	outSpent := captureOutput(func() {
		msgInspectApproval([]string{"-file", approvedPath, "-state-dir", stateDir})
	})
	if !strings.Contains(outSpent, "Nonce Status:   SPENT") {
		t.Errorf("expected SPENT status, got:\n%s", outSpent)
	}

	// 3. Inspect unsigned request
	requestPath := filepath.Join(dir, "request.json")
	unsigned := envelope
	unsigned.Signature = ""
	writeApprovalTestFile(t, requestPath, unsigned)
	outUnsigned := captureOutput(func() {
		msgInspectApproval([]string{"-file", requestPath})
	})
	if !strings.Contains(outUnsigned, "UNSIGNED (pending approval)") {
		t.Errorf("expected unsigned status, got:\n%s", outUnsigned)
	}
	if !strings.Contains(outUnsigned, "ready for review") {
		t.Errorf("expected ready for review status, got:\n%s", outUnsigned)
	}
	_ = approverPublic
	_ = buf
}
