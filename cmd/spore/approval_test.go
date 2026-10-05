package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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

	"github.com/gagliardetto/solana-go"
	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/derosim"
	"github.com/liqdmetal/spore/internal/evm"
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

// Two-device loop over a real simulated DERO surface: a requester builds a
// capability request for the exact pointer it would post, the approver signs
// it through the batch core (as `msg approve -request-dir` would), the
// requester posts it through the same postApprovedCapability path send-e2
// uses, and the spent ledger + exclusive-create outputs make every stage idempotent.
func TestTwoDeviceApprovalLoopEndToEnd(t *testing.T) {
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

	// Two distinct devices: requester key 0x31 signs the request, approver
	// key 0x52 must be the one that signs the approval.
	requesterPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPublic, _ := approvalFixtureKeys(t)
	approverHex := hex.EncodeToString(approverPublic)

	// The exact pointer the approved send must post: same payload
	// send-e2 would generate for this session right now.
	var sessionID [8]byte
	copy(sessionID[:], []byte("loop0001"))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
	request, err := newCapabilityEnvelope("dero", senderAddress, recipientAddress, 60_000, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Requester device: queue dir holds the pending request.
	queueDir := filepath.Join(t.TempDir(), "queue")
	if err := os.MkdirAll(queueDir, 0o700); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(queueDir, "loop0001.json")
	writeApprovalTestFile(t, requestPath, request)

	// Approver device: identity file, outbox, and the requester's state-dir
	// for spent-nonce hygiene; sign via the batch core, exactly as
	// `msg approve -request-dir QUEUE -out-dir OUTBOX -state-dir STATE -confirm`.
	approverSeed := bytes.Repeat([]byte{0x52}, 32)
	approverKeyPath := filepath.Join(t.TempDir(), "approver.key")
	if err := os.WriteFile(approverKeyPath, []byte(hex.EncodeToString(approverSeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "outbox")
	stateDir := filepath.Join(t.TempDir(), "state")
	results := runApprovalBatch([]string{requestPath}, approverKeyPath, outDir, stateDir, true)
	if len(results) != 1 || results[0].Status != approvalBatchSigned || results[0].Output == "" {
		t.Fatalf("batch approve must sign the pending request, got: %+v", results)
	}
	approvedPath := results[0].Output

	// The signed output must verify against the approver key out-of-band,
	// and the batch result must carry everything a requester needs to build
	// the follow-up send command without re-reading the request.
	approved, err := decodeCapabilityFile(approvedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCapabilityApproval(approved, approverHex, time.Now()); err != nil {
		t.Fatalf("signed output does not verify: %v", err)
	}
	if results[0].Chain != "dero" || results[0].Recipient != recipientAddress || results[0].AmountAtomic != 60_000 {
		t.Fatalf("batch result lost the handoff fields: %+v", results[0])
	}

	// Requester device: post the approval through the exact send-e2 path.
	requesterSeed := bytes.Repeat([]byte{0x31}, 32)
	requesterKeyPath := filepath.Join(t.TempDir(), "requester.key")
	if err := os.WriteFile(requesterKeyPath, []byte(hex.EncodeToString(requesterSeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	stateKeyPath := filepath.Join(t.TempDir(), "state.key")
	if err := os.WriteFile(stateKeyPath, []byte(hex.EncodeToString(make([]byte, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := newSendApprovalFlags(t, senderRPC, requesterKeyPath, stateDir, stateKeyPath, approvedPath, approverHex)
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
	if err := postApprovedCapability(fs, recipientAddress, "0.6dero", approvedPath); err != nil {
		t.Fatalf("approved post failed: %v", err)
	}
	if got := sim.Balance("sender"); got != balanceBefore-60_000 {
		t.Fatalf("sender balance=%d want=%d", got, balanceBefore-60_000)
	}

	// The posted transfer must carry the exact approved pointer.
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
	wantPointer, _ := hex.DecodeString(approved.Pointer)
	gotPointer, ok := (ratchetwire.DeroChainCodec{}).DecodePointer(posted)
	if !ok || !bytes.Equal(gotPointer.MarshalBinary(), wantPointer) {
		t.Fatalf("posted pointer=%x, want exact approved pointer %x", gotPointer.MarshalBinary(), wantPointer)
	}

	// Requester-side replay guard: rerunning the send with the SAME approval
	// must be refused by the spent ledger before any broadcast — the
	// recipient still holds exactly the one transfer posted above.
	if err := postApprovedCapability(fs, recipientAddress, "0.6dero", approvedPath); err == nil || !strings.Contains(err.Error(), "replay refused") {
		t.Fatalf("same DERO approval replay must be refused by the spent ledger, got: %v", err)
	}
	entries, err = dero.NewClient(recipientRPC, "", "").GetTransfers(context.Background(), dero.GetTransfersParams{In: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("replayed post must not broadcast: recipient has %d transfer entries, want 1", len(entries))
	}

	// The nonce burned at post time. Re-offering the same request to the
	// approver (a re-scanned queue, or -watch rescanning forever) is refused
	// with the replay reason — the loop is closed and idempotent.
	reResult := runApprovalBatch([]string{requestPath}, approverKeyPath, outDir, stateDir, true)
	if len(reResult) != 1 || reResult[0].Status != approvalBatchSkipped || !strings.Contains(reResult[0].Reason, "replay refused") {
		t.Fatalf("post-consume rescan must be refused by the spent ledger, got: %+v", reResult)
	}

	// The already-signed envelope survives the rescan as a live queue member:
	// with the shared state-dir it is now SPENT, so the handoff helper must
	// exclude it (the send already happened) while -json marks it spent for
	// pipeline consumers.
	summariesOut := captureApprovalTestOutput(t, func() {
		msgListApprovals([]string{"-dir", outDir, "-state-dir", stateDir, "-json"})
	})
	var summaries []approvalSummary
	if err := json.Unmarshal([]byte(summariesOut), &summaries); err != nil {
		t.Fatalf("unmarshal list-approvals json: %v; raw:\n%s", err, summariesOut)
	}
	if len(summaries) != 1 || summaries[0].Status != "SPENT" || summaries[0].Nonce != approved.Nonce {
		t.Fatalf("outbox summary must mark the consumed approval SPENT, got: %+v", summaries)
	}
	commandsOut := captureApprovalTestOutput(t, func() {
		msgListApprovals([]string{"-dir", outDir, "-state-dir", stateDir, "-print-commands"})
	})
	if !strings.Contains(commandsOut, "no SIGNED approvals ready to send") || strings.Contains(commandsOut, approvedPath) {
		t.Fatalf("handoff must exclude the spent approval, got:\n%s", commandsOut)
	}

	// Posting the same approval again is refused before broadcast.
	if err := postApprovedCapability(fs, recipientAddress, "0.6dero", approvedPath); err == nil || !strings.Contains(err.Error(), "replay refused") {
		t.Fatalf("same approval replay error = %v", err)
	}
	if got := sim.Balance("sender"); got != balanceBefore-60_000 {
		t.Fatalf("replay moved funds: sender balance=%d want=%d", got, balanceBefore-60_000)
	}
}

// runTwoDeviceApprovalLoop is the chain-neutral two-device workflow shared by
// the EVM and Solana loop tests: the requester queues a request for the exact
// pointer it would post, the approver signs it through the batch core (the
// -request-dir/-watch engine), and the requester posts it through the same
// postApprovedCapability path send-e2 uses against the provided mock node.
// replayRefusal must fail the second post. Returns the signed envelope plus
// the approval-spent state dir for the post-loop ledger assertions.
func runTwoDeviceApprovalLoop(t *testing.T, chain, requestPath, approverKeyPath string, amountAtomic uint64, requesterPrivate ed25519.PrivateKey, post func(t *testing.T, fs *flag.FlagSet, to, amount, approvalPath string), buildFlags func(t *testing.T, rpc, identityPath, stateDir, stateKeyPath, approvalPath, approverHex string) *flag.FlagSet) (CapabilityEnvelope, string) {
	t.Helper()
	approverPublic, _ := approvalFixtureKeys(t)
	approverHex := hex.EncodeToString(approverPublic)
	outDir := filepath.Join(t.TempDir(), "outbox")
	stateDir := filepath.Join(t.TempDir(), "state")
	results := runApprovalBatch([]string{requestPath}, approverKeyPath, outDir, stateDir, true)
	if len(results) != 1 || results[0].Status != approvalBatchSigned || results[0].Output == "" {
		t.Fatalf("batch approve must sign the pending %s request, got: %+v", chain, results)
	}
	approvedPath := results[0].Output
	approved, err := decodeCapabilityFile(approvedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCapabilityApproval(approved, approverHex, time.Now()); err != nil {
		t.Fatalf("signed %s output does not verify: %v", chain, err)
	}
	if results[0].Chain != chain || results[0].AmountAtomic != amountAtomic {
		t.Fatalf("batch result lost the %s handoff fields: %+v", chain, results[0])
	}
	identityPath := filepath.Join(t.TempDir(), "requester.key")
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(bytes.Repeat([]byte{0x31}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	stateKeyPath := filepath.Join(t.TempDir(), "state.key")
	if err := os.WriteFile(stateKeyPath, []byte(hex.EncodeToString(make([]byte, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := buildFlags(t, "", identityPath, stateDir, stateKeyPath, approvedPath, approverHex)
	storedRequester, err := hex.DecodeString(approved.Requester)
	if err != nil {
		t.Fatal(err)
	}
	// postApprovedCapability re-derives the requester pub from the -identity
	// file via secure.SigPubOf (a spore-namespaced KDF, NOT the raw key); the
	// identity file must therefore hold the requester identity seed and the
	// envelope must have been requested by that same identity.
	fileSeed, err := readHexFile(identityPath, 32)
	if err != nil {
		t.Fatal(err)
	}
	filePub, err := secure.SigPubOf(fileSeed)
	if err != nil {
		t.Fatal(err)
	}
	wipeBytes(fileSeed)
	if !bytes.Equal(filePub, storedRequester) {
		t.Fatalf("identity file pub %x does not match envelope requester %x", filePub, storedRequester)
	}
	post(t, fs, approved.Recipient, "", approvedPath)
	// The nonce burned at post time: re-offering the same request to the
	// approver (a re-scanned queue, or -watch rescanning forever) is refused
	// with the replay reason.
	reResult := runApprovalBatch([]string{requestPath}, approverKeyPath, outDir, stateDir, true)
	if len(reResult) != 1 || reResult[0].Status != approvalBatchSkipped || !strings.Contains(reResult[0].Reason, "replay refused") {
		t.Fatalf("post-consume rescan must be refused by the spent ledger, got: %+v", reResult)
	}
	// The handoff helper must exclude the consumed envelope (the send already
	// happened) while -json marks it SPENT for pipeline consumers.
	commandsOut := captureApprovalTestOutput(t, func() {
		msgListApprovals([]string{"-dir", outDir, "-state-dir", stateDir, "-print-commands"})
	})
	if !strings.Contains(commandsOut, "no SIGNED approvals ready to send") || strings.Contains(commandsOut, approvedPath) {
		t.Fatalf("handoff must exclude the spent %s approval, got:\n%s", chain, commandsOut)
	}
	summariesOut := captureApprovalTestOutput(t, func() {
		msgListApprovals([]string{"-dir", outDir, "-state-dir", stateDir, "-json"})
	})
	var summaries []approvalSummary
	if err := json.Unmarshal([]byte(summariesOut), &summaries); err != nil {
		t.Fatalf("unmarshal list-approvals json: %v; raw:\n%s", err, summariesOut)
	}
	if len(summaries) != 1 || summaries[0].Status != "SPENT" || summaries[0].Nonce != approved.Nonce {
		t.Fatalf("outbox summary must mark the consumed %s approval SPENT, got: %+v", chain, summaries)
	}
	return approved, stateDir
}

func TestTwoDeviceApprovalLoopEndToEndEVM(t *testing.T) {
	requesterPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPublic, _ := approvalFixtureKeys(t)
	var sessionID [8]byte
	copy(sessionID[:], []byte("loopevm1"))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
	recipientAddress := "0x2222222222222222222222222222222222222222"
	mailboxAddress := "0x3333333333333333333333333333333333333333"
	// The requester's sending key must be the EVM key whose 0x address the
	// envelope is bound to (postApprovedCapability refuses a different sender).
	evmKeyHex := "0102030405060708010203040506070801020304050607080102030405060708" // fixed never-for-funds rehearsal key
	evmAddress, err := evm.AddressForKey(evmKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	request, err := newCapabilityEnvelope("evm", evmAddress, recipientAddress, 0, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if request.Action != capabilityEVMDeliver {
		t.Fatalf("wrong action %q", request.Action)
	}

	// Mock EVM node: a read-only RPC fronted by the SAME local EIP-155
	// signing proxy the evm-proxy command uses (the production path for
	// send-e2). The raw eth_sendRawTransaction layer captures the broadcast so
	// we can prove the delivered calldata is the byte-identical approved
	// pointer.
	var rawTxHex string
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "eth_chainId":
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "0x1"})
		case "eth_getTransactionCount":
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "0x0"})
		case "eth_gasPrice":
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "0x1"})
		case "eth_estimateGas":
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "0x5208"})
		case "eth_sendRawTransaction":
			var params []string
			_ = json.Unmarshal(req.Params, &params)
			if len(params) == 1 {
				rawTxHex = params[0]
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "0xfeedbeef00000000000000000000000000000000000000000000000000000001"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32000, "message": "no such method: " + req.Method}})
		}
	}))
	defer node.Close()
	proxy, err := evm.NewProxy(node.URL, evmKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(proxy.Handler())
	defer srv.Close()

	queueDir := filepath.Join(t.TempDir(), "queue")
	if err := os.MkdirAll(queueDir, 0o700); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(queueDir, "loopevm1.json")
	writeApprovalTestFile(t, requestPath, request)
	approverKeyPath := filepath.Join(t.TempDir(), "approver.key")
	if err := os.WriteFile(approverKeyPath, []byte(hex.EncodeToString(bytes.Repeat([]byte{0x52}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	post := func(t *testing.T, fs *flag.FlagSet, to, amount, approvalPath string) {
		t.Helper()
		if err := postApprovedCapability(fs, to, "", approvalPath); err != nil {
			t.Fatalf("approved EVM post failed: %v", err)
		}
		// Replaying the same approval must be refused by the spent ledger
		// before any broadcast.
		if err := postApprovedCapability(fs, to, "", approvalPath); err == nil || !strings.Contains(err.Error(), "replay refused") {
			t.Fatalf("same EVM approval replay error = %v", err)
		}
	}
	buildFlags := func(t *testing.T, _, identityPath, stateDir, stateKeyPath, approvalPath, approver string) *flag.FlagSet {
		t.Helper()
		fs := flag.NewFlagSet("evm-loop-send", flag.ContinueOnError)
		fs.SetOutput(new(bytes.Buffer))
		e2Common(fs)
		fs.String("identity", "", "")
		fs.String("require-approval", "", "")
		fs.String("approval-request", "", "")
		fs.String("approval-file", "", "")
		for name, value := range map[string]string{
			"chain": "evm", "rpc": srv.URL, "identity": identityPath, "from": evmAddress, "mailbox": mailboxAddress,
			"store": "http://127.0.0.1:1", "state-dir": stateDir, "state-key": stateKeyPath,
			"require-approval": approver, "approval-file": approvalPath,
			"config": filepath.Join(t.TempDir(), "missing-config.json"), "session-ttl": "0s",
		} {
			if err := fs.Set(name, value); err != nil {
				t.Fatalf("set -%s: %v", name, err)
			}
		}
		return fs
	}
	approved, _ := runTwoDeviceApprovalLoop(t, "evm", requestPath, approverKeyPath, 0, requesterPrivate, post, buildFlags)

	// The broadcast raw transaction must carry the deliver() calldata holding
	// the JSON-encoded approved pointer (EVM/Solana ride the JSONCodec), with
	// the recipient address the envelope approved.
	if rawTxHex == "" {
		t.Fatal("no raw transaction was broadcast to the EVM node")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(rawTxHex, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := ratchetwire.JSONCodec{}.EncodePointer(mustParsePointerPayload(t, approved.Pointer))
	if err != nil {
		t.Fatal(err)
	}
	var wantRecipient [20]byte
	reqBytes, _ := hex.DecodeString(strings.TrimPrefix(recipientAddress, "0x"))
	copy(wantRecipient[:], reqBytes)
	if !bytes.Contains(raw, encoded) || !bytes.Contains(raw, wantRecipient[:]) {
		t.Fatalf("broadcast tx calldata does not carry the approved pointer for %s", recipientAddress)
	}
}

func TestTwoDeviceApprovalLoopEndToEndSolana(t *testing.T) {
	requesterPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPublic, _ := approvalFixtureKeys(t)
	var sessionID [8]byte
	copy(sessionID[:], []byte("loopsol1"))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
	// Deterministic sender keypair from a fixed seed: ed25519.NewKeyFromSeed
	// yields seed(32) || pub(32), exactly the solana.PrivateKey layout. The
	// requester's -identity (ed25519 0x41) and this Solana signer are separate
	// keys by design: the envelope binds the ed25519 requester, the carrier
	// flags bind this signer.
	senderKey := solana.PrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, 32)))
	recipientKey, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	expectedInboxPDA, err := solanaBackend.DeriveInboxPDA(solanaBackend.DefaultProgramID, recipientKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	request, err := newCapabilityEnvelope("solana", senderKey.PublicKey().String(), recipientKey.PublicKey().String(), 0, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if request.Action != capabilitySolanaDeliver {
		t.Fatalf("wrong action %q", request.Action)
	}

	// Mock Solana RPC: satisfy getLatestBlockhash, capture sendTransaction.
	var sentTxPayload string
	var sendTxCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "getLatestBlockhash":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{
					"context": map[string]any{"slot": 42},
					"value":   map[string]any{"blockhash": "11111111111111111111111111111111", "lastValidBlockHeight": 1000},
				},
			})
		case "sendTransaction":
			sendTxCount++
			// Decode the base64 wire tx and capture its message bytes so the
			// assertion can prove the approved recipient's inbox PDA rides in
			// the account keys (the mock's error path also mirrors a real
			// node's preflight failure when the payer is not funded).
			if len(req.Params) > 0 {
				if txB64, ok := req.Params[0].(string); ok {
					if raw, derr := base64.StdEncoding.DecodeString(txB64); derr == nil {
						sentTxPayload = string(raw)
					}
				}
			}
			// Simulate the node's preflight: the payer has no funds in this
			// mock, which surfaces as an RPC error after the tx is captured.
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32002, "message": "Transaction simulation failed", "data": map[string]any{"err": "InvalidAccountForFee", "logs": []string{}}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32000, "message": "no such method: " + req.Method}})
		}
	}))
	defer srv.Close()

	queueDir := filepath.Join(t.TempDir(), "queue")
	if err := os.MkdirAll(queueDir, 0o700); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(queueDir, "loopsol1.json")
	writeApprovalTestFile(t, requestPath, request)
	approverKeyPath := filepath.Join(t.TempDir(), "approver.key")
	if err := os.WriteFile(approverKeyPath, []byte(hex.EncodeToString(bytes.Repeat([]byte{0x52}, 32))), 0o600); err != nil {
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
	post := func(t *testing.T, fs *flag.FlagSet, to, amount, approvalPath string) {
		t.Helper()
		// The mock node deliberately fails the send (preflight: unfunded payer,
		// the one thing a mock cannot fake) AFTER receiving the fully signed
		// transaction; postApprovedCapability must surface that as the
		// ambiguous-broadcast burn so the approval cannot be retried unsafely.
		err := postApprovedCapability(fs, to, "", approvalPath)
		if err == nil {
			t.Fatalf("mock Solana node rejected the send but postApprovedCapability reported success")
		}
		if !strings.Contains(err.Error(), "broadcast result is ambiguous") {
			t.Fatalf("expected ambiguous-broadcast burn on mock rejection, got: %v", err)
		}
		// The retry after the ambiguous broadcast must be refused by the
		// spent ledger: the nonce was burned even though the RPC result was
		// never confirmed — the at-most-once promise in its adversarial form.
		if err := postApprovedCapability(fs, to, "", approvalPath); err == nil || !strings.Contains(err.Error(), "replay refused") {
			t.Fatalf("retry after ambiguous Solana broadcast must be replay-refused, got: %v", err)
		}
	}
	buildFlags := func(t *testing.T, _, identityPath, stateDir, stateKeyPath, approvalPath, approver string) *flag.FlagSet {
		t.Helper()
		fs := flag.NewFlagSet("solana-loop-send", flag.ContinueOnError)
		fs.SetOutput(new(bytes.Buffer))
		e2Common(fs)
		fs.String("identity", "", "")
		fs.String("require-approval", "", "")
		fs.String("approval-request", "", "")
		fs.String("approval-file", "", "")
		for name, value := range map[string]string{
			"chain": "solana", "rpc": srv.URL, "identity": identityPath, "keyfile": keyfilePath,
			"store": "http://127.0.0.1:1", "state-dir": stateDir, "state-key": stateKeyPath,
			"require-approval": approver, "approval-file": approvalPath,
			"config": filepath.Join(t.TempDir(), "missing-config.json"), "session-ttl": "0s",
		} {
			if err := fs.Set(name, value); err != nil {
				t.Fatalf("set -%s: %v", name, err)
			}
		}
		return fs
	}
	runTwoDeviceApprovalLoop(t, "solana", requestPath, approverKeyPath, 0, requesterPrivate, post, buildFlags)

	// The submitted (mock-rejected, but captured) transaction must reference
	// the approved recipient's inbox PDA in its account keys — the Solana
	// deliver surface this approval authorizes. The transaction is fully
	// signed by the payer key from -keyfile before submission.
	if sentTxPayload == "" {
		t.Fatal("no transaction was submitted to the Solana RPC")
	}
	if !bytes.Contains([]byte(sentTxPayload), expectedInboxPDA.Bytes()) {
		t.Fatalf("submitted tx does not reference the approved recipient inbox PDA %s", expectedInboxPDA)
	}
	if !bytes.Contains([]byte(sentTxPayload), senderKey.PublicKey().Bytes()) {
		t.Fatalf("submitted tx was not signed by the -keyfile payer %s", senderKey.PublicKey())
	}
	// Exactly ONE sendTransaction ever reached the node — the ambiguous
	// first attempt. The retry was refused by the spent ledger before any
	// broadcast could be constructed.
	if sendTxCount != 1 {
		t.Fatalf("sendTransaction reached the node %d times, want exactly 1", sendTxCount)
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

// TestApprovedCapabilityExpiredMidFlightRefusedBeforeBroadcast pins the
// 15-minute TTL at its worst moment: an approval that was valid when signed
// but expired before the requester's send rerun must be refused by envelope
// validation — before the nonce burn and before any broadcast.
func TestApprovedCapabilityExpiredMidFlightRefusedBeforeBroadcast(t *testing.T) {
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
	envelope.SenderAddress = sim.Address("sender")
	envelope.Recipient = sim.Address("recipient")
	// Mid-flight expiry: the window was well inside the TTL when signed, but
	// the rerun happens one second after ExpiresAt. CreatedAt stays inside
	// the future-creation tolerance.
	envelope.CreatedAt = time.Now().Add(-10 * time.Minute).Unix()
	envelope.ExpiresAt = time.Now().Add(-1 * time.Second).Unix()
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
	if err := postApprovedCapability(fs, envelope.Recipient, "0.25dero", approvalPath); err == nil || !strings.Contains(err.Error(), "approval envelope: expired") {
		t.Fatalf("expired approval must be refused before broadcast, got: %v", err)
	}
	if got := sim.Balance("sender"); got != balance {
		t.Fatalf("expired approval moved funds: %d -> %d", balance, got)
	}
	entries, err := dero.NewClient(server.URL+"/w/recipient", "", "").GetTransfers(context.Background(), dero.GetTransfersParams{In: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expired approval must not broadcast, recipient got %d transfer(s)", len(entries))
	}
}

// TestApprovedCapabilityWarnsOnShortTTLHeadroom pins the operator warning:
// an approval inside its final two minutes still broadcasts, but the send
// rerun says so on stderr; a comfortable approval stays quiet.
func TestApprovedCapabilityWarnsOnShortTTLHeadroom(t *testing.T) {
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
	for _, tc := range []struct {
		name        string
		headroom    time.Duration
		wantWarning bool
	}{
		{"short", 90 * time.Second, true},
		{"comfortable", 13 * time.Minute, false},
	} {
		envelope, _, approver := approvalFixture(t)
		envelope.SenderAddress = sim.Address("sender")
		envelope.Recipient = sim.Address("recipient")
		// A 14-minute window: comfortably inside the 15-minute TTL cap.
		envelope.CreatedAt = time.Now().Add(-1 * time.Minute).Unix()
		envelope.ExpiresAt = time.Now().Add(tc.headroom).Unix()
		signRequesterForTest(t, &envelope)
		transcript, err := capabilityTranscript(envelope)
		if err != nil {
			t.Fatal(err)
		}
		_, private := approvalFixtureKeys(t)
		envelope.Signature = hex.EncodeToString(ed25519.Sign(private, transcript))
		approvalPath := filepath.Join(t.TempDir(), "approved-"+tc.name+".json")
		writeApprovalTestFile(t, approvalPath, envelope)
		stateKeyPath := filepath.Join(t.TempDir(), "state-"+tc.name+".key")
		if err := os.WriteFile(stateKeyPath, []byte(hex.EncodeToString(make([]byte, 32))), 0o600); err != nil {
			t.Fatal(err)
		}
		fs := newSendApprovalFlags(t, server.URL+"/w/sender", identityPath, t.TempDir(), stateKeyPath, approvalPath, hex.EncodeToString(approver))
		outC := make(chan string)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			var b bytes.Buffer
			_, _ = b.ReadFrom(r)
			outC <- b.String()
		}()
		origStderr := os.Stderr
		os.Stderr = w
		postErr := postApprovedCapability(fs, envelope.Recipient, "0.25dero", approvalPath)
		_ = w.Close()
		os.Stderr = origStderr
		warning := <-outC
		if postErr != nil {
			t.Fatalf("%s: approved post failed: %v", tc.name, postErr)
		}
		if got := strings.Contains(warning, "expires in"); got != tc.wantWarning {
			t.Fatalf("%s: stderr warning = %v (want %v), stderr:\n%s", tc.name, got, tc.wantWarning, warning)
		}
	}
}

// TestWatchMetricsDueAndReport pins the -watch station's self-metrics: the
// heartbeat fires once per period (never inside it, never when disabled),
// and the report renders the same summary the metrics command does over the
// station's live artifacts.
func TestWatchMetricsDueAndReport(t *testing.T) {
	var next time.Time
	now := time.Unix(1_000_000, 0)
	if watchMetricsDue(&next, 0, now) {
		t.Fatal("metrics-every=0 must disable the heartbeat")
	}
	// The loop schedules the first heartbeat one full period out.
	next = now.Add(10 * time.Minute)
	if watchMetricsDue(&next, 10*time.Minute, now.Add(time.Minute)) {
		t.Fatal("heartbeat must not fire inside the period")
	}
	if !watchMetricsDue(&next, 10*time.Minute, now.Add(10*time.Minute)) {
		t.Fatal("heartbeat must fire at the period boundary")
	}
	if !next.Equal(now.Add(20 * time.Minute)) {
		t.Fatalf("schedule must advance by one period, got %v", next)
	}

	// Report over live artifacts: one pending request, no outbox, no ledger.
	queueDir, _ := lockTestRequest(t, t.TempDir(), "selfmet", time.Now())
	queueDir = filepath.Dir(queueDir)
	outDir := filepath.Join(t.TempDir(), "outbox")
	stateDir := filepath.Join(t.TempDir(), "state")
	out := captureApprovalTestOutput(t, func() {
		watchMetricsReport(queueDir, outDir, stateDir, time.Now())
	})
	for _, want := range []string{
		"approve: self-metrics at ",
		"queue: 1 request(s)",
		"status: PENDING=1",
		"locks: 0 live",
		"ledger: 0 spent nonce(s)",                         // fresh station: empty ledger
		"outbox: 0 signed output(s), 0 signed-but-unspent", // fresh station: outbox exists, empty
	} {
		if !strings.Contains(out, want) {
			t.Errorf("self-metrics report missing %q, got:\n%s", want, out)
		}
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

// mustParsePointerPayload parses a hex pointer field into a PointerPayload
// (approval_test local helper for the chain-assertion steps).
func mustParsePointerPayload(t *testing.T, hexPointer string) ratchetwire.PointerPayload {
	t.Helper()
	raw, err := hex.DecodeString(hexPointer)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ratchetwire.ParsePointerPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// captureApprovalTestOutput runs fn with os.Stdout swapped for a pipe and
// returns everything it printed (approval_test local variant of the capture
// pattern used across the suite).
func captureApprovalTestOutput(t *testing.T, fn func()) string {
	t.Helper()
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
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

	// 4. Test -json output format
	outJSON := captureOutput(func() {
		msgInspectApproval([]string{"-file", approvedPath, "-state-dir", stateDir, "-json"})
	})
	var jsonRes struct {
		PointerSHA256 string `json:"pointer_sha256"`
		Valid         bool   `json:"valid"`
		Signed        bool   `json:"signed"`
		NonceStatus   string `json:"nonce_status"`
	}
	if err := json.Unmarshal([]byte(outJSON), &jsonRes); err != nil {
		t.Fatalf("unmarshal -json inspect output: %v; raw:\n%s", err, outJSON)
	}
	if !jsonRes.Valid || !jsonRes.Signed || jsonRes.NonceStatus != "SPENT" {
		t.Errorf("unexpected json result: %+v", jsonRes)
	}

	// 5. Test -require-approver match
	wantApproverHex := hex.EncodeToString(approverPublic)
	outMatch := captureOutput(func() {
		msgInspectApproval([]string{"-file", approvedPath, "-require-approver", wantApproverHex})
	})
	if !strings.Contains(outMatch, "Capability Envelope:") {
		t.Errorf("expected inspect output on approver match, got:\n%s", outMatch)
	}
	_ = buf
}

func TestMsgListApprovals(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	envelope1, _, _ := approvalFixture(t) // DERO signed
	envelope1Path := filepath.Join(dir, "1_dero_signed.json")
	writeApprovalTestFile(t, envelope1Path, envelope1)

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
	copy(sessionID[:], []byte("session2"))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
	envelope2, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, 15_000, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	envelope2Path := filepath.Join(dir, "2_dero_pending.json")
	writeApprovalTestFile(t, envelope2Path, envelope2)

	// Consume envelope1's nonce so it becomes SPENT
	if err := consumeCapabilityNonce(stateDir, envelope1); err != nil {
		t.Fatal(err)
	}

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

	// 1. Text listing (all)
	outAll := captureOutput(func() {
		msgListApprovals([]string{"-dir", dir, "-state-dir", stateDir})
	})
	if !strings.Contains(outAll, "SPENT") || !strings.Contains(outAll, "PENDING") {
		t.Errorf("expected SPENT and PENDING in list output:\n%s", outAll)
	}

	// 2. Filter status: pending
	outPending := captureOutput(func() {
		msgListApprovals([]string{"-dir", dir, "-state-dir", stateDir, "-status", "pending"})
	})
	if strings.Contains(outPending, "SPENT") || !strings.Contains(outPending, "PENDING") {
		t.Errorf("expected only PENDING in filtered output:\n%s", outPending)
	}

	// 3. JSON output format
	outJSON := captureOutput(func() {
		msgListApprovals([]string{"-dir", dir, "-state-dir", stateDir, "-json"})
	})
	var list []approvalSummary
	if err := json.Unmarshal([]byte(outJSON), &list); err != nil {
		t.Fatalf("unmarshal json list: %v; raw:\n%s", err, outJSON)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 envelopes, got %d", len(list))
	}
	foundSpent, foundPending := false, false
	for _, item := range list {
		if item.Status == "SPENT" {
			foundSpent = true
		}
		if item.Status == "PENDING" {
			foundPending = true
		}
	}
	if !foundSpent || !foundPending {
		t.Errorf("expected spent and pending items in json summary, got: %+v", list)
	}
}

func TestMsgApproveBatch(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "signed")
	identitySeed := bytes.Repeat([]byte{0x52}, 32)
	identityPath := filepath.Join(dir, "approver.key")
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(identitySeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	requesterPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPrivate, err := secure.SigKeypairOf(identitySeed)
	if err != nil {
		t.Fatal(err)
	}
	approverPublic := approverPrivate.Public().(ed25519.PublicKey)
	buildEnvelope := func(amount uint64) CapabilityEnvelope {
		var sessionID [8]byte
		copy(sessionID[:], []byte("batch001"))
		pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
		envelope, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, amount, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	pendingA := filepath.Join(dir, "a_pending.json")
	writeApprovalTestFile(t, pendingA, buildEnvelope(5_000))
	pendingB := filepath.Join(dir, "b_pending.json")
	writeApprovalTestFile(t, pendingB, buildEnvelope(7_000))
	signedPath := filepath.Join(dir, "c_signed.json")
	signedEnv, _, _ := approvalFixture(t) // already signed by the 0x52 approver
	writeApprovalTestFile(t, signedPath, signedEnv)
	invalidPath := filepath.Join(dir, "d_invalid.json")
	invalidEnv := buildEnvelope(9_000)
	invalidEnv.ExpiresAt = time.Now().Add(-time.Minute).Unix() // expiry no longer covered by requester sig
	writeApprovalTestFile(t, invalidPath, invalidEnv)
	unrelatedPath := filepath.Join(dir, "unrelated.json")
	if err := os.WriteFile(unrelatedPath, []byte(`{"hello":"world"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	batch := []string{pendingA, pendingB, signedPath, invalidPath}
	countStatus := func(results []approvalBatchResult, status string) int {
		n := 0
		for _, r := range results {
			if r.Status == status {
				n++
			}
		}
		return n
	}

	// 1. Dry run (no -confirm): everything is skipped, nothing is written.
	results := runApprovalBatch(batch, identityPath, outDir, "", false)
	if len(results) != 4 || countStatus(results, "skipped") != 4 {
		t.Fatalf("dry run should skip all four requests, got: %+v", results)
	}
	if _, err := os.Stat(outDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run created output dir: stat error=%v", err)
	}

	// 2. Confirmed run: only the two pending requests are signed and verify.
	results = runApprovalBatch(batch, identityPath, outDir, "", true)
	if len(results) != 4 || countStatus(results, "signed") != 2 || countStatus(results, "skipped") != 2 || countStatus(results, "failed") != 0 {
		t.Fatalf("confirmed batch outcomes wrong, got: %+v", results)
	}
	for _, r := range results {
		if r.Status != "signed" {
			continue
		}
		if r.Nonce == "" || r.Output == "" {
			t.Fatalf("signed result missing nonce/output: %+v", r)
		}
		signedFile, err := decodeCapabilityFile(r.Output)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyCapabilityApproval(signedFile, hex.EncodeToString(approverPublic), time.Now()); err != nil {
			t.Fatalf("batch-signed approval %s did not verify: %v", r.Output, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "a_pending.signed.json")); err != nil {
		t.Fatalf("expected a_pending.signed.json in out-dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "c_signed.signed.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("already-signed request must not be re-signed: stat error=%v", err)
	}

	// 3. Directory scan picks up exactly the capability envelopes.
	scanned, err := scanApprovalRequestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 4 {
		t.Fatalf("expected 4 capability envelopes in scan, got %d: %v", len(scanned), scanned)
	}

	// 4. Rerun: exclusive-create outputs turn into per-file failures, not overwrites.
	results = runApprovalBatch([]string{pendingA, pendingB}, identityPath, outDir, "", true)
	if countStatus(results, "failed") != 2 {
		t.Fatalf("rerun over existing outputs must fail per file, got: %+v", results)
	}

	// 5. JSON report matches the results.
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
	outJSON := captureOutput(func() {
		renderApprovalBatchReport(results, true)
	})
	var report struct {
		Signed  int                   `json:"signed"`
		Skipped int                   `json:"skipped"`
		Failed  int                   `json:"failed"`
		Results []approvalBatchResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(outJSON), &report); err != nil {
		t.Fatalf("unmarshal batch json: %v; raw:\n%s", err, outJSON)
	}
	if report.Signed != 0 || report.Skipped != 0 || report.Failed != 2 || len(report.Results) != 2 {
		t.Fatalf("unexpected batch report: %+v", report)
	}
	for _, r := range report.Results {
		if r.Chain != "dero" || r.Recipient == "" || r.Nonce == "" {
			t.Fatalf("batch report result missing envelope fields: %+v", r)
		}
	}

	// 6. Requests addressed to another approver device are skipped, not signed.
	otherIdentity := filepath.Join(dir, "other.key")
	if err := os.WriteFile(otherIdentity, []byte(hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	otherApproverPath := filepath.Join(dir, "e_other_approver.json")
	writeApprovalTestFile(t, otherApproverPath, buildEnvelope(11_000))
	results = runApprovalBatch([]string{otherApproverPath}, otherIdentity, outDir, "", true)
	if len(results) != 1 || results[0].Status != "skipped" || !strings.Contains(results[0].Reason, "different approver") {
		t.Fatalf("other-approver request must be skipped, got: %+v", results)
	}
}

func TestMsgApproveBatchCLI(t *testing.T) {
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

	dir := t.TempDir()
	identitySeed := bytes.Repeat([]byte{0x52}, 32)
	identityPath := filepath.Join(dir, "approver.key")
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(identitySeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	requesterPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPrivate, err := secure.SigKeypairOf(identitySeed)
	if err != nil {
		t.Fatal(err)
	}
	approverPublic := approverPrivate.Public().(ed25519.PublicKey)

	// Empty queue: -json still emits a valid empty report.
	emptyQueue := filepath.Join(dir, "empty")
	if err := os.MkdirAll(emptyQueue, 0o700); err != nil {
		t.Fatal(err)
	}
	emptyOut := filepath.Join(dir, "signed-empty")
	outJSON := captureOutput(func() {
		msgApprove([]string{"-request-dir", emptyQueue, "-identity", identityPath, "-out-dir", emptyOut, "-confirm", "-json"})
	})
	var emptyReport struct {
		Signed  int                   `json:"signed"`
		Skipped int                   `json:"skipped"`
		Failed  int                   `json:"failed"`
		Results []approvalBatchResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(outJSON), &emptyReport); err != nil {
		t.Fatalf("unmarshal empty batch json: %v; raw:\n%s", err, outJSON)
	}
	if emptyReport.Signed != 0 || len(emptyReport.Results) != 0 {
		t.Fatalf("unexpected empty batch report: %+v", emptyReport)
	}

	// Single pending request in a scanned queue dir gets signed via the CLI.
	queueDir := filepath.Join(dir, "queue")
	if err := os.MkdirAll(queueDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var sessionID [8]byte
	copy(sessionID[:], []byte("batch002"))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
	pending, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, 3_000, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeApprovalTestFile(t, filepath.Join(queueDir, "pending.json"), pending)
	outDir := filepath.Join(dir, "signed")
	outJSON = captureOutput(func() {
		msgApprove([]string{"-request-dir", queueDir, "-identity", identityPath, "-out-dir", outDir, "-state-dir", filepath.Join(dir, "state"), "-confirm", "-json"})
	})
	var report struct {
		Signed  int                   `json:"signed"`
		Skipped int                   `json:"skipped"`
		Failed  int                   `json:"failed"`
		Results []approvalBatchResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(outJSON), &report); err != nil {
		t.Fatalf("unmarshal batch json: %v; raw:\n%s", err, outJSON)
	}
	if report.Signed != 1 || report.Skipped != 0 || report.Failed != 0 || len(report.Results) != 1 || report.Results[0].Output == "" {
		t.Fatalf("unexpected batch report: %+v", report)
	}
	signedFile, err := decodeCapabilityFile(report.Results[0].Output)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCapabilityApproval(signedFile, hex.EncodeToString(approverPublic), time.Now()); err != nil {
		t.Fatalf("CLI batch approval did not verify: %v", err)
	}
}

func TestValidateApproveWatchFlags(t *testing.T) {
	cases := []struct {
		name         string
		requestDir   string
		request      string
		confirm      bool
		asJSON       bool
		every        time.Duration
		metricsEvery time.Duration
		wantErr      string
	}{
		{"valid", "queue", "", true, false, 30 * time.Second, 10 * time.Minute, ""},
		{"missing request-dir", "", "", true, false, 30 * time.Second, 10 * time.Minute, "-watch requires -request-dir"},
		{"-request rejected", "queue", "a.json", true, false, 30 * time.Second, 10 * time.Minute, "use -request-dir instead of -request"},
		{"-confirm required", "queue", "", false, false, 30 * time.Second, 10 * time.Minute, "pass -confirm"},
		{"-json rejected", "queue", "", true, true, 30 * time.Second, 10 * time.Minute, "-json is not supported in -watch mode"},
		{"zero interval", "queue", "", true, false, 0, 10 * time.Minute, "-every must be a positive duration"},
		{"negative interval", "queue", "", true, false, -time.Second, 10 * time.Minute, "-every must be a positive duration"},
		{"disabled metrics-every", "queue", "", true, false, 30 * time.Second, 0, ""},
		{"negative metrics-every", "queue", "", true, false, 30 * time.Second, -time.Minute, "-metrics-every must be a positive duration or 0"},
	}
	for _, tc := range cases {
		err := validateApproveWatchFlags(tc.requestDir, tc.request, tc.confirm, tc.asJSON, tc.every, tc.metricsEvery)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: want error containing %q, got: %v", tc.name, tc.wantErr, err)
		}
	}
}

func TestRunApprovalWatchCycle(t *testing.T) {
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

	dir := t.TempDir()
	identitySeed := bytes.Repeat([]byte{0x52}, 32)
	identityPath := filepath.Join(dir, "approver.key")
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(identitySeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	requesterPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPrivate, err := secure.SigKeypairOf(identitySeed)
	if err != nil {
		t.Fatal(err)
	}
	approverPublic := approverPrivate.Public().(ed25519.PublicKey)
	queueDir := filepath.Join(dir, "queue")
	outDir := filepath.Join(dir, "signed")
	if err := os.MkdirAll(queueDir, 0o700); err != nil {
		t.Fatal(err)
	}
	makeEnvelope := func(tag string, amount uint64) string {
		var sessionID [8]byte
		copy(sessionID[:], []byte(tag))
		pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
		envelope, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, amount, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(queueDir, tag+".json")
		writeApprovalTestFile(t, path, envelope)
		return path
	}

	seen := make(map[string]string)
	// Cycle 1 with an empty queue: nothing signed, no output, no error.
	signed, failed, err := runApprovalWatchCycle(queueDir, identityPath, outDir, "", true, seen)
	if err != nil || signed != 0 || failed != 0 {
		t.Fatalf("empty queue cycle: signed=%d failed=%d err=%v", signed, failed, err)
	}

	// Cycle 2: one request appears and gets signed; the report includes the
	// post-signing handoff line.
	pendingPath := makeEnvelope("watch001", 4_000)
	out := captureOutput(func() {
		signed, failed, err = runApprovalWatchCycle(queueDir, identityPath, outDir, "", true, seen)
	})
	if err != nil || signed != 1 || failed != 0 {
		t.Fatalf("cycle with one pending request: signed=%d failed=%d err=%v", signed, failed, err)
	}
	if !strings.Contains(out, "SIGNED  "+pendingPath) || !strings.Contains(out, "-approval-file "+filepath.Join(outDir, "watch001.signed.json")) {
		t.Errorf("expected signed report with handoff, got:\n%s", out)
	}

	// Cycle 3: the same queue again — the signed file is skipped as "already
	// signed" with no output (deduped), and nothing is re-signed.
	out = captureOutput(func() {
		signed, failed, err = runApprovalWatchCycle(queueDir, identityPath, outDir, "", true, seen)
	})
	if err != nil || signed != 0 || failed != 0 {
		t.Fatalf("steady-state rerun cycle: signed=%d failed=%d err=%v", signed, failed, err)
	}
	if strings.Contains(out, "SIGNED") {
		t.Errorf("steady-state rerun must stay quiet, got:\n%s", out)
	}

	// A request that leaves the queue loses its dedup entry, so re-arriving
	// is reported again. Use an other-approver request (never signable, so it
	// stays SKIPPED and never gains a signed output) to exercise that path.
	approverOtherPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x99}, 32))
	if err != nil {
		t.Fatal(err)
	}
	makeOtherApprover := func() CapabilityEnvelope {
		var sessionID [8]byte
		copy(sessionID[:], []byte("watch002"))
		pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
		envelope, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, 6_000, pointer, sessionID, requesterPrivate, approverOtherPrivate.Public().(ed25519.PublicKey), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	otherPath := filepath.Join(queueDir, "other.json")
	writeApprovalTestFile(t, otherPath, makeOtherApprover())
	out = captureOutput(func() {
		signed, failed, err = runApprovalWatchCycle(queueDir, identityPath, outDir, "", true, seen)
	})
	if err != nil || !strings.Contains(out, "SKIPPED "+otherPath) {
		t.Fatalf("other-approver request must be skipped and reported once, out:\n%s", out)
	}
	// Unchanged status next cycle: deduped, quiet.
	out = captureOutput(func() {
		signed, failed, err = runApprovalWatchCycle(queueDir, identityPath, outDir, "", true, seen)
	})
	if err != nil || signed != 0 || failed != 0 || strings.Contains(out, otherPath) {
		t.Errorf("unchanged status must stay quiet, out:\n%s", out)
	}
	// Leave the queue and come back: reported again.
	if err := os.Remove(otherPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runApprovalWatchCycle(queueDir, identityPath, outDir, "", true, seen); err != nil {
		t.Fatal(err)
	}
	writeApprovalTestFile(t, otherPath, makeOtherApprover())
	out = captureOutput(func() {
		signed, failed, err = runApprovalWatchCycle(queueDir, identityPath, outDir, "", true, seen)
	})
	if err != nil || !strings.Contains(out, "SKIPPED "+otherPath) {
		t.Errorf("re-arriving file must be re-reported, out:\n%s", out)
	}
}

func TestMsgApproveBatchSkipsSpentNonces(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "signed")
	stateDir := filepath.Join(dir, "state")
	identitySeed := bytes.Repeat([]byte{0x52}, 32)
	identityPath := filepath.Join(dir, "approver.key")
	if err := os.WriteFile(identityPath, []byte(hex.EncodeToString(identitySeed)), 0o600); err != nil {
		t.Fatal(err)
	}
	requesterPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPrivate, err := secure.SigKeypairOf(identitySeed)
	if err != nil {
		t.Fatal(err)
	}
	approverPublic := approverPrivate.Public().(ed25519.PublicKey)
	buildEnvelope := func(amount uint64) CapabilityEnvelope {
		var sessionID [8]byte
		copy(sessionID[:], []byte("spent001"))
		pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
		envelope, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, amount, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	spentPath := filepath.Join(dir, "spent.json")
	spentEnv := buildEnvelope(1_000)
	writeApprovalTestFile(t, spentPath, spentEnv)
	freshPath := filepath.Join(dir, "fresh.json")
	writeApprovalTestFile(t, freshPath, buildEnvelope(2_000))

	if err := consumeCapabilityNonce(stateDir, spentEnv); err != nil {
		t.Fatal(err)
	}

	// With -state-dir the burned request is skipped with a replay reason and
	// only the fresh one is signed.
	results := runApprovalBatch([]string{spentPath, freshPath}, identityPath, outDir, stateDir, true)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got: %+v", results)
	}
	if results[0].Status != "skipped" || !strings.Contains(results[0].Reason, "replay") {
		t.Fatalf("spent-nonce request must be skipped with replay reason, got: %+v", results[0])
	}
	if results[1].Status != "signed" {
		t.Fatalf("fresh request must be signed, got: %+v", results[1])
	}

	// Negative control: without -state-dir the same spent request is signed
	// again, proving the skip came from the replay ledger, not the envelope.
	otherOut := filepath.Join(dir, "signed-nostate")
	results = runApprovalBatch([]string{spentPath}, identityPath, otherOut, "", true)
	if len(results) != 1 || results[0].Status != "signed" {
		t.Fatalf("spent request without -state-dir must still be signed, got: %+v", results)
	}
}

func TestMsgListApprovalsPrintCommands(t *testing.T) {
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

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	envelopeSigned, _, _ := approvalFixture(t) // DERO signed, valid
	signedPath := filepath.Join(dir, "1_dero_signed.json")
	writeApprovalTestFile(t, signedPath, envelopeSigned)

	requesterPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPrivate, err := secure.SigKeypairOf(bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	approverPublic := approverPrivate.Public().(ed25519.PublicKey)
	var sessionID [8]byte
	copy(sessionID[:], []byte("prntcmd1"))
	pointer := ratchetwire.PointerPayload{Version: ratchetwire.PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}.MarshalBinary()
	pending, err := newCapabilityEnvelope("dero", derosim.ZeroAddress, derosim.ZeroAddress, 7_500, pointer, sessionID, requesterPrivate, approverPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pendingPath := filepath.Join(dir, "2_dero_pending.json")
	writeApprovalTestFile(t, pendingPath, pending)

	// 1. Placeholders: -identity/-pinned-sig omitted -> IDENTITY/PINNED_SIG.
	out := captureOutput(func() {
		msgListApprovals([]string{"-dir", dir, "-state-dir", stateDir, "-print-commands"})
	})
	if !strings.Contains(out, "spore msg send-e2 -chain dero -to "+envelopeSigned.Recipient) ||
		!strings.Contains(out, "-approval-file "+signedPath) ||
		!strings.Contains(out, "-require-approval "+envelopeSigned.Approver) ||
		!strings.Contains(out, "-identity IDENTITY") ||
		!strings.Contains(out, "-pinned-sig PINNED_SIG") {
		t.Errorf("expected ready-to-run command with placeholders, got:\n%s", out)
	}
	if !strings.Contains(out, "# 1 PENDING (not ready to send)") || strings.Contains(out, pendingPath) {
		t.Errorf("pending envelopes must be counted, never emitted as commands, got:\n%s", out)
	}
	if strings.Contains(out, "no SIGNED approvals") {
		t.Errorf("unexpected empty notice when a signed envelope exists:\n%s", out)
	}

	// 2. Embedded identity and pinned sig land in the command verbatim.
	pinned := hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))
	out = captureOutput(func() {
		msgListApprovals([]string{"-dir", dir, "-state-dir", stateDir, "-print-commands", "-identity", "req.key", "-pinned-sig", pinned})
	})
	if !strings.Contains(out, "-identity req.key") || !strings.Contains(out, "-pinned-sig "+pinned) {
		t.Errorf("expected embedded identity and pinned sig, got:\n%s", out)
	}

	// 3. -status signed selects exactly the signed envelope (no pending line).
	out = captureOutput(func() {
		msgListApprovals([]string{"-dir", dir, "-state-dir", stateDir, "-print-commands", "-status", "signed"})
	})
	if !strings.Contains(out, "-approval-file "+signedPath) || strings.Contains(out, "PENDING") {
		t.Errorf("-status signed must emit only the signed command, got:\n%s", out)
	}

	// 4. -json and -print-commands are mutually exclusive.
	if err := validateListApprovalsFlags(true, true); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual-exclusion error, got: %v", err)
	}
	if err := validateListApprovalsFlags(true, false); err != nil {
		t.Errorf("unexpected error for -print-commands alone: %v", err)
	}
}
