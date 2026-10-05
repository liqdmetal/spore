// Second-device approval for one exact DERO transfer-with-pointer action.
// The signed envelope carries its expiry and nonce so retries do not silently
// change the approved action and a consumed approval cannot be replayed.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/evm"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
	solanaBackend "github.com/liqdmetal/spore/internal/solana"
)

const (
	ApprovalTTL = 15 * time.Minute
	// approvalTTLHeadroomWarn: the send rerun warns the operator when an
	// approval is inside this much of its remaining TTL — still valid, but a
	// stalled handoff will hit expiry instead of the chain.
	approvalTTLHeadroomWarn = 2 * time.Minute
	capabilityProtocol      = "spore.capability-approval"
	capabilityVersion       = 1
	capabilityDeroTransfer  = "dero.transfer-with-pointer"
	capabilityEVMDeliver    = "evm.deliver-with-pointer"
	capabilitySolanaDeliver = "solana.deliver-with-pointer"
	capabilityNonceSize     = 16
	maxCapabilityFileBytes  = 16 << 10
)

// CapabilityEnvelope is the only action currently accepted by the approval
// gate: an exact DERO value transfer carrying one opaque E2 pointer.
type CapabilityEnvelope struct {
	Protocol           string `json:"protocol"`
	Version            int    `json:"version"`
	Action             string `json:"action"`
	Chain              string `json:"chain"`
	Requester          string `json:"requester_public_key"`
	RequesterSignature string `json:"requester_signature"`
	SenderAddress      string `json:"sender_address"`
	Recipient          string `json:"recipient"`
	AmountAtomic       uint64 `json:"amount_atomic"`
	Pointer            string `json:"pointer"` // canonical ratchetwire pointer bytes, hex encoded
	SessionID          string `json:"session_id"`
	CreatedAt          int64  `json:"created_at_unix"`
	ExpiresAt          int64  `json:"expires_at_unix"`
	Nonce              string `json:"nonce"`
	Approver           string `json:"approver_public_key"`
	Signature          string `json:"signature,omitempty"`
}

func newCapabilityEnvelope(chain, senderAddress, recipient string, amount uint64, pointer []byte, sessionID [8]byte, requesterPrivate ed25519.PrivateKey, approver ed25519.PublicKey, now time.Time) (CapabilityEnvelope, error) {
	var nonce [capabilityNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return CapabilityEnvelope{}, fmt.Errorf("approval nonce: %w", err)
	}
	if len(requesterPrivate) != ed25519.PrivateKeySize {
		return CapabilityEnvelope{}, errors.New("approval requester key must be a 64-byte Ed25519 private key")
	}
	created := now.Unix()
	requester := requesterPrivate.Public().(ed25519.PublicKey)
	action := capabilityDeroTransfer
	if strings.EqualFold(chain, "evm") {
		action = capabilityEVMDeliver
		chain = "evm"
	} else if strings.EqualFold(chain, "solana") {
		action = capabilitySolanaDeliver
		chain = "solana"
	} else {
		chain = "dero"
	}
	e := CapabilityEnvelope{
		Protocol: capabilityProtocol, Version: capabilityVersion, Action: action,
		Chain: chain, Requester: hex.EncodeToString(requester), SenderAddress: senderAddress, Recipient: recipient, AmountAtomic: amount,
		Pointer: hex.EncodeToString(pointer), SessionID: hex.EncodeToString(sessionID[:]), CreatedAt: created,
		ExpiresAt: created + int64(ApprovalTTL.Seconds()),
		Nonce:     hex.EncodeToString(nonce[:]), Approver: hex.EncodeToString(approver),
	}
	transcript, err := capabilityTranscript(e)
	if err != nil {
		return CapabilityEnvelope{}, fmt.Errorf("approval transcript: %w", err)
	}
	e.RequesterSignature = hex.EncodeToString(ed25519.Sign(requesterPrivate, transcript))
	if err := validateCapabilityEnvelope(e, now, false); err != nil {
		return CapabilityEnvelope{}, err
	}
	return e, nil
}

func decodeCapabilityFile(path string) (CapabilityEnvelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return CapabilityEnvelope{}, fmt.Errorf("approval file: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxCapabilityFileBytes+1))
	if err != nil {
		return CapabilityEnvelope{}, fmt.Errorf("approval file: read: %w", err)
	}
	if len(raw) > maxCapabilityFileBytes {
		return CapabilityEnvelope{}, fmt.Errorf("approval file: exceeds %d-byte limit", maxCapabilityFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var e CapabilityEnvelope
	if err := dec.Decode(&e); err != nil {
		return CapabilityEnvelope{}, fmt.Errorf("approval file: decode envelope: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return CapabilityEnvelope{}, errors.New("approval file: contains multiple JSON values")
		}
		return CapabilityEnvelope{}, fmt.Errorf("approval file: trailing JSON: %w", err)
	}
	return e, nil
}

// writeCapabilityFile never overwrites a pending request or an existing
// approval. That avoids replacing the payload while another device reviews it.
func writeCapabilityFile(path string, e CapabilityEnvelope) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("approval file path is required")
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("approval file: encode envelope: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("approval file: create %s: %w", path, err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("approval file: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("approval file: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("approval file: close: %w", err)
	}
	ok = true
	return nil
}

func validateCapabilityEnvelope(e CapabilityEnvelope, now time.Time, signed bool) error {
	if e.Protocol != capabilityProtocol || e.Version != capabilityVersion {
		return errors.New("approval envelope: unsupported protocol or version")
	}
	switch e.Action {
	case capabilityDeroTransfer:
		if e.Chain != "dero" {
			return errors.New("approval envelope: dero.transfer-with-pointer requires chain=dero")
		}
		if _, err := dero.ValidateAddress(e.Recipient); err != nil {
			return fmt.Errorf("approval envelope: invalid DERO recipient: %w", err)
		}
		if _, err := dero.ValidateAddress(e.SenderAddress); err != nil {
			return fmt.Errorf("approval envelope: invalid DERO sender address: %w", err)
		}
		if e.AmountAtomic == 0 {
			return errors.New("approval envelope: amount_atomic must be greater than zero for DERO transfer")
		}
	case capabilityEVMDeliver:
		if e.Chain != "evm" {
			return errors.New("approval envelope: evm.deliver-with-pointer requires chain=evm")
		}
		if _, err := evm.ValidateAddress(e.Recipient); err != nil {
			return fmt.Errorf("approval envelope: invalid EVM recipient: %w", err)
		}
		if _, err := evm.ValidateAddress(e.SenderAddress); err != nil {
			return fmt.Errorf("approval envelope: invalid EVM sender address: %w", err)
		}
		if e.AmountAtomic != 0 {
			return errors.New("approval envelope: EVM mailbox deliver() is not payable; amount_atomic must be 0")
		}
	case capabilitySolanaDeliver:
		if e.Chain != "solana" {
			return errors.New("approval envelope: solana.deliver-with-pointer requires chain=solana")
		}
		if _, err := solanaBackend.ValidateAddress(e.Recipient); err != nil {
			return fmt.Errorf("approval envelope: invalid Solana recipient: %w", err)
		}
		if _, err := solanaBackend.ValidateAddress(e.SenderAddress); err != nil {
			return fmt.Errorf("approval envelope: invalid Solana sender address: %w", err)
		}
		if e.AmountAtomic != 0 {
			return errors.New("approval envelope: Solana program deliver() is not payable; amount_atomic must be 0")
		}
	default:
		return errors.New("approval envelope: unsupported action")
	}
	if e.Recipient == "" || strings.TrimSpace(e.Recipient) != e.Recipient || len(e.Recipient) > 512 {
		return errors.New("approval envelope: invalid recipient")
	}
	requester, err := hex.DecodeString(e.Requester)
	if err != nil || len(requester) != ed25519.PublicKeySize || hex.EncodeToString(requester) != e.Requester {
		return errors.New("approval envelope: requester_public_key must be 64 lowercase hex characters")
	}
	pointer, err := hex.DecodeString(e.Pointer)
	if err != nil || hex.EncodeToString(pointer) != e.Pointer {
		return errors.New("approval envelope: pointer must be canonical lowercase hex")
	}
	if _, err := ratchetwire.ParsePointerPayload(pointer); err != nil {
		return fmt.Errorf("approval envelope: invalid E2 pointer: %w", err)
	}
	nonce, err := hex.DecodeString(e.Nonce)
	if err != nil || len(nonce) != capabilityNonceSize || hex.EncodeToString(nonce) != e.Nonce {
		return errors.New("approval envelope: nonce must be 32 lowercase hex characters")
	}
	sessionID, err := hex.DecodeString(e.SessionID)
	if err != nil || len(sessionID) != 8 || hex.EncodeToString(sessionID) != e.SessionID {
		return errors.New("approval envelope: session_id must be 16 lowercase hex characters")
	}
	approver, err := hex.DecodeString(e.Approver)
	if err != nil || len(approver) != ed25519.PublicKeySize || hex.EncodeToString(approver) != e.Approver {
		return errors.New("approval envelope: approver_public_key must be 64 lowercase hex characters")
	}
	if bytes.Equal(requester, approver) {
		return errors.New("approval envelope: requester and approver keys must be distinct")
	}
	requesterSig, err := hex.DecodeString(e.RequesterSignature)
	if err != nil || len(requesterSig) != ed25519.SignatureSize || hex.EncodeToString(requesterSig) != e.RequesterSignature {
		return errors.New("approval envelope: requester_signature must be 128 lowercase hex characters")
	}
	transcript, err := capabilityTranscript(e)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(requester), transcript, requesterSig) {
		return errors.New("approval envelope: requester signature does not verify")
	}
	if signed {
		approvalSig, err := hex.DecodeString(e.Signature)
		if err != nil || len(approvalSig) != ed25519.SignatureSize || hex.EncodeToString(approvalSig) != e.Signature {
			return errors.New("approval envelope: signature must be 128 lowercase hex characters")
		}
		if !ed25519.Verify(ed25519.PublicKey(approver), transcript, approvalSig) {
			return errors.New("approval signature does not verify; refusing to post")
		}
	} else if e.Signature != "" {
		return errors.New("approval request must be unsigned")
	}
	if e.CreatedAt <= 0 || e.ExpiresAt <= e.CreatedAt || e.ExpiresAt-e.CreatedAt > int64(ApprovalTTL.Seconds()) {
		return errors.New("approval envelope: invalid or overlong expiry")
	}
	if e.CreatedAt > now.Unix()+30 {
		return errors.New("approval envelope: creation time is in the future")
	}
	if now.Unix() >= e.ExpiresAt {
		return errors.New("approval envelope: expired")
	}
	return nil
}

// capabilityTranscript is a domain-separated, fixed-width/length-prefixed
// signing representation. The signature covers every authority-bearing field
// and the hash of the exact pointer bytes, not JSON serialization details.
func capabilityTranscript(e CapabilityEnvelope) ([]byte, error) {
	pointer, err := hex.DecodeString(e.Pointer)
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(e.Nonce)
	if err != nil {
		return nil, err
	}
	approver, err := hex.DecodeString(e.Approver)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("spore/capability-approval/v1\x00")
	writeField := func(value []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		out.Write(length[:])
		out.Write(value)
	}
	writeField([]byte(e.Protocol))
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], uint32(e.Version))
	out.Write(version[:])
	writeField([]byte(e.Action))
	writeField([]byte(e.Chain))
	requester, err := hex.DecodeString(e.Requester)
	if err != nil {
		return nil, err
	}
	writeField(requester)
	writeField([]byte(e.SenderAddress))
	writeField([]byte(e.Recipient))
	sessionID, err := hex.DecodeString(e.SessionID)
	if err != nil {
		return nil, err
	}
	writeField(sessionID)
	var amount [8]byte
	binary.BigEndian.PutUint64(amount[:], e.AmountAtomic)
	out.Write(amount[:])
	pointerHash := sha256.Sum256(pointer)
	out.Write(pointerHash[:])
	var created, expires [8]byte
	binary.BigEndian.PutUint64(created[:], uint64(e.CreatedAt))
	binary.BigEndian.PutUint64(expires[:], uint64(e.ExpiresAt))
	out.Write(created[:])
	out.Write(expires[:])
	writeField(nonce)
	writeField(approver)
	return out.Bytes(), nil
}

func approveCapabilityFile(requestPath, identityPath, outputPath string, confirm bool) error {
	e, err := decodeCapabilityFile(requestPath)
	if err != nil {
		return err
	}
	// The one-shot path races watch stations on the same queue, so it takes
	// the same per-request signing lock the batch core uses. Dry runs never
	// sign and never lock.
	if !confirm {
		return approveCapabilityEnvelope(e, identityPath, outputPath, false)
	}
	release, busy, lockErr := lockApprovalRequest(requestPath, time.Now())
	if lockErr != nil {
		return fmt.Errorf("signing lock: %w", lockErr)
	}
	if busy != "" {
		return errors.New(busy)
	}
	err = approveCapabilityEnvelope(e, identityPath, outputPath, true)
	release()
	return err
}

// printCapabilityActionReview writes the exact human-reviewable action (what
// moves, where, which pointer, until when) to stderr before any signature.
func printCapabilityActionReview(e CapabilityEnvelope) {
	pointer, _ := hex.DecodeString(e.Pointer)
	pointerHash := sha256.Sum256(pointer)
	expires := time.Unix(e.ExpiresAt, 0).UTC().Format(time.RFC3339)
	switch e.Action {
	case capabilityEVMDeliver:
		fmt.Fprintf(os.Stderr, "EVM mailbox deliver approval: 0 value from %s to %s; pointer sha256 %x; requested by %s; expires %s\n", e.SenderAddress, e.Recipient, pointerHash, e.Requester, expires)
	case capabilitySolanaDeliver:
		fmt.Fprintf(os.Stderr, "Solana program deliver approval: 0 value from %s to %s; pointer sha256 %x; requested by %s; expires %s\n", e.SenderAddress, e.Recipient, pointerHash, e.Requester, expires)
	default:
		fmt.Fprintf(os.Stderr, "DERO transfer approval: %s DERO (%d atomic units) from %s to %s; pointer sha256 %x; requested by %s; expires %s\n", formatAmount("dero", e.AmountAtomic), e.AmountAtomic, e.SenderAddress, e.Recipient, pointerHash, e.Requester, expires)
	}
}

// approveCapabilityEnvelope validates and signs an already-decoded capability
// request after printing a human review of the exact action; shared by the
// single-file and batch approve paths.
func approveCapabilityEnvelope(e CapabilityEnvelope, identityPath, outputPath string, confirm bool) error {
	if err := validateCapabilityEnvelope(e, time.Now(), false); err != nil {
		return err
	}
	seed, err := readHexFile(identityPath, 32)
	if err != nil {
		return fmt.Errorf("approval identity: %w", err)
	}
	privateKey, err := secure.SigKeypairOf(seed)
	if err != nil {
		return fmt.Errorf("approval identity: %w", err)
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
		for i := range privateKey {
			privateKey[i] = 0
		}
	}()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	approver, _ := hex.DecodeString(e.Approver)
	if !bytes.Equal(publicKey, approver) {
		return errors.New("approval request names a different approver key")
	}
	printCapabilityActionReview(e)
	if !confirm {
		return errors.New("explicit human approval required; review the action above and retry with -confirm")
	}
	transcript, err := capabilityTranscript(e)
	if err != nil {
		return fmt.Errorf("approval transcript: %w", err)
	}
	e.Signature = hex.EncodeToString(ed25519.Sign(privateKey, transcript))
	return writeCapabilityFile(outputPath, e)
}

func verifyCapabilityApproval(e CapabilityEnvelope, expectedApprover string, now time.Time) error {
	if err := validateCapabilityEnvelope(e, now, true); err != nil {
		return err
	}
	expected, err := hex.DecodeString(expectedApprover)
	if err != nil || len(expected) != ed25519.PublicKeySize {
		return errors.New("-require-approval must be a 64-hex Ed25519 public key")
	}
	approver, _ := hex.DecodeString(e.Approver)
	if !bytes.Equal(approver, expected) {
		return errors.New("approval envelope is for a different -require-approval key")
	}
	transcript, err := capabilityTranscript(e)
	if err != nil {
		return fmt.Errorf("approval transcript: %w", err)
	}
	sig, _ := hex.DecodeString(e.Signature)
	if !ed25519.Verify(ed25519.PublicKey(approver), transcript, sig) {
		return errors.New("approval signature does not verify; refusing to post")
	}
	return nil
}

// consumeCapabilityNonce atomically burns the signed nonce before broadcast.
// This is deliberately at-most-once: after an ambiguous RPC result, retrying
// the same approval cannot accidentally send a duplicate payment.
func consumeCapabilityNonce(stateDir string, e CapabilityEnvelope) error {
	if strings.TrimSpace(stateDir) == "" {
		return errors.New("approved DERO send requires -state-dir for replay protection")
	}
	dir := filepath.Join(stateDir, "approval-spent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("approval replay guard: create state: %w", err)
	}
	path := filepath.Join(dir, e.Nonce+".spent")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("approval nonce was already consumed; replay refused")
		}
		return fmt.Errorf("approval replay guard: reserve nonce: %w", err)
	}
	transcript, err := capabilityTranscript(e)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	digest := sha256.Sum256(transcript)
	if _, err := fmt.Fprintf(f, "%x\n", digest); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("approval replay guard: persist nonce: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("approval replay guard: sync nonce: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("approval replay guard: close nonce: %w", err)
	}
	return nil
}

// validateCapabilityRequestFlags enforces the second-device capability flag
// combinations on the send paths: -require-approval must name a distinct
// approver key, the chain must support typed capabilities, escrow is refused,
// and -amount must match the chain (positive DERO; none for EVM/Solana).
func validateCapabilityRequestFlags(fs *flag.FlagSet, chainName, amount, escrow string, requester ed25519.PublicKey) error {
	approverHex := flagValueOr(fs, "require-approval", "")
	requestPath := flagValueOr(fs, "approval-request", "")
	approvalPath := flagValueOr(fs, "approval-file", "")
	if approverHex == "" {
		if requestPath != "" || approvalPath != "" {
			return errors.New("-approval-request and -approval-file require -require-approval")
		}
		return nil
	}
	if requestPath != "" && approvalPath != "" {
		return errors.New("-approval-request cannot be combined with -approval-file")
	}
	if !strings.EqualFold(chainName, "dero") && !strings.EqualFold(chainName, "evm") && !strings.EqualFold(chainName, "solana") {
		return errors.New("second-device capabilities currently support DERO, EVM, and Solana only")
	}
	if escrow != "" {
		return errors.New("second-device capabilities do not authorize HTLC escrow")
	}
	if strings.EqualFold(chainName, "dero") {
		asset, atomic, err := parseAmountFlag(amount)
		if err != nil {
			return err
		}
		if asset != "dero" || atomic == 0 {
			return errors.New("second-device capability requires a positive DERO -amount")
		}
	} else if strings.EqualFold(chainName, "evm") {
		if amount != "" {
			return errors.New("second-device capability on EVM mailbox path does not accept -amount")
		}
	} else if strings.EqualFold(chainName, "solana") {
		if amount != "" {
			return errors.New("second-device capability on Solana deliver path does not accept -amount")
		}
	}
	approver, err := hex.DecodeString(approverHex)
	if err != nil || len(approver) != ed25519.PublicKeySize {
		return errors.New("-require-approval must be a 64-hex Ed25519 public key")
	}
	if len(requester) != ed25519.PublicKeySize {
		return errors.New("second-device capability requires the sending -identity")
	}
	if bytes.Equal(requester, approver) {
		return errors.New("-require-approval must identify a distinct second-device key")
	}
	return nil
}

func sendIdentityPublic(identityPath string) (ed25519.PublicKey, []byte, error) {
	if strings.TrimSpace(identityPath) == "" {
		return nil, nil, errors.New("sending -identity is required")
	}
	seed, err := readHexFile(identityPath, 32)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := secure.SigPubOf(seed)
	if err != nil {
		for i := range seed {
			seed[i] = 0
		}
		return nil, nil, err
	}
	return ed25519.PublicKey(publicKey), seed, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func validateApprovalForSend(fs *flag.FlagSet, chainName, amount, escrow, identityPath string) ([]byte, error) {
	requester, seed, err := sendIdentityPublic(identityPath)
	if err != nil {
		return nil, fmt.Errorf("sending identity: %w", err)
	}
	if err := validateCapabilityRequestFlags(fs, chainName, amount, escrow, requester); err != nil {
		wipeBytes(seed)
		return nil, err
	}
	return seed, nil
}

func validateApprovalWithoutSigningKey(fs *flag.FlagSet, chainName, amount, escrow string) error {
	if flagValueOr(fs, "require-approval", "") == "" {
		return validateCapabilityRequestFlags(fs, chainName, amount, escrow, nil)
	}
	return errors.New("second-device capability requires the sending -identity")
}

func prepareCapabilityApproval(fs *flag.FlagSet, chainName, senderAddress, recipient, amount string, pointer []byte, sessionID [8]byte, requester ed25519.PrivateKey) error {
	approverHex := flagValueOr(fs, "require-approval", "")
	requestPath := flagValueOr(fs, "approval-request", "")
	if approverHex == "" {
		return validateApprovalWithoutSigningKey(fs, chainName, amount, flagValueOr(fs, "escrow", ""))
	}
	if flagValueOr(fs, "approval-file", "") != "" {
		return errors.New("internal: signed approval must be handled before creating a new E2 frame")
	}
	if len(requester) != ed25519.PrivateKeySize {
		return errors.New("second-device capability requires the sending identity signing key")
	}
	requesterPublic := requester.Public().(ed25519.PublicKey)
	if err := validateCapabilityRequestFlags(fs, chainName, amount, flagValueOr(fs, "escrow", ""), requesterPublic); err != nil {
		return err
	}
	var atomic uint64
	if strings.EqualFold(chainName, "dero") {
		_, a, err := parseAmountFlag(amount)
		if err != nil {
			return err
		}
		atomic = a
	}
	approver, err := hex.DecodeString(approverHex)
	if err != nil {
		return err
	}
	envelope, err := newCapabilityEnvelope(chainName, senderAddress, recipient, atomic, pointer, sessionID, requester, ed25519.PublicKey(approver), time.Now())
	if err != nil {
		return err
	}
	path := requestPath
	if path == "" {
		stateDir := flagValueOr(fs, "state-dir", "")
		if stateDir == "" {
			return errors.New("second-device capability requires -state-dir to store its pending request")
		}
		path = filepath.Join(stateDir, "approval-"+envelope.Nonce+".json")
	}
	if err := writeCapabilityFile(path, envelope); err != nil {
		return err
	}
	return fmt.Errorf("second-device approval required; review %s on the approver device with `spore msg approve -request %s -identity KEY -out SIGNED.json -confirm`, then rerun this exact %s send with -approval-file SIGNED.json (valid until %s)", path, path, strings.ToUpper(chainName), time.Unix(envelope.ExpiresAt, 0).UTC().Format(time.RFC3339))
}

func postApprovedCapability(fs *flag.FlagSet, recipient, amount, approvalPath string) error {
	approverHex := flagValueOr(fs, "require-approval", "")
	if approverHex == "" {
		return errors.New("-approval-file requires -require-approval")
	}
	chain := strings.ToLower(flagValueOr(fs, "chain", ""))
	if chain != "dero" && chain != "evm" && chain != "solana" {
		return errors.New("signed capabilities currently support DERO, EVM, and Solana only")
	}
	if flagValueOr(fs, "escrow", "") != "" {
		return errors.New("signed capabilities do not authorize HTLC escrow")
	}
	if flagValueOr(fs, "approval-request", "") != "" {
		return errors.New("-approval-request cannot be combined with -approval-file")
	}
	var atomic uint64
	if chain == "dero" {
		asset, a, err := parseAmountFlag(amount)
		if err != nil {
			return err
		}
		if asset != "dero" || a == 0 {
			return errors.New("signed capability must match a positive DERO -amount")
		}
		atomic = a
	} else if chain == "evm" && amount != "" {
		return errors.New("signed capability on EVM mailbox path does not accept -amount")
	} else if chain == "solana" && amount != "" {
		return errors.New("signed capability on Solana deliver path does not accept -amount")
	}
	resolved, _, err := resolveTo(context.Background(), recipient, flagValueOr(fs, "maildb", ""), flagValueOr(fs, "daemon", ""))
	if err != nil {
		return err
	}
	var canonicalRecipient string
	if chain == "dero" {
		canonicalRecipient, err = dero.ValidateAddress(resolved)
	} else if chain == "evm" {
		canonicalRecipient, err = evm.ValidateAddress(resolved)
	} else {
		canonicalRecipient, err = solanaBackend.ValidateAddress(resolved)
	}
	if err != nil {
		return err
	}
	envelope, err := decodeCapabilityFile(approvalPath)
	if err != nil {
		return err
	}
	if err := verifyCapabilityApproval(envelope, approverHex, time.Now()); err != nil {
		return err
	}
	if envelope.Chain != chain {
		return fmt.Errorf("signed capability is for chain %s, not %s", envelope.Chain, chain)
	}
	if envelope.Recipient != canonicalRecipient || envelope.AmountAtomic != atomic {
		return errors.New("signed capability does not match this recipient and amount")
	}
	// Operator heads-up: inside the final stretch of the TTL the approval is
	// still valid, but a stalled handoff will hit expiry instead of the
	// chain — say so before burning the nonce. Validation above already
	// refused expired approvals, so remaining here is strictly positive.
	if remaining := time.Until(time.Unix(envelope.ExpiresAt, 0)); remaining < approvalTTLHeadroomWarn {
		fmt.Fprintf(os.Stderr, "warning: approved %s capability expires in %s — broadcast now or re-request with a fresh nonce\n", strings.ToUpper(chain), remaining.Round(time.Second))
	}
	identityPath := flagValueOr(fs, "identity", "")
	if identityPath == "" {
		return fmt.Errorf("approved %s send requires the original -identity", strings.ToUpper(chain))
	}
	seed, err := readHexFile(identityPath, 32)
	if err != nil {
		return fmt.Errorf("sending identity: %w", err)
	}
	requester, err := secure.SigPubOf(seed)
	if err != nil {
		return fmt.Errorf("sending identity: %w", err)
	}
	storedRequester, _ := hex.DecodeString(envelope.Requester)
	wipeBytes(seed)
	if !bytes.Equal(requester, storedRequester) {
		return errors.New("signed capability was requested by a different sending identity")
	}
	fabricRoute, err := fabricSendConfig(fs, canonicalRecipient)
	if err != nil {
		return err
	}
	carrier, err := e2Carrier(fs)
	if err != nil {
		return err
	}
	var canonicalSender string
	if chain == "dero" {
		backend, ok := carrier.Chain.(*dero.Backend)
		if !ok {
			return errors.New("signed DERO capability resolved to a non-DERO carrier")
		}
		currentSender, err := backend.Address(context.Background())
		if err != nil {
			return fmt.Errorf("read current DERO sender address: %w", err)
		}
		canonicalSender, err = dero.ValidateAddress(currentSender)
		if err != nil {
			return err
		}
	} else if chain == "evm" {
		evmBackend, ok := carrier.Chain.(*evm.Backend)
		if !ok {
			return errors.New("signed EVM capability resolved to a non-EVM carrier")
		}
		if evmBackend.Mailbox() == "" {
			return errors.New("signed EVM capability requires a configured MyceliumMailbox (-mailbox)")
		}
		currentSender, err := evmBackend.Address(context.Background())
		if err != nil {
			return fmt.Errorf("read current EVM sender address: %w", err)
		}
		canonicalSender, err = evm.ValidateAddress(currentSender)
		if err != nil {
			return err
		}
	} else {
		solBackend, ok := carrier.Chain.(*solanaBackend.Backend)
		if !ok {
			return errors.New("signed Solana capability resolved to a non-Solana carrier")
		}
		currentSender, err := solBackend.Address(context.Background())
		if err != nil {
			return fmt.Errorf("read current Solana sender address: %w", err)
		}
		canonicalSender, err = solanaBackend.ValidateAddress(currentSender)
		if err != nil {
			return err
		}
		recPK, err := solanaBackend.PublicKeyFromAddress(canonicalRecipient)
		if err != nil {
			return fmt.Errorf("verify Solana recipient pubkey: %w", err)
		}
		if _, err := solBackend.InboxPDA(recPK); err != nil {
			return fmt.Errorf("verify Solana recipient inbox PDA: %w", err)
		}
	}
	if envelope.SenderAddress != canonicalSender {
		return fmt.Errorf("signed capability is bound to sender %s, current sender is %s", envelope.SenderAddress, canonicalSender)
	}
	pointer, _ := hex.DecodeString(envelope.Pointer)
	if err := consumeCapabilityNonce(flagValueOr(fs, "state-dir", ""), envelope); err != nil {
		return err
	}
	result, err := carrier.PostPointer(context.Background(), envelope.Recipient, pointer, envelope.AmountAtomic)
	if err != nil {
		return fmt.Errorf("approved %s broadcast result is ambiguous; this nonce is burned and cannot be retried: %w", strings.ToUpper(chain), err)
	}
	sid, _ := hex.DecodeString(envelope.SessionID)
	var sessionID [8]byte
	copy(sessionID[:], sid)
	if chain == "dero" {
		fmt.Printf("approved DERO capability posted txid %s amount %sdero pointer %s\n", result.TxID, formatAmount("dero", envelope.AmountAtomic), envelope.Pointer)
	} else if chain == "evm" {
		fmt.Printf("approved EVM capability posted txid %s pointer %s\n", result.TxID, envelope.Pointer)
	} else {
		fmt.Printf("approved Solana capability posted txid %s pointer %s\n", result.TxID, envelope.Pointer)
	}
	fabricPublishPointer(context.Background(), fabricRoute, sessionID, pointer)
	return nil
}

// msgApprove signs prepared capabilities only after an explicit -confirm.
// A single request is signed to -out; several requests (comma-separated
// -request list, or a -request-dir scan of a shared queue) are signed to one
// <name>.signed.json each under -out-dir, reporting per-file outcomes instead
// of aborting at the first bad file. Without -confirm a batch only reviews.
// With -state-dir (or the configured default), requests whose nonce is
// already burned in the approval-spent replay ledger are skipped, so a
// re-scanned queue only signs what can still be posted.
// With -watch the same batch becomes an always-on approver station: it
// rescans -request-dir every -every interval and signs new requests as they
// arrive, until SIGINT/SIGTERM.
//
//	spore msg approve -request REQUEST.json -identity KEY -out SIGNED.json -confirm
//	spore msg approve -request A.json,B.json -identity KEY -out-dir DIR -confirm [-json] [-state-dir D]
//	spore msg approve -request-dir QUEUE -identity KEY -out-dir DIR -confirm [-json] [-state-dir D]
//	spore msg approve -request-dir QUEUE -identity KEY -out-dir DIR -watch [-every 30s] [-state-dir D]
func msgApprove(args []string) {
	fs := flag.NewFlagSet("msg approve", flag.ExitOnError)
	request := fs.String("request", "", "approval request JSON file(s) to review and sign (comma-separated list for batch)")
	requestDir := fs.String("request-dir", "", "directory to scan for pending approval request JSON files (batch mode)")
	identity := fs.String("identity", "", "approver identity private key file (hex, 32 bytes)")
	out := fs.String("out", "", "write signed approval JSON envelope to this file (single request)")
	outDir := fs.String("out-dir", "", "write one signed approval per request into this directory (batch mode)")
	confirm := fs.Bool("confirm", false, "confirm the printed actions; required to sign")
	asJSON := fs.Bool("json", false, "batch mode: emit per-request results in machine-readable JSON format")
	stateDir := fs.String("state-dir", "", "batch mode: encrypted endpoint session state directory whose approval-spent ledger marks already-consumed nonces")
	watch := fs.Bool("watch", false, "batch mode: keep rescanning -request-dir and signing new requests until interrupted (always-on approver station)")
	every := fs.Duration("every", 30*time.Second, "watch mode: queue rescan interval (e.g. 10s, 1m)")
	_ = fs.Parse(args)
	if *identity == "" {
		check(errors.New("approve requires -identity"))
	}
	if *watch {
		check(validateApproveWatchFlags(*requestDir, *request, *confirm, *asJSON, *every))
	}
	batch := *watch || *requestDir != "" || *outDir != "" || strings.Contains(*request, ",")
	if !batch {
		if *request == "" {
			check(errors.New("approve requires -request, or -request-dir for batch mode"))
		}
		if *out == "" {
			check(errors.New("approve requires -out, or -out-dir for batch mode"))
		}
		if *asJSON {
			check(errors.New("approve: -json is only supported in batch mode"))
		}
		check(approveCapabilityFile(*request, *identity, *out, *confirm))
		fmt.Printf("approval written to %s\n", *out)
		return
	}
	if *requestDir != "" && *request != "" {
		check(errors.New("approve: -request-dir cannot be combined with -request"))
	}
	if *out != "" {
		check(errors.New("approve: -out signs exactly one request; use -out-dir for batch mode"))
	}
	if *outDir == "" {
		check(errors.New("batch approve requires -out-dir"))
	}
	if *stateDir == "" {
		_ = loadConfigForFlags(fs)
		if f := fs.Lookup("state-dir"); f != nil && f.Value.String() != "" {
			*stateDir = f.Value.String()
		}
	}
	if *watch {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		runApprovalWatchLoop(ctx, *requestDir, *identity, *outDir, *stateDir, *every)
		return
	}
	var requestPaths []string
	if *requestDir != "" {
		paths, err := scanApprovalRequestDir(*requestDir)
		check(err)
		requestPaths = paths
	} else {
		for _, part := range strings.Split(*request, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				check(errors.New("approve: -request contains an empty path"))
			}
			requestPaths = append(requestPaths, part)
		}
	}
	if len(requestPaths) == 0 {
		if *asJSON {
			renderApprovalBatchReport(nil, true)
			return
		}
		fmt.Printf("no capability approval requests found in %s\n", *requestDir)
		return
	}
	results := runApprovalBatch(requestPaths, *identity, *outDir, *stateDir, *confirm)
	renderApprovalBatchReport(results, *asJSON)
	failed := 0
	for _, r := range results {
		if r.Status != approvalBatchSigned && r.Status != approvalBatchSkipped {
			failed++
		}
	}
	if failed > 0 {
		check(fmt.Errorf("batch approve: %d of %d request(s) failed", failed, len(results)))
	}
}

// Batch approve outcomes.
const (
	approvalBatchSigned  = "signed"
	approvalBatchSkipped = "skipped"
	approvalBatchFailed  = "failed"
)

// approvalBatchResult is the per-request outcome of one batch approve run.
// The envelope fields (chain/action/recipient/amount) make the JSON report
// self-contained, so pipeline tooling can build the follow-up send command
// for each signed envelope without re-reading the request files.
type approvalBatchResult struct {
	Request      string `json:"request"`
	Output       string `json:"output,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	Chain        string `json:"chain,omitempty"`
	Action       string `json:"action,omitempty"`
	Recipient    string `json:"recipient,omitempty"`
	AmountAtomic uint64 `json:"amount_atomic,omitempty"`
	Status       string `json:"status"` // signed, skipped, failed
	Reason       string `json:"reason,omitempty"`
}

// scanApprovalRequestDir returns the capability-envelope JSON files in dir.
// Non-JSON files and JSON that is not a capability envelope are ignored so a
// shared queue directory may hold unrelated files.
func scanApprovalRequestDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("batch approve: scan %s: %w", dir, err)
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if e, err := decodeCapabilityFile(path); err != nil || e.Protocol != capabilityProtocol {
			continue
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// approvalLockTTL is how long a signing lock may sit untouched before
// another station treats its holder as crashed and breaks it. Signing is a
// sub-second local operation, so a lock this old means the holder is gone.
// Same-host locks whose holder process is provably dead break immediately
// (see holderIsDeadLocal); remote or unknown owners keep the TTL as their
// only break trigger. The exclusive-create output remains the backstop for
// the same-out-dir case.
const approvalLockTTL = 60 * time.Second

// os.Remove on a lock can transiently fail: on Windows, deletion is refused
// with a sharing violation while any other handle to the file is open (Go's
// os.Open omits FILE_SHARE_DELETE), and a racing station's busy-path lookup
// reads the lock for a few microseconds. release() therefore retries the
// removal within this budget; a lock that still survives it self-heals via
// the TTL stale-break.
const (
	approvalLockRemoveBudget = 250 * time.Millisecond
	approvalLockRemoveDelay  = 2 * time.Millisecond
)

// approvalLockHostname tags lock ownership. Liveness breaking must never
// apply to another host's lock: a PID from a remote station means nothing
// locally, and breaking it would un-guard double-signing across hosts.
var approvalLockHostname = func() string {
	h, err := os.Hostname()
	if err != nil {
		return "" // unknown host: every lock stays TTL-only
	}
	return h
}()

// lockApprovalRequest takes an exclusive signing lock for one queue request
// so two approver stations on the same queue never double-sign the same
// nonce: without it, two stations with different -out-dir would each produce
// a valid approval for one nonce (the same-out-dir race is already covered by
// the exclusive-create output). The lock is a sibling <request>.lock file
// whose content is the owner as "<hostname> <pid>"; creation is
// O_CREATE|O_EXCL, and a lock is broken by ATOMIC RENAME (never
// delete-and-recreate, which would let two stale-breakers race into mutual
// ownership) when it is older than approvalLockTTL — or, same host only,
// when its PID is provably dead (holderIsDeadLocal).
//
// Returns exactly one of: a release func (idempotent; removes the file only
// if it still names us), a busyReason (the lock is held by a live station),
// or err (lock infrastructure failed — the caller must treat the request as
// FAILED rather than sign unlocked).
func lockApprovalRequest(requestPath string, now time.Time) (release func(), busyReason string, err error) {
	lockPath := requestPath + ".lock"
	myOwner := approvalLockHostname + " " + strconv.Itoa(os.Getpid())
	create := func() (*os.File, error) {
		return os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	}
	f, err := create()
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, "", fmt.Errorf("create %s: %w", lockPath, err)
		}
		// Held by someone: decide live vs crashed — by age past the TTL, or
		// immediately when the lock provably names a dead holder on this host.
		info, statErr := os.Stat(lockPath)
		if statErr != nil {
			// Vanished between create and stat: a holder released or a breaker
			// is mid-retry — report busy this cycle; the next scan re-checks.
			return nil, "signing lock contended; retried on the next scan", nil
		}
		holderHost, heldPID := parseLockOwner(lockPath)
		if now.Sub(info.ModTime()) <= approvalLockTTL && !holderIsDeadLocal(holderHost, heldPID) {
			return nil, fmt.Sprintf("signing lock held by another approver (pid %s)", heldPID), nil
		}
		// Stale holder or dead local holder: break by atomic rename, then
		// retry the create. If the rename fails the holder released (or
		// another breaker won) underneath us — either way re-enter the normal
		// flow instead of forcing it.
		broken := fmt.Sprintf("%s.broken-%d-%d", lockPath, os.Getpid(), now.UnixNano())
		if rerr := os.Rename(lockPath, broken); rerr == nil {
			os.Remove(broken)
		}
		f, err = create()
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return nil, "signing lock contended; retried on the next scan", nil
			}
			return nil, "", fmt.Errorf("create %s: %w", lockPath, err)
		}
	}
	if _, werr := f.WriteString(myOwner + "\n"); werr != nil {
		f.Close()
		os.Remove(lockPath)
		return nil, "", fmt.Errorf("write %s: %w", lockPath, werr)
	}
	f.Close()
	var once bool
	return func() {
		if once {
			return
		}
		once = true
		// Remove only while the file still names us: a stale-breaker must
		// never delete a lock a live station took after ours was broken.
		// Re-check ownership on every attempt — the lock can be stale-broken
		// and re-taken while we are retrying.
		deadline := time.Now().Add(approvalLockRemoveBudget)
		for {
			b, rerr := os.ReadFile(lockPath)
			if rerr != nil || strings.TrimSpace(string(b)) != myOwner {
				return
			}
			if os.Remove(lockPath) == nil {
				return
			}
			if time.Now().After(deadline) {
				return
			}
			time.Sleep(approvalLockRemoveDelay)
		}
	}, "", nil
}

// parseLockOwner reads a lock's owner tag as "<hostname> <pid>". A pid-only
// body is a legacy or mid-write lock and yields an empty host, which disables
// liveness breaking and keeps the TTL as the only break trigger.
func parseLockOwner(lockPath string) (host, pid string) {
	b, rerr := os.ReadFile(lockPath)
	if rerr != nil {
		return "", "unknown"
	}
	fields := strings.Fields(string(b))
	switch {
	case len(fields) >= 2:
		return fields[0], fields[1]
	case len(fields) == 1:
		return "", fields[0]
	default:
		return "", "unknown"
	}
}

// holderIsDeadLocal reports whether a lock provably names a dead holder on
// this host: same hostname, parseable positive PID, and no live process
// behind it. A recycled PID or any remote or unknown owner stays on the
// conservative TTL path.
func holderIsDeadLocal(host, pid string) bool {
	if host == "" || host != approvalLockHostname {
		return false
	}
	n, err := strconv.Atoi(pid)
	if err != nil || n <= 0 {
		return false
	}
	return !pidAlive(n)
}

// runApprovalBatch validates and signs each request into outDir as
// <request base>.signed.json, aggregating per-file outcomes instead of
// aborting on the first bad file. Already-signed, invalid, expired, spent
// (nonce burned in stateDir's approval-spent ledger), and other-approver
// requests are skipped with a reason; without -confirm nothing is signed
// (dry run). Outputs are exclusive-create, so a rerun never overwrites an
// existing approval.
func runApprovalBatch(requestPaths []string, identityPath, outDir, stateDir string, confirm bool) []approvalBatchResult {
	results := make([]approvalBatchResult, 0, len(requestPaths))
	if len(requestPaths) == 0 {
		return results
	}
	approverPublic, seed, err := sendIdentityPublic(identityPath)
	if err != nil {
		for _, requestPath := range requestPaths {
			results = append(results, approvalBatchResult{Request: requestPath, Status: approvalBatchFailed, Reason: fmt.Sprintf("approval identity: %v", err)})
		}
		return results
	}
	wipeBytes(seed)
	outDirReady := false
	for _, requestPath := range requestPaths {
		result := approvalBatchResult{Request: requestPath, Status: approvalBatchFailed}
		e, err := decodeCapabilityFile(requestPath)
		if err != nil {
			result.Reason = err.Error()
			results = append(results, result)
			continue
		}
		result.Nonce = e.Nonce
		result.Chain = e.Chain
		result.Action = e.Action
		result.Recipient = e.Recipient
		result.AmountAtomic = e.AmountAtomic
		if e.Signature != "" {
			result.Status = approvalBatchSkipped
			result.Reason = "already signed"
			results = append(results, result)
			continue
		}
		if err := validateCapabilityEnvelope(e, time.Now(), false); err != nil {
			result.Status = approvalBatchSkipped
			result.Reason = err.Error()
			results = append(results, result)
			continue
		}
		if stateDir != "" {
			spentPath := filepath.Join(stateDir, "approval-spent", e.Nonce+".spent")
			if info, err := os.Stat(spentPath); err == nil && !info.IsDir() {
				result.Status = approvalBatchSkipped
				result.Reason = "nonce already consumed; replay refused"
				results = append(results, result)
				continue
			}
		}
		approver, _ := hex.DecodeString(e.Approver)
		if !bytes.Equal(approver, approverPublic) {
			result.Status = approvalBatchSkipped
			result.Reason = "named for a different approver key"
			results = append(results, result)
			continue
		}
		if !confirm {
			printCapabilityActionReview(e)
			result.Status = approvalBatchSkipped
			result.Reason = "confirmation required; rerun with -confirm to sign"
			results = append(results, result)
			continue
		}
		if !outDirReady {
			if err := os.MkdirAll(outDir, 0o700); err != nil {
				result.Reason = fmt.Sprintf("create output dir: %v", err)
				results = append(results, result)
				continue
			}
			outDirReady = true
		}
		// Signing lock: two stations racing the same queue (different -out-dir,
		// or a watch station racing a manual one-shot) must never both sign one
		// nonce. Infrastructure failure is loud (failed), a live holder is a
		// quiet skip the next scan re-classifies as "already signed".
		release, busy, lockErr := lockApprovalRequest(requestPath, time.Now())
		if lockErr != nil {
			result.Reason = fmt.Sprintf("signing lock: %v", lockErr)
			results = append(results, result)
			continue
		}
		if busy != "" {
			result.Status = approvalBatchSkipped
			result.Reason = busy
			results = append(results, result)
			continue
		}
		outputPath := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(requestPath), ".json")+".signed.json")
		result.Output = outputPath
		err = approveCapabilityEnvelope(e, identityPath, outputPath, true)
		release()
		if err != nil {
			result.Reason = err.Error()
			results = append(results, result)
			continue
		}
		result.Status = approvalBatchSigned
		results = append(results, result)
	}
	return results
}

// renderApprovalBatchReport prints per-request outcomes as text or JSON.
func renderApprovalBatchReport(results []approvalBatchResult, asJSON bool) {
	signed, skipped, failed := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case approvalBatchSigned:
			signed++
		case approvalBatchSkipped:
			skipped++
		default:
			failed++
		}
	}
	if asJSON {
		report := struct {
			Signed  int                   `json:"signed"`
			Skipped int                   `json:"skipped"`
			Failed  int                   `json:"failed"`
			Results []approvalBatchResult `json:"results"`
		}{Signed: signed, Skipped: skipped, Failed: failed, Results: results}
		if report.Results == nil {
			report.Results = []approvalBatchResult{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}
	fmt.Printf("batch approve: %d signed, %d skipped, %d failed\n", signed, skipped, failed)
	for _, r := range results {
		switch r.Status {
		case approvalBatchSigned:
			fmt.Printf("  SIGNED  %s -> %s\n", r.Request, r.Output)
			fmt.Printf("          next: rerun the original %s send to %s with -approval-file %s\n", strings.ToUpper(r.Chain), r.Recipient, r.Output)
		case approvalBatchSkipped:
			fmt.Printf("  SKIPPED %s (%s)\n", r.Request, r.Reason)
		default:
			fmt.Printf("  FAILED  %s (%s)\n", r.Request, r.Reason)
		}
	}
}

// validateApproveWatchFlags enforces the -watch flag combinations: watch is a
// rescannable queue (not a fixed -request list), it signs automatically so it
// needs the same explicit -confirm as a one-shot batch, JSON reports are a
// one-shot feature (the signed files are the watch artifacts), and the rescan
// interval must be positive.
func validateApproveWatchFlags(requestDir, request string, confirm, asJSON bool, every time.Duration) error {
	if requestDir == "" {
		return errors.New("approve: -watch requires -request-dir (a queue directory to rescan)")
	}
	if request != "" {
		return errors.New("approve: -watch rescans a queue directory; use -request-dir instead of -request")
	}
	if !confirm {
		return errors.New("approve: -watch signs automatically; pass -confirm to authorize it")
	}
	if asJSON {
		return errors.New("approve: -json is not supported in -watch mode; the signed files in -out-dir are the artifacts")
	}
	if every <= 0 {
		return errors.New("approve: -every must be a positive duration (e.g. 10s, 1m)")
	}
	return nil
}

// runApprovalWatchLoop is the always-on approver station: rescan the queue
// every interval, sign new pending requests, and stay quiet about files whose
// status has not changed since the previous cycle. A transient scan failure
// (queue dir briefly missing, permissions) is logged and retried on the next
// tick — it must not kill the station. Returns when ctx is cancelled
// (SIGINT/SIGTERM via signal.NotifyContext at the call site).
func runApprovalWatchLoop(ctx context.Context, requestDir, identityPath, outDir, stateDir string, every time.Duration) {
	seen := make(map[string]string)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	log.Printf("approve: watching %s every %s; signing to %s as requests arrive (Ctrl-C to stop)", requestDir, every, outDir)
	for cycle := 1; ; cycle++ {
		signed, failed, err := runApprovalWatchCycle(requestDir, identityPath, outDir, stateDir, true, seen)
		if err != nil {
			log.Printf("approve: watch: %v (retrying next tick)", err)
		} else if signed > 0 || failed > 0 {
			log.Printf("approve: cycle %d: %d signed, %d failed", cycle, signed, failed)
		}
		select {
		case <-ctx.Done():
			log.Printf("approve: watch stopped after %d cycle(s)", cycle)
			return
		case <-ticker.C:
		}
	}
}

// runApprovalWatchCycle performs one watch iteration: rescan requestDir, sign
// what is pending, and print only requests whose (status, reason) changed
// since the previous cycle, so steady-state rescans stay quiet. Requests
// whose signed output already exists in outDir are left out entirely — the
// batch core would only fail on the exclusive-create output again, and the
// cycle that signed it already reported. seen keys are request paths and
// values are "status|reason" summaries; entries for files that left the queue
// are dropped so a re-arriving file is reported again. signed/failed count
// only requests handled this cycle. The shared batch core (runApprovalBatch)
// does the actual signing unchanged.
func runApprovalWatchCycle(requestDir, identityPath, outDir, stateDir string, confirm bool, seen map[string]string) (signed, failed int, err error) {
	paths, err := scanApprovalRequestDir(requestDir)
	if err != nil {
		return 0, 0, err
	}
	current := make(map[string]bool, len(paths))
	for _, path := range paths {
		current[path] = true
	}
	for path := range seen {
		if !current[path] {
			delete(seen, path)
		}
	}
	var pending []string
	for _, path := range paths {
		outPath := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(path), ".json")+".signed.json")
		if info, serr := os.Stat(outPath); serr == nil && !info.IsDir() {
			continue // signed output exists from an earlier cycle or run: handled
		}
		pending = append(pending, path)
	}
	for _, r := range runApprovalBatch(pending, identityPath, outDir, stateDir, confirm) {
		summary := r.Status + "|" + r.Reason
		if prev, ok := seen[r.Request]; ok && prev == summary {
			continue // unchanged since a previous cycle: already reported
		}
		seen[r.Request] = summary
		switch r.Status {
		case approvalBatchSigned:
			seen[r.Request] = approvalBatchSkipped + "|already signed" // the next rescan sees it signed; stay quiet
			signed++
			fmt.Printf("  SIGNED  %s -> %s\n", r.Request, r.Output)
			fmt.Printf("          next: rerun the original %s send to %s with -approval-file %s\n", strings.ToUpper(r.Chain), r.Recipient, r.Output)
		case approvalBatchSkipped:
			fmt.Printf("  SKIPPED %s (%s)\n", r.Request, r.Reason)
		default:
			failed++
			fmt.Printf("  FAILED  %s (%s)\n", r.Request, r.Reason)
		}
	}
	return signed, failed, nil
}

// msgInspectApproval parses and displays a capability envelope file,
// checks signatures and expiry, and verifies replay status against state-dir.
//
//	spore msg inspect-approval -file ENVELOPE.json [-state-dir DIR] [-json] [-require-approver PUBKEY]
func msgInspectApproval(args []string) {
	fs := flag.NewFlagSet("msg inspect-approval", flag.ExitOnError)
	file := fs.String("file", "", "capability envelope JSON file to inspect (request or signed approval)")
	stateDir := fs.String("state-dir", "", "encrypted endpoint session state directory to check spent nonce replay ledger")
	asJSON := fs.Bool("json", false, "output inspection result in machine-readable JSON format")
	requireApprover := fs.String("require-approver", "", "verify approver public key matches this 64-hex Ed25519 key (fails non-zero on mismatch)")
	_ = fs.Parse(args)
	if *file == "" {
		check(errors.New("inspect-approval requires -file"))
	}
	if *stateDir == "" {
		_ = loadConfigForFlags(fs)
		if f := fs.Lookup("state-dir"); f != nil && f.Value.String() != "" {
			*stateDir = f.Value.String()
		}
	}
	e, err := decodeCapabilityFile(*file)
	check(err)

	now := time.Now()
	signed := e.Signature != ""

	// Check validity
	valErr := validateCapabilityEnvelope(e, now, signed)

	var pointerHash [32]byte
	if ptr, err := hex.DecodeString(e.Pointer); err == nil {
		pointerHash = sha256.Sum256(ptr)
	}

	transcript, _ := capabilityTranscript(e)

	// Check requester signature
	reqPK, err := hex.DecodeString(e.Requester)
	reqSig, err2 := hex.DecodeString(e.RequesterSignature)
	requesterValid := err == nil && err2 == nil && len(reqPK) == ed25519.PublicKeySize && len(reqSig) == ed25519.SignatureSize && transcript != nil && ed25519.Verify(ed25519.PublicKey(reqPK), transcript, reqSig)

	// Check approver signature
	approverValid := false
	if signed {
		appPK, err := hex.DecodeString(e.Approver)
		appSig, err2 := hex.DecodeString(e.Signature)
		approverValid = err == nil && err2 == nil && len(appPK) == ed25519.PublicKeySize && len(appSig) == ed25519.SignatureSize && transcript != nil && ed25519.Verify(ed25519.PublicKey(appPK), transcript, appSig)
	}

	// Check replay ledger
	nonceStatus := "UNKNOWN"
	if *stateDir != "" {
		spentPath := filepath.Join(*stateDir, "approval-spent", e.Nonce+".spent")
		if info, err := os.Stat(spentPath); err == nil && !info.IsDir() {
			nonceStatus = "SPENT"
		} else if errors.Is(err, os.ErrNotExist) {
			nonceStatus = "UNSPENT"
		}
	}

	isExpired := now.Unix() >= e.ExpiresAt

	// Check -require-approver
	if *requireApprover != "" {
		expected, err := hex.DecodeString(*requireApprover)
		if err != nil || len(expected) != ed25519.PublicKeySize {
			check(errors.New("-require-approver must be a 64-hex Ed25519 public key"))
		}
		if !strings.EqualFold(e.Approver, *requireApprover) {
			check(fmt.Errorf("envelope approver %s does not match required approver %s", e.Approver, *requireApprover))
		}
	}

	if *asJSON {
		res := struct {
			Envelope        CapabilityEnvelope `json:"envelope"`
			PointerSHA256   string             `json:"pointer_sha256"`
			Expired         bool               `json:"expired"`
			RequesterValid  bool               `json:"requester_valid"`
			ApproverValid   bool               `json:"approver_valid"`
			Signed          bool               `json:"signed"`
			NonceStatus     string             `json:"nonce_status"`
			Valid           bool               `json:"valid"`
			ValidationError string             `json:"validation_error,omitempty"`
		}{
			Envelope:       e,
			PointerSHA256:  hex.EncodeToString(pointerHash[:]),
			Expired:        isExpired,
			RequesterValid: requesterValid,
			ApproverValid:  approverValid,
			Signed:         signed,
			NonceStatus:    nonceStatus,
			Valid:          valErr == nil,
		}
		if valErr != nil {
			res.ValidationError = valErr.Error()
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(res))
		return
	}

	fmt.Println("Capability Envelope:")
	fmt.Printf("  Protocol:       %s (v%d)\n", e.Protocol, e.Version)
	fmt.Printf("  Action:         %s\n", e.Action)
	fmt.Printf("  Chain:          %s\n", e.Chain)
	fmt.Printf("  Sender:         %s\n", e.SenderAddress)
	fmt.Printf("  Recipient:      %s\n", e.Recipient)
	if e.Action == capabilityDeroTransfer {
		fmt.Printf("  Amount:         %s DERO (%d atomic)\n", formatAmount("dero", e.AmountAtomic), e.AmountAtomic)
	} else {
		fmt.Printf("  Amount:         0 (non-payable deliver)\n")
	}
	fmt.Printf("  Session ID:     %s\n", e.SessionID)
	fmt.Printf("  Pointer SHA256: %x\n", pointerHash)
	fmt.Printf("  Nonce:          %s\n", e.Nonce)
	fmt.Printf("  Created:        %s\n", time.Unix(e.CreatedAt, 0).UTC().Format(time.RFC3339))
	fmt.Printf("  Expires:        %s\n", time.Unix(e.ExpiresAt, 0).UTC().Format(time.RFC3339))
	if isExpired {
		fmt.Println("  Expiry Status:  EXPIRED")
	} else {
		rem := time.Duration(e.ExpiresAt-now.Unix()) * time.Second
		fmt.Printf("  Expiry Status:  VALID (expires in %s)\n", rem.Round(time.Second))
	}

	fmt.Println("\nSignatures & Authorities:")
	fmt.Printf("  Requester:      %s\n", e.Requester)
	if requesterValid {
		fmt.Printf("  Requester Sig:  VALID (%s...)\n", shortSig(e.RequesterSignature))
	} else {
		fmt.Printf("  Requester Sig:  INVALID (%s)\n", e.RequesterSignature)
	}

	fmt.Printf("  Approver:       %s\n", e.Approver)
	if signed {
		if approverValid {
			fmt.Printf("  Approver Sig:   VALID (%s...)\n", shortSig(e.Signature))
		} else {
			fmt.Printf("  Approver Sig:   INVALID (%s)\n", e.Signature)
		}
	} else {
		fmt.Println("  Approver Sig:   UNSIGNED (pending approval)")
	}

	fmt.Println("\nReplay & Ledger Status:")
	if *stateDir != "" {
		spentPath := filepath.Join(*stateDir, "approval-spent", e.Nonce+".spent")
		if nonceStatus == "SPENT" {
			fmt.Printf("  Nonce Status:   SPENT (consumed in %s)\n", spentPath)
		} else if nonceStatus == "UNSPENT" {
			fmt.Println("  Nonce Status:   UNSPENT (not recorded in local approval-spent ledger)")
		} else {
			fmt.Printf("  Nonce Status:   UNKNOWN (error inspecting ledger)\n")
		}
	} else {
		fmt.Println("  Nonce Status:   UNKNOWN (no -state-dir supplied to check approval-spent ledger)")
	}

	if valErr != nil {
		fmt.Printf("\nOverall Validity: INVALID (%v)\n", valErr)
	} else if signed {
		fmt.Println("\nOverall Validity: VALID (signed capability approval ready to post)")
	} else {
		fmt.Println("\nOverall Validity: VALID (unsigned approval request ready for review)")
	}
}

func shortSig(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// approvalEnvelopeStatus is the classified state of one capability envelope
// against a queue/state snapshot.
type approvalEnvelopeStatus struct {
	Status     string // PENDING, SIGNED, SPENT, EXPIRED, INVALID (list-approvals vocabulary)
	SkipReason string // batch-core-shaped reason the request is not signable now ("" for PENDING)
	Signed     bool
	Valid      bool
	Expired    bool
	Spent      bool
}

// classifyApprovalEnvelope is the single source of truth for envelope queue
// status: msgListApprovals' table and msgApprovalMetrics' skip-reason
// breakdown must never disagree. Status precedence mirrors list-approvals
// exactly; skipReason names what the batch core would report for a request
// it cannot sign ("already signed", "nonce already consumed; replay refused",
// "approval envelope: expired", or the validation error for INVALID).
func classifyApprovalEnvelope(e CapabilityEnvelope, now time.Time, stateDir string) approvalEnvelopeStatus {
	signed := e.Signature != ""
	valErr := validateCapabilityEnvelope(e, now, signed)
	isExpired := now.Unix() >= e.ExpiresAt

	isSpent := false
	if stateDir != "" {
		spentPath := filepath.Join(stateDir, "approval-spent", e.Nonce+".spent")
		if info, err := os.Stat(spentPath); err == nil && !info.IsDir() {
			isSpent = true
		}
	}

	cls := approvalEnvelopeStatus{Signed: signed, Valid: valErr == nil, Expired: isExpired, Spent: isSpent}
	cls.Status = "PENDING"
	if valErr != nil && !isExpired {
		cls.Status = "INVALID"
	} else if isSpent {
		cls.Status = "SPENT"
	} else if isExpired {
		cls.Status = "EXPIRED"
	} else if signed {
		cls.Status = "SIGNED"
	}
	switch cls.Status {
	case "SIGNED":
		cls.SkipReason = "already signed"
	case "SPENT":
		cls.SkipReason = "nonce already consumed; replay refused"
	case "EXPIRED":
		cls.SkipReason = "approval envelope: expired"
	case "INVALID":
		cls.SkipReason = valErr.Error()
	}
	return cls
}

type approvalSummary struct {
	Path         string `json:"path"`
	Chain        string `json:"chain"`
	Action       string `json:"action"`
	Sender       string `json:"sender"`
	Recipient    string `json:"recipient"`
	Amount       string `json:"amount"`
	AmountAtomic uint64 `json:"amount_atomic,omitempty"`
	Approver     string `json:"approver,omitempty"`
	Nonce        string `json:"nonce"`
	Status       string `json:"status"` // PENDING, SIGNED, EXPIRED, SPENT, INVALID
	Expired      bool   `json:"expired"`
	Signed       bool   `json:"signed"`
	Spent        bool   `json:"spent"`
	Valid        bool   `json:"valid"`
	ExpiresAt    int64  `json:"expires_at_unix"`
	ExpiresIn    string `json:"expires_in"`
}

// validateListApprovalsFlags enforces the list-approvals flag combinations:
// -json and -print-commands are mutually exclusive (-json already carries
// every field the commands are built from).
func validateListApprovalsFlags(printCommands, asJSON bool) error {
	if printCommands && asJSON {
		return errors.New("list-approvals: -json and -print-commands are mutually exclusive (-json already carries every field the commands are built from)")
	}
	return nil
}

// msgListApprovals scans a directory or state-dir and lists capability envelopes.
// With -print-commands it instead prints one ready-to-run requester send
// command per SIGNED envelope (the requester supplies -identity and
// -pinned-sig to fill in the last two blanks), mirroring `spore sub send`:
// printing beats silently half-sending, because posting a capability burns
// its nonce.
//
//	spore msg list-approvals [-dir DIR] [-state-dir DIR] [-status pending|signed|spent|all] [-json]
//	spore msg list-approvals [-dir DIR] [-state-dir DIR] -print-commands [-identity KEYFILE] [-pinned-sig HEX]
func msgListApprovals(args []string) {
	fs := flag.NewFlagSet("msg list-approvals", flag.ExitOnError)
	scanDir := fs.String("dir", "", "directory to scan for .json capability envelopes (defaults to -state-dir or current dir)")
	stateDir := fs.String("state-dir", "", "encrypted endpoint session state directory to check spent nonce replay ledger")
	statusFilter := fs.String("status", "all", "filter by status: all|pending|signed|spent|expired")
	asJSON := fs.Bool("json", false, "output summary list in machine-readable JSON format")
	printCommands := fs.Bool("print-commands", false, "print one ready-to-run requester send command per SIGNED envelope instead of the summary table")
	commandIdentity := fs.String("identity", "", "print-commands: requester identity private key file to embed in the commands (placeholder if empty)")
	commandPinned := fs.String("pinned-sig", "", "print-commands: recipient pinned signing key hex to embed in the commands (placeholder if empty)")
	_ = fs.Parse(args)
	check(validateListApprovalsFlags(*printCommands, *asJSON))

	if *stateDir == "" {
		_ = loadConfigForFlags(fs)
		if f := fs.Lookup("state-dir"); f != nil && f.Value.String() != "" {
			*stateDir = f.Value.String()
		}
	}
	targetDir := *scanDir
	if targetDir == "" {
		if *stateDir != "" {
			targetDir = *stateDir
		} else {
			targetDir = "."
		}
	}

	entries, err := os.ReadDir(targetDir)
	check(err)

	now := time.Now()
	var summaries []approvalSummary

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(targetDir, entry.Name())
		e, err := decodeCapabilityFile(path)
		if err != nil {
			continue // skip non-capability JSON files
		}
		if e.Protocol != capabilityProtocol {
			continue
		}

		cls := classifyApprovalEnvelope(e, now, *stateDir)

		filter := strings.ToLower(strings.TrimSpace(*statusFilter))
		if filter != "" && filter != "all" {
			if !strings.EqualFold(cls.Status, filter) {
				continue
			}
		}

		amountStr := "0"
		if e.Action == capabilityDeroTransfer {
			amountStr = formatAmount("dero", e.AmountAtomic) + " dero"
		}

		expiresInStr := "expired"
		if !cls.Expired {
			rem := time.Duration(e.ExpiresAt-now.Unix()) * time.Second
			expiresInStr = rem.Round(time.Second).String()
		}

		summaries = append(summaries, approvalSummary{
			Path:         path,
			Chain:        e.Chain,
			Action:       e.Action,
			Sender:       e.SenderAddress,
			Recipient:    e.Recipient,
			Amount:       amountStr,
			AmountAtomic: e.AmountAtomic,
			Approver:     e.Approver,
			Nonce:        e.Nonce,
			Status:       cls.Status,
			Expired:      cls.Expired,
			Signed:       cls.Signed,
			Spent:        cls.Spent,
			Valid:        cls.Valid,
			ExpiresAt:    e.ExpiresAt,
			ExpiresIn:    expiresInStr,
		})
	}

	if *asJSON {
		if summaries == nil {
			summaries = []approvalSummary{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(summaries))
		return
	}

	if *printCommands {
		printApprovalSendCommands(summaries, *commandIdentity, *commandPinned)
		return
	}

	if len(summaries) == 0 {
		fmt.Printf("no capability envelopes found in %s (filter: %s)\n", targetDir, *statusFilter)
		return
	}

	fmt.Printf("%-10s %-8s %-12s %-16s %-16s %-12s %s\n", "STATUS", "CHAIN", "AMOUNT", "SENDER", "RECIPIENT", "EXPIRES IN", "FILE")
	for _, s := range summaries {
		fmt.Printf("%-10s %-8s %-12s %-16s %-16s %-12s %s\n",
			s.Status,
			s.Chain,
			s.Amount,
			shortTx(s.Sender),
			shortTx(s.Recipient),
			s.ExpiresIn,
			filepath.Base(s.Path),
		)
	}
}

// approvalSendCommand builds the ready-to-run requester command that posts
// one SIGNED capability: rerun the exact send with -approval-file (the
// -require-approval key must match the envelope's approver). identity and
// pinned may be empty, in which case placeholder shells are printed for the
// two requester-only secrets (never guess them: -pinned-sig is the requester's
// out-of-band trust anchor, same policy as send-e2).
func approvalSendCommand(s approvalSummary, identity, pinned string) string {
	if identity == "" {
		identity = "IDENTITY"
	}
	if pinned == "" {
		pinned = "PINNED_SIG"
	}
	return fmt.Sprintf("spore msg send-e2 -chain %s -to %s -amount %s -require-approval %s -approval-file %s -identity %s -pinned-sig %s",
		s.Chain, s.Recipient, s.Amount, s.Approver, s.Path, identity, pinned)
}

// printApprovalSendCommands prints one ready-to-run requester command per
// SIGNED envelope, with change-quieting comments for everything else (spent
// is success — the send already happened and burned the nonce). The requester
// still supplies -identity and -pinned-sig: printing beats silently
// half-sending, because posting a capability burns its nonce (same
// philosophy as `spore sub send`).
func printApprovalSendCommands(summaries []approvalSummary, identity, pinned string) {
	printed := 0
	for _, s := range summaries {
		if s.Status == "SIGNED" {
			fmt.Println(approvalSendCommand(s, identity, pinned))
			printed++
		}
	}
	other := make(map[string]int)
	for _, s := range summaries {
		if s.Status != "SIGNED" {
			other[s.Status]++
		}
	}
	statuses := make([]string, 0, len(other))
	for status := range other {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	for _, status := range statuses {
		fmt.Printf("# %d %s (not ready to send)\n", other[status], status)
	}
	if printed == 0 {
		fmt.Println("# no SIGNED approvals ready to send")
	}
}
