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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/evm"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
	solanaBackend "github.com/liqdmetal/spore/internal/solana"
)

const (
	ApprovalTTL             = 15 * time.Minute
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
	pointer, _ := hex.DecodeString(e.Pointer)
	pointerHash := sha256.Sum256(pointer)
	if e.Action == capabilityEVMDeliver {
		fmt.Fprintf(os.Stderr, "EVM mailbox deliver approval: 0 value from %s to %s; pointer sha256 %x; requested by %s; expires %s\n", e.SenderAddress, e.Recipient, pointerHash, e.Requester, time.Unix(e.ExpiresAt, 0).UTC().Format(time.RFC3339))
	} else if e.Action == capabilitySolanaDeliver {
		fmt.Fprintf(os.Stderr, "Solana program deliver approval: 0 value from %s to %s; pointer sha256 %x; requested by %s; expires %s\n", e.SenderAddress, e.Recipient, pointerHash, e.Requester, time.Unix(e.ExpiresAt, 0).UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintf(os.Stderr, "DERO transfer approval: %s DERO (%d atomic units) from %s to %s; pointer sha256 %x; requested by %s; expires %s\n", formatAmount("dero", e.AmountAtomic), e.AmountAtomic, e.SenderAddress, e.Recipient, pointerHash, e.Requester, time.Unix(e.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
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

// msgApprove signs a prepared capability only after an explicit -confirm.
//
// \tspore msg approve -request REQUEST.json -identity KEY -out SIGNED.json -confirm
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

// msgApprove signs a prepared capability only after an explicit -confirm.
//
//	spore msg approve -request REQUEST.json -identity KEY -out SIGNED.json -confirm
func msgApprove(args []string) {
	fs := flag.NewFlagSet("msg approve", flag.ExitOnError)
	request := fs.String("request", "", "approval request JSON file to review and sign")
	identity := fs.String("identity", "", "approver identity private key file (hex, 32 bytes)")
	out := fs.String("out", "", "write signed approval JSON envelope to this file")
	confirm := fs.Bool("confirm", false, "confirm the printed action; required to sign")
	_ = fs.Parse(args)
	if *request == "" || *identity == "" || *out == "" {
		check(errors.New("approve requires -request, -identity, and -out"))
	}
	check(approveCapabilityFile(*request, *identity, *out, *confirm))
	fmt.Printf("approval written to %s\n", *out)
}

// msgInspectApproval parses and displays a capability envelope file,
// checks signatures and expiry, and verifies replay status against state-dir.
//
//	spore msg inspect-approval -file ENVELOPE.json [-state-dir DIR]
func msgInspectApproval(args []string) {
	fs := flag.NewFlagSet("msg inspect-approval", flag.ExitOnError)
	file := fs.String("file", "", "capability envelope JSON file to inspect (request or signed approval)")
	stateDir := fs.String("state-dir", "", "encrypted endpoint session state directory to check spent nonce replay ledger")
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
	if now.Unix() >= e.ExpiresAt {
		fmt.Println("  Expiry Status:  EXPIRED")
	} else {
		rem := time.Duration(e.ExpiresAt-now.Unix()) * time.Second
		fmt.Printf("  Expiry Status:  VALID (expires in %s)\n", rem.Round(time.Second))
	}

	fmt.Println("\nSignatures & Authorities:")
	fmt.Printf("  Requester:      %s\n", e.Requester)
	reqPK, err := hex.DecodeString(e.Requester)
	reqSig, err2 := hex.DecodeString(e.RequesterSignature)
	if err == nil && err2 == nil && len(reqPK) == ed25519.PublicKeySize && len(reqSig) == ed25519.SignatureSize && transcript != nil && ed25519.Verify(ed25519.PublicKey(reqPK), transcript, reqSig) {
		fmt.Printf("  Requester Sig:  VALID (%s...)\n", shortSig(e.RequesterSignature))
	} else {
		fmt.Printf("  Requester Sig:  INVALID (%s)\n", e.RequesterSignature)
	}

	fmt.Printf("  Approver:       %s\n", e.Approver)
	if signed {
		appPK, err := hex.DecodeString(e.Approver)
		appSig, err2 := hex.DecodeString(e.Signature)
		if err == nil && err2 == nil && len(appPK) == ed25519.PublicKeySize && len(appSig) == ed25519.SignatureSize && transcript != nil && ed25519.Verify(ed25519.PublicKey(appPK), transcript, appSig) {
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
		if info, err := os.Stat(spentPath); err == nil && !info.IsDir() {
			fmt.Printf("  Nonce Status:   SPENT (consumed in %s)\n", spentPath)
		} else if errors.Is(err, os.ErrNotExist) {
			fmt.Println("  Nonce Status:   UNSPENT (not recorded in local approval-spent ledger)")
		} else {
			fmt.Printf("  Nonce Status:   UNKNOWN (error inspecting ledger: %v)\n", err)
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
