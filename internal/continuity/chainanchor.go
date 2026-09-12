package continuity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/liqdmetal/spore/internal/anchor"
)

var ErrInvalidChainAnchor = errors.New("continuity: invalid chain anchor")

const (
	chainAnchorVersion uint8  = 1
	chainAnchorType           = "spore-continuity-dero-anchor"
	maxChainAnchorSeq  uint64 = (1 << 40) - 1
)

// ChainAnchor is an opaque commitment that may be posted to a chain. VaultID
// and PolicyID are already SHA-256 identifiers, so the DERO wire record carries
// them directly as its two 32-byte hash fields. DERO's recipient-encrypted
// message field keeps those identifiers out of public transaction metadata. It
// contains no ciphertext, plaintext, recipient key, or wallet authority.
type ChainAnchor struct {
	Type       string `json:"type"`
	Version    uint8  `json:"version"`
	VaultID    string `json:"vault_id"`
	PolicyID   string `json:"policy_id"`
	CheckInSeq uint64 `json:"checkin_seq"`
	Deadline   int64  `json:"deadline"`
}

// NewChainAnchor binds an exact, currently valid quorum policy to its vault.
func NewChainAnchor(v *Vault, policy *QuorumPolicy) (*ChainAnchor, error) {
	if err := VerifyPolicyForVault(policy, v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidChainAnchor, err)
	}
	last := v.Checkins[len(v.Checkins)-1]
	a := &ChainAnchor{
		Type: chainAnchorType, Version: chainAnchorVersion,
		VaultID: v.VaultID, PolicyID: policy.PolicyID,
		CheckInSeq: last.Seq, Deadline: last.Deadline,
	}
	if err := a.Verify(); err != nil {
		return nil, err
	}
	return a, nil
}

// Verify checks the self-contained opaque commitment, without a vault or
// policy. VerifyAgainst performs the stronger exact-state check.
func (a *ChainAnchor) Verify() error {
	if a == nil || a.Type != chainAnchorType || a.Version != chainAnchorVersion || a.Deadline <= 0 || a.CheckInSeq > maxChainAnchorSeq {
		return ErrInvalidChainAnchor
	}
	vaultID, err := decodeFixed(a.VaultID, 32)
	if err != nil || isZero(vaultID) {
		return ErrInvalidChainAnchor
	}
	policyID, err := decodeFixed(a.PolicyID, 32)
	if err != nil || isZero(policyID) {
		return ErrInvalidChainAnchor
	}
	return nil
}

// VerifyAgainst rejects an anchor for a later or different check-in epoch.
func (a *ChainAnchor) VerifyAgainst(v *Vault, policy *QuorumPolicy) error {
	if err := a.Verify(); err != nil {
		return err
	}
	if err := VerifyPolicyForVault(policy, v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidChainAnchor, err)
	}
	want, err := NewChainAnchor(v, policy)
	if err != nil {
		return err
	}
	if *a != *want {
		return ErrInvalidChainAnchor
	}
	return nil
}

// ParseChainAnchor decodes and validates the versioned local JSON form. Strict
// decoding prevents an operator from accidentally accepting a second meaning
// for a field added by a future producer.
func ParseChainAnchor(raw []byte) (*ChainAnchor, error) {
	var a ChainAnchor
	if err := decodeStrict(raw, &a); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidChainAnchor, err)
	}
	if err := a.Verify(); err != nil {
		return nil, err
	}
	return &a, nil
}

// ToDEROAnchor maps the commitment to the existing four-argument DERO anchor
// wire format. The two identifiers remain opaque 32-byte hashes on-chain.
func (a *ChainAnchor) ToDEROAnchor() (*anchor.Anchor, error) {
	if err := a.Verify(); err != nil {
		return nil, err
	}
	vaultID, _ := hex.DecodeString(a.VaultID)
	policyID, _ := hex.DecodeString(a.PolicyID)
	return &anchor.Anchor{
		Version: anchor.Version, Kind: anchor.KindContinuity,
		EphemeralPub: bytes32(vaultID), CID: bytes32(policyID),
		BurnDeadline: uint64(a.Deadline), ContinuitySeq: a.CheckInSeq,
	}, nil
}

// ParseDEROChainAnchor converts the opaque wire record back into its local
// commitment. Only KindContinuity is accepted; message anchors cannot be
// repurposed as continuity anchors.
func ParseDEROChainAnchor(w *anchor.Anchor) (*ChainAnchor, error) {
	if w == nil || w.Version != anchor.Version || w.Kind != anchor.KindContinuity || w.Flags != 0 || w.BurnDeadline > math.MaxInt64 {
		return nil, ErrInvalidChainAnchor
	}
	a := &ChainAnchor{
		Type: chainAnchorType, Version: chainAnchorVersion,
		VaultID:    hex.EncodeToString(w.EphemeralPub[:]),
		PolicyID:   hex.EncodeToString(w.CID[:]),
		CheckInSeq: w.ContinuitySeq, Deadline: int64(w.BurnDeadline),
	}
	if err := a.Verify(); err != nil {
		return nil, err
	}
	return a, nil
}

func isZero(raw []byte) bool {
	return len(raw) > 0 && bytes.Equal(raw, make([]byte, len(raw)))
}

func bytes32(raw []byte) (out [32]byte) {
	copy(out[:], raw)
	return out
}
