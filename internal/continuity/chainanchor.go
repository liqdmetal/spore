package continuity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/liqdmetal/spore/internal/anchor"
)

var ErrInvalidChainAnchor = errors.New("continuity: invalid chain anchor")

const maxChainAnchorSeq uint64 = (1 << 40) - 1

// ChainAnchor is the public commitment that may be posted to a chain. VaultID
// and PolicyID are already SHA-256 identifiers, so the DERO wire record carries
// them directly as its two 32-byte hash fields. It contains no ciphertext,
// plaintext, recipient key, or wallet authority.
type ChainAnchor struct {
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
	ca := &ChainAnchor{
		VaultID: v.VaultID, PolicyID: policy.PolicyID,
		CheckInSeq: last.Seq, Deadline: last.Deadline,
	}
	if err := ca.Verify(); err != nil {
		return nil, err
	}
	return ca, nil
}

// Verify checks the self-contained public commitment, without a vault or
// policy. VerifyAgainst performs the stronger exact-state check.
func (a *ChainAnchor) Verify() error {
	if a == nil || a.Deadline <= 0 || a.CheckInSeq > maxChainAnchorSeq {
		return ErrInvalidChainAnchor
	}
	if _, err := decodeFixed(a.VaultID, 32); err != nil {
		return ErrInvalidChainAnchor
	}
	if _, err := decodeFixed(a.PolicyID, 32); err != nil {
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

// ParseDEROChainAnchor converts the opaque wire record back into its public
// commitment. Only KindContinuity is accepted; message anchors cannot be
// repurposed as continuity anchors.
func ParseDEROChainAnchor(w *anchor.Anchor) (*ChainAnchor, error) {
	if w == nil || w.Version != anchor.Version || w.Kind != anchor.KindContinuity || w.Flags != 0 || w.BurnDeadline > math.MaxInt64 {
		return nil, ErrInvalidChainAnchor
	}
	a := &ChainAnchor{
		VaultID:    hex.EncodeToString(w.EphemeralPub[:]),
		PolicyID:   hex.EncodeToString(w.CID[:]),
		CheckInSeq: w.ContinuitySeq,
		Deadline:   int64(w.BurnDeadline),
	}
	if err := a.Verify(); err != nil {
		return nil, err
	}
	return a, nil
}

func bytes32(raw []byte) (out [32]byte) {
	copy(out[:], raw)
	return out
}
