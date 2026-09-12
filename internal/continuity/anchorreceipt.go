package continuity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

const anchorReceiptVersion uint8 = 1
const anchorReceiptType = "spore-continuity-dero-anchor-receipt"

var ErrInvalidAnchorReceipt = errors.New("continuity: invalid anchor receipt")

// AnchorReceipt records the exact local wallet submission and the opaque
// continuity anchor it was intended to carry. It is not a confirmation of
// chain finality; AnchorReceiptAgainstWallet performs payload readback.
type AnchorReceipt struct {
	Type        string `json:"type"`
	Version     uint8  `json:"version"`
	TXID        string `json:"txid"`
	Destination string `json:"destination"`
	VaultID     string `json:"vault_id"`
	PolicyID    string `json:"policy_id"`
	CheckInSeq  uint64 `json:"checkin_seq"`
	Deadline    int64  `json:"deadline"`
	RingSize    uint64 `json:"ringsize"`
	PostedAt    int64  `json:"posted_at"`
	WireDigest  string `json:"wire_digest"`
}

// DigestAnchorWire returns the domain-separated digest of the exact packed
// DERO payload bytes sent to the wallet.
func DigestAnchorWire(packed []byte) string {
	h := sha256.New()
	h.Write([]byte(domain + "/anchor-wire/v1"))
	h.Write(packed)
	return hex.EncodeToString(h.Sum(nil))
}

// NewAnchorReceipt constructs a receipt after the wallet returns a txid.
func NewAnchorReceipt(a *ChainAnchor, txid, destination string, ringSize uint64, postedAt int64, wireDigest string) (*AnchorReceipt, error) {
	if a == nil || a.Verify() != nil {
		return nil, ErrInvalidAnchorReceipt
	}
	r := &AnchorReceipt{
		Type: anchorReceiptType, Version: anchorReceiptVersion,
		TXID: txid, Destination: destination,
		VaultID: a.VaultID, PolicyID: a.PolicyID,
		CheckInSeq: a.CheckInSeq, Deadline: a.Deadline,
		RingSize: ringSize, PostedAt: postedAt, WireDigest: wireDigest,
	}
	if err := r.Verify(); err != nil {
		return nil, err
	}
	return r, nil
}

// Verify validates the receipt's self-contained structure. It does not claim
// that the tx is mined, final, or present in wallet history.
func (r *AnchorReceipt) Verify() error {
	if r == nil || r.Type != anchorReceiptType || r.Version != anchorReceiptVersion ||
		r.TXID == "" || len(r.TXID) > 256 || strings.TrimSpace(r.TXID) != r.TXID ||
		r.Destination == "" || strings.TrimSpace(r.Destination) != r.Destination ||
		r.Deadline <= 0 || r.RingSize != 8 && r.RingSize != 16 || r.PostedAt <= 0 {
		return ErrInvalidAnchorReceipt
	}
	vault, err := decodeFixed(r.VaultID, 32)
	if err != nil || isZero(vault) {
		return ErrInvalidAnchorReceipt
	}
	policy, err := decodeFixed(r.PolicyID, 32)
	if err != nil || isZero(policy) {
		return ErrInvalidAnchorReceipt
	}
	if _, err := decodeFixed(r.WireDigest, 32); err != nil {
		return ErrInvalidAnchorReceipt
	}
	return nil
}

// VerifyAgainst checks that a receipt describes this exact local anchor and
// the exact posting parameters supplied by the caller.
func (r *AnchorReceipt) VerifyAgainst(a *ChainAnchor, txid, destination string, ringSize uint64, wireDigest string) error {
	if err := r.Verify(); err != nil {
		return err
	}
	if a == nil || a.Verify() != nil || r.TXID != txid || r.Destination != destination ||
		r.VaultID != a.VaultID || r.PolicyID != a.PolicyID || r.CheckInSeq != a.CheckInSeq ||
		r.Deadline != a.Deadline || r.RingSize != ringSize || r.WireDigest != wireDigest {
		return fmt.Errorf("%w: receipt does not match anchor submission", ErrInvalidAnchorReceipt)
	}
	return nil
}

// VerifyAnchorPayload reconstructs the continuity anchor from wallet history
// and requires an exact canonical-payload digest match. This proves wallet
// readback of the intended payload; it does not prove block finality.
func VerifyAnchorPayload(ctx context.Context, client *dero.Client, receipt *AnchorReceipt, expected *ChainAnchor) error {
	if client == nil || receipt == nil || expected == nil {
		return ErrInvalidAnchorReceipt
	}
	if err := receipt.VerifyAgainst(expected, receipt.TXID, receipt.Destination, receipt.RingSize, receipt.WireDigest); err != nil {
		return err
	}
	wire, err := expected.ToDEROAnchor()
	if err != nil {
		return err
	}
	packed, err := dero.PackArguments(wire.ToArguments())
	if err != nil {
		return err
	}
	if DigestAnchorWire(packed) != receipt.WireDigest {
		return fmt.Errorf("%w: local wire digest mismatch", ErrInvalidAnchorReceipt)
	}
	payloads, err := client.GetTransferPayloads(ctx, receipt.TXID)
	if err != nil {
		return err
	}
	for _, payload := range payloads {
		args, err := dero.PayloadToArgs(payload)
		if err != nil {
			continue
		}
		observed, err := anchor.FromArguments(args)
		if err != nil || observed.Kind != anchor.KindContinuity {
			continue
		}
		observedContinuity, err := ParseDEROChainAnchor(observed)
		if err != nil || *observedContinuity != *expected {
			continue
		}
		canonical, err := dero.PackArguments(args)
		if err == nil && DigestAnchorWire(canonical) == receipt.WireDigest {
			return nil
		}
	}
	return fmt.Errorf("%w: txid history contains no exact continuity payload", ErrInvalidAnchorReceipt)
}

// ParseAnchorReceipt decodes and verifies the strict local JSON form.
func ParseAnchorReceipt(raw []byte) (*AnchorReceipt, error) {
	var r AnchorReceipt
	if err := decodeStrict(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAnchorReceipt, err)
	}
	if err := r.Verify(); err != nil {
		return nil, err
	}
	return &r, nil
}
