package continuity

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

const noticeVersion uint8 = 1

var ErrInvalidNotice = errors.New("continuity: invalid release notice")

// ReleaseNotice is a signed, release-ready signal. It contains no payload,
// recipient key, or ciphertext. An observer can produce it from the public
// vault after verifying that its signed deadline has passed.
type ReleaseNotice struct {
	Version     uint8  `json:"version"`
	VaultID     string `json:"vault_id"`
	PolicyID    string `json:"policy_id"`
	OwnerSigPub string `json:"owner_sig_pub"`
	CheckInSeq  uint64 `json:"checkin_seq"`
	LastCheckIn int64  `json:"last_check_in"`
	Deadline    int64  `json:"deadline"`
	ObservedAt  int64  `json:"observed_at"`
	ObserverPub string `json:"observer_pub"`
	Signature   string `json:"signature"`
}

// NewObserverKey generates the independent Ed25519 key used to sign notices.
// The private key is 64 bytes and must be stored like any other signing key.
func NewObserverKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// Observe verifies the vault and creates a signed release-ready notice. It
// does not require, inspect, or receive any recipient private key or payload.
func Observe(v *Vault, observerPriv []byte, now int64) (*ReleaseNotice, error) {
	if v == nil || len(observerPriv) != ed25519.PrivateKeySize || now <= 0 {
		return nil, ErrInvalidNotice
	}
	status, err := v.Status(now)
	if err != nil {
		return nil, err
	}
	if !status.Releasable {
		return nil, ErrNotDue
	}
	key := append(ed25519.PrivateKey(nil), observerPriv...)
	defer sporecrypto.Zero(key)
	pub := key.Public().(ed25519.PublicKey)
	last := v.Checkins[len(v.Checkins)-1]
	n := &ReleaseNotice{
		Version: noticeVersion, VaultID: v.VaultID, PolicyID: v.PolicyID,
		OwnerSigPub: v.OwnerSigPub, CheckInSeq: last.Seq, LastCheckIn: last.At,
		Deadline: last.Deadline, ObservedAt: now, ObserverPub: hex.EncodeToString(pub),
	}
	n.Signature = hex.EncodeToString(ed25519.Sign(key, noticeTranscript(n)))
	if err := n.Verify(); err != nil {
		return nil, err
	}
	return n, nil
}

// Verify authenticates a notice without needing the observer private key.
func (n *ReleaseNotice) Verify() error {
	if n == nil || n.Version != noticeVersion || n.VaultID == "" || n.PolicyID == "" || n.OwnerSigPub == "" || n.LastCheckIn <= 0 || n.Deadline <= n.LastCheckIn || n.ObservedAt < n.Deadline {
		return ErrInvalidNotice
	}
	if _, err := decodeFixed(n.VaultID, 32); err != nil {
		return ErrInvalidNotice
	}
	if _, err := decodeFixed(n.PolicyID, 32); err != nil {
		return ErrInvalidNotice
	}
	if _, err := decodeFixed(n.OwnerSigPub, ed25519.PublicKeySize); err != nil {
		return ErrInvalidNotice
	}
	pub, err := decodeFixed(n.ObserverPub, ed25519.PublicKeySize)
	if err != nil {
		return ErrInvalidNotice
	}
	sig, err := hex.DecodeString(n.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), noticeTranscript(n), sig) {
		return ErrInvalidNotice
	}
	return nil
}

// VerifyNoticeForVault verifies both the notice signature and that the notice
// refers to this exact, currently verifiable vault state.
func VerifyNoticeForVault(v *Vault, n *ReleaseNotice) error {
	if v == nil || n == nil {
		return ErrInvalidNotice
	}
	if err := v.Verify(); err != nil {
		return err
	}
	if err := n.Verify(); err != nil {
		return err
	}
	last := v.Checkins[len(v.Checkins)-1]
	if n.VaultID != v.VaultID || n.PolicyID != v.PolicyID || n.OwnerSigPub != v.OwnerSigPub || n.CheckInSeq != last.Seq || n.LastCheckIn != last.At || n.Deadline != last.Deadline {
		return fmt.Errorf("%w: notice does not match vault", ErrInvalidNotice)
	}
	return nil
}

// ParseNotice decodes and verifies a notice from its JSON representation.
func ParseNotice(raw []byte) (*ReleaseNotice, error) {
	var n ReleaseNotice
	if err := json.Unmarshal(raw, &n); err != nil {
		return nil, err
	}
	if err := n.Verify(); err != nil {
		return nil, err
	}
	return &n, nil
}

func noticeTranscript(n *ReleaseNotice) []byte {
	b, _ := json.Marshal(struct {
		Domain      string `json:"domain"`
		Version     uint8  `json:"version"`
		VaultID     string `json:"vault_id"`
		PolicyID    string `json:"policy_id"`
		OwnerSigPub string `json:"owner_sig_pub"`
		CheckInSeq  uint64 `json:"checkin_seq"`
		LastCheckIn int64  `json:"last_check_in"`
		Deadline    int64  `json:"deadline"`
		ObservedAt  int64  `json:"observed_at"`
		ObserverPub string `json:"observer_pub"`
	}{domain + "/release-notice/v1", n.Version, n.VaultID, n.PolicyID, n.OwnerSigPub, n.CheckInSeq, n.LastCheckIn, n.Deadline, n.ObservedAt, n.ObserverPub})
	return b
}
