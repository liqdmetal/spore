package continuity

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const watchStateVersion uint8 = 1
const watchStateType = "spore-continuity-watch-state"

var ErrInvalidWatchState = errors.New("continuity: invalid watch state")

// WatchState is a signed local checkpoint for metadata-only continuity
// observation. It records the exact vault epoch and observer identity, never
// payload material or recipient private data.
type WatchState struct {
	Type               string `json:"type"`
	Version            uint8  `json:"version"`
	VaultID            string `json:"vault_id"`
	PolicyID           string `json:"policy_id"`
	OwnerSigPub        string `json:"owner_sig_pub"`
	CheckInSeq         uint64 `json:"checkin_seq"`
	LastCheckIn        int64  `json:"last_check_in"`
	Deadline           int64  `json:"deadline"`
	ObserverPub        string `json:"observer_pub"`
	NotificationQueued bool   `json:"notification_queued"`
	QueuedAt           int64  `json:"queued_at,omitempty"`
	Signature          string `json:"signature"`
}

// NewWatchState creates an unsigned checkpoint bound to the current vault
// epoch, then signs it with the independent observer key.
func NewWatchState(v *Vault, observerPriv []byte) (*WatchState, error) {
	if v == nil || len(observerPriv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidWatchState
	}
	if err := v.Verify(); err != nil {
		return nil, err
	}
	priv := append(ed25519.PrivateKey(nil), observerPriv...)
	defer zeroBytes(priv)
	pub := priv.Public().(ed25519.PublicKey)
	last := v.Checkins[len(v.Checkins)-1]
	state := &WatchState{
		Type: watchStateType, Version: watchStateVersion,
		VaultID: v.VaultID, PolicyID: v.PolicyID, OwnerSigPub: v.OwnerSigPub,
		CheckInSeq: last.Seq, LastCheckIn: last.At, Deadline: last.Deadline,
		ObserverPub: hex.EncodeToString(pub),
	}
	state.Signature = hex.EncodeToString(ed25519.Sign(priv, watchTranscript(state)))
	if err := state.Verify(); err != nil {
		return nil, err
	}
	return state, nil
}

// MarkNotificationQueued records that the exact signed release notice for the
// current epoch has been durably handed to the notification outbox. Calling it
// again is idempotent.
func (s *WatchState) MarkNotificationQueued(observerPriv []byte, notice *ReleaseNotice, now int64) error {
	if err := s.Verify(); err != nil {
		return err
	}
	if notice == nil || now <= 0 || len(observerPriv) != ed25519.PrivateKeySize {
		return ErrInvalidWatchState
	}
	if err := notice.Verify(); err != nil {
		return ErrInvalidWatchState
	}
	if notice.VaultID != s.VaultID || notice.PolicyID != s.PolicyID ||
		notice.OwnerSigPub != s.OwnerSigPub || notice.CheckInSeq != s.CheckInSeq ||
		notice.LastCheckIn != s.LastCheckIn || notice.Deadline != s.Deadline ||
		notice.ObservedAt < s.Deadline {
		return ErrInvalidWatchState
	}
	priv := append(ed25519.PrivateKey(nil), observerPriv...)
	defer zeroBytes(priv)
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != s.ObserverPub || notice.ObserverPub != s.ObserverPub {
		return ErrInvalidWatchState
	}
	if s.NotificationQueued {
		return nil
	}
	s.NotificationQueued = true
	s.QueuedAt = now
	s.Signature = hex.EncodeToString(ed25519.Sign(priv, watchTranscript(s)))
	return s.Verify()
}

// Verify authenticates the checkpoint's self-contained structure.
func (s *WatchState) Verify() error {
	if s == nil || s.Type != watchStateType || s.Version != watchStateVersion ||
		s.VaultID == "" || s.PolicyID == "" || s.OwnerSigPub == "" ||
		s.LastCheckIn <= 0 || s.Deadline <= s.LastCheckIn || s.ObserverPub == "" {
		return ErrInvalidWatchState
	}
	if _, err := decodeFixed(s.VaultID, 32); err != nil {
		return ErrInvalidWatchState
	}
	if _, err := decodeFixed(s.PolicyID, 32); err != nil {
		return ErrInvalidWatchState
	}
	if _, err := decodeFixed(s.OwnerSigPub, ed25519.PublicKeySize); err != nil {
		return ErrInvalidWatchState
	}
	pub, err := decodeFixed(s.ObserverPub, ed25519.PublicKeySize)
	if err != nil {
		return ErrInvalidWatchState
	}
	if s.NotificationQueued && s.QueuedAt <= 0 {
		return ErrInvalidWatchState
	}
	if !s.NotificationQueued && s.QueuedAt != 0 {
		return ErrInvalidWatchState
	}
	sig, err := hex.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), watchTranscript(s), sig) {
		return ErrInvalidWatchState
	}
	return nil
}

// VerifyForVault binds the checkpoint to the vault's currently signed epoch.
// A later check-in invalidates the old checkpoint and requires a fresh state.
func (s *WatchState) VerifyForVault(v *Vault) error {
	if v == nil {
		return ErrInvalidWatchState
	}
	if err := v.Verify(); err != nil {
		return err
	}
	if err := s.Verify(); err != nil {
		return err
	}
	last := v.Checkins[len(v.Checkins)-1]
	if s.VaultID != v.VaultID || s.PolicyID != v.PolicyID || s.OwnerSigPub != v.OwnerSigPub ||
		s.CheckInSeq != last.Seq || s.LastCheckIn != last.At || s.Deadline != last.Deadline {
		return fmt.Errorf("%w: checkpoint does not match current vault epoch", ErrInvalidWatchState)
	}
	return nil
}

// ParseWatchState decodes and verifies a strict local checkpoint.
func ParseWatchState(raw []byte) (*WatchState, error) {
	var s WatchState
	if err := decodeStrict(raw, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidWatchState, err)
	}
	if err := s.Verify(); err != nil {
		return nil, err
	}
	return &s, nil
}

func watchTranscript(s *WatchState) []byte {
	b, _ := json.Marshal(struct {
		Domain             string `json:"domain"`
		Type               string `json:"type"`
		Version            uint8  `json:"version"`
		VaultID            string `json:"vault_id"`
		PolicyID           string `json:"policy_id"`
		OwnerSigPub        string `json:"owner_sig_pub"`
		CheckInSeq         uint64 `json:"checkin_seq"`
		LastCheckIn        int64  `json:"last_check_in"`
		Deadline           int64  `json:"deadline"`
		ObserverPub        string `json:"observer_pub"`
		NotificationQueued bool   `json:"notification_queued"`
		QueuedAt           int64  `json:"queued_at"`
	}{domain + "/watch-state/v1", s.Type, s.Version, s.VaultID, s.PolicyID, s.OwnerSigPub, s.CheckInSeq, s.LastCheckIn, s.Deadline, s.ObserverPub, s.NotificationQueued, s.QueuedAt})
	return b
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func WatchEventID(s *WatchState) string {
	if s == nil {
		return ""
	}
	b, _ := json.Marshal(struct {
		Domain      string `json:"domain"`
		VaultID     string `json:"vault_id"`
		PolicyID    string `json:"policy_id"`
		OwnerSigPub string `json:"owner_sig_pub"`
		CheckInSeq  uint64 `json:"checkin_seq"`
		LastCheckIn int64  `json:"last_check_in"`
		Deadline    int64  `json:"deadline"`
		ObserverPub string `json:"observer_pub"`
	}{domain + "/watch-event/v1", s.VaultID, s.PolicyID, s.OwnerSigPub, s.CheckInSeq, s.LastCheckIn, s.Deadline, s.ObserverPub})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func randomWatchNonce() ([]byte, error) {
	b := make([]byte, 16)
	_, err := crand.Read(b)
	return b, err
}
