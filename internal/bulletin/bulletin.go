// Package bulletin implements signed, hash-addressed Spore public notices.
package bulletin

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	Version          = 1
	Domain           = "spore/public-bulletin/dero/v1"
	Kind             = 0x05
	NoticeKind       = 1978
	MaxNotice        = 44 << 10 // allow for relay metadata within a 64 KiB event cap
	MaxNoticeEvents  = 64
	MaxBodyEvents    = 8
	MaxRelayResults  = 256
	MaxRelays        = 16
	MaxIndexBytes    = 1 << 20
	MaxIndexedBodies = 4096
	MaxSequence      = (1 << 40) - 1 // Keep the wire/API limit identical to the DVM contract.
)

var (
	ErrInvalid   = errors.New("bulletin: invalid notice")
	ErrSignature = errors.New("bulletin: publisher signature invalid")
	ErrSequence  = errors.New("bulletin: sequence mismatch")
)

type Notice struct {
	Version  int    `json:"version"`
	Channel  string `json:"channel"`
	Sequence uint64 `json:"sequence"`
	CID      string `json:"cid"`
	Deadline int64  `json:"deadline"`
	Sig      string `json:"sig"`
}

type Signature struct {
	Publisher string `json:"publisher"`
	Channel   string `json:"channel"`
	Sequence  uint64 `json:"sequence"`
	CID       string `json:"cid"`
	Deadline  int64  `json:"deadline"`
	Sig       string `json:"sig"`
}

// BodyCID identifies exact off-chain bytes. The bulletin never interprets or
// republishes that content; public content-addressed storage remains public.
func BodyCID(body []byte) [32]byte { return sha256.Sum256(body) }

func newNotice(channel string, sequence uint64, cid [32]byte, deadline int64) (*Notice, error) {
	if !validChannel(channel) || sequence == 0 || sequence > MaxSequence || deadline <= 0 {
		return nil, ErrInvalid
	}
	return &Notice{Version: Version, Channel: channel, Sequence: sequence,
		CID: hex.EncodeToString(cid[:]), Deadline: deadline}, nil
}

func Sign(privateKey ed25519.PrivateKey, channel string, sequence uint64, body []byte, deadline time.Time) (*Notice, error) {
	if len(privateKey) != ed25519.PrivateKeySize || len(body) == 0 || len(body) > MaxNotice {
		return nil, ErrInvalid
	}
	deadline = time.Unix(deadline.Unix(), 0)
	if !deadline.After(time.Now()) {
		return nil, ErrInvalid
	}
	cid := BodyCID(body)
	notice, err := newNotice(channel, sequence, cid, deadline.Unix())
	if err != nil {
		return nil, err
	}
	notice.Sig = hex.EncodeToString(ed25519.Sign(privateKey, transcript(channel, sequence, notice.CID, notice.Deadline)))
	return notice, nil
}

func Verify(publicKey ed25519.PublicKey, notice *Notice, body []byte, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize || notice == nil || notice.Version != Version ||
		!validChannel(notice.Channel) || notice.Sequence == 0 || notice.Sequence > MaxSequence || notice.Deadline <= 0 ||
		len(body) == 0 || len(body) > MaxNotice || now.Unix() >= notice.Deadline {
		return ErrInvalid
	}
	cid, err := decodeCID(notice.CID)
	if err != nil || BodyCID(body) != cid {
		return ErrInvalid
	}
	sig, err := hex.DecodeString(notice.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrSignature
	}
	if !ed25519.Verify(publicKey, transcript(notice.Channel, notice.Sequence, notice.CID, notice.Deadline), sig) {
		return ErrSignature
	}
	return nil
}

func VerifySequence(publicKey ed25519.PublicKey, notice *Notice, body []byte, channel string, next uint64, now time.Time) error {
	if !validChannel(channel) || next == 0 || next > MaxSequence || notice == nil || notice.Channel != channel || notice.Sequence != next {
		return ErrSequence
	}
	return Verify(publicKey, notice, body, now)
}

func transcript(channel string, sequence uint64, cid string, deadline int64) []byte {
	return []byte(Domain + ":" + channel + ":" + strconv.FormatUint(sequence, 10) + ":" + cid + ":" + strconv.FormatInt(deadline, 10))
}

// validChannel is deliberately ASCII-only and delimiter-free so its accepted
// inputs match the DVM contract's byte-wise validation and signed transcript.
func validChannel(channel string) bool {
	if channel == "" || len(channel) > 64 {
		return false
	}
	for i := 0; i < len(channel); i++ {
		c := channel[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func decodeCID(value string) ([32]byte, error) {
	var cid [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(cid) || value != strings.ToLower(value) {
		return cid, fmt.Errorf("%w: cid must be 64 lowercase hex characters", ErrInvalid)
	}
	copy(cid[:], decoded)
	return cid, nil
}

func (n *Notice) SignatureArtifact() (*Signature, error) {
	if n == nil || n.Version != Version || !validChannel(n.Channel) || n.Sequence == 0 || n.Sequence > MaxSequence || n.Deadline <= 0 {
		return nil, ErrInvalid
	}
	if _, err := decodeCID(n.CID); err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(n.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrSignature
	}
	return &Signature{Channel: n.Channel, Sequence: n.Sequence, CID: n.CID, Deadline: n.Deadline, Sig: n.Sig}, nil
}

func ParseSequence(value string) (uint64, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return 0, ErrInvalid
	}
	sequence, err := strconv.ParseUint(value, 10, 64)
	if err != nil || sequence == 0 || sequence > MaxSequence {
		return 0, ErrInvalid
	}
	return sequence, nil
}
