// Package anchor defines the on-chain record that rides inside a DERO
// transaction's encrypted message field.
//
// The DERO message field is NOT a raw byte blob: it is 111 bytes
// (transaction.PAYLOAD0_LIMIT) of CBOR-encoded rpc.Arguments — a map of
// name+datatype -> value, restricted to string / int64 / uint64 / float64 /
// hash(32B) / address(33B) / time. crypto.Hash values cross the JSON boundary
// as 64-char hex strings.
//
// The anchor is expressed as four typed arguments (measured 91 bytes CBOR,
// within the 111-byte budget):
//
//	name  type    content
//	  K    H      message: ephemeral X25519 pubkey; continuity: vault ID
//	  C    H      message: body CID; continuity: quorum policy ID
//	  D    U      burn deadline, unix seconds
//	  F    U      meta: version | kind<<8 | flags<<16 | continuity seq<<24
//
// It carries NO plaintext, NO ciphertext, and NO long-term key material. Once
// the ephemeral secrets are erased, this record is inert: a dead public key,
// a hash, and a deadline.
package anchor

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// DERO Argument data types (mirrors derohe rpc.DataType string constants).
const (
	DataString  = "S"
	DataInt64   = "I"
	DataUint64  = "U"
	DataFloat64 = "F"
	DataHash    = "H"
	DataAddress = "A"
	DataTime    = "T"
)

// Version is the current anchor wire version.
const Version byte = 1

// Kind discriminates the anchor's purpose.
type Kind byte

const (
	KindMessage    Kind = 0x01 // body ciphertext exists off-chain
	KindAck        Kind = 0x02 // receipt for a message
	KindKeyRotate  Kind = 0x03 // recipient advertises a new medium-term pubkey
	KindContinuity Kind = 0x04 // continuity vault/quorum commitment
) //nolint:revive // wire names are protocol constants

const maxContinuitySeq uint64 = (1 << 40) - 1

// ContinuitySeq is encoded in the high 40 bits of the F metadata word when
// KindContinuity is used. The four-argument wire shape stays within DERO's
// payload limit while committing the exact signed check-in epoch.

// Flags bits.
const (
	FlagAckRequested byte = 1 << 0
)

// Argument is a single typed payload argument, wire-identical to
// derohe rpc.Argument over JSON.
type Argument struct {
	Name     string      `json:"name"`
	DataType string      `json:"datatype"`
	Value    interface{} `json:"value"`
}

// Arguments is a list of arguments.
type Arguments []Argument

// Anchor is a parsed on-chain record.
type Anchor struct {
	Version      byte
	Kind         Kind
	EphemeralPub [32]byte
	CID          [32]byte
	BurnDeadline uint64 // unix seconds
	Flags        byte
	// ContinuitySeq is used only by KindContinuity and is encoded in the
	// otherwise-unused high 40 bits of the F metadata word.
	ContinuitySeq uint64
} /*nolint:revive // wire-facing protocol record */

func (a *Anchor) metadata() uint64 {
	meta := uint64(a.Version) | uint64(a.Kind)<<8 | uint64(a.Flags)<<16
	if a.Kind == KindContinuity {
		meta |= a.ContinuitySeq << 24
	}
	return meta
}

// ToArguments renders the anchor as the typed argument list that the wallet
// RPC packs into the on-chain message field.
func (a *Anchor) ToArguments() Arguments {
	meta := a.metadata()
	return Arguments{
		{Name: "K", DataType: DataHash, Value: hex.EncodeToString(a.EphemeralPub[:])},
		{Name: "C", DataType: DataHash, Value: hex.EncodeToString(a.CID[:])},
		{Name: "D", DataType: DataUint64, Value: a.BurnDeadline},
		{Name: "F", DataType: DataUint64, Value: meta},
	}
}

// FromArguments parses an anchor out of a typed argument list (as received
// from get_transfers).
func FromArguments(args Arguments) (*Anchor, error) {
	a := &Anchor{}
	var meta uint64
	have := map[string]bool{}
	for _, arg := range args {
		key := arg.Name + arg.DataType
		if have[arg.Name] {
			return nil, fmt.Errorf("anchor: duplicate field %q", arg.Name)
		}
		switch key {
		case "K" + DataHash:
			h, err := hashFromValue(arg.Value)
			if err != nil {
				return nil, fmt.Errorf("anchor: K: %w", err)
			}
			a.EphemeralPub = h
			have["K"] = true
		case "C" + DataHash:
			h, err := hashFromValue(arg.Value)
			if err != nil {
				return nil, fmt.Errorf("anchor: C: %w", err)
			}
			a.CID = h
			have["C"] = true
		case "D" + DataUint64:
			v, err := uintFromValue(arg.Value)
			if err != nil {
				return nil, fmt.Errorf("anchor: D: %w", err)
			}
			a.BurnDeadline = v
			have["D"] = true
		case "F" + DataUint64:
			v, err := uintFromValue(arg.Value)
			if err != nil {
				return nil, fmt.Errorf("anchor: F: %w", err)
			}
			meta = v
			have["F"] = true
		default:
			return nil, fmt.Errorf("anchor: unknown field %q", arg.Name)
		}
	}
	if !have["K"] || !have["C"] || !have["D"] || !have["F"] {
		return nil, errors.New("anchor: missing required K/C/D/F field (not a compost anchor)")
	}
	a.Version = byte(meta)
	a.Kind = Kind(byte(meta >> 8))
	a.Flags = byte(meta >> 16)
	if a.Version != Version {
		return nil, fmt.Errorf("anchor: unsupported version %d", a.Version)
	}
	if a.Kind == KindContinuity {
		a.ContinuitySeq = meta >> 24
		if a.ContinuitySeq > maxContinuitySeq {
			return nil, errors.New("anchor: invalid continuity check-in sequence")
		}
	}
	return a, nil
}

// Expired reports whether the burn deadline has passed.
func (a *Anchor) Expired(now time.Time) bool {
	return now.Unix() > int64(a.BurnDeadline)
}

// hashFromValue accepts a 64-char hex string, raw []byte, or [32]byte.
func hashFromValue(v interface{}) ([32]byte, error) {
	var h [32]byte
	switch x := v.(type) {
	case string:
		b, err := hex.DecodeString(x)
		if err != nil || len(b) != 32 {
			return h, fmt.Errorf("hash value must be 64-char hex, got %q", x)
		}
		copy(h[:], b)
		return h, nil
	case []byte:
		if len(x) != 32 {
			return h, fmt.Errorf("hash []byte len %d, want 32", len(x))
		}
		copy(h[:], x)
		return h, nil
	case [32]byte:
		return x, nil
	default:
		return h, fmt.Errorf("unhandled hash value type %T", v)
	}
}

// uintFromValue accepts the numeric shapes JSON may produce.
func uintFromValue(v interface{}) (uint64, error) {
	switch x := v.(type) {
	case uint64:
		return x, nil
	case int64:
		if x < 0 {
			return 0, errors.New("negative uint64")
		}
		return uint64(x), nil
	case float64:
		// 2^64 is exactly representable as float64 but is outside uint64;
		// compare before converting so malformed JSON cannot wrap or truncate.
		if x < 0 || x >= 18446744073709551616.0 || x != float64(uint64(x)) {
			return 0, errors.New("invalid uint64")
		}
		return uint64(x), nil
	case string:
		u, err := strconv.ParseUint(x, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("uint64 string %q: %w", x, err)
		}
		return u, nil
	default:
		return 0, fmt.Errorf("unhandled uint64 value type %T", v)
	}
}
