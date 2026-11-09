package continuity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// A vault file is the authority, but recipients and observers hold copies. A
// copy stops being evidence the moment the owner checks in, because its latest
// signed deadline is the old one: left alone, that deadline passes and a
// recipient can release against a decision the owner has already revoked.
// Check-in envelopes are how an updated chain travels without the vault's
// ciphertext, payload key, or private material ever moving again.

const checkinEnvelopeVersion uint8 = 1

var (
	// ErrCheckInForeign marks an envelope that does not belong to this vault.
	ErrCheckInForeign = errors.New("continuity: check-in envelope is for a different vault")
	// ErrCheckInChain marks an envelope whose records are not a continuation of
	// this vault's signed chain.
	ErrCheckInChain = errors.New("continuity: check-in envelope does not extend the signed chain")
)

// CheckInEnvelope is the owner-signed check-in chain of one vault in a form
// that is safe to hand to recipients, observers, and a messenger. It carries
// the public vault id, the owner signing key, and signed liveness records --
// no payload ciphertext, no payload key, no private material.
type CheckInEnvelope struct {
	Version     uint8           `json:"version"`
	VaultID     string          `json:"vault_id"`
	OwnerSigPub string          `json:"owner_sig_pub"`
	Checkins    []CheckInRecord `json:"checkins"`
}

// CheckIns exports the vault's signed check-in chain as an envelope.
func (v *Vault) CheckIns() (*CheckInEnvelope, error) {
	if v == nil {
		return nil, ErrInvalidVault
	}
	if err := v.Verify(); err != nil {
		return nil, err
	}
	records := make([]CheckInRecord, len(v.Checkins))
	copy(records, v.Checkins)
	return &CheckInEnvelope{
		Version:     checkinEnvelopeVersion,
		VaultID:     v.VaultID,
		OwnerSigPub: v.OwnerSigPub,
		Checkins:    records,
	}, nil
}

// ParseCheckInEnvelope decodes one envelope strictly. It does not compare the
// envelope with a vault; MergeCheckIns does that.
func ParseCheckInEnvelope(raw []byte) (*CheckInEnvelope, error) {
	var env CheckInEnvelope
	if err := decodeStrict(raw, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCheckInChain, err)
	}
	if env.Version != checkinEnvelopeVersion || env.VaultID == "" || len(env.Checkins) == 0 || len(env.Checkins) > MaxCheckIns {
		return nil, ErrCheckInChain
	}
	if _, err := decodeFixed(env.OwnerSigPub, ed25519.PublicKeySize); err != nil {
		return nil, ErrCheckInChain
	}
	return &env, nil
}

// MergeCheckIns advances v with the records in env. It is atomic: nothing is
// appended unless every new record is contiguous, deadline-correct, and signed
// by the vault's owner signing key. Re-delivering an envelope v already
// contains is a no-op, so an at-least-once transport cannot corrupt the chain.
// It consults no clock and needs no private key: it only copies deadlines the
// owner already signed.
func (v *Vault) MergeCheckIns(env *CheckInEnvelope) (int, error) {
	if v == nil {
		return 0, ErrInvalidVault
	}
	if err := v.Verify(); err != nil {
		return 0, err
	}
	if env == nil || env.Version != checkinEnvelopeVersion {
		return 0, ErrCheckInChain
	}
	if env.VaultID != v.VaultID || env.OwnerSigPub != v.OwnerSigPub {
		return 0, ErrCheckInForeign
	}
	sigPub, err := decodeFixed(env.OwnerSigPub, ed25519.PublicKeySize)
	if err != nil {
		return 0, ErrCheckInChain
	}
	records := env.Checkins
	if len(records) == 0 || len(records) > MaxCheckIns {
		return 0, ErrCheckInChain
	}
	// The envelope must carry this vault's genesis record, so a chain that
	// starts somewhere else can never be grafted onto this one.
	if records[0].Seq != 0 || records[0].At != v.CreatedAt || records[0].Sig != v.Checkins[0].Sig {
		return 0, fmt.Errorf("%w: genesis record mismatch", ErrCheckInChain)
	}
	overlap := len(records)
	if overlap > len(v.Checkins) {
		overlap = len(v.Checkins)
	}
	for i := 0; i < overlap; i++ {
		if records[i] != v.Checkins[i] {
			return 0, fmt.Errorf("%w: record %d does not match this copy", ErrCheckInChain, i)
		}
	}
	added := records[overlap:]
	if len(added) == 0 {
		return 0, nil
	}
	if len(v.Checkins)+len(added) > MaxCheckIns {
		return 0, ErrCheckInChain
	}
	last := v.Checkins[len(v.Checkins)-1]
	checked := make([]CheckInRecord, 0, len(added))
	for i, c := range added {
		if c.Seq != last.Seq+1 {
			return 0, fmt.Errorf("%w: record %d has sequence %d", ErrCheckInChain, i, c.Seq)
		}
		if c.Prev != checkinDigest(last) {
			return 0, fmt.Errorf("%w: record %d does not chain to its predecessor", ErrCheckInChain, i)
		}
		if c.At <= last.At || c.Deadline <= c.At {
			return 0, fmt.Errorf("%w: record %d time does not advance", ErrCheckInChain, i)
		}
		expected, ok := safeAdd(c.At, v.IntervalSeconds+v.GraceSeconds)
		if !ok || c.Deadline != expected {
			return 0, fmt.Errorf("%w: record %d deadline is not the vault interval plus grace", ErrCheckInChain, i)
		}
		sig, err := decodeFixed(c.Sig, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(sigPub), checkinTranscript(v.VaultID, c), sig) {
			return 0, fmt.Errorf("%w: record %d signature does not verify", ErrCheckInChain, i)
		}
		checked = append(checked, c)
		last = c
	}
	before := len(v.Checkins)
	v.Checkins = append(v.Checkins, checked...)
	if err := v.Verify(); err != nil {
		v.Checkins = v.Checkins[:before]
		return 0, err
	}
	return len(checked), nil
}
