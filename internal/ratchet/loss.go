package ratchet

import (
	"encoding/binary"
	"encoding/hex"
	"sort"
	"time"

	"github.com/liqdmetal/spore/internal/crypto"
)

// LossRecord identifies one message that has NOT been delivered.
//
// Two states matter, and they are decided by the skipped-key store:
//
//   - PENDING (recoverable): the ciphertext has not arrived, but its message
//     key is still buffered. If the body turns up before the deadline the
//     message decrypts normally. A gap at this point is latency, not loss.
//
//   - LOST (unrecoverable): the buffered key was swept once its burn deadline
//     passed (SweepSkipped). The key is deleted and, by forward secrecy, cannot
//     be re-derived from anything the session still holds. The message is gone
//     for good — this is the only point at which "lost" is provable.
//
// That boundary is the whole design: a skipped key is deleted exactly when the
// message it would decrypt can no longer be fetched (both inherit the same burn
// deadline), so "key swept" and "message unrecoverable" are the same event.
type LossRecord struct {
	// RatchetKey is the sender's DH ratchet public key — the chain this
	// message belongs to. Two chains from the same session are distinguished
	// by this, so a gap is never mis-attributed across a DH ratchet step.
	RatchetKey [32]byte
	// N is the message number within that chain.
	N uint32
	// Deadline is the burn deadline this key inherited from the message.
	// Zero means unbounded (no TTL), which is bounded by the hard caps
	// instead and never swept by deadline.
	Deadline time.Time
}

// Pending reports whether this message can still be decrypted if its
// ciphertext arrives. A zero deadline never expires.
func (r LossRecord) Pending(now time.Time) bool {
	return r.Deadline.IsZero() || r.Deadline.After(now)
}

// decodeSkipID reverses skipID: hex(dhPub(32) || n(4 LE)).
func decodeSkipID(id string) (LossRecord, bool) {
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 36 {
		return LossRecord{}, false
	}
	var rec LossRecord
	copy(rec.RatchetKey[:], raw[:32])
	rec.N = binary.LittleEndian.Uint32(raw[32:])
	return rec, true
}

// sortLoss orders records deterministically (chain, then message number) so
// callers — and tests — see a stable sequence.
func sortLoss(recs []LossRecord) {
	sort.Slice(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		if cmp := string(a.RatchetKey[:]); cmp != string(b.RatchetKey[:]) {
			return cmp < string(b.RatchetKey[:])
		}
		return a.N < b.N
	})
}

// Outstanding returns every message this session is still missing but could
// still decrypt: buffered skipped keys whose deadline has not passed.
//
// This is the retry set. An empty result with a non-empty LostCount means the
// conversation has gaps that are already unrecoverable — the caller should say
// so rather than silently showing a thread with holes.
func (s *Session) Outstanding() []LossRecord {
	out := make([]LossRecord, 0, len(s.skipped))
	for id, sk := range s.skipped {
		rec, ok := decodeSkipID(id)
		if !ok {
			continue
		}
		// The deadline lives on the skipped key, not in the identifier, so
		// it must be copied across — a gap reported without its deadline
		// cannot be told apart from one that will never expire.
		rec.Deadline = sk.Deadline
		out = append(out, rec)
	}
	sortLoss(out)
	return out
}

// OutstandingCount is Outstanding without the allocation.
func (s *Session) OutstandingCount() int { return len(s.skipped) }

// SweepSkippedDetailed drops skipped keys whose inherited burn deadline has
// passed and returns them. Each returned record is a CONFIRMED LOSS: the
// ciphertext never arrived and the key to decrypt it is now gone.
//
// SweepSkipped is the count-only wrapper; this is the reporting form.
func (s *Session) SweepSkippedDetailed(now time.Time) []LossRecord {
	if len(s.skipped) == 0 {
		return nil
	}
	var swept []LossRecord
	for id, sk := range s.skipped {
		if sk.Deadline.IsZero() || !sk.Deadline.Before(now) {
			continue
		}
		if rec, ok := decodeSkipID(id); ok {
			rec.Deadline = sk.Deadline
			swept = append(swept, rec)
		}
		// Zero the key on the way out: it is unrecoverable the moment we
		// decide to drop it, so do not leave the material in memory.
		crypto.Zero(sk.MK[:])
		delete(s.skipped, id)
	}
	if len(swept) == 0 {
		return nil
	}
	s.recountSkipped()
	sortLoss(swept)
	return swept
}

// recountSkipped rebuilds the per-chain counters from what survived a sweep.
func (s *Session) recountSkipped() {
	s.skippedPerChain = map[string]int{}
	for id := range s.skipped {
		raw, err := hex.DecodeString(id)
		if err != nil || len(raw) < 32 {
			continue
		}
		s.skippedPerChain[hex.EncodeToString(raw[:32])]++
	}
}
