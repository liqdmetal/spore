// Package fabric implements the relay-fabric primitives that are decided at
// the wire level (docs/RELAY_FABRIC.md open question 1, DECIDED; WIRE_SPEC
// §8): epoch-salted handle derivation, registration tokens, and the queued
// pointer envelope. The fabric client verbs (freg/fput/fpop over the
// spore-peer socket) are slice F2; this package is the shared derivation and
// codec both sides of that client — and both implementations (Go here, Rust
// in spore-peer) must agree byte-for-byte, pinned by
// docs/interop-vectors.json "fabric_v1".
//
// Two planes, one seam (the decided design):
//
//   - Pointer plane: untouched. A published pointer carries
//     Route = ratchetwire.RouteKey(sid) verbatim, and FetchFrame's
//     RouteKey(f.SessionID) == p.Route binding holds end-to-end.
//   - Fabric plane: relays index queued pointers by FabricHandle, a
//     seed-salted derivation that never reveals sid (HKDF is one-way).
//
// The recipient derives FabricHandle from (seed, epoch, sid); the seed rides
// the contact card, the epoch increments on prekey-batch rotation.
package fabric

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Wire labels. Version strings ("spore/fabric/v1/...") are part of the wire
// contract — changing one changes every derived handle or token.
const (
	LabelHandle = "spore/fabric/v1/handle"
	LabelReg    = "spore/fabric/v1/reg"

	// EnvelopeV1 is the fabric envelope version byte.
	EnvelopeV1 byte = 1

	// PointerLen is the exact pointer length an envelope may carry (the
	// 74-byte PointerPayload: version+reserved+route+cid+deadline).
	PointerLen = 74

	// envelopeLen = version(1) + handle(32) + pointer(74) + received_at(8).
	envelopeLen = 1 + 32 + PointerLen + 8
)

// hkdfExpand matches the ratchet's KDF discipline: HKDF-SHA256 with a zero
// salt (golang.org/x/crypto/hkdf with nil salt zero-fills the salt block, as
// RFC 5869 specifies) and info = the wire label || big-endian epoch || sid.
// The Rust implementation hand-rolls the same construction; the
// interop-vectors.json fabric_v1 section pins the agreement.
func hkdfExpand(ikm, info []byte, n int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, nil, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// FabricHandle derives the epoch-salted lookup handle relays index by:
//
//	FabricHandle = HKDF-SHA256(seed, LabelHandle || epoch_be || sid)[0:32]
//
// seed is the 32-byte contact-card secret; epoch increments on prekey-batch
// rotation; sid is the ratchet session id. The pointer's Route stays
// RouteKey(sid) — this handle is the fabric-plane lookup key only.
func FabricHandle(seed [32]byte, epoch uint32, sid [8]byte) ([32]byte, error) {
	info := make([]byte, 0, len(LabelHandle)+4+len(sid))
	info = append(info, LabelHandle...)
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	info = append(info, e[:]...)
	info = append(info, sid[:]...)
	out, err := hkdfExpand(seed[:], info, 32)
	if err != nil {
		return [32]byte{}, err
	}
	var h [32]byte
	copy(h[:], out)
	return h, nil
}

// RegToken computes the freg/fpop possession token:
//
//	token = HMAC-SHA256(seed, LabelReg || handle || server_nonce), hex-encoded
//
// Possession of the seed, not knowledge of the public handle, drains. No
// signature scheme exists here on purpose: a signature would hand relays a
// cross-relay identity key, which is exactly the linkage the epochs exist to
// break (docs/RELAY_FABRIC.md, hijacker row).
func RegToken(seed [32]byte, handle [32]byte, serverNonce string) string {
	mac := hmac.New(sha256.New, seed[:])
	mac.Write([]byte(LabelReg))
	mac.Write(handle[:])
	mac.Write([]byte(serverNonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// Envelope is the queued-pointer object a relay holds per (handle, CID).
type Envelope struct {
	Handle     [32]byte
	Pointer    [PointerLen]byte // PointerPayload verbatim; CID + BurnDeadline inside
	ReceivedAt uint64           // unix-seconds, for FIFO order + diagnostics
}

// MarshalEnvelope serializes the v1 envelope:
//
//	version u8 =1 | handle 32 | pointer 74 | received_at u64 LE
//
// received_at is little-endian, matching the pointer's BurnDeadline
// convention elsewhere in this protocol (WIRE_SPEC §2).
func (e Envelope) MarshalBinary() []byte {
	out := make([]byte, envelopeLen)
	out[0] = EnvelopeV1
	copy(out[1:33], e.Handle[:])
	copy(out[33:33+PointerLen], e.Pointer[:])
	binary.LittleEndian.PutUint64(out[33+PointerLen:], e.ReceivedAt)
	return out
}

// ParseEnvelope decodes and structurally validates an envelope. Relays
// validate shape only — version, lengths, and that the embedded pointer is
// PointerPayload-shaped — never pointer semantics (design law 4: the
// ratchet is the filter). A nonzero pointer deadline is policy, enforced at
// the fput verb, not here.
func ParseEnvelope(b []byte) (Envelope, error) {
	if len(b) != envelopeLen {
		return Envelope{}, fmt.Errorf("fabric: bad envelope length %d != %d", len(b), envelopeLen)
	}
	if b[0] != EnvelopeV1 {
		return Envelope{}, fmt.Errorf("fabric: bad envelope version %d", b[0])
	}
	var e Envelope
	copy(e.Handle[:], b[1:33])
	copy(e.Pointer[:], b[33:33+PointerLen])
	if e.Pointer[0] != 1 || e.Pointer[1] != 0 {
		return Envelope{}, fmt.Errorf("fabric: bad pointer payload header")
	}
	e.ReceivedAt = binary.LittleEndian.Uint64(b[33+PointerLen:])
	return e, nil
}
