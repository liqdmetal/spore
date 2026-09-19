// Canonical m³ payload encoding — chain-agnostic.
//
// A spore message has ONE canonical wire form regardless of which chain
// carries it (DERO CBOR args, EVM calldata, Monero tx_extra). This keeps the
// crypto/core identical across trees; only the transport wrapping differs.
//
// Wire format (all length-prefixed, big-endian, no CBOR/JSON dependency):
//
//	byte 0          kind: 0x01 = text whisper, 0x02 = long-body pointer
//	byte 1..2       payload length (uint16 BE)
//	bytes 3..       payload:
//	                  text:      UTF-8 message bytes
//	                  pointer:   32B ephemeral pub || 32B body CID
package whisper

import (
	"encoding/binary"
	"errors"

	"github.com/liqdmetal/spore/internal/chain"
)

// Canonical message kinds.
const (
	KindText    byte = 0x01
	KindPointer byte = 0x02
)

// EncodeTextCanonical encodes a text whisper into the canonical wire form.
func EncodeTextCanonical(text string) []byte {
	b := []byte(text)
	out := make([]byte, 0, 3+len(b))
	out = append(out, KindText)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(b)))
	out = append(out, l[:]...)
	out = append(out, b...)
	return out
}

// EncodePointerCanonical encodes a long-body pointer (ephemeral pub + CID).
func EncodePointerCanonical(ephPub, bodyCID [32]byte) []byte {
	out := make([]byte, 0, 3+64)
	out = append(out, KindPointer)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], 64)
	out = append(out, l[:]...)
	out = append(out, ephPub[:]...)
	out = append(out, bodyCID[:]...)
	return out
}

// ErrBadPayload is returned for a malformed canonical payload.
var ErrBadPayload = errors.New("whisper: bad canonical payload")

// DecodeCanonical parses a canonical payload. kind in {text,pointer}. For text,
// text is set. For pointer, ephPub/bodyCID are set. ok=false if malformed.
func DecodeCanonical(p []byte) (kind byte, text string, ephPub, bodyCID [32]byte, ok bool) {
	if len(p) < 3 {
		return 0, "", [32]byte{}, [32]byte{}, false
	}
	kind = p[0]
	n := int(binary.BigEndian.Uint16(p[1:3]))
	if 3+n > len(p) {
		return 0, "", [32]byte{}, [32]byte{}, false
	}
	body := p[3 : 3+n]
	switch kind {
	case KindText:
		return KindText, string(body), [32]byte{}, [32]byte{}, true
	case KindPointer:
		if len(body) != 64 {
			return 0, "", [32]byte{}, [32]byte{}, false
		}
		copy(ephPub[:], body[:32])
		copy(bodyCID[:], body[32:])
		return KindPointer, "", ephPub, bodyCID, true
	}
	return 0, "", [32]byte{}, [32]byte{}, false
}

// CanonicalCodec adapts the canonical wire form to the chain.Codec interface,
// so any chain backend can carry m³ messages without chain-specific payload
// knowledge. chain.Payload is []byte, so these satisfy the seam.
type CanonicalCodec struct{}

// EncodeText implements whisper.Codec.
func (CanonicalCodec) EncodeText(text string) (chain.Payload, error) {
	return EncodeTextCanonical(text), nil
}

// EncodePointer implements whisper.Codec.
func (CanonicalCodec) EncodePointer(ephPub, bodyCID [32]byte) (chain.Payload, error) {
	return EncodePointerCanonical(ephPub, bodyCID), nil
}

// DecodeText implements whisper.Codec.
func (CanonicalCodec) DecodeText(p chain.Payload) (string, bool) {
	k, text, _, _, ok := DecodeCanonical(p)
	return text, ok && k == KindText
}

// DecodePointer implements whisper.Codec.
func (CanonicalCodec) DecodePointer(p chain.Payload) ([32]byte, [32]byte, bool) {
	k, _, eph, cid, ok := DecodeCanonical(p)
	return eph, cid, ok && k == KindPointer
}
