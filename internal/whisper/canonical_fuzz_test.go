package whisper

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzDecodeCanonical hammers the canonical payload parser (the m³ wire
// walker every chain backend feeds anchors into) with arbitrary bytes.
// Invariant: for ANY input, DecodeCanonical either returns ok=false or a
// well-formed (kind, text / ephPub, bodyCID) triple — it must never panic,
// never read out of bounds, and never accept a pointer frame shorter or
// longer than 64 bytes.
func FuzzDecodeCanonical(f *testing.F) {
	// Seeds: valid text frame, valid pointer frame, truncations, a lying
	// length prefix (claims more than present), a huge claimed length, and
	// unknown kinds.
	f.Add(EncodeTextCanonical("hello"))
	f.Add(EncodePointerCanonical([32]byte{1}, [32]byte{2}))
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x00})
	f.Add([]byte{0x02, 0x00, 0x3F})                  // pointer claims 63 bytes
	f.Add([]byte{0x02, 0x00, 0x41})                  // pointer claims 65 bytes
	f.Add([]byte{0x01, 0xFF, 0xFF})                  // claims 65535, has 0
	f.Add([]byte{0x7F, 0x00, 0x01, 0x41})            // unknown kind
	f.Add([]byte{0x01, 0x00, 0x04, 'a', 0x00, 0xFF}) // trailing garbage
	zero64 := bytes.Repeat([]byte{0}, 64)
	f.Add([]byte{0x02, 0x00, 0x40})
	f.Add(append([]byte{0x02, 0x00, 0x40}, zero64...))

	f.Fuzz(func(t *testing.T, p []byte) {
		kind, text, ephPub, bodyCID, ok := DecodeCanonical(p)
		if !ok {
			return
		}
		switch kind {
		case KindText:
			// Text frames: recovered text must equal the declared body.
			n := int(binary.BigEndian.Uint16(p[1:3]))
			if text != string(p[3:3+n]) {
				t.Fatalf("text frame mismatch: %q != body", text)
			}
			if ephPub != ([32]byte{}) || bodyCID != ([32]byte{}) {
				t.Fatal("text frame must not set pointer fields")
			}
		case KindPointer:
			// Pointer frames: body must have been exactly 64.
			n := int(binary.BigEndian.Uint16(p[1:3]))
			if n != 64 {
				t.Fatalf("pointer accepted with body length %d", n)
			}
			if text != "" {
				t.Fatal("pointer frame must not set text")
			}
		default:
			t.Fatalf("unknown kind %d accepted", kind)
		}
	})
}
