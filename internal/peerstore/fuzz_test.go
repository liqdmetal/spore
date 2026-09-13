package peerstore

import (
	"crypto/sha256"
	"testing"
)

// FuzzClassify drives the pure response dispatcher with hostile frames:
// wrong status bytes, huge/tiny bodies, bodies whose hash does not match the
// requested cid, error strings of every shape. The cid is fixed (the hash of
// a known good body); the fuzzer mutates the frame. classify must never
// panic and must never return a body whose sha256 != cid.
func FuzzClassify(f *testing.F) {
	good := []byte("opaque-ciphertext-4")
	cid := sha256.Sum256(good)
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x01, 0x02, 0x03})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, '4', '0', '4', ' ', 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd'})
	f.Add([]byte{0x01, '4', '1', '0', ' ', 'g', 'o', 'n', 'e'})
	f.Add([]byte{0x02, 0xff, 0xff, 0xff, 0xff})
	f.Add(append([]byte{0x00}, good...))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, payload []byte) {
		body, err := classify(payload, cid)
		if err == nil {
			if sha256.Sum256(body) != cid {
				t.Fatalf("classify returned a body that does not hash to the requested cid")
			}
			if len(body) == 0 {
				t.Fatalf("classify returned an empty body as success")
			}
		}
	})
}
