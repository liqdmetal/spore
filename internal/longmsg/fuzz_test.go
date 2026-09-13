package longmsg

import (
	"bytes"
	"testing"
)

// FuzzUnpadBody drives the padding layer with hostile ciphertext-shaped
// input: unpad must never panic, must never return more bytes than it was
// given, and a valid round-trip (pad -> unpad) must always reproduce the
// original plaintext.
func FuzzUnpadBody(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}) // n = MaxInt64, the overflow regression
	f.Add(padBody([]byte("round-trip plaintext")))
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := unpadBody(in)
		if err == nil {
			if len(out) > len(in) {
				t.Fatalf("unpad returned %d bytes from %d input bytes", len(out), len(in))
			}
			// re-pad the result and verify the round trip is stable
			repadded := padBody(out)
			out2, err2 := unpadBody(repadded)
			if err2 != nil || !bytes.Equal(out2, out) {
				t.Fatalf("unpad not idempotent on its own output")
			}
		}
	})
}
