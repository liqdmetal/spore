package longmsg

import (
	"testing"
)

func TestPadUnpadRoundTrip(t *testing.T) {
	for _, msg := range []string{"", "hi", "a", "short body", "x" + string(make([]byte, 2000))} {
		pt := []byte(msg)
		padded := padBody(pt)
		// Padded length must be a multiple of the bucket + header, and never
		// less than what the plaintext needs.
		if len(padded)%BodyPaddingBucket != 0 {
			t.Fatalf("padded len %d not a multiple of bucket %d", len(padded), BodyPaddingBucket)
		}
		got, err := unpadBody(padded)
		if err != nil {
			t.Fatalf("unpad %q: %v", msg, err)
		}
		if string(got) != msg {
			t.Fatalf("round-trip mismatch: got %q want %q", got, msg)
		}
	}
}

func TestPaddingKillsSizeFingerprint(t *testing.T) {
	// Two very different-length bodies must pad to the SAME ciphertext size.
	short := padBody([]byte("hi"))
	long := padBody([]byte("this is a much longer body that should pad to the same bucket"))
	if len(short) != len(long) {
		t.Fatalf("short=%d long=%d — padding must equalize sizes", len(short), len(long))
	}
	if len(short) < 1024 {
		t.Fatalf("short padded to %d — should be >= one 1024 bucket", len(short))
	}
}

func TestUnpadRejectsTampered(t *testing.T) {
	padded := padBody([]byte("hello world"))
	// Corrupt the length header so the claimed length exceeds the buffer.
	bad := append([]byte(nil), padded...)
	bad[7] = 0xff // high byte -> claimed length huge, beyond the buffer
	if _, err := unpadBody(bad); err == nil {
		t.Fatal("expected error for corrupt padding header")
	}
	if _, err := unpadBody([]byte{0x01}); err == nil {
		t.Fatal("expected error for short body")
	}
}
