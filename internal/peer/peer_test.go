package peer

import (
	"crypto/sha256"
	"testing"
)

// TestVerifyBody is a pure-function test of the seam's integrity gate: a body
// whose sha256 != requested cid must be rejected before decrypt.
func TestVerifyBody(t *testing.T) {
	good := []byte("correct body")
	wrong := []byte("different content")
	cid := sha256.Sum256(good)

	if err := verifyBody(bodyResult{data: good, err: nil}, cid); err != nil {
		t.Fatalf("good body rejected: %v", err)
	}
	if err := verifyBody(bodyResult{data: wrong, err: nil}, cid); err == nil {
		t.Fatal("wrong body not rejected")
	}
	if err := verifyBody(bodyResult{data: nil, err: errEmpty}, cid); err == nil {
		t.Fatal("empty body not rejected")
	}
	big := make([]byte, MaxBody+1)
	if err := verifyBody(bodyResult{data: big, err: nil}, cid); err != ErrTooBig {
		t.Fatalf("oversize body: got %v, want ErrTooBig", err)
	}
}
