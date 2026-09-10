package dero

import (
	"bytes"
	"testing"
)

func TestValidateAddress(t *testing.T) {
	valid := "dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq"
	if got, err := ValidateAddress(valid); err != nil || got != valid {
		t.Fatalf("valid address: got %q err=%v", got, err)
	}
	for _, bad := range []string{
		"",
		"dero1abc",
		"deto1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq",
		"dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pna",
	} {
		if _, err := ValidateAddress(bad); err == nil {
			t.Fatalf("accepted invalid address %q", bad)
		}
	}
}

// TestValidateCompressedPoint pins the BN256 field arithmetic in both
// directions. The bug this guards is silent: using bn256.Order (the group
// order) instead of bn256.P (the base-field modulus) still compiles and still
// rejects garbage, but tests quadratic residuosity in the wrong field and so
// false-rejects roughly half of all genuinely valid compressed points.
//
// TestValidateAddress above is the primary guard, because it drives a REAL
// mainnet address through the same code path.
func TestValidateCompressedPoint(t *testing.T) {
	// x = 4: x³ + 3 = 67, which is not a quadratic residue mod p.
	offCurve := make([]byte, 33)
	offCurve[31] = 0x04 // big-endian x = 4, y selector 0
	if err := validateCompressedPoint(offCurve); err == nil {
		t.Fatal("accepted an off-curve compressed key (x=4)")
	}

	// x = all ones is a valid point on y² = x³ + 3.
	if err := validateCompressedPoint(bytes.Repeat([]byte{1}, 33)); err != nil {
		t.Fatalf("rejected an on-curve compressed key: %v", err)
	}

	// x = 0 is on the curve only if 3 is a quadratic residue; reject-or-accept
	// is not the point here — the length and selector checks are.
	if err := validateCompressedPoint(make([]byte, 32)); err == nil {
		t.Fatal("accepted a 32-byte compressed key")
	}

	badSelector := bytes.Repeat([]byte{1}, 33)
	badSelector[32] = 0x02
	if err := validateCompressedPoint(badSelector); err == nil {
		t.Fatal("accepted a non-canonical y selector")
	}

	// x = P is out of range (must be < p).
	tooLarge := make([]byte, 33)
	for i := 0; i < 32; i++ {
		tooLarge[i] = 0xff
	}
	if err := validateCompressedPoint(tooLarge); err == nil {
		t.Fatal("accepted an out-of-range x coordinate")
	}
}
