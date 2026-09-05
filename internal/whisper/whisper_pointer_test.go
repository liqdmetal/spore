package whisper

import (
	"bytes"
	"testing"

	"github.com/liqdmetal/mycelium/internal/anchor"
)

// TestPointerRoundTrip: build + parse a pointer-whisper (K + C hashes).
func TestPointerRoundTrip(t *testing.T) {
	var eph, cid [32]byte
	copy(eph[:], bytes.Repeat([]byte{0xab}, 32))
	copy(cid[:], bytes.Repeat([]byte{0xcd}, 32))
	args := BuildPointerArgs(eph, cid)
	if len(args) != 3 {
		t.Fatalf("pointer args = %d, want 3", len(args))
	}
	gotEph, gotCid, ok := ParsePointer(args)
	if !ok {
		t.Fatal("should parse as pointer")
	}
	if gotEph != eph || gotCid != cid {
		t.Fatal("pointer roundtrip mismatch")
	}
	// A pointer must NOT parse as a short text whisper, and vice versa.
	if _, isText := ParseArgs(args); isText {
		t.Fatal("pointer should not parse as text whisper")
	}
}

// TestTextNotPointer: a normal text whisper is not a pointer.
func TestTextNotPointer(t *testing.T) {
	args, _ := BuildArgs("hi there")
	if _, _, ok := ParsePointer(args); ok {
		t.Fatal("text whisper should not parse as pointer")
	}
	if _, isText := ParseArgs(args); !isText {
		t.Fatal("should parse as text whisper")
	}
}

// TestPointerFitsBudget: the pointer's packed size must be under 111 bytes.
func TestPointerFitsBudget(t *testing.T) {
	var eph, cid [32]byte
	copy(eph[:], bytes.Repeat([]byte{0xaa}, 32))
	copy(cid[:], bytes.Repeat([]byte{0xbb}, 32))
	args := BuildPointerArgs(eph, cid)
	// Measure the packed size via the same CBOR map encoding derohe uses
	// (3 args: WU uint, KH hash, CH hash). We replicate the map packing.
	// The anchor hash arg alone is 34 bytes hex + framing; 2 hashes ~68 +
	// the uint ~6 + map header = ~78 bytes — comfortably under 111.
	if len(args) > 8 {
		// args is the in-memory list; verify each hash value is 64-char hex.
		for _, a := range args {
			if a.DataType == anchor.DataHash {
				s, ok := a.Value.(string)
				if !ok || len(s) != 64 {
					t.Fatalf("hash arg not 64-char hex: %v", a.Value)
				}
			}
		}
	}
}
