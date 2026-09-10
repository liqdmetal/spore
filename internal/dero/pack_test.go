package dero

import (
	"bytes"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestPackArgumentsMatchesR153Shape(t *testing.T) {
	args := anchor.Arguments{
		{Name: "W", DataType: anchor.DataUint64, Value: uint64(0xE220)},
		{Name: "T", DataType: anchor.DataString, Value: "hello"},
	}
	got, err := PackArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xa2, 0x62, 'T', 'S', 0x65, 'h', 'e', 'l', 'l', 'o', 0x62, 'W', 'U', 0x19, 0xe2, 0x20}
	if !bytes.Equal(got, want) {
		t.Fatalf("CBOR = %x, want %x", got, want)
	}
	if len(got) > Payload0Limit {
		t.Fatalf("packed size %d exceeds R153 limit", len(got))
	}
}

func TestPackArgumentsRejectsUnsupportedAndOversized(t *testing.T) {
	if _, err := PackArguments(anchor.Arguments{{Name: "X", DataType: "Z", Value: "x"}}); err == nil {
		t.Fatal("accepted unknown datatype")
	}
	if _, err := PackArguments(anchor.Arguments{{Name: "X", DataType: anchor.DataAddress, Value: "dero1bad"}}); err == nil {
		t.Fatal("accepted string address as R153 address value")
	}
	// An all-ones x coordinate IS a valid BN256 point, so packing it must
	// succeed. (This assertion was briefly inverted; the fixture is on-curve.)
	if _, err := PackArguments(anchor.Arguments{{Name: "X", DataType: anchor.DataAddress, Value: bytes.Repeat([]byte{1}, 33)}}); err != nil {
		t.Fatalf("rejected valid compressed address key: %v", err)
	}
	// x = 4 is off-curve: x³ + 3 = 67 is not a quadratic residue mod p, so the
	// compressed key must be refused.
	offCurve := make([]byte, 33)
	offCurve[31] = 0x04 // big-endian x = 4
	if _, err := PackArguments(anchor.Arguments{{Name: "X", DataType: anchor.DataAddress, Value: offCurve}}); err == nil {
		t.Fatal("accepted off-curve compressed address key")
	}
	if _, err := PackArguments(anchor.Arguments{{Name: "T", DataType: anchor.DataString, Value: string(bytes.Repeat([]byte{'x'}, Payload0Limit))}}); err == nil {
		t.Fatal("accepted oversized payload")
	}
}
