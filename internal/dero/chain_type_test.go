package dero

import (
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestArgsToPayloadRejectsDeclaredTypeMismatch(t *testing.T) {
	cases := []anchor.Argument{
		{Name: "U", DataType: anchor.DataUint64, Value: "1"},
		{Name: "H", DataType: anchor.DataHash, Value: []byte("not-a-hash")},
		{Name: "A", DataType: anchor.DataAddress, Value: "dero1bad"},
		{Name: "T", DataType: anchor.DataTime, Value: "2026-01-01"},
	}
	for _, arg := range cases {
		if _, err := ArgsToPayload(anchor.Arguments{arg}); err == nil {
			t.Fatalf("accepted mismatched %s/%s value %#v", arg.Name, arg.DataType, arg.Value)
		}
	}
}

func TestArgsToPayloadAcceptsNativeSupportedTypes(t *testing.T) {
	args := anchor.Arguments{
		{Name: "S", DataType: anchor.DataString, Value: "text"},
		{Name: "U", DataType: anchor.DataUint64, Value: uint64(7)},
		{Name: "I", DataType: anchor.DataInt64, Value: int64(-7)},
		{Name: "F", DataType: anchor.DataFloat64, Value: float64(1.5)},
		{Name: "H", DataType: anchor.DataHash, Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Name: "T", DataType: anchor.DataTime, Value: time.Unix(1700000000, 0).UTC()},
	}
	if _, err := ArgsToPayload(args); err != nil {
		t.Fatalf("rejected native supported types: %v", err)
	}
}
