package dero

import (
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestArgsToPayloadRejectsDuplicateEffectiveWireType(t *testing.T) {
	cases := []anchor.Arguments{
		{
			{Name: "X", DataType: anchor.DataInt64, Value: uint64(1)},
			{Name: "X", DataType: anchor.DataUint64, Value: uint64(2)},
		},
		{
			{Name: "X", DataType: anchor.DataUint64, Value: uint64(1)},
			{Name: "X", DataType: anchor.DataInt64, Value: uint64(2)},
		},
	}
	for i, args := range cases {
		if _, err := ArgsToPayload(args); err == nil {
			t.Fatalf("case %d accepted duplicate effective wire datatype", i)
		}
	}
}

func TestArgsToPayloadAllowsDistinctWireKeys(t *testing.T) {
	args := anchor.Arguments{
		{Name: "X", DataType: anchor.DataString, Value: "text"},
		{Name: "X", DataType: anchor.DataUint64, Value: uint64(2)},
	}
	if _, err := ArgsToPayload(args); err != nil {
		t.Fatalf("rejected distinct wire keys: %v", err)
	}
}
