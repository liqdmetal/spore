package dero

import (
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestPayloadCodecRejectsUnsafeNumericCoercion(t *testing.T) {
	for _, payload := range []string{
		`{"a":[{"n":"D","t":"U","v":"1.5"}]}`,
		`{"a":[{"n":"D","t":"U","v":"18446744073709551616"}]}`,
	} {
		if _, err := PayloadToArgs([]byte(payload)); err == nil {
			t.Fatalf("accepted invalid uint payload %s", payload)
		}
	}
}

func TestPayloadCodecRejectsUnknownTypesAndMissingEnvelope(t *testing.T) {
	for _, payload := range []string{
		`{"a":[{"n":"D","t":"X","v":"1"}]}`,
		`{"a":null}`,
		`{}`,
	} {
		if _, err := PayloadToArgs([]byte(payload)); err == nil {
			t.Fatalf("accepted malformed payload %s", payload)
		}
	}
}

func TestPayloadCodecRejectsUnsafeFloatCoercion(t *testing.T) {
	for _, value := range []string{"1.5", "18446744073709551616"} {
		payload := []byte(`{"a":[{"n":"D","t":"U","v":` + value + `}]}`)
		if _, err := PayloadToArgs(payload); err == nil {
			t.Fatalf("accepted unsafe numeric payload %s", payload)
		}
	}
}

func TestPayloadCodecRoundTripsSupportedArguments(t *testing.T) {
	args := anchor.Arguments{
		{Name: "W", DataType: anchor.DataUint64, Value: uint64(0xE220)},
		{Name: "S", DataType: anchor.DataString, Value: "hello"},
	}
	wire, err := ArgsToPayload(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PayloadToArgs(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(args) || got[0].Value != uint64(0xE220) || got[1].Value != "hello" {
		t.Fatalf("round trip = %#v", got)
	}
}
