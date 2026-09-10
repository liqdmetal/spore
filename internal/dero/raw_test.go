package dero

import (
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestRawPayloadToArgs(t *testing.T) {
	// sender-position byte + CBOR map: {"TU": 1, "SS": "Whisper"}.
	valid := []byte{0, 0xa2, 0x62, 'T', 'U', 0x01, 0x62, 'S', 'S', 0x67, 'W', 'h', 'i', 's', 'p', 'e', 'r'}
	args, err := RawPayloadToArgs(valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[0].Name != "T" || args[0].DataType != anchor.DataUint64 || args[1].Name != "S" || args[1].Value != "Whisper" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestRawPayloadRejectsMalformed(t *testing.T) {
	for _, data := range [][]byte{
		{0},
		{0, 0xa1, 0x61, 'W'},
		{0, 0xa1, 0x61, 'W', 0x01},
		{0, 0xa1, 0x61, 'W', 0x61, 'x'},
	} {
		if _, err := RawPayloadToArgs(data); err == nil {
			t.Fatalf("accepted malformed payload %x", data)
		}
	}
}
