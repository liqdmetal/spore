package dero

import (
	"bytes"
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

func TestRawPayloadAcceptsEveryRingPosition(t *testing.T) {
	validMap := []byte{0xa1, 0x62, 'T', 'U', 0x01}
	for pos := 0; pos <= 0xff; pos++ {
		data := append([]byte{byte(pos)}, validMap...)
		args, err := RawPayloadToArgs(data)
		if err != nil {
			t.Fatalf("ring position %d rejected: %v", pos, err)
		}
		if len(args) != 1 || args[0].Name != "T" {
			t.Fatalf("ring position %d: args=%#v", pos, args)
		}
	}
}

func TestRawPayloadAcceptsPaddedData(t *testing.T) {
	data := append([]byte{0}, []byte{0xa1, 0x62, 'T', 'U', 0x01}...)
	data = append(data, bytes.Repeat([]byte{0xaa}, 100)...)
	args, err := RawPayloadToArgs(data)
	if err != nil || len(args) != 1 || args[0].Name != "T" {
		t.Fatalf("padded raw payload: args=%#v err=%v", args, err)
	}
}

func TestRawPayloadRejectsOversizedKey(t *testing.T) {
	key := append([]byte{0x78, byte(maxPayloadName + 2)}, bytes.Repeat([]byte{'X'}, maxPayloadName+2)...)
	data := append([]byte{0, 0xa1}, key...)
	data = append(data, 0x01)
	if _, err := RawPayloadToArgs(data); err == nil {
		t.Fatal("accepted oversized raw key")
	}
}
