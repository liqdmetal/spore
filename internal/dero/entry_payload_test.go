package dero

import (
	"bytes"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestEntryPayloadFallsBackToRawWhenRPCDecodeFails(t *testing.T) {
	raw := append([]byte{0}, []byte{0xa1, 0x62, 'T', 'U', 0x01}...)
	got, err := EntryPayload(Entry{
		TXID:       "tx",
		PayloadRPC: anchor.Arguments{{Name: "W", DataType: "U", Value: "not-uint"}},
		Data:       raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	args, err := PayloadToArgs(got)
	if err != nil || len(args) != 1 || args[0].Name != "T" {
		t.Fatalf("args=%#v err=%v", args, err)
	}
}

func TestEntryPayloadRejectsMalformedRaw(t *testing.T) {
	_, err := EntryPayload(Entry{TXID: "tx", Data: bytes.Repeat([]byte{0xff}, 8)})
	if err == nil {
		t.Fatal("accepted malformed raw payload")
	}
}
