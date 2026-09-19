package whisper

import (
	"encoding/base64"
	"testing"
)

// TestParseFromDataEngramBytes uses the REAL raw `data` payload that Engram
// returned for the "hello from compost" whisper (which it could not decode as
// payload_rpc due to trailing CBOR pad). Our tolerant parser must read it.
func TestParseFromDataEngramBytes(t *testing.T) {
	// Real base64 data field captured from Engram's get_transfers.
	b64 := "AaJiVFN4H2hlbGxvIGZyb20gY29tcG9zdCDigJQgcmVhZCBvaz9iV1UZBXFtWeNYWCKlZQ6cAUodzQE5eejN0flcgvOLUJVl9Nz84zMWTzFZqFmrX2Bp32uTFM1njCshnzMxMr5eZ6psWKaXL4p53Q=="
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	text, ok := ParseArgsFromData(data)
	if !ok {
		t.Fatalf("should parse whisper from raw data, got ok=false")
	}
	if text != "hello from compost \u2014 read ok?" {
		t.Fatalf("text = %q", text)
	}
}

// TestParseFromDataShort is a synthetic minimal whisper: sender byte + map
// {WU:0x571, TS:"hi"} + trailing pad.
func TestParseFromDataShort(t *testing.T) {
	data := []byte{
		0x01,           // sender pos
		0xa2,           // map(2)
		0x62, 'W', 'U', // key "WU"
		0x19, 0x05, 0x71, // uint 0x571
		0x62, 'T', 'S', // key "TS"
		0x62, 'h', 'i', // text "hi"
		0xde, 0xad, 0xbe, 0xef, // trailing pad
	}
	text, ok := ParseArgsFromData(data)
	if !ok {
		t.Fatalf("expected ok")
	}
	if text != "hi" {
		t.Fatalf("text = %q", text)
	}
}

// TestParseFromDataNonWhisper: no W marker -> not ok.
func TestParseFromDataNonWhisper(t *testing.T) {
	data := []byte{0x01, 0xa1, 0x62, 'X', 'X', 0x61, 'y'} // map{XX:"y"}
	if _, ok := ParseArgsFromData(data); ok {
		t.Fatal("should not parse non-whisper")
	}
}
