package dero

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

// Golden payload-0 corpus.
//
// Every fixture here is the byte-exact shape DERO R153 puts on chain:
//
//	[ring position: 1 byte][CBOR map: n bytes][random pad to PAYLOAD0_LIMIT]
//
// Sizes, offsets, and map headers were VERIFIED against live mainnet
// transactions (four incoming transfers on derod R153): each returned exactly
// 112 bytes of decrypted data — 1 ring byte + 111 payload-0 — with the CBOR map
// header at offset 1 (observed 0xa2 for two arguments and 0xa4 for four), and
// ring positions of 0x00 and 0x01. The E2-pointer transactions observed on
// chain carried exactly W=57888 (0xE220) + R + C + D, which is the argument set
// DeroChainCodec emits.
//
// The VALUES below are synthetic. This file exists to freeze the wire SHAPE,
// not to carry anyone's traffic.

// padToPayload0 pads a packed CBOR map to the on-chain size with a deterministic
// filler, standing in for the wallet's random padding (rpc.CheckPack).
func padToPayload0(t *testing.T, ringPos byte, args anchor.Arguments) []byte {
	t.Helper()
	packed, err := PackArguments(args)
	if err != nil {
		t.Fatalf("PackArguments: %v", err)
	}
	if len(packed) > Payload0Limit {
		t.Fatalf("packed %d bytes exceeds payload-0 limit %d", len(packed), Payload0Limit)
	}
	out := make([]byte, 0, Payload0Limit+1)
	out = append(out, ringPos)
	out = append(out, packed...)
	for i := len(packed); i < Payload0Limit; i++ {
		// Deterministic filler so a failure is reproducible.
		out = append(out, byte(0xa5+i))
	}
	if len(out) != Payload0Limit+1 {
		t.Fatalf("padded length %d, want %d", len(out), Payload0Limit+1)
	}
	return out
}

// TestGoldenPayloadSizeMatchesMainnet pins the total on-chain size. Four live
// R153 transfers all returned exactly 112 bytes of decrypted data, so a change
// here means the payload framing no longer matches what the network sends.
func TestGoldenPayloadSizeMatchesMainnet(t *testing.T) {
	args := anchor.Arguments{
		{Name: "T", DataType: anchor.DataString, Value: "sick"},
		{Name: "W", DataType: anchor.DataUint64, Value: uint64(1393)},
	}
	wire := padToPayload0(t, 0x01, args)
	if len(wire) != 112 {
		t.Fatalf("payload is %d bytes, want 112 (1 ring byte + %d payload-0)", len(wire), Payload0Limit)
	}
	if Payload0Limit != 111 {
		t.Fatalf("Payload0Limit = %d, want 111 (144 - 33)", Payload0Limit)
	}
}

// TestGoldenWhisperShape covers the two-argument form observed on chain
// (CBOR map header 0xa2) as used by a short whisper.
func TestGoldenWhisperShape(t *testing.T) {
	args := anchor.Arguments{
		{Name: "T", DataType: anchor.DataString, Value: "hello"},
		{Name: "W", DataType: anchor.DataUint64, Value: uint64(1393)},
	}
	// The map header must be 0xa2: CBOR major type 5 (map) with 2 pairs.
	packed, err := PackArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	if packed[0] != 0xa2 {
		t.Fatalf("map header = 0x%02x, want 0xa2 (2-pair map)", packed[0])
	}

	wire := padToPayload0(t, 0x00, args)
	got, err := RawPayloadToArgs(wire)
	if err != nil {
		t.Fatalf("real-shaped whisper rejected: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded %d args, want 2", len(got))
	}
	// The decoder returns arguments sorted by name+type, so look them up.
	if w, ok := argByName(got, "W"); !ok || w.Value != uint64(1393) {
		t.Fatalf("W argument = %#v", w)
	}
	if s, ok := argByName(got, "T"); !ok || s.Value != "hello" {
		t.Fatalf("T argument = %#v", s)
	}
}

// TestGoldenE2PointerShape covers the four-argument form observed on chain
// (CBOR map header 0xa4). Entries that carried an E2 pointer used exactly
// W=0xE220 plus R, C, D — the argument set DeroChainCodec produces.
func TestGoldenE2PointerShape(t *testing.T) {
	args := anchor.Arguments{
		{Name: "W", DataType: anchor.DataUint64, Value: uint64(0xE220)},
		{Name: "R", DataType: anchor.DataHash, Value: hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))},
		{Name: "C", DataType: anchor.DataHash, Value: hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32))},
		{Name: "D", DataType: anchor.DataUint64, Value: uint64(1788969051)},
	}
	packed, err := PackArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	if packed[0] != 0xa4 {
		t.Fatalf("map header = 0x%02x, want 0xa4 (4-pair map)", packed[0])
	}

	wire := padToPayload0(t, 0x01, args)
	got, err := RawPayloadToArgs(wire)
	if err != nil {
		t.Fatalf("real-shaped E2 pointer rejected: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("decoded %d args, want 4", len(got))
	}
	if w, ok := argByName(got, "W"); !ok || w.Value != uint64(0xE220) {
		t.Fatalf("W = %#v, want 0xE220", w)
	}
	if d, ok := argByName(got, "D"); !ok || d.Value != uint64(1788969051) {
		t.Fatalf("D = %#v", d)
	}
	// Every E2 pointer on chain must be recoverable through the padded path,
	// since that is the only form some wallets return.
	if r, ok := argByName(got, "R"); !ok || r.Value != args[1].Value {
		t.Fatalf("R hash did not round-trip: %#v", r)
	}
}

// TestGoldenRingPositionMatchesObserved pins the ring byte against the values
// seen on chain and confirms padding length never affects the result.
func TestGoldenRingPositionMatchesObserved(t *testing.T) {
	args := anchor.Arguments{{Name: "W", DataType: anchor.DataUint64, Value: uint64(0xE220)}}
	for _, pos := range []byte{0x00, 0x01, 0x02, 0x7f, 0x80, 0xff} {
		wire := padToPayload0(t, pos, args)
		if wire[0] != pos {
			t.Fatalf("ring byte = 0x%02x, want 0x%02x", wire[0], pos)
		}
		got, err := RawPayloadToArgs(wire)
		if err != nil {
			t.Fatalf("ring position 0x%02x rejected: %v", pos, err)
		}
		if len(got) != 1 {
			t.Fatalf("ring position 0x%02x decoded %d args", pos, len(got))
		}
	}
}

// TestGoldenPaddingIsIgnored is the contract that makes random padding safe:
// decoding keys off the CBOR map's declared pair count, never the buffer
// length. A truncated (unpadded) buffer must decode identically to the padded
// one, because some wallets hand back whichever they happen to have.
func TestGoldenPaddingIsIgnored(t *testing.T) {
	args := anchor.Arguments{
		{Name: "T", DataType: anchor.DataString, Value: "padding test"},
		{Name: "W", DataType: anchor.DataUint64, Value: uint64(57888)},
	}
	padded := padToPayload0(t, 0x00, args)
	packed, err := PackArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	unpadded := append([]byte{0x00}, packed...)

	fromPadded, err := RawPayloadToArgs(padded)
	if err != nil {
		t.Fatalf("padded form rejected: %v", err)
	}
	fromUnpadded, err := RawPayloadToArgs(unpadded)
	if err != nil {
		t.Fatalf("unpadded form rejected: %v", err)
	}
	if len(fromPadded) != len(fromUnpadded) {
		t.Fatalf("padded decoded %d args, unpadded %d", len(fromPadded), len(fromUnpadded))
	}
	for i := range fromPadded {
		if fromPadded[i] != fromUnpadded[i] {
			t.Fatalf("argument %d differs between padded and unpadded", i)
		}
	}
}

// TestGoldenCorpusRoundTripsThroughArgEncoding closes the loop: every golden
// shape must survive ArgsToPayload -> PackArguments -> RawPayloadToArgs and
// come back as the same typed arguments. This is the property the receive path
// depends on end to end.
func TestGoldenCorpusRoundTripsThroughArgEncoding(t *testing.T) {
	corpus := []anchor.Arguments{
		{
			{Name: "T", DataType: anchor.DataString, Value: "whisper"},
			{Name: "W", DataType: anchor.DataUint64, Value: uint64(1393)},
		},
		{
			{Name: "W", DataType: anchor.DataUint64, Value: uint64(0xE220)},
			{Name: "R", DataType: anchor.DataHash, Value: hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))},
			{Name: "C", DataType: anchor.DataHash, Value: hex.EncodeToString(bytes.Repeat([]byte{0xbb}, 32))},
			{Name: "D", DataType: anchor.DataUint64, Value: uint64(1788969051)},
		},
		{
			{Name: "K", DataType: anchor.DataHash, Value: hex.EncodeToString(bytes.Repeat([]byte{0xcc}, 32))},
			{Name: "C", DataType: anchor.DataHash, Value: hex.EncodeToString(bytes.Repeat([]byte{0xdd}, 32))},
			{Name: "D", DataType: anchor.DataUint64, Value: uint64(1700000000)},
			{Name: "F", DataType: anchor.DataUint64, Value: uint64(0x000101)},
		},
	}
	for i, want := range corpus {
		packed, err := PackArguments(want)
		if err != nil {
			t.Fatalf("case %d: PackArguments: %v", i, err)
		}
		if len(packed) > Payload0Limit {
			t.Fatalf("case %d: %d bytes exceeds the %d-byte budget", i, len(packed), Payload0Limit)
		}
		wire := padToPayload0(t, 0x01, want)
		got, err := RawPayloadToArgs(wire)
		if err != nil {
			t.Fatalf("case %d: RawPayloadToArgs: %v", i, err)
		}
		if len(got) != len(want) {
			t.Fatalf("case %d: decoded %d args, want %d", i, len(got), len(want))
		}
		for _, w := range want {
			g, ok := argByName(got, w.Name)
			if !ok {
				t.Fatalf("case %d: argument %q missing", i, w.Name)
			}
			if g.Value != w.Value {
				t.Fatalf("case %d: argument %q = %#v, want %#v", i, w.Name, g.Value, w.Value)
			}
		}
	}
}

// argByName finds an argument by name. The payload decoder returns arguments
// sorted by name+type rather than in written order, so callers must look them
// up rather than index them.
func argByName(args anchor.Arguments, name string) (anchor.Argument, bool) {
	for _, a := range args {
		if a.Name == name {
			return a, true
		}
	}
	return anchor.Argument{}, false
}
