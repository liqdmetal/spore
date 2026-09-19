package ratchetwire

import (
	"bytes"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

// Golden E2-pointer framing, verified against live mainnet.
//
// Four real R153 transfers were inspected: each returned exactly 112 bytes of
// decrypted payload-0 data (1 ring byte + 111 bytes payload). Two carried an E2
// pointer and their on-chain argument set was W=57888 (0xE220) + R + C + D with
// a CBOR map header of 0xa4 — exactly what DeroChainCodec emits.
//
// These tests close the loop the receive path actually runs: DeroChainCodec
// encode -> CBOR pack -> wallet padding -> raw payload decode -> DeroChainCodec
// decode. A drift at ANY step strands every message, and the values here are
// synthetic so no real traffic is carried.

// TestGoldenDeroCodecSurvivesThePaddedPath drives a pointer through the full
// on-chain framing and back.
func TestGoldenDeroCodecSurvivesThePaddedPath(t *testing.T) {
	p := PointerPayload{
		Version:      PointerV1,
		Route:        ptr32(0x11),
		CID:          ptr32(0x22),
		BurnDeadline: 1788969051,
	}
	route, cid := p.Route, p.CID

	codec := DeroChainCodec{}
	payload, err := codec.EncodePointer(p)
	if err != nil {
		t.Fatalf("EncodePointer: %v", err)
	}
	args, err := dero.PayloadToArgs(payload)
	if err != nil {
		t.Fatalf("PayloadToArgs: %v", err)
	}

	// On-chain marker must be present, and the argument count must match the
	// 4-pair map header observed on mainnet.
	if w, ok := goldenArg(args, "W"); !ok || w.Value != uint64(0xE220) {
		t.Fatalf("on-chain marker W = %#v, want 0xE220", w)
	}
	if len(args) != 4 {
		t.Fatalf("pointer carries %d arguments, want 4 (W/R/C/D)", len(args))
	}
	packed, err := dero.PackArguments(args)
	if err != nil {
		t.Fatalf("PackArguments: %v", err)
	}
	if packed[0] != 0xa4 {
		t.Fatalf("CBOR map header = 0x%02x, want 0xa4 (4 pairs, as on mainnet)", packed[0])
	}

	// Rebuild the exact on-chain layout: [ring byte][CBOR map][pad to 111].
	wire := make([]byte, 0, dero.Payload0Limit+1)
	wire = append(wire, 0x01)
	wire = append(wire, packed...)
	for i := len(packed); i < dero.Payload0Limit; i++ {
		wire = append(wire, byte(0xa5+i))
	}
	if len(wire) != 112 {
		t.Fatalf("framed payload is %d bytes, want 112", len(wire))
	}

	// The receive path: decode the padded raw payload, re-encode, decode.
	back, err := dero.RawPayloadToArgs(wire)
	if err != nil {
		t.Fatalf("RawPayloadToArgs on the real-shaped frame: %v", err)
	}
	reencoded, err := dero.ArgsToPayload(back)
	if err != nil {
		t.Fatalf("ArgsToPayload: %v", err)
	}
	got, ok := codec.DecodePointer(reencoded)
	if !ok {
		t.Fatal("DecodePointer rejected a pointer this build just framed")
	}
	if got.Route != route || got.CID != cid || got.BurnDeadline != p.BurnDeadline {
		t.Fatalf("pointer drifted through the padded path:\n got  %#v\n want %#v", got, p)
	}
}

// TestGoldenE2PointerFitsPayload0Budget confirms a real pointer plus the ring
// byte fits the on-chain budget with room for padding, which is what makes the
// pointer form viable at all.
func TestGoldenE2PointerFitsPayload0Budget(t *testing.T) {
	p := PointerPayload{
		Version:      PointerV1,
		Route:        ptr32(0x33),
		CID:          ptr32(0x44),
		BurnDeadline: 1789054009,
	}
	payload, err := (DeroChainCodec{}).EncodePointer(p)
	if err != nil {
		t.Fatal(err)
	}
	args, err := dero.PayloadToArgs(payload)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := dero.PackArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) > dero.Payload0Limit {
		t.Fatalf("pointer packs to %d bytes, over the %d-byte payload-0 budget",
			len(packed), dero.Payload0Limit)
	}
	// Measured: the pointer packs to 89 of 111 bytes, leaving 22 bytes of
	// headroom. That is real slack — a fifth small field would fit without a
	// format change — so do not assume the budget is exhausted when extending
	// the pointer. (The live mainnet pointers observed carried the same four
	// arguments; their exact packed width depends on the deadline value, which
	// is 8 bytes of CBOR either way.)
	t.Logf("pointer packs to %d of %d bytes (%d bytes of padding)",
		len(packed), dero.Payload0Limit, dero.Payload0Limit-len(packed))
}

// TestGoldenCanonicalAndDeroCodecsAgreeOnTheSamePointer: both codecs must carry
// an identical PointerPayload, so a conversation is not broken by which carrier
// happens to be selected.
func TestGoldenCanonicalAndDeroCodecsAgreeOnTheSamePointer(t *testing.T) {
	p := PointerPayload{
		Version:      PointerV1,
		Route:        ptr32(0x55),
		CID:          ptr32(0x66),
		BurnDeadline: 1789054009,
	}
	canonical, err := (CanonicalChainCodec{}).EncodePointer(p)
	if err != nil {
		t.Fatal(err)
	}
	deroPayload, err := (DeroChainCodec{}).EncodePointer(p)
	if err != nil {
		t.Fatal(err)
	}
	// Different wires by design...
	if bytes.Equal(canonical, deroPayload) {
		t.Fatal("the two codecs produced identical wires; expected different encodings")
	}
	// ...same pointer.
	gotCanonical, ok := (CanonicalChainCodec{}).DecodePointer(canonical)
	if !ok {
		t.Fatal("canonical round-trip failed")
	}
	gotDero, ok := (DeroChainCodec{}).DecodePointer(deroPayload)
	if !ok {
		t.Fatal("DERO round-trip failed")
	}
	if gotCanonical != gotDero || gotDero.Route != p.Route || gotDero.CID != p.CID {
		t.Fatalf("codecs disagree:\n canonical %#v\n dero      %#v", gotCanonical, gotDero)
	}
}

// ptr32 builds a [32]byte filled with b.
func ptr32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// goldenArg looks an argument up by name (the payload decoder returns
// arguments sorted by name+type, not in written order).
func goldenArg(args anchor.Arguments, name string) (anchor.Argument, bool) {
	for _, a := range args {
		if a.Name == name {
			return a, true
		}
	}
	return anchor.Argument{}, false
}
