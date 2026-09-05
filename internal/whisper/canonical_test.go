package whisper

import "testing"

func TestCanonicalTextRoundTrip(t *testing.T) {
	codec := CanonicalCodec{}
	msg := "hello from the mycorrhizal network"
	p, err := codec.EncodeText(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := codec.DecodeText(p)
	if !ok || got != msg {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestCanonicalPointerRoundTrip(t *testing.T) {
	codec := CanonicalCodec{}
	eph := [32]byte{0xab}
	cid := [32]byte{0xcd}
	p, err := codec.EncodePointer(eph, cid)
	if err != nil {
		t.Fatal(err)
	}
	ge, gc, ok := codec.DecodePointer(p)
	if !ok || ge != eph || gc != cid {
		t.Fatalf("pointer mismatch ok=%v", ok)
	}
	// A pointer should NOT decode as text.
	if _, isText := codec.DecodeText(p); isText {
		t.Fatal("pointer decoded as text")
	}
}

func TestCanonicalMalformed(t *testing.T) {
	c := CanonicalCodec{}
	short := []byte{0x01, 0x00}
	if _, ok := c.DecodeText(short); ok {
		t.Fatal("short payload should fail")
	}
	// kind 0x99 unknown
	bad := []byte{0x99, 0x00, 0x00}
	if _, _, _, _, ok := DecodeCanonical(bad); ok {
		t.Fatal("unknown kind should fail")
	}
}
