package anchor

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

func TestRoundTripViaArguments(t *testing.T) {
	a := &Anchor{
		Version:      Version,
		Kind:         KindMessage,
		BurnDeadline: 1_900_000_000,
		Flags:        FlagAckRequested,
	}
	copy(a.EphemeralPub[:], bytes.Repeat([]byte{0xAB}, 32))
	copy(a.CID[:], bytes.Repeat([]byte{0xCD}, 32))

	args := a.ToArguments()
	b, err := FromArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != a.Version || b.Kind != a.Kind || b.BurnDeadline != a.BurnDeadline || b.Flags != a.Flags {
		t.Fatal("scalar fields mismatch")
	}
	if b.EphemeralPub != a.EphemeralPub || b.CID != a.CID {
		t.Fatal("array fields mismatch")
	}
}

// TestArgumentCountAndTypes pins the wire layout: 4 args, 2 hash + 2 uint64.
func TestArgumentCountAndTypes(t *testing.T) {
	a := &Anchor{Version: Version, Kind: KindMessage}
	args := a.ToArguments()
	if len(args) != 4 {
		t.Fatalf("arg count = %d, want 4", len(args))
	}
	want := map[string]string{"K": DataHash, "C": DataHash, "D": DataUint64, "F": DataUint64}
	for _, arg := range args {
		if want[arg.Name] != arg.DataType {
			t.Fatalf("arg %q type %q, want %q", arg.Name, arg.DataType, want[arg.Name])
		}
	}
}

// TestHashHexCrossing verifies the hash values are 64-char hex (the exact
// form the wallet RPC uses for crypto.Hash across JSON).
func TestHashHexCrossing(t *testing.T) {
	a := &Anchor{Version: Version, Kind: KindMessage}
	args := a.ToArguments()
	for _, arg := range args {
		if arg.DataType != DataHash {
			continue
		}
		s, ok := arg.Value.(string)
		if !ok {
			t.Fatalf("hash value type %T, want string", arg.Value)
		}
		if len(s) != 64 {
			t.Fatalf("hash value len %d, want 64", len(s))
		}
		if _, err := hex.DecodeString(s); err != nil {
			t.Fatalf("hash value not hex: %v", err)
		}
	}
}

func TestFromArgumentsMissingFields(t *testing.T) {
	if _, err := FromArguments(Arguments{{Name: "D", DataType: DataUint64, Value: uint64(1)}}); err == nil {
		t.Fatal("expected missing-field error")
	}
	args := (&Anchor{Version: Version, Kind: KindMessage}).ToArguments()
	filtered := args[:0]
	for _, arg := range args {
		if arg.Name != "D" {
			filtered = append(filtered, arg)
		}
	}
	if _, err := FromArguments(filtered); err == nil {
		t.Fatal("expected missing D-field error")
	}
}

func TestFromArgumentsRejectsNonIntegralNumbers(t *testing.T) {
	args := (&Anchor{Version: Version, Kind: KindMessage}).ToArguments()
	for i := range args {
		if args[i].Name == "D" {
			args[i].Value = float64(1.5)
		}
	}
	if _, err := FromArguments(args); err == nil {
		t.Fatal("expected fractional uint rejection")
	}
}

func TestFromArgumentsRejectsTrailingDigits(t *testing.T) {
	args := (&Anchor{Version: Version, Kind: KindMessage}).ToArguments()
	for i := range args {
		if args[i].Name == "D" {
			args[i].Value = "123junk"
		}
	}
	if _, err := FromArguments(args); err == nil {
		t.Fatal("expected malformed uint rejection")
	}
}

func TestFromArgumentsBadVersion(t *testing.T) {
	args := (&Anchor{Version: Version, Kind: KindMessage}).ToArguments()
	// corrupt the meta (F) field to carry version 9
	for i := range args {
		if args[i].Name == "F" {
			args[i].Value = uint64(9 | (uint64(KindMessage) << 8))
		}
	}
	if _, err := FromArguments(args); err == nil {
		t.Fatal("expected version error")
	}
}

func TestFromArgumentsHashAsHexString(t *testing.T) {
	// Simulate the shape get_transfers returns: hash values as hex strings,
	// uint64 values as JSON numbers (float64 after a plain unmarshal).
	args := Arguments{
		{Name: "K", DataType: DataHash, Value: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
		{Name: "C", DataType: DataHash, Value: "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"},
		{Name: "D", DataType: DataUint64, Value: float64(1234567890)},
		{Name: "F", DataType: DataUint64, Value: float64(uint64(Version) | uint64(KindMessage)<<8)},
	}
	a, err := FromArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	if a.BurnDeadline != 1234567890 {
		t.Fatalf("deadline = %d", a.BurnDeadline)
	}
	if a.Kind != KindMessage {
		t.Fatalf("kind = %d", a.Kind)
	}
}

func TestExpired(t *testing.T) {
	a := &Anchor{BurnDeadline: uint64(time.Now().Add(-time.Second).Unix())}
	if !a.Expired(time.Now()) {
		t.Fatal("expected expired")
	}
	a.BurnDeadline = uint64(time.Now().Add(time.Hour).Unix())
	if a.Expired(time.Now()) {
		t.Fatal("expected not expired")
	}
}
