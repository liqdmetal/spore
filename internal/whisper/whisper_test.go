package whisper

import (
	"strings"
	"testing"

	"github.com/liqdmetal/mycelium/internal/anchor"
)

func TestRoundTrip(t *testing.T) {
	text := "meet at the usual place"
	args, err := BuildArgs(text)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ParseArgs(args)
	if !ok {
		t.Fatal("should parse as whisper")
	}
	if got != text {
		t.Fatalf("roundtrip = %q, want %q", got, text)
	}
}

func TestMaxLengthBoundary(t *testing.T) {
	ok, err := BuildArgs(strings.Repeat("a", MaxTextLen))
	if err != nil {
		t.Fatal(err)
	}
	if len(ok) != 2 {
		t.Fatalf("want 2 args, got %d", len(ok))
	}
	if _, err := BuildArgs(strings.Repeat("a", MaxTextLen+1)); err == nil {
		t.Fatal("expected too-long error")
	}
}

func TestNonWhisperSkipped(t *testing.T) {
	// A compost anchor (K/C/D/F) must NOT parse as a whisper.
	a := &anchor.Anchor{Version: anchor.Version, Kind: anchor.KindMessage, BurnDeadline: 123}
	_, ok := ParseArgs(a.ToArguments())
	if ok {
		t.Fatal("compost anchor should not parse as whisper")
	}
	// Empty / nil args also not a whisper.
	if _, ok := ParseArgs(nil); ok {
		t.Fatal("nil should not parse")
	}
}

func TestUnicodeAndWhitespace(t *testing.T) {
	text := "bring the thing 🔒 meeting 3pm"
	args, err := BuildArgs(text)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ParseArgs(args)
	if !ok || got != text {
		t.Fatalf("unicode roundtrip failed: %q ok=%v", got, ok)
	}
}
