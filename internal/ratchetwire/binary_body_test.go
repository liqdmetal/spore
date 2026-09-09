package ratchetwire

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// TestBinaryBodyRoundTripsByteExact answers a concrete product question: can
// spore carry an arbitrary FILE (PDF, tarball, image) — a "private file drop" —
// or only text?
//
// The E2 path stores the ciphertext body in a BodyStore and puts only a
// ~74-byte pointer on the carrier, so size is bounded by the body store, not by
// the chain. What has to be PROVEN is that bytes come back exactly: no UTF-8
// coercion, no NUL truncation, no CRLF translation, no size-dependent chunking
// bug.
func TestBinaryBodyRoundTripsByteExact(t *testing.T) {
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	rnd := func(n int) []byte {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return b
	}

	cases := []struct {
		name string
		body []byte
	}{
		{"all 256 byte values", allBytes},
		{"NUL and invalid UTF-8", []byte{0x00, 0x00, 0xff, 0xfe, 0x00, 0x80, 0xc0, 0x00}},
		{"CRLF/LF mix must not translate", []byte("a\r\nb\nc\r\n\x00")},
		{"PDF-like header", append([]byte("%PDF-1.7\n\x00\x01\x02"), 0xff, 0x00, 0x0a)},
		{"empty body", []byte{}},
		{"1 byte", []byte{0x00}},
		{"64 KiB random", rnd(64 << 10)},
		{"1 MiB random", rnd(1 << 20)},
		{"4 MiB random (newsletter attachment)", rnd(4 << 20)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			st := newAdversarialBodyStore()
			bundle, aliceID, bobID, opk := adversarialFixture(t)
			key := filled(19)

			as, err := NewFileStateStore(t.TempDir(), key)
			if err != nil {
				t.Fatal(err)
			}
			bs, err := NewFileStateStore(t.TempDir(), key)
			if err != nil {
				t.Fatal(err)
			}
			alice, err := NewDurableEndpoint(st, as, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			bob, err := NewDurableEndpoint(st, bs, time.Now())
			if err != nil {
				t.Fatal(err)
			}

			ptr, _, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), tc.body, cliDeadline(24*time.Hour))
			if err != nil {
				t.Fatalf("SendFirst(%d bytes): %v", len(tc.body), err)
			}
			frame, err := FetchFrame(st, ptr, time.Now())
			if err != nil {
				t.Fatalf("FetchFrame(%d bytes): %v", len(tc.body), err)
			}
			raw, err := GetBody(st, ptr, time.Now())
			if err != nil {
				t.Fatalf("GetBody(%d bytes): %v", len(tc.body), err)
			}
			got, err := bob.ReceiveFirst(bobID, filled(3), opk, frame, raw)
			if err != nil {
				t.Fatalf("ReceiveFirst(%d bytes): %v", len(tc.body), err)
			}
			if !bytes.Equal(got, tc.body) {
				t.Fatalf("NOT byte-exact: got %d bytes want %d, first diff at index %s",
					len(got), len(tc.body), diffAt(got, tc.body))
			}
		})
	}
}

func diffAt(a, b []byte) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return fmt.Sprintf("%d (%#x vs %#x)", i, a[i], b[i])
		}
	}
	if len(a) != len(b) {
		return fmt.Sprintf("length only (%d vs %d)", len(a), len(b))
	}
	return "none"
}
