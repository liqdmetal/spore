package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/mailbox"
)

// liveCheckNames is the contract: every self-test that must exist. Renaming or
// dropping one silently weakens the guard, so this test pins the set.
var liveCheckNames = []string{
	"addr-mainnet",
	"addr-reject",
	"payload-0",
	"ring-byte",
	"e2-pointer",
	"ratchet-echo",
	"mailbox-put",
}

// TestLiveDoctorChecksAllPass is the regression gate. It runs the same
// known-answer self-tests `spore doctor --live` runs and requires every one to
// pass, so a corrupted constant, a wrong field modulus, or an over-eager input
// guard fails in CI rather than on the wire.
func TestLiveDoctorChecksAllPass(t *testing.T) {
	checks := runLiveDoctorChecks(doctorLiveOpts{})
	got := map[string]doctorCheck{}
	for _, c := range checks {
		got[c.Name] = c
	}
	for _, name := range liveCheckNames {
		c, ok := got[name]
		if !ok {
			t.Fatalf("self-test %q is missing", name)
		}
		if !c.OK {
			t.Errorf("self-test %q FAILED: %s", name, c.Note)
		}
	}
	// mailbox-put must be a skip, not a silent pass, when no store is given.
	if note := got["mailbox-put"].Note; !strings.Contains(note, "skipped") {
		t.Errorf("mailbox-put without -store should report a skip, got %q", note)
	}
}

// TestLiveDoctorDetectsUnreachableStore proves mailbox-put actually exercises
// the network instead of reporting success unconditionally: an unreachable
// store must fail the check.
func TestLiveDoctorDetectsUnreachableStore(t *testing.T) {
	// 127.0.0.1 on a port nothing listens on: connection refused, fast.
	checks := runLiveDoctorChecks(doctorLiveOpts{
		Store:   "http://127.0.0.1:1/u/probe",
		Timeout: 2 * time.Second,
	})
	for _, c := range checks {
		if c.Name != "mailbox-put" {
			continue
		}
		if c.OK {
			t.Fatalf("mailbox-put passed against an unreachable store: %s", c.Note)
		}
		return
	}
	t.Fatal("mailbox-put check missing")
}

// TestLiveDoctorStoreRoundTripAgainstRealHandler runs mailbox-put end to end
// against the real mailbox HTTP handler, so the check is proven to work when a
// store is actually reachable rather than only proven to fail when it is not.
func TestLiveDoctorStoreRoundTripAgainstRealHandler(t *testing.T) {
	m, err := mailbox.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	checks := runLiveDoctorChecks(doctorLiveOpts{Store: srv.URL, Timeout: 5 * time.Second})
	for _, c := range checks {
		if c.Name != "mailbox-put" {
			continue
		}
		if !c.OK {
			t.Fatalf("store round-trip failed against a live handler: %s", c.Note)
		}
		return
	}
	t.Fatal("mailbox-put check missing")
}

// TestPaddedPayload0MatchesDeroLayout pins the reconstructed payload against
// DERO's actual byte layout, because a wrong offset here would make every
// payload-0 self-test vacuous.
//
//	[ring position: 1 byte] [CBOR map: n] [random pad to PAYLOAD0_LIMIT]
func TestPaddedPayload0MatchesDeroLayout(t *testing.T) {
	args := anchor.Arguments{
		{Name: "K", DataType: anchor.DataHash, Value: randHex32()},
		{Name: "D", DataType: anchor.DataUint64, Value: uint64(1790000000)},
	}
	wire, err := paddedPayload0(0x7f, args)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != dero.Payload0Limit+1 {
		t.Fatalf("payload length %d, want %d (1 ring byte + %d data)",
			len(wire), dero.Payload0Limit+1, dero.Payload0Limit)
	}
	if wire[0] != 0x7f {
		t.Fatalf("ring byte = 0x%02x, want 0x7f", wire[0])
	}
	// The CBOR map must begin at offset 1 and occupy exactly the packed region.
	packed, err := dero.PackArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	if got := wire[1 : 1+len(packed)]; string(got) != string(packed) {
		t.Fatal("CBOR map is not at offset 1 / not byte-identical to PackArguments output")
	}
	// And it must decode back to what produced it. Arguments come back sorted
	// by name+type, so look them up rather than indexing.
	back, err := dero.RawPayloadToArgs(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(args) {
		t.Fatalf("decoded %d args, want %d", len(back), len(args))
	}
	if d, ok := argNamed(back, "D"); !ok || d.Value != uint64(1790000000) {
		t.Fatalf("uint argument round-trip = %#v", back)
	}
	if k, ok := argNamed(back, "K"); !ok || k.Value != args[0].Value {
		t.Fatalf("hash argument round-trip = %#v", back)
	}
}

// TestPaddedPayload0ToleratesPaddingLengths confirms the decoder keys off the
// CBOR map's declared count, not the buffer length, which is what makes random
// padding safe.
func TestPaddedPayload0ToleratesPaddingLengths(t *testing.T) {
	args := anchor.Arguments{{Name: "T", DataType: anchor.DataString, Value: "hello"}}
	wire, err := paddedPayload0(0, args)
	if err != nil {
		t.Fatal(err)
	}
	// Truncate the trailing pad: the map is complete, so decoding must still
	// succeed. This mirrors a wallet that returns an unpadded buffer.
	packed, err := dero.PackArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	unpadded := append([]byte{0}, packed...)
	got, err := dero.RawPayloadToArgs(unpadded)
	if err != nil {
		t.Fatalf("unpadded payload rejected: %v", err)
	}
	if len(got) != 1 || got[0].Value != "hello" {
		t.Fatalf("unpadded decode = %#v", got)
	}
	// And the fully padded form decodes to the same thing.
	gotPadded, err := dero.RawPayloadToArgs(wire)
	if err != nil {
		t.Fatalf("padded payload rejected: %v", err)
	}
	if len(gotPadded) != len(got) {
		t.Fatalf("padded %d args vs unpadded %d", len(gotPadded), len(got))
	}
}
