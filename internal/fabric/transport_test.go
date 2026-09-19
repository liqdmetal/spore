package fabric

// transport_test.go — the transport-agnostic proof (F4a): the Client state
// machine (register-before-drain, renewal window, one re-register + retry on
// auth refusals) runs IDENTICALLY over MemTransport as over TCP. The scripted
// relay here records every request it sees, so the assertions are about the
// client's behavior, not any socket.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// scriptedRelay is a FabricRelay with per-verb behavior hooks and a call log.
type scriptedRelay struct {
	calls  []string
	onFreg func(r *scriptedRelay, req Request) (Outcome, error)
	onFpop func(r *scriptedRelay, req Request) (Outcome, error)
	onFput func(r *scriptedRelay, req Request) (Outcome, error)
	fregN  int
}

func (r *scriptedRelay) ServeFabric(req Request) (Outcome, error) {
	r.calls = append(r.calls, req.Verb)
	switch req.Verb {
	case "freg":
		r.fregN++
		if r.onFreg != nil {
			return r.onFreg(r, req)
		}
		return Outcome{Payload: map[string]any{"token": "t", "expires": float64(time.Now().Add(time.Hour).Unix())}}, nil
	case "fput":
		if r.onFput != nil {
			return r.onFput(r, req)
		}
		return Outcome{Payload: map[string]any{"queued": true}}, nil
	case "fpop":
		if r.onFpop != nil {
			return r.onFpop(r, req)
		}
		return Outcome{Payload: map[string]any{"pointers": []any{}}}, nil
	}
	return Outcome{}, fmt.Errorf("fabric: 400 bad fabric verb")
}

func memClient(t *testing.T, relay FabricRelay) (*Client, [32]byte) {
	t.Helper()
	var seed [32]byte
	seed[0] = 0xAB
	c, err := NewClientOn(NewMemTransport(relay), seed, 3, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, seed
}

func TestClientOverMemTransportDrainsAfterRegister(t *testing.T) {
	relay := &scriptedRelay{}
	c, seed := memClient(t, relay)

	ptrs, err := c.DrainOnce(context.Background(), seed, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(ptrs) != 0 {
		t.Fatalf("expected empty drain, got %d", len(ptrs))
	}
	// The state machine's exact shape: register (the drain requires a token),
	// then pop. Nothing else.
	if strings.Join(relay.calls, ",") != "freg,fpop" {
		t.Fatalf("calls = %v, want [freg fpop]", relay.calls)
	}
	// Second tick within the renewal window: NO second freg.
	if _, err := c.DrainOnce(context.Background(), seed, time.Hour); err != nil {
		t.Fatal(err)
	}
	if strings.Join(relay.calls, ",") != "freg,fpop,fpop" {
		t.Fatalf("calls after second tick = %v, want single freg", relay.calls)
	}
}

func TestClientOverMemTransportReregistersOnAuthRefusal(t *testing.T) {
	relay := &scriptedRelay{}
	c, seed := memClient(t, relay)
	// Simulate a LEASE THE RELAY HAS EXPIRED but the client still believes
	// live: stale token, unexpired local expiry (under the client's lock —
	// the field is mutex-guarded). EnsureRegistered must therefore skip the
	// renewal, fpop must refuse, and the retry path must recover.
	c.mu.Lock()
	c.token = "stale-token"
	c.expires = time.Now().Add(time.Hour)
	c.mu.Unlock()

	// First fpop refuses with the verbatim 403 the relay sends; the client
	// must re-register and retry exactly once, then succeed. The relay
	// refuses only BEFORE the re-register lands (fregN counts freg calls;
	// after the retry's single freg it is 1).
	relay.onFpop = func(r *scriptedRelay, req Request) (Outcome, error) {
		if r.fregN < 1 {
			return Outcome{}, fmt.Errorf("fabric: 403 wrong token")
		}
		return Outcome{Payload: map[string]any{"pointers": []any{}}}, nil
	}

	if _, err := c.DrainOnce(context.Background(), seed, time.Hour); err != nil {
		t.Fatal(err)
	}
	if strings.Join(relay.calls, ",") != "fpop,freg,fpop" {
		t.Fatalf("calls = %v, want [fpop freg fpop] — one retry, not a loop", relay.calls)
	}
}

func TestMemTransportValidatesVerbsLikeTheRelay(t *testing.T) {
	relay := &scriptedRelay{}
	tr := NewMemTransport(relay)
	if _, err := tr.RoundTrip(context.Background(), Request{Verb: "put", Payload: nil}); err == nil ||
		!strings.Contains(err.Error(), "400") {
		t.Fatalf("unknown verb err = %v, want the relay's 400 discipline", err)
	}
}
