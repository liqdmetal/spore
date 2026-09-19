package fabric

// transport.go — the FabricTransport seam (slice F4a; docs/RELAY_FABRIC_F4.md
// §1). The client state machine (lease renewal, re-register-on-403, drain
// batching) is expressed over ONE interface; TCP and in-memory are the first
// two implementations, and the F4d Iroh sidecar plugs in behind the same
// seam. The contract any implementation must honor:
//
//   - RoundTrip carries EXACTLY the legacy verb semantics — same "NNN text"
//     refusal discipline (400/403/404/410/413/429/501/503), same ok payload
//     shapes — and adds nothing: no caching, no retry, no reordering across
//     handles, no interpretation of the pointer or token bytes.
//   - One logical request in, one outcome out. No pipelining.
//
// An implementation that caches, retries differently, or reorders is wrong
// by definition (the seam's doc contract in RELAY_FABRIC_F4.md).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// Request is one fabric verb: the semantic payload, transport-agnostic.
// Verb is "freg" | "fput" | "fpop"; Payload uses the legacy JSON keys
// (handle/token/nonce/lease, handle/pointer_hex/deadline, handle/token/max).
type Request struct {
	Verb    string
	Payload map[string]any
}

// Outcome is one relay response: the parsed ok payload. Refusals surface as
// an error carrying the relay's verbatim status string ("NNN text").
type Outcome struct {
	Payload map[string]any
}

// FabricTransport moves one fabric request to a relay and returns its
// outcome. See the package contract above — the interface is deliberately
// narrow: anything a transport invents beyond RoundTrip is a spec violation.
type FabricTransport interface {
	RoundTrip(ctx context.Context, req Request) (Outcome, error)
	ioCloser
}

// ioCloser mirrors io.Closer locally so the doc comment above stays the only
// place the contract is stated (embedding io.Closer reads fine too; a named
// local keeps gofmt-stable method sets for the two implementations below).
type ioCloser interface {
	Close() error
}

// classifyReply is the shared response classifier (the §8 wire discipline:
// 0x00 + JSON payload on success, 0x01 + "NNN text" refusal). Both the TCP
// transport and the Go-side smoke harness use it, so a reply's meaning never
// depends on which transport carried it.
func classifyReply(resp []byte) (Outcome, error) {
	if len(resp) == 0 {
		return Outcome{}, fmt.Errorf("fabric: empty reply")
	}
	if resp[0] != 0x00 {
		return Outcome{}, fmt.Errorf("fabric: %s", strings.TrimSpace(string(resp[1:])))
	}
	out := map[string]any{}
	if err := json.Unmarshal(resp[1:], &out); err != nil {
		return Outcome{}, fmt.Errorf("fabric: bad ok payload: %w", err)
	}
	return Outcome{Payload: out}, nil
}

// --- TCP transport (the F1–F3 wire path, extracted verbatim) ----------------

// TCPTransport speaks the legacy JSON verbs over a spore-peer socket: one
// fresh §5-framed connection per request (the shipped shape — stateless
// requests, server closes after each reply; the rpc2 method family rides the
// same socket separately). Encoding: legacy JSON, byte-identical to what
// Client.verb has always put on the wire.
type TCPTransport struct {
	addr string
}

// NewTCPTransport builds the transport for the relay at addr.
func NewTCPTransport(addr string) *TCPTransport { return &TCPTransport{addr: addr} }

// Addr returns the relay address this transport dials.
func (t *TCPTransport) Addr() string { return t.addr }

// RoundTrip sends one legacy JSON verb and classifies the reply.
func (t *TCPTransport) RoundTrip(ctx context.Context, req Request) (Outcome, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return Outcome{}, fmt.Errorf("fabric: dial %s: %w", t.addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	wire := map[string]any{"verb": req.Verb}
	for k, v := range req.Payload {
		wire[k] = v
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return Outcome{}, err
	}
	if err := writeFrame(conn, payload); err != nil {
		return Outcome{}, err
	}
	resp, err := readFrame(conn)
	if err != nil {
		return Outcome{}, err
	}
	return classifyReply(resp)
}

// Close is a no-op: TCP transports hold no persistent state.
func (t *TCPTransport) Close() error { return nil }

// --- in-memory transport (the transport-agnostic proof) ---------------------

// FabricRelay is the SERVER half of the seam, in-process: anything that can
// answer a fabric Request by the same semantics a relay serves on the socket.
// The Go smoke harness's JSON-verb server satisfies this via serveFabricReq;
// tests stub it directly. MemTransport routes by relay name — a Client built
// with NewClientOn("mem-relay") finds it here without any socket.
type FabricRelay interface {
	ServeFabric(req Request) (Outcome, error)
}

// MemTransport is the in-memory FabricTransport: RoundTrip dispatches
// straight to the mounted FabricRelay. It exists to prove the CLIENT state
// machine (renewal windows, retry-on-403, drain batching, the drain-union
// interplay) is transport-agnostic — the same property internal/rendezvous's
// MemTransport proves for the body path. No sockets, no ports, fully hermetic.
// One transport instance is scoped to one relay, exactly like TCPTransport is
// scoped to one addr; clients pick a transport the same way they pick an addr.
type MemTransport struct {
	relay FabricRelay
}

// NewMemTransport builds an in-memory transport bound to one relay.
func NewMemTransport(relay FabricRelay) *MemTransport { return &MemTransport{relay: relay} }

// RoundTrip dispatches to the mounted relay. The verb set is validated
// exactly as the relay validates it (unknown verb → 400-shaped error), so a
// client bug surfaces identically on both transports.
func (m *MemTransport) RoundTrip(_ context.Context, req Request) (Outcome, error) {
	switch req.Verb {
	case "freg", "fput", "fpop":
	default:
		return Outcome{}, fmt.Errorf("fabric: 400 bad fabric verb")
	}
	if m.relay == nil {
		return Outcome{}, fmt.Errorf("fabric: no relay mounted")
	}
	return m.relay.ServeFabric(req)
}

// Close is a no-op: the mounted relay outlives the transport.
func (m *MemTransport) Close() error { return nil }
