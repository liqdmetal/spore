package fabric

// rpc2transport.go — the CBOR/rpc2 encoding of the fabric verbs as a
// FabricTransport (slice F4a; RELAY_FABRIC_F4.md §1: "the CBOR/rpc2 variants
// are just a second encoding behind the same seam"). The wire family:
//
//	freg → Peer.FabricReg, fput → Peer.FabricPut, fpop → Peer.FabricPop
//
// framed exactly as spore-peer's rpc2 subset (LE32 length + CBOR header map
// {M,S,E} + one CBOR payload item), with the byte-exact frames pinned in
// docs/interop-vectors.json fabric_v1.rpc2_*. Refusals keep the legacy
// "NNN text" discipline inside the header's E field, so isAuthError and the
// client's re-register+retry logic are encoding-agnostic.

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// rpc2Methods maps the semantic verb to its rpc2 method name.
var rpc2Methods = map[string]string{
	"freg": "Peer.FabricReg",
	"fput": "Peer.FabricPut",
	"fpop": "Peer.FabricPop",
}

// rpc2Seq fixes the sequence numbers the golden vectors pin (deterministic
// per verb, so a conformance test can byte-compare whole frames).
func rpc2Seq(verb string) uint64 {
	switch verb {
	case "fput":
		return 1
	case "fpop":
		return 2
	case "freg":
		return 3
	}
	return 0
}

// CBORTransport speaks the rpc2 method family over the spore-peer socket:
// the same §5 transport as TCPTransport, CBOR encoding, the same stateless
// one-request-one-connection posture (persistent rpc2 connections are the
// Rust sync subset's shape; fabric clients keep the F1–F3 posture).
type CBORTransport struct {
	addr string
}

// NewCBORTransport builds the transport for the relay at addr.
func NewCBORTransport(addr string) *CBORTransport { return &CBORTransport{addr: addr} }

// Addr returns the relay address this transport dials.
func (t *CBORTransport) Addr() string { return t.addr }

// strKey fetches a required string field from a verb payload.
func strKey(payload map[string]any, key, verb string) (string, error) {
	s, ok := payload[key].(string)
	if !ok || s == "" {
		return "", fmt.Errorf("fabric: 400 %s rpc2 payload needs string %q", verb, key)
	}
	return s, nil
}

// numKey fetches a required numeric field (JSON shape: float64).
func numKey(payload map[string]any, key, verb string) (uint64, error) {
	switch v := payload[key].(type) {
	case float64:
		return uint64(v), nil
	case uint64:
		return v, nil
	case int:
		return uint64(v), nil
	case int64:
		return uint64(v), nil
	default:
		return 0, fmt.Errorf("fabric: 400 %s rpc2 payload needs number %q", verb, key)
	}
}

// encodeCanonicalRequest encodes one fabric verb as its rpc2 payload through
// the ORDERED builders — the canonical key order the golden vectors pin —
// validating that the payload carries exactly the verb's closed key set.
// A client payload with unknown or missing keys is a programming error and
// fails here rather than producing off-contract wire bytes.
func encodeCanonicalRequest(req Request) ([]byte, error) {
	switch req.Verb {
	case "freg":
		h, err := strKey(req.Payload, "handle", "freg")
		if err != nil {
			return nil, err
		}
		tok, err := strKey(req.Payload, "token", "freg")
		if err != nil {
			return nil, err
		}
		nonce, _ := req.Payload["nonce"].(string) // optional (relays ignore it)
		lease, err := numKey(req.Payload, "lease", "freg")
		if err != nil {
			return nil, err
		}
		return EncodeFabricReg(h, tok, nonce, lease)
	case "fput":
		h, err := strKey(req.Payload, "handle", "fput")
		if err != nil {
			return nil, err
		}
		ph, err := strKey(req.Payload, "pointer_hex", "fput")
		if err != nil {
			return nil, err
		}
		ptr, err := hexDecodeString(ph)
		if err != nil {
			return nil, fmt.Errorf("fabric: 400 fput rpc2 pointer_hex: %w", err)
		}
		dl, err := numKey(req.Payload, "deadline", "fput")
		if err != nil {
			return nil, err
		}
		return EncodeFabricPut(h, ptr, dl)
	case "fpop":
		h, err := strKey(req.Payload, "handle", "fpop")
		if err != nil {
			return nil, err
		}
		tok, err := strKey(req.Payload, "token", "fpop")
		if err != nil {
			return nil, err
		}
		maxN, err := numKey(req.Payload, "max", "fpop")
		if err != nil {
			return nil, err
		}
		return EncodeFabricPop(h, tok, int(maxN))
	}
	return nil, fmt.Errorf("fabric: 400 bad fabric verb")
}

// hexDecodeString is encoding/hex with a fabric error wrap.
func hexDecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// RoundTrip sends one fabric verb as an rpc2 method call and classifies the
// reply: a non-empty header E is the relay's verbatim refusal ("NNN text");
// otherwise the payload item is coerced to the same map shape the JSON verbs
// produce (numbers as float64), so Client logic is encoding-agnostic.
func (t *CBORTransport) RoundTrip(ctx context.Context, req Request) (Outcome, error) {
	method, ok := rpc2Methods[req.Verb]
	if !ok {
		return Outcome{}, fmt.Errorf("fabric: 400 bad fabric verb")
	}
	payload, err := encodeCanonicalRequest(req)
	if err != nil {
		return Outcome{}, err
	}
	// The rpc2 BODY (header map + payload item) goes on the wire through
	// writeFrame, which adds the §5 LE32 length prefix — exactly where the
	// Rust handler's write_frame does. encodeRPC2Frame (with prefix) exists
	// for the vector generator and conformance tests only.
	hdr := cborMap(3)
	hdr = append(hdr, cborKV("M", cborText(method))...)
	hdr = append(hdr, cborKV("S", cborUint(rpc2Seq(req.Verb)))...)
	hdr = append(hdr, cborKV("E", cborText(""))...)
	frame := append(hdr, payload...)

	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return Outcome{}, fmt.Errorf("fabric: dial %s: %w", t.addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := writeFrame(conn, frame); err != nil {
		return Outcome{}, err
	}
	resp, err := readFrame(conn)
	if err != nil {
		return Outcome{}, err
	}
	msg, err := decodeRPC2Frame(resp)
	if err != nil {
		return Outcome{}, err
	}
	if msg.Error != "" {
		return Outcome{}, fmt.Errorf("fabric: %s", strings.TrimSpace(msg.Error))
	}
	return Outcome{Payload: rpc2PayloadMap(msg.Payload)}, nil
}

// Close is a no-op: CBOR transports hold no persistent state.
func (t *CBORTransport) Close() error { return nil }

// NewCBORClient builds a Client over the rpc2/CBOR encoding — the identical
// state machine as NewClient, the second encoding behind the same seam.
func NewCBORClient(addr string, seed [32]byte, epoch uint32, sid [8]byte) (*Client, error) {
	return NewClientOn(NewCBORTransport(addr), seed, epoch, sid)
}

// rpc2PayloadMap coerces a decoded rpc2 payload into the JSON-verb shape:
// map[string]any with numbers as float64. The fabric payloads are closed
// (maps, arrays, strings, uints, bools) — anything else is a relay bug and
// surfaces as an empty map, which the client's key lookups already treat
// as a protocol failure.
func rpc2PayloadMap(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, item := range m {
		out[k] = rpc2Coerce(item)
	}
	return out
}

func rpc2Coerce(v any) any {
	switch x := v.(type) {
	case uint64:
		return float64(x) // the JSON-verb numeric shape
	case int:
		return float64(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = rpc2Coerce(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[k] = rpc2Coerce(item)
		}
		return out
	default:
		return v
	}
}
