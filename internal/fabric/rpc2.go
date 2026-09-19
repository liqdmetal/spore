package fabric

// rpc2.go — the CBOR/rpc2 encoding of the fabric verbs (slice F4a, F4d's
// "CBOR method variants" landed early). The legacy JSON verbs keep their
// byte-exact framing; this file adds the rpc2 family over the SAME §5
// transport (LE32 length prefix), mirroring spore-peer's p2p::cbor module:
//
//	frame    = LE32(len) || header || payload?
//	header   = CBOR map { "M": method, "S": seq, "E": error }  (always 3 pairs)
//	payload  = one CBOR item (map for fabric requests/responses)
//
// Semantics are the legacy verbs verbatim — same handle normalization, same
// token checks, same caps; only the encoding differs. The byte-exact frames
// are pinned in docs/interop-vectors.json fabric_v1.rpc2_*, generated from
// the same construction the Rust codec uses (text keys, big-endian length
// heads, no indefinite lengths, reserved infos rejected).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// CBOR major types used by the rpc2 subset.
const (
	cborMajorUint   byte = 0
	cborMajorNeg         = 1
	cborMajorBytes       = 2
	cborMajorText        = 3
	cborMajorArray       = 4
	cborMajorMap         = 5
	cborMajorSimple      = 7
)

// cborHead emits one CBOR type/length head (RFC 8949; the exact encoder
// p2p::cbor::head mirrors — shortest form only, no indefinite lengths).
func cborHead(major byte, n uint64) []byte {
	var out []byte
	switch {
	case n < 24:
		out = []byte{major<<5 | byte(n)}
	case n <= 0xff:
		out = []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		out = []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	case n <= 0xffff_ffff:
		out = []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		out = []byte{major<<5 | 27}
		for i := 7; i >= 0; i-- {
			out = append(out, byte(n>>(8*i)))
		}
	}
	return out
}

func cborText(s string) []byte { return append(cborHead(cborMajorText, uint64(len(s))), s...) }
func cborUint(v uint64) []byte { return cborHead(cborMajorUint, v) }
func cborBool(b bool) []byte { // simple values: true = 0xf5, false = 0xf4
	if b {
		return []byte{cborMajorSimple<<5 | 21}
	}
	return []byte{cborMajorSimple<<5 | 20}
}
func cborKV(k string, v []byte) []byte { return append(cborText(k), v...) }
func cborMap(n int) []byte             { return cborHead(cborMajorMap, uint64(n)) }
func cborArray(n int) []byte           { return cborHead(cborMajorArray, uint64(n)) }

// encodeRPC2Frame builds one rpc2 frame: LE32 length + header map + optional
// payload item (nil payload = response/error style, matching the Rust
// error_response which sends no payload item).
func encodeRPC2Frame(method string, seq uint64, errMsg string, payload []byte) []byte {
	hdr := cborMap(3)
	hdr = append(hdr, cborKV("M", cborText(method))...)
	hdr = append(hdr, cborKV("S", cborUint(seq))...)
	hdr = append(hdr, cborKV("E", cborText(errMsg))...)
	body := hdr
	if payload != nil {
		body = append(body, payload...)
	}
	out := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...)
}

// cborValue encodes the rpc2 payload subset as CBOR: nil, bool, uint64/int,
// string, []any, map[string]any (text keys only, fxamacker-compatible).
// Anything else is a programming error — the fabric payloads are closed.
func cborValue(v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return []byte{cborMajorSimple<<5 | 22}, nil // null
	case bool:
		return cborBool(x), nil
	case uint64:
		return cborUint(x), nil
	case int:
		return cborUint(uint64(x)), nil
	case int64:
		return cborUint(uint64(x)), nil
	case string:
		return cborText(x), nil
	case []any:
		out := cborArray(len(x))
		for _, item := range x {
			b, err := cborValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return out, nil
	case map[string]any:
		out := cborMap(len(x))
		for k, item := range x {
			b, err := cborValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, cborKV(k, b)...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("fabric: rpc2 payload type %T not encodable", v)
	}
}

// rpc2 decode errors are value errors (the caller surfaces them verbatim).
var (
	errRPC2Truncated = errors.New("fabric: truncated rpc2 frame")
	errRPC2Malformed = errors.New("fabric: malformed rpc2 frame")
	errRPC2Deep      = errors.New("fabric: rpc2 frame too deeply nested")
)

// rpc2MaxDepth matches the Rust decoder's hostile-frame posture: real rpc2
// traffic nests at most a handful of levels; deeper is hostile.
const rpc2MaxDepth = 64

// decodeCBORItem decodes one CBOR item, returning the value and the byte
// count consumed (measured consumption, mirroring p2p.rs decode_value:
// no heuristics, indefinite lengths and reserved infos rejected).
//
// Allocation discipline: item sizes are bounded by the FRAME, never by the
// attacker's declared length — maps and arrays are grown by append as real
// items are decoded, so a 27-head claiming 2^64 elements costs O(bytes
// present), not O(declared). Text is UTF-8-validated to match the Rust
// decoder exactly (std::str::from_utf8 in p2p.rs): the two implementations
// must accept the same frames, not merely the same bytes-into-structs.
func decodeCBORItem(buf []byte, depth int) (any, int, error) {
	if depth > rpc2MaxDepth {
		return nil, 0, errRPC2Deep
	}
	if len(buf) == 0 {
		return nil, 0, errRPC2Truncated
	}
	ib := buf[0]
	major, info := ib>>5, ib&0x1f
	var n uint64
	pos := 1
	switch info {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23:
		n = uint64(info)
	case 24:
		if len(buf) < 2 {
			return nil, 0, errRPC2Truncated
		}
		n, pos = uint64(buf[1]), 2
	case 25:
		if len(buf) < 3 {
			return nil, 0, errRPC2Truncated
		}
		n, pos = uint64(buf[1])<<8|uint64(buf[2]), 3
	case 26:
		if len(buf) < 5 {
			return nil, 0, errRPC2Truncated
		}
		n, pos = uint64(buf[1])<<24|uint64(buf[2])<<16|uint64(buf[3])<<8|uint64(buf[4]), 5
	case 27:
		if len(buf) < 9 {
			return nil, 0, errRPC2Truncated
		}
		for _, b := range buf[1:9] {
			n = n<<8 | uint64(b)
		}
		pos = 9
	default: // 28..=30 reserved, 31 indefinite — both rejected
		return nil, 0, errRPC2Malformed
	}
	// The consumed length n counts PAYLOAD bytes for text/bytes; for uints
	// the head itself carries the value (nothing follows). The truncation
	// check applies only where n names following bytes — a uint check would
	// misread the NEXT item's head as this value's payload (caught by the
	// pinned ok-response vector, which the first decoder draft mis-parsed).
	rest := buf[pos:]
	switch major {
	case cborMajorUint:
		return n, pos, nil
	case cborMajorText:
		// n > len(buf) — computed WITHOUT addition, so a near-2^64 length
		// cannot wrap the check (the wrap made a huge-length frame pass
		// truncation and panic in the allocator; caught by FuzzFabricRPC2
		// Frame's seed corpus on its first run — the Rust decoder's
		// checked_add was right all along).
		if n > uint64(len(rest)) {
			return nil, 0, errRPC2Truncated
		}
		// UTF-8 gate — byte-for-byte parity with the Rust decoder's
		// std::str::from_utf8: invalid UTF-8 in a text item is malformed
		// on both sides of the wire.
		s := rest[:n]
		if !utf8.Valid(s) {
			return nil, 0, errRPC2Malformed
		}
		return string(s), pos + int(n), nil
	case cborMajorBytes:
		if n > uint64(len(rest)) {
			return nil, 0, errRPC2Truncated
		}
		b := make([]byte, n)
		copy(b, rest[:n])
		return b, pos + int(n), nil
	case cborMajorArray:
		// No capacity hint from n: the declared length is attacker input.
		// A 27-head may claim 2^64 items while carrying none; append-grown
		// slices bound allocation by the bytes actually present.
		arr := make([]any, 0)
		used := pos
		for i := uint64(0); i < n; i++ {
			item, u, err := decodeCBORItem(buf[used:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, item)
			used += u
		}
		return arr, used, nil
	case cborMajorMap:
		// Same allocation discipline as arrays: size hints from a hostile
		// head would turn a 9-byte frame into a multi-gigabyte map.
		m := make(map[string]any)
		used := pos
		for i := uint64(0); i < n; i++ {
			key, u, err := decodeCBORItem(buf[used:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			ks, ok := key.(string)
			if !ok {
				return nil, 0, errRPC2Malformed // text keys only (fxamacker shape)
			}
			used += u
			val, u2, err := decodeCBORItem(buf[used:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			m[ks] = val
			used += u2
		}
		return m, used, nil
	case cborMajorSimple:
		// Only the null/true/false simple values (info 20..=22) carry
		// meaning on the rpc2 wire; every other simple value is rejected
		// (floats and undefined never appear in fabric payloads).
		switch info {
		case 20:
			return false, pos, nil
		case 21:
			return true, pos, nil
		case 22:
			return nil, pos, nil
		}
		return nil, 0, errRPC2Malformed
	default: // negint and tags have no rpc2 use
		return nil, 0, errRPC2Malformed
	}
}

// RPC2Message is one decoded rpc2 exchange: the header fields plus the
// optional payload item (nil when absent, as on error responses).
type RPC2Message struct {
	Method  string
	Seq     uint64
	Error   string
	Payload any
}

// DecodeRPC2Frame parses one rpc2 frame (the LE32 prefix is expected to be
// stripped by the caller, matching the Rust read_frame boundary): a CBOR
// header map {M,S,E} followed optionally by one payload item. A zero-
// consumption decode is malformed by definition — same rule as Rust.
//
// Exported (F4a follow-up) as the hostile-frame entry point for the fuzz
// target: the decoder is the relay-facing parse surface of the second
// encoding, so it is fuzzed like the other wire parsers
// (internal/wirefuzz, OSS-Fuzz projects/spore).
func DecodeRPC2Frame(body []byte) (RPC2Message, error) {
	var msg RPC2Message
	head, used, err := decodeCBORItem(body, 0)
	if err != nil {
		return msg, err
	}
	hdr, ok := head.(map[string]any)
	if !ok {
		return msg, errRPC2Malformed
	}
	m, _ := hdr["M"].(string)
	e, _ := hdr["E"].(string)
	var s uint64
	switch v := hdr["S"].(type) {
	case uint64:
		s = v
	case int:
		s = uint64(v)
	}
	msg.Method, msg.Seq, msg.Error = m, s, e
	if used < len(body) {
		payload, u, err := decodeCBORItem(body[used:], 0)
		if err != nil {
			return msg, err
		}
		if u == 0 {
			return msg, errRPC2Malformed
		}
		msg.Payload = payload
	}
	return msg, nil
}

// rpc2 request payload builders — the semantic fields are IDENTICAL to the
// legacy JSON verbs (fabric.go docs/RELAY_FABRIC.md F4a): same keys, same
// hex conventions, same caps; only the container encoding differs.
//
// KEY ORDER IS CANONICAL: CBOR maps encode in the order the encoder visits
// them. The payloads below are built as ordered pair lists (not Go maps,
// whose iteration order is randomized) in the SAME order the Rust encoder's
// serde_json::Map preserves — the golden vectors and the Rust conformance
// test both pin that order, so the encoders are byte-identical, not merely
// semantically equal.

// cborPair is one key:value pair in an rpc2 payload map.
type cborPair struct {
	k string
	v any
}

// cborPairs encodes an ordered pair list as a CBOR map.
func cborPairs(pairs []cborPair) ([]byte, error) {
	out := cborMap(len(pairs))
	for _, p := range pairs {
		b, err := cborValue(p.v)
		if err != nil {
			return nil, err
		}
		out = append(out, cborKV(p.k, b)...)
	}
	return out, nil
}

// EncodeFabricReg builds a Peer.FabricReg request payload. The client-chosen
// nonce rides the payload in both encodings (the relay ignores it; the token
// already binds it) so the two encodings stay semantically identical.
func EncodeFabricReg(handleHex, token, nonce string, leaseSec uint64) ([]byte, error) {
	return cborPairs([]cborPair{
		{"handle", handleHex},
		{"token", token},
		{"nonce", nonce},
		{"lease", leaseSec},
	})
}

// EncodeFabricPut builds a Peer.FabricPut request payload.
func EncodeFabricPut(handleHex string, pointer []byte, deadline uint64) ([]byte, error) {
	if len(pointer) != PointerLen {
		return nil, fmt.Errorf("fabric: put wants a %d-byte pointer, got %d", PointerLen, len(pointer))
	}
	return cborPairs([]cborPair{
		{"handle", handleHex},
		{"pointer_hex", fmt.Sprintf("%x", pointer)},
		{"deadline", deadline},
	})
}

// EncodeFabricPop builds a Peer.FabricPop request payload.
func EncodeFabricPop(handleHex, token string, max int) ([]byte, error) {
	return cborPairs([]cborPair{
		{"handle", handleHex},
		{"token", token},
		{"max", uint64(max)},
	})
}
