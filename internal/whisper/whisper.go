// Package whisper is the no-relay, no-mailbox unicast messenger: a short line
// rides directly inside a DERO transaction's encrypted payload. DERO encrypts
// every tx payload point-to-point to the recipient's wallet, so confidentiality
// is native — there is no box, no shared store, no relay. Each member only ever
// talks to their own wallet/daemon. A whisper is a real tx: it propagates to the
// recipient's node via P2P, confirms into a block, and the recipient's wallet
// surfaces it as an incoming transfer with the payload decrypted.
//
// This is the L3/L1 seam in WHISPER.md: the SAME transfer is both the mined
// anchor (L3, proven get_transfers path, ~1 block) and, when caught in the pool
// before mining by a Rust scanner on derohe-rs (L1), a ~1-2s message. The
// payload layout below is what both receivers parse.
package whisper

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/liqdmetal/mycelium/internal/anchor"
	"github.com/liqdmetal/mycelium/internal/chain"
	"github.com/liqdmetal/mycelium/internal/dero"
)

// Payload markers. A whisper is carried as typed Arguments in the tx payload.
// The recipient's wallet decrypts the payload automatically and hands it back
// as payload_rpc in get_transfers.
const (
	// ArgW is a version/type marker (uint).
	ArgW = "W"
	// ArgT is the message text (string). One of T or (for long/structured)
	// a hash+C pointer may be present.
	ArgT = "T"
)

// Kind marker values for ArgW.
const (
	// WhisperV1 is a plaintext short line (already private: DERO encrypts the
	// whole payload to the recipient wallet).
	WhisperV1 uint64 = 0x571 // "W" version 1
	// PointerV1 marks a pointer-whisper: the payload carries K (sender
	// ephemeral pub) + C (body CID) and NO text. The long body is fetched
	// peer-to-peer (compost-peer) and decrypted with the ephemeral pub.
	PointerV1 uint64 = 0x5710 // "W" pointer version 1
)

// MaxTextLen bounds a whisper line so the packed payload stays under DERO's
// 111-byte PAYLOAD0_LIMIT after CBOR framing. The text is one S arg; measure
// says ~90 bytes text fits comfortably. Short signaling by design.
const MaxTextLen = 80

// TextTooLong reports the max whisper length.
var ErrTooLong = errors.New("whisper: line too long")

// ParseArgsFromData parses a whisper out of the RAW payload bytes (the `data`
// field) returned by a wallet that could not decode payload_rpc (Engram chokes
// on DERO's trailing random pad via a stricter CBOR version). The payload is:
//
//	[0]      sender position byte (ignored)
//	[1..]    CBOR map { "WU": uint, "TS": text, ... } then random pad
//
// A tolerant, minimal CBOR map walker reads the two fields we care about and
// ignores everything after (the pad). Returns ok=false if it can't find a
// whisper marker.
func ParseArgsFromData(data []byte) (text string, ok bool) {
	if len(data) < 2 {
		return "", false
	}
	i := 1 // skip sender-position byte
	// expect map head: a0..bf (map, n<=31) or 0xb8/0xb9 etc for larger
	if len(data) <= i || data[i]&0xe0 != 0xa0 {
		return "", false
	}
	i++
	// we don't strictly need the map count; walk key->value pairs tolerantly
	var kindV, seenW, seenT bool
	var v uint64
	var t string
	for i+1 < len(data) {
		// read a key (text string head)
		ki := i
		keyBytes, ni, okk := cborText(data, ki)
		if !okk {
			break
		}
		key := string(keyBytes)
		i = ni
		if i >= len(data) {
			break
		}
		switch key {
		case "WU": // uint
			val, ni2, okv := cborUint(data, i)
			if !okv {
				return "", false
			}
			v = val
			i = ni2
			seenW = true
			if seenW && seenT {
				kindV = v == WhisperV1
				return t, kindV
			}
		case "TS": // text string
			val, ni2, okv := cborText(data, i)
			if !okv {
				return "", false
			}
			t = string(val)
			i = ni2
			seenT = true
			if seenW && seenT {
				kindV = v == WhisperV1
				return t, kindV
			}
		default:
			// unknown field; skip its value (uint or text)
			if data[i]&0xe0 == 0x60 { // text
				_, ni2, _ := cborText(data, i)
				i = ni2
			} else if data[i]&0xe0 == 0x00 { // uint
				_, ni2, _ := cborUint(data, i)
				i = ni2
			} else {
				break
			}
		}
	}
	return t, kindV && seenW && seenT
}

// cborText reads a CBOR text string (major type 3) starting at data[i].
func cborText(data []byte, i int) ([]byte, int, bool) {
	if i >= len(data) || data[i]&0xe0 != 0x60 {
		return nil, i, false
	}
	ai := data[i] & 0x1f
	i++
	var n int
	switch {
	case ai < 24:
		n = int(ai)
	case ai == 24:
		if i >= len(data) {
			return nil, i, false
		}
		n = int(data[i])
		i++
	case ai == 25:
		if i+2 > len(data) {
			return nil, i, false
		}
		n = int(data[i])<<8 | int(data[i+1])
		i += 2
	case ai == 26:
		if i+4 > len(data) {
			return nil, i, false
		}
		n = int(data[i])<<24 | int(data[i+1])<<16 | int(data[i+2])<<8 | int(data[i+3])
		i += 4
	default:
		return nil, i, false
	}
	if i+n > len(data) {
		return nil, i, false
	}
	return data[i : i+n], i + n, true
}

// cborUint reads a CBOR unsigned integer (major type 0).
func cborUint(data []byte, i int) (uint64, int, bool) {
	if i >= len(data) || data[i]&0xe0 != 0x00 {
		return 0, i, false
	}
	ai := data[i] & 0x1f
	i++
	var v uint64
	switch {
	case ai < 24:
		v = uint64(ai)
	case ai == 24:
		if i >= len(data) {
			return 0, i, false
		}
		v = uint64(data[i])
		i++
	case ai == 25:
		if i+2 > len(data) {
			return 0, i, false
		}
		v = uint64(data[i])<<8 | uint64(data[i+1])
		i += 2
	case ai == 26:
		if i+4 > len(data) {
			return 0, i, false
		}
		v = uint64(data[i])<<24 | uint64(data[i+1])<<16 | uint64(data[i+2])<<8 | uint64(data[i+3])
		i += 4
	case ai == 27:
		if i+8 > len(data) {
			return 0, i, false
		}
		for b := 0; b < 8; b++ {
			v = v<<8 | uint64(data[i+b])
		}
		i += 8
	default:
		return 0, i, false
	}
	return v, i, true
}

// ParsePointerFromData attempts pointer decode from raw bytes. Pointer
// whispers carry K/C as CBOR byte-strings (major type 2); decoding them from
// the raw padded payload is a rarer path — return not-ok so callers fall back
// to the payload_rpc parse. (Text whispers are the common Engram case and are
// handled by ParseArgsFromData.)
func ParsePointerFromData(data []byte) ([32]byte, [32]byte, bool) {
	return [32]byte{}, [32]byte{}, false
}

// BuildArgs renders a whisper into the payload Arguments for a transfer.
func BuildArgs(text string) (anchor.Arguments, error) {
	if len(text) > MaxTextLen {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooLong, len(text), MaxTextLen)
	}
	return anchor.Arguments{
		{Name: ArgW, DataType: anchor.DataUint64, Value: WhisperV1},
		{Name: ArgT, DataType: anchor.DataString, Value: text},
	}, nil
}

// BuildPointerArgs renders a pointer-whisper: K=ephemeral pub, C=body CID,
// no text. Used when a long body is held by the sender and fetched by CID.
func BuildPointerArgs(ephPub, bodyCID [32]byte) anchor.Arguments {
	return anchor.Arguments{
		{Name: ArgW, DataType: anchor.DataUint64, Value: PointerV1},
		{Name: "K", DataType: anchor.DataHash, Value: hex.EncodeToString(ephPub[:])},
		{Name: "C", DataType: anchor.DataHash, Value: hex.EncodeToString(bodyCID[:])},
	}
}

// ParseArgs reads a whisper out of payload_rpc. Returns ok=false if the args
// are not a whisper (different marker), so callers skip non-whisper transfers.
func ParseArgs(args anchor.Arguments) (text string, ok bool) {
	var kindV, seenW, seenT bool
	var v uint64
	var t string
	for _, a := range args {
		switch a.Name + a.DataType {
		case ArgW + anchor.DataUint64:
			if x, err := uintVal(a.Value); err == nil {
				v = x
				seenW = true
			}
		case ArgT + anchor.DataString:
			if s, err := strVal(a.Value); err == nil {
				t = s
				seenT = true
			}
		}
	}
	kindV = seenW && v == WhisperV1
	return t, kindV && seenT
}

// ParsePointer reads a pointer-whisper (K + C). ok=false if not a pointer form.
func ParsePointer(args anchor.Arguments) (ephPub, bodyCID [32]byte, ok bool) {
	var seenW, seenK, seenC bool
	var v uint64
	for _, a := range args {
		switch a.Name + a.DataType {
		case ArgW + anchor.DataUint64:
			if x, err := uintVal(a.Value); err == nil {
				v = x
				seenW = true
			}
		case "K" + anchor.DataHash:
			if h, err := hashVal(a.Value); err == nil {
				ephPub = h
				seenK = true
			}
		case "C" + anchor.DataHash:
			if h, err := hashVal(a.Value); err == nil {
				bodyCID = h
				seenC = true
			}
		}
	}
	return ephPub, bodyCID, seenW && v == PointerV1 && seenK && seenC
}

func hashVal(v interface{}) ([32]byte, error) {
	var h [32]byte
	switch x := v.(type) {
	case string:
		b, err := hex.DecodeString(x)
		if err != nil || len(b) != 32 {
			return h, fmt.Errorf("bad hash hex")
		}
		copy(h[:], b)
	case []byte:
		if len(x) != 32 {
			return h, fmt.Errorf("bad hash bytes")
		}
		copy(h[:], x)
	case [32]byte:
		return x, nil
	default:
		return h, fmt.Errorf("unhandled hash type %T", v)
	}
	return h, nil
}

// Send posts a whisper (a real min-postage transfer whose payload is the line)
// to recipientAddr. Returns the txid. The line is confidential end-to-end by
// DERO's own point-to-point payload encryption.
func Send(ctx context.Context, client *dero.Client, recipientAddr, text string) (string, error) {
	args, err := BuildArgs(text)
	if err != nil {
		return "", err
	}
	return client.PostPayload(ctx, recipientAddr, args, 2)
}

// Codec renders/parses mycelium payloads into a chain.Chain's native form.
// whisper talks to a chain only through Codec + chain.Chain, so the core has
// no dependency on any specific chain backend.
type Codec interface {
	// EncodeText renders a short-line whisper (kind=text) to a chain.Payload.
	EncodeText(text string) (chain.Payload, error)
	// EncodePointer renders a long-body pointer whisper to a chain.Payload.
	EncodePointer(ephPub, bodyCID [32]byte) (chain.Payload, error)
	// DecodeText parses a received payload; ok=false if not a text whisper.
	DecodeText(p chain.Payload) (text string, ok bool)
	// DecodePointer parses a received payload; ok=false if not a pointer.
	DecodePointer(p chain.Payload) (ephPub, bodyCID [32]byte, ok bool)
}

// DeroCodec implements Codec over the dero backend's payload envelope.
type DeroCodec struct{}

// EncodeText implements Codec.
func (DeroCodec) EncodeText(text string) (chain.Payload, error) {
	args, err := BuildArgs(text)
	if err != nil {
		return nil, err
	}
	return dero.ArgsToPayload(args)
}

// EncodePointer implements Codec.
func (DeroCodec) EncodePointer(ephPub, bodyCID [32]byte) (chain.Payload, error) {
	return dero.ArgsToPayload(BuildPointerArgs(ephPub, bodyCID))
}

// DecodeText implements Codec.
func (DeroCodec) DecodeText(p chain.Payload) (string, bool) {
	args, err := dero.PayloadToArgs(p)
	if err != nil {
		return "", false
	}
	return ParseArgs(args)
}

// DecodePointer implements Codec.
func (DeroCodec) DecodePointer(p chain.Payload) ([32]byte, [32]byte, bool) {
	args, err := dero.PayloadToArgs(p)
	if err != nil {
		return [32]byte{}, [32]byte{}, false
	}
	return ParsePointer(args)
}

// SendChain posts a whisper through any chain.Chain backend.
func SendChain(ctx context.Context, c chain.Chain, codec Codec, recipientAddr, text string) (string, error) {
	p, err := codec.EncodeText(text)
	if err != nil {
		return "", err
	}
	res, err := c.PostPayload(ctx, recipientAddr, p, 1)
	if err != nil {
		return "", err
	}
	return res.TxID, nil
}

// SendLongChain posts a long-body pointer whisper through any chain.Chain.
func SendLongChain(ctx context.Context, c chain.Chain, codec Codec, recipientAddr string, ephPub, bodyCID [32]byte) (string, error) {
	p, err := codec.EncodePointer(ephPub, bodyCID)
	if err != nil {
		return "", err
	}
	res, err := c.PostPayload(ctx, recipientAddr, p, 1)
	if err != nil {
		return "", err
	}
	return res.TxID, nil
}

// RecvChain polls any chain.Chain for incoming whispers/pointers, decoding with
// codec, and delivers each exactly once.
func RecvChain(ctx context.Context, c chain.Chain, codec Codec, opts chain.WatchOpts) (<-chan Msg, <-chan error) {
	ch := make(chan Msg)
	errc := make(chan error, 1)
	go func() {
		defer close(ch)
		defer close(errc)
		in, werr := chain.Watch(ctx, c, opts)
		for {
			select {
			case inc, ok := <-in:
				if !ok {
					return
				}
				if text, isText := codec.DecodeText(inc.Payload); isText {
					select {
					case ch <- Msg{TXID: inc.TxID, TopoHeight: inc.TopoHeight, Sender: inc.Sender, Text: text}:
					case <-ctx.Done():
						return
					}
					continue
				}
				if eph, cid, isPtr := codec.DecodePointer(inc.Payload); isPtr {
					select {
					case ch <- Msg{TXID: inc.TxID, TopoHeight: inc.TopoHeight, Sender: inc.Sender, HasPointer: true, EphPub: eph, BodyCID: cid}:
					case <-ctx.Done():
						return
					}
				}
			case err, ok := <-werr:
				if !ok {
					return
				}
				select {
				case errc <- err:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, errc
}

// Recv polls get_transfers (in:true) for incoming whispers and delivers each as
// it confirms. Delivered txids are deduped so a whisper fires once. Non-whisper
// incoming transfers are skipped.
func Recv(ctx context.Context, client *dero.Client, minHeight uint64, interval time.Duration) (<-chan Msg, <-chan error) {
	ch := make(chan Msg)
	errc := make(chan error, 1)
	go func() {
		defer close(ch)
		defer close(errc)
		cursor := minHeight
		seen := map[string]bool{}
		for {
			entries, err := client.GetTransfers(ctx, dero.GetTransfersParams{In: true, MinHeight: cursor})
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				errc <- err
				return
			}
			for _, e := range entries {
				if seen[e.TXID] {
					continue
				}
				if e.TopoHeight > int64(cursor) {
					cursor = uint64(e.TopoHeight)
				}
				text, isWhisper := ParseArgs(e.PayloadRPC)
				if !isWhisper && len(e.Data) > 0 {
					// Some wallets (Engram) fail to decode payload_rpc from the
					// padded CBOR but still return the raw `data` bytes.
					text, isWhisper = ParseArgsFromData(e.Data)
				}
				if isWhisper {
					seen[e.TXID] = true
					select {
					case ch <- Msg{TXID: e.TXID, TopoHeight: e.TopoHeight, Sender: e.Sender, Text: text}:
					case <-ctx.Done():
						return
					}
					continue
				}
				eph, cid, isPtr := ParsePointer(e.PayloadRPC)
				if !isPtr && len(e.Data) > 0 {
					eph, cid, isPtr = ParsePointerFromData(e.Data)
				}
				if isPtr {
					seen[e.TXID] = true
					select {
					case ch <- Msg{TXID: e.TXID, TopoHeight: e.TopoHeight, Sender: e.Sender,
						HasPointer: true, EphPub: eph, BodyCID: cid}:
					case <-ctx.Done():
						return
					}
					continue
				}
			}
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, errc
}

// Msg is one delivered whisper.
type Msg struct {
	TXID       string
	TopoHeight int64
	Sender     string
	Text       string // short line (WhisperV1); empty for pointer form
	HasPointer bool
	EphPub     [32]byte // for pointer form: sender ephemeral pub
	BodyCID    [32]byte // for pointer form: body to fetch
}

// --- value coercion helpers ---

func uintVal(v interface{}) (uint64, error) {
	switch x := v.(type) {
	case uint64:
		return x, nil
	case int64:
		if x < 0 {
			return 0, errors.New("neg")
		}
		return uint64(x), nil
	case float64:
		if x < 0 {
			return 0, errors.New("neg")
		}
		return uint64(x), nil
	case string:
		var u uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(x), "%d", &u); err != nil {
			return 0, err
		}
		return u, nil
	}
	return 0, fmt.Errorf("unhandled uint type %T", v)
}

func strVal(v interface{}) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case []byte:
		return string(x), nil
	}
	return "", fmt.Errorf("unhandled string type %T", v)
}
