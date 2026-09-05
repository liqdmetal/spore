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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/liqdmetal/compost/internal/anchor"
	"github.com/liqdmetal/compost/internal/dero"
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
)

// MaxTextLen bounds a whisper line so the packed payload stays under DERO's
// 111-byte PAYLOAD0_LIMIT after CBOR framing. The text is one S arg; measure
// says ~90 bytes text fits comfortably. Short signaling by design.
const MaxTextLen = 80

// TextTooLong reports the max whisper length.
var ErrTooLong = errors.New("whisper: line too long")

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
				if !isWhisper {
					continue
				}
				seen[e.TXID] = true
				select {
				case ch <- Msg{TXID: e.TXID, TopoHeight: e.TopoHeight, Sender: e.Sender, Text: text}:
				case <-ctx.Done():
					return
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
	Text       string
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
