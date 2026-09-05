// Package chain is the abstraction that makes mycelium multi-chain: the core
// (whisper, rendezvous, rooms) depends only on this interface, never on a
// specific chain's wallet-RPC. A chain backend (DERO today; EVM, Monero next)
// implements it.
//
// Mycelium rides any chain that provides two primitives:
//  1. a way to post an encrypted payload (the whisper/pointer) to a recipient,
//  2. a way to list payloads addressed to us (receive).
//
// A backend maps those onto its native tx/message model. Everything the core
// needs is below — deliberately small so adding a chain is cheap.
package chain

import (
	"context"
	"errors"
	"time"
)

// ErrNotWhisper is returned by ParsePayload when the payload isn't one our
// messenger understands (e.g. a plain transfer with no message).
var ErrNotWhisper = errors.New("chain: not a spore payload")

// Argument is one typed field in a payload (chain-agnostic shape). Different
// chains carry arguments differently (DERO: CBOR rpc.Arguments; EVM: calldata;
// Monero: tx_extra), but the messenger only needs string + integer fields, so
// this minimal shape is enough for the core.
type Argument struct {
	Name  string
	Value string // string form; numeric values are serialized here
}

// Payload is an opaque, transport-ready message body to send or received.
// The core builds/parses it via a backend's codec, not through these bytes.
type Payload []byte

// PostResult is what a successful send returns.
type PostResult struct {
	TxID string
}

// Incoming is one payload received that is addressed to us.
type Incoming struct {
	TxID       string
	TopoHeight int64
	Sender     string
	// Payload is the raw message payload (whisper or pointer). The caller
	// decodes it with the backend's ParsePayload.
	Payload Payload
}

// Chain is the per-chain backend seam.
type Chain interface {
	// Name returns the chain identifier ("dero", "evm", ...).
	Name() string
	// Address returns our own address on this chain.
	Address(ctx context.Context) (string, error)
	// Height returns current chain height/topo.
	Height(ctx context.Context) (uint64, error)
	// PostPayload sends a payload (whisper or pointer) to recipientAddr.
	// amountHint allows a backend to set a nonzero transfer value where the
	// chain requires it (DERO needs >=1 atomic or the recipient never sees it).
	PostPayload(ctx context.Context, recipientAddr string, p Payload, amountHint uint64) (PostResult, error)
	// ListIncoming returns payloads addressed to us at or after minHeight.
	ListIncoming(ctx context.Context, minHeight uint64) ([]Incoming, error)
}

// WatchOpts controls the receive poller.
type WatchOpts struct {
	MinHeight uint64
	Interval  time.Duration
}

// Watch polls ListIncoming and emits each new payload exactly once (deduped by
// txid). Emits on newCh until ctx is done or an unrecoverable error occurs.
func Watch(ctx context.Context, c Chain, opts WatchOpts) (<-chan Incoming, <-chan error) {
	out := make(chan Incoming)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		iv := opts.Interval
		if iv <= 0 {
			iv = 3 * time.Second
		}
		cursor := opts.MinHeight
		seen := map[string]bool{}
		for {
			list, err := c.ListIncoming(ctx, cursor)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				select {
				case errc <- err:
				case <-ctx.Done():
				}
			} else {
				for _, inc := range list {
					if seen[inc.TxID] {
						continue
					}
					if inc.TopoHeight > int64(cursor) {
						cursor = uint64(inc.TopoHeight)
					}
					seen[inc.TxID] = true
					select {
					case out <- inc:
					case <-ctx.Done():
						return
					}
				}
			}
			select {
			case <-time.After(iv):
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}
