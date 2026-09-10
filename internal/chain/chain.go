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
	// ScanHeight is the backend's stable query cursor. DERO's get_transfers
	// min_height filters block height, not topoheight; keeping that cursor
	// separate prevents a DAG topoheight from skipping entries.
	ScanHeight uint64
	Sender     string
	// Amount is the native transfer value that rode WITH this payload, in
	// the chain's atomic unit (DERO: 1 DERO = 100000 atomic; EVM: wei).
	// 0 means the backend does not surface per-message value (or none was
	// attached beyond required postage). Pay-with-message: the pointer and
	// the money ride the same transaction, atomically.
	Amount uint64
	// Payload is the raw message payload (whisper or pointer). The caller
	// decodes it with the backend's ParsePayload.
	Payload Payload
	// BurnKey is an opaque, backend-specific handle a Burner can use to erase
	// this exact stored message from chain state after it has been received
	// (e.g. an EVM/Solana mailbox sequence number). Empty when the backend
	// has nothing to burn (DERO's native message field is not a persistent
	// contract slot the way an EVM/Solana mailbox account is).
	BurnKey string
}

// Burner is implemented by chain backends that store delivered messages in
// on-chain state (a mailbox contract/account) rather than the tx itself, and
// so can also erase that state — the "compostable" half of delivery. Nothing
// should live on a chain longer than it takes the recipient to read it.
type Burner interface {
	// Burn erases the stored message identified by burnKey (as set on the
	// Incoming that delivered it). Best-effort: a failed burn never blocks
	// or fails delivery — it just means chain state didn't rot on schedule.
	Burn(ctx context.Context, burnKey string) error
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
	// AutoBurn, when true, erases each delivered message from on-chain
	// mailbox state (via the Burner interface) immediately after it is
	// emitted to the caller. Compost semantics: once read, it rots — nothing
	// but a scrap trace (a spent tx / an empty mapping slot) is left behind.
	// No-op on backends that don't implement Burner (e.g. DERO).
	AutoBurn bool
}

// Watch polls ListIncoming and emits each new payload exactly once (deduped by
// txid). Emits on newCh until ctx is done or an unrecoverable error occurs.
func Watch(ctx context.Context, c Chain, opts WatchOpts) (<-chan Incoming, <-chan error) {
	out := make(chan Incoming)
	errc := make(chan error, 1)
	burner, canBurn := c.(Burner)
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
					id := incomingIdentity(inc)
					if id == "" {
						continue
					}
					if seen[id] {
						continue
					}
					// Prefer a backend-provided query cursor. DERO supplies block
					// height here because R153 get_transfers min_height is a
					// block-height filter; other backends can fall back to topo.
					select {
					case out <- inc:
						scan := inc.ScanHeight
						if scan == 0 && inc.TopoHeight > 0 {
							scan = uint64(inc.TopoHeight)
						}
						if scan > cursor {
							cursor = scan
						}
						seen[id] = true
						// Compost: erase the on-chain copy now that the
						// caller has it. Best-effort — a burn failure never
						// re-delivers or blocks; it just leaves the scrap.
						if opts.AutoBurn && canBurn && inc.BurnKey != "" {
							_ = burner.Burn(ctx, inc.BurnKey)
						}
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
