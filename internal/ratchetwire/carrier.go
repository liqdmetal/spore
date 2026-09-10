package ratchetwire

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
)

// Carrier is the live-chain seam E2 needs. The implementation must post and
// scan only pointer payloads. No caller should invoke the legacy text or
// one-shot codecs for an E2 conversation.
type ChainCarrier struct {
	Chain chain.Chain
	Codec ChainPayloadCodec
}

var ErrLegacyDowngrade = errors.New("ratchetwire: refusing legacy carrier downgrade")

func (c ChainCarrier) validate() error {
	if c.Chain == nil || c.Codec == nil {
		return errors.New("ratchetwire: incomplete chain carrier")
	}
	return nil
}

// PostE2 encodes a pointer using the selected chain codec and posts it. The
// only bytes handed to the chain backend are the opaque pointer encoding.
func PostE2(ctx context.Context, c ChainCarrier, recipient string, pointer []byte, amountHint uint64) (chain.PostResult, error) {
	if err := c.validate(); err != nil {
		return chain.PostResult{}, err
	}
	parsed, err := ParsePointerPayload(pointer)
	if err != nil {
		return chain.PostResult{}, err
	}
	encoded, err := c.Codec.EncodePointer(parsed)
	if err != nil {
		return chain.PostResult{}, err
	}
	return c.Chain.PostPayload(ctx, recipient, encoded, amountHint)
}

// PostPointer is the production E2 send seam: callers pass the canonical
// ratchetwire pointer bytes returned by Endpoint, and this method performs the
// existing chain transport without exposing frame or session bytes.
func (c ChainCarrier) PostPointer(ctx context.Context, recipient string, pointer []byte, amountHint uint64) (chain.PostResult, error) {
	return PostE2(ctx, c, recipient, pointer, amountHint)
}

// DecodeIncomingE2 accepts only a valid pointer encoded by this chain codec.
// It never attempts to parse an E1/native payload as E2.
func (c ChainCarrier) DecodeIncomingE2(inc chain.Incoming) (Pointer, error) {
	if err := c.validate(); err != nil {
		return Pointer{}, err
	}
	p, ok := c.Codec.DecodePointer(inc.Payload)
	if !ok {
		return Pointer{}, fmt.Errorf("%w: tx %s is not E2", ErrLegacyDowngrade, inc.TxID)
	}
	return p.Pointer(), nil
}

// FetchIncomingE2 decodes an incoming chain pointer and fetches the matching
// authenticated frame. Invalid or legacy payloads are rejected; no fallback
// body lookup or legacy decode is attempted.
//
// On a body-fetch failure the POINTER IS STILL RETURNED: the address is known
// even when the bytes are not, which is what lets the caller queue a retry.
// Only an undecodable pointer yields a zero Pointer.
func (c ChainCarrier) FetchIncomingE2(st BodyStore, inc chain.Incoming, now time.Time) (Frame, Pointer, error) {
	p, err := c.DecodeIncomingE2(inc)
	if err != nil {
		return Frame{}, Pointer{}, err
	}
	frame, err := FetchFrame(st, p, now)
	if err != nil {
		return Frame{}, p, err
	}
	return frame, p, nil
}

// WatchE2 polls the carrier and emits only valid E2 pointers. Invalid or
// legacy payloads are rejected instead of silently downgraded.
func WatchE2(ctx context.Context, c ChainCarrier, opts chain.WatchOpts) (<-chan chain.Incoming, <-chan error) {
	if err := c.validate(); err != nil {
		errch := make(chan error, 1)
		errch <- err
		close(errch)
		return nil, errch
	}
	in, errs := chain.Watch(ctx, c.Chain, opts)
	out := make(chan chain.Incoming)
	outErr := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(outErr)
		for {
			select {
			case inc, ok := <-in:
				if !ok {
					return
				}
				if _, err := c.DecodeIncomingE2(inc); err != nil {
					select {
					case outErr <- err:
					case <-ctx.Done():
						return
					}
					continue
				}
				select {
				case out <- inc:
				case <-ctx.Done():
					return
				}
			case err, ok := <-errs:
				if ok && err != nil {
					select {
					case outErr <- err:
					case <-ctx.Done():
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, outErr
}

func (p Pointer) Expired(now time.Time) bool {
	return p.BurnDeadline == 0 || now.Unix() >= int64(p.BurnDeadline)
}
