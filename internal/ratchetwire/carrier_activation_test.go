package ratchetwire

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/store"
)

type activationChain struct {
	payload chain.Payload
}

func (c *activationChain) Name() string                            { return "test" }
func (c *activationChain) Address(context.Context) (string, error) { return "me", nil }
func (c *activationChain) Height(context.Context) (uint64, error)  { return 1, nil }
func (c *activationChain) PostPayload(_ context.Context, _ string, p chain.Payload, _ uint64) (chain.PostResult, error) {
	c.payload = append(chain.Payload(nil), p...)
	return chain.PostResult{TxID: "activation-tx"}, nil
}
func (c *activationChain) ListIncoming(context.Context, uint64) ([]chain.Incoming, error) {
	return nil, nil
}

func TestChainCarrierPostPointerAndFetchIncoming(t *testing.T) {
	deadline := uint64(time.Now().Add(time.Hour).Unix())
	var pp PointerPayload
	pp.Version = PointerV1
	pp.BurnDeadline = deadline
	pp.Route[0], pp.CID[0] = 1, 2
	pointer := pp.MarshalBinary()

	backend := &activationChain{}
	carrier := ChainCarrier{Chain: backend, Codec: CanonicalChainCodec{}}
	got, err := carrier.PostPointer(context.Background(), "recipient", pointer, 1)
	if err != nil || got.TxID != "activation-tx" {
		t.Fatalf("post=%+v err=%v", got, err)
	}
	inc := chain.Incoming{TxID: got.TxID, Payload: backend.payload}
	st := store.NewMemStore()
	frameBytes := []byte("not a frame")
	if err := st.Put(pp.CID, frameBytes, time.Unix(int64(deadline), 0)); err != nil {
		t.Fatal(err)
	}
	_, _, err = carrier.FetchIncomingE2(st, inc, time.Now())
	if !errors.Is(err, ErrBadFrame) {
		t.Fatalf("fetch err=%v, want bad frame", err)
	}
}

func TestChainCarrierRejectsLegacyIncoming(t *testing.T) {
	carrier := ChainCarrier{Chain: &activationChain{}, Codec: CanonicalChainCodec{}}
	_, err := carrier.DecodeIncomingE2(chain.Incoming{TxID: "legacy", Payload: []byte("legacy text")})
	if !errors.Is(err, ErrLegacyDowngrade) {
		t.Fatalf("err=%v, want downgrade refusal", err)
	}
}
