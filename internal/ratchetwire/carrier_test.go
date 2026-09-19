package ratchetwire

import (
	"context"
	"testing"

	"github.com/liqdmetal/spore/internal/chain"
)

type carrierChain struct {
	payload chain.Payload
}

func (f *carrierChain) Name() string                            { return "test" }
func (f *carrierChain) Address(context.Context) (string, error) { return "", nil }
func (f *carrierChain) Height(context.Context) (uint64, error)  { return 0, nil }
func (f *carrierChain) PostPayload(_ context.Context, _ string, p chain.Payload, _ uint64) (chain.PostResult, error) {
	f.payload = append([]byte(nil), p...)
	return chain.PostResult{TxID: "tx"}, nil
}
func (f *carrierChain) ListIncoming(context.Context, uint64) ([]chain.Incoming, error) {
	return nil, nil
}

func TestChainCarrierPostsOnlyCodecPointer(t *testing.T) {
	p := PointerPayload{Version: PointerV1, BurnDeadline: 9999999999}
	p.Route[0] = 1
	p.CID[0] = 2
	f := &carrierChain{}
	c := ChainCarrier{Chain: f, Codec: CanonicalChainCodec{}}
	result, err := PostE2(context.Background(), c, "recipient", p.MarshalBinary(), 1)
	if err != nil || result.TxID != "tx" {
		t.Fatalf("post=%q err=%v", result.TxID, err)
	}
	got, ok := c.Codec.DecodePointer(f.payload)
	if !ok || got != p {
		t.Fatalf("got=%#v ok=%v", got, ok)
	}
}
