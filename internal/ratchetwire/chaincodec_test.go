package ratchetwire

import (
	"testing"
	"time"
)

func TestAllCarrierCodecsRoundTripOpaquePointer(t *testing.T) {
	p := PointerPayload{Version: PointerV1, BurnDeadline: uint64(time.Now().Add(time.Hour).Unix())}
	p.Route[0] = 0x11
	p.CID[0] = 0x22
	codecs := map[string]ChainPayloadCodec{
		"canonical": CanonicalChainCodec{},
		"dero":      DeroChainCodec{},
		"json":      JSONCodec{},
	}
	if _, err := (XMRChainCodec{}).EncodePointer(p); err != ErrCarrierUnsupported {
		t.Fatalf("xmr carrier must refuse oversized pointer: %v", err)
	}
	for name, codec := range codecs {
		t.Run(name, func(t *testing.T) {
			wire, err := codec.EncodePointer(p)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := codec.DecodePointer(wire)
			if !ok || got != p {
				t.Fatalf("round trip: %#v, %v", got, ok)
			}
		})
	}
}
