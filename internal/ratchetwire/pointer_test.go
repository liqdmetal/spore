package ratchetwire

import (
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

func TestPointerPayloadRoundTripAndStrictness(t *testing.T) {
	var p PointerPayload
	p.Version = PointerV1
	p.Route[0] = 1
	p.CID[0] = 2
	p.BurnDeadline = uint64(time.Now().Add(time.Hour).Unix())
	wire := p.MarshalBinary()
	got, err := ParsePointerPayload(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("round trip changed pointer: %#v != %#v", got, p)
	}
	for _, bad := range [][]byte{wire[:len(wire)-1], append([]byte(nil), wire...), append(append([]byte(nil), wire...), 0)} {
		if len(bad) > 1 {
			bad[0] = 2
		}
		if _, err := ParsePointerPayload(bad); err == nil {
			t.Fatal("malformed pointer accepted")
		}
	}
}

func TestGetBodyRejectsDeadlineAtExactSecond(t *testing.T) {
	st := store.NewMemStore()
	body := []byte("body")
	deadline := time.Unix(100, 0)
	cid := BodyCID(body)
	if err := st.Put(cid, body, deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := GetBody(st, Pointer{CID: cid, BurnDeadline: 100}, time.Unix(100, 0)); err != ErrExpired {
		t.Fatalf("exact deadline accepted: %v", err)
	}
}
