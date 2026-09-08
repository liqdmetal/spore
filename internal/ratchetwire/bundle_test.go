package ratchetwire

import (
	"testing"

	"github.com/liqdmetal/spore/internal/ratchet"
)

func TestPublicBundleRoundTripAndPinnedVerification(t *testing.T) {
	id := bytes32(1)
	spk := bytes32(2)
	b, err := ratchet.BuildBundle(id[:], spk[:], 7, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalPublicBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPublicBundle(raw, make([]byte, 32)); err == nil {
		t.Fatal("bundle accepted with wrong pinned key")
	}
	bad := append([]byte(nil), raw...)
	bad[len(bad)-2] ^= 1
	if _, err := VerifyPublicBundle(bad, id[:]); err == nil {
		t.Fatal("tampered bundle accepted")
	}
}

func bytes32(v byte) (x [32]byte) {
	for i := range x {
		x[i] = v
	}
	return
}
