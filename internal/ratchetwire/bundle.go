package ratchetwire

import (
	"encoding/json"
	"errors"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// PublicBundle is the endpoint-local, public representation of an SPK bundle.
// It deliberately has no private-key fields and is not a message or ratchet
// state container.
type PublicBundle struct {
	Version uint8             `json:"version"`
	Bundle  ratchet.SPKBundle `json:"bundle"`
}

const PublicBundleVersion uint8 = 1

func MarshalPublicBundle(b *ratchet.SPKBundle) ([]byte, error) {
	if b == nil {
		return nil, errors.New("ratchetwire: nil prekey bundle")
	}
	return json.Marshal(PublicBundle{Version: PublicBundleVersion, Bundle: *b})
}

// ParsePublicBundle accepts only the canonical public envelope. Signature
// pinning remains a send-side operation: callers must call Verify before use.
func ParsePublicBundle(raw []byte) (*ratchet.SPKBundle, error) {
	var p PublicBundle
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errors.New("ratchetwire: malformed prekey bundle")
	}
	if p.Version != PublicBundleVersion {
		return nil, errors.New("ratchetwire: unsupported prekey bundle version")
	}
	return &p.Bundle, nil
}

func VerifyPublicBundle(raw, pinnedSigPub []byte) (*ratchet.SPKBundle, error) {
	b, err := ParsePublicBundle(raw)
	if err != nil {
		return nil, err
	}
	if err := b.Verify(pinnedSigPub); err != nil {
		return nil, err
	}
	return b, nil
}
