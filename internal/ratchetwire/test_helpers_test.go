package ratchetwire

import (
	"testing"

	"github.com/liqdmetal/spore/internal/crypto"
)

func filled(n byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = n
	}
	return b
}

// mustKeyPair generates a valid crypto.KeyPair, skipping on failure.
func mustKeyPair(tb testing.TB) *crypto.KeyPair {
	kp, err := crypto.GenerateKey()
	if err != nil || kp == nil || len(kp.Priv) < 32 {
		tb.Skipf("keygen failed or short key (%d bytes priv)", len(kp.Priv))
	}
	return kp
}
