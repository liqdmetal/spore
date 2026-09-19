package ratchet

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/liqdmetal/spore/internal/crypto"
)

// hkdfExpand is plain HKDF-SHA256 with an empty salt (the X3DH ikm already
// carries the F prefix for domain separation).
func hkdfExpand(ikm, info []byte, n int) ([]byte, error) {
	h := hkdf.New(sha256.New, ikm, nil, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

func ed25519Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// pub32 returns the key's 32-byte public half as a fixed array (for
// transcript hashing).
func pub32(k *crypto.KeyPair) [32]byte {
	var p [32]byte
	copy(p[:], k.Pub)
	return p
}

// spkPubOf derives the public half of a signed-prekey scalar.
func spkPubOf(spkPriv []byte) *[32]byte {
	k, err := crypto.KeyPairFromPriv(spkPriv)
	if err != nil {
		z := [32]byte{}
		return &z
	}
	p := pub32(k)
	return &p
}

func pub32Of(k *crypto.KeyPair) [32]byte { return pub32(k) }

// newInitiatorSession arms Alice's ratchet (§5): her ratchet key IS the X3DH
// ephemeral; her sending chain opens off KDF_RK(SK, DH3). dhQueue injects
// fixed scalars for the deterministic vectors (nil = real randomness).
func newInitiatorSession(sk [32]byte, sid [8]byte, ekPriv, spkPeerPub []byte, dhQueue [][]byte) *Session {
	s := newSession(sk, sid32(sid), queueGen(dhQueue))
	copy(s.dhPriv[:], ekPriv)
	k, err := crypto.KeyPairFromPriv(ekPriv)
	if err == nil {
		copy(s.dhPub[:], k.Pub)
	}
	dh3, err2 := crypto.SharedSecret(ekPriv, spkPeerPub)
	if err2 == nil {
		if rkNew, ck, derr := kdfRK(s.rk[:], dh3, s.sid[:]); derr == nil {
			s.rk = rkNew
			s.cks = append([]byte(nil), ck[:]...)
		}
	}
	return s
}

// newResponderSession arms Bob's ratchet: his RECEIVING chain mirrors
// Alice's sending chain (KDF_RK(SK, DH3) with SPK on our side of the DH).
// His sending chain opens lazily on his first Encrypt (fresh DH key).
func newResponderSession(sk [32]byte, sid [8]byte, spkPriv, ekPeerPub []byte, dhQueue [][]byte) *Session {
	s := newSession(sk, sid32(sid), queueGen(dhQueue))
	copy(s.dhRemote[:], ekPeerPub)
	s.hasRemote = true
	dh3, err := crypto.SharedSecret(spkPriv, ekPeerPub)
	if err == nil {
		if rkNew, ck, derr := kdfRK(s.rk[:], dh3, s.sid[:]); derr == nil {
			s.rk = rkNew
			s.ckr = append([]byte(nil), ck[:]...)
		}
	}
	return s
}

// queueGen returns a dhGen that pops pre-fixed scalars in order, erroring
// when the queue is exhausted (a vector run that needs more ratchet steps
// than it provisioned is a bug, not something to paper over). A nil/empty
// queue returns nil so newSession installs the random generator.
func queueGen(queue [][]byte) func() (priv [32]byte, err error) {
	if len(queue) == 0 {
		return nil
	}
	i := 0
	return func() (priv [32]byte, err error) {
		if i >= len(queue) {
			return priv, errors.New("ratchet: deterministic DH queue exhausted — provision more scalars for the vector run")
		}
		k, kerr := crypto.KeyPairFromPriv(queue[i])
		i++
		if kerr != nil {
			return priv, kerr
		}
		copy(priv[:], k.Priv)
		return priv, nil
	}
}

// mustSign signs with the identity-derived Ed25519 key. Signing is
// deterministic; an error here is a programming error (nil key).
func mustSign(k ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(k, msg)
}

// sid32 widens the 8-byte session id into the [32]byte newSession expects.
func sid32(b [8]byte) [32]byte {
	var z [32]byte
	copy(z[:], b[:])
	return z
}
