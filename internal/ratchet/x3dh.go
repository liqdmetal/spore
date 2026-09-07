// X3DH (Extended Triple Diffie-Hellman) for spore — docs/RATCHET.md §3/§4/§10.
//
// The recipient's mailbox is the prekey server: it publishes a bundle
// {IK_pub, SPK_pub, SPK_sig, OPK_pub}, where SPK_sig = Ed25519(identity,
// SPK transcript) proves prekey ownership under the SAME identity-derived
// sig key that signs envelopes (SENDER_AUTH.md §3 — one identity, one sig
// key, derived by secure.SigKeypairOf). OPKs are bound transitively:
// SHA256(OPK_pub) rides INSIDE the signed SPK blob, so no per-OPK signature
// overhead (§3).
//
// Initiation (§4): verify SPK_sig against the PINNED sig key, then
//
//	DH1 = X25519(IK_A, SPK_B)   DH2 = X25519(EK_A, IK_B)
//	DH3 = X25519(EK_A, SPK_B)   DH4 = X25519(EK_A, OPK_B)   (when available)
//	SK  = HKDF(F || DH1 || DH2 || DH3 || DH4, info="spore/x3dh/v1/sk")
//
// with F = 32×0xFF (domain separation, per Signal). session_id =
// SHA256(X3DH transcript)[:8] — binds every handshake to the session (§10).
// OPK exhaustion degrades gracefully to DH1–DH3 with the degraded flag set
// in the handshake (§10).
//
// What rides the chain is UNCHANGED: X3DH inputs travel inside the first
// ratcheted body path as the HandshakeMessage, never the 111-byte whisper.
package ratchet

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/secure"
)

// x3dh labels/constants (docs/RATCHET.md §4, §10).
var (
	labelSK     = "spore/x3dh/v1/sk"
	labelSPK    = "spore/spk/v1"
	errShortKey = errors.New("ratchet: key must be 32 bytes")
)

// SPKBundle is the recipient's published prekey bundle (§3). OPKPub is the
// one-time prekey handed out ONCE by the mailbox; it is optional (nil when
// the OPK pool is exhausted — degraded 2-DH mode, §10).
type SPKBundle struct {
	IKPub   [32]byte `json:"ik_pub"`    // identity X25519 public
	SPKPub  [32]byte `json:"spk_pub"`   // signed prekey public
	SPKID   uint32   `json:"spk_id"`    // monotonic SPK identifier
	SPKSig  [64]byte `json:"spk_sig"`   // Ed25519(identity, spkTranscript)
	OPKPub  *[32]byte `json:"opk_pub"`  // nil = degraded (no OPK available)
	OPKID   uint32   `json:"opk_id"`
	OPKHash [32]byte `json:"opk_hash"`  // sha256(OPK_pub), covered by SPKSig
}

// spkTranscript is the exact bytes Ed25519 signs over: label || SPKPub ||
// SPKID || OPKHash. The OPK hash (and, transitively, every hash listed in a
// batch upload) is covered by ONE signature (§3).
func (b *SPKBundle) spkTranscript() []byte {
	out := make([]byte, 0, len(labelSPK)+32+4+32)
	out = append(out, labelSPK...)
	out = append(out, b.SPKPub[:]...)
	out = binary.LittleEndian.AppendUint32(out, b.SPKID)
	out = append(out, b.OPKHash[:]...)
	return out
}

// BuildBundle constructs the bundle from Bob's identity scalar and his
// signed prekey. opkPriv may be nil (no OPK available — degraded mode).
func BuildBundle(identityPriv, spkPriv []byte, spkID uint32, opkPriv *[32]byte, opkID uint32) (*SPKBundle, error) {
	if len(identityPriv) != 32 || len(spkPriv) != 32 {
		return nil, errShortKey
	}
	ik, err := crypto.KeyPairFromPriv(identityPriv)
	if err != nil {
		return nil, err
	}
	spk, err := crypto.KeyPairFromPriv(spkPriv)
	if err != nil {
		return nil, err
	}
	b := &SPKBundle{SPKID: spkID, OPKID: opkID}
	copy(b.IKPub[:], ik.Pub)
	copy(b.SPKPub[:], spk.Pub)
	if opkPriv != nil {
		opk, err := crypto.KeyPairFromPriv(opkPriv[:])
		if err != nil {
			return nil, err
		}
		b.OPKPub = &[32]byte{}
		copy(b.OPKPub[:], opk.Pub)
		b.OPKHash = sha256.Sum256(opk.Pub)
	} else {
		b.OPKHash = sha256.Sum256(nil) // well-defined degraded marker
	}
	sigPriv, err := secure.SigKeypairOf(identityPriv)
	if err != nil {
		return nil, err
	}
	copy(b.SPKSig[:], mustSign(sigPriv, b.spkTranscript()))
	return b, nil
}

// Verify authenticates the bundle against the sender's PINNED sig key for
// this identity (docs/RATCHET.md §4 step 1 — reject on failure). It also
// checks the OPK actually hashes into the signed transcript, so a mailbox
// cannot swap a one-time prekey undetected.
func (b *SPKBundle) Verify(pinnedSigPub []byte) error {
	if len(pinnedSigPub) != 32 {
		return errors.New("ratchet: pinned sig key must be 32 bytes")
	}
	if !ed25519Verify(pinnedSigPub, b.spkTranscript(), b.SPKSig[:]) {
		return fmt.Errorf("ratchet: SPK_sig invalid for pinned key %x", pinnedSigPub[:8])
	}
	if b.OPKPub != nil {
		want := sha256.Sum256(b.OPKPub[:])
		if want != b.OPKHash {
			return errors.New("ratchet: OPK_pub does not match the hash in the signed SPK transcript")
		}
	} else if b.OPKHash != sha256.Sum256(nil) {
		return errors.New("ratchet: bundle claims degraded mode but OPK hash is set")
	}
	return nil
}

// HandshakeMessage travels INSIDE the first ratcheted body (§4: never the
// 111-byte whisper). Wire form:
//
//	ik_pub(32) || ek_pub(32) || spk_id(u32 LE) || opk_id(u32 LE, 0xFFFFFFFF = none)
//	|| session_id(8) || degraded(1)
type HandshakeMessage struct {
	IKPub     [32]byte
	EKPub     [32]byte
	SPKID     uint32
	OPKID     uint32
	SessionID [8]byte
	Degraded  bool
}

const noOPK = 0xFFFFFFFF

func (h *HandshakeMessage) MarshalBinary() []byte {
	out := make([]byte, 0, 32+32+4+4+8+1)
	out = append(out, h.IKPub[:]...)
	out = append(out, h.EKPub[:]...)
	out = binary.LittleEndian.AppendUint32(out, h.SPKID)
	out = binary.LittleEndian.AppendUint32(out, h.OPKID)
	out = append(out, h.SessionID[:]...)
	d := byte(0)
	if h.Degraded {
		d = 1
	}
	return append(out, d)
}

func UnmarshalHandshake(b []byte) (*HandshakeMessage, error) {
	if len(b) < 32+32+4+4+8+1 {
		return nil, fmt.Errorf("ratchet: handshake truncated (%d bytes)", len(b))
	}
	h := &HandshakeMessage{}
	copy(h.IKPub[:], b[:32])
	copy(h.EKPub[:], b[32:64])
	h.SPKID = binary.LittleEndian.Uint32(b[64:])
	h.OPKID = binary.LittleEndian.Uint32(b[68:])
	copy(h.SessionID[:], b[72:80])
	h.Degraded = b[80] == 1
	return h, nil
}

// establish computes SK and the session id from one side's DH outputs.
func establish(dh1, dh2, dh3, dh4 []byte, transcript []byte) (sk [32]byte, sid [8]byte, err error) {
	f := make([]byte, 32)
	for i := range f {
		f[i] = 0xFF
	}
	ikm := f
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)
	if dh4 != nil {
		ikm = append(ikm, dh4...)
	}
	s, err := hkdfExpand(ikm, []byte(labelSK), 32)
	if err != nil {
		return sk, sid, err
	}
	copy(sk[:], s)
	sum := sha256.Sum256(transcript)
	copy(sid[:], sum[:8])
	return sk, sid, nil
}

// handshakeTranscript is the canonical X3DH transcript both sides compute:
// label || IK_A || EK_A || IK_B || SPK_B || (OPK_B | 32×0x00).
func handshakeTranscript(ikA, ekA, ikB, spkB [32]byte, opkB *[32]byte) []byte {
	out := make([]byte, 0, len(labelSK)+32*4+32)
	out = append(out, labelSK...)
	out = append(out, ikA[:]...)
	out = append(out, ekA[:]...)
	out = append(out, ikB[:]...)
	out = append(out, spkB[:]...)
	if opkB != nil {
		out = append(out, opkB[:]...)
	} else {
		out = append(out, make([]byte, 32)...)
	}
	return out
}

// EstablishInitiator is Alice's side (§4). pinnedSig is Bob's Ed25519 sig
// key the sender has PINNED out-of-band; the bundle is rejected if its
// SPK_sig does not verify against it. Returns the session and the handshake
// to deliver inside the first ratcheted body.
func EstablishInitiator(identityPriv []byte, bundle *SPKBundle, pinnedSig []byte) (*Session, *HandshakeMessage, error) {
	return EstablishInitiatorDet(identityPriv, bundle, pinnedSig, nil, nil)
}

// EstablishInitiatorDet is EstablishInitiator with caller-supplied
// randomness (EK scalar and, optionally, the first ratchet DH scalars used
// in order). Production callers MUST use EstablishInitiator. This variant
// exists for the deterministic interop vectors (docs/RATCHET.md §11.2).
func EstablishInitiatorDet(identityPriv []byte, bundle *SPKBundle, pinnedSig []byte, ekPriv []byte, dhPrivs [][]byte) (*Session, *HandshakeMessage, error) {
	if err := bundle.Verify(pinnedSig); err != nil {
		return nil, nil, fmt.Errorf("ratchet: bundle rejected: %w", err)
	}
	ikA, err := crypto.KeyPairFromPriv(identityPriv)
	if err != nil {
		return nil, nil, err
	}
	var ek *crypto.KeyPair
	if ekPriv != nil {
		ek, err = crypto.KeyPairFromPriv(ekPriv)
	} else {
		ek, err = crypto.GenerateKey()
	}
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Zero(ek.Priv)
	dh1, err := crypto.SharedSecret(identityPriv, bundle.SPKPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: DH1: %w", err)
	}
	dh2, err := crypto.SharedSecret(ek.Priv, bundle.IKPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: DH2: %w", err)
	}
	dh3, err := crypto.SharedSecret(ek.Priv, bundle.SPKPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: DH3: %w", err)
	}
	var dh4 []byte
	if bundle.OPKPub != nil {
		if dh4, err = crypto.SharedSecret(ek.Priv, bundle.OPKPub[:]); err != nil {
			return nil, nil, fmt.Errorf("ratchet: DH4: %w", err)
		}
	}
	tr := handshakeTranscript(pub32(ikA), pub32(ek), bundle.IKPub, bundle.SPKPub, bundle.OPKPub)
	sk, sid, err := establish(dh1, dh2, dh3, dh4, tr)
	if err != nil {
		return nil, nil, err
	}
	hs := &HandshakeMessage{
		IKPub:     pub32(ikA),
		EKPub:     pub32(ek),
		SPKID:     bundle.SPKID,
		SessionID: sid,
		Degraded:  bundle.OPKPub == nil,
	}
	if bundle.OPKPub != nil {
		hs.OPKID = bundle.OPKID
	} else {
		hs.OPKID = noOPK
	}
	// DR init, initiator side: our ratchet key IS the X3DH ephemeral (§5):
	// opening chain = KDF_RK(SK, DH3).
	s := newInitiatorSession(sk, sid, ek.Priv, bundle.SPKPub[:], dhPrivs)
	return s, hs, nil
}

// EstablishResponder is Bob's side (§4). He consumes the handshake with his
// identity, signed-prekey, and (if referenced) one-time prekey scalars and
// reconstructs the same SK, then arms his receiving chain.
func EstablishResponder(identityPriv, spkPriv []byte, opkPriv *[32]byte, hs *HandshakeMessage) (*Session, error) {
	return EstablishResponderDet(identityPriv, spkPriv, opkPriv, hs, nil)
}

// EstablishResponderDet is EstablishResponder with injected ratchet DH
// scalars (deterministic vectors only; see EstablishInitiatorDet).
func EstablishResponderDet(identityPriv, spkPriv []byte, opkPriv *[32]byte, hs *HandshakeMessage, dhPrivs [][]byte) (*Session, error) {
	ikB, err := crypto.KeyPairFromPriv(identityPriv)
	if err != nil {
		return nil, err
	}
	dh1, err := crypto.SharedSecret(spkPriv, hs.IKPub[:])
	if err != nil {
		return nil, fmt.Errorf("ratchet: DH1: %w", err)
	}
	dh2, err := crypto.SharedSecret(identityPriv, hs.EKPub[:])
	if err != nil {
		return nil, fmt.Errorf("ratchet: DH2: %w", err)
	}
	dh3, err := crypto.SharedSecret(spkPriv, hs.EKPub[:])
	if err != nil {
		return nil, fmt.Errorf("ratchet: DH3: %w", err)
	}
	var dh4 []byte
	if opkPriv != nil {
		if dh4, err = crypto.SharedSecret(opkPriv[:], hs.EKPub[:]); err != nil {
			return nil, fmt.Errorf("ratchet: DH4: %w", err)
		}
	}
	var opkPub *[32]byte
	if opkPriv != nil {
		k, err := crypto.KeyPairFromPriv(opkPriv[:])
		if err != nil {
			return nil, err
		}
		opkPub = &[32]byte{}
		copy(opkPub[:], k.Pub)
	}
	tr := handshakeTranscript(hs.IKPub, hs.EKPub, pub32(ikB), *spkPubOf(spkPriv), opkPub)
	sk, sid, err := establish(dh1, dh2, dh3, dh4, tr)
	if err != nil {
		return nil, err
	}
	if sid != hs.SessionID {
		return nil, errors.New("ratchet: session id mismatch — handshake corrupted")
	}
	if hs.Degraded && opkPriv != nil {
		return nil, errors.New("ratchet: initiator claims degraded mode but we hold an OPK for this id")
	}
	s := newResponderSession(sk, sid, spkPriv, hs.EKPub[:], dhPrivs)
	return s, nil
}
