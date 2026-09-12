package ratchetwire

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
)

// hexDecodeString decodes a hex identity/public-key string to bytes.
func hexDecodeString(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// Endpoint is the endpoint-local E2 adapter. It never writes session state to
// a carrier or body store; callers persist ExportState through a protected
// local keystore.
type Endpoint struct {
	Sessions   *SessionTable
	Store      BodyStore
	secureWire *SecureWire // nil = legacy mode (no envelope v2 wrapping)
}

// SecureWire binds internal/secure envelope v2 into the ratchet wire so every
// on-chain pointer carries a SIGNED, E2E-encrypted body. On DERO the inner
// codec delegates to the native tx-point-to-point secrecy; on EVM/Solana the
// same envelope kills plaintext injection because the strict receiver refuses
// unsigned payloads outright.
type SecureWire struct {
	// Identity priv: 32-byte X25519 scalar. Also derives the sender's Ed25519
	// signing key deterministically (SENDER_AUTH.md §2).
	IdentityPriv []byte
	// Recipient pub: the target's 32-byte X25519 public key (for sending).
	RecipientPub [32]byte
	// Pinned sig: the sender's Ed25519 signature prefix we expect on incoming
	// envelopes. Zero-valued = accept any valid v2 signature. Non-zero = contact-pinning
	// mode (T1 in ROADMAP-PRODUCTION.md): reject everything from an unknown signer.
	PinnedSig [32]byte
}

// NewSecureWire constructs a SecureWire from hex strings (CLI-friendly).
func NewSecureWire(identityHex, recipientPubHex string, pinnedSigHex *[32]byte) (*SecureWire, error) {
	id, err := hexDecodeString(identityHex)
	if err != nil {
		return nil, fmt.Errorf("securewire: invalid identity hex: %w", err)
	}
	if len(id) == 0 {
		return nil, nil // nil means "not configured"
	}
	sw := &SecureWire{IdentityPriv: id}
	if recipientPubHex != "" {
		recipient, err := hexDecodeString(recipientPubHex)
		if err != nil {
			return nil, fmt.Errorf("securewire: invalid recipient hex: %w", err)
		}
		if len(recipient) == 0 {
			return nil, nil
		}
		copy(sw.RecipientPub[:], recipient)
	}
	if pinnedSigHex != nil && len(*pinnedSigHex) == 32 {
		copy(sw.PinnedSig[:], (*pinnedSigHex)[:])
	}
	return sw, nil
}

// isPinned reports whether this SecureWire has a contact-pinning anchor set —
// non-zero means reject any sender whose sig pub does not match.
func (sw *SecureWire) isPinned() bool {
	var zero [32]byte
	return sw.PinnedSig != zero
}

// encodePayload wraps plaintext in a kind-0xE1 envelope v2, then returns the
// wire-ready ciphertext. This is called BEFORE ratchet.DoubleRatchet.Encrypt
// during send so the frame body IS the envelope ciphertext.
func (sw *SecureWire) encodePayload(plaintext []byte) ([]byte, error) {
	if len(sw.IdentityPriv) == 0 || len(sw.RecipientPub[:]) == 0 {
		return nil, fmt.Errorf("securewire: identity and recipient keys required")
	}
	return secure.Encrypt(sw.IdentityPriv, sw.RecipientPub[:], plaintext)
}

// decodePayload unwraps an envelope v2, verifying the sender signature BEFORE
// returning the inner plaintext. Returns the decrypted text.
// On contact-pin failure it returns a sentinel ErrPinMismatch so callers can
// distinguish impersonation from transport noise without changing Endpoint.
func (sw *SecureWire) decodePayload(ratchetPlain []byte) ([]byte, error) {
	if len(sw.IdentityPriv) == 0 {
		return nil, fmt.Errorf("securewire: identity key required for decode")
	}
	pl, senderPub, err := secure.Open(sw.IdentityPriv, ratchetPlain)
	if err != nil {
		return nil, fmt.Errorf("securewire: decode: %w", err)
	}
	// Contact pin enforcement: when PinnedSig is non-zero, reject everything
	// whose sender SigPub does not match — zero-allowlist kills replay from
	// an impersonator or mailbox compromise at the wire layer.
	var zero [32]byte
	if sw.isPinned() && [32]byte(senderPub) != zero && [32]byte(senderPub) != sw.PinnedSig {
		return nil, &ErrPinMismatch{Expected: sw.PinnedSig, Got: senderPub}
	}
	return pl, nil
}

// ErrPinMismatch is returned when SecureWire rejects a message because the
// sender's Ed25519 SigPub does not match the pinned anchor (contact pin).
type ErrPinMismatch struct {
	Expected [32]byte // the pinned sender SigPub
	Got      []byte   // the actual sender SigPub from the envelope
}

func (e *ErrPinMismatch) Error() string {
	return fmt.Sprintf("securewire: pin mismatch: expected=%x got=%x", e.Expected, e.Got)
}

func NewEndpoint(st BodyStore) *Endpoint {
	return &Endpoint{Sessions: NewSessionTable(), Store: st}
}

// NewEndpointWithSecureWire creates an Endpoint with envelope v2 wrapping.
func NewEndpointWithSecureWire(st BodyStore, sw *SecureWire) *Endpoint {
	return &Endpoint{Sessions: NewSessionTable(), Store: st, secureWire: sw}
}

func exportSession(s *ratchet.Session) ([]byte, error) {
	if s == nil {
		return nil, errors.New("ratchetwire: nil session")
	}
	return s.Export()
}

func pointerFor(p Pointer) []byte {
	return PointerPayload{Version: PointerV1, Route: p.Route, CID: p.CID, BurnDeadline: p.BurnDeadline}.MarshalBinary()
}

// SendFirst creates an X3DH init frame, stores it off-chain, and returns the
// pointer plus its canonical chain encoding. The caller posts only the pointer.
//
// SendFirst is SendFirstSession with the session id discarded; callers that
// must persist the session durably should use SendFirstSession.
func (e *Endpoint) SendFirst(identity []byte, bundle *ratchet.SPKBundle, pinnedSig []byte, plaintext []byte, deadline time.Time) (Pointer, []byte, error) {
	p, raw, _, err := e.SendFirstSession(identity, bundle, pinnedSig, plaintext, deadline)
	return p, raw, err
}

// SendFirstSession is SendFirst plus the new session's id.
//
// The session id is returned DIRECTLY rather than being recovered by fetching
// the just-stored frame back out of the body store. That recovery step was a
// real bug: it had to synthesise a "now" just under the frame's burn deadline,
// and the stored deadline is truncated to whole seconds while a caller-supplied
// deadline is not. With nanoseconds present (any real `time.Now().Add(ttl)`),
// the synthesised instant landed in the SAME second as the deadline, FetchFrame
// rejected the frame as expired, and the send failed AFTER the body was already
// stored. Tests missed it because they pass deadlines built from
// `now.Truncate(time.Second)`, which has zero nanoseconds.
//
// Deriving the id from the map of live sessions is also wrong: an endpoint can
// hold several sessions and map iteration order is undefined. Returning it from
// the handshake is both correct and free.
func (e *Endpoint) SendFirstSession(identity []byte, bundle *ratchet.SPKBundle, pinnedSig []byte, plaintext []byte, deadline time.Time) (Pointer, []byte, [8]byte, error) {
	if e == nil || e.Store == nil || e.Sessions == nil {
		return Pointer{}, nil, [8]byte{}, errors.New("ratchetwire: incomplete endpoint")
	}
	s, hs, err := ratchet.EstablishInitiator(identity, bundle, pinnedSig)
	if err != nil {
		return Pointer{}, nil, [8]byte{}, err
	}

	// If SecureWire is configured, wrap plaintext in envelope v2 BEFORE ratchet encryption
	wirePlain := plaintext
	if e.secureWire != nil {
		var innerErr error
		wirePlain, innerErr = e.secureWire.encodePayload(plaintext)
		if innerErr != nil {
			return Pointer{}, nil, [8]byte{}, fmt.Errorf("securewire encode: %w", innerErr)
		}
	}

	msg, err := s.Encrypt(wirePlain)
	if err != nil {
		return Pointer{}, nil, [8]byte{}, err
	}
	frame, err := NewInitFrame(hs, msg, deadline)
	if err != nil {
		return Pointer{}, nil, [8]byte{}, err
	}
	state, err := exportSession(s)
	if err != nil {
		return Pointer{}, nil, [8]byte{}, err
	}
	if err := e.Sessions.Restore(hs.SessionID, state); err != nil {
		return Pointer{}, nil, [8]byte{}, fmt.Errorf("ratchetwire: install initiator: %w", err)
	}
	ptr, err := PutFrame(e.Store, frame)
	if err != nil {
		e.Sessions.Erase(hs.SessionID)
		return Pointer{}, nil, [8]byte{}, err
	}
	return ptr, pointerFor(ptr), hs.SessionID, nil
}

// ReceiveFirst validates an off-chain init frame before installing endpoint
// state. The caller has already decoded the signed handshake and fetched the body.
func (e *Endpoint) ReceiveFirst(identity, spk []byte, opk *[32]byte, frame Frame, rawFrame []byte) ([]byte, error) {
	if e == nil || e.Sessions == nil {
		return nil, errors.New("ratchetwire: incomplete endpoint")
	}
	if frame.Kind != FrameInit {
		return nil, errors.New("ratchetwire: not an init frame")
	}
	hs, err := frame.HandshakeMessage()
	if err != nil {
		return nil, err
	}
	s, err := ratchet.EstablishResponder(identity, spk, opk, hs)
	if err != nil {
		return nil, err
	}
	if err := e.Sessions.AcceptInit(hs, s, rawFrame); err != nil {
		return nil, err
	}
	// Decrypt after publishing so the session transition is serialized with
	// installation. If authentication fails, remove this just-installed
	// session so a valid retry with the same init cannot be permanently blocked.
	plaintext, err := s.DecryptWithDeadline(frame.Message, time.Unix(int64(frame.Deadline), 0))
	if err != nil {
		e.Sessions.Erase(hs.SessionID)
		return nil, err
	}

	// If SecureWire is configured, unwrap envelope v2 AFTER ratchet decryption
	if e.secureWire != nil {
		plaintext, err = e.secureWire.decodePayload(plaintext)
		if err != nil {
			return nil, fmt.Errorf("securewire decode: %w", err)
		}
	}

	return plaintext, nil
}

// ReceiveFirstFromPool consumes the handshake's OPK durably before accepting.
func (e *Endpoint) ReceiveFirstFromOPKPool(identity, spk []byte, pool *OPKPool, frame Frame, rawFrame []byte) ([]byte, error) {
	if pool == nil {
		return nil, errors.New("ratchetwire: nil OPK pool")
	}
	hs, err := frame.HandshakeMessage()
	if err != nil {
		return nil, err
	}
	if hs.Degraded {
		return e.ReceiveFirst(identity, spk, nil, frame, rawFrame)
	}
	opk, err := pool.Take(hs.OPKID)
	if err != nil {
		return nil, err
	}
	return e.ReceiveFirst(identity, spk, &opk, frame, rawFrame)
}

// SendNext encrypts a continuation, stores it under a fresh CID, and returns
// the opaque chain pointer. State persistence must occur after this returns and
// before the application acknowledges delivery.
func (e *Endpoint) SendNext(id [8]byte, plaintext []byte, deadline time.Time) (Pointer, []byte, error) {
	if e == nil || e.Store == nil || e.Sessions == nil {
		return Pointer{}, nil, errors.New("ratchetwire: incomplete endpoint")
	}
	var ptr Pointer
	err := e.Sessions.withSession(id, func(s *ratchet.Session) error {
		// If SecureWire is configured, wrap plaintext in envelope v2 BEFORE ratchet encryption
		wirePlain := plaintext
		if e.secureWire != nil {
			var innerErr error
			wirePlain, innerErr = e.secureWire.encodePayload(plaintext)
			if innerErr != nil {
				return fmt.Errorf("securewire encode: %w", innerErr)
			}
		}

		msg, err := s.Encrypt(wirePlain)
		if err != nil {
			return err
		}
		frame, err := NewMessageFrame(id, msg, deadline)
		if err != nil {
			return err
		}
		ptr, err = PutFrame(e.Store, frame)
		return err
	})
	if err != nil {
		return Pointer{}, nil, err
	}
	return ptr, pointerFor(ptr), nil
}

func (e *Endpoint) ReceiveNext(p Pointer, now time.Time) ([]byte, error) {
	if e == nil || e.Store == nil || e.Sessions == nil {
		return nil, errors.New("ratchetwire: incomplete endpoint")
	}
	frame, err := FetchFrame(e.Store, p, now)
	if err != nil {
		return nil, err
	}
	if frame.Kind != FrameMessage {
		return nil, errors.New("ratchetwire: expected continuation")
	}
	plaintext, err := e.Sessions.Decrypt(frame.SessionID, frame.Message, time.Unix(int64(frame.Deadline), 0))
	if err != nil {
		return nil, err
	}

	// If SecureWire is configured, unwrap envelope v2 AFTER ratchet decryption
	if e.secureWire != nil {
		plaintext, err = e.secureWire.decodePayload(plaintext)
		if err != nil {
			return nil, fmt.Errorf("securewire decode: %w", err)
		}
	}

	return plaintext, nil
}