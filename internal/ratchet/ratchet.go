// Package ratchet implements X3DH + the Signal double ratchet for spore
// (docs/RATCHET.md). It layers forward secrecy (G1) and post-compromise
// security (G2) on top of the sender-authenticated session: a stolen device
// key decrypts only the in-flight window — never history — and a session
// self-heals after compromise ends via fresh DH ratchet inputs.
//
// Construction (all labels carry the spore/ prefix and a version):
//
//	KDF_RK(rk, dh_out) = HKDF-SHA256(salt=rk, ikm=dh_out,
//	                     info="spore/dr/v1/rk"||session_id) → (rk', ck)
//	KDF_CK(ck)         = HMAC-SHA256(ck, 0x01) → mk
//	                     HMAC-SHA256(ck, 0x02) → ck'
//	mk → (aead_key, nonce) = HKDF(mk, info="spore/dr/v1/mk"||header||sid)
//	aead               = XChaCha20-Poly1305, AAD = "spore/dr/v1/aad"||sid||header
//
// Wire form (Message.MarshalBinary):
//
//	header(40) || nonce(24) || ciphertext
//	header = dh_pub(32) || prev_chain_len(u32 LE) || msg_num(u32 LE)
//
// The header is AAD — never trusted separately (docs/RATCHET.md §5). The
// 8-byte session id is bound into the AAD and into every KDF label, so
// messages and keys from one session can never be laundered into another.
//
// Skipped-key policy (the rot adaptation, §5): out-of-order delivery may
// require buffering skipped message keys. Hard bounds are enforced and fail
// CLOSED (64/chain, 1024/session by default), and every skipped key inherits
// the message's burn deadline — SweepSkipped drops expired keys at Reap/Trim
// time, so an offline gap cannot become a permanent key archive.
package ratchet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/liqdmetal/spore/internal/crypto"
)

// Header is the 40-byte per-message ratchet header (docs/RATCHET.md §5):
// the sender's current DH ratchet public key, the length of the PREVIOUS
// sending chain (for skipped-key indexing), and this message's number in the
// current chain.
type Header struct {
	DHPub [32]byte
	PN    uint32 // length of sender's previous chain (skipped-key index)
	N     uint32 // message number in the current chain
}

const headerLen = 32 + 4 + 4

// marshal returns the 40-byte big-endian wire form. All multi-byte integers
// on the ratchet wire are little-endian per the design doc.
func (h Header) marshal() []byte {
	b := make([]byte, headerLen)
	copy(b, h.DHPub[:])
	binary.LittleEndian.PutUint32(b[32:], h.PN)
	binary.LittleEndian.PutUint32(b[36:], h.N)
	return b
}

func unmarshalHeader(b []byte) (Header, error) {
	if len(b) < headerLen {
		return Header{}, fmt.Errorf("ratchet: header truncated (%d < %d)", len(b), headerLen)
	}
	var h Header
	copy(h.DHPub[:], b[:32])
	h.PN = binary.LittleEndian.Uint32(b[32:])
	h.N = binary.LittleEndian.Uint32(b[36:])
	return h, nil
}

// Message is one ratcheted application message (docs/RATCHET.md §6): the
// wire form is header || nonce || ciphertext, with the header as AAD. The
// AEAD key comes from the ratchet; there is NO outer envelope signature —
// authentication is the X3DH handshake bound to pinned identities plus the
// DH ratchet chain itself.
type Message struct {
	Header     Header
	Nonce      [24]byte
	Ciphertext []byte
}

const (
	nonceOff = headerLen
	nonceLen = 24
)

// MarshalBinary returns header(40) || nonce(24) || ciphertext.
func (m Message) MarshalBinary() []byte {
	out := make([]byte, 0, headerLen+nonceLen+len(m.Ciphertext))
	out = append(out, m.Header.marshal()...)
	out = append(out, m.Nonce[:]...)
	out = append(out, m.Ciphertext...)
	return out
}

// UnmarshalMessage parses the wire form.
func UnmarshalMessage(b []byte) (Message, error) {
	const minCiphertext = 16 // XChaCha20-Poly1305 authentication tag.
	if len(b) < headerLen+nonceLen+minCiphertext {
		return Message{}, fmt.Errorf("ratchet: message truncated (%d bytes)", len(b))
	}
	h, err := unmarshalHeader(b[:headerLen])
	if err != nil {
		return Message{}, err
	}
	var n [24]byte
	copy(n[:], b[headerLen:headerLen+nonceLen])
	return Message{Header: h, Nonce: n, Ciphertext: append([]byte(nil), b[headerLen+nonceLen:]...)}, nil
}

// KDF labels (docs/RATCHET.md §5, §10).
var (
	labelRK  = "spore/dr/v1/rk"
	labelMK  = "spore/dr/v1/mk"
	labelAAD = "spore/dr/v1/aad"
)

// kdfRK is KDF_RK: HKDF-SHA256(salt=rk, ikm=dh_out, info=labelRK||sid)
// → (rk', ck). Returns the rotated root key and the new chain key.
func kdfRK(rk, dhOut, sid []byte) (rkNew, ck [32]byte, err error) {
	info := make([]byte, 0, len(labelRK)+len(sid))
	info = append(info, labelRK...)
	info = append(info, sid...)
	h := hkdf.New(sha256.New, dhOut, rk, info)
	if _, err = io.ReadFull(h, rkNew[:]); err != nil {
		return
	}
	if _, err = io.ReadFull(h, ck[:]); err != nil {
		return
	}
	return
}

// kdfCK is KDF_CK: HMAC(ck,0x01)→mk, HMAC(ck,0x02)→ck'. The input chain key
// is zeroed by the caller AFTER both derivations succeed (advance is
// unconditional once a message key is released, §10).
func kdfCK(ck []byte) (mk, ckNew [32]byte) {
	h1 := hmac.New(sha256.New, ck)
	h1.Write([]byte{0x01})
	copy(mk[:], h1.Sum(nil))
	h2 := hmac.New(sha256.New, ck)
	h2.Write([]byte{0x02})
	copy(ckNew[:], h2.Sum(nil))
	return
}

// mkAEAD expands a message key + header into the AEAD key and nonce. The
// header is mixed in so the key is unique per (chain, message) even before
// use, and the session id binds derivations to the session (§10).
func mkAEAD(mk, header, sid []byte) (key [32]byte, nonce [24]byte, err error) {
	info := make([]byte, 0, len(labelMK)+len(header)+len(sid))
	info = append(info, labelMK...)
	info = append(info, header...)
	info = append(info, sid...)
	h := hkdf.New(sha256.New, mk, nil, info)
	if _, err = io.ReadFull(h, key[:]); err != nil {
		return
	}
	if _, err = io.ReadFull(h, nonce[:]); err != nil {
		return
	}
	return
}

func aad(sid []byte, header []byte) []byte {
	out := make([]byte, 0, len(labelAAD)+len(sid)+len(header))
	out = append(out, labelAAD...)
	out = append(out, sid...)
	out = append(out, header...)
	return out
}

// skippedKey is one buffered out-of-order message key with its inherited
// burn deadline (docs/RATCHET.md §5: at Trim/Reap time expired keys die with
// the message they would have decrypted).
type skippedKey struct {
	MK       [32]byte  `json:"mk"`
	Deadline time.Time `json:"deadline"` // zero = no TTL
}

// ExportedState is the serializable form of a Session: EVERYTHING needed to
// resume it, including private scalars. It exists so (a) session state can
// live in the protected store (§7) and (b) the compromise-simulation test
// can steal a snapshot. Treat the bytes as the device key itself.
type ExportedState struct {
	// Created and LastActivity are endpoint-local lifecycle metadata. They are
	// intentionally exported so durable stores preserve expiry state.
	Created           time.Time             `json:"created,omitempty"`
	LastActivity      time.Time             `json:"last_activity,omitempty"`
	RK                [32]byte              `json:"rk"`
	DHPriv            [32]byte              `json:"dh_priv"`
	DHPub             [32]byte              `json:"dh_pub"`
	DHRemote          [32]byte              `json:"dh_remote"`
	HasRemote         bool                  `json:"has_remote"`
	CKs               []byte                `json:"cks,omitempty"`
	CKr               []byte                `json:"ckr,omitempty"`
	Ns                uint32                `json:"ns"`
	Cr                uint32                `json:"cr"`
	PN                uint32                `json:"pn"`
	SID               [8]byte               `json:"sid"`
	Skipped           map[string]skippedKey `json:"skipped"`
	PerChain          map[string]int        `json:"per_chain"`
	MaxSkipPerChain   int                   `json:"max_skip_chain"`
	MaxSkipPerSession int                   `json:"max_skip_session"`
}

// Export serializes the full session state (private material included).
func (s *Session) Export() ([]byte, error) {
	return json.Marshal(s.state())
}

func (s *Session) state() ExportedState {
	e := ExportedState{
		Created: s.created, LastActivity: s.lastActivity,
		RK: s.rk, DHPriv: s.dhPriv, DHPub: s.dhPub, DHRemote: s.dhRemote,
		HasRemote: s.hasRemote, Ns: s.ns, Cr: s.cr, PN: s.pn, SID: s.sid,
		Skipped: s.skipped, PerChain: s.skippedPerChain,
		MaxSkipPerChain: s.MaxSkipPerChain, MaxSkipPerSession: s.MaxSkipPerSession,
	}
	if s.cks != nil {
		e.CKs = append([]byte(nil), s.cks...)
	}
	if s.ckr != nil {
		e.CKr = append([]byte(nil), s.ckr...)
	}
	return e
}

// ImportState restores a session from Export bytes. The returned session
// uses real randomness for future DH ratchet steps.
func ImportState(b []byte) (*Session, error) {
	var e ExportedState
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("ratchet: import: %w", err)
	}
	s := newSession(e.RK, sidBytes(e.SID), nil)
	s.created, s.lastActivity = e.Created, e.LastActivity
	if s.created.IsZero() {
		s.created = time.Now()
	}
	if s.lastActivity.IsZero() {
		s.lastActivity = s.created
	}
	s.dhPriv, s.dhPub, s.dhRemote = e.DHPriv, e.DHPub, e.DHRemote
	s.hasRemote = e.HasRemote
	s.cks, s.ckr = e.CKs, e.CKr
	s.ns, s.cr, s.pn = e.Ns, e.Cr, e.PN
	s.sid = e.SID
	s.skipped = e.Skipped
	if s.skipped == nil {
		s.skipped = map[string]skippedKey{}
	}
	s.skippedPerChain = e.PerChain
	s.MaxSkipPerChain = e.MaxSkipPerChain
	s.MaxSkipPerSession = e.MaxSkipPerSession
	return s, nil
}

func sidBytes(b [8]byte) [32]byte {
	var z [32]byte
	copy(z[:], b[:])
	return z
}

// ErrDecrypt is returned when a ratcheted message fails authentication
// (wrong key, tamper, foreign session, or replay). Deliberately uniform —
// the exact failure mode is not leaked to the wire.
var ErrDecrypt = errors.New("ratchet: cannot decrypt message")

// Session is one double-ratchet session (one per device-pair, §8). It is NOT
// thread-safe: the caller serializes (one conversation, one owner).
type Session struct {
	created      time.Time
	lastActivity time.Time
	rk           [32]byte
	dhPriv       [32]byte // our current ratchet scalar (zero until we have one)
	dhPub        [32]byte
	dhRemote     [32]byte
	hasRemote    bool
	cks          []byte // our sending chain key (nil until established)
	ckr          []byte // our receiving chain key (nil until established)
	ns           uint32 // next send index in current chain
	cr           uint32 // next expected receive index in current chain
	pn           uint32 // length of the chain before the current receiving chain
	sid          [8]byte

	skipped         map[string]skippedKey // "dhpubhex:n" → key
	skippedPerChain map[string]int

	// Bounds (docs/RATCHET.md §5) — exceeded = fail closed.
	MaxSkipPerChain   int
	MaxSkipPerSession int

	// dhGen produces the next DH ratchet keypair. Default: fresh randomness.
	// The deterministic variants (vector tests) inject fixed scalars.
	dhGen func() (priv [32]byte, err error)
}

// Default skipped-key bounds (docs/RATCHET.md §5).
const (
	DefaultMaxSkipPerChain   = 64
	DefaultMaxSkipPerSession = 1024
)

func newSession(sk, sid [32]byte, dhGen func() (priv [32]byte, err error)) *Session {
	now := time.Now()
	s := &Session{
		created: now, lastActivity: now,
		skipped:           map[string]skippedKey{},
		skippedPerChain:   map[string]int{},
		MaxSkipPerChain:   DefaultMaxSkipPerChain,
		MaxSkipPerSession: DefaultMaxSkipPerSession,
		dhGen:             dhGen,
	}
	copy(s.rk[:], sk[:])
	copy(s.sid[:], sid[:8])
	if s.dhGen == nil {
		s.dhGen = func() (priv [32]byte, err error) {
			k, gerr := crypto.GenerateKey()
			if gerr != nil {
				return priv, gerr
			}
			copy(priv[:], k.Priv)
			return priv, nil
		}
	}
	return s
}

// Lifecycle returns endpoint-local timestamps used for durable expiry.
func (s *Session) Lifecycle() (created, lastActivity time.Time) { return s.created, s.lastActivity }

// InactiveBefore reports whether the session has had no successful ratchet
// activity since cutoff. A zero cutoff never expires a session.
func (s *Session) InactiveBefore(cutoff time.Time) bool {
	return !cutoff.IsZero() && s.lastActivity.Before(cutoff)
}

// ID returns the 8-byte session id (SHA256 of the X3DH transcript) — bound
// into every KDF label and every AEAD AAD (docs/RATCHET.md §10).
func (s *Session) ID() [8]byte { return s.sid }

// ensureDHKey lazily creates our ratchet keypair (responder's first send or
// a receiver-side DH step before having sent).
func (s *Session) ensureDHKey() error {
	var zero [32]byte
	if s.dhPriv != zero {
		return nil
	}
	priv, err := s.dhGen()
	if err != nil {
		return err
	}
	k, err := crypto.KeyPairFromPriv(priv[:])
	if err != nil {
		return err
	}
	copy(s.dhPriv[:], k.Priv)
	copy(s.dhPub[:], k.Pub)
	return nil
}

// dhStep performs one DH ratchet step: (rk', cks-or-ckr) = KDF_RK(rk,
// DH(our_ratchet, peer_ratchet)). Direction is implicit in which chain key
// the caller assigns (§5: DH ratchet step on every direction change).
func (s *Session) dhStep() (ck [32]byte, err error) {
	out, err := crypto.SharedSecret(s.dhPriv[:], s.dhRemote[:])
	if err != nil {
		return ck, fmt.Errorf("ratchet: DH step: %w", err)
	}
	rkNew, ckNew, err := kdfRK(s.rk[:], out, s.sid[:])
	if err != nil {
		return ck, err
	}
	s.rk = rkNew
	return ckNew, nil
}

// Encrypt seals pt under the current sending chain.
func (s *Session) Encrypt(pt []byte) (Message, error) {
	var m Message
	// First send after a DH ratchet step (or the responder's first send):
	// generate a FRESH ratchet key and open the sending chain off it (§5).
	if s.cks == nil {
		if !s.hasRemote {
			return m, errors.New("ratchet: no sending chain and no peer ratchet key yet")
		}
		if err := s.ensureDHKey(); err != nil {
			return m, err
		}
		ck, err := s.dhStep()
		if err != nil {
			return m, err
		}
		ckb := ck
		s.cks = ckb[:]
		s.ns = 0
	}
	mk, ckNext := kdfCK(s.cks)
	// Chain-key advance is unconditional once the message key is released,
	// even if anything below fails (§10); the consumed chain key is erased.
	next := append([]byte(nil), ckNext[:]...)
	crypto.Zero(s.cks)
	s.cks = next
	h := Header{DHPub: s.dhPub, PN: s.pn, N: s.ns}
	s.ns++
	hb := h.marshal()
	key, nonce, err := mkAEAD(mk[:], hb, s.sid[:])
	if err != nil {
		return m, err
	}
	ct, err := crypto.SealAAD(pt, key[:], nonce[:], aad(s.sid[:], hb))
	if err != nil {
		return m, err
	}
	m = Message{Header: h, Nonce: nonce, Ciphertext: ct}
	s.lastActivity = time.Now()
	return m, nil
}

// Decrypt opens a received message, handling DH ratchet steps and
// out-of-order delivery via the bounded skipped-key store. Replay detection:
// a message number below the receiving chain's cursor is rejected outright.
func (s *Session) Decrypt(m Message) ([]byte, error) {
	return s.decrypt(m, time.Time{})
}

// DecryptWithDeadline is Decrypt where deadline is this message's burn
// deadline. Any message keys SKIPPED while processing it (out-of-order
// delivery) inherit that deadline in the skipped-key store — the rot
// property (§5/§7). Within a conversation every message carries the same
// TTL, so applying the triggering message's deadline to the whole skipped
// batch is faithful in practice and strictly tighter than a global TTL.
func (s *Session) DecryptWithDeadline(m Message, deadline time.Time) ([]byte, error) {
	return s.decrypt(m, deadline)
}

func (s *Session) decrypt(m Message, deadline time.Time) ([]byte, error) {
	// Ratchet transitions are speculative until AEAD authentication succeeds.
	// Snapshot the complete state so malformed/tampered messages cannot burn
	// chain keys, skipped keys, or DH-ratchet state.
	snapshot, err := s.Export()
	if err != nil {
		return nil, err
	}
	rollback := func() {
		if restored, restoreErr := ImportState(snapshot); restoreErr == nil {
			*s = *restored
		}
	}
	hb := m.Header.marshal()
	// New remote ratchet key → DH ratchet step (§5: on EVERY direction
	// change; this is what heals a compromised session, G2).
	if !s.hasRemote || m.Header.DHPub != s.dhRemote {
		if s.ckr != nil {
			// Skipped keys on the OLD chain up to the sender's PN.
			if err := s.skipTo(s.dhRemote, s.cr, m.Header.PN, deadline); err != nil {
				rollback()
				return nil, err
			}
		}
		s.dhRemote = m.Header.DHPub
		s.hasRemote = true
		ck, err := s.dhStep()
		if err != nil {
			rollback()
			return nil, err
		}
		ckb := ck
		s.ckr = ckb[:]
		s.cr = 0
		s.pn = s.ns
		// Per the Signal construction: after the DH ratchet step, OUR ratchet
		// key is retired and a fresh one is generated for the next sending
		// chain. This is what heals a compromised session (G2): the fresh
		// scalar never existed in any stolen snapshot.
		crypto.Zero(s.dhPriv[:])
		crypto.Zero(s.dhPub[:])
		var zero [32]byte
		s.dhPriv = zero
		s.dhPub = zero
		s.cks = nil
		s.ns = 0
	}
	// Key resolution order (in this order replay is impossible to confuse
	// with out-of-order): (1) exactly at the cursor → consume the chain;
	// (2) already buffered as a skipped key → use and delete it (this is
	// what makes 2,3,1-after-3 deliver, and a duplicate 2 afterwards a
	// replay, since the key was consumed); (3) ahead of the cursor → skip
	// with bounds; (4) below the cursor with no stored key → replay.
	var mk [32]byte
	consume := func() {
		mkRaw, ckNext := kdfCK(s.ckr)
		mk = mkRaw
		next := append([]byte(nil), ckNext[:]...)
		crypto.Zero(s.ckr)
		s.ckr = next
		s.cr++
	}
	switch {
	case m.Header.N == s.cr:
		consume()
	default:
		id := skipID(m.Header.DHPub, m.Header.N)
		if sk, ok := s.skipped[id]; ok {
			mk = sk.MK
			delete(s.skipped, id)
			s.skippedPerChain[chainID(m.Header.DHPub)]--
			break
		}
		if m.Header.N < s.cr {
			rollback()
			return nil, fmt.Errorf("ratchet: replayed message (n=%d < cursor=%d, no stored key)", m.Header.N, s.cr)
		}
		if err := s.skipTo(m.Header.DHPub, s.cr, m.Header.N, deadline); err != nil {
			rollback()
			return nil, err
		}
		consume()
	}
	key, _, err := mkAEAD(mk[:], hb, s.sid[:])
	if err != nil {
		return nil, err
	}
	pt, err := crypto.OpenAAD(m.Ciphertext, key[:], m.Nonce[:], aad(s.sid[:], hb))
	if err != nil {
		rollback()
		return nil, ErrDecrypt
	}
	s.lastActivity = time.Now()
	return pt, nil
}

// skipTo buffers message keys from `from` to `to` (exclusive) on the chain
// identified by dhPub. Bounds are enforced and FAIL CLOSED (§5): exceeding
// the per-chain or per-session cap aborts the receive — the sender re-sends
// or the parties re-key; we never silently over-keep.
func (s *Session) skipTo(dhPub [32]byte, from, to uint32, deadline time.Time) error {
	if to < from {
		// We already consumed more of this chain than the sender's PN
		// accounts for — nothing to skip, not an error (per Signal's
		// SkipMessageKeys being a no-op below the cursor).
		return nil
	}
	gap := int(to - from)
	if gap == 0 {
		return nil
	}
	if gap > s.MaxSkipPerChain {
		return fmt.Errorf("ratchet: %d skipped keys exceeds per-chain cap %d — failing closed", gap, s.MaxSkipPerChain)
	}
	if len(s.skipped)+gap > s.MaxSkipPerSession {
		return fmt.Errorf("ratchet: %d buffered keys would exceed session cap %d — failing closed", len(s.skipped)+gap, s.MaxSkipPerSession)
	}
	if s.ckr == nil {
		return errors.New("ratchet: cannot skip without a receiving chain")
	}
	for i := from; i < to; i++ {
		mk, ckNext := kdfCK(s.ckr)
		next := append([]byte(nil), ckNext[:]...)
		crypto.Zero(s.ckr)
		s.ckr = next
		s.skipped[skipID(dhPub, i)] = skippedKey{MK: mk, Deadline: deadline}
	}
	s.skippedPerChain[chainID(dhPub)] += gap
	s.cr = to
	return nil
}

func skipID(dhPub [32]byte, n uint32) string {
	b := make([]byte, 32, 36)
	copy(b, dhPub[:])
	b = binary.LittleEndian.AppendUint32(b, n)
	// Hex-encoded (not raw bytes) so the Export/Import JSON round-trip is
	// lossless for every byte.
	return hex.EncodeToString(b)
}

// chainID keys the per-chain skipped-key counters (same hex discipline as
// skipID).
func chainID(dhPub [32]byte) string { return hex.EncodeToString(dhPub[:]) }

// SweepSkipped drops skipped keys whose inherited burn deadline has passed
// (docs/RATCHET.md §5/§7: call from the Reap/Trim loop). Returns how many
// keys died. Zero-deadline keys never expire here — they are bounded by the
// hard caps instead.
//
// Each dropped key is a confirmed loss; SweepSkippedDetailed reports which.
func (s *Session) SweepSkipped(now time.Time) int {
	return len(s.SweepSkippedDetailed(now))
}

// Erase wipes all key material (conversation delete, §7: finally the
// "unrecoverable by anyone, including participants" promise).
func (s *Session) Erase() {
	crypto.Zero(s.rk[:])
	crypto.Zero(s.dhPriv[:])
	crypto.Zero(s.dhPub[:])
	crypto.Zero(s.dhRemote[:])
	if s.cks != nil {
		crypto.Zero(s.cks)
		s.cks = nil
	}
	if s.ckr != nil {
		crypto.Zero(s.ckr)
		s.ckr = nil
	}
	for id, sk := range s.skipped {
		crypto.Zero(sk.MK[:])
		delete(s.skipped, id)
	}
	s.skippedPerChain = map[string]int{}
}
