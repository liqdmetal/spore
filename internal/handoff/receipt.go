package handoff

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/liqdmetal/spore/internal/secure"
)

const ReceiptDomain = "spore/private-handoff-receipt/v1"

// Receipt acknowledges durable application persistence, not reading, approval,
// correctness, RelayOS state, or payment. Its deterministic body makes exact
// reprocessing idempotent; receipts themselves are never acknowledged.
type Receipt struct {
	Version   int    `json:"version"`
	HandoffID string `json:"handoff_id"`
	EventID   string `json:"event_id"`
	EventHash string `json:"event_hash"`
	TermsHash string `json:"terms_hash"`
	Sequence  int    `json:"sequence"`
	Session   string `json:"session"`
	Sender    Peer   `json:"sender"`
	Recipient Peer   `json:"recipient"`
	ExpiresAt int64  `json:"expires_at"`
	Status    string `json:"status"`
}

type SignedReceipt struct {
	Domain    string  `json:"domain"`
	Receipt   Receipt `json:"receipt"`
	Signature string  `json:"signature"`
}

func receiptFor(e Envelope, session string) Receipt {
	terms, _ := json.Marshal(e.Message.Terms)
	return Receipt{Version: 1, HandoffID: e.Message.Terms.ID, EventID: e.Message.EventID,
		EventHash: e.Hash(), TermsHash: Commitment(terms), Sequence: e.Message.Sequence,
		Session: session, Sender: e.Message.Recipient(), Recipient: e.Message.Sender(),
		ExpiresAt: e.Message.Terms.ExpiresAt, Status: "persisted"}
}

func (r Receipt) validate() error {
	if r.Version != 1 || !validHex(r.HandoffID, 16) || !validHex(r.EventID, 16) ||
		!validHash(r.EventHash) || !validHash(r.TermsHash) || !validHex(r.Session, 8) ||
		r.Sequence < 1 || r.Sequence > 3 || r.ExpiresAt <= 0 || r.Status != "persisted" {
		return errors.New("handoff: invalid persistence receipt")
	}
	if err := r.Sender.Validate(); err != nil {
		return err
	}
	if err := r.Recipient.Validate(); err != nil {
		return err
	}
	if r.Sender.Address == r.Recipient.Address || r.Sender.Pinned == r.Recipient.Pinned {
		return errors.New("handoff: receipt participants must differ")
	}
	return nil
}

func SignReceipt(e Envelope, session string, identity []byte) (SignedReceipt, error) {
	if err := e.Verify(); err != nil {
		return SignedReceipt{}, err
	}
	r := receiptFor(e, session)
	if err := r.validate(); err != nil {
		return SignedReceipt{}, err
	}
	pub, err := secure.SigPubOf(identity)
	if err != nil {
		return SignedReceipt{}, err
	}
	if hex.EncodeToString(pub) != r.Sender.Pinned {
		return SignedReceipt{}, errors.New("handoff: receipt signer is not the event recipient")
	}
	key, err := secure.SigKeypairOf(identity)
	if err != nil {
		return SignedReceipt{}, err
	}
	defer clear(key)
	raw, err := json.Marshal(r)
	if err != nil {
		return SignedReceipt{}, err
	}
	sig := ed25519.Sign(key, append([]byte(ReceiptDomain+"\x00"), raw...))
	return SignedReceipt{Domain: ReceiptDomain, Receipt: r, Signature: hex.EncodeToString(sig)}, nil
}

func (s SignedReceipt) Verify() error {
	if s.Domain != ReceiptDomain {
		return errors.New("handoff: invalid receipt signing domain")
	}
	if err := s.Receipt.validate(); err != nil {
		return err
	}
	if !validHex(s.Signature, ed25519.SignatureSize) {
		return errors.New("handoff: malformed receipt signature")
	}
	sig, _ := hex.DecodeString(s.Signature)
	pin, _ := hex.DecodeString(s.Receipt.Sender.Pinned)
	raw, err := json.Marshal(s.Receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pin, append([]byte(ReceiptDomain+"\x00"), raw...), sig) {
		return errors.New("handoff: receipt signature mismatch")
	}
	return nil
}

func (s SignedReceipt) Matches(e Envelope, session string) bool {
	return s.Receipt == receiptFor(e, session)
}
func (s SignedReceipt) Hash() string { raw, _ := json.Marshal(s); return Commitment(raw) }
func EncodeReceipt(s SignedReceipt) ([]byte, error) {
	if err := s.Verify(); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}
func DecodeReceipt(raw []byte) (SignedReceipt, error) {
	var s SignedReceipt
	if err := DecodeJSON(raw, &s, 8192); err != nil {
		return s, err
	}
	return s, s.Verify()
}

func IsReceipt(raw []byte) bool { return isDomain(raw, ReceiptDomain) }
