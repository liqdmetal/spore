package handoff

import (
	"errors"
	"time"
)

// Receive atomically persists the event, signed receipt, and receipt delivery
// intent. A receipt cannot escape before the event itself is durable. An exact
// recovery retry reuses the same deterministic receipt without adding an event.
func (s *Store) Receive(e Envelope, local Peer, session string, identity []byte, now time.Time) error {
	if err := e.Verify(); err != nil {
		return err
	}
	if e.Message.Recipient() != local || !validHex(session, 8) {
		return errors.New("handoff: invalid receive identity/session")
	}
	if now.Unix() >= e.Message.Terms.ExpiresAt || e.Message.Terms.ExpiresAt > now.Add(30*24*time.Hour).Unix() {
		return errors.New("handoff: expired or excessive event expiry")
	}
	receipt, err := SignReceipt(e, session, identity)
	if err != nil {
		return err
	}
	return s.transaction(now, func(d *document) error {
		if err := applyEvent(d, e, local, session, false); err != nil {
			return err
		}
		for i := range d.Records {
			r := &d.Records[i]
			if r.Latest().Terms.ID != e.Message.Terms.ID {
				continue
			}
			for _, prior := range r.Receipts {
				if prior.Receipt.EventHash == e.Hash() {
					if prior != receipt {
						return errors.New("handoff: receipt conflict")
					}
					return nil
				}
			}
			r.Receipts = append(r.Receipts, receipt)
			r.Outbox = append(r.Outbox, Delivery{EventHash: receipt.Hash()})
			return nil
		}
		return ErrNotFound
	})
}

func (s *Store) ReceiveReceipt(receipt SignedReceipt, local Peer, session string, now time.Time) error {
	if err := receipt.Verify(); err != nil {
		return err
	}
	if receipt.Receipt.Recipient != local || receipt.Receipt.Session != session || now.Unix() >= receipt.Receipt.ExpiresAt {
		return errors.New("handoff: receipt identity/session/expiry mismatch")
	}
	return s.transaction(now, func(d *document) error {
		for i := range d.Records {
			r := &d.Records[i]
			if r.Latest().Terms.ID != receipt.Receipt.HandoffID {
				continue
			}
			if r.Local != local || r.Session != session {
				return errors.New("handoff: receipt targets another session or identity")
			}
			found := false
			for _, e := range r.Events {
				if e.Message.Sender() == local && receipt.Matches(e, session) {
					found = true
				}
			}
			if !found {
				return errors.New("handoff: receipt does not match a locally sent event")
			}
			for _, prior := range r.Receipts {
				if prior.Receipt.EventHash == receipt.Receipt.EventHash {
					if prior != receipt {
						return errors.New("handoff: conflicting receipt")
					}
					return nil
				}
			}
			var delivery *Delivery
			for j := range r.Outbox {
				if r.Outbox[j].EventHash == receipt.Receipt.EventHash {
					delivery = &r.Outbox[j]
				}
			}
			if delivery == nil {
				return errors.New("handoff: receipt has no outbound event")
			}
			r.Receipts = append(r.Receipts, receipt)
			delivery.ApplicationReceived = true
			return nil
		}
		return ErrNotFound
	})
}
