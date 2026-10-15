package handoff

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// Flush never bootstraps a session. authorize must recheck the current pinned
// contact, allowlist, and authenticated session before preparing OR reposting.
func (s *Store) Flush(ctx context.Context, ep *ratchetwire.DurableEndpoint, local Peer,
	authorize func(Peer, string) error, post func(context.Context, string, []byte) error) error {
	if ep == nil || authorize == nil || post == nil {
		return errors.New("handoff: delivery requires endpoint, authorization, and carrier")
	}
	if pending, err := ep.PendingReceive(); err != nil {
		return err
	} else if pending != nil {
		return errors.New("handoff: recover pending application receive before flushing")
	}
	release, err := s.LockDelivery()
	if err != nil {
		return err
	}
	defer release()
	rows, err := s.List(time.Now())
	if err != nil {
		return err
	}
	device, err := ratchetwire.LoadOrCreateDevice(ep.StateDir())
	if err != nil {
		return err
	}
	var failures []error
	for _, r := range rows {
		for _, entry := range r.Outbox {
			if entry.Sent || entry.ApplicationReceived {
				continue
			}
			if r.Local != local {
				failures = append(failures, errors.New("handoff: pending event belongs to a different local identity"))
				continue
			}
			err = nil
			var payload []byte
			var recipient Peer
			for _, e := range r.Events {
				if e.Hash() == entry.EventHash {
					payload, err = Encode(e)
					recipient = e.Message.Recipient()
				}
			}
			for _, receipt := range r.Receipts {
				if receipt.Hash() == entry.EventHash {
					payload, err = EncodeReceipt(receipt)
					recipient = receipt.Receipt.Recipient
				}
			}
			if err == nil {
				err = s.flushOne(ctx, ep, device, r, payload, recipient, entry, authorize, post)
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("handoff %s event %s: %w", r.Latest().Terms.ID, entry.EventHash, err))
			}
		}
	}
	return errors.Join(failures...)
}

func (s *Store) flushOne(ctx context.Context, ep *ratchetwire.DurableEndpoint, device *ratchetwire.DeviceState,
	r Record, payload []byte, recipient Peer, entry Delivery, authorize func(Peer, string) error,
	post func(context.Context, string, []byte) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if time.Now().Unix() >= r.Latest().Terms.ExpiresAt {
		return errors.New("expired before delivery")
	}
	if err := authorize(recipient, r.Session); err != nil {
		return err
	}
	raw, err := hex.DecodeString(r.Session)
	if err != nil || len(raw) != 8 {
		return errors.New("invalid session")
	}
	var sid [8]byte
	copy(sid[:], raw)
	if err := ratchetwire.CheckSendAllowed(ep.StateDir(), sid, device); err != nil {
		return err
	}
	id := r.Latest().Terms.ID
	update := func(stage string, p []byte) error { return s.UpdateDelivery(id, entry.EventHash, stage, p, time.Now()) }
	if len(entry.Pointer) == 0 {
		if entry.Preparing {
			return errors.New("pointer preparation interrupted; refusing to advance ratchet again; preserve state and coordinate a fresh handoff/session")
		}
		if len(payload) == 0 {
			return errors.New("handoff: missing outbound payload")
		}
		if err := update("begin", nil); err != nil {
			return err
		}
		_, pointer, err := ep.SendNext(sid, payload, time.Unix(r.Latest().Terms.ExpiresAt, 0))
		if err != nil {
			return err
		}
		if err := update("pointer", pointer); err != nil {
			return err
		}
		entry.Pointer = pointer
	}
	if !entry.Accounted {
		if err := ratchetwire.RecordSendOnce(ep.StateDir(), sid, device, "handoff:"+entry.EventHash); err != nil {
			return err
		}
		if err := update("account", nil); err != nil {
			return err
		}
	}
	callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := post(callCtx, recipient.Address, entry.Pointer); err != nil {
		return fmt.Errorf("delivery pending (retry with handoff flush): %w", err)
	}
	return update("sent", nil)
}
