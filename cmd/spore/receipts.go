package main

import (
	"encoding/json"
	"time"

	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// E2 receipts are ordinary ratcheted messages whose plaintext is this
// envelope, identified by the "spore/receipt/v1" type field. They ride the
// exact same X3DH/Double-Ratchet session as the message they acknowledge, so
// a receipt is as private as the message itself: only the two endpoints can
// read it, it forwards-secretes like any other frame, and it is stored
// off-chain under the same TTL. No new frame kind, no protocol change.
const receiptType = "spore/receipt/v1"

type receiptEnvelope struct {
	Type      string `json:"type"`
	InReplyTo string `json:"in_reply_to"` // sender's txid/pointer of the message being acked
	Status    string `json:"status"`      // "delivered" | "read"
	At        int64  `json:"at"`          // unix seconds
}

// marshalReceipt renders a receipt envelope as the plaintext body of a
// ratcheted message. inReplyTo is the sender-side txid of the message being
// acknowledged (what the sender printed as "sent-e2 txid ...").
func marshalReceipt(inReplyTo, status string) ([]byte, error) {
	return json.Marshal(receiptEnvelope{
		Type:      receiptType,
		InReplyTo: inReplyTo,
		Status:    status,
		At:        time.Now().Unix(),
	})
}

// parseReceipt reports whether b is a receipt envelope and, if so, its
// in_reply_to and status. Non-JSON or non-receipt plaintext returns ok=false
// so ordinary messages are printed normally.
func parseReceipt(b []byte) (inReplyTo, status string, ok bool) {
	var env receiptEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return "", "", false
	}
	if env.Type != receiptType {
		return "", "", false
	}
	return env.InReplyTo, env.Status, true
}

// sendReceipt acknowledges message inReplyTo on session id via SendNext. The
// caller posts the returned pointer to the chain.
func sendReceipt(ep *ratchetwire.DurableEndpoint, id [8]byte, inReplyTo, status string, ttl time.Duration) (ratchetwire.Pointer, []byte, error) {
	body, err := marshalReceipt(inReplyTo, status)
	if err != nil {
		return ratchetwire.Pointer{}, nil, err
	}
	return ep.SendNext(id, body, time.Now().Add(ttl))
}
