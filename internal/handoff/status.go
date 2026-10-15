package handoff

func (r Record) DeliveryStatus(d Delivery) string {
	for _, receipt := range r.Receipts {
		if receipt.Hash() == d.EventHash && d.Sent {
			return "persistence receipt posted; no acknowledgement required"
		}
	}
	if d.ApplicationReceived {
		return "peer-persisted"
	}
	if d.Sent {
		return "posted; awaiting signed persistence receipt"
	}
	if d.Preparing {
		return "blocked: interrupted pointer preparation; preserve state and coordinate a fresh session"
	}
	return "queued: run handoff flush"
}

func NextAction(r Record) string {
	for _, d := range r.Outbox {
		if d.Preparing {
			return "attention: blocked delivery preparation"
		}
	}
	for _, d := range r.Outbox {
		if !d.Sent && !d.ApplicationReceived {
			return "action: flush queued events/receipts"
		}
	}
	for _, d := range r.Outbox {
		if d.Sent && !d.ApplicationReceived {
			for _, event := range r.Events {
				if event.Hash() == d.EventHash {
					return "attention: awaiting signed peer-persistence receipt; not proof of human review"
				}
			}
		}
	}
	switch r.Status() {
	case "brief":
		if r.Local == r.Latest().Terms.Provider {
			return "action: review brief/policy and deliver result"
		}
		return "waiting: provider deliverable; inspect persistence receipt separately"
	case "deliver":
		if r.Local == r.Latest().Terms.Buyer {
			return "action: review exact result, then explicitly accept or reject"
		}
		return "waiting: buyer decision; persistence is not approval"
	default:
		return "final human decision recorded; inspect decision delivery/receipt separately; no settlement"
	}
}
