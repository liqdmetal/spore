package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/bounds"
	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/daoreview"
	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
)

func handoffUsage(w io.Writer) {
	fmt.Fprintln(w, `usage: spore work-order handoff commitments -brief-file F -policy-file F
       spore work-order handoff brief -registration F -to CONTACT -brief-file F -policy-file F [-expires 168h]
       spore work-order handoff deliver -id ID -result-file F
       spore work-order handoff decide -id ID -accept|-reject
       spore work-order handoff export -id ID -artifact brief|policy|result -out NEW_FILE
       spore work-order handoff list|show -id ID|status|flush|prune|recover
       spore work-order handoff recover [-discard-pending-cid EXACT_CID]

brief/deliver/decide queue locally; use handoff flush to send explicitly.
State commands require -identity, -state-dir, -state-key, and -handoff-address
(or -address). brief/deliver/decide/flush also require a pinned -maildb contact
and an existing authenticated E2 session. Normal E2 store/carrier/config flags apply.
Briefs/deliverables are bounded to 16 KiB; policy to 8 KiB; expiry is at most 30 days.
export explicitly writes a plaintext copy; protect and remove that copy yourself.
status distinguishes queued, posted, peer-persisted, blocked, and next human actions.
recover completes a journaled receive locally; discard requires its exact CID.
Signed receipts mean application persistence, NOT reading, acceptance, or payment.
Acceptance is a human decision, NOT independent verification or payment.
Use msg recv-e2 -handoff-address ADDR to receive handoff events.`)
}

func handoffCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		handoffUsage(stderr)
		return nil
	}
	op := args[0]
	fs := flag.NewFlagSet("work-order handoff "+op, flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "handoff ID")
	artifact := fs.String("artifact", "", "artifact to export: brief, policy, or result")
	output := fs.String("out", "", "new plaintext artifact output file (explicit export only)")
	discardCID := fs.String("discard-pending-cid", "", "recover only: explicitly discard this exact pending CID after committing ratchet state; no receipt is issued")
	briefFile := fs.String("brief-file", "", "private brief bytes, up to 16 KiB")
	policyFile := fs.String("policy-file", "", "human acceptance policy bytes, up to 8 KiB")
	registrationFile := fs.String("registration", "", "local observation exported by work-order register -out")
	resultFile := fs.String("result-file", "", "deliverable bytes, up to 16 KiB")
	to := fs.String("to", "", "pinned provider nickname or address")
	expires := fs.Duration("expires", 7*24*time.Hour, "retention and delivery expiry, maximum 720h")
	accept := fs.Bool("accept", false, "explicitly accept the exact received deliverable")
	reject := fs.Bool("reject", false, "explicitly reject the exact received deliverable")
	incidentCommon(fs)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *discardCID != "" && op != "recover" {
		return errors.New("handoff: -discard-pending-cid is only valid with recover")
	}
	if fs.NArg() != 0 {
		return errors.New("handoff: unexpected positional arguments")
	}
	switch op {
	case "commitments", "brief", "deliver", "decide", "list", "show", "export", "flush", "prune", "status", "recover":
	default:
		return fmt.Errorf("handoff: unknown operation %q", op)
	}
	if op == "commitments" {
		brief, err := bounds.ReadBound(*briefFile, handoff.MaxContent)
		if err != nil {
			return err
		}
		defer crypto.Zero(brief)
		policy, err := bounds.ReadBound(*policyFile, handoff.MaxPolicy)
		if err != nil {
			return err
		}
		defer crypto.Zero(policy)
		if len(brief) == 0 || len(policy) == 0 {
			return errors.New("handoff: brief and policy must not be empty")
		}
		return json.NewEncoder(stdout).Encode(map[string]string{"description_commitment": handoff.Commitment(brief), "policy_hash": handoff.Commitment(policy)})
	}
	if err := loadConfigForFlags(fs); err != nil {
		return err
	}
	local, identity, st, err := openHandoffLocal(fs)
	if err != nil {
		return err
	}
	defer crypto.Zero(identity)
	if op == "status" {
		rows, err := st.List(time.Now())
		if err != nil {
			return err
		}
		key, err := readHexFile(flagValueOr(fs, "state-key", ""), 32)
		if err != nil {
			return err
		}
		defer crypto.Zero(key)
		states, err := ratchetwire.NewFileStateStore(flagValueOr(fs, "state-dir", ""), key)
		if err != nil {
			return err
		}
		pending, err := states.PendingApplicationReceive()
		if err != nil {
			return err
		}
		if pending != nil {
			fmt.Fprintf(stdout, "receive-recovery-pending\tcid %x\tsession %x\n", pending.CID, pending.Session)
		}
		for _, r := range rows {
			if r.Local != local {
				continue
			}
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", r.Latest().Terms.ID, r.Status(), handoff.NextAction(r))
			for _, item := range r.Outbox {
				fmt.Fprintf(stdout, "  %s\t%s\n", item.EventHash, r.DeliveryStatus(item))
			}
		}
		return nil
	}
	if op == "list" || op == "prune" {
		rows, err := st.List(time.Now())
		if err != nil {
			return err
		}
		if op == "prune" {
			_, err = fmt.Fprintln(stdout, "expired handoffs removed from active store; external copies/backups are not erased")
			return err
		}
		for _, r := range rows {
			if r.Local == local {
				if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\n", r.Latest().Terms.ID, r.Status(), r.Latest().Terms.Registration.Objective.ObjectiveID); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if op == "show" || op == "export" {
		r, err := st.Get(*id, time.Now())
		if err != nil {
			return err
		}
		if r.Local != local {
			return errors.New("handoff: local identity does not own this record")
		}
		if op == "show" {
			return json.NewEncoder(stdout).Encode(r)
		}
		var data []byte
		switch *artifact {
		case "brief":
			data = r.Events[0].Message.Content
		case "policy":
			data = r.Events[0].Message.Policy
		case "result":
			if len(r.Events) < 2 {
				return errors.New("handoff: no deliverable received")
			}
			data = r.Events[1].Message.Content
		default:
			return errors.New("handoff export requires -artifact brief|policy|result")
		}
		if *output == "" || *output == "-" {
			return errors.New("handoff export requires -out NEW_FILE, not stdout")
		}
		f, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		complete := false
		defer func() {
			_ = f.Close()
			if !complete {
				_ = os.Remove(*output)
			}
		}()
		if _, err := f.Write(data); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		complete = true
		_, err = fmt.Fprintf(stdout, "exported plaintext %s to %s; this copy is outside encrypted retention\n", *artifact, *output)
		return err
	}
	if op == "decide" && *accept == *reject {
		return errors.New("handoff decide requires exactly one of -accept or -reject")
	}
	ep, _, err := newDurableEndpointFromFlags(fs)
	if err != nil {
		return err
	}
	defer closeBodyStore(ep.Store)
	mdb, err := handoffContacts(fs)
	if err != nil {
		return err
	}
	ing := &e2Ingestor{ep: ep, ik: identity, mdb: mdb, handoffStore: st, handoffLocal: local}
	if op == "recover" && *discardCID != "" {
		if err := ep.DiscardReceive(*discardCID); err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, "pending application payload explicitly discarded; ratchet retained; no receipt issued")
		return err
	}
	if err := ing.recoverHandoffReceive(); err != nil {
		return err
	}
	if op == "recover" {
		_, err = fmt.Fprintln(stdout, "receive recovery complete; persistence receipts remain queued for explicit flush")
		return err
	}
	if op == "flush" {
		carrier, err := e2Carrier(fs)
		if err != nil {
			return err
		}
		err = st.Flush(ctx, ep, local, func(peer handoff.Peer, session string) error { return authorizeHandoffPeer(ep, mdb, peer, session) }, func(ctx context.Context, recipient string, pointer []byte) error {
			_, err := carrier.PostPointer(ctx, recipient, pointer, 1)
			return err
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, "handoff outbox drained; transport success is not human acceptance or settlement")
		return err
	}
	var msg handoff.Message
	var session string
	if op == "brief" {
		if *to == "" || *registrationFile == "" || *expires <= 0 || *expires > 30*24*time.Hour {
			return errors.New("handoff brief requires -registration, -to, and an expiry in (0,720h]")
		}
		var reg handoff.Registration
		raw, err := bounds.ReadBound(*registrationFile, 16<<10)
		if err != nil {
			return err
		}
		if err := handoff.DecodeJSON(raw, &reg, 16<<10); err != nil {
			return err
		}
		if err := reg.Validate(); err != nil {
			return err
		}
		contact, err := resolveIncidentContact(mdb, *to)
		if err != nil {
			return err
		}
		sid, err := incidentSession(ep, contact)
		if err != nil {
			return err
		}
		session = hex.EncodeToString(sid[:])
		provider := handoff.Peer{Address: contact.Address, Pinned: strings.ToLower(contact.Pinned)}
		if err := authorizeHandoffPeer(ep, mdb, provider, session); err != nil {
			return err
		}
		brief, err := bounds.ReadBound(*briefFile, handoff.MaxContent)
		if err != nil {
			return err
		}
		defer crypto.Zero(brief)
		policy, err := bounds.ReadBound(*policyFile, handoff.MaxPolicy)
		if err != nil {
			return err
		}
		defer crypto.Zero(policy)
		newID, err := handoff.NewID()
		if err != nil {
			return err
		}
		msg = handoff.Message{Version: 1, Terms: handoff.Terms{ID: newID, Registration: reg, Buyer: local, Provider: provider, ExpiresAt: time.Now().Add(*expires).Unix()}, Kind: "brief", Sequence: 1, Content: brief, Policy: policy}
	} else {
		r, err := st.Get(*id, time.Now())
		if err != nil {
			return err
		}
		if r.Local != local {
			return errors.New("handoff: wrong local identity")
		}
		if r.Events[0].Message.Terms.Registration.Source == "local-dao-review" {
			return errors.New("handoff: DAO review decisions require dao-review decide; generic deliver/accept/reject are disabled")
		}
		latest := r.Latest()
		msg = handoff.Message{Version: 1, Terms: latest.Terms, Sequence: latest.Sequence + 1, Previous: r.Events[len(r.Events)-1].Hash()}
		session = r.Session
		if op == "deliver" {
			content, err := bounds.ReadBound(*resultFile, handoff.MaxContent)
			if err != nil {
				return err
			}
			defer crypto.Zero(content)
			msg.Kind, msg.Content, msg.ResultHash = "deliver", content, handoff.Commitment(content)
		} else {
			msg.Kind, msg.ResultHash = "reject", latest.ResultHash
			if *accept {
				msg.Kind = "accept"
			}
		}
		if err := authorizeHandoffPeer(ep, mdb, msg.Recipient(), session); err != nil {
			return err
		}
	}
	msg.EventID, err = handoff.NewID()
	if err != nil {
		return err
	}
	event, err := handoff.Sign(msg, identity)
	if err != nil {
		return err
	}
	if err := st.Apply(event, local, session, true, time.Now()); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "handoff %s: %s queued; run work-order handoff flush to deliver\nregistration: sender-observed, not independently verified; acceptance: human decision only; settlement: not performed\n", msg.Terms.ID, msg.Kind)
	return err
}

func openHandoffLocal(fs *flag.FlagSet) (handoff.Peer, []byte, *handoff.Store, error) {
	var local handoff.Peer
	key, err := readHexFile(flagValueOr(fs, "state-key", ""), 32)
	if err != nil {
		return local, nil, nil, err
	}
	defer crypto.Zero(key)
	dir := flagValueOr(fs, "state-dir", "")
	if dir == "" {
		return local, nil, nil, errors.New("handoff: -state-dir is required")
	}
	identity, err := readHexFile(flagValueOr(fs, "identity", ""), 32)
	if err != nil {
		return local, nil, nil, err
	}
	pub, err := secure.SigPubOf(identity)
	if err != nil {
		crypto.Zero(identity)
		return local, nil, nil, err
	}
	local = handoff.Peer{Address: handoffAddress(fs), Pinned: hex.EncodeToString(pub)}
	if err := local.Validate(); err != nil {
		crypto.Zero(identity)
		return local, nil, nil, err
	}
	st, err := handoff.Open(filepath.Join(dir, "handoffs.enc"), key)
	if err != nil {
		crypto.Zero(identity)
		return local, nil, nil, err
	}
	return local, identity, st, nil
}

func handoffAddress(fs *flag.FlagSet) string {
	if address := flagValueOr(fs, "handoff-address", ""); address != "" {
		return address
	}
	return flagValueOr(fs, "address", "")
}

func handoffContacts(fs *flag.FlagSet) (*maildb.MailDB, error) {
	path := flagValueOr(fs, "maildb", "")
	if path == "" {
		cfg, err := LoadConfig(configPath(flagValueOr(fs, "config", "")))
		if err != nil {
			return nil, err
		}
		if cfg != nil {
			path = cfg.Maildb
		}
	}
	if path == "" {
		return nil, errors.New("handoff: pinned -maildb or config maildb required")
	}
	return maildb.Open(path)
}

// handleHandoff consumes protocol messages before plaintext mail indexing,
// attachments, notifications, or transport receipts can imply acceptance.
func (g *e2Ingestor) handleHandoff(sid [8]byte, plain []byte) bool {
	if !handoff.IsEnvelope(plain) && !handoff.IsReceipt(plain) {
		return false
	}
	if g.handoffStore == nil || g.handoffLocal.Validate() != nil {
		fmt.Fprintln(os.Stderr, "handoff: local state/identity unavailable; configure -handoff-address and -state-key before receiving")
		return true
	}
	err := g.persistHandoff(sid, plain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "handoff: rejected event:", err)
		return true
	}
	fmt.Println("handoff: application persisted; receipts queued for explicit flush (not human acceptance)")
	return true
}

func (g *e2Ingestor) persistHandoff(sid [8]byte, plain []byte) error {
	if g.handoffStore == nil || g.handoffLocal.Validate() != nil {
		return errors.New("handoff: configure local identity/address/store before receiving or recovering")
	}
	session := hex.EncodeToString(sid[:])
	if handoff.IsReceipt(plain) {
		receipt, err := handoff.DecodeReceipt(plain)
		if err != nil {
			return err
		}
		if err := authorizeHandoffPeer(g.ep, g.mdb, receipt.Receipt.Sender, session); err != nil {
			return err
		}
		return g.handoffStore.ReceiveReceipt(receipt, g.handoffLocal, session, time.Now())
	}
	event, err := handoff.Decode(plain)
	if err != nil {
		return err
	}
	if err := authorizeHandoffPeer(g.ep, g.mdb, event.Message.Sender(), session); err != nil {
		return err
	}
	if event.Message.Terms.Registration.Source == "local-dao-review" {
		if event.Message.Kind == "brief" {
			packet, err := daoreview.FromBrief(event)
			if err != nil {
				return err
			}
			if time.Now().Unix() < packet.Review.Manifest.CreatedAt {
				return errors.New("dao-review: future review creation time")
			}
		} else {
			r, err := g.handoffStore.Get(event.Message.Terms.ID, time.Now())
			if err != nil {
				return err
			}
			decision, err := daoreview.DecisionFromRecord(handoff.Record{Events: []handoff.Envelope{r.Events[0], event}})
			if err != nil {
				return err
			}
			if decision.Decision.At > time.Now().Unix() {
				return errors.New("dao-review: future decision timestamp")
			}
		}
	}
	return g.handoffStore.Receive(event, g.handoffLocal, session, g.ik, time.Now())
}

func (g *e2Ingestor) recoverHandoffReceive() error {
	if g.ep == nil {
		return nil
	}
	return g.ep.RecoverReceive(func(p *ratchetwire.ReceivePending) error { return g.persistHandoff(p.Session, p.Payload) })
}

func authorizeHandoffPeer(ep *ratchetwire.DurableEndpoint, db *maildb.MailDB, peer handoff.Peer, session string) error {
	if db == nil || ep == nil {
		return errors.New("handoff: authenticated contact store/endpoint unavailable")
	}
	contact, ok := db.Contact(peer.Address)
	if !ok || contact.Blocked || !db.Allowed(peer.Address) || strings.ToLower(contact.Pinned) != peer.Pinned || contact.Bundle == nil {
		return errors.New("handoff: missing, blocked, or changed pinned contact")
	}
	pin, err := hex.DecodeString(contact.Pinned)
	if err != nil || contact.Bundle.Verify(pin) != nil {
		return errors.New("handoff: contact bundle signature invalid")
	}
	raw, err := hex.DecodeString(session)
	if err != nil || len(raw) != 8 {
		return errors.New("handoff: invalid session ID")
	}
	var sid [8]byte
	copy(sid[:], raw)
	s := ep.Sessions.Get(sid)
	if s == nil {
		return errors.New("handoff: established session is unavailable")
	}
	ik, ok := s.PeerIdentity()
	if !ok || ik != contact.Bundle.IKPub {
		return errors.New("handoff: session does not authenticate the pinned contact")
	}
	return nil
}
