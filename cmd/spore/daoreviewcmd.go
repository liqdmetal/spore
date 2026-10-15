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
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/bounds"
	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/daoreview"
	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/sporrelay"
)

func daoReviewUsage(w io.Writer) {
	fmt.Fprintln(w, `usage: spore dao-review create -dao ID -proposal ID -epoch N -to CONTACT [-to CONTACT ...]
         -threshold N -evidence-file F -policy-file F -out NEW_MANIFEST [-deadline 48h] [-expires 168h]
       spore dao-review decide -id HANDOFF_ID -expect-review-hash HASH -approve|-reject
       spore dao-review status
       spore dao-review certificate -expect-review-hash HASH -out NEW_CERTIFICATE
       spore dao-review verify -certificate F -expect-review-hash HASH
       spore dao-review show -id HANDOFF_ID
       spore dao-review export -id HANDOFF_ID -artifact brief|policy|result -out NEW_FILE
       spore dao-review flush|recover|prune (same explicit handoff transport/recovery)

State commands use normal E2 config/identity/state/maildb flags. Set -address
or -handoff-address to the exact pinned local contact address. Reviewers need
established authenticated E2 sessions with the coordinator. Receiving uses msg recv-e2.
create freezes the roster, threshold, evidence/policy hashes, DAO/proposal/epoch,
and expiry in a coordinator-signed manifest. No RelayOS registration is claimed.
Strict-majority approval threshold; one final decision per reviewer per review.
verify requires an independently authenticated exact review hash; a self-selected
roster is not proof of DAO membership. Certificates reveal roster and approvals,
NOT private evidence/policy bytes. They authorize no automatic spending/execution.`)
}

func daoReviewCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		daoReviewUsage(stderr)
		return nil
	}
	op := args[0]
	switch op {
	case "show", "flush", "recover", "prune":
		return handoffCommand(ctx, args, stdout, stderr)
	}
	fs := flag.NewFlagSet("dao-review "+op, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dao := fs.String("dao", "", "DAO namespace (locally asserted, not on-chain membership proof)")
	proposal := fs.String("proposal", "", "immutable proposal identifier")
	epoch := fs.Uint64("epoch", 0, "explicit membership/proposal epoch")
	threshold := fs.Int("threshold", 0, "strict-majority approval threshold")
	evidence := fs.String("evidence-file", "", "private evidence bytes (16 KiB maximum)")
	policy := fs.String("policy-file", "", "private policy bytes (must fit packet with manifest in 8 KiB)")
	out := fs.String("out", "", "exclusively created private manifest/certificate output")
	id := fs.String("id", "", "reviewer's handoff ID")
	expected := fs.String("expect-review-hash", "", "independently authenticated exact signed review hash")
	certFile := fs.String("certificate", "", "certificate JSON to verify offline")
	artifact := fs.String("artifact", "", "explicit plaintext export: brief, policy, or result (signed decision)")
	approve := fs.Bool("approve", false, "explicitly approve exact immutable proposal")
	reject := fs.Bool("reject", false, "explicitly reject exact immutable proposal")
	deadline := fs.Duration("deadline", 48*time.Hour, "review deadline from creation")
	expires := fs.Duration("expires", 168*time.Hour, "retention/certificate expiry (maximum 720h, later than deadline)")
	var targets multiStringFlag
	fs.Var(&targets, "to", "pinned reviewer nickname/address (repeat)")
	incidentCommon(fs)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("dao-review: unexpected positional arguments")
	}
	switch op {
	case "create", "decide", "status", "certificate", "verify", "export":
	default:
		return fmt.Errorf("dao-review: unknown command %q", op)
	}
	if op == "verify" {
		raw, err := bounds.ReadBound(*certFile, daoreview.MaxCertificate)
		if err != nil {
			return err
		}
		c, err := daoreview.DecodeCertificate(raw, *expected, time.Now())
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "verified: %s\nreview hash: %s\nscoped human approval evidence only; no membership discovery, execution, or spending authority\n", c.Summary(), c.Review.Hash())
		return err
	}
	if err := loadConfigForFlags(fs); err != nil {
		return err
	}
	local, identity, st, err := openHandoffLocal(fs)
	if err != nil {
		return err
	}
	defer crypto.Zero(identity)
	if op == "export" {
		r, err := st.Get(*id, time.Now())
		if err != nil {
			return err
		}
		if r.Local != local {
			return errors.New("dao-review: record belongs to another identity")
		}
		packet, err := daoreview.FromBrief(r.Events[0])
		if err != nil {
			return err
		}
		var data []byte
		switch *artifact {
		case "brief":
			data = r.Events[0].Message.Content
		case "policy":
			data = packet.Policy
		case "result":
			if _, err := daoreview.DecisionFromRecord(r); err != nil {
				return err
			}
			data = r.Events[1].Message.Content
		default:
			return errors.New("dao-review export requires -artifact brief|policy|result")
		}
		if err := daoWriteBytes(*out, data); err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, "exported plaintext review artifact; this copy is outside encrypted retention")
		return err
	}
	if op == "status" || op == "certificate" {
		rows, err := st.List(time.Now())
		if err != nil {
			return err
		}
		groups := map[string][]handoff.Record{}
		order := []string{}
		for _, r := range rows {
			if r.Local != local || r.Events[0].Message.Terms.Registration.Source != "local-dao-review" {
				continue
			}
			p, err := daoreview.FromBrief(r.Events[0])
			if err != nil {
				return err
			}
			h := p.Review.Hash()
			if _, ok := groups[h]; !ok {
				order = append(order, h)
			}
			groups[h] = append(groups[h], r)
		}
		if op == "certificate" {
			records := groups[*expected]
			if len(records) == 0 {
				return errors.New("dao-review: no local review matches trusted hash")
			}
			packet, err := daoreview.FromBrief(records[0].Events[0])
			if err != nil {
				return err
			}
			if packet.Review.Manifest.Coordinator != local {
				return errors.New("dao-review: only the coordinator collects this roster's decisions")
			}
			var decisions []daoreview.SignedDecision
			seen := map[string]bool{}
			for _, r := range records {
				if len(r.Events) < 2 {
					continue
				}
				d, err := daoreview.DecisionFromRecord(r)
				if err != nil {
					return err
				}
				if seen[d.Decision.Reviewer.Pinned] {
					return errors.New("dao-review: duplicate reviewer records")
				}
				seen[d.Decision.Reviewer.Pinned] = true
				decisions = append(decisions, d)
			}
			c, err := daoreview.NewCertificate(packet.Review, decisions, time.Now())
			if err != nil {
				return err
			}
			if err := c.Verify(*expected, time.Now()); err != nil {
				return err
			}
			if err := daoWriteNew(*out, c); err != nil {
				return err
			}
			_, err = fmt.Fprintf(stdout, "quorum certificate exported: %s\n%s\nreview hash: %s\nno execution or spending performed\n", *out, c.Summary(), *expected)
			return err
		}
		if len(order) == 0 {
			_, err = fmt.Fprintln(stdout, "no active DAO reviews; expired reviews are pruned on access")
			return err
		}
		for _, h := range order {
			records := groups[h]
			p, err := daoreview.FromBrief(records[0].Events[0])
			if err != nil {
				return err
			}
			m := p.Review.Manifest
			approvals, rejections := 0, 0
			choices := map[string]string{}
			for _, r := range records {
				if len(r.Events) > 1 {
					d, err := daoreview.DecisionFromRecord(r)
					if err != nil {
						return err
					}
					if choices[d.Decision.Reviewer.Pinned] != "" {
						return errors.New("dao-review: duplicate reviewer records")
					}
					choices[d.Decision.Reviewer.Pinned] = d.Decision.Choice
					if d.Decision.Choice == "approve" {
						approvals++
					} else {
						rejections++
					}
				}
			}
			state := "awaiting-decisions"
			if approvals >= m.Threshold {
				state = "approval-quorum-met"
			} else if rejections > len(m.Reviewers)-m.Threshold {
				state = "approval-quorum-impossible"
			} else if time.Now().Unix() >= m.Deadline {
				state = "deadline-closed-no-quorum"
			}
			if local != m.Coordinator {
				state = "reviewer-local-view (not a global tally)"
			}
			fmt.Fprintf(stdout, "%s/%s epoch %d\nreview hash: %s\nstatus: %s; approvals %d/%d; rejects %d; deadline %s\n", m.DAO, m.Proposal, m.Epoch, h, state, approvals, m.Threshold, rejections, time.Unix(m.Deadline, 0).UTC().Format(time.RFC3339))
			if local == m.Coordinator {
				for _, peer := range m.Reviewers {
					choice := choices[peer.Pinned]
					if choice == "" {
						choice = "missing decision"
					}
					fmt.Fprintf(stdout, "  reviewer %s: %s\n", peer.Address, choice)
				}
			}
			for _, r := range records {
				fmt.Fprintf(stdout, "  handoff %s\n", r.Events[0].Message.Terms.ID)
				for _, d := range r.Outbox {
					fmt.Fprintf(stdout, "    %s\n", r.DeliveryStatus(d))
				}
			}
		}
		return nil
	}
	ep, _, err := newDurableEndpointFromFlags(fs)
	if err != nil {
		return err
	}
	defer closeBodyStore(ep.Store)
	db, err := handoffContacts(fs)
	if err != nil {
		return err
	}
	if err := (&e2Ingestor{ep: ep, ik: identity, mdb: db, handoffStore: st, handoffLocal: local}).recoverHandoffReceive(); err != nil {
		return err
	}
	if op == "decide" {
		if *approve == *reject {
			return errors.New("dao-review decide requires exactly one of -approve or -reject")
		}
		r, err := st.Get(*id, time.Now())
		if err != nil {
			return err
		}
		if r.Local != local || len(r.Events) != 1 {
			return errors.New("dao-review: not a fresh invitation for this identity; decisions are final")
		}
		p, err := daoreview.FromBrief(r.Events[0])
		if err != nil {
			return err
		}
		if p.Review.Hash() != *expected {
			return errors.New("dao-review: invitation differs from independently trusted review hash")
		}
		choice := "reject"
		if *approve {
			choice = "approve"
		}
		d, err := daoreview.SignDecision(r.Events[0], local, choice, identity, time.Now())
		if err != nil {
			return err
		}
		if err := authorizeHandoffPeer(ep, db, p.Review.Manifest.Coordinator, r.Session); err != nil {
			return err
		}
		raw, err := json.Marshal(d)
		if err != nil {
			return err
		}
		eventID, err := handoff.NewID()
		if err != nil {
			return err
		}
		msg := handoff.Message{Version: 1, Terms: r.Events[0].Message.Terms, EventID: eventID, Sequence: 2, Previous: r.Events[0].Hash(), Kind: "deliver", Content: raw, ResultHash: handoff.Commitment(raw)}
		e, err := handoff.Sign(msg, identity)
		if err != nil {
			return err
		}
		if err := st.Apply(e, local, r.Session, true, time.Now()); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "DAO review %s: %s signed and queued; run dao-review flush\nno execution or spending performed\n", p.Review.Hash(), choice)
		return err
	}
	if len(targets) < 1 || len(targets) > daoreview.MaxReviewers || *deadline <= 0 || *expires <= *deadline || *expires > 720*time.Hour {
		return errors.New("dao-review: select 1..16 reviewers, positive deadline, and expiry after deadline up to 720h")
	}
	rawEvidence, err := bounds.ReadBound(*evidence, handoff.MaxContent)
	if err != nil {
		return err
	}
	defer crypto.Zero(rawEvidence)
	rawPolicy, err := bounds.ReadBound(*policy, handoff.MaxPolicy)
	if err != nil {
		return err
	}
	defer crypto.Zero(rawPolicy)
	if len(rawEvidence) == 0 || len(rawPolicy) == 0 {
		return errors.New("dao-review: evidence and policy must not be empty")
	}
	reviewID, err := handoff.NewID()
	if err != nil {
		return err
	}
	now := time.Now()
	m := daoreview.Manifest{Version: 1, ID: reviewID, DAO: *dao, Proposal: *proposal, Epoch: *epoch, Coordinator: local, EvidenceHash: handoff.Commitment(rawEvidence), PolicyHash: handoff.Commitment(rawPolicy), Threshold: *threshold, CreatedAt: now.Unix(), Deadline: now.Add(*deadline).Unix(), ExpiresAt: now.Add(*expires).Unix()}
	sessions := map[string]string{}
	for _, target := range targets {
		c, err := resolveIncidentContact(db, target)
		if err != nil {
			return err
		}
		sid, err := incidentSession(ep, c)
		if err != nil {
			return err
		}
		peer := handoff.Peer{Address: c.Address, Pinned: strings.ToLower(c.Pinned)}
		session := hex.EncodeToString(sid[:])
		if err := authorizeHandoffPeer(ep, db, peer, session); err != nil {
			return err
		}
		m.Reviewers = append(m.Reviewers, peer)
		sessions[peer.Pinned] = session
	}
	signed, err := daoreview.SignManifest(m, identity)
	if err != nil {
		return err
	}
	packet, err := daoreview.EncodePacket(daoreview.Packet{Review: signed, Policy: rawPolicy})
	if err != nil {
		return err
	}
	var events []handoff.Envelope
	var sessionList []string
	for _, peer := range signed.Manifest.Reviewers {
		id := daoreview.InvitationID(signed, peer)
		eventID, err := handoff.NewID()
		if err != nil {
			return err
		}
		reg := handoff.Registration{Source: "local-dao-review", Version: 1, ObservedAt: now.Unix(), Objective: sporrelay.WorkOrder{ObjectiveID: "dao-review:" + reviewID, OwnerPseudonym: local.Pinned, DescriptionCommitment: m.EvidenceHash, PolicyHash: handoff.Commitment(packet)}}
		msg := handoff.Message{Version: 1, Terms: handoff.Terms{ID: id, Registration: reg, Buyer: local, Provider: peer, ExpiresAt: m.ExpiresAt}, EventID: eventID, Sequence: 1, Kind: "brief", Content: rawEvidence, Policy: packet}
		e, err := handoff.Sign(msg, identity)
		if err != nil {
			return err
		}
		events = append(events, e)
		sessionList = append(sessionList, sessions[peer.Pinned])
	}
	if err := daoWriteNew(*out, signed); err != nil {
		return err
	}
	if err := st.ApplyBatch(events, local, sessionList, now); err != nil {
		_ = os.Remove(*out)
		return err
	}
	_, err = fmt.Fprintf(stdout, "DAO review queued atomically for %d reviewers\nreview hash: %s\nmanifest: %s\nshare this hash through the DAO's independently authenticated governance channel\nrun dao-review flush explicitly; no remote registration/execution/spending performed\n", len(events), signed.Hash(), *out)
	return err
}

func daoWriteNew(path string, v any) error {
	if path == "" || path == "-" {
		return errors.New("dao-review: -out NEW_FILE is required (no stdout artifact export)")
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > daoreview.MaxCertificate {
		return errors.New("dao-review: artifact exceeds size cap")
	}
	return daoWriteBytes(path, append(raw, '\n'))
}

func daoWriteBytes(path string, raw []byte) error {
	if path == "" || path == "-" {
		return errors.New("dao-review: -out NEW_FILE is required (no stdout artifact export)")
	}
	if len(raw) > daoreview.MaxCertificate {
		return errors.New("dao-review: artifact exceeds size cap")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(raw); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
