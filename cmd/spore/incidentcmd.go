package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/incident"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
)

func incidentCmd(args []string) {
	if len(args) == 0 {
		incidentUsage()
		return
	}
	switch args[0] {
	case "create":
		incidentCreate(args[1:])
	case "invite":
		incidentInvite(args[1:])
	case "reply":
		incidentReply(args[1:])
	case "list":
		incidentList(args[1:])
	case "show":
		incidentShow(args[1:])
	case "resolve":
		incidentResolve(args[1:])
	case "flush":
		incidentFlush(args[1:])
	case "-h", "--help", "help":
		incidentUsage()
	default:
		fmt.Fprintf(os.Stderr, "incident: unknown command %q\n", args[0])
		incidentUsage()
		os.Exit(2)
	}
}

func incidentUsage() {
	fmt.Fprintln(os.Stderr, `usage: spore incident create -summary TEXT -deadline 15m -expires 24h -quorum N [-details-file F]
       spore incident invite -id ID -to CONTACT [-to CONTACT ...]
       spore incident reply -id ID -ack| -decline
       spore incident list | show -id ID | resolve -id ID | flush

All commands take the normal E2 carrier/store flags plus -identity, -state-dir,
-state-key, and -maildb. An established authenticated session to each pinned
contact is required; incidents never bootstrap or downgrade an E2 session.`)
}

func incidentCommon(fs *flag.FlagSet) {
	e2Common(fs)
	fs.String("identity", "", "local E2 identity private key file")
}

func incidentAddress(fs *flag.FlagSet) string {
	if address := flagValueOr(fs, "incident-address", ""); address != "" {
		return address
	}
	return flagValueOr(fs, "address", "")
}

func openIncidentLocal(fs *flag.FlagSet) (*incident.Store, []byte, []byte, error) {
	stateDir, stateKeyFile := flagValueOr(fs, "state-dir", ""), flagValueOr(fs, "state-key", "")
	if stateDir == "" || stateKeyFile == "" {
		return nil, nil, nil, errors.New("incident requires -state-dir and -state-key")
	}
	identityPath := flagValueOr(fs, "identity", "")
	if identityPath == "" {
		return nil, nil, nil, errors.New("incident requires -identity")
	}
	key, err := readHexFile(stateKeyFile, 32)
	if err != nil {
		return nil, nil, nil, err
	}
	identity, err := readHexFile(identityPath, 32)
	if err != nil {
		return nil, nil, nil, err
	}
	st, err := incident.Open(filepath.Join(stateDir, "incidents.enc"), key)
	if err != nil {
		return nil, nil, nil, err
	}
	return st, identity, key, nil
}

func openIncidentEndpoint(fs *flag.FlagSet) (*incident.Store, *ratchetwire.DurableEndpoint, []byte, error) {
	st, identity, _, err := openIncidentLocal(fs)
	if err != nil {
		return nil, nil, nil, err
	}
	ep, _, err := newDurableEndpointFromFlags(fs)
	if err != nil {
		return nil, nil, nil, err
	}
	return st, ep, identity, nil
}

func incidentContacts(fs *flag.FlagSet) *maildb.MailDB {
	path := flagValueOr(fs, "maildb", "")
	if path == "" {
		if cfg, err := LoadConfig(configPath(flagValueOr(fs, "config", ""))); err == nil && cfg != nil {
			path = cfg.Maildb
		}
	}
	if path == "" {
		check(errors.New("incident requires -maildb or maildb in config.json"))
	}
	db, err := maildb.Open(path)
	check(err)
	return db
}

func resolveIncidentContact(db *maildb.MailDB, name string) (maildb.Contact, error) {
	if c, ok := db.Contact(name); ok {
		if c.Pinned != "" {
			return c, nil
		}
	}
	if c, ok := contactByNickname(db, name); ok && c.Pinned != "" {
		return c, nil
	}
	return maildb.Contact{}, fmt.Errorf("%q is not a pinned mail contact", name)
}

func incidentSession(ep *ratchetwire.DurableEndpoint, contact maildb.Contact) ([8]byte, error) {
	if contact.Bundle == nil {
		return [8]byte{}, fmt.Errorf("%s has no verified prekey bundle; add this contact from a signed invite", contact.Address)
	}
	pin, err := hex.DecodeString(contact.Pinned)
	if err != nil || len(pin) != 32 || contact.Bundle.Verify(pin) != nil {
		return [8]byte{}, fmt.Errorf("%s contact bundle does not verify against its pinned key", contact.Address)
	}
	for _, sid := range ep.Sessions.IDs() {
		session := ep.Sessions.Get(sid)
		if session == nil {
			continue
		}
		peerIK, ok := session.PeerIdentity()
		if ok && peerIK == contact.Bundle.IKPub {
			return sid, nil
		}
	}
	return [8]byte{}, fmt.Errorf("no established E2 session for %s; send or receive a regular E2 message first", contact.Address)
}

func incidentCreate(args []string) {
	fs := flag.NewFlagSet("incident create", flag.ExitOnError)
	summary := fs.String("summary", "", "short incident description")
	detailsFile := fs.String("details-file", "", "private details file (max 16 KiB; omit for none)")
	deadline := fs.Duration("deadline", 15*time.Minute, "response deadline from now")
	expires := fs.Duration("expires", 24*time.Hour, "incident expiry from now")
	quorum := fs.Int("quorum", 1, "number of acknowledgements required to record quorum")
	var recipients multiStringFlag
	fs.Var(&recipients, "to", "pinned contact nickname or address (repeat for each responder)")
	incidentCommon(fs)
	_ = fs.Parse(args)
	check(loadConfigForFlags(fs))
	st, identity, _, err := openIncidentLocal(fs)
	check(err)
	if len(recipients) == 0 {
		check(errors.New("incident create requires one or more -to pinned contacts"))
	}
	mdb := incidentContacts(fs)
	ep, _, err := newDurableEndpointFromFlags(fs)
	check(err)
	var details []byte
	if *detailsFile != "" {
		details, err = os.ReadFile(*detailsFile)
		check(err)
	}
	pub, err := secure.SigPubOf(identity)
	check(err)
	address := incidentAddress(fs)
	if address == "" || *summary == "" || *deadline <= 0 || *expires <= *deadline || *quorum < 1 {
		check(errors.New("incident create requires a local -incident-address, -summary, positive -deadline, -expires greater than -deadline, and positive -quorum"))
	}
	if *quorum > len(recipients) {
		check(errors.New("incident create quorum cannot exceed the number of selected responders"))
	}
	responders := make([]incident.Responder, 0, len(recipients))
	seen := make(map[string]bool)
	for _, target := range recipients {
		contact, err := resolveIncidentContact(mdb, target)
		check(err)
		if seen[strings.ToLower(contact.Address)] {
			check(fmt.Errorf("incident create: duplicate responder %s", contact.Address))
		}
		seen[strings.ToLower(contact.Address)] = true
		sid, err := incidentSession(ep, contact)
		check(err)
		responders = append(responders, incident.Responder{Address: contact.Address, Pinned: contact.Pinned, Session: hex.EncodeToString(sid[:]), Status: incident.Invited})
	}
	now := time.Now()
	r, err := st.Create(address, hex.EncodeToString(pub), *summary, string(details), now.Add(*deadline), now.Add(*expires), *quorum, responders, now)
	check(err)
	if err := st.FinalizeSelection(r.ID); err != nil {
		check(err)
	}
	fmt.Printf("incident %s created with %d selected responder(s); deliver invitations with `spore incident invite -id %s -to CONTACT`\n", r.ID, len(responders), r.ID)
}

func incidentInvite(args []string) {
	fs := flag.NewFlagSet("incident invite", flag.ExitOnError)
	id := fs.String("id", "", "incident ID")
	var recipients multiStringFlag
	fs.Var(&recipients, "to", "contact nickname or address (repeat for each responder)")
	incidentCommon(fs)
	_ = fs.Parse(args)
	check(loadConfigForFlags(fs))
	if *id == "" || len(recipients) == 0 {
		check(errors.New("incident invite requires -id and one or more -to contacts"))
	}
	st, ep, identity, err := openIncidentEndpoint(fs)
	check(err)
	defer closeBodyStore(ep.Store)
	mdb := incidentContacts(fs)
	record, err := st.Get(*id, time.Now())
	check(err)
	pub, err := secure.SigPubOf(identity)
	check(err)
	if record.CreatorPinned != hex.EncodeToString(pub) {
		check(errors.New("incident invite: local signing identity does not own this incident"))
	}
	if !record.SelectionFinalized {
		check(errors.New("incident invite: finalize responder selection before sending invitations"))
	}
	carrier, err := e2Carrier(fs)
	check(err)
	for _, target := range recipients {
		contact, err := resolveIncidentContact(mdb, target)
		check(err)
		sessionID, err := incidentSession(ep, contact)
		check(err)
		eventID, err := incident.NewEventID()
		check(err)
		msg := incident.Message{Version: incident.Version, Type: "invite", IncidentID: record.ID, EventID: eventID, Creator: record.Creator, CreatorPinned: record.CreatorPinned, Sender: record.Creator, SenderPinned: record.CreatorPinned, Recipient: contact.Address, RecipientPinned: contact.Pinned, Summary: record.Summary, Details: record.Details, Deadline: record.Deadline, ExpiresAt: record.ExpiresAt, Required: record.Required}
		payload, err := incident.SignMessage(msg, identity)
		check(err)
		if _, err := st.AddInviteOutbox(record.ID, eventID, incident.Peer{Address: contact.Address, Pinned: contact.Pinned}, hex.EncodeToString(sessionID[:]), payload, time.Now()); err != nil {
			check(err)
		}
		fmt.Printf("invitation queued for %s (%x)\n", contact.Address, sessionID)
	}
	if err := (&e2Ingestor{incidentStore: st, ep: ep}).sendIncidentOutbox(carrier); err != nil {
		fmt.Fprintln(os.Stderr, "incident outbox:", err)
	}
}

func incidentReply(args []string) {
	fs := flag.NewFlagSet("incident reply", flag.ExitOnError)
	id := fs.String("id", "", "incident ID")
	ack := fs.Bool("ack", false, "acknowledge incident")
	decline := fs.Bool("decline", false, "decline incident")
	incidentCommon(fs)
	_ = fs.Parse(args)
	check(loadConfigForFlags(fs))
	if *id == "" || *ack == *decline {
		check(errors.New("incident reply requires -id and exactly one of -ack or -decline"))
	}
	st, ep, identity, err := openIncidentEndpoint(fs)
	check(err)
	defer closeBodyStore(ep.Store)
	mdb := incidentContacts(fs)
	r, err := st.Get(*id, time.Now())
	check(err)
	myAddress := incidentAddress(fs)
	if len(r.Responders) != 1 || r.Responders[0].Address != myAddress {
		check(errors.New("incident reply: local identity is not an invitee on this incident"))
	}
	pub, err := secure.SigPubOf(identity)
	check(err)
	if !strings.EqualFold(hex.EncodeToString(pub), r.Responders[0].Pinned) {
		check(errors.New("incident reply: local identity key does not match the invitee's pinned signing key"))
	}
	creator, err := resolveIncidentContact(mdb, r.Creator)
	check(err)
	if !strings.EqualFold(r.CreatorPinned, creator.Pinned) {
		check(errors.New("incident reply: creator pin differs from the locally pinned contact"))
	}
	sid, err := incidentSession(ep, creator)
	check(err)
	if hex.EncodeToString(sid[:]) != r.Responders[0].Session {
		check(errors.New("incident reply: saved E2 session does not match the pinned creator"))
	}
	eventID, err := incident.NewEventID()
	check(err)
	status, typ := incident.Acked, "ack"
	if *decline {
		status, typ = incident.Declined, "decline"
	}
	msg := incident.Message{Version: incident.Version, Type: typ, IncidentID: r.ID, EventID: eventID, Creator: r.Creator, CreatorPinned: r.CreatorPinned, Sender: r.Responders[0].Address, SenderPinned: hex.EncodeToString(pub), Recipient: r.Creator, RecipientPinned: r.CreatorPinned}
	payload, err := incident.SignMessage(msg, identity)
	check(err)
	if err := st.QueueResponse(r.ID, msg.Sender, msg.SenderPinned, status, eventID, msg.Recipient, msg.RecipientPinned, hex.EncodeToString(sid[:]), payload, time.Now()); err != nil {
		check(err)
	}
	carrier, err := e2Carrier(fs)
	check(err)
	if err := (&e2Ingestor{incidentStore: st, ep: ep}).sendIncidentOutbox(carrier); err != nil {
		fmt.Fprintln(os.Stderr, "incident outbox:", err)
	}
}

func incidentList(args []string) {
	fs := flag.NewFlagSet("incident list", flag.ExitOnError)
	incidentCommon(fs)
	_ = fs.Parse(args)
	check(loadConfigForFlags(fs))
	st, ep, _, err := openIncidentEndpoint(fs)
	check(err)
	defer closeBodyStore(ep.Store)
	rows, err := st.List(time.Now())
	check(err)
	if len(rows) == 0 {
		fmt.Println("no incidents")
		return
	}
	for _, r := range rows {
		fmt.Printf("%s\t%s\t%s\t%d/%d responders\t%s\n", r.ID, r.Status, r.Summary, countAcked(r), r.Required, time.Unix(r.ExpiresAt, 0).Format(time.RFC3339))
	}
}

func incidentShow(args []string) {
	fs := flag.NewFlagSet("incident show", flag.ExitOnError)
	id := fs.String("id", "", "incident ID")
	incidentCommon(fs)
	_ = fs.Parse(args)
	check(loadConfigForFlags(fs))
	if *id == "" {
		check(errors.New("incident show requires -id"))
	}
	st, ep, _, err := openIncidentEndpoint(fs)
	check(err)
	defer closeBodyStore(ep.Store)
	r, err := st.Get(*id, time.Now())
	check(err)
	fmt.Printf("incident %s: %s\ncreator: %s\nstatus: %s\nquorum: %d/%d\ndeadline: %s\nexpires: %s\n", r.ID, r.Summary, r.Creator, r.Status, countAcked(r), r.Required, time.Unix(r.Deadline, 0).Format(time.RFC3339), time.Unix(r.ExpiresAt, 0).Format(time.RFC3339))
	if r.Details != "" {
		fmt.Printf("details: %s\n", r.Details)
	}
	for _, p := range r.Responders {
		fmt.Printf("responder %s %s\n", p.Address, p.Status)
	}
	for _, event := range r.Events {
		fmt.Printf("%s %s %s\n", time.Unix(event.At, 0).Format(time.RFC3339), event.Kind, event.Actor)
	}
}

func incidentResolve(args []string) {
	fs := flag.NewFlagSet("incident resolve", flag.ExitOnError)
	id := fs.String("id", "", "incident ID")
	incidentCommon(fs)
	_ = fs.Parse(args)
	check(loadConfigForFlags(fs))
	if *id == "" {
		check(errors.New("incident resolve requires -id"))
	}
	st, ep, identity, err := openIncidentEndpoint(fs)
	check(err)
	defer closeBodyStore(ep.Store)
	pub, err := secure.SigPubOf(identity)
	check(err)
	r, err := st.Get(*id, time.Now())
	check(err)
	if !strings.EqualFold(r.CreatorPinned, hex.EncodeToString(pub)) {
		check(errors.New("incident resolve: current signing identity is not the creator"))
	}
	r, err = st.Resolve(*id, r.Creator, time.Now())
	check(err)
	fmt.Printf("incident %s resolved\n", r.ID)
}

func incidentFlush(args []string) {
	fs := flag.NewFlagSet("incident flush", flag.ExitOnError)
	incidentCommon(fs)
	_ = fs.Parse(args)
	check(loadConfigForFlags(fs))
	st, ep, _, err := openIncidentEndpoint(fs)
	check(err)
	defer closeBodyStore(ep.Store)
	carrier, err := e2Carrier(fs)
	check(err)
	if err := (&e2Ingestor{incidentStore: st, ep: ep}).sendIncidentOutbox(carrier); err != nil {
		check(err)
	}
	fmt.Println("incident outbox drained")
}

func countAcked(r incident.Record) int {
	n := 0
	for _, p := range r.Responders {
		if p.Status == incident.Acked {
			n++
		}
	}
	return n
}

type multiStringFlag []string

func (m *multiStringFlag) String() string { return strings.Join(*m, ",") }
func (m *multiStringFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("empty value")
	}
	*m = append(*m, value)
	return nil
}
