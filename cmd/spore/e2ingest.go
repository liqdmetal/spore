package main

// e2Ingestor is the SINGLE E2 frame-ingestion pipeline, shared by the chain
// watcher (msg recv-e2) and the relay-fabric drain loop (spore fabric
// subscribe, slice F2). It is the mechanical extraction of msgRecvE2's
// handleFrame closure: decryption, receipts, money envelopes, attachments,
// maildb indexing, notifications, and auto-ack happen in exactly ONE place —
// two decrypt paths would be a security surface, not just duplication.
//
// The fabric seam (WIRE_SPEC §8, RELAY_FABRIC "bootstrap fence"): fabric
// drain refuses FrameInit. A brand-new session's handshake pointer can only
// be recognized on-chain (the recipient cannot pre-derive a handle for a sid
// it has never seen), so bootstrap rides the chain carrier by design. The
// fence also closes a real attack: a hostile relay could replay a REAL
// chain-visible init pointer at a fabric handle; ingesting it here would
// consume a one-time prekey and break the later chain-side decrypt of the
// same handshake. FrameMessage continuations are the fabric's cargo.

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/incident"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/notify"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/receipts"
	"github.com/liqdmetal/spore/internal/secure"
)

type e2Ingestor struct {
	st            ratchetwire.BodyStore
	ep            *ratchetwire.DurableEndpoint
	ik, sk        []byte
	op            *[32]byte
	pool          *ratchetwire.OPKPool
	incidentStore *incident.Store
	handoffStore  *handoff.Store
	handoffLocal  handoff.Peer
	stateDir      string
	creator       string
	creatorPinned string
	carrier       ratchetwire.ChainCarrier
	ackCtx        context.Context // context for auto-ack pointer posts
	outDir        string
	receipts      string // receipts ledger path ("" disables)
	mdb           *maildb.MailDB
	dispatcher    *notify.Dispatcher // nil disables notifications
	autoAck       bool
	ackTTL        time.Duration
}

func (g *e2Ingestor) incidentPeer(sid [8]byte) (maildb.Contact, []byte, error) {
	if g.mdb == nil || g.ep == nil {
		return maildb.Contact{}, nil, errors.New("incident: authenticated pinned contact store is unavailable")
	}
	session := g.ep.Sessions.Get(sid)
	if session == nil {
		return maildb.Contact{}, nil, errors.New("incident: unknown E2 session")
	}
	peerIK, ok := session.PeerIdentity()
	if !ok {
		return maildb.Contact{}, nil, errors.New("incident: E2 session lacks authenticated peer identity; establish a new session")
	}
	var match maildb.Contact
	var pin []byte
	for _, contact := range g.mdb.Contacts() {
		if contact.Bundle == nil || contact.Bundle.IKPub != peerIK {
			continue
		}
		candidate, err := hex.DecodeString(contact.Pinned)
		if err != nil || len(candidate) != 32 || contact.Bundle.Verify(candidate) != nil {
			continue
		}
		if match.Address != "" {
			return maildb.Contact{}, nil, errors.New("incident: session identity ambiguously matches multiple contacts")
		}
		match, pin = contact, candidate
	}
	if match.Address == "" {
		return maildb.Contact{}, nil, errors.New("incident: E2 peer is not an authenticated pinned contact")
	}
	return match, pin, nil
}

func (g *e2Ingestor) handleIncident(_ chain.Incoming, sid [8]byte, plain []byte) bool {
	if !incident.IsIncidentEnvelope(plain) {
		return false
	}
	if g.incidentStore == nil || g.creator == "" || g.creatorPinned == "" {
		fmt.Fprintln(os.Stderr, "incident: message received but local identity/address is not configured (-incident-address and -state-key required)")
		return true
	}

	contact, pinned, err := g.incidentPeer(sid)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return true
	}

	msg, err := incident.DecodeSignedMessage(plain, pinned)
	if err != nil {
		fmt.Fprintln(os.Stderr, "incident: rejected signed message:", err)
		return true
	}

	if msg.Sender != contact.Address || !strings.EqualFold(msg.SenderPinned, contact.Pinned) {
		fmt.Fprintln(os.Stderr, "incident: authenticated E2 peer does not match message sender")
		return true
	}

	if msg.Recipient != g.creator || !strings.EqualFold(msg.RecipientPinned, g.creatorPinned) {
		fmt.Fprintln(os.Stderr, "incident: message is not addressed to this local identity")
		return true
	}

	if msg.Type == "invite" {
		if msg.Creator != contact.Address || !strings.EqualFold(msg.CreatorPinned, contact.Pinned) {
			fmt.Fprintln(os.Stderr, "incident: invitation creator does not match authenticated E2 peer")
			return true
		}
		if _, err := g.incidentStore.ImportInvitation(msg, g.creator, g.creatorPinned, hex.EncodeToString(sid[:]), time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "incident: invitation refused:", err)
			return true
		}
		fmt.Printf("incident %s invited: %s (from %s)\n", msg.IncidentID, msg.Summary, contact.Address)
		return true
	}

	if msg.Creator != g.creator || !strings.EqualFold(msg.CreatorPinned, g.creatorPinned) {
		fmt.Fprintln(os.Stderr, "incident: response does not target this incident creator")
		return true
	}

	status := incident.Acked
	if msg.Type == "decline" {
		status = incident.Declined
	}
	r, err := g.incidentStore.Respond(msg.IncidentID, contact.Address, hex.EncodeToString(pinned), status, msg.EventID, hex.EncodeToString(sid[:]), time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "incident: response refused:", err)
		return true
	}

	fmt.Printf("incident %s: %s from %s; status %s\n", r.ID, msg.Type, contact.Address, r.Status)
	return true
}

// sendIncidentOutbox retries the exact prepared pointer after a transport
// failure. It persists a preparation marker before advancing the ratchet, so
// a crash before the opaque pointer is durably saved blocks the outbox instead
// of silently encrypting the same event at a later ratchet position.
func (g *e2Ingestor) sendIncidentOutbox(c ratchetwire.ChainCarrier) error {
	if g.incidentStore == nil || g.ep == nil {
		return errors.New("incident: outbox requires an open encrypted store and E2 endpoint")
	}
	rows, err := g.incidentStore.List(time.Now())
	if err != nil {
		return err
	}
	device, err := ratchetwire.LoadOrCreateDevice(g.ep.StateDir())
	if err != nil {
		return err
	}
	var failures []string
	for _, record := range rows {
		pending, err := g.incidentStore.Pending(record.ID)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		for _, entry := range pending {
			sidRaw, err := hex.DecodeString(entry.Session)
			if err != nil || len(sidRaw) != 8 {
				failures = append(failures, fmt.Sprintf("%s: invalid session ID", entry.EventID))
				continue
			}
			var sid [8]byte
			copy(sid[:], sidRaw)
			if err := ratchetwire.CheckSendAllowed(g.ep.StateDir(), sid, device); err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", entry.EventID, err))
				continue
			}
			preparedNow := len(entry.Pointer) == 0
			if preparedNow {
				if entry.Accounted || entry.Preparing {
					failures = append(failures, fmt.Sprintf("%s: pointer preparation was interrupted after it was durably started; refusing to advance the ratchet again", entry.EventID))
					continue
				}
				if time.Now().Unix() >= record.ExpiresAt {
					failures = append(failures, fmt.Sprintf("%s: expired before pointer preparation", entry.EventID))
					continue
				}
				if err := g.incidentStore.BeginDeliveryPreparation(record.ID, entry.EventID); err != nil {
					failures = append(failures, fmt.Sprintf("%s: start pointer preparation: %v", entry.EventID, err))
					continue
				}
				_, pointer, err := g.ep.SendNext(sid, entry.Payload, time.Unix(record.ExpiresAt, 0))
				if err != nil {
					failures = append(failures, fmt.Sprintf("%s: prepare: %v", entry.EventID, err))
					continue
				}
				if err := g.incidentStore.PrepareDelivery(record.ID, entry.EventID, entry.Session, pointer); err != nil {
					failures = append(failures, fmt.Sprintf("%s: persist prepared pointer: %v", entry.EventID, err))
					continue
				}
				entry.Pointer = pointer
			}
			if !entry.Accounted {
				if err := ratchetwire.RecordSendOnce(g.ep.StateDir(), sid, device, entry.EventID); err != nil {
					failures = append(failures, fmt.Sprintf("%s: record device send: %v", entry.EventID, err))
					continue
				}
				if err := g.incidentStore.MarkAccounted(record.ID, entry.EventID); err != nil {
					failures = append(failures, fmt.Sprintf("%s: record send accounting: %v", entry.EventID, err))
					continue
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			_, err = c.PostPointer(ctx, entry.Recipient, entry.Pointer, 1)
			cancel()
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: delivery pending: %v", entry.EventID, err))
				continue
			}
			if err := g.incidentStore.MarkSent(record.ID, entry.EventID); err != nil {
				failures = append(failures, fmt.Sprintf("%s: delivered but status not saved: %v", entry.EventID, err))
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d incident delivery item(s) remain pending: %s", len(failures), strings.Join(failures, "; "))
	}
	return nil
}

// ingest processes one successfully fetched frame. fromFabric marks pointers
// delivered by the relay-fabric drain (spore fabric subscribe) rather than
// the chain watcher; it exists ONLY to enforce the FrameInit fence — every
// other step is byte-identical for both transports.
func (g *e2Ingestor) ingest(inc chain.Incoming, frame ratchetwire.Frame, p ratchetwire.Pointer, fromFabric bool) {
	if fromFabric && frame.Kind == ratchetwire.FrameInit {
		// Bootstrap fence (see file comment): first contact never rides the
		// fabric. Refuse BEFORE any prekey state is touched.
		fmt.Fprintf(os.Stderr, "e2 fabric: init frame refused on fabric path (bootstrap rides the chain) cid %x\n", p.CID)
		return
	}
	if err := g.recoverHandoffReceive(); err != nil {
		fmt.Fprintln(os.Stderr, "handoff: receive recovery pending:", err)
		return
	}
	var plain []byte
	var decErr error
	switch frame.Kind {
	case ratchetwire.FrameInit:
		body, bodyErr := ratchetwire.GetBody(g.st, p, time.Now())
		if bodyErr != nil {
			fmt.Fprintln(os.Stderr, "e2 frame:", bodyErr)
			return
		}
		if g.pool != nil {
			plain, decErr = g.ep.ReceiveFirstFromOPKPool(g.ik, g.sk, g.pool, frame, body)
		} else {
			plain, decErr = g.ep.ReceiveFirst(g.ik, g.sk, g.op, frame, body)
		}
	case ratchetwire.FrameMessage:
		// Continuations must use the installed ratchet session. Never
		// reinterpret them as a fresh handshake (downgrade resistance).
		plain, decErr = g.ep.ReceiveNextJournaled(p, time.Now(), func(raw []byte) bool { return handoff.IsEnvelope(raw) || handoff.IsReceipt(raw) }, func(pending *ratchetwire.ReceivePending) error {
			return g.persistHandoff(pending.Session, pending.Payload)
		})
	default:
		decErr = ratchetwire.ErrLegacyDowngrade
	}
	if decErr != nil {
		var pre *ratchetwire.PrekeyRejectedError
		if errors.As(decErr, &pre) {
			fmt.Fprintf(os.Stderr, "e2 prekey rejected: stage=%s opk=%d txid=%s: %v\n", pre.Stage, pre.OPKID, shortTx(inc.TxID), pre.Err)
		} else {
			fmt.Fprintln(os.Stderr, "e2 decrypt:", decErr)
		}
		return
	}
	if frame.Kind == ratchetwire.FrameMessage && (handoff.IsEnvelope(plain) || handoff.IsReceipt(plain)) {
		// The journal callback already committed the event/receipt atomically.
		// Do not run application persistence a second time after deleting it.
		fmt.Println("handoff: application persisted; outgoing receipts require explicit handoff flush")
		return
	}
	// Fabric-delivered frames resolve to a known session by construction
	// (the handle derived from that sid is what was drained). Apply the
	// allowlist to the session's known peer: a blocked sender's messages
	// are surfaced on neither transport.
	if fromFabric && g.mdb != nil && inc.Sender != "" {
		if !g.mdb.Allowed(inc.Sender) {
			fmt.Fprintf(os.Stderr, "e2: dropped fabric message from blocked sender %s\n", shortTx(inc.Sender))
			return
		}
	}
	if frame.Kind == ratchetwire.FrameInit && (handoff.IsEnvelope(plain) || handoff.IsReceipt(plain)) {
		fmt.Fprintln(os.Stderr, "handoff: initial-session application messages refused; establish a normal E2 conversation first")
		return
	}
	if g.handleHandoff(frame.SessionID, plain) {
		return
	}
	if g.handleIncident(inc, frame.SessionID, plain) {
		return
	}
	// Receipts are ratcheted messages like any other: detect the
	// envelope and surface it as an ack line instead of a message.
	receiptInReplyTo, receiptStatus, isReceipt := parseReceipt(plain)
	if isReceipt {
		fmt.Printf("ack %s: %s (for %s)\n", shortTx(inc.TxID), receiptStatus, shortTx(receiptInReplyTo))
		return
	}
	// Money envelopes (invoice/payment) ride the session like
	// receipts: surface them as money lines, not message bodies.
	if kind, summary, isMoney := parseMoneyEnvelope(plain); isMoney {
		_ = kind
		fmt.Printf("%s %s\n", shortTx(inc.TxID), summary)
		if rec, ok := parseMoneyRecord(plain); ok {
			rec.Direction = "received"
			rec.Peer = inc.Sender
			rec.TxID = inc.TxID
			if g.receipts != "" {
				if err := receipts.Append(g.receipts, rec); err != nil {
					fmt.Fprintln(os.Stderr, "e2 receipts:", err)
				}
			}
		}
		return
	}
	// Attachments / keep-a-copy mode: write the decrypted body to a
	// file named by txid instead of printing it.
	if g.outDir != "" {
		if err := os.WriteFile(filepath.Join(g.outDir, shortTx(inc.TxID)+".msg"), plain, 0600); err != nil {
			fmt.Fprintln(os.Stderr, "e2 out-dir:", err)
			return
		}
		fmt.Printf("msg %s: saved %s/%s.msg\n", shortTx(inc.TxID), g.outDir, shortTx(inc.TxID))
	} else {
		fmt.Printf("msg %s: %s\n", shortTx(inc.TxID), plain)
	}
	// Pay-with-message: surface any native value that rode the
	// pointer tx. Postage (1 atomic) is noise; anything above it
	// is money and gets its own line. (Fabric pointers carry no
	// value — inc.Amount is zero there.)
	if inc.Amount > 1 {
		fmt.Printf("  ↳ received %d atomic units on tx %s\n", inc.Amount, shortTx(inc.TxID))
	}
	// Mail-store hook: record into threads + search index. Blocked
	// senders were already dropped before decryption, so everything
	// recorded here passed the allowlist.
	if g.mdb != nil {
		if rerr := g.mdb.RecordMessage(hex.EncodeToString(frame.SessionID[:]), inc.Sender, inc.TxID, time.Now(), plain); rerr != nil {
			fmt.Fprintln(os.Stderr, "e2 maildb:", rerr)
		}
	}
	// Notify only after local decryption and never include plaintext.
	// Provider failures are diagnostics; they must not stop receiving.
	if g.dispatcher != nil {
		if nerr := g.dispatcher.Send(notify.Event{TxID: inc.TxID, Subject: "Spore private message", Received: time.Now()}); nerr != nil {
			fmt.Fprintln(os.Stderr, "e2 notify:", nerr)
		}
	}
	if g.autoAck && frame.SessionID != ([8]byte{}) {
		// Reply "delivered" on the same session; the sender's recv
		// side prints it as an ack line. Best-effort: a failed ack
		// send or post is logged, never fatal.
		_, raw, ackErr := sendReceipt(g.ep, frame.SessionID, inc.TxID, "delivered", g.ackTTL)
		if ackErr != nil {
			fmt.Fprintln(os.Stderr, "e2 ack:", ackErr)
			return
		}
		if _, postErr := g.carrier.PostPointer(g.ackCtx, inc.Sender, raw, 1); postErr != nil {
			fmt.Fprintln(os.Stderr, "e2 ack post:", postErr)
		}
	}
}

// Allowed is the transport-neutral allowlist check: shared by the chain
// watcher (before FetchIncomingE2) and the fabric drain (before ingest).
// A blocked sender's frame never touches ratchet state on either transport.
func (g *e2Ingestor) Allowed(sender string) bool {
	return g.mdb == nil || g.mdb.Allowed(sender)
}

// ingestPointer is the fabric-drain entry point: parse the raw 74-byte
// pointer, let FetchFrame enforce the RouteKey(sid)==Route binding (design
// law 4), fetch the frame, and hand it to the shared pipeline. It returns
// the pointer payload for the caller's retry queue when the BODY fetch
// fails, mirroring the chain watcher's retry behavior.
func (g *e2Ingestor) ingestPointer(raw []byte, now time.Time) (retry ratchetwire.Pointer, ok bool) {
	pp, err := ratchetwire.ParsePointerPayload(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2 fabric: bad pointer:", err)
		return ratchetwire.Pointer{}, false
	}
	p := pp.Pointer()
	// The session must already exist — the bootstrap fence again, enforced
	// structurally: an unknown sid has no ratchet state, so ingest would
	// fail at decrypt anyway. Refusing here keeps the failure legible and
	// keeps hostile handles from burning fetches.
	frame, err := ratchetwire.FetchFrame(g.st, p, now)
	if err != nil {
		return p, false
	}
	if frame.Kind == ratchetwire.FrameInit {
		// Bootstrap fence: an init never ingests over fabric. This is a refusal,
		// not an ingest, so report it as one. Return not-ok with no retry: the
		// caller un-marks the CID, so a later copy from another relay or tick
		// stays eligible, and a retry could only be refused again.
		fmt.Fprintf(os.Stderr, "e2 fabric: init pointer refused, not ingested (bootstrap rides the chain) cid %x\n", p.CID)
		if err := noteFabricRefusal(g.stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "e2 fabric: refusal count not persisted:", err)
		}
		return ratchetwire.Pointer{}, false
	}
	cidHex := hex.EncodeToString(p.CID[:])
	inc := chain.Incoming{TxID: "fabric-" + cidHex[:16], Payload: raw}
	g.ingest(inc, frame, p, true)
	return ratchetwire.Pointer{}, true
}

// openE2Receiver is the receiver-side setup shared by `msg recv-e2` and
// `spore fabric subscribe` (F2): identity/prekey files, body store, durable
// endpoint, maildb, and the notify dispatcher. Both commands construct the
// SAME e2Ingestor over the SAME stores, so a frame ingested from either
// transport behaves identically.
func openE2Receiver(fs *flag.FlagSet, outDir string, outDirRequired bool) (*e2Ingestor, func(), error) {
	identity := fs.Lookup("identity").Value.String()
	spk := fs.Lookup("spk").Value.String()
	if identity == "" || spk == "" {
		return nil, nil, errors.New("requires -identity and -spk")
	}
	if outDirRequired && outDir != "" {
		// Validate BEFORE any prekey state can be consumed: a bad output
		// path must not burn a one-time prekey and then force a replay of
		// a frame that can no longer be opened.
		if err := os.MkdirAll(outDir, 0700); err != nil {
			return nil, nil, fmt.Errorf("create -out-dir: %w", err)
		}
	}
	st, err := newE2BodyStore(e2StoreOptionsFromFlags(fs))
	if err != nil {
		return nil, nil, err
	}
	ik, err := readHexFile(identity, 32)
	if err != nil {
		return nil, nil, err
	}
	sk, err := readHexFile(spk, 32)
	if err != nil {
		return nil, nil, err
	}
	var op *[32]byte
	var pool *ratchetwire.OPKPool
	if v := fs.Lookup("opk-pool").Value.String(); v != "" {
		pool, err = ratchetwire.NewPersistentOPKPool(v)
		if err != nil {
			return nil, nil, err
		}
	}
	if v := fs.Lookup("opk").Value.String(); v != "" {
		x, e := readHexFile(v, 32)
		if e != nil {
			return nil, nil, e
		}
		op = &[32]byte{}
		copy(op[:], x)
	}
	stateDir := fs.Lookup("state-dir").Value.String()
	stateKeyFile := fs.Lookup("state-key").Value.String()
	if stateDir == "" || stateKeyFile == "" {
		return nil, nil, errors.New("E2 requires -state-dir and -state-key")
	}
	stateKey, err := readHexFile(stateKeyFile, 32)
	if err != nil {
		return nil, nil, err
	}
	sessionTTL, err := time.ParseDuration(fs.Lookup("session-ttl").Value.String())
	if err != nil {
		return nil, nil, err
	}
	states, err := ratchetwire.NewFileStateStore(stateDir, stateKey)
	if err != nil {
		return nil, nil, err
	}
	ep, err := ratchetwire.NewDurableEndpointWithExpiry(st, states, sessionTTL, time.Now())
	if err != nil {
		return nil, nil, err
	}
	var mdb *maildb.MailDB
	maildbPath := fs.Lookup("maildb").Value.String()
	if maildbPath != "" {
		mdb, err = maildb.Open(maildbPath)
		if err != nil {
			return nil, nil, err
		}
	}
	creatorSig, err := secure.SigPubOf(ik)
	if err != nil {
		return nil, nil, err
	}
	incidentDB, err := incident.Open(filepath.Join(stateDir, "incidents.enc"), stateKey)
	if err != nil {
		return nil, nil, err
	}
	handoffDB, err := handoff.Open(filepath.Join(stateDir, "handoffs.enc"), stateKey)
	if err != nil {
		return nil, nil, err
	}
	var dispatcher *notify.Dispatcher
	webhookURL := fs.Lookup("ntfy").Value.String()
	if webhookURL != "" || fs.Lookup("notify-email").Value.String() != "" || fs.Lookup("notify-sms").Value.String() != "" {
		webhookToken := ""
		if webhookURL != "" {
			webhookToken = os.Getenv("SPORE_NOTIFY_WEBHOOK_TOKEN")
		}
		dispatcher, err = notify.NewFromEnv(notify.Options{
			WebhookURL: webhookURL, WebhookToken: webhookToken,
			EmailTo:  fs.Lookup("notify-email").Value.String(),
			SMSTo:    fs.Lookup("notify-sms").Value.String(),
			SMTPHost: fs.Lookup("notify-smtp-host").Value.String(), SMTPPort: int(fs.Lookup("notify-smtp-port").Value.(flag.Getter).Get().(int)),
			SMTPFrom:     fs.Lookup("notify-smtp-from").Value.String(),
			SMTPUsername: fs.Lookup("notify-smtp-user").Value.String(),
			TwilioSID:    fs.Lookup("notify-twilio-sid").Value.String(),
			TwilioFrom:   fs.Lookup("notify-twilio-from").Value.String(),
		})
		if err != nil {
			return nil, nil, err
		}
	}
	ackTTL, err := time.ParseDuration(fs.Lookup("ack-ttl").Value.String())
	if err != nil {
		return nil, nil, err
	}
	creator := flagValueOr(fs, "incident-address", "")
	if creator == "" {
		creator = flagValueOr(fs, "address", "")
	}
	creatorPinned := hex.EncodeToString(creatorSig)
	ing := &e2Ingestor{
		st: st, ep: ep, ik: ik, sk: sk, op: op, pool: pool, incidentStore: incidentDB, stateDir: stateDir, creator: creator, creatorPinned: creatorPinned,
		handoffStore: handoffDB, handoffLocal: handoff.Peer{Address: handoffAddress(fs), Pinned: creatorPinned},
		carrier: ratchetwire.ChainCarrier{}, // fabric path never auto-acks on-chain
		ackCtx:  context.Background(),
		outDir:  outDir, receipts: fs.Lookup("receipts").Value.String(),
		mdb: mdb, dispatcher: dispatcher,
		autoAck: fs.Lookup("auto-ack").Value.String() == "true",
		ackTTL:  ackTTL,
	}
	if err := ing.recoverHandoffReceive(); err != nil {
		closeBodyStore(st)
		return nil, nil, fmt.Errorf("handoff: receive recovery pending: %w", err)
	}
	// Rejection counts are throttled, so a count can still be pending when the
	// command returns. The caller defers this cleanup, which covers normal exit
	// and the signal-driven return from Ctrl-C.
	cleanup := func() {
		if err := pool.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "e2: prekey rejection counts not persisted at exit: %v\n", err)
		}
	}
	return ing, cleanup, nil
}
