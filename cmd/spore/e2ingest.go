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
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/notify"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/receipts"
)

type e2Ingestor struct {
	st         ratchetwire.BodyStore
	ep         *ratchetwire.DurableEndpoint
	ik, sk     []byte
	op         *[32]byte
	pool       *ratchetwire.OPKPool
	carrier    ratchetwire.ChainCarrier
	ackCtx     context.Context // context for auto-ack pointer posts
	outDir     string
	receipts   string // receipts ledger path ("" disables)
	mdb        *maildb.MailDB
	dispatcher *notify.Dispatcher // nil disables notifications
	autoAck    bool
	ackTTL     time.Duration
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
		plain, decErr = g.ep.ReceiveNext(p, time.Now())
	default:
		decErr = ratchetwire.ErrLegacyDowngrade
	}
	if decErr != nil {
		fmt.Fprintln(os.Stderr, "e2 decrypt:", decErr)
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
	return &e2Ingestor{
		st: st, ep: ep, ik: ik, sk: sk, op: op, pool: pool,
		carrier: ratchetwire.ChainCarrier{}, // fabric path never auto-acks on-chain
		ackCtx:  context.Background(),
		outDir:  outDir, receipts: fs.Lookup("receipts").Value.String(),
		mdb: mdb, dispatcher: dispatcher,
		autoAck: fs.Lookup("auto-ack").Value.String() == "true",
		ackTTL:  ackTTL,
	}, func() {}, nil
}
