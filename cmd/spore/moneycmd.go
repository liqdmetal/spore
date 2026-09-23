package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/liqdmetal/spore/internal/notify"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/receipts"
)

// msgInvoiceE2 sends a typed invoice envelope into an existing session:
// "please send me X of ASSET for THIS". The invoice body rides the ratchet
// like any other continuation — no server, no third party, and the payer
// settles it with `msg pay -invoice <id> -amount ...` which attaches the
// chain value to the payment tx itself.
func msgInvoiceE2(args []string) {
	fs := flag.NewFlagSet("msg invoice", flag.ExitOnError)
	to := fs.String("to", "", "recipient chain address (the payer)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	amount := fs.String("amount", "", "amount to request, whole units + asset suffix (e.g. 25dero)")
	forWhat := fs.String("for", "", "what the invoice is for (free text)")
	due := fs.Duration("due", 0, "payment deadline from now (e.g. 72h); 0 = no deadline")
	email := fs.String("email", "", "also email a courtesy invoice to this address via SMTP (SPORE_NOTIFY_SMTP_HOST/PORT/USERNAME/PASSWORD/FROM env)")
	ttl := fs.Duration("ttl", 24*time.Hour, "frame retention")
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to append this invoice to")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	if *to == "" || *sessionHex == "" || *amount == "" {
		check(errors.New("invoice requires -to -session -amount (and usually -for)"))
	}
	rawID, err := hex.DecodeString(*sessionHex)
	check(err)
	if len(rawID) != 8 {
		check(errors.New("-session must be 16 hex chars (8 bytes)"))
	}
	var sessionID [8]byte
	copy(sessionID[:], rawID)

	// Validate + build the envelope BEFORE touching session state: a
	// malformed amount must not advance the ratchet.
	body, env, err := marshalInvoice(amtAsset(*amount), amtNumber(*amount), *forWhat, dueTime(*due))
	check(err)

	ep, _ := durableEndpointFromFlags(fs)
	_, raw, err := ep.SendNext(sessionID, body, time.Now().Add(*ttl))
	check(err)
	c, err := e2Carrier(fs)
	check(err)
	r, err := c.PostPointer(context.Background(), *to, raw, 1)
	check(err)
	fmt.Printf("invoice %s: %s %s for %q sent on tx %s\n", env.ID, formatAmount(env.Asset, env.Atomic), env.Asset, env.For, r.TxID)
	if err := receipts.Append(*receiptsFile, receipts.Record{At: env.Created, Session: *sessionHex,
		Peer: *to, Direction: "sent", Kind: "invoice", InvoiceID: env.ID,
		Asset: env.Asset, Atomic: env.Atomic, For: env.For, TxID: r.TxID}); err != nil {
		log.Printf("invoice: ledger %s: %v", *receiptsFile, err)
	}
	if *email != "" {
		nd, err := notify.NewFromEnv(notify.Options{EmailTo: *email})
		if err != nil {
			log.Printf("invoice: email %s: %v", *email, err)
		} else if err := nd.Send(notify.Event{
			Subject: fmt.Sprintf("spore invoice %s: %s %s — %s", env.ID, formatAmount(env.Asset, env.Atomic), env.Asset, env.For),
			TxID:    r.TxID,
		}); err != nil {
			log.Printf("invoice: email %s: %v", *email, err)
		} else {
			fmt.Printf("invoice emailed to %s\n", *email)
		}
	}
}

// msgPayE2 settles an invoice (or pays spontaneously) INTO an existing
// session: the payment envelope (txid, amount, invoice id) rides the
// ratchet AND the chain value rides the same tx via -amount semantics.
// Money and proof-of-money are one atomic object.
func msgPayE2(args []string) {
	fs := flag.NewFlagSet("msg pay", flag.ExitOnError)
	to := fs.String("to", "", "recipient chain address (the payee)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	amount := fs.String("amount", "", "amount to pay, whole units + asset suffix (e.g. 25dero) — attached to THIS tx")
	invoice := fs.String("invoice", "", "invoice id being settled (from the INVOICE line the payee sent); empty = spontaneous payment")
	note := fs.String("note", "", "optional note for the payee")
	ttl := fs.Duration("ttl", 24*time.Hour, "frame retention")
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to append this payment to")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	if *to == "" || *sessionHex == "" || *amount == "" {
		check(errors.New("pay requires -to -session -amount (optionally -invoice ID)"))
	}
	rawID, err := hex.DecodeString(*sessionHex)
	check(err)
	if len(rawID) != 8 {
		check(errors.New("-session must be 16 hex chars (8 bytes)"))
	}
	var sessionID [8]byte
	copy(sessionID[:], rawID)

	asset, atomic, err := parseAmountFlag(*amount)
	check(err)
	if !carrierCarriesValue(fs.Lookup("chain").Value.String()) {
		check(fmt.Errorf("pay requires a value-carrying carrier (dero|evm); %s cannot attach money — refusing to send a payment note for value that never moved", fs.Lookup("chain").Value.String()))
	}

	ep, _ := durableEndpointFromFlags(fs)

	// Send the chain value FIRST as a bare pointer-less transfer? No — the
	// value rides WITH the payment envelope's pointer tx below. Build the
	// envelope after the tx is known? The envelope must reference the txid
	// of its own settlement, which is a chicken-and-egg on a single tx.
	// Resolution: the envelope carries the amount + invoice id; the txid is
	// learned by BOTH parties from the chain (the payee sees inc.TxID with
	// inc.Amount). So marshal with the session-side view; the recipient
	// matches money to envelope by tx.
	body, err := marshalPayment(*invoice, asset, atomic, "same-tx", *note)
	check(err)
	_, raw, err := ep.SendNext(sessionID, body, time.Now().Add(*ttl))
	check(err)
	c, err := e2Carrier(fs)
	check(err)
	r, err := c.PostPointer(context.Background(), *to, raw, atomic)
	check(err)
	fmt.Printf("PAID %s %s tx %s%s\n", formatAmount(asset, atomic), asset, r.TxID, invoiceRef(*invoice))
	if err := receipts.Append(*receiptsFile, receipts.Record{At: time.Now().Unix(), Session: *sessionHex,
		Peer: *to, Direction: "sent", Kind: "payment", InvoiceID: *invoice,
		Asset: asset, Atomic: atomic, Note: *note, TxID: r.TxID}); err != nil {
		log.Printf("pay: ledger %s: %v", *receiptsFile, err)
	}
}

// msgReceipts lists the local invoice/payment ledger (newest first),
// optionally filtered to one session, and optionally exported as JSON.
func msgReceipts(args []string) {
	fs := flag.NewFlagSet("msg receipts", flag.ExitOnError)
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to read")
	sessionHex := fs.String("session", "", "only show records for this 16-hex session")
	out := fs.String("out", "", "export the filtered ledger to this JSON file")
	_ = fs.Parse(args)
	recs, err := receipts.List(*receiptsFile, *sessionHex)
	check(err)
	if *out != "" {
		raw, err := json.MarshalIndent(recs, "", "  ")
		check(err)
		check(os.WriteFile(*out, append(raw, '\n'), 0o600))
		fmt.Printf("exported %d record(s) to %s\n", len(recs), *out)
		return
	}
	if len(recs) == 0 {
		fmt.Println("no receipts in", *receiptsFile)
		return
	}
	fmt.Printf("%-10s %-8s %-6s %-14s %-10s %-14s %s\n", "WHEN", "KIND", "DIR", "AMOUNT", "INVOICE", "TXID", "NOTE")
	for _, r := range recs {
		fmt.Printf("%-10s %-8s %-6s %-14s %-10s %-14s %s\n",
			time.Unix(r.At, 0).Format("01-02 15:04"), r.Kind, r.Direction,
			formatAmount(r.Asset, r.Atomic)+" "+r.Asset, shortOrDash(r.InvoiceID),
			shortTx(r.TxID), shortOrDash(r.Note))
	}
}

func shortOrDash(s string) string {
	if s == "" {
		return "-"
	}
	if len(s) > 14 {
		return s[:14]
	}
	return s
}

func invoiceRef(id string) string {
	if id == "" {
		return ""
	}
	return " (settles " + id + ")"
}

// amtAsset/amtNumber split "25dero" for marshalInvoice, which takes asset
// and number separately.
func amtAsset(s string) string {
	a, _, _ := parseAmountFlag(s)
	return a
}
func amtNumber(s string) string {
	i := len(s)
	for i > 0 && isASCIILetter(s[i-1]) {
		i--
	}
	return s[:i]
}

func dueTime(d time.Duration) time.Time {
	if d <= 0 {
		return time.Time{}
	}
	return time.Now().Add(d)
}

// newDurableEndpointFromFlags restores the session state and body store used
// by continuation commands. Errors are returned so settlement commands can
// validate their notice path before submitting an irreversible contract call.
func newDurableEndpointFromFlags(fs *flag.FlagSet) (*ratchetwire.DurableEndpoint, ratchetwire.BodyStore, error) {
	stateDir := flagValueOr(fs, "state-dir", "")
	stateKeyFile := flagValueOr(fs, "state-key", "")
	if stateDir == "" || stateKeyFile == "" {
		return nil, nil, errors.New("E2 requires -state-dir and -state-key")
	}
	stateKey, err := readHexFile(stateKeyFile, 32)
	if err != nil {
		return nil, nil, err
	}
	sessionTTL, err := time.ParseDuration(flagValueOr(fs, "session-ttl", "0s"))
	if err != nil {
		return nil, nil, err
	}
	states, err := ratchetwire.NewFileStateStore(stateDir, stateKey)
	if err != nil {
		return nil, nil, err
	}

	st, err := newE2BodyStore(e2StoreOptionsFromFlags(fs))
	if err != nil {
		return nil, nil, err
	}
	ep, err := ratchetwire.NewDurableEndpointWithExpiry(st, states, sessionTTL, time.Now())
	if err != nil {
		closeBodyStore(st)
		return nil, nil, err
	}
	return ep, st, nil
}

func closeBodyStore(st ratchetwire.BodyStore) {
	if closer, ok := st.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

// durableEndpointFromFlags is the fatal-error wrapper used by existing CLI
// commands that cannot proceed without a restored endpoint.
func durableEndpointFromFlags(fs *flag.FlagSet) (*ratchetwire.DurableEndpoint, ratchetwire.BodyStore) {
	ep, st, err := newDurableEndpointFromFlags(fs)
	check(err)
	return ep, st
}
