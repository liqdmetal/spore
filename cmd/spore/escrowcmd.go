// In-thread HTLC settlement: `msg escrow claim` and `msg escrow refund`.
//
// `msg send -escrow htlc` funds RelayHTLC; these commands settle it and
// announce the result on the existing ratcheted session.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/receipts"
	"github.com/liqdmetal/spore/internal/sap"
)

// escrowHash32 parses a 64-hex-char HTLC hash argument.
func escrowHash32(name, value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil {
		return out, fmt.Errorf("-%s must be 64 hex chars: %w", name, err)
	}
	if len(raw) != len(out) {
		return out, fmt.Errorf("-%s must be 32 bytes (64 hex chars), got %d bytes", name, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

type escrowNotice struct {
	endpoint *ratchetwire.DurableEndpoint
	carrier  ratchetwire.ChainCarrier
	to       string
	session  [8]byte
}

// prepareEscrowNotice checks the DERO recipient, restores the session, opens
// the body store, and builds the carrier before any irreversible settlement.
func prepareEscrowNotice(fs *flag.FlagSet, to, sessionHex string) (*escrowNotice, error) {
	if !strings.EqualFold(flagValueOr(fs, "chain", "dero"), "dero") {
		return nil, fmt.Errorf("escrow/dex settlement requires -chain dero")
	}
	recipient, err := dero.ValidateAddress(to)
	if err != nil {
		return nil, fmt.Errorf("settlement -to: %w", err)
	}
	session, err := parseSessionID(sessionHex)
	if err != nil {
		return nil, err
	}
	ep, st, err := newDurableEndpointFromFlags(fs)
	if err != nil {
		return nil, err
	}
	if ep.Sessions.Get(session) == nil {
		closeBodyStore(st)
		return nil, fmt.Errorf("unknown session %x; settlement notice requires an existing session", session)
	}
	carrier, err := e2Carrier(fs)
	if err != nil {
		closeBodyStore(st)
		return nil, err
	}
	return &escrowNotice{endpoint: ep, carrier: carrier, to: recipient, session: session}, nil
}

func (n *escrowNotice) close() { closeBodyStore(n.endpoint.Store) }

// escrowAnnounce sends the settlement notice after the contract call succeeds.
func escrowAnnounce(n *escrowNotice, body []byte) error {
	_, raw, err := n.endpoint.SendNext(n.session, body, time.Now().Add(24*time.Hour))
	if err != nil {
		return err
	}
	_, err = n.carrier.PostPointer(context.Background(), n.to, raw, 1)
	return err
}

func reportSettlementNotice(operation, txid string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: settlement tx %s succeeded, but the in-thread notice failed: %v\n", operation, shortTx(txid), err)
	}
}

func parseSessionID(sessionHex string) ([8]byte, error) {
	var sessionID [8]byte
	raw, err := hex.DecodeString(sessionHex)
	if err != nil {
		return sessionID, fmt.Errorf("-session must be 16 hex chars (8 bytes): %w", err)
	}
	if len(raw) != len(sessionID) {
		return sessionID, fmt.Errorf("-session must be 16 hex chars (8 bytes)")
	}
	copy(sessionID[:], raw)
	return sessionID, nil
}

func escrowClient(fs *flag.FlagSet) (*dero.Client, uint64, error) {
	if !strings.EqualFold(flagValueOr(fs, "chain", "dero"), "dero") {
		return nil, 0, fmt.Errorf("escrow settlement requires -chain dero")
	}
	rpc := flagValueOr(fs, "rpc", "")
	if rpc == "" {
		return nil, 0, fmt.Errorf("escrow settlement requires -rpc (DERO wallet RPC)")
	}
	ringSize, err := deroRingSizeFromFlags(fs, "dero")
	if err != nil {
		return nil, 0, err
	}
	u, p := parseLogin(flagValueOr(fs, "rpc-login", ""))
	return dero.NewClient(rpc, u, p), ringSize, nil
}

// msgEscrowClaimE2 claims a funded HTLC after validating the preimage locally.
func msgEscrowClaimE2(args []string) {
	fs := flag.NewFlagSet("msg escrow claim", flag.ExitOnError)
	hashHex := fs.String("hash", "", "64-hex HTLC preimage hash")
	preimageHex := fs.String("preimage", "", "64-hex preimage satisfying -hash")
	to := fs.String("to", "", "counterparty DERO address (receives the settlement notice)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	note := fs.String("note", "", "optional note for the counterparty")
	atomic := fs.Uint64("amount-atomic", 0, "escrowed amount in atomic units (display only)")
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to append this settlement to")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	check(runEscrowClaim(fs, *hashHex, *preimageHex, *to, *sessionHex, *note, *atomic, *receiptsFile))
}

func runEscrowClaim(fs *flag.FlagSet, hashHex, preimageHex, to, sessionHex, note string, atomic uint64, receiptsFile string) error {
	if hashHex == "" || preimageHex == "" || to == "" || sessionHex == "" {
		return fmt.Errorf("escrow claim requires -hash -preimage -to -session")
	}
	hash, err := escrowHash32("hash", hashHex)
	if err != nil {
		return err
	}
	preimage, err := escrowHash32("preimage", preimageHex)
	if err != nil {
		return err
	}
	if sha256.Sum256(preimage[:]) != hash {
		return fmt.Errorf("preimage does not match: sha256(preimage) != hash — contract would reject the claim")
	}
	client, ringSize, err := escrowClient(fs)
	if err != nil {
		return err
	}
	sap.LoadContractIDsFromEnv()
	notice, err := prepareEscrowNotice(fs, to, sessionHex)
	if err != nil {
		return err
	}
	defer notice.close()

	txid, err := sap.HTLCClaim(context.Background(), client, hash, preimage, notice.to, ringSize)
	if err != nil {
		return fmt.Errorf("HTLC claim: %w", err)
	}
	fmt.Printf("ESCROW CLAIMED hash %s tx %s", shortTx(hashHex), shortTx(txid))
	if atomic > 0 {
		fmt.Printf(" (%d atomic)", atomic)
	}
	fmt.Println()
	if err := receipts.Append(receiptsFile, receipts.Record{At: time.Now().Unix(), Session: sessionHex,
		Peer: notice.to, Direction: "sent", Kind: "escrow-claim", Asset: "dero",
		Atomic: atomic, Note: note, TxID: txid}); err != nil {
		fmt.Fprintf(os.Stderr, "escrow: ledger %s: %v\n", receiptsFile, err)
	}
	body, err := marshalEscrowNotice("claim", strings.ToLower(hashHex), strings.ToLower(preimageHex), txid, note, atomic)
	if err != nil {
		reportSettlementNotice("escrow claim", txid, err)
		return nil
	}
	reportSettlementNotice("escrow claim", txid, escrowAnnounce(notice, body))
	return nil
}

// msgEscrowRefundE2 refunds an expired HTLC and announces the settlement.
func msgEscrowRefundE2(args []string) {
	fs := flag.NewFlagSet("msg escrow refund", flag.ExitOnError)
	hashHex := fs.String("hash", "", "64-hex HTLC preimage hash")
	to := fs.String("to", "", "counterparty DERO address (receives the settlement notice)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	note := fs.String("note", "", "optional note for the counterparty")
	atomic := fs.Uint64("amount-atomic", 0, "escrowed amount in atomic units (display only)")
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to append this settlement to")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	check(runEscrowRefund(fs, *hashHex, *to, *sessionHex, *note, *atomic, *receiptsFile))
}

func runEscrowRefund(fs *flag.FlagSet, hashHex, to, sessionHex, note string, atomic uint64, receiptsFile string) error {
	if hashHex == "" || to == "" || sessionHex == "" {
		return fmt.Errorf("escrow refund requires -hash -to -session")
	}
	hash, err := escrowHash32("hash", hashHex)
	if err != nil {
		return err
	}
	client, ringSize, err := escrowClient(fs)
	if err != nil {
		return err
	}
	sap.LoadContractIDsFromEnv()
	notice, err := prepareEscrowNotice(fs, to, sessionHex)
	if err != nil {
		return err
	}
	defer notice.close()

	txid, err := sap.HTLCRefund(context.Background(), client, hash, ringSize)
	if err != nil {
		return fmt.Errorf("HTLC refund: %w", err)
	}
	fmt.Printf("ESCROW REFUNDED hash %s tx %s", shortTx(hashHex), shortTx(txid))
	if atomic > 0 {
		fmt.Printf(" (%d atomic)", atomic)
	}
	fmt.Println()
	if err := receipts.Append(receiptsFile, receipts.Record{At: time.Now().Unix(), Session: sessionHex,
		Peer: notice.to, Direction: "sent", Kind: "escrow-refund", Asset: "dero",
		Atomic: atomic, Note: note, TxID: txid}); err != nil {
		fmt.Fprintf(os.Stderr, "escrow: ledger %s: %v\n", receiptsFile, err)
	}
	body, err := marshalEscrowNotice("refund", strings.ToLower(hashHex), "", txid, note, atomic)
	if err != nil {
		reportSettlementNotice("escrow refund", txid, err)
		return nil
	}
	reportSettlementNotice("escrow refund", txid, escrowAnnounce(notice, body))
	return nil
}
