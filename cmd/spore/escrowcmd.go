// In-thread HTLC settlement: `msg escrow claim` and `msg escrow refund`.
//
// `msg send -escrow htlc` has been able to FUND a RelayHTLC since the escrow
// branch landed, but closing one required dropping out of the messenger to
// hand-build an InvokeSC call. These two commands close the loop entirely
// in-thread: they call the same sap bindings the funder used, verify the
// hash/preimage pairing locally BEFORE spending postage on a doomed tx, and
// then announce the settlement to the counterparty as a typed money envelope
// riding the ratcheted session (so the counterparty learns the preimage — or
// the expiry — without scanning the chain).
//
//	spore msg escrow claim  -hash HEX -preimage HEX -to ADDR -session HEX [-state-dir D -state-key F] ...
//	spore msg escrow refund -hash HEX -to ADDR -session HEX [-state-dir D -state-key F] ...
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
	if len(raw) != 32 {
		return out, fmt.Errorf("-%s must be 32 bytes (64 hex chars), got %d bytes", name, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// escrowAnnounce posts the settlement envelope through the existing session
// (SendNext on the durable endpoint) and appends it to the receipts ledger.
func escrowAnnounce(fs *flag.FlagSet, to, sessionHex string, envelope []byte) {
	ep, _ := durableEndpointFromFlags(fs)
	_, raw, err := ep.SendNext(mustSessionID(sessionHex), envelope, time.Now().Add(24*time.Hour))
	if err != nil {
		fmt.Fprintf(os.Stderr, "escrow: settlement announced on-chain but the in-thread notice failed: %v\n", err)
		return
	}
	c, err := e2Carrier(fs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "escrow: notice not posted (carrier build failed): %v\n", err)
		return
	}
	r, err := c.PostPointer(context.Background(), to, raw, 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "escrow: notice not posted: %v\n", err)
		return
	}
	fmt.Printf(" notice tx %s (counterparty notified in-thread)\n", r.TxID)
}

// mustSessionID parses the 16-hex session id (shared with msg pay).
func mustSessionID(sessionHex string) [8]byte {
	rawID, err := hex.DecodeString(sessionHex)
	check(err)
	if len(rawID) != 8 {
		check(fmt.Errorf("-session must be 16 hex chars (8 bytes)"))
	}
	var sessionID [8]byte
	copy(sessionID[:], rawID)
	return sessionID
}

// msgEscrowClaimE2 claims a funded HTLC with the preimage. The preimage hash
// pairing is verified LOCALLY first (sha256(preimage) == -hash): a mismatched
// pair can never satisfy the contract, so spending a ring-sig tx on it is
// pure loss.
func msgEscrowClaimE2(args []string) {
	fs := flag.NewFlagSet("msg escrow claim", flag.ExitOnError)
	hashHex := fs.String("hash", "", "64-hex HTLC preimage hash (the -escrow-hash the funder used)")
	preimageHex := fs.String("preimage", "", "64-hex preimage that satisfies -hash (sha256(preimage) == hash)")
	to := fs.String("to", "", "counterparty chain address (receives the in-thread settlement notice)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	note := fs.String("note", "", "optional note for the counterparty")
	atomic := fs.Uint64("amount-atomic", 0, "escrowed amount in atomic units (display only)")
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to append this settlement to")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	if *hashHex == "" || *preimageHex == "" || *to == "" || *sessionHex == "" {
		check(fmt.Errorf("escrow claim requires -hash -preimage -to -session"))
	}
	hash, err := escrowHash32("hash", *hashHex)
	check(err)
	preimage, err := escrowHash32("preimage", *preimageHex)
	check(err)
	if sha256.Sum256(preimage[:]) != hash {
		check(fmt.Errorf("preimage does not match: sha256(preimage) != hash — the contract would reject this claim; refusing to spend postage on a doomed tx"))
	}

	fsRPC := fs.Lookup("rpc")
	if fsRPC == nil {
		check(fmt.Errorf("escrow claim requires -rpc (DERO wallet RPC)"))
	}
	u, p := parseLogin(fs.Lookup("rpc-login").Value.String())
	client := dero.NewClient(fsRPC.Value.String(), u, p)
	sap.LoadContractIDsFromEnv()
	ring, err := deroRingSizeFromFlags(fs, "dero")
	check(err)

	txid, err := sap.HTLCClaim(context.Background(), client, hash, preimage, *to, ring)
	check(err)
	fmt.Printf("ESCROW CLAIMED hash %s tx %s", shortTx(*hashHex), shortTx(txid))
	if *atomic > 0 {
		fmt.Printf(" (%d atomic)", *atomic)
	}
	fmt.Println()
	if err := receipts.Append(*receiptsFile, receipts.Record{At: time.Now().Unix(), Session: *sessionHex,
		Peer: *to, Direction: "sent", Kind: "escrow-claim", Asset: "dero",
		Atomic: *atomic, Note: *note, TxID: txid}); err != nil {
		fmt.Fprintf(os.Stderr, "escrow: ledger %s: %v\n", *receiptsFile, err)
	}
	env, err := marshalEscrowNotice("claim", strings.ToLower(*hashHex), strings.ToLower(*preimageHex), txid, *note, *atomic)
	check(err)
	escrowAnnounce(fs, *to, *sessionHex, env)
}

// msgEscrowRefundE2 refunds an EXPIRED HTLC back to the funder. Like claim,
// it announces the outcome in-thread so the payee learns the deal is dead.
func msgEscrowRefundE2(args []string) {
	fs := flag.NewFlagSet("msg escrow refund", flag.ExitOnError)
	hashHex := fs.String("hash", "", "64-hex HTLC preimage hash (the -escrow-hash the funder used)")
	to := fs.String("to", "", "counterparty chain address (receives the in-thread settlement notice)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	note := fs.String("note", "", "optional note for the counterparty")
	atomic := fs.Uint64("amount-atomic", 0, "escrowed amount in atomic units (display only)")
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to append this settlement to")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	if *hashHex == "" || *to == "" || *sessionHex == "" {
		check(fmt.Errorf("escrow refund requires -hash -to -session"))
	}
	hash, err := escrowHash32("hash", *hashHex)
	check(err)

	fsRPC := fs.Lookup("rpc")
	if fsRPC == nil {
		check(fmt.Errorf("escrow refund requires -rpc (DERO wallet RPC)"))
	}
	u, p := parseLogin(fs.Lookup("rpc-login").Value.String())
	client := dero.NewClient(fsRPC.Value.String(), u, p)
	sap.LoadContractIDsFromEnv()
	ring, err := deroRingSizeFromFlags(fs, "dero")
	check(err)

	txid, err := sap.HTLCRefund(context.Background(), client, hash, ring)
	check(err)
	fmt.Printf("ESCROW REFUNDED hash %s tx %s", shortTx(*hashHex), shortTx(txid))
	if *atomic > 0 {
		fmt.Printf(" (%d atomic)", *atomic)
	}
	fmt.Println()
	if err := receipts.Append(*receiptsFile, receipts.Record{At: time.Now().Unix(), Session: *sessionHex,
		Peer: *to, Direction: "sent", Kind: "escrow-refund", Asset: "dero",
		Atomic: *atomic, Note: *note, TxID: txid}); err != nil {
		fmt.Fprintf(os.Stderr, "escrow: ledger %s: %v\n", *receiptsFile, err)
	}
	env, err := marshalEscrowNotice("refund", strings.ToLower(*hashHex), "", txid, *note, *atomic)
	check(err)
	escrowAnnounce(fs, *to, *sessionHex, env)
}
