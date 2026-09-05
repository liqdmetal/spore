// Command liveevmsend is a live end-to-end driver for the spore long-body
// mailbox on an EVM/anvil dev node. It exercises the exact Model-A long-body
// delivery path against a running `mailbox run` (evm backend, MyceliumMailbox
// contract) using the real internal packages (longmsg/secure/whisper/store/evm):
//
//  1. encrypts a plaintext body to the mailbox's X25519 pubkey (fresh
//     ephemeral) and stores the ciphertext in a local store (SendBody),
//  2. HTTP-PUSHes the ciphertext to the mailbox /put/<cid> body server,
//  3. builds an E2E envelope (0xE0) around the canonical pointer-whisper and
//     posts it on EVM via deliver(to, data) on the MyceliumMailbox contract,
//  4. prints the pointer details + txid so a human can confirm the mailbox
//     scanner decrypted + stored the body (mailbox list/get).
//
// It is a dev/e2e tool; addresses and the RPC are anvil dev-node values.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/evm"
	"github.com/liqdmetal/spore/internal/longmsg"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
	"github.com/liqdmetal/spore/internal/whisper"
)

const (
	mailboxPubHex = "d13c72f0f27103042e646552a9728315c240aa7f8fcde74b8611e2a52f828066" // mailbox long-term X25519 pub (encrypt body + pointer to)
	mailboxHTTP   = "http://127.0.0.1:19292"                                           // mailbox body server
	rpcURL        = "http://127.0.0.1:8545"
	senderAddr    = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" // anvil account 0 (unlocked, signs)
	recipientAddr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" // anvil account 1 == mailbox -from (deliver target)
	mailboxCtr    = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512" // MyceliumMailbox contract
	ttl           = 24 * time.Hour
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: liveevmsend <plaintext>")
		os.Exit(2)
	}
	body := os.Args[1]

	ctx := context.Background()

	// Mailbox pubkey as 32 raw bytes.
	mailboxPub, err := hex.DecodeString(mailboxPubHex)
	if err != nil || len(mailboxPub) != 32 {
		fmt.Fprintf(os.Stderr, "bad mailbox pub hex: %v (len %d)\n", err, len(mailboxPub))
		os.Exit(1)
	}

	// Sender endpoint with an in-memory store (holds the outbound ciphertext).
	ep, err := longmsg.NewEndpoint(store.NewMemStore())
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewEndpoint: %v\n", err)
		os.Exit(1)
	}

	// 1) Encrypt the body to the mailbox pub (fresh ephemeral) -> pointer + ciphertext.
	ptr, err := ep.SendBody(mailboxPub, []byte(body), ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SendBody: %v\n", err)
		os.Exit(1)
	}
	cidHex := hex.EncodeToString(ptr.CID[:])
	fmt.Printf("body encrypted: cid=%s eph_pub=%s burn=%d\n",
		cidHex, hex.EncodeToString(ptr.EphemeralPub[:]), ptr.BurnDeadline)

	// Read the ciphertext back from the sender store to HTTP-push it.
	ct, err := ep.Store().Get(ptr.CID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read ciphertext back: %v\n", err)
		os.Exit(1)
	}

	// 2) HTTP-PUSH the ciphertext body to the mailbox.
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		mailboxHTTP+"/put/"+cidHex, bytes.NewReader(ct))
	if err != nil {
		fmt.Fprintf(os.Stderr, "new put req: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Burn-Deadline", strconv.FormatUint(ptr.BurnDeadline, 10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "http push: %v\n", err)
		os.Exit(1)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	fmt.Printf("http push /put/%s -> status %d\n", cidHex, resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}

	// 3) Build the E2E envelope around the canonical pointer-whisper: exactly
	// what the mailbox's secure.NewRecvCodec(CanonicalCodec) expects to unwrap.
	// SecureCodec.EncodePointer = Encrypt(mailboxPub) -> kind 0xE0 || eph || nonce || ct
	// whose decrypted plaintext is the canonical pointer. NOT wrapped twice.
	senderKey := ep.PrivKey() // sender's own 32-byte scalar (only validated by Encrypt)
	sc, err := secure.NewSendCodec(whisper.CanonicalCodec{}, senderKey, mailboxPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewSendCodec: %v\n", err)
		os.Exit(1)
	}
	pointerPayload, err := sc.EncodePointer(ptr.EphemeralPub, ptr.CID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "EncodePointer: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("pointer payload: %d bytes, leading byte 0x%02x (expect 0xe0 envelope)\n",
		len(pointerPayload), pointerPayload[0])
	crypto.Zero(senderKey) // ephemeral sender identity; mailbox decrypts via its own key

	// Post on EVM via the MyceliumMailbox contract: deliver(to=recipient, data).
	c := evm.NewBackend(rpcURL, "evm", senderAddr)
	c.SetMailbox(mailboxCtr)
	res, err := c.PostPayload(ctx, recipientAddr, pointerPayload, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PostPayload: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("pointer posted on EVM: txid=%s\n", res.TxID)

	// Wait a few poll intervals for the mailbox scanner (interval 1s) to see it.
	time.Sleep(4 * time.Second)

	// 4) Read the decrypted message back over the mailbox HTTP list/get.
	lresp, err := http.Get(mailboxHTTP + "/list")
	if err != nil {
		fmt.Fprintf(os.Stderr, "GET /list: %v\n", err)
		os.Exit(1)
	}
	lbody, _ := io.ReadAll(lresp.Body)
	lresp.Body.Close()
	fmt.Printf("mailbox /list (status %d):\n%s\n", lresp.StatusCode, string(lbody))

	gresp, err := http.Get(mailboxHTTP + "/get/" + cidHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GET /get: %v\n", err)
		os.Exit(1)
	}
	gbody, _ := io.ReadAll(gresp.Body)
	gresp.Body.Close()
	fmt.Printf("mailbox /get/%s (status %d):\n%s\n", cidHex, gresp.StatusCode, string(gbody))

	if !bytes.Contains(gbody, []byte(body)) {
		fmt.Fprintln(os.Stderr, "WARN: mailbox /get does not contain the plaintext body")
		os.Exit(1)
	}
	fmt.Println("E2E OK: mailbox decrypted + stored the long body.")
}
