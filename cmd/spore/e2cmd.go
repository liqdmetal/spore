package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/backend"
	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/store"
)

// msgE2 is deliberately separate from legacy msg: it has no one-shot
// fallback and never accepts plaintext as a command-line flag (argv is
// visible to shell history, `ps`, and crash/monitoring reports). Bundles can
// be supplied explicitly (-bundle) or fetched from a mailbox's /prekey
// endpoint (-bundle-url); either way, EstablishInitiator still verifies the
// bundle's SPK_sig against -pinned-sig, so discovery is a transport
// convenience only and never substitutes for out-of-band trust.
func msgE2(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spore msg send-e2|recv-e2 [flags]")
		return
	}
	switch args[0] {
	case "send-e2":
		msgSendE2(args[1:])
	case "recv-e2":
		msgRecvE2(args[1:])
	case "reply-e2":
		msgReplyE2(args[1:])
	case "forward-e2":
		msgForwardE2(args[1:])
	case "sessions":
		msgSessions(args[1:])
	case "prekeygen":
		msgPrekeygen(args[1:])
	case "compose":
		msgCompose(args[1:])
	case "flush":
		msgFlush(args[1:])
	case "mail":
		msgMail(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "msg: unknown e2 subcommand")
	}
}

func e2Store(url, token string) (ratchetwire.BodyStore, error) {
	if url == "" {
		return nil, errors.New("-store is required (E2 never uses a local-only implicit store)")
	}
	return store.NewHTTPStoreWithToken(url, token)
}
func e2Carrier(fs *flag.FlagSet) (ratchetwire.ChainCarrier, error) {
	value := func(name string) string {
		if f := fs.Lookup(name); f != nil {
			return f.Value.String()
		}
		return ""
	}
	privateKey := value("private-key")
	if path := value("private-key-file"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return ratchetwire.ChainCarrier{}, err
		}
		privateKey = strings.TrimSpace(string(b))
	}
	var relays []string
	if raw := value("relays"); raw != "" {
		for _, r := range strings.Split(raw, ",") {
			if r = strings.TrimSpace(r); r != "" {
				relays = append(relays, r)
			}
		}
	}
	cfg := backend.ChainConfig{Type: value("chain"), RPC: value("rpc"), Login: value("rpc-login"), From: value("from"), KeyFile: value("keyfile"), ProgramID: value("program"), PrivateKey: privateKey, Network: value("network"), BaseURL: value("base-url"), Address: value("address"), Name: value("chain-id"), PostPath: value("post-path"), ListPath: value("list-path"), HeightPath: value("height-path"), MessageField: value("message-field"), RecipientField: value("recipient-field"), DeliveryGuaranteed: value("delivery-guaranteed") == "true", Relays: relays}
	c, err := backend.Build(context.Background(), cfg)
	if err != nil {
		return ratchetwire.ChainCarrier{}, err
	}
	var codec ratchetwire.ChainPayloadCodec
	switch strings.ToLower(c.Name()) {
	case "dero":
		codec = ratchetwire.DeroChainCodec{}
	case "evm", "solana":
		codec = ratchetwire.JSONCodec{}
	case "nostr", "bitcoin", "cosmos", "ton":
		codec = ratchetwire.CanonicalChainCodec{}
	default:
		return ratchetwire.ChainCarrier{}, fmt.Errorf("E2 pointer carrier unsupported on %s; refusing downgrade", c.Name())
	}
	return ratchetwire.ChainCarrier{Chain: c, Codec: codec}, nil
}
func readHexFile(path string, n int) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	x, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || (n > 0 && len(x) != n) {
		return nil, fmt.Errorf("%s must contain %d-byte hex", path, n)
	}
	return x, nil
}
func readBundle(path string) (*ratchet.SPKBundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out ratchet.SPKBundle
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// fetchBundle discovers a recipient's public prekey bundle from a mailbox's
// GET /prekey endpoint. This is a transport convenience over -bundle FILE.json
// only: EstablishInitiator still verifies SPK_sig against the caller-supplied
// -pinned-sig, so a compromised or malicious mailbox can at worst withhold or
// serve a stale bundle (causing send-e2 to fail) — it cannot forge a bundle
// that passes signature pinning, and it never sees plaintext, ciphertext, or
// any private key material (this is a GET with no body).
func fetchBundle(ctx context.Context, url, token string) (*ratchet.SPKBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("bundle discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("bundle discovery: recipient has not published a prekey bundle")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle discovery: unexpected status %s", resp.Status)
	}
	var wire struct {
		Bundle ratchet.SPKBundle `json:"bundle"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return nil, fmt.Errorf("bundle discovery: malformed response: %w", err)
	}
	return &wire.Bundle, nil
}

// readPlaintext resolves the message body without ever putting it on the
// command line: shell history, `ps`/process listings, and crash/monitoring
// tools all read argv. -msg-file reads a file (use /dev/stdin or a named
// pipe for scripting); with neither flag set, plaintext is read from stdin
// so it never appears as a process argument.
func readPlaintext(msgFile string) ([]byte, error) {
	if msgFile != "" {
		if msgFile == "-" {
			return readAllTrimNewline(os.Stdin)
		}
		b, err := os.ReadFile(msgFile)
		if err != nil {
			return nil, err
		}
		return trimTrailingNewline(b), nil
	}
	return readAllTrimNewline(os.Stdin)
}

func readAllTrimNewline(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return trimTrailingNewline(b), nil
}

func trimTrailingNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b
}

func e2Common(fs *flag.FlagSet) {
	fs.String("chain", "dero", "pointer carrier: dero|evm|solana (xmr unsupported)")
	fs.String("rpc", "", "chain RPC")
	fs.String("rpc-login", "", "RPC user:pass")
	fs.String("from", "", "sender chain address")
	fs.String("keyfile", "", "Solana signer JSON")
	fs.String("program", "", "Solana program ID")
	fs.String("private-key", "", "Nostr private key (prefer -private-key-file)")
	fs.String("private-key-file", "", "file containing Nostr private key")
	fs.String("relays", "", "comma-separated Nostr relay URLs")
	fs.String("network", "", "carrier network")
	fs.String("base-url", "", "carrier API base URL")
	fs.String("address", "", "carrier wallet/address")
	fs.String("chain-id", "", "Cosmos chain ID")
	fs.String("post-path", "", "carrier post path")
	fs.String("list-path", "", "carrier list path")
	fs.String("height-path", "", "carrier height path")
	fs.String("message-field", "", "Cosmos message field")
	fs.String("recipient-field", "", "Cosmos recipient field")
	fs.Bool("delivery-guaranteed", false, "assert carrier preserves exact pointer delivery")
	fs.String("store", "", "HTTP off-chain frame store URL")
	fs.String("store-token", "", "bearer token for the HTTP off-chain frame store")
	fs.String("state-dir", "", "encrypted endpoint session state directory (required)")
	fs.String("state-key", "", "file containing 32-byte hex state encryption key (required)")
	fs.Duration("session-ttl", 0, "inactivity TTL for durable E2 sessions (zero disables expiry)")
}

func msgPrekeygen(args []string) {
	fs := flag.NewFlagSet("msg prekeygen", flag.ExitOnError)
	identity := fs.String("identity-out", "", "identity private key hex output (0600)")
	spk := fs.String("spk-out", "", "signed-prekey private key hex output (0600)")
	opk := fs.String("opk-out", "", "optional one-time-prekey private key hex output (0600)")
	bundle := fs.String("bundle-out", "", "public SPKBundle JSON output (0644)")
	spkID := fs.Uint("spk-id", 1, "signed-prekey identifier")
	opkID := fs.Uint("opk-id", 1, "one-time-prekey identifier")
	_ = fs.Parse(args)
	if *identity == "" || *spk == "" || *bundle == "" {
		check(errors.New("prekeygen requires -identity-out -spk-out -bundle-out"))
	}
	key := func() []byte {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			check(e)
		}
		return b
	}
	ik, sk := key(), key()
	var op *[32]byte
	if *opk != "" {
		x := key()
		op = &[32]byte{}
		copy(op[:], x)
	}
	b, err := ratchet.BuildBundle(ik, sk, uint32(*spkID), op, uint32(*opkID))
	check(err)
	write := func(path string, data []byte, mode os.FileMode) {
		if err := os.WriteFile(path, data, mode); err != nil {
			check(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			check(err)
		}
	}
	write(*identity, []byte(hex.EncodeToString(ik)+"\\n"), 0600)
	write(*spk, []byte(hex.EncodeToString(sk)+"\\n"), 0600)
	if *opk != "" {
		write(*opk, []byte(hex.EncodeToString(op[:])+"\\n"), 0600)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	check(err)
	write(*bundle, append(data, '\n'), 0644)
}

func msgSendE2(args []string) {
	fs := flag.NewFlagSet("msg send-e2", flag.ExitOnError)
	to := fs.String("to", "", "recipient chain address")
	identity := fs.String("identity", "", "file containing sender identity private key hex")
	bundle := fs.String("bundle", "", "recipient SPK bundle JSON file (mutually exclusive with -bundle-url)")
	bundleURL := fs.String("bundle-url", "", "fetch recipient SPK bundle from a mailbox GET /prekey URL (mutually exclusive with -bundle; discovery is a transport convenience only — -pinned-sig is still required and still verified)")
	bundleToken := fs.String("bundle-token", "", "bearer token for -bundle-url, if the mailbox requires auth")
	pinned := fs.String("pinned-sig", "", "recipient signing public key hex")
	msgFile := fs.String("msg-file", "", "file containing plaintext (use '-' or omit for stdin; never pass plaintext as an argv flag — argv is visible to shell history, ps, and crash reports)")
	ttl := fs.Duration("ttl", 24*time.Hour, "frame retention")
	e2Common(fs)
	_ = fs.Parse(args)
	if *to == "" || *identity == "" || *pinned == "" {
		check(errors.New("send-e2 requires -to -identity -pinned-sig, and exactly one of -bundle or -bundle-url (plaintext via -msg-file or stdin)"))
	}
	if (*bundle == "") == (*bundleURL == "") {
		check(errors.New("send-e2 requires exactly one of -bundle or -bundle-url, not both and not neither"))
	}
	if err := sendE2Core(fs, *to, *identity, *bundle, *bundleURL, *bundleToken, *pinned, *msgFile, *ttl); err != nil {
		check(err)
	}
}

// sendE2Core is the shared send path for send-e2 and the offline-compose
// flush. fs must be a parsed e2Common FlagSet. Errors are returned (caller
// decides fatal vs spool-retry) and the plaintext never touches argv.
func sendE2Core(fs *flag.FlagSet, to, identity, bundle, bundleURL, bundleToken, pinned, msgFile string, ttl time.Duration) error {
	plaintext, err := readPlaintext(msgFile)
	if err != nil {
		return err
	}
	if len(plaintext) == 0 {
		return errors.New("send-e2: empty plaintext")
	}
	st, err := e2Store(fs.Lookup("store").Value.String(), fs.Lookup("store-token").Value.String())
	if err != nil {
		return err
	}
	id, err := readHexFile(identity, 32)
	if err != nil {
		return err
	}
	var b *ratchet.SPKBundle
	if bundle != "" {
		b, err = readBundle(bundle)
		if err != nil {
			return err
		}
	} else {
		b, err = fetchBundle(context.Background(), bundleURL, bundleToken)
		if err != nil {
			return err
		}
	}
	sig, err := hex.DecodeString(pinned)
	if err != nil {
		return err
	}
	if len(sig) != 32 {
		return errors.New("-pinned-sig must be 32-byte hex")
	}
	stateDir := fs.Lookup("state-dir").Value.String()
	stateKeyFile := fs.Lookup("state-key").Value.String()
	if stateDir == "" || stateKeyFile == "" {
		return errors.New("E2 requires -state-dir and -state-key")
	}
	stateKey, err := readHexFile(stateKeyFile, 32)
	if err != nil {
		return err
	}
	sessionTTL, err := time.ParseDuration(fs.Lookup("session-ttl").Value.String())
	if err != nil {
		return err
	}
	// Apply expiry before restoring any durable session so stale key material
	// cannot process a frame during this invocation.
	states, err := ratchetwire.NewFileStateStore(stateDir, stateKey)
	if err != nil {
		return err
	}
	ep, err := ratchetwire.NewDurableEndpointWithExpiry(st, states, sessionTTL, time.Now())
	if err != nil {
		return err
	}
	_, raw, err := ep.SendFirst(id, b, sig, plaintext, time.Now().Add(ttl))
	if err != nil {
		return err
	}
	c, err := e2Carrier(fs)
	if err != nil {
		return err
	}
	r, err := c.PostPointer(context.Background(), to, raw, 1)
	if err != nil {
		return err
	}
	fmt.Printf("sent-e2 txid %s pointer %x\n", r.TxID, raw)
	return nil
}

// msgForwardE2 re-sends an existing decrypted message (e.g. one saved by
// recv-e2 -out-dir) to a NEW recipient. It starts a fresh X3DH session with
// that recipient — forward is a new conversation, not a continuation — and
// reuses the exact sendE2Core path send-e2 uses, so bundle discovery,
// pinning, durable state, and the pointer post all behave identically.
func msgForwardE2(args []string) {
	fs := flag.NewFlagSet("msg forward-e2", flag.ExitOnError)
	to := fs.String("to", "", "new recipient chain address")
	identity := fs.String("identity", "", "file containing sender identity private key hex")
	bundle := fs.String("bundle", "", "recipient SPK bundle JSON file (mutually exclusive with -bundle-url)")
	bundleURL := fs.String("bundle-url", "", "fetch recipient SPK bundle from a mailbox GET /prekey URL (mutually exclusive with -bundle)")
	bundleToken := fs.String("bundle-token", "", "bearer token for -bundle-url, if the mailbox requires auth")
	pinned := fs.String("pinned-sig", "", "recipient signing public key hex")
	file := fs.String("file", "", "the decrypted message file to forward (e.g. a <txid>.msg from recv-e2 -out-dir)")
	ttl := fs.Duration("ttl", 24*time.Hour, "frame retention")
	e2Common(fs)
	_ = fs.Parse(args)
	if *to == "" || *identity == "" || *pinned == "" || *file == "" {
		check(errors.New("forward-e2 requires -to -identity -pinned-sig -file, and exactly one of -bundle or -bundle-url"))
	}
	if (*bundle == "") == (*bundleURL == "") {
		check(errors.New("forward-e2 requires exactly one of -bundle or -bundle-url"))
	}
	if err := sendE2Core(fs, *to, *identity, *bundle, *bundleURL, *bundleToken, *pinned, *file, *ttl); err != nil {
		check(err)
	}
}

func msgRecvE2(args []string) {
	fs := flag.NewFlagSet("msg recv-e2", flag.ExitOnError)
	identity := fs.String("identity", "", "our identity private key file")
	spk := fs.String("spk", "", "our signed-prekey private key file")
	opk := fs.String("opk", "", "legacy single one-time-prekey private key file")
	opkPool := fs.String("opk-pool", "", "endpoint-local persistent one-time-prekey pool JSON (preferred)")
	interval := fs.Duration("interval", 3*time.Second, "poll interval")
	min := fs.Uint64("min-height", 0, "scan height")
	autoAck := fs.Bool("auto-ack", false, "reply 'delivered' on the same session after each successfully decrypted message (delivery receipts)")
	ackTTL := fs.Duration("ack-ttl", 24*time.Hour, "frame retention for auto-ack receipts")
	outDir := fs.String("out-dir", "", "write each received message body to a file in this dir (named <txid>.msg) instead of stdout — attachments/keep-a-copy mode")
	ntfy := fs.String("ntfy", "", "POST a 'new message' notification to this ntfy topic URL on each message (content never leaves the mailbox; metadata only)")
	maildbPath := fs.String("maildb", "", "path to the local mail store (maildb JSON). When set, each decrypted message is recorded into its thread + search index, and blocked contacts are dropped")
	e2Common(fs)
	_ = fs.Parse(args)
	if *identity == "" || *spk == "" {
		check(errors.New("recv-e2 requires -identity and -spk"))
	}
	st, err := e2Store(fs.Lookup("store").Value.String(), fs.Lookup("store-token").Value.String())
	check(err)
	ik, err := readHexFile(*identity, 32)
	check(err)
	sk, err := readHexFile(*spk, 32)
	check(err)
	var op *[32]byte
	var pool *ratchetwire.OPKPool
	if *opkPool != "" {
		pool, err = ratchetwire.NewPersistentOPKPool(*opkPool)
		check(err)
	}
	if *opk != "" {
		x, e := readHexFile(*opk, 32)
		check(e)
		op = &[32]byte{}
		copy(op[:], x)
	}
	c, err := e2Carrier(fs)
	check(err)
	stateDir := fs.Lookup("state-dir").Value.String()
	stateKeyFile := fs.Lookup("state-key").Value.String()
	if stateDir == "" || stateKeyFile == "" {
		check(errors.New("E2 requires -state-dir and -state-key"))
	}
	stateKey, err := readHexFile(stateKeyFile, 32)
	check(err)
	sessionTTL, err := time.ParseDuration(fs.Lookup("session-ttl").Value.String())
	check(err)
	states, err := ratchetwire.NewFileStateStore(stateDir, stateKey)
	check(err)
	ep, err := ratchetwire.NewDurableEndpointWithExpiry(st, states, sessionTTL, time.Now())
	check(err)
	// Open the mail store ONCE, not per message (re-reading the whole JSON
	// file for every delivery is wasteful, and a per-message Open failure
	// would be silently swallowed). Fail loudly up front instead.
	var mdb *maildb.MailDB
	if *maildbPath != "" {
		mdb, err = maildb.Open(*maildbPath)
		check(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	in, errs := ratchetwire.WatchE2(ctx, c, chain.WatchOpts{MinHeight: *min, Interval: *interval})
	for {
		select {
		case inc, ok := <-in:
			if !ok {
				return
			}
			// Allowlist check BEFORE any decryption: a blocked sender's
			// frame never touches ratchet state and is never even parsed
			// past the pointer. Chain senders are pseudonymous, so this
			// filters by chain identity (what maildb knows), not by
			// long-term key.
			if mdb != nil && !mdb.Allowed(inc.Sender) {
				fmt.Fprintf(os.Stderr, "e2: dropped message from blocked sender %s\n", shortTx(inc.Sender))
				continue
			}
			frame, p, e := c.FetchIncomingE2(st, inc, time.Now())
			if e != nil {
				fmt.Fprintln(os.Stderr, "e2 frame:", e)
				continue
			}
			var plain []byte
			switch frame.Kind {
			case ratchetwire.FrameInit:
				body, bodyErr := ratchetwire.GetBody(st, p, time.Now())
				if bodyErr != nil {
					fmt.Fprintln(os.Stderr, "e2 frame:", bodyErr)
					continue
				}
				if pool != nil {
					plain, e = ep.ReceiveFirstFromOPKPool(ik, sk, pool, frame, body)
				} else {
					plain, e = ep.ReceiveFirst(ik, sk, op, frame, body)
				}
			case ratchetwire.FrameMessage:
				// Continuations must use the installed ratchet session. Never
				// reinterpret them as a fresh handshake (downgrade resistance).
				plain, e = ep.ReceiveNext(p, time.Now())
			default:
				e = ratchetwire.ErrLegacyDowngrade
			}
			if e != nil {
				fmt.Fprintln(os.Stderr, "e2 decrypt:", e)
				continue
			}
			// Receipts are ratcheted messages like any other: detect the
			// envelope and surface it as an ack line instead of a message.
			receiptInReplyTo, receiptStatus, isReceipt := parseReceipt(plain)
			if isReceipt {
				fmt.Printf("ack %s: %s (for %s)\n", shortTx(inc.TxID), receiptStatus, shortTx(receiptInReplyTo))
				continue
			}
			// Attachments / keep-a-copy mode: write the decrypted body to a
			// file named by txid instead of printing it.
			if *outDir != "" {
				if err := os.WriteFile(filepath.Join(*outDir, shortTx(inc.TxID)+".msg"), plain, 0600); err != nil {
					fmt.Fprintln(os.Stderr, "e2 out-dir:", err)
					continue
				}
				fmt.Printf("msg %s: saved %s/%s.msg\n", shortTx(inc.TxID), *outDir, shortTx(inc.TxID))
			} else {
				fmt.Printf("msg %s: %s\n", shortTx(inc.TxID), plain)
			}
			// Mail-store hook: record into threads + search index. Blocked
			// senders were already dropped before decryption, so everything
			// recorded here passed the allowlist.
			if mdb != nil {
				if rerr := mdb.RecordMessage(hex.EncodeToString(frame.SessionID[:]), inc.Sender, inc.TxID, time.Now(), plain); rerr != nil {
					fmt.Fprintln(os.Stderr, "e2 maildb:", rerr)
				}
			}
			// ntfy hook: notify that a message arrived. The ntfy server
			// sees only "you got a message" + a short txid — the body never
			// leaves the mailbox. Receipts are skipped: a receipt already
			// implies an active conversation and auto-ack would re-notify
			// on every ack. Topic URL secrecy is the access control.
			if *ntfy != "" && !isReceipt {
				body := fmt.Sprintf("spore: new message %s", shortTx(inc.TxID))
				req, nerr := http.NewRequestWithContext(ctx, http.MethodPost, *ntfy, strings.NewReader(body))
				if nerr == nil {
					req.Header.Set("Title", "Spore message")
					// Bounded client: an unreachable/slow ntfy server must
					// never wedge the receive loop.
					if _, derr := (&http.Client{Timeout: 10 * time.Second}).Do(req); derr != nil {
						fmt.Fprintln(os.Stderr, "e2 ntfy:", derr)
					}
				}
			}
			if *autoAck && frame.SessionID != ([8]byte{}) {
				// Reply "delivered" on the same session; the sender's recv
				// side prints it as an ack line. Best-effort: a failed ack
				// send or post is logged, never fatal.
				_, raw, ackErr := sendReceipt(ep, frame.SessionID, inc.TxID, "delivered", *ackTTL)
				if ackErr != nil {
					fmt.Fprintln(os.Stderr, "e2 ack:", ackErr)
					continue
				}
				if _, postErr := c.PostPointer(ctx, inc.Sender, raw, 1); postErr != nil {
					fmt.Fprintln(os.Stderr, "e2 ack post:", postErr)
				}
			}
		case e := <-errs:
			if e != nil {
				fmt.Fprintln(os.Stderr, "e2 watch:", e)
			}
		case <-ctx.Done():
			return
		}
	}
}

// msgReplyE2 continues an existing ratchet session: the email "reply" —
// same conversation, SendNext on the durable session. The pointer is posted
// to the recipient chain address like any other continuation.
func msgReplyE2(args []string) {
	fs := flag.NewFlagSet("msg reply-e2", flag.ExitOnError)
	to := fs.String("to", "", "recipient chain address")
	sessionHex := fs.String("session", "", "16-hex session id (see msg sessions)")
	msgFile := fs.String("msg-file", "", "file containing plaintext (use '-' or omit for stdin; never pass plaintext as an argv flag)")
	ttl := fs.Duration("ttl", 24*time.Hour, "frame retention")
	e2Common(fs)
	_ = fs.Parse(args)
	if *to == "" || *sessionHex == "" {
		check(errors.New("reply-e2 requires -to and -session (plaintext via -msg-file or stdin)"))
	}
	rawID, err := hex.DecodeString(*sessionHex)
	check(err)
	if len(rawID) != 8 {
		check(errors.New("-session must be 16 hex chars (8 bytes)"))
	}
	var sessionID [8]byte
	copy(sessionID[:], rawID)
	plaintext, err := readPlaintext(*msgFile)
	check(err)
	if len(plaintext) == 0 {
		check(errors.New("reply-e2: empty plaintext"))
	}
	st, err := e2Store(fs.Lookup("store").Value.String(), fs.Lookup("store-token").Value.String())
	check(err)
	stateDir := fs.Lookup("state-dir").Value.String()
	stateKeyFile := fs.Lookup("state-key").Value.String()
	if stateDir == "" || stateKeyFile == "" {
		check(errors.New("E2 requires -state-dir and -state-key"))
	}
	stateKey, err := readHexFile(stateKeyFile, 32)
	check(err)
	sessionTTL, err := time.ParseDuration(fs.Lookup("session-ttl").Value.String())
	check(err)
	states, err := ratchetwire.NewFileStateStore(stateDir, stateKey)
	check(err)
	ep, err := ratchetwire.NewDurableEndpointWithExpiry(st, states, sessionTTL, time.Now())
	check(err)
	_, raw, err := ep.SendNext(sessionID, plaintext, time.Now().Add(*ttl))
	check(err)
	c, err := e2Carrier(fs)
	check(err)
	r, err := c.PostPointer(context.Background(), *to, raw, 1)
	check(err)
	fmt.Printf("reply-e2 txid %s pointer %x\n", r.TxID, raw)
}

// msgSessions lists the durable ratchet sessions for the configured state
// dir. Sessions are the threads: each id is one conversation you can reply
// into with reply-e2.
func msgSessions(args []string) {
	fs := flag.NewFlagSet("msg sessions", flag.ExitOnError)
	e2Common(fs)
	_ = fs.Parse(args)
	// Listing sessions never touches the off-chain body store, so -store is
	// optional here: fall back to an in-memory store when omitted.
	var st ratchetwire.BodyStore
	if storeURL := fs.Lookup("store").Value.String(); storeURL != "" {
		s, err := e2Store(storeURL, fs.Lookup("store-token").Value.String())
		check(err)
		st = s
	} else {
		st = store.NewMemStore()
	}
	stateDir := fs.Lookup("state-dir").Value.String()
	stateKeyFile := fs.Lookup("state-key").Value.String()
	if stateDir == "" || stateKeyFile == "" {
		check(errors.New("E2 requires -state-dir and -state-key"))
	}
	stateKey, err := readHexFile(stateKeyFile, 32)
	check(err)
	sessionTTL, err := time.ParseDuration(fs.Lookup("session-ttl").Value.String())
	check(err)
	states, err := ratchetwire.NewFileStateStore(stateDir, stateKey)
	check(err)
	ep, err := ratchetwire.NewDurableEndpointWithExpiry(st, states, sessionTTL, time.Now())
	check(err)
	ids := ep.Sessions.IDs()
	if len(ids) == 0 {
		fmt.Println("no sessions")
		return
	}
	for _, id := range ids {
		fmt.Printf("%x\n", id)
	}
}
