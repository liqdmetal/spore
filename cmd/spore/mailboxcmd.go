// mailbox — the always-on, cross-chain long-body recipient command.
//
//	spore mailbox run  -dir DIR [-chain CHAIN ...] [-listen :ADDR] [-peer-addr HOST:PORT]
//	spore mailbox list -dir DIR
//	spore mailbox get  -dir DIR <cid-or-txid>
//
// A mailbox holds the recipient's long-term spore X25519 key + a durable
// store in -dir (key generated on first run and printed). It runs a body
// server (so senders whose node isn't publicly reachable can HTTP-PUSH the
// body by CID to /put/<cid>) plus a chain scanner over ANY backend
// (dero/evm/xmr/solana) that, on each pointer-whisper, fetches + verifies +
// decrypts the body and stores the plaintext. list/get read what arrived
// while it ran headless.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/mailbox"
	"github.com/liqdmetal/spore/internal/peer"
	"github.com/liqdmetal/spore/internal/safehttp"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
	"github.com/liqdmetal/spore/internal/whisper"
)

// addChainFlags registers the chain backend selection flags (shared by the
// mailbox run subcommand).
func addChainFlags(fs *flag.FlagSet) {
	fs.String("chain", "dero", "chain backend: dero|evm|xmr|solana")
	fs.String("rpc", "", "wallet/daemon JSON-RPC endpoint")
	fs.String("rpc-login", "", "RPC basic auth user:pass")
	fs.String("from", "", "our address (evm / chain)")
	fs.String("keyfile", "", "solana signer keypair JSON path")
	fs.String("program", "", "solana mailbox program id (default mainnet)")
	fs.String("mailbox", "", "evm: MyceliumMailbox contract address (log-based delivery)")
	fs.Bool("xmr-unverified", false, "allow the NOT live-verified XMR backend (experimental; results unreliable)")
}

func mailboxcmd(args []string) {
	if len(args) == 0 {
		mailboxUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "run":
		mailboxRun(args[1:])
	case "host":
		mailboxHost(args[1:])
	case "list":
		mailboxList(args[1:])
	case "get":
		mailboxGet(args[1:])
	case "-h", "--help":
		mailboxUsage()
	default:
		fmt.Fprintf(os.Stderr, "mailbox: unknown subcommand %q (want run|host|list|get)\n", args[0])
		os.Exit(2)
	}
}

func mailboxUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore mailbox run -dir DIR [-chain dero|evm|xmr|solana] [-listen :ADDR]
             [-rpc URL] [-rpc-login u:p] [-from ADDR] [-keyfile SOL] [-program PID]
             [-peer-addr host:port] [-peer-bin B] [-interval 3s] [-reap 30s]
             [-min-height N]          (serve + scan + decrypt long bodies, always-on)
             [-cert CERT] [-key KEY]  (serve HTTPS when both set)
             [-token SECRET]          (require Authorization: Bearer SECRET on every route)
  spore mailbox host -users DIR [-listen :ADDR] [-tokens FILE]
             [-cert CERT] [-key KEY] [-interval 3s] [-reap 30s] [-privacy]
             [-log-ttl 168h] [-min-height N] [-auto-burn]
                                      (HOSTED multi-user service: every
                                       subdirectory of -users is one mailbox,
                                       all served from ONE listener at
                                       /u/<name>/... behind ONE shared chain
                                       watcher, so chain RPC load does not grow
                                       with user count)
  spore mailbox list -dir DIR      (show decrypted messages)
  spore mailbox get -dir DIR <cid-or-txid>   (print one decrypted message)`)
}

// mailboxKeyPath is where mailbox.Open persists the long-term scalar.
func mailboxCodec(fs *flag.FlagSet, m *mailbox.Mailbox) whisper.Codec {
	base := whisper.Codec(whisper.CanonicalCodec{})
	chainType := fs.Lookup("chain").Value.String()
	if strings.EqualFold(chainType, "dero") {
		// DERO encrypts the whisper payload to the wallet natively.
		return whisper.DeroCodec{}
	}
	// Public chains (evm/xmr/solana): pointer-whispers are wrapped E2E to our
	// pubkey, so decrypt the envelope with the same mailbox key that decrypts
	// the body. Plaintext (unwrapped) canonical pointers still pass through.
	sc, err := secure.NewRecvCodec(base, m.Key())
	check(err)
	return sc
}

func mailboxRun(args []string) {
	fs := flag.NewFlagSet("mailbox run", flag.ExitOnError)
	dir := fs.String("dir", "", "data dir (persists key, bodies, and messages)")
	listen := fs.String("listen", "127.0.0.1:19292", "mailbox HTTP listen (push + serve + list/get; default loopback-only)")
	interval := fs.Duration("interval", 3*time.Second, "chain poll interval")
	reap := fs.Duration("reap", 30*time.Second, "expired-body reaper interval")
	minHeight := fs.Uint64("min-height", 0, "scan the chain from this height")
	peerAddr := fs.String("peer-addr", "", "reachable sender peer (host:port) to pull bodies not pushed here")
	peerBin := fs.String("peer-bin", "spore-peer", "path to the spore-peer binary")
	privacy := fs.Bool("privacy", false, "hosted/privacy mode: don't record the sender in the message log")
	logTTL := fs.Duration("log-ttl", mailbox.DefaultLogTTL, "decrypted-message log retention (rot); 0 disables trimming")
	cert := fs.String("cert", "", "TLS cert PEM path (serve HTTPS when set with -key)")
	key := fs.String("key", "", "TLS key PEM path (serve HTTPS when set with -cert)")
	token := fs.String("token", "", "shared secret; require `Authorization: Bearer <token>` on every HTTP route")
	addChainFlags(fs)
	_ = fs.Parse(args)

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "mailbox run: -dir required")
		fs.Usage()
		os.Exit(2)
	}
	// Exposure policy (audit C2): /list serves every DECRYPTED message — a
	// non-loopback bind without a token is a plaintext archive open to the
	// network, so it is refused outright.
	if err := safehttp.CheckBind(*listen, *token, "mailbox run"); err != nil {
		fmt.Fprintln(os.Stderr, "mailbox run:", err)
		os.Exit(2)
	}
	if *cert == "" && !safehttp.HostIsLoopback(*listen) {
		log.Printf("mailbox: WARNING — serving decrypted messages over plain HTTP on a non-loopback bind; set -cert/-key for TLS")
	}
	m, err := mailbox.Open(*dir, nil)
	check(err)
	m.SetLogTTL(*logTTL)
	if *privacy {
		m.SetNoSenderLog(true)
		log.Printf("mailbox: privacy mode — sender not recorded in the message log")
	}
	log.Printf("mailbox: message log is ENCRYPTED; retention %s", *logTTL)

	c := msgBackend(fs) // build the named chain.Chain backend
	codec := mailboxCodec(fs, m)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// HTTP surface: senders HTTP-push bodies to /put/<cid>; list/get read the
	// mailbox while it runs; /body/<cid> serves stored bodies for peer pull.
	// When a shared -token is set the surface is gated behind it so a hosted
	// mailbox isn't open to the internet; when -cert/-key are both set the
	// surface is served over HTTPS (else plain HTTP, backward compatible).
	var handler http.Handler = m.Handler()
	if *token != "" {
		handler = m.HandlerToken(*token)
		log.Printf("mailbox: HTTP auth enabled — every route requires `Authorization: Bearer <token>`")
	}
	hsrv := &http.Server{Addr: *listen, Handler: handler}
	serve := hsrv.ListenAndServe
	scheme := "http"
	if *cert != "" && *key != "" {
		serve = func() error { return hsrv.ListenAndServeTLS(*cert, *key) }
		scheme = "https"
	} else if (*cert == "") != (*key == "") {
		log.Fatalf("mailbox run: -cert and -key must both be set to serve TLS (got cert=%q key=%q)", *cert, *key)
	}
	go func() {
		log.Printf("mailbox: serving on %s://%s (dir %s)", scheme, *listen, *dir)
		if err := serve(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()		// Reap expired (burned) bodies and trim the message log (rot) in the
		// background.
		go func() {
			t := time.NewTicker(*reap)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					if n := m.Reap(time.Now()); n > 0 {
						log.Printf("mailbox: reaped %d burned body(ies)", n)
					}
					if kept, err := m.TrimLog(time.Now()); err != nil {
						log.Printf("mailbox: log trim: %v", err)
					} else if c := m.CorruptLogLines(); c > 0 {
						log.Printf("mailbox: log trim kept %d, skipped %d corrupt line(s)", kept, c)
					}
				case <-ctx.Done():
					return
				}
			}
		}()

	log.Printf("mailbox: pubkey %s", hex.EncodeToString(m.PublicKey()))
	log.Printf("mailbox: senders encrypt bodies to that pub; push the body to %s://<this-host>%s/put/<cid>", scheme, *listen)
	log.Printf("mailbox: scanning %s for pointer-whispers", c.Name())

	// Fetch: the mailbox's own store first (HTTP-pushed bodies); fall back to
	// the sender's reachable peer only when the body wasn't pushed here.
	fetch := func(ctx context.Context, cid [32]byte) ([]byte, error) {
		b, err := m.LocalFetch(ctx, cid)
		if err == nil {
			return b, nil
		}
		if *peerAddr != "" && (errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExpired)) {
			log.Printf("mailbox: body %x not local; pulling from peer %s", cid[:8], *peerAddr)
			return peer.Fetch(ctx, *peerBin, *peerAddr, cid)
		}
		return nil, err
	}

	on := func(msg mailbox.Message) {
		printMessage(">>", msg)
	}
	errc := make(chan error)
	go m.RunScanner(ctx, c, codec, chain.WatchOpts{
		MinHeight: *minHeight, Interval: *interval,
	}, fetch, on, errc)

	for {
		select {
		case err := <-errc:
			log.Printf("mailbox: scan: %v", err)
		case <-ctx.Done():
			hsrv.Close()
			return
		}
	}
}

func mailboxList(args []string) {
	fs := flag.NewFlagSet("mailbox list", flag.ExitOnError)
	dir := fs.String("dir", "", "mailbox data dir")
	_ = fs.Parse(args)
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "mailbox list: -dir required")
		fs.Usage()
		os.Exit(2)
	}
	m, err := mailbox.Open(*dir, nil)
	check(err)
	msgs, err := m.List()
	check(err)
	if len(msgs) == 0 {
		fmt.Println("no messages")
		return
	}
	fmt.Printf("%-3s %-5s %-18s %-10s %-18s %6s  %s\n", "#", "kind", "received(utc)", "topo", "cid/txid", "bytes", "preview")
	for i, msg := range msgs {
		id := msg.CID
		if id == "" {
			id = msg.TxID
		}
		if len(id) > 18 {
			id = id[:18]
		}
		preview := strings.ReplaceAll(msg.Text, "\n", " ")
		if len(preview) > 44 {
			preview = preview[:44] + "…"
		}
		fmt.Printf("%-3d %-5s %-18s %-10d %-18s %6d  %s\n",
			i, msg.Kind, time.Unix(msg.ReceivedAt, 0).UTC().Format("2006-01-02 15:04"), msg.TopoHeight, id, msg.Size, preview)
	}
}

func mailboxGet(args []string) {
	fs := flag.NewFlagSet("mailbox get", flag.ExitOnError)
	dir := fs.String("dir", "", "mailbox data dir")
	_ = fs.Parse(args)
	if *dir == "" || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "mailbox get: -dir and <cid-or-txid> required")
		fs.Usage()
		os.Exit(2)
	}
	m, err := mailbox.Open(*dir, nil)
	check(err)
	msg, err := m.Get(fs.Arg(0))
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintf(os.Stderr, "no message with id %q\n", fs.Arg(0))
		os.Exit(1)
	}
	check(err)
	printMessage("", *msg)
}

func printMessage(prefix string, msg mailbox.Message) {
	meta := fmt.Sprintf("%s/%s/%s", time.Unix(msg.ReceivedAt, 0).UTC().Format("2006-01-02 15:04:05"), msg.TxID, msg.Sender)
	kind := msg.Kind
	cidNote := ""
	if msg.Kind == "long" {
		kind = "long body"
		cidNote = fmt.Sprintf(" (cid %s)", msg.CID)
	}
	sep := ""
	if prefix != "" {
		sep = " "
	}
	if prefix != "" {
		fmt.Printf("%s%s[%s] %s%s\n", prefix, sep, meta, kind, cidNote)
	} else {
		fmt.Printf("[%s] %s%s\n", meta, kind, cidNote)
	}
	fmt.Println(msg.Text)
}
