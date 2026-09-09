// Command compost is the CLI for the compostable messenger on DERO.
//
// Subcommands:
//
//	demo        in-process send→receive→burn lifecycle (no node)
//	keygen      print a fresh medium-term key (pub + priv hex)
//	daemon      recipient mailbox: durable inbox + chain scanner + decrypt
//	send        encrypt a message, push body to recipient inbox, post anchor
//
// Model A (mailbox): each endpoint runs its own `compost daemon`. Senders push
// the encrypted body straight to the recipient's daemon (the inbox); no shared
// or third-party store ever holds ciphertext for more than one conversation.
// The daemon keeps bodies on disk, reaps them at TTL, and only decrypts a body
// once its anchor appears on-chain.
package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/backend"
	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/channel"
	"github.com/liqdmetal/spore/internal/crypto"
	derodaemon "github.com/liqdmetal/spore/internal/daemon"
	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/donate"
	"github.com/liqdmetal/spore/internal/longmsg"
	"github.com/liqdmetal/spore/internal/peer"
	"github.com/liqdmetal/spore/internal/safehttp"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/session"
	"github.com/liqdmetal/spore/internal/store"
	"github.com/liqdmetal/spore/internal/whisper"
)

//go:embed web/chat.html
var chatHTML []byte

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if os.Args[1] == "-version" || os.Args[1] == "version" {
		fmt.Printf("spore %s\n", version)
		return
	}
	switch os.Args[1] {
	case "demo":
		demo()
	case "keygen":
		keygen()
	case "daemon":
		daemon(os.Args[2:])
	case "send":
		send(os.Args[2:])
	case "channel":
		channelserve(os.Args[2:])
	case "chat":
		chat(os.Args[2:])
	case "web":
		webchat(os.Args[2:])
	case "whisper":
		whispercmd(os.Args[2:])
	case "donate":
		donatecmd(os.Args[2:])
	case "msg":
		if len(os.Args) > 2 && (os.Args[2] == "send-e2" || os.Args[2] == "recv-e2" || os.Args[2] == "reply-e2" || os.Args[2] == "forward-e2" || os.Args[2] == "sessions" || os.Args[2] == "prekeygen" || os.Args[2] == "compose" || os.Args[2] == "flush" || os.Args[2] == "mail" || os.Args[2] == "invoice" || os.Args[2] == "pay") {
			msgE2(os.Args[2:])
		} else {
			msgcmd(os.Args[2:])
		}
	case "mailbox":
		mailboxcmd(os.Args[2:])
	case "panic":
		paniccmd(os.Args[2:])
	case "init":
		initcmd(os.Args[2:])
	case "prekeybatch":
		prekeybatchcmd(os.Args[2:])
	case "relay":
		relaycmd(os.Args[2:])
	case "status":
		statuscmd(os.Args[2:])
	case "doctor":
		doctorcmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore demo
  spore keygen
  spore daemon -listen :PORT -dir DIR -priv HEX -rpc URL [-rpc-login u:p]
  spore send -to ADDR -peer-pub HEX -peer-inbox URL -msg TEXT [-rpc URL] [-rpc-login u:p] [-ttl 1h]
  spore channel -listen :PORT [-linettl 7d] [-presencettl 1m] [-dir D]   (run an IRC box; rooms rot after linettl)
  spore chat -box URL -channel NAME -nick X [-key HEX] [-interval 3s]
             [-say "text"] [-online]
  spore web -listen :PORT [-wallet-rpc URL -wallet-login u:p] [-dir D]  (browser chat)
  spore whisper send -rpc URL [-rpc-login u:p] -to ADDR -msg TEXT   (no-relay short)
  spore whisper send-long -to ADDR -recipient-pub HEX -file F|-msg TEXT [-out-dir D] [-rpc URL]
  spore whisper recv -rpc URL [-rpc-login u:p] [-key KFILE] [-peer-addr host:port] [-peer-bin B]
  spore whisper keygen [-key KFILE]
  spore donate [chain] | --all                          (per-chain donation rail)
  spore msg send -chain dero|evm|xmr|solana -to ADDR -msg TEXT ...   (chain-agnostic send)
  spore msg recv -chain dero|evm|xmr|solana ...                       (chain-agnostic recv)
  spore msg prekeygen -identity-out F -spk-out F -bundle-out F [-opk-out F]   (E2 key material)
  spore msg send-e2 -to ADDR -identity F (-bundle F | -bundle-url URL) -pinned-sig HEX
             [-chain dero|evm|solana|nostr|bitcoin|cosmos|ton ...] -store URL
             -state-dir D -state-key F [-msg-file F|-]   (forward-private E2 send; plaintext NEVER on argv)
  spore msg recv-e2 -identity F -spk F [-opk-pool F] -store URL -state-dir D -state-key F
             [-auto-ack] [-maildb F] [-out-dir D] [-ntfy URL]   (forward-private E2 receive loop)
  spore msg reply-e2 -to ADDR -session HEX -state-dir D -state-key F [-msg-file F|-]   (continue a thread)
  spore msg forward-e2 -to ADDR -identity F -file F (-bundle F | -bundle-url URL) -pinned-sig HEX ...   (new session, same body)
  spore msg sessions [-store URL] -state-dir D -state-key F   (list thread/session ids)
  spore msg compose -out DIR [-msg-file F|-] ...   (offline: queue a send for later)
  spore msg flush -dir DIR   (drain the compose queue through the real send path)
  spore msg mail -db F add|list|block|unblock|threads|search|purge [flags]   (local contacts/threads/search)
  spore msg invoice -to ADDR -session HEX -amount 25dero [-for TEXT] [-due 72h] ...   (request payment in-thread)
  spore msg pay -to ADDR -session HEX -amount 25dero [-invoice ID] ...   (settle: money + proof ride ONE atomic tx)
  spore panic [-home ~/.spore] [-state-dir D] [-maildb F] [-spool D] [-out-dir D] [-confirm]   (verifiable local wipe; dry-run without -confirm)
  spore init [-dir ~/.spore] [-opks 50] [-chain dero] [-store URL]   (one-shot onboarding: generates identity kit + config.json; afterwards ALL e2 commands pick up defaults automatically)
  spore prekeybatch gen -out F.json [-n 50] [-start-id 1]   (offline: sign N single-use PUBLIC bundles; OPK privates -> your opk pool)
  spore prekeybatch push -in F.json -mailbox URL [-token SECRET]   (upload batch so GET /prekey can serve single-use bundles)
  spore prekeybatch status -mailbox URL   (is the mailbox serving prekey material? consumes one bundle)
  spore status [-chain dero|evm|xmr|solana ...] [-mailbox-http URL] [-timeout 5s]   (connection health HUD)
  spore doctor [-priv HEX] [-dir DIR] [-listen ADDR] [-chain ...]                   (pre-flight sanity check)
  spore msg send-long -to ADDR -recipient-pub HEX -file F|-msg TEXT [-xmr XMRADDR] [-out-dir D] [-rpc URL] [-daemon URL] [-ttl 24h]   (long body; pointer rides DERO whisper; XMR = identity tag)
  spore msg keygen [-out FILE]           (identity keypair for E2E encryption)
  spore msg send ... -key HEX -peer-pub HEX    (encrypt E2E to peer pub)
  spore msg recv ... -key HEX                   (decrypt E2E with our priv)
  spore mailbox run -dir DIR [-chain dero|evm|xmr|solana] [-listen :ADDR] [-peer-addr H:P] [-rpc URL] [-from ADDR] [-keyfile SOL] [-program PID]   (always-on long-body serve+scan+decrypt)
  spore mailbox host -users DIR [-listen :ADDR] [-tokens FILE] [-cert C -key K] [-interval 3s]   (HOSTED multi-user: N mailboxes, ONE shared chain watcher, one listener at /u/<name>/...)
  spore mailbox list -dir DIR                   (show decrypted messages)
  spore mailbox get -dir DIR <cid-or-txid>      (print one decrypted message)
  spore relay run -listen :ADDR [-dir DIR] [-token SECRET] [-interval 10s] [-reap 30s]
             (store-and-forward hop for opaque bodies: push via X-Relay-Dest, forward to the mailbox)
  spore relay -h, --help                         (relay help)`)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// writeJSON writes v as a JSON response.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func parseLogin(login string) (u, p string) {
	if login == "" {
		return "", ""
	}
	for i := 0; i < len(login); i++ {
		if login[i] == ':' {
			return login[:i], login[i+1:]
		}
	}
	return login, ""
}

func makeClient(fs *flag.FlagSet) *dero.Client {
	u, p := parseLogin(fs.Lookup("rpc-login").Value.String())
	return dero.NewClient(fs.Lookup("rpc").Value.String(), u, p)
}

func addRPCFlags(fs *flag.FlagSet) {
	fs.String("rpc", "http://127.0.0.1:20209/json_rpc", "wallet RPC /json_rpc endpoint")
	fs.String("rpc-login", "", "wallet RPC basic auth user:pass")
}

// keygen prints a fresh medium-term key as pub:priv hex. The pub half goes to
// senders; the priv half is what the recipient's daemon runs with.
func keygen() {
	e, err := session.New(store.NewMemStore())
	check(err)
	sigPub, err := secure.SigPubOf(e.PrivKey())
	check(err)
	fmt.Printf("pub:  %s\n", hex.EncodeToString(e.PublicKey()))
	fmt.Printf("sig:  %s\n", hex.EncodeToString(sigPub))
	fmt.Printf("priv: %s\n", hex.EncodeToString(e.PrivKey()))
	fmt.Println("give 'pub' AND 'sig' to senders; run your daemon with 'priv'.")
}

// daemon runs a recipient's mailbox: an HTTP inbox that accepts pushed bodies
// (stored durably on disk), plus a scanner that polls the chain for anchors
// and decrypts the matching body. One process; nothing is ever handed to a
// third party. Bodies are reaped once their TTL passes.
func daemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:19191", "mailbox listen address (sender inbox; default loopback-only)")
	dir := fs.String("dir", "", "data dir for the durable body store")
	priv := fs.String("priv", "", "our medium-term privkey (hex)")
	interval := fs.Duration("interval", 5*time.Second, "anchor poll interval")
	reap := fs.Duration("reap", 30*time.Second, "body reaper interval")
	addRPCFlags(fs)
	_ = fs.Parse(args)

	if *dir == "" || *priv == "" {
		fmt.Fprintln(os.Stderr, "daemon: -dir and -priv required")
		fs.Usage()
		os.Exit(2)
	}
	// Exposure policy (audit C2): the daemon inbox accepts pushed bodies from
	// the network; refuse a non-loopback bind without a token.
	if err := safehttp.CheckBind(*listen, "", "daemon"); err != nil {
		fmt.Fprintln(os.Stderr, "daemon:", err)
		os.Exit(2)
	}
	privRaw, err := hex.DecodeString(*priv)
	check(err)

	st, err := store.NewDiskStore(*dir)
	check(err)
	e, err := session.NewFromPriv(st, privRaw)
	check(err)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Inbox: accept pushed bodies into the same durable store the scanner reads.
	inbox := store.NewServer(st, *reap)
	hsrv := &http.Server{Addr: *listen, Handler: inbox.Handler()}
	go func() {
		log.Printf("mailbox listening on %s (dir %s)", *listen, *dir)
		if err := hsrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	client := makeClient(fs)
	h, err := client.GetHeight(ctx)
	if err != nil {
		log.Printf("chain unreachable at start (will retry in background): %v", err)
		h = 0
	}
	log.Printf("pubkey %s (chain ~%d)", hex.EncodeToString(e.PublicKey()), h)

	ch, errc := client.IncomingAnchors(ctx, 0, *interval)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			pt, err := e.Receive(ev.Anchor)
			if err != nil {
				log.Printf("tx %s: cannot decrypt (skip): %v", ev.TXID, err)
				continue
			}
			fmt.Printf(">> %s\n", pt)
			if ev.Anchor.Flags&anchor.FlagAckRequested != 0 {
				fmt.Printf("   (ack requested)\n")
			}
		case err := <-errc:
			log.Printf("poll error: %v", err)
		case <-ctx.Done():
			inbox.Stop()
			hsrv.Close()
			return
		}
	}
}

// send encrypts a message, pushes the ciphertext to the recipient's mailbox
// (peer-inbox), then posts the anchor on-chain. The body never touches a
// shared store or the chain.
func send(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "", "recipient DERO address")
	peerPub := fs.String("peer-pub", "", "recipient medium-term pubkey (hex)")
	inbox := fs.String("peer-inbox", "", "recipient mailbox base URL (e.g. http://host:19191)")
	msg := fs.String("msg", "", "message text")
	ttl := fs.Duration("ttl", time.Hour, "time-to-live before the body burns")
	ringsize := fs.Uint64("ringsize", 2, "DERO ringsize")
	addRPCFlags(fs)
	_ = fs.Parse(args)

	if *to == "" || *peerPub == "" || *inbox == "" || *msg == "" {
		fmt.Fprintln(os.Stderr, "send: -to, -peer-pub, -peer-inbox, -msg required")
		fs.Usage()
		os.Exit(2)
	}
	peerRaw, err := hex.DecodeString(*peerPub)
	check(err)

	// The recipient's mailbox is a remote HTTP store from the sender's view.
	st, err := store.NewHTTPStore(*inbox)
	check(err)
	e, err := session.New(st)
	check(err)

	a, err := e.Send(peerRaw, []byte(*msg), *ttl, true)
	check(err)

	txid, err := makeClient(fs).PostAnchor(context.Background(), *to, a, *ringsize)
	check(err)
	fmt.Printf("pushed body to inbox, CID %s\n", hex.EncodeToString(a.CID[:]))
	fmt.Printf("anchor posted on-chain, txid %s\n", txid)
	fmt.Printf("burns at %s (unix %d)\n", time.Unix(int64(a.BurnDeadline), 0).UTC(), a.BurnDeadline)
}

// channelserve runs an IRC-style channel box: a rendezvous point that relays
// TTL-bounded lines and tracks presence. It never holds a channel key, so it
// stores a private room's ciphertext without being able to read it.
func channelserve(args []string) {
	fs := flag.NewFlagSet("channel", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:19192", "listen address (default loopback-only)")
	linettl := fs.Duration("linettl", 7*24*time.Hour, "line retention (rooms compost after this)")
	presencettl := fs.Duration("presencettl", time.Minute, "presence window")
	maxlines := fs.Int("maxlines", 2000, "per-channel ring cap")
	dir := fs.String("dir", "", "persist rooms to this dir (survives restart); empty = in-memory")
	_ = fs.Parse(args)

	var b *channel.Box
	if *dir != "" {
		pb, err := channel.NewPersistentBox(channel.BoxConfig{
			LineTTL: *linettl, PresenceTTL: *presencettl,
			ReapEvery: 30 * time.Second, MaxLines: *maxlines,
		}, *dir)
		if err != nil {
			log.Fatalf("channel: cannot open box dir: %v", err)
		}
		b = pb
	} else {
		b = channel.NewBox(channel.BoxConfig{
			LineTTL: *linettl, PresenceTTL: *presencettl,
			ReapEvery: 30 * time.Second, MaxLines: *maxlines,
		})
	}
	// Exposure policy (audit C3/M3): the box relays any room it is given and
	// its sender names are client-supplied — refuse a network bind without a
	// token and serve the tokened surface.
	if err := safehttp.CheckBind(*listen, "", "channel"); err != nil {
		fmt.Fprintln(os.Stderr, "channel:", err)
		os.Exit(2)
	}
	log.Printf("channel box on %s (lines rot after %s; presence %s)", *listen, *linettl, *presencettl)
	log.Fatal(http.ListenAndServe(*listen, channel.NewServer(b)))
}

// webchat runs a channel box AND serves the in-browser chat UI on the same
// origin, so friends can join with zero setup (open a URL). Same-origin means
// no CORS needed for the page itself; the API stays permissive for remote
// pages too.
func webchat(args []string) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:19192", "listen address (default loopback-only)")
	linettl := fs.Duration("linettl", 7*24*time.Hour, "line retention (rooms compost after this)")
	presencettl := fs.Duration("presencettl", 2*time.Minute, "presence window")
	maxlines := fs.Int("maxlines", 5000, "per-channel ring cap")
	cert := fs.String("cert", "", "TLS cert file (enables https)")
	key := fs.String("key", "", "TLS private key file")

	// wallet RPC the browser routes to for whispers (must hold the key).
	// Registered BEFORE Parse so the flags are known.
	wrc := fs.String("wallet-rpc", "", "wallet RPC /json_rpc endpoint for whisper send")
	wlogin := fs.String("wallet-login", "", "wallet RPC basic auth user:pass")
	// Exposure policy (audit C1): the browser whisper proxy makes the wallet
	// SPEND (real postage per send) and serves the DECRYPTED inbox. It is
	// therefore off unless explicitly enabled, and a non-loopback bind with
	// the proxy on requires a token.
	allowSpend := fs.Bool("allow-browser-spend", false, "enable the /whisper/send + /whisper/recv browser proxy (UNSAFE: wallet spend + inbox read; requires -token on non-loopback binds)")
	webToken := fs.String("token", "", "shared secret; require `Authorization: Bearer <token>` on the whisper proxy routes")
	dir := fs.String("dir", "", "persist rooms to this dir (survives restart); empty = in-memory")
	_ = fs.Parse(args)

	if err := safehttp.CheckBind(*listen, *webToken, "web"); err != nil {
		fmt.Fprintln(os.Stderr, "web:", err)
		os.Exit(2)
	}
	if *wrc != "" && !*allowSpend {
		log.Printf("web: -wallet-rpc given but the browser whisper proxy is DISABLED (it lets any visitor spend wallet postage and read the inbox). Pass -allow-browser-spend (and use a -token) to enable it deliberately.")
	}
	if *allowSpend && !safehttp.HostIsLoopback(*listen) && *webToken == "" {
		fmt.Fprintln(os.Stderr, "web: refusing to expose the wallet proxy on a non-loopback bind without -token (audit C1)")
		os.Exit(2)
	}

	var b *channel.Box
	if *dir != "" {
		pb, err := channel.NewPersistentBox(channel.BoxConfig{
			LineTTL: *linettl, PresenceTTL: *presencettl,
			ReapEvery: 30 * time.Second, MaxLines: *maxlines,
		}, *dir)
		if err != nil {
			log.Fatalf("web: cannot open box dir: %v", err)
		}
		b = pb
	} else {
		b = channel.NewBox(channel.BoxConfig{
			LineTTL: *linettl, PresenceTTL: *presencettl,
			ReapEvery: 30 * time.Second, MaxLines: *maxlines,
		})
	}
	api := channel.WithCORS(channel.BoxRoutes(b))

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/chat" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(chatHTML)
			return
		}
		// Whisper endpoints: proxy send/recv to the wallet so the browser can
		// post no-relay messages without holding keys itself.
		if *wrc != "" && *allowSpend {
			// Token gate when configured (mandatory on non-loopback binds).
			if *webToken != "" {
				auth := r.Header.Get("Authorization")
				if !strings.HasPrefix(auth, "Bearer ") ||
					subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(*webToken)) != 1 {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
			if r.URL.Path == "/whisper/send" && r.Method == "POST" {
				webWhisperSend(w, r, *wrc, *wlogin)
				return
			}
			if r.URL.Path == "/whisper/recv" && r.Method == "GET" {
				webWhisperRecv(w, r, *wrc, *wlogin)
				return
			}
		}
		api.ServeHTTP(w, r)
	}))
	srv := &http.Server{Addr: *listen, Handler: mux}
	if *cert != "" && *key != "" {
		log.Printf("compost web chat on https://%s  (public+private rooms, presence; lines rot after %s)", *listen, *linettl)
		log.Fatal(srv.ListenAndServeTLS(*cert, *key))
	}
	log.Printf("compost web chat on http://%s  (public+private rooms, presence; lines rot after %s)", *listen, *linettl)
	log.Fatal(srv.ListenAndServe())
}

// webWhisperSend posts a whisper through the daemon's wallet RPC (the browser
// can't sign txs itself). Body: {"to":addr,"msg":text}.
func webWhisperSend(w http.ResponseWriter, r *http.Request, wrc, wlogin string) {
	u, p := parseLogin(wlogin)
	client := dero.NewClient(wrc, u, p)
	var req struct {
		To  string `json:"to"`
		Msg string `json:"msg"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	txid, err := whisper.Send(r.Context(), client, req.To, req.Msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]string{"txid": txid})
}

// webWhisperRecv polls the wallet for incoming whispers and returns them.
func webWhisperRecv(w http.ResponseWriter, r *http.Request, wrc, wlogin string) {
	u, p := parseLogin(wlogin)
	client := dero.NewClient(wrc, u, p)
	minHeight, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	entries, err := client.GetTransfers(r.Context(), dero.GetTransfersParams{In: true, MinHeight: minHeight})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	type wm struct {
		Txid   string `json:"txid"`
		Sender string `json:"sender"`
		Text   string `json:"text"`
	}
	var out []wm
	for _, e := range entries {
		text, ok := whisper.ParseArgs(e.PayloadRPC)
		if !ok && len(e.Data) > 0 {
			text, ok = whisper.ParseArgsFromData(e.Data)
		}
		if ok {
			out = append(out, wm{Txid: e.TXID, Sender: e.Sender, Text: text})
		}
	}
	writeJSON(w, out)
}

// chat joins a channel box as one nick. With -say it posts one line and exits;
// otherwise it heartbeats and tails the room, decrypting private lines if -key
// is given.
func chat(args []string) {
	fs := flag.NewFlagSet("chat", flag.ExitOnError)
	box := fs.String("box", "", "channel box base URL")
	room := fs.String("channel", "", "channel name (e.g. #relay)")
	nick := fs.String("nick", "", "our nick/address shown to others")
	keyHex := fs.String("key", "", "channel key (hex) for a private room; omit for public")
	say := fs.String("say", "", "if set, post this line then exit")
	interval := fs.Duration("interval", 3*time.Second, "tail poll interval")
	online := fs.Bool("online", false, "print online members then exit")
	_ = fs.Parse(args)

	if *box == "" || *room == "" || *nick == "" {
		fmt.Fprintln(os.Stderr, "chat: -box, -channel, -nick required")
		fs.Usage()
		os.Exit(2)
	}
	c, err := channel.NewClient(*box, *nick)
	check(err)
	var key *channel.Key
	if *keyHex != "" {
		key, err = channel.KeyFromHex(*keyHex)
		check(err)
	}
	ctx := context.Background()

	if *online {
		on, err := c.Online(ctx, *room)
		check(err)
		for _, m := range on {
			fmt.Println(m)
		}
		return
	}

	if *say != "" {
		var ln channel.Line
		if key != nil {
			ln, err = c.PrivatePost(ctx, *room, key, []byte(*say))
		} else {
			ln, err = c.PublicPost(ctx, *room, []byte(*say))
		}
		check(err)
		fmt.Printf("posted seq %d (%s)\n", ln.Seq, map[bool]string{true: "private", false: "public"}[ln.Private])
		return
	}

	// Tail mode: heartbeat to stay online, poll for new lines.
	c.HeartbeatLoop(ctx, *room, *interval)
	seen := uint64(0)
	for {
		lines, err := c.Poll(ctx, *room, seen)
		if err != nil {
			log.Printf("poll: %v", err)
		} else {
			for _, ln := range lines {
				seen = ln.Seq // advance cursor; box returns seq strictly > after
				switch {
				case !ln.Private:
					fmt.Printf("[%s] %s\n", ln.Sender, ln.Data)
				case key == nil:
					// private ciphertext, no key — skip silently
				default:
					pt, oerr := channel.OpenLine(key, *room, ln.Data)
					if oerr != nil {
						continue // wrong key / tampered
					}
					fmt.Printf("[%s] %s\n", ln.Sender, pt)
				}
			}
		}
		time.Sleep(*interval)
	}
}

// whisper is the no-relay unicast messenger: a short line rides the tx payload,
// encrypted to the recipient by DERO natively. No box, no store, no relay.
//
//	whisper send  -rpc URL [-rpc-login u:p] -to ADDR -msg TEXT
//	whisper recv  -rpc URL [-rpc-login u:p] [-interval 3s]
func whispercmd(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "send":
		whisperSend(args[1:])
	case "send-long":
		whisperSendLong(args[1:])
	case "recv":
		whisperRecv(args[1:])
	case "keygen":
		whisperKeygen(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

// whisper keygen creates a persistent long-term endpoint (pub+priv) for
// nobody-but-us long bodies. Print pub to give senders; keep priv for recv.
func whisperKeygen(args []string) {
	fs := flag.NewFlagSet("whisper keygen", flag.ExitOnError)
	keyFile := fs.String("key", "", "write persistent privkey (hex) to this file")
	_ = fs.Parse(args)
	st := store.NewMemStore()
	e, err := longmsg.NewEndpoint(st)
	check(err)
	if *keyFile != "" {
		check(os.WriteFile(*keyFile, []byte(hex.EncodeToString(e.PrivKey())), 0o600))
		fmt.Printf("wrote persistent long-term privkey to %s\n", *keyFile)
	}
	fmt.Printf("give senders this compost long-term pubkey:\n%s\n", hex.EncodeToString(e.PublicKey()))
}

// whisperSendLong encrypts a long body to the recipient's compost pubkey, holds
// it locally, and posts a pointer-whisper. Body never rides a block. The sender
// must run `spore-peer serve` so the recipient can fetch the body.
func whisperSendLong(args []string) {
	fs := flag.NewFlagSet("whisper send-long", flag.ExitOnError)
	to := fs.String("to", "", "recipient DERO address or dero-name")
	recipPubHex := fs.String("recipient-pub", "", "recipient compost long-term pubkey (hex)")
	file := fs.String("file", "", "file whose contents to send")
	msg := fs.String("msg", "", "or literal message text (long)")
	outDir := fs.String("out-dir", "compost-outbox", "dir to hold the outbound body")
	daemonURL := fs.String("daemon", "http://127.0.0.1:10102/json_rpc", "daemon RPC for name resolution")
	ttl := fs.Duration("ttl", 24*time.Hour, "body retention")
	addRPCFlags(fs)
	_ = fs.Parse(args)

	if *to == "" || *recipPubHex == "" || (*file == "" && *msg == "") {
		fmt.Fprintln(os.Stderr, "whisper send-long: -to, -recipient-pub, and -file or -msg required")
		os.Exit(2)
	}
	var plaintext []byte
	var err error
	if *file != "" {
		plaintext, err = os.ReadFile(*file)
	} else {
		plaintext = []byte(*msg)
	}
	check(err)
	recipPub, err := hex.DecodeString(*recipPubHex)
	check(err)

	// Sender holds its own outbound body in a disk store.
	st, err := store.NewDiskStore(*outDir)
	check(err)
	e, err := longmsg.NewEndpoint(st)
	check(err)
	ptr, err := e.SendBody(recipPub, plaintext, *ttl)
	check(err)

	// Post a pointer-whisper to the DERO address.
	client := makeClient(fs)
	dest, err := resolveDest(context.Background(), *daemonURL, *to)
	check(err)
	txid, err := client.PostPayload(context.Background(), dest, whisper.BuildPointerArgs(ptr.EphemeralPub, ptr.CID), 2)
	check(err)
	fmt.Printf("long body held in %s (cid %s)\n", *outDir, hex.EncodeToString(ptr.CID[:]))
	fmt.Printf("pointer-whisper sent to %s (%s), txid %s\n", *to, dest[:14]+"…", txid)
	fmt.Println("recipient needs your reachable node; run:  spore-peer serve --dir " + *outDir)
}

func whisperSend(args []string) {
	fs := flag.NewFlagSet("whisper send", flag.ExitOnError)
	to := fs.String("to", "", "recipient DERO address or dero-name")
	msg := fs.String("msg", "", "message text (<=80 bytes)")
	daemonURL := fs.String("daemon", "http://127.0.0.1:10102/json_rpc", "daemon RPC for name resolution")
	addRPCFlags(fs)
	_ = fs.Parse(args)
	if *to == "" || *msg == "" {
		fmt.Fprintln(os.Stderr, "whisper send: -to and -msg required")
		os.Exit(2)
	}
	client := makeClient(fs)
	dest, err := resolveDest(context.Background(), *daemonURL, *to)
	check(err)
	txid, err := whisper.Send(context.Background(), client, dest, *msg)
	check(err)
	fmt.Printf("whisper sent to %s (%s), txid %s\n", *to, dest[:14]+"…", txid)
}

// resolveDest turns a user-supplied destination (a dero-name or a bech32
// address) into an address. Addresses pass through; names resolve via the
// daemon's NameToAddress.
func resolveDest(ctx context.Context, daemonURL, dest string) (string, error) {
	if strings.HasPrefix(dest, "dero1") {
		return dest, nil // already an address
	}
	if daemonURL == "" {
		return "", fmt.Errorf("cannot resolve name %q: no -daemon given", dest)
	}
	dc := derodaemon.NewClient(daemonURL)
	return dc.ResolveName(ctx, dest)
}

func whisperRecv(args []string) {
	fs := flag.NewFlagSet("whisper recv", flag.ExitOnError)
	interval := fs.Duration("interval", 3*time.Second, "poll interval")
	keyFile := fs.String("key", "", "persistent long-term privkey (hex) to decrypt long bodies")
	inDir := fs.String("in-dir", "compost-inbox", "dir to hold fetched bodies")
	peerAddr := fs.String("peer-addr", "", "sender's reachable spore-peer serve address host:port (for long bodies)")
	peerBin := fs.String("peer-bin", "spore-peer", "path to spore-peer binary")
	addRPCFlags(fs)
	_ = fs.Parse(args)

	client := makeClient(fs)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Build the receiving long-term endpoint (persistent key) so long bodies
	// can be decrypted.
	var recvEP *longmsg.Endpoint
	if *keyFile != "" {
		st, err := store.NewDiskStore(*inDir)
		check(err)
		keyBytes, kerr := os.ReadFile(*keyFile)
		if kerr == nil {
			priv, herr := hex.DecodeString(strings.TrimSpace(string(keyBytes)))
			check(herr)
			recvEP, err = longmsg.NewEndpointFromPriv(st, priv)
			check(err)
		} else {
			// No key file yet — create one so future long bodies decrypt.
			recvEP, err = longmsg.NewEndpoint(st)
			check(err)
			check(os.WriteFile(*keyFile, []byte(hex.EncodeToString(recvEP.PrivKey())), 0o600))
			log.Printf("created persistent long-term key at %s; share its pubkey with senders", *keyFile)
		}
	}

	log.Printf("whisper recv: listening for no-relay messages (own node only)")
	ch, errc := whisper.Recv(ctx, client, 0, *interval)
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				return
			}
			if !m.HasPointer {
				fmt.Printf("whisper %s: %s\n", shortTx(m.TXID), m.Text)
				continue
			}
			fmt.Printf("whisper %s: long-message pointer (cid %s)\n", shortTx(m.TXID), hex.EncodeToString(m.BodyCID[:]))
			if *keyFile == "" {
				fmt.Println("  (run with -key and -peer-addr to fetch + decrypt this body)")
				continue
			}
			if *peerAddr == "" {
				fmt.Println("  (no -peer-addr given; sender must run spore-peer serve and share its address)")
				continue
			}
			body, err := peer.Fetch(ctx, *peerBin, *peerAddr, m.BodyCID)
			if err != nil {
				fmt.Printf("  fetch failed (is the sender reachable?): %v\n", err)
				continue
			}
			ptr := &longmsg.Pointer{EphemeralPub: m.EphPub, CID: m.BodyCID}
			pt, err := recvEP.ReceiveBody(ptr, func([32]byte) ([]byte, error) { return body, nil })
			if err != nil {
				fmt.Printf("  decrypt failed: %v\n", err)
				continue
			}
			fmt.Printf("  >>> long message (%d bytes): %s\n", len(pt), string(pt))
		case err := <-errc:
			log.Printf("recv error: %v", err)
		case <-ctx.Done():
			return
		}
	}
}

func shortTx(txid string) string {
	if len(txid) > 16 {
		return txid[:16] + "…"
	}
	return txid
}

// demo exercises the full send→receive→burn lifecycle in-process against the
// in-memory store, without touching a DERO node.
func demo() {
	st := store.NewMemStore()

	alice, err := session.New(st)
	check(err)
	bob, err := session.New(st)
	check(err)

	const ttl = 2 * time.Second
	msg := []byte("meet at the usual place, bring the thing")

	fmt.Println("== send (alice → bob) ==")
	a, err := alice.Send(bob.PublicKey(), msg, ttl, true)
	check(err)
	args := a.ToArguments()
	fmt.Printf("anchor as %d typed arguments (DERO field limit 111 bytes CBOR)\n", len(args))
	fmt.Printf("  kind=%d cid=%s deadline=%d ack=%v\n", a.Kind, hex.EncodeToString(a.CID[:8]), a.BurnDeadline, a.Flags&anchor.FlagAckRequested != 0)
	fmt.Printf("  store bodies=%d\n", st.Len())

	fmt.Println("== receive (bob) ==")
	got, err := anchor.FromArguments(args)
	check(err)
	pt, err := bob.Receive(got)
	check(err)
	fmt.Printf("bob received: %q\n", pt)

	fmt.Println("== wait out TTL + reap ==")
	time.Sleep(ttl + 100*time.Millisecond)
	n := st.Reap(time.Now())
	fmt.Printf("reaped %d body(ies); store now %d\n", n, st.Len())

	fmt.Println("== post-burn read attempt ==")
	_, err = bob.Receive(got)
	if err != nil {
		fmt.Printf("rejected as expected: %v\n", err)
	} else {
		fmt.Println("FAIL: message still readable after burn")
		os.Exit(1)
	}

	fmt.Println("OK: body evicted, key erased, anchor inert.")
}

// defaultDonateRegistry builds the operator's per-chain donation addresses.
// Replace with real addresses before publishing; these are the user's known
// rails.
func defaultDonateRegistry() *donate.Registry {
	r := donate.New()
	r.Register(donate.Entry{
		Chain:   "dero",
		Address: "dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq", // spore dev (DERO)
		Note:    "DERO mainnet",
	})
	r.Register(donate.Entry{
		Chain:   "xmr",
		Address: "", // TODO: fill once the Hetzner XMR node / wallet is up
		Note:    "Monero — fill after live monero-wallet-rpc",
	})
	r.Register(donate.Entry{
		Chain:   "evm",
		Address: "", // TODO: fill with the operator's EVM/EOA address
		Note:    "EVM-compatible chains",
	})
	return r
}

func donatecmd(args []string) {
	reg := defaultDonateRegistry()
	if len(args) == 0 || args[0] == "--all" || args[0] == "-a" {
		fmt.Print(reg.Render())
		return
	}
	chainArg := args[0]
	if chainArg == "-h" || chainArg == "--help" {
		fmt.Println("usage: spore donate [chain]")
		fmt.Println("       spore donate --all")
		return
	}
	e, ok := reg.Get(chainArg)
	if !ok {
		fmt.Printf("no donation address registered for %q. registered: %v\n", chainArg, reg.Chains())
		os.Exit(1)
	}
	fmt.Println(e.Address)
}

// msg sends/receives a spore message on ANY registered chain backend,
// dispatching on -chain. Uses the chain-agnostic canonical codec so the same
// wire semantics hold across DERO, EVM, and XMR.
func msgcmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spore msg send|recv|send-e2|recv-e2|send-long|keygen [flags]")
		fmt.Fprintln(os.Stderr, "       (chain-agnostic; see -chain)")
		os.Exit(2)
	}
	switch args[0] {
	case "send":
		msgSend(args[1:])
	case "send-e2":
		msgSendE2(args[1:])
	case "recv-e2":
		msgRecvE2(args[1:])
	case "recv":
		msgRecv(args[1:])
	case "send-long":
		msgSendLong(args[1:])
	case "keygen":
		msgKeygen(args[1:])
	case "-h", "--help":
		fmt.Fprintln(os.Stderr, "usage: spore msg send|recv|send-e2|recv-e2|send-long|keygen [flags]")
	default:
		fmt.Fprintf(os.Stderr, "msg: unknown subcommand %q (want send|recv|send-long|keygen)\n", args[0])
		os.Exit(2)
	}
}

func msgBackend(fs *flag.FlagSet) chain.Chain {
	chainType := fs.Lookup("chain").Value.String()
	cfg := backend.ChainConfig{
		Type:      chainType,
		RPC:       fs.Lookup("rpc").Value.String(),
		Login:     fs.Lookup("rpc-login").Value.String(),
		From:      fs.Lookup("from").Value.String(),
		KeyFile:   fs.Lookup("keyfile").Value.String(),
		ProgramID: fs.Lookup("program").Value.String(),
	}
	if f := fs.Lookup("xmr-unverified"); f != nil && f.Value.String() == "true" {
		cfg.AllowUnverified = true
	}
	if f := fs.Lookup("mailbox"); f != nil {
		cfg.Mailbox = f.Value.String()
	}
	c, err := backend.Build(context.Background(), cfg)
	check(err)
	return c
}

func msgSend(args []string) {
	fs := flag.NewFlagSet("msg send", flag.ExitOnError)
	to := fs.String("to", "", "recipient address on that chain")
	msg := fs.String("msg", "", "message text")
	fs.String("chain", "dero", "chain backend: dero|evm|xmr|solana")
	fs.Bool("xmr-unverified", false, "allow the NOT live-verified XMR backend (experimental)")
	fs.String("rpc", "", "wallet/daemon JSON-RPC endpoint")
	fs.String("rpc-login", "", "RPC basic auth user:pass (dero)")
	fs.String("from", "", "our address (evm)")
	fs.String("key", "", "our spore priv key (64 hex) for E2E encryption")
	fs.String("peer-pub", "", "recipient spore pub key (64 hex) for E2E encryption")
	fs.String("keyfile", "", "solana signer keypair JSON path")
	fs.String("program", "", "solana mailbox program id (default mainnet)")
	fs.String("mailbox", "", "evm: MyceliumMailbox contract address (log-based delivery)")
	_ = fs.Parse(args)
	if *to == "" || *msg == "" {
		fmt.Fprintln(os.Stderr, "msg send: -to and -msg required")
		os.Exit(2)
	}
	c := msgBackend(fs)
	codec := secureSendCodec(fs, c.Name())
	txid, err := whisper.SendChain(context.Background(), c, codec, *to, *msg)
	if err != nil {
		log.Fatalf("msg send on %s: %v", c.Name(), err)
	}
	fmt.Printf("sent on %s to %s, txid %s\n", c.Name(), *to, txid)
}

func msgRecv(args []string) {
	fs := flag.NewFlagSet("msg recv", flag.ExitOnError)
	interval := fs.Duration("interval", 3*time.Second, "poll interval")
	minHeight := fs.Uint64("min-height", 0, "scan from height")
	fs.String("chain", "dero", "chain backend: dero|evm|xmr|solana")
	fs.Bool("xmr-unverified", false, "allow the NOT live-verified XMR backend (experimental)")
	fs.String("rpc", "", "wallet/daemon JSON-RPC endpoint")
	fs.String("rpc-login", "", "RPC basic auth user:pass (dero)")
	fs.String("from", "", "our address (evm)")
	fs.String("key", "", "our spore priv key (64 hex) to decrypt E2E messages")
	fs.String("keyfile", "", "solana signer keypair JSON path")
	fs.String("program", "", "solana mailbox program id (default mainnet)")
	fs.String("mailbox", "", "evm: MyceliumMailbox contract address (log-based delivery)")
	autoBurn := fs.Bool("auto-burn", true, "erase each message from on-chain mailbox state right after receiving it (evm/solana only; nothing persists but a spent tx)")
	_ = fs.Parse(args)
	c := msgBackend(fs)
	codec := secureRecvCodec(fs, c.Name())
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Printf("msg recv on %s: listening for spore messages", c.Name())
	ch, errc := whisper.RecvChain(ctx, c, codec, chain.WatchOpts{MinHeight: *minHeight, Interval: *interval, AutoBurn: *autoBurn})
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				return
			}
			if !m.HasPointer {
				fmt.Printf("msg %s: %s\n", shortTx(m.TXID), m.Text)
			} else {
				fmt.Printf("msg %s: long-pointer (cid %x)\n", shortTx(m.TXID), m.BodyCID)
			}
		case err := <-errc:
			log.Printf("recv error: %v", err)
		case <-ctx.Done():
			return
		}
	}
}

// msgKeygen generates a spore identity keypair for end-to-end encryption.
// Give the PUB half to people who send you messages; keep the PRIV to decrypt.
func msgKeygen(args []string) {
	fs := flag.NewFlagSet("msg keygen", flag.ExitOnError)
	outFile := fs.String("out", "", "write priv key to file (0600) instead of stdout")
	_ = fs.Parse(args)
	kp, err := crypto.GenerateKey()
	check(err)
	defer crypto.Zero(kp.Priv)
	sigPub, err := secure.SigPubOf(kp.Priv)
	check(err)
	pubHex := hex.EncodeToString(kp.Pub)
	sigHex := hex.EncodeToString(sigPub)
	privHex := hex.EncodeToString(kp.Priv)
	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(privHex), 0o600); err != nil {
			check(err)
		}
		fmt.Printf("wrote priv key to %s\n", *outFile)
	} else {
		fmt.Printf("pub:  %s\n", pubHex)
		fmt.Printf("sig:  %s\n", sigHex)
		fmt.Printf("priv: %s\n", privHex)
	}
	fmt.Println("give 'pub' AND 'sig' to people messaging you; they encrypt to it, you verify sender signatures against 'sig'. Keep 'priv' secret.")
}

// secureFlags returns the send-side secure codec when -key and -peer-pub are
// given, else nil (plaintext codec).
func secureSendCodec(fs *flag.FlagSet, chainType string) whisper.Codec {
	base := whisper.Codec(whisper.CanonicalCodec{})
	// DERO already encrypts natively; use the DERO codec there unless the user
	// explicitly supplies keys for E2E.
	if chainType == "dero" {
		base = whisper.DeroCodec{}
	}
	keyHex := fs.Lookup("key").Value.String()
	peerHex := fs.Lookup("peer-pub").Value.String()
	if keyHex == "" || peerHex == "" {
		return base
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		check(fmt.Errorf("msg: -key must be 64 hex chars (32 bytes)"))
	}
	peer, err := hex.DecodeString(peerHex)
	if err != nil || len(peer) != 32 {
		check(fmt.Errorf("msg: -peer-pub must be 64 hex chars (32 bytes)"))
	}
	sc, err := secure.NewSendCodec(base, key, peer)
	check(err)
	return sc
}

func secureRecvCodec(fs *flag.FlagSet, chainType string) whisper.Codec {
	base := whisper.Codec(whisper.CanonicalCodec{})
	if chainType == "dero" {
		base = whisper.DeroCodec{}
	}
	keyHex := fs.Lookup("key").Value.String()
	if keyHex == "" {
		return base
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		check(fmt.Errorf("msg: -key must be 64 hex chars (32 bytes)"))
	}
	// Public chains (evm/xmr/solana): STRICT — only signed envelopes decode.
	// DERO: legacy mode — its native point-to-point payload encryption is the
	// trusted secrecy layer, so non-envelope whispers still decode.
	if chainType == "dero" {
		sc, err := secure.NewRecvCodecLegacy(base, key)
		check(err)
		return sc
	}
	sc, err := secure.NewRecvCodec(base, key)
	check(err)
	return sc
}

// msgSendLong sends a LONG body whose pointer rides the DERO whisper path — the
// B1 XMR off-chain delivery use case. Monero can't carry message pointers
// on-chain, so XMR contributes identity only; DERO delivers the pointer; the
// body itself never rides any block and is fetched peer-to-peer by CID.
//
//   - The body is E2E-encrypted (X25519) to the recipient's spore pub and held
//     in the sender's out-dir disk store — nobody but sender and receiver.
//   - The pointer (sender ephemeral pub + body CID) is posted as a DERO whisper
//     to the recipient's DERO delivery address (-to): the only live long-body
//     delivery channel.
//   - An optional -xmr address tags the message by writing a plaintext header
//     line ("xmr:<addr>\n") onto the body BEFORE SendBody encrypts it, so the
//     decrypted body tells the recipient which XMR address/context it belongs
//     to. This header is metadata only: it changes neither the canonical
//     pointer format nor the whisper codec.
//
// Only the DERO chain is wired for the pointer whisper today; any other -chain
// is rejected.
func msgSendLong(args []string) {
	fs := flag.NewFlagSet("msg send-long", flag.ExitOnError)
	fs.String("chain", "dero", "delivery chain for the pointer whisper (only dero is wired for long bodies)")
	to := fs.String("to", "", "recipient DERO delivery address (receives the pointer whisper)")
	recipPubHex := fs.String("recipient-pub", "", "recipient spore X25519 pubkey (64 hex) to encrypt the body to")
	file := fs.String("file", "", "file whose contents to send")
	msg := fs.String("msg", "", "or literal message text (long)")
	outDir := fs.String("out-dir", "spore-outbox", "dir to hold the outbound body")
	daemonURL := fs.String("daemon", "http://127.0.0.1:10102/json_rpc", "daemon RPC for name resolution")
	ttl := fs.Duration("ttl", 24*time.Hour, "body retention")
	xmrAddr := fs.String("xmr", "", "recipient XMR address to tag the body with (identity metadata; prepended as a header line)")
	addRPCFlags(fs)
	_ = fs.Parse(args)

	if !strings.EqualFold(fs.Lookup("chain").Value.String(), "dero") {
		fmt.Fprintf(os.Stderr, "msg send-long: -chain %s unsupported for long bodies — only 'dero' is wired (the DERO pointer whisper is the long-body carrier)\n", fs.Lookup("chain").Value.String())
		os.Exit(2)
	}
	if *to == "" || *recipPubHex == "" || (*file == "" && *msg == "") {
		fmt.Fprintln(os.Stderr, "msg send-long: -to, -recipient-pub, and -file or -msg required")
		os.Exit(2)
	}
	var plaintext []byte
	var err error
	if *file != "" {
		plaintext, err = os.ReadFile(*file)
	} else {
		plaintext = []byte(*msg)
	}
	check(err)
	recipPub, err := hex.DecodeString(*recipPubHex)
	check(err)
	if len(recipPub) != 32 {
		fmt.Fprintln(os.Stderr, "msg send-long: -recipient-pub must be 64 hex chars (32 bytes)")
		os.Exit(2)
	}
	// B1: tag the body with the recipient's XMR identity as a plaintext header
	// line (metadata). It is encrypted with the rest of the body, so only the
	// recipient ever sees it, and it needs no change to the pointer/codec.
	if *xmrAddr != "" {
		plaintext = xmrTagBody(*xmrAddr, plaintext)
	}

	// Sender holds its own outbound body in a disk store; the body never rides
	// a block or a shared/third-party store.
	st, err := store.NewDiskStore(*outDir)
	check(err)
	e, err := longmsg.NewEndpoint(st)
	check(err)
	ptr, err := e.SendBody(recipPub, plaintext, *ttl)
	check(err)

	// Post the pointer as a DERO whisper to the delivery address.
	client := makeClient(fs)
	dest, err := resolveDest(context.Background(), *daemonURL, *to)
	check(err)
	txid, err := client.PostPayload(context.Background(), dest, whisper.BuildPointerArgs(ptr.EphemeralPub, ptr.CID), 2)
	check(err)
	fmt.Printf("long body held in %s (cid %s)\n", *outDir, hex.EncodeToString(ptr.CID[:]))
	if *xmrAddr != "" {
		fmt.Printf("  tagged for XMR recipient %s\n", *xmrAddr)
	}
	fmt.Printf("pointer-whisper sent to %s (%s), txid %s\n", *to, dest[:14]+"…", txid)
	fmt.Println("recipient needs your reachable node + their whisper recv to fetch+decrypt; run:  spore msg recv -chain dero")
}

// xmrTagBody prefixes an "xmr:<address>\n" header line onto a body so the
// decrypted message tells the recipient which XMR address/context it belongs
// to (B1 identity). It returns the body unchanged when addr is empty. This is
// a metadata header only — it rides inside the encrypted body and never changes
// the canonical pointer format or the whisper codec.
func xmrTagBody(xmrAddr string, plaintext []byte) []byte {
	if xmrAddr == "" {
		return plaintext
	}
	return append([]byte("xmr:"+xmrAddr+"\n"), plaintext...)
}
