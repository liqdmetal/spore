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
	"syscall"
	"time"

	"github.com/liqdmetal/compost/internal/anchor"
	"github.com/liqdmetal/compost/internal/channel"
	"github.com/liqdmetal/compost/internal/dero"
	"github.com/liqdmetal/compost/internal/session"
	"github.com/liqdmetal/compost/internal/store"
	"github.com/liqdmetal/compost/internal/whisper"
)

//go:embed web/chat.html
var chatHTML []byte

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
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
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  compost demo
  compost keygen
  compost daemon -listen :PORT -dir DIR -priv HEX -rpc URL [-rpc-login u:p]
  compost send -to ADDR -peer-pub HEX -peer-inbox URL -msg TEXT [-rpc URL] [-rpc-login u:p] [-ttl 1h]
  compost channel -listen :PORT [-linettl 15m] [-presencettl 1m]   (run an IRC box)
  compost chat -box URL -channel NAME -nick X [-key HEX] [-interval 3s]
             [-say "text"] [-online]
  compost whisper send -rpc URL [-rpc-login u:p] -to ADDR -msg TEXT   (no-relay)
  compost whisper recv -rpc URL [-rpc-login u:p] [-interval 3s]`)
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
	fmt.Printf("pub:  %s\n", hex.EncodeToString(e.PublicKey()))
	fmt.Printf("priv: %s\n", hex.EncodeToString(e.PrivKey()))
	fmt.Println("give 'pub' to senders; run your daemon with 'priv'.")
}

// daemon runs a recipient's mailbox: an HTTP inbox that accepts pushed bodies
// (stored durably on disk), plus a scanner that polls the chain for anchors
// and decrypts the matching body. One process; nothing is ever handed to a
// third party. Bodies are reaped once their TTL passes.
func daemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	listen := fs.String("listen", ":19191", "mailbox listen address (sender inbox)")
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
	listen := fs.String("listen", ":19192", "listen address")
	linettl := fs.Duration("linettl", 15*time.Minute, "line retention")
	presencettl := fs.Duration("presencettl", time.Minute, "presence window")
	maxlines := fs.Int("maxlines", 2000, "per-channel ring cap")
	_ = fs.Parse(args)

	b := channel.NewBox(channel.BoxConfig{
		LineTTL: *linettl, PresenceTTL: *presencettl,
		ReapEvery: 30 * time.Second, MaxLines: *maxlines,
	})
	log.Printf("channel box on %s (lines rot after %s; presence %s)", *listen, *linettl, *presencettl)
	log.Fatal(http.ListenAndServe(*listen, channel.NewServer(b)))
}

// webchat runs a channel box AND serves the in-browser chat UI on the same
// origin, so friends can join with zero setup (open a URL). Same-origin means
// no CORS needed for the page itself; the API stays permissive for remote
// pages too.
func webchat(args []string) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	listen := fs.String("listen", ":19192", "listen address")
	linettl := fs.Duration("linettl", 2*time.Hour, "line retention")
	presencettl := fs.Duration("presencettl", 2*time.Minute, "presence window")
	maxlines := fs.Int("maxlines", 5000, "per-channel ring cap")
	cert := fs.String("cert", "", "TLS cert file (enables https)")
	key := fs.String("key", "", "TLS private key file")
	_ = fs.Parse(args)

	b := channel.NewBox(channel.BoxConfig{
		LineTTL: *linettl, PresenceTTL: *presencettl,
		ReapEvery: 30 * time.Second, MaxLines: *maxlines,
	})
	api := channel.WithCORS(channel.BoxRoutes(b))

	// wallet RPC the browser routes to for whispers (must hold the key).
	wrc := fs.String("wallet-rpc", "", "wallet RPC /json_rpc endpoint for whisper send")
	wlogin := fs.String("wallet-login", "", "wallet RPC basic auth user:pass")

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/chat" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(chatHTML)
			return
		}
		// Whisper endpoints: proxy send/recv to the wallet so the browser can
		// post no-relay messages without holding keys itself.
		if *wrc != "" {
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
		if text, ok := whisper.ParseArgs(e.PayloadRPC); ok {
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
	case "recv":
		whisperRecv(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func whisperSend(args []string) {
	fs := flag.NewFlagSet("whisper send", flag.ExitOnError)
	to := fs.String("to", "", "recipient DERO address")
	msg := fs.String("msg", "", "message text (<=80 bytes)")
	addRPCFlags(fs)
	_ = fs.Parse(args)
	if *to == "" || *msg == "" {
		fmt.Fprintln(os.Stderr, "whisper send: -to and -msg required")
		os.Exit(2)
	}
	client := makeClient(fs)
	txid, err := whisper.Send(context.Background(), client, *to, *msg)
	check(err)
	fmt.Printf("whisper sent, txid %s (confirms in ~1 block; recipient's own node delivers it)\n", txid)
}

func whisperRecv(args []string) {
	fs := flag.NewFlagSet("whisper recv", flag.ExitOnError)
	interval := fs.Duration("interval", 3*time.Second, "poll interval")
	addRPCFlags(fs)
	_ = fs.Parse(args)

	client := makeClient(fs)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Printf("whisper recv: listening for no-relay messages (own node only)")
	ch, errc := whisper.Recv(ctx, client, 0, *interval)
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				return
			}
			fmt.Printf("whisper %s: %s\n", shortTx(m.TXID), m.Text)
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
