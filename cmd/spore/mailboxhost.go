package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/mailbox"
	"github.com/liqdmetal/spore/internal/notify"
	"github.com/liqdmetal/spore/internal/safehttp"
)

// mailboxHost — the hosted multi-user service (Model B), and the command that
// makes the shared chain scanner real.
//
//	spore mailbox host -users DIR [-listen :19292] [-tokens FILE] [-chain dero -rpc URL] ...
//
// Why this exists: `mailbox run` is one process per user, and each one polls the
// chain independently. At 10k users that is 10k pollers — at a 3s interval,
// ~3,333 RPC calls/second against a single chain node, which is the first thing
// that dies (measured: one mailbox process is only ~5.2 MB RSS / 4 threads, so
// RAM was never the binding constraint; chain polling was).
//
// This command runs N mailboxes in ONE process behind ONE chain watcher
// (mailbox.ScanHub), so chain RPC load is independent of user count. Measured
// with the hub's own scaling test: 1 subscriber = 8 polls in 200ms,
// 50 subscribers = 9 polls. Flat.
//
// Layout:
//
//	-users DIR/
//	          alice/   <- a mailbox dir (its own key, bodies, log)
//	          bob/
//	          ...
//
// Every user is served from ONE HTTP listener, path-routed:
//
//	GET|PUT  /u/alice/put/<cid>     alice's mailbox routes
//	GET      /u/alice/list
//	GET      /u/alice/prekey        alice's single-use bundle pop
//
// One listener means one TLS cert and one firewall rule for any number of
// users, which is what makes this operable.
//
// Trust model is unchanged from a personal mailbox: the host is a BLIND
// courier. Each mailbox holds its own key, bodies are E2E ciphertext, and
// -privacy blanks senders in the log. The host operator sees traffic and
// timing, never plaintext. See docs/MODEL_B_SERVICE.md.
func mailboxHost(args []string) {
	fs := flag.NewFlagSet("mailbox host", flag.ExitOnError)
	usersDir := fs.String("users", "", "directory whose SUBDIRECTORIES are each one mailbox dir (required)")
	listen := fs.String("listen", "127.0.0.1:19292", "single multiplexed HTTP listen address for all users")
	tokensFile := fs.String("tokens", "", "optional JSON file {\"alice\":\"secret\",...} mapping user -> bearer token; users absent from it get an OPEN mailbox route (refused on non-loopback binds)")
	cert := fs.String("cert", "", "TLS cert PEM (serve HTTPS when set with -key)")
	key := fs.String("key", "", "TLS key PEM (serve HTTPS when set with -cert)")
	privacy := fs.Bool("privacy", true, "don't record senders in any user's message log (hosted-service default: the operator should not learn who talks to whom)")
	logTTL := fs.Duration("log-ttl", mailbox.DefaultLogTTL, "decrypted-message log retention per user")
	reap := fs.Duration("reap", 30*time.Second, "expired-body reaper interval (all users)")
	interval := fs.Duration("interval", 3*time.Second, "SHARED chain poll interval (one watcher for all users)")
	rate := fs.Uint("rate", 120, "per-IP request throttle per minute on the host mux (0 = unlimited)")
	notifyFile := fs.String("notify-file", "", "optional JSON map of user -> {email,sms,webhook}; provider secrets/settings come from environment")
	minHeight := fs.Uint64("min-height", 0, "scan the chain from this height")
	autoBurn := fs.Bool("auto-burn", false, "erase each user's on-chain mailbox slot after that user accepts a delivery (per-user, never hub-level)")
	addChainFlags(fs)
	_ = fs.Parse(args)

	if *usersDir == "" {
		fmt.Fprintln(os.Stderr, "mailbox host: -users DIR is required (each subdirectory is one mailbox)")
		fs.Usage()
		os.Exit(2)
	}
	if (*cert == "") != (*key == "") {
		log.Fatalf("mailbox host: -cert and -key must both be set to serve TLS (got cert=%q key=%q)", *cert, *key)
	}
	// Per-user auth is enforced below (each user must have a token unless the
	// bind is loopback). There is no single host-wide token to pre-check here.
	if *cert == "" && !safehttp.HostIsLoopback(*listen) {
		log.Printf("mailbox host: WARNING — serving on a non-loopback bind without TLS; set -cert/-key so user bodies and tokens are not sent in the clear")
	}

	tokens, err := loadHostTokens(*tokensFile)
	check(err)

	// Open every user's mailbox up front: a bad user dir must fail loudly at
	// startup rather than silently dropping that user from the fan-out.
	entries, err := os.ReadDir(*usersDir)
	check(err)
	names := []string{}
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			// A directory whose name is not a valid route segment can never be
			// reached over HTTP, so fail loudly at startup instead of hosting
			// an unreachable mailbox.
			if !validUserName(e.Name()) {
				log.Fatalf("mailbox host: user directory %q is not a valid name (no '/', '\\', '%%', '.' or '..') — rename it", e.Name())
			}
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		log.Fatalf("mailbox host: no user subdirectories found in %s", *usersDir)
	}

	type userBox struct {
		name string
		mb   *mailbox.Mailbox
		tok  string
	}
	notifyRoot := *notifyFile
	if notifyRoot == "" {
		notifyRoot = filepath.Join(*usersDir, "notify.json")
	}
	notifiers, err := buildMailboxNotifiers(notifyRoot, names, notify.Options{
		SMTPHost:     os.Getenv("SPORE_NOTIFY_SMTP_HOST"),
		SMTPPort:     parseEnvPort("SPORE_NOTIFY_SMTP_PORT", 587),
		SMTPFrom:     os.Getenv("SPORE_NOTIFY_SMTP_FROM"),
		SMTPUsername: os.Getenv("SPORE_NOTIFY_SMTP_USER"),
		TwilioSID:    os.Getenv("SPORE_NOTIFY_TWILIO_SID"),
		TwilioFrom:   os.Getenv("SPORE_NOTIFY_TWILIO_FROM"),
		WebhookToken: os.Getenv("SPORE_NOTIFY_WEBHOOK_TOKEN"),
	})
	check(err)
	boxes := make([]userBox, 0, len(names))
	// Prebuild each user's HTTP handler ONCE. Constructing it per request
	// would allocate on every hit for every one of N users.
	routes := map[string]http.Handler{}
	for _, n := range names {
		dir := filepath.Join(*usersDir, n)
		mb, err := mailbox.Open(dir, nil)
		if err != nil {
			log.Fatalf("mailbox host: open user %q: %v", n, err)
		}
		mb.SetLogTTL(*logTTL)
		if *privacy {
			mb.SetNoSenderLog(true)
		}
		tok := tokens[n]
		if tok == "" && !safehttp.HostIsLoopback(*listen) {
			log.Fatalf("mailbox host: user %q has no token in -tokens and -listen %s is not loopback; refusing to expose an unauthenticated mailbox to the network", n, *listen)
		}
		boxes = append(boxes, userBox{name: n, mb: mb, tok: tok})
		var handler http.Handler
		if tok != "" {
			handler = mb.HandlerToken(tok)
		} else {
			handler = mb.Handler()
		}
		if notifier := notifiers[n]; notifier != nil {
			handler = notifyBodyPut(handler, notifier)
		}
		routes[n] = handler
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// ONE chain backend, ONE watcher, shared by every mailbox.
	c := msgBackend(fs)
	hub := mailbox.NewScanHub(ctx, c, chain.WatchOpts{
		MinHeight: *minHeight,
		Interval:  *interval,
		AutoBurn:  false, // forced off by the hub anyway; burn is per-subscriber
	})
	defer hub.Close()

	defer func() {
		for _, q := range notifiers {
			_ = q.Close()
		}
	}()
	for _, b := range boxes {
		b := b
		codec := mailboxCodec(fs, b.mb)
		fetch := b.mb.LocalFetch
		errc := make(chan error, 64)
		hub.Subscribe(ctx, b.mb, codec, fetch, func(msg mailbox.Message) {
			log.Printf("mailbox host: [%s] new %s message (%d bytes)", b.name, msg.Kind, msg.Size)
		}, errc, *autoBurn, 256)
		go func() {
			for {
				select {
				case e, ok := <-errc:
					if !ok {
						return
					}
					log.Printf("mailbox host: [%s] %v", b.name, e)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Per-IP fixed-window throttle for the host mux (-rate).
	hostLimiter := newHostLimiter(*rate)

	// Single multiplexed HTTP listener, path-routed per user. Wrapped with
	// per-IP request throttling (host-level, -rate) and an HSTS header, so a
	// token holder (or a public profile scraper) cannot hammer the box.
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if *rate > 0 {
			ip := clientIP(r)
			if !hostLimiter.allow(ip, time.Now().Unix()/60) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		if r.URL.Path == "/" {
			writeHostIndex(w)
			return
		}
		name, rest, ok := splitUserRoute(r.URL.Path)
		if !ok {
			// Malformed or traversal-shaped: 404, NOT the index. Answering 200
			// for "/u/alice/../../etc/passwd" would tell a prober that its
			// crafted path was handled rather than rejected.
			http.NotFound(w, r)
			return
		}
		// Host-level user routes: the pay-me QR (public GET, token-gated PUT)
		// and the public profile page. Served from the user's own dir; every
		// other route delegates to the (token-gated) mailbox handler.
		if rest == "/qr" || rest == "/" || rest == "/profile.json" {
			var box *userBox
			for i := range boxes {
				if boxes[i].name == name {
					box = &boxes[i]
					break
				}
			}
			if box == nil {
				http.NotFound(w, r)
				return
			}
			if rest == "/qr" {
				handleUserQR(w, r, filepath.Join(*usersDir, name), box.tok)
				return
			}
			if rest == "/profile.json" {
				handleUserProfileJSON(w, r, filepath.Join(*usersDir, name), box.tok)
				return
			}
			handleUserProfile(w, r, filepath.Join(*usersDir, name))
			return
		}
		h, known := routes[name]
		if !known {
			http.NotFound(w, r)
			return
		}
		// Rewrite the path so the mailbox sees its own root-relative routes.
		r2 := r.Clone(r.Context())
		r2.URL.Path = rest
		h.ServeHTTP(w, r2)
	})

	hsrv := &http.Server{Addr: *listen, Handler: mux}
	scheme := "http"
	if *cert != "" {
		scheme = "https"
	}

	// Shared reaper: one ticker for all users, not one goroutine each.
	go func() {
		t := time.NewTicker(*reap)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				for _, b := range boxes {
					if n := b.mb.Reap(time.Now()); n > 0 {
						log.Printf("mailbox host: [%s] reaped %d burned body(ies)", b.name, n)
					}
					if _, err := b.mb.TrimLog(time.Now()); err != nil {
						log.Printf("mailbox host: [%s] log trim: %v", b.name, err)
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		log.Printf("mailbox host: serving %d user(s) on %s://%s/u/<name>/...", len(boxes), scheme, *listen)
		var err error
		if *cert != "" {
			err = hsrv.ListenAndServeTLS(*cert, *key)
		} else {
			err = hsrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	log.Printf("mailbox host: ONE shared %s chain watcher for %d mailboxes (poll every %s) — chain RPC load does not grow with user count", c.Name(), len(boxes), *interval)
	log.Printf("mailbox host: privacy mode=%v (sender not logged), log retention %s, auto-burn=%v", *privacy, *logTTL, *autoBurn)
	for _, b := range boxes {
		auth := "open"
		if b.tok != "" {
			auth = "bearer"
		}
		log.Printf("  %-24s %s://%s/u/%s/  auth=%s", b.name, scheme, *listen, b.name, auth)
	}

	<-ctx.Done()
	log.Printf("mailbox host: shutting down")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = hsrv.Shutdown(shutCtx)
	hub.Close()
	st := hub.Stats()
	log.Printf("mailbox host: stopped (delivered=%d dropped=%d)", st.Delivered, st.Dropped)
}

// splitUserRoute turns "/u/alice/put/abc" into ("alice", "/put/abc", true).
//
// The host handler is a raw http.HandlerFunc, NOT an http.ServeMux, so the
// request path arrives UNCLEANED — "/u/../bob/list" really does reach here with
// name "..". The map lookup would 404 that anyway (no user is named ".."), but
// relying on a map miss for path traversal is the wrong shape of defense, so
// traversal-looking names are rejected explicitly.
//
// A valid user name is one path segment with no dots, no separators, and no
// percent-encoding: it must be usable as a directory name under -users.
func splitUserRoute(path string) (name, rest string, ok bool) {
	const prefix = "/u/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	tail := path[len(prefix):]
	if i := strings.IndexByte(tail, '/'); i >= 0 {
		name, rest = tail[:i], tail[i:]
	} else {
		name, rest = tail, "/"
	}
	if !validUserName(name) {
		return "", "", false
	}
	// The rewritten `rest` is handed VERBATIM to the user's mailbox handler,
	// which is a raw handler doing prefix matching — it does not clean paths
	// either. Reject any upward segment here rather than depending on every
	// downstream route to be traversal-proof forever.
	if hasUpwardSegment(rest) {
		return "", "", false
	}
	return name, rest, true
}

// hasUpwardSegment reports whether a request path contains a "." or ".."
// segment, which no legitimate mailbox route ever does.
func hasUpwardSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// validUserName reports whether name is safe to use as a user route segment and
// as a subdirectory of -users. Rejects empty, ".", "..", anything containing a
// slash or backslash, and percent-encoding (which could hide either).
func validUserName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, "/\\%") {
		return false
	}
	return true
}

// writeHostIndex answers "/" with a one-line liveness note. It deliberately
// does NOT list user names: on a public bind the set of hosted usernames is
// itself metadata an attacker could enumerate, so the index reveals nothing
// beyond "this is a spore mailbox host."
func writeHostIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "spore mailbox host: use /u/<name>/<route>")
}

// clientIP resolves the real client address for the throttle. The listener
// sits behind the TLS edge (Caddy) on loopback, so RemoteAddr is always
// 127.0.0.1 and every visitor would share one bucket; the edge sets
// X-Forwarded-For, which is trustworthy here because nothing but the edge can
// reach the loopback port.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			xff = xff[:i]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// hostLimiter is a fixed-window per-IP request counter for the host mux.
// Bounded memory: stale windows are overwritten on the next hit from that IP.
// The window key is MINUTES (nowSec/60), matching the "-rate per minute" flag.
type hostLimiter struct {
	max  uint
	wins map[string][2]int64 // ip -> [windowStartSec, count]
	mu   sync.Mutex
}

func newHostLimiter(max uint) *hostLimiter {
	return &hostLimiter{max: max, wins: map[string][2]int64{}}
}

func (l *hostLimiter) allow(ip string, nowSec int64) bool {
	if l.max == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.wins[ip]
	if !ok || w[0] != nowSec {
		l.wins[ip] = [2]int64{nowSec, 1}
		return true
	}
	if uint(w[1]) >= l.max {
		return false
	}
	w[1]++
	l.wins[ip] = w
	return true
}

// handleUserQR serves the user's public pay-me QR (GET) or accepts a new one
// (PUT, gated by the same per-user bearer token as the mailbox itself). The QR
// encodes a signed spore-invite-v1 URI; it is public by design — the invite
// carries public keys only. Uploading is private: only the mailbox owner (or
// the operator with their token) may replace it.
func handleUserQR(w http.ResponseWriter, r *http.Request, dir, tok string) {
	qrPath := filepath.Join(dir, "qr.png")
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(qrPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(data)
	case http.MethodPut:
		if tok != "" {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") ||
				subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(tok)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		if len(body) < 8 || string(body[:8]) != "\x89PNG\r\n\x1a\n" {
			http.Error(w, "body is not a PNG", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(qrPath, body, 0o600); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUserProfileJSON serves the user-editable profile card: GET is public
// (the profile is a public page), PUT is gated by the user's bearer token,
// exactly like the QR upload. The record is validated for shape and size, and
// the rendered page always takes address/pin from onboarding.json, so a
// profile can never forge the identity anchor.
func handleUserProfileJSON(w http.ResponseWriter, r *http.Request, dir, tok string) {
	path := filepath.Join(dir, "profile.json")
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(data)
	case http.MethodPut:
		if tok != "" {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") ||
				subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(tok)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		var probe map[string]any
		if err := json.Unmarshal(body, &probe); err != nil {
			http.Error(w, "body is not JSON", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUserProfile renders the user's public profile page — a link-in-bio
// card (Linktree-style, self-sovereign): name, tagline, pay-me QR, links,
// contact address, and optional assurance entries. Driven by a user-editable
// profile.json (PUT-gated like the QR) with fallback to the onboarding record.
// No secrets are ever rendered: address, pinned fingerprint, and public links
// only.
func handleUserProfile(w http.ResponseWriter, r *http.Request, dir string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	card := struct {
		Name    string `json:"name"`
		Tagline string `json:"tagline"`
		Links   []struct {
			Label string `json:"label"`
			URL   string `json:"url"`
		} `json:"links"`
		PayMe struct {
			Chain  string `json:"chain"`
			Amount string `json:"amount"`
			Note   string `json:"note"`
		} `json:"pay_me"`
		Assurance []struct {
			Source string `json:"source"`
			Claim  string `json:"claim"`
			Ref    string `json:"ref"`
		} `json:"assurance"`
	}{}
	if err != nil || len(raw) == 0 {
		// Fallback: render from the provisioning record alone.
		raw, err = os.ReadFile(filepath.Join(dir, "onboarding.json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var onboarding struct {
			Name       string `json:"name"`
			MailboxURL string `json:"mailbox_url"`
			Address    string `json:"address"`
			PinnedSig  string `json:"pinned_sig"`
		}
		if err := json.Unmarshal(raw, &onboarding); err != nil {
			http.Error(w, "corrupt onboarding record", http.StatusInternalServerError)
			return
		}
		card.Name, card.PayMe.Chain = onboarding.Name, "dero"
		renderProfile(w, card, onboarding.Address, onboarding.PinnedSig, onboarding.MailboxURL)
		return
	}
	if err := json.Unmarshal(raw, &card); err != nil {
		http.Error(w, "corrupt profile.json", http.StatusInternalServerError)
		return
	}
	// The address/pin live in the onboarding record — profile.json cannot
	// forge them, so the page's trust anchor always comes from provisioning.
	ob, err := os.ReadFile(filepath.Join(dir, "onboarding.json"))
	if err != nil {
		http.Error(w, "missing onboarding record", http.StatusInternalServerError)
		return
	}
	var onboarding struct {
		MailboxURL string `json:"mailbox_url"`
		Address    string `json:"address"`
		PinnedSig  string `json:"pinned_sig"`
	}
	if err := json.Unmarshal(ob, &onboarding); err != nil {
		http.Error(w, "corrupt onboarding record", http.StatusInternalServerError)
		return
	}
	renderProfile(w, card, onboarding.Address, onboarding.PinnedSig, onboarding.MailboxURL)
}

func renderProfile(w http.ResponseWriter, card struct {
	Name    string `json:"name"`
	Tagline string `json:"tagline"`
	Links   []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
	PayMe struct {
		Chain  string `json:"chain"`
		Amount string `json:"amount"`
		Note   string `json:"note"`
	} `json:"pay_me"`
	Assurance []struct {
		Source string `json:"source"`
		Claim  string `json:"claim"`
		Ref    string `json:"ref"`
	} `json:"assurance"`
}, address, pinned, mailboxURL string) {
	esc := func(s string) string { return html.EscapeString(s) }
	shortAddr := address
	if len(shortAddr) > 22 {
		shortAddr = shortAddr[:12] + "…" + shortAddr[len(shortAddr)-8:]
	}
	linksHTML := ""
	for _, l := range card.Links {
		if l.Label == "" || l.URL == "" {
			continue
		}
		linksHTML += fmt.Sprintf(`<a class="link" href="%s" target="_blank" rel="noopener">%s</a>`, esc(l.URL), esc(l.Label))
	}
	assuranceHTML := ""
	for _, a := range card.Assurance {
		ref := ""
		if a.Ref != "" {
			ref = fmt.Sprintf(` <span class="ref">%s</span>`, esc(a.Ref))
		}
		assuranceHTML += fmt.Sprintf(`<div class="assur"><span class="tick">✓</span>%s%s</div>`, esc(a.Claim), ref)
	}
	payNote := ""
	if card.PayMe.Amount != "" {
		payNote = fmt.Sprintf(`<div class="row">pay-me <b>%s</b>%s</div>`, esc(card.PayMe.Amount), map[bool]string{true: ` — ` + esc(card.PayMe.Note)}[card.PayMe.Note != ""])
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s · spore profile</title>
<style>
  :root{--bg:#0c0f14;--panel:#151a22;--line:#2a3342;--fg:#e6e9ef;--muted:#8b95a5;--accent:#5eead4;--ok:#4ade80}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
    font:15px/1.55 ui-monospace,'SF Mono',Menlo,Consolas,monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:34px;max-width:460px;width:calc(100%% - 40px);margin:24px 0}
  h1{font-size:20px;margin:0 0 4px;color:var(--accent)}.sub{color:var(--muted);font-size:13px;margin-bottom:14px}
  img{width:230px;height:230px;display:block;margin:0 auto 16px;border-radius:10px;background:#fff}
  a.link{display:block;text-decoration:none;text-align:center;color:var(--fg);background:#0c0f14;
    border:1px solid var(--line);border-radius:9px;padding:10px;margin:8px 0;font-size:14px}
  a.link:hover{border-color:var(--accent);color:var(--accent)}
  code{background:#0c0f14;border:1px solid var(--line);padding:2px 6px;border-radius:6px;font-size:12px;word-break:break-all}
  .row{margin:8px 0;color:var(--muted);font-size:12px}.row b{color:var(--fg);font-weight:600}
  .assur{display:flex;gap:8px;align-items:baseline;color:var(--muted);font-size:12px;margin:6px 0}
  .assur .tick{color:var(--ok);font-weight:700}.assur .ref{opacity:.6}
  .note{color:var(--muted);font-size:12px;margin-top:16px;border-top:1px solid var(--line);padding-top:12px}
</style></head><body>
<div class="card">
  <h1>%s</h1><div class="sub">%s</div>
  <img src="./qr" alt="spore invite QR — scan to message %s privately">
  %s
  %s
  <div class="row">address <b>%s</b></div>
  <div class="row">pin <b>%s…</b></div>
  %s
  <div class="note">Scan the QR to add and message this person privately — end-to-end encrypted, and any payment rides the same atomic transaction. Hosted mailboxes hold only TTL-bound ciphertext; no server ever holds the keys.</div>
</div></body></html>`,
		esc(card.Name), esc(card.Name), esc(card.Tagline), esc(card.Name), linksHTML, assuranceHTML,
		esc(shortAddr), esc(shortPinned(pinned)), payNote)
}

func shortPinned(s string) string {
	if len(s) <= 10 {
		return s
	}
	return s[:10]
}

// loadHostTokens reads the optional {user: token} map. A missing file is not an
// error (loopback hosting needs no tokens); a malformed one is.
func loadHostTokens(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	var m map[string]string
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("mailbox host: -tokens must be a JSON object of {\"user\":\"token\"}: %w", err)
	}
	return m, nil
}
