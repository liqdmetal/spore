package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/mailbox"
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
		if tok != "" {
			routes[n] = mb.HandlerToken(tok)
		} else {
			routes[n] = mb.Handler()
		}
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

	// Single multiplexed HTTP listener, path-routed per user.
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
