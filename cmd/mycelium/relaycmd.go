// relay — the relay-fabric hop command.
//
//	mycelium relay run -listen :ADDR [-dir DIR] [-token SECRET] [-interval 10s] [-reap 30s]
//
// A relay is an always-on store-and-forward middle node: a phone pushes an
// opaque body bound for a destination mailbox (X-Relay-Dest) and the relay
// holds it, then best-effort retransmits it to that mailbox's /put route so the
// mailbox sees the relay's IP, not the phone's, and no single operator sees the
// full phone<->mailbox association. The relay only ever holds content-addressed
// ciphertext and never decrypts.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/liqdmetal/mycelium/internal/relay"
	"github.com/liqdmetal/mycelium/internal/store"
)

func relaycmd(args []string) {
	if len(args) == 0 {
		relayUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "run":
		relayRun(args[1:])
	case "-h", "--help":
		relayUsage()
	default:
		fmt.Fprintf(os.Stderr, "relay: unknown subcommand %q (want run)\n", args[0])
		os.Exit(2)
	}
}

func relayUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  mycelium relay run -listen :ADDR [-dir DIR] [-token SECRET] [-interval 10s] [-reap 30s]
             (store-and-forward hop for opaque bodies; always-on)
  mycelium relay -h, --help

flags:
  -listen    relay HTTP listen address (default :19300)
  -dir       disk dir to durably hold bodies; empty = in-memory
  -token     shared secret; require Authorization: Bearer *** on every route
  -interval  forwarder retry interval (default 10s)
  -reap      expired-body reaper interval (default 30s)`)
}

func relayRun(args []string) {
	fs := flag.NewFlagSet("relay run", flag.ExitOnError)
	listen := fs.String("listen", ":19300", "relay HTTP listen address")
	dir := fs.String("dir", "", "disk dir to durably hold bodies (empty = in-memory)")
	token := fs.String("token", "", "shared secret; require `Authorization: Bearer *** on every route")
	interval := fs.Duration("interval", 10*time.Second, "forwarder retry interval")
	reap := fs.Duration("reap", 30*time.Second, "expired-body reaper interval")
	_ = fs.Parse(args)

	var st store.Store
	dirNote := "(in-memory)"
	if *dir != "" {
		ds, err := store.NewDiskStore(*dir)
		if err != nil {
			log.Fatalf("relay run: cannot open store dir: %v", err)
		}
		st = ds
		dirNote = *dir
	} else {
		st = store.NewMemStore()
	}
	r := relay.New(st)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var handler http.Handler = r.Handler()
	if *token != "" {
		handler = r.HandlerToken(*token)
		log.Printf("relay: HTTP auth enabled — every route requires `Authorization: Bearer ***")
	}
	hsrv := &http.Server{Addr: *listen, Handler: handler}
	go func() {
		log.Printf("relay: serving on http://%s (dir %s)", *listen, dirNote)
		if err := hsrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Reap expired (burned) bodies and best-effort retry forwarding.
	go func() {
		t := time.NewTicker(*reap)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if n := r.Reap(time.Now()); n > 0 {
					log.Printf("relay: reaped %d burned body(ies)", n)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go r.ForwardLoop(ctx, *interval)

	log.Printf("relay: pushing opaque bodies to http://%s/relay/<cid> with X-Relay-Dest: <mailbox-base>", *listen)
	log.Printf("relay: forwarding interval %s, reap %s", *interval, *reap)

	<-ctx.Done()
	hsrv.Close()
}
