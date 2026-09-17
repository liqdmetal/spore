package main

// serve implements `spore serve`: an always-on spore-peer body store. This is
// the operational half of the sporepeer:// story — the sender's node is
// SUPPOSED to be the always-on holder of the bodies it sends (that is the
// privacy property: no mailbox operator, only the two endpoints ever hold the
// bytes), and a store that dies with the send command that started it defeats
// the model. The daemon keeps the listener alive for as long as the node is
// up, composting expired bodies on a background cadence.
//
// Wire: exactly the spore-peer JSON subset (WIRE_SPEC §5) that the reference
// Rust `spore-peer serve --dir` speaks — same frames, same 64 MiB response
// cap, same error strings (404 not found / 400 bad cid / 500 cid mismatch /
// 400 bad frame / 410 gone). It is a drop-in replacement in both directions.
//
// Security posture (AUDIT-SPOREPEER): the transport is UNAUTHENTICATED —
// anyone who can reach the port can fetch whatever bodies the hold still
// contains (ciphertext-by-CID is inert without the ratchet key, but treat it
// as public). Serve defaults to LOOPBACK; publish deliberately with -listen
// 0.0.0.0:8099. Expiry is enforced at read time regardless of configuration;
// -reap-every only controls when expired bytes leave the disk.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/peerstore"
)

func servecmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := fs.String("dir", "", "hold directory: bodies served from here until their burn deadline (same layout as -store-dir)")
	listen := fs.String("listen", "127.0.0.1:8099", "bind address for the spore-peer listener (loopback by default; use 0.0.0.0:8099 to serve contacts over the network)")
	reapEvery := fs.Duration("reap-every", 10*time.Minute, "compost expired bodies in the background on this cadence (expiry is enforced at read time regardless; 0 disables background composting)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "spore serve: -dir is required (the hold directory this node serves bodies from)")
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "spore serve: unexpected argument %q\n", fs.Arg(0))
		os.Exit(2)
	}

	st, err := peerstore.NewSporePeerStore(peerstore.SporePeerConfig{
		Dir:       *dir,
		Listen:    *listen,
		ReapEvery: *reapEvery,
	})
	if err != nil {
		logFatal(fmt.Errorf("spore serve: %w", err))
	}

	// The -dir default mirrors the e2 flag surface (`spore init` layouts use
	// ~/.spore/hold) — but serve takes it explicitly so the daemon owns its
	// hold path unambiguously.
	fmt.Printf("spore serve: holding %s\nspore serve: listening on sporepeer://%s (your contact points -store sporepeer://<this-addr> at it)\n",
		*dir, st.LocalAddr())
	if *reapEvery > 0 {
		fmt.Printf("spore serve: composting expired bodies every %s\n", *reapEvery)
	}

	// Block until SIGINT/SIGTERM, then drain: stop accepting, wait for
	// in-flight connections, close the hold cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("spore serve: shutting down")
	if err := st.Close(); err != nil {
		logFatal(err)
	}
}

// logFatal reports err and exits non-zero — one place so the daemon's error
// paths stay uniform.
func logFatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
