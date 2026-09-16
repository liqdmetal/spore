package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liqdmetal/spore/internal/nostr"
	"github.com/liqdmetal/spore/internal/peerstore"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/relay"
	"github.com/liqdmetal/spore/internal/store"
)

// e2StoreOptions bundles every knob of the off-chain body-store plumbing.
// Keeping it a struct (instead of a positional-parameter list) means new
// store backends or knobs are added in one place, and call sites never grow
// blank-string placeholder arguments.
type e2StoreOptions struct {
	// URL is the -store value: http(s)://mailbox, nostr://relay1,relay2,
	// peer://host:port, or sporepeer://host:port.
	URL string
	// Token is the -store-token bearer token (HTTP stores only).
	Token string
	// KeyFile is the -store-key dedicated signing key file (nostr:// only).
	KeyFile string
	// RelayBase is the -relay anonymous write-relay base URL (HTTP only).
	RelayBase string
	// HoldDir is the -store-dir hold directory (sporepeer:// only).
	HoldDir string
	// ServeAddr is the -store-serve bind address for this node's spore-peer
	// listener (sporepeer:// only).
	ServeAddr string
}

// registerE2StoreFlags registers the -store* / -relay flags shared by every
// E2 command. Carrier and state flags stay in e2Common; this keeps the
// body-store surface in one unit alongside the dispatch below.
func registerE2StoreFlags(fs *flag.FlagSet) {
	fs.String("store", "", "off-chain frame store: http(s)://mailbox, nostr://relay1,relay2 (public commons), or sporepeer://host:port (P2P: the other endpoint's node; pair with -store-serve)")
	fs.String("store-token", "", "bearer token for an HTTP store (ignored for nostr:// and sporepeer://)")
	fs.String("store-dir", "", "directory where THIS node holds the bodies it produces (required for sporepeer://; `spore init` layouts can use ~/.spore/hold)")
	fs.String("store-serve", "", "bind address for this node's spore-peer listener, e.g. 0.0.0.0:8099 (sporepeer:// only): your contact points -store sporepeer://<your-addr>:<port> at it")
	fs.String("relay", "", "anonymous relay hop base URL (e.g. https://relay.example.org): route off-chain body WRITES through this relay instead of PUTting straight to -store — the mailbox sees the relay's IP and you never need the mailbox's own token. The relay operator must allowlist your destination (-allow-dest). HTTP stores only")
	fs.String("store-key", "", "file with a 32-byte hex DEDICATED signing key for -store nostr:// (do NOT reuse identity/chain keys — publishing is linkable by pubkey; `spore init` writes one)")
}

// e2StoreOptionsFromFlags is the single canonical flags→options mapping for
// the body-store flags. Commands that own their own flag set (web E2) can
// build e2StoreOptions directly instead.
func e2StoreOptionsFromFlags(fs *flag.FlagSet) e2StoreOptions {
	return e2StoreOptions{
		URL:       flagValueOr(fs, "store", ""),
		Token:     flagValueOr(fs, "store-token", ""),
		KeyFile:   flagValueOr(fs, "store-key", ""),
		RelayBase: flagValueOr(fs, "relay", ""),
		HoldDir:   flagValueOr(fs, "store-dir", ""),
		ServeAddr: flagValueOr(fs, "store-serve", ""),
	}
}

// newE2BodyStore builds the body store described by opts: the URL scheme
// picks the backend, the remaining fields configure it. Every E2 command
// builds its store through here so backend validation and error wording
// stay identical across commands.
func newE2BodyStore(opts e2StoreOptions) (ratchetwire.BodyStore, error) {
	if opts.URL == "" {
		return nil, errors.New("-store is required (E2 never uses a local-only implicit store)")
	}
	if rest, ok := strings.CutPrefix(opts.URL, "nostr://"); ok {
		if opts.RelayBase != "" {
			return nil, errors.New("-relay applies to an http(s) mailbox only: -store nostr:// already publishes bodies to a relay commons, so pick one (drop -relay for the nostr path)")
		}
		var relays []string
		for _, r := range strings.Split(rest, ",") {
			if r = strings.TrimSpace(r); r != "" {
				if !strings.HasPrefix(r, "wss://") && !strings.HasPrefix(r, "ws://") {
					r = "wss://" + r
				}
				relays = append(relays, r)
			}
		}
		if len(relays) == 0 {
			return nil, errors.New("-store nostr:// requires at least one relay (e.g. -store nostr://relay.damus.io,nos.lol)")
		}
		if opts.KeyFile == "" {
			return nil, errors.New("-store nostr:// requires -store-key (a DEDICATED body-store signing key file; `spore init` writes one at store.key — do not reuse your identity or chain key, publishing is linkable by pubkey)")
		}
		k, err := readHexFile(opts.KeyFile, 32)
		if err != nil {
			return nil, err
		}
		// Index next to the key so Delete/Reap survive restarts. Without it
		// we could still Get, but Reap would have nothing to iterate — i.e.
		// bodies would never be cleaned up from the commons.
		indexPath := ""
		if dir := filepath.Dir(opts.KeyFile); dir != "" && dir != "." {
			indexPath = filepath.Join(dir, "nostrstore-index.json")
		}
		return nostr.NewNostrStore(nostr.NostrStoreConfig{
			PrivateKey: hex.EncodeToString(k),
			Relays:     relays,
			IndexPath:  indexPath,
		})
	}
	if rest, ok := strings.CutPrefix(opts.URL, "peer://"); ok {
		if opts.RelayBase != "" {
			return nil, errors.New("-relay does not apply to a peer:// store: the peer hop IS the transport")
		}
		if rest == "" || !strings.Contains(rest, ":") {
			return nil, errors.New("-store peer:// requires the sender's node address, e.g. peer://192.0.2.10:8099 (receive-only: the sender must run `spore-peer serve` on that node)")
		}
		return &peerstore.PeerStore{Addr: rest}, nil
	}
	if rest, ok := strings.CutPrefix(opts.URL, "sporepeer://"); ok {
		if opts.RelayBase != "" {
			return nil, errors.New("-relay does not apply to a sporepeer:// store: the peer hop IS the transport")
		}
		if rest == "" || !strings.Contains(rest, ":") {
			return nil, errors.New("-store sporepeer:// requires the peer's node address, e.g. sporepeer://192.0.2.10:8099 (the OTHER endpoint's spore-peer listener; pair it with -store-serve on your own side so they can fetch from you)")
		}
		if opts.HoldDir == "" {
			return nil, errors.New("-store sporepeer:// requires -store-dir (a directory where THIS node holds the bodies it produces; the sender's hold is what the receiver fetches from)")
		}
		st, err := peerstore.NewSporePeerStore(peerstore.SporePeerConfig{
			Dir:    opts.HoldDir,
			Addr:   rest,
			Listen: opts.ServeAddr,
		})
		if err != nil {
			return nil, err
		}
		if opts.ServeAddr != "" {
			fmt.Fprintf(os.Stderr, " spore-peer serving on %s — your contact uses -store sporepeer://%s\n", st.LocalAddr(), st.LocalAddr())
		}
		return st, nil
	}
	inner, err := store.NewHTTPStoreWithToken(opts.URL, opts.Token)
	if err != nil {
		return nil, err
	}
	if opts.RelayBase == "" {
		return inner, nil
	}
	return relay.NewRelayStore(opts.RelayBase, opts.URL, inner)
}
