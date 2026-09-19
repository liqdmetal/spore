package main

// fabriccover.go — the PUBLISHER face of cover traffic (slice F4b,
// docs/RELAY_FABRIC_F4.md §2). `spore fabric cover` runs a long-lived loop
// that fput's freshly minted decoy pointers at the recipient's REAL fabric
// handles on every configured relay, at Poisson-drawn intervals
// (-fabric-cover-rph covers/hour, exponential waits — never a ticker).
//
// The fan-out mirrors fabricPublishPointer EXACTLY — same seed-derived
// handles (epochs n and n-1), same relays, same verb, same 74-byte size —
// so a relay cannot separate the cover stream from the real stream by
// shape. A separate "beacon" handle would be a double failure: a handle
// that exists only for cover is observable as such, and the real handle's
// fingerprint would remain naked.
//
// The paired halves of the design:
//
//   - The SENDER's operator runs this loop so the relay's view of the
//     handle becomes a dense stream that hides the sparse real sends
//     (fabricPublishPointer optionally FOLDS a real send into the next
//     cover slot when -fabric-cover-fold is on).
//   - The RECIPIENT's drain loop (fabric subscribe) recognizes decoys by
//     their DecoyRoute binding and skips them BEFORE the body fetch — the
//     recipient-side cost of cover is one cheap local comparison per
//     decoy, not a fetch and not a decrypt.
//
// Identity: the decoy pointer binds a constant cover route, so the handle
// used to PUBLISH cover needs no derivation of its own — the real handle
// here is the recipient's (seed, epoch, sid) exactly as -route-fabric
// publishes to it. Seed and relays resolve like everywhere else in the
// fabric commands: flags, seed file, or a maildb contact card.

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/liqdmetal/spore/internal/fabric"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/store"
)

// isDecoy reports whether raw parses as a pointer bound to one of the
// decoy routes. Parse errors are NOT decoys — malformed pointers are
// reported by ingest, not silently eaten by the filter.
func isDecoy(raw []byte, routes map[[32]byte]bool) bool {
	pp, err := ratchetwire.ParsePointerPayload(raw)
	if err != nil {
		return false
	}
	return routes[pp.Route]
}

func fabricCover(args []string) {
	fs := flag.NewFlagSet("fabric cover", flag.ExitOnError)
	e2Common(fs)
	registerFabricFlags(fs)
	sessions := fs.String("cover-session", "", "comma-separated 16-hex session ids to cover (REQUIRED; the sids your sends actually use — see `spore msg sessions`)")
	storeDir := fs.String("cover-store", "", "decoy body store dir (default: <state-dir>/fabric-cover-bodies, else ./fabric-cover-bodies)")
	once := fs.Bool("cover-once", false, "fire ONE cover event and exit (smoke test)")
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	rph := 0.0
	if f := fs.Lookup("fabric-cover-rph"); f != nil {
		if v, perr := strconv.ParseFloat(f.Value.String(), 64); perr == nil {
			rph = v
		}
	}
	if rph <= 0 {
		check(fmt.Errorf("fabric cover requires -fabric-cover-rph > 0 (cover traffic changes a node's public request profile; enabling it is a conscious choice, so there is no implicit default)"))
	}
	seedHex, err := fabricSeedHex(fs)
	check(err)
	seedRaw, err := hex.DecodeString(seedHex)
	check(err)
	if len(seedRaw) != 32 {
		check(fmt.Errorf("-fabric-seed must be 32 bytes (64 hex chars)"))
	}
	var seed [32]byte
	copy(seed[:], seedRaw)
	relays, err := fabricRelayList(fs)
	check(err)
	if len(relays) == 0 {
		check(fmt.Errorf("no fabric relays: pass -fabric-relay host:port (repeatable) or save relays on the contact card"))
	}
	epochN := uint32(1)
	if f := fs.Lookup("fabric-epoch"); f != nil {
		epochN = flagUint(f)
	}
	// Cover MUST target the handles real sends actually use: per session,
	// per drain epoch. A stream parked on a handle nobody drains (or a
	// zero sid) would decorate the wrong handle and hide nothing.
	var sids [][8]byte
	for _, part := range strings.Split(*sessions, ",") {
		part = trimSpace(part)
		if part == "" {
			continue
		}
		raw, err := hex.DecodeString(part)
		if err != nil || len(raw) != 8 {
			check(fmt.Errorf("-cover-session entries must be 16 hex chars (8 bytes), got %q", part))
		}
		var sid [8]byte
		copy(sid[:], raw)
		sids = append(sids, sid)
	}
	if len(sids) == 0 {
		check(fmt.Errorf("fabric cover requires -cover-session (comma-separated 16-hex session ids your sends actually use; cover parked on any other handle hides nothing)"))
	}

	// Targets mirror the real publish fan-out: every session x every drain
	// epoch (n and n-1, the dual-publish set) x every relay, handles
	// derived from the contact seed exactly as fabricPublishPointer
	// derives them. This identity is the design law — cover rides the
	// REAL handles.
	var targets []fabric.CoverTarget
	for _, addr := range relays {
		for _, sid := range sids {
			for _, e := range fabricEpochs(epochN, false) {
				h, err := fabric.FabricHandle(seed, e, sid)
				if err != nil {
					check(err)
				}
				targets = append(targets, fabric.CoverTarget{Addr: addr, Handle: hex.EncodeToString(h[:])})
			}
		}
	}

	// Decoy body store: decoys are REAL bodies the sender holds (content-
	// addressed under the same sha256 convention as every store), so a
	// hostile ratchet-bound fetch finds bytes, not an error oracle.
	stateDir := flagValueOr(fs, "state-dir", "")
	dir := *storeDir
	if dir == "" {
		if stateDir != "" {
			dir = filepath.Join(stateDir, "fabric-cover-bodies")
		} else {
			dir = "fabric-cover-bodies"
		}
	}
	bodyStore, err := store.NewDiskStore(dir)
	check(err)

	sched, err := fabric.NewCoverScheduler(rph, nil, nil)
	check(err)
	loop := &fabric.CoverLoop{
		Sched:   sched,
		Targets: targets,
		Store:   bodyStore,
		BodyTTL: fabric.DecoyBodyTTL,
		Log: func(format string, args ...any) {
			fmt.Printf("fabric cover: "+format+"\n", args...)
		},
	}
	fmt.Printf("fabric cover: %d target(s) (%d relay(s) x %d session(s) x %d epoch(s)), %.4g covers/hour (mean wait %s), decoy store %s\n",
		len(targets), len(relays), len(sids), len(fabricEpochs(epochN, false)), rph, sched.MaxFold(), dir)
	if *once {
		if err := loop.FireOnce(context.Background()); err != nil {
			check(err)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := loop.Run(ctx); err != nil && err != context.Canceled {
		check(err)
	}
	fmt.Println("fabric cover: stopped")
}
