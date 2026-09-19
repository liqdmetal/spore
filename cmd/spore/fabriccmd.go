package main

// fabricCmd — slice F2's client face of the relay fabric (docs/RELAY_FABRIC,
// WIRE_SPEC §8). Two verbs:
//
//	spore fabric subscribe — the RECIPIENT's drain loop: register every
//	    configured relay under the contact-seed-derived handle (epochs n and
//	    n-1 per the DECIDED dual-publish protocol), fpop each relay on a
//	    ticker, and feed every drained 74-byte pointer into the SHARED
//	    e2Ingestor pipeline (e2ingest.go) — the exact pipeline the chain
//	    watcher uses, so decryption stays in ONE place.
//	spore fabric handle    — derive and print the fabric handle(s) for a
//	    contact's seed: what the sender needs for -route-fabric, what the
//	    recipient needs to sanity-check registration.
//
// Bootstrap fence (WIRE_SPEC §8, RELAY_FABRIC): fabric drains carry
// FrameMessage continuations ONLY. A brand-new session's handshake pointer
// can only be recognized on-chain (the recipient cannot pre-derive a handle
// for a sid it has never seen), so first contact rides the chain carrier;
// the e2Ingestor refuses FrameInit from the fabric path and the drain loop
// additionally skips unknown sessions before spending a fetch.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/fabric"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

func fabricCmd(args []string) {
	if len(args) == 0 {
		fabricUsage()
		return
	}
	switch args[0] {
	case "subscribe":
		fabricSubscribe(args[1:])
	case "cover":
		fabricCover(args[1:])
	case "handle":
		fabricHandle(args[1:])
	default:
		fabricUsage()
		os.Exit(2)
	}
}

func fabricUsage() {
	fmt.Fprint(os.Stderr, `usage: spore fabric <command> [flags]

  subscribe     register at relays and drain pointers into E2 ingestion
                (the recipient's half of the relay fabric; pairs with
                -route-fabric on send)
  cover         run the publisher-side cover-traffic loop (F4b):
                Poisson-drawn decoy fputs at the real handles
                (-fabric-cover-rph; see docs/RELAY_FABRIC_F4.md)
  handle        derive the fabric handle for a contact seed (send-side use)
`)
}

// registerFabricFlags registers fabric knobs on fs WITHOUT colliding with
// the receiver flags openE2Receiver reads or the e2Common set (-fabric-epoch
// lives on e2Common, shared with the send path). Both run on the same
// FlagSet for `fabric subscribe`.
func registerFabricFlags(fs *flag.FlagSet) {
	fs.String("fabric-seed", "", "contact seed (64-char hex) to derive fabric handles; overrides any -fabric-relays-derived lookup")
	fs.String("fabric-seed-file", "", "file containing the contact seed hex (alternative to -fabric-seed)")
	fs.Bool("fabric-latest-only", false, "drain ONLY epoch n (skip n-1); use when every pre-rotation pointer has burned")
	fs.Duration("fabric-lease", 72*time.Hour, "fabric registration lease to request (relays cap at 7d)")
	fs.String("fabric-relay", "", "fabric relay host:port to drain (repeatable: -fabric-relay a -fabric-relay b)")
	fs.String("fabric-decoy-skip-file", "", "optional decoy-route filter file (64-hex routes, one per line); the default filter already covers the shipped cover route (F4b)")
}

// fabricSeedHex resolves the contact seed from flags or, absent both, from
// the maildb contact record named by -maildb/-to semantics (single contact
// with a seed wins; ambiguity is an error, not a guess).
func fabricSeedHex(fs *flag.FlagSet) (string, error) {
	if v := fs.Lookup("fabric-seed").Value.String(); v != "" {
		return v, nil
	}
	if v := fs.Lookup("fabric-seed-file").Value.String(); v != "" {
		b, err := os.ReadFile(v)
		if err != nil {
			return "", err
		}
		return trimSpace(string(b)), nil
	}
	maildbPath := fs.Lookup("maildb").Value.String()
	if maildbPath == "" {
		return "", fmt.Errorf("no fabric seed: pass -fabric-seed, -fabric-seed-file, or -maildb (a contact with a saved seed)")
	}
	db, err := maildb.Open(maildbPath)
	if err != nil {
		return "", err
	}
	seed := ""
	nick := ""
	for _, c := range db.Contacts() {
		if c.FabricSeed == "" {
			continue
		}
		if seed != "" {
			return "", fmt.Errorf("multiple contacts carry fabric seeds; name one explicitly (-fabric-seed or -to %s)", nick)
		}
		seed = c.FabricSeed
		nick = c.Nickname
	}
	if seed == "" {
		return "", fmt.Errorf("no maildb contact has a fabric seed (saved by `spore msg mail add -invite`)")
	}
	return seed, nil
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\r' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// fabricRelayList assembles the relay set: explicit -fabric-relay flags
// (repeatable), then the contact card's FabricRelays from maildb.
func fabricRelayList(fs *flag.FlagSet) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(list string) {
		start := 0
		for i := 0; i <= len(list); i++ {
			if i == len(list) || list[i] == ',' {
				item := trimSpace(list[start:i])
				if item != "" && !seen[item] {
					seen[item] = true
					out = append(out, item)
				}
				start = i + 1
			}
		}
	}
	// flag.FlagSet holds repeated String flags: VisitAll sees the LAST
	// value only, so repeats must be read from the raw args. Fabric
	// subscribe therefore ALSO accepts a comma list: -fabric-relay "a,b".
	if v := fs.Lookup("fabric-relay").Value.String(); v != "" {
		add(v)
	}
	maildbPath := fs.Lookup("maildb").Value.String()
	if maildbPath != "" {
		db, err := maildb.Open(maildbPath)
		if err != nil {
			return out, nil // relays are optional; seed errors are the loud ones
		}
		if to := fs.Lookup("to"); to != nil && to.Value.String() != "" {
			want := to.Value.String()
			for _, c := range db.Contacts() {
				if c.Nickname == want && c.FabricRelays != "" {
					add(c.FabricRelays)
				}
			}
		}
	}
	return out, nil
}

// fabricSessionTargets enumerates the (sid, epoch) handle targets to drain:
// every live session, at epochs n and n-1 (DECIDED rotation protocol),
// deduplicated by handle. Sessions not present in the durable table are
// skipped — that IS the bootstrap fence: unknown sids cannot be pre-derived,
// so their pointers can only arrive via the chain watcher. Each target
// carries its OWN epoch: the n-1 handle derives with epoch n-1, not n.
func fabricSessionTargets(ep *ratchetwire.DurableEndpoint, seed [32]byte, epoch uint32, latestOnly bool) map[string]fabricTarget {
	handles := map[string]fabricTarget{}
	for _, sid := range ep.Sessions.IDs() {
		for _, e := range fabricEpochs(epoch, latestOnly) {
			h, err := fabric.FabricHandle(seed, e, sid)
			if err != nil {
				continue
			}
			handles[hex.EncodeToString(h[:])] = fabricTarget{sid: sid, epoch: e}
		}
	}
	return handles
}

// fabricTarget is one (session, epoch) drain destination.
type fabricTarget struct {
	sid   [8]byte
	epoch uint32
}

func fabricEpochs(epoch uint32, latestOnly bool) []uint32 {
	if latestOnly || epoch == 0 || epoch == 1 {
		return []uint32{epoch}
	}
	return []uint32{epoch, epoch - 1}
}

func fabricSubscribe(args []string) {
	fs, o := newRecvE2Flagset()
	registerFabricFlags(fs)
	once := fs.Bool("once", false, "drain once and exit (no ticker loop)")
	interval := fs.Duration("fabric-interval", 5*time.Second, "drain cadence")
	jitterPct := fs.Int("fabric-jitter", 20, "drain cadence jitter percent (+/-N% per pass; 0 = fixed interval)")
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	if *o.identity == "" || *o.spk == "" {
		check(fmt.Errorf("fabric subscribe requires -identity and -spk (the same receiver kit as recv-e2)"))
	}

	// Receiver setup — SHARED with msg recv-e2 (openE2Receiver), so the
	// drain ingests through the exact pipeline the chain watcher uses.
	ing, cleanup, err := openE2Receiver(fs, "", false)
	check(err)
	defer cleanup()

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
	// flag.Getter.Get() returns CONCRETE values whose exact type for uint
	// flags varies by Go version (uint vs uint64) — read through flagUint.
	epoch := flagUint(fs.Lookup("fabric-epoch"))
	latestOnly := fs.Lookup("fabric-latest-only").Value.(flag.Getter).Get().(bool)
	lease := fs.Lookup("fabric-lease").Value.(flag.Getter).Get().(time.Duration)

	// One client per (relay, handle) per pass; handles derive from live
	// sessions, re-enumerated every tick — a session created by a
	// chain-watcher FrameInit between ticks starts draining automatically
	// on the next pass, with no restart.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Clients persist per (relay, handle) across ticks: each remembers its
	// possession token and lease expiry, so EnsureRegistered renews only
	// near expiry instead of re-fregging every pass. New targets (a session
	// created by a chain-watcher FrameInit between ticks, a rotated epoch)
	// join on the next pass with no restart.
	clients := map[string]*fabric.Client{} // key: addr|handleHex
	// Drain union (F3, AUDIT-RELAYFABRIC R-N1): ONE consumed-CID set across
	// every relay and tick, persisted beside the ratchet state. The first
	// copy of a pointer to ingest successfully consumes the CID; duplicates
	// from other relays (or re-drains after a restart) are skipped BEFORE
	// the body fetch — M relays cost ONE fetch, not M. Marked on success
	// only: a pointer whose fetch failed stays unmarked, so a second
	// relay's copy can still deliver it (the CONSUMED-set contract).
	seenPath := filepath.Join(flagValueOr(fs, "state-dir", ""), "fabric-seen.txt")
	seen := fabric.NewSeenCIDs(seenPath)
	defer seen.Prune(time.Now())
	// Decoy pre-filter (F4b): cover pointers bind a constant route the
	// ratchet can never accept. Skipping them BEFORE the drain-union means
	// decoys never touch seen-state, never burn a body fetch (FetchFrame's
	// store Get precedes its route-binding check), and never reach ratchet
	// state. Recipient-side cost of sender cover: one local comparison.
	decoyRoutes, derr := fabric.ReadDecoySkipFile(flagValueOr(fs, "fabric-decoy-skip-file", ""))
	check(derr)
	// Pointers whose BODY fetch failed ride an in-process retry list — the
	// same transient state the chain watcher queues. Bounded: attempts die
	// at the pointer's own burn deadline (the relay composts then anyway).
	type fabricRetry struct {
		raw      []byte
		deadline uint64
		tries    int
	}
	retrying := map[string]fabricRetry{} // key: hex CID

	drainOnce := func() {
		seen.Prune(time.Now())
		targets := fabricSessionTargets(ing.ep, seed, epoch, latestOnly)
		for _, addr := range relays {
			for handleHex, tgt := range targets {
				key := addr + "|" + handleHex
				cl := clients[key]
				if cl == nil {
					cl, err = fabric.NewClient(addr, seed, tgt.epoch, tgt.sid)
					if err != nil {
						fmt.Fprintln(os.Stderr, "fabric:", err)
						continue
					}
					clients[key] = cl
				}
				ptrs, err := cl.DrainOnce(ctx, seed, lease)
				if err != nil {
					fmt.Fprintf(os.Stderr, "fabric %s: drain: %v\n", addr, err)
					continue
				}
				for _, raw := range ptrs {
					// Decoy pre-filter (F4b) BEFORE the drain union: a decoy
					// must not consume seen-state or a body fetch. Malformed
					// pointers are NOT treated as decoys — ingest reports them.
					if isDecoy(raw, decoyRoutes) {
						continue
					}
					// Drain-union gate: the first union-wide sighting consumes
					// the CID; duplicates from other relays/ticks are skipped
					// before FetchFrame can burn a body fetch.
					if !seen.Observe(raw) {
						continue
					}
					if retry, ok := ing.ingestPointer(raw, time.Now()); !ok {
						// Ingest failed (body not yet available, ...): un-mark
						// so another relay's copy stays eligible, and queue the
						// bounded in-process retry as before.
						seen.Forget(raw)
						if retry.CID != ([32]byte{}) {
							retrying[hex.EncodeToString(retry.CID[:])] = fabricRetry{raw: raw, deadline: retry.BurnDeadline, tries: 1}
						}
						continue
					}
					fmt.Printf("fabric %s: ingested pointer (session %x, epoch %d)\n", addr, tgt.sid, tgt.epoch)
				}
			}
		}
		// Retry pass: bodies whose stores only now hold the frame. A retry
		// attempt re-observes (it was un-marked at failure time) and forgets
		// again on failure, keeping the union a CONSUMED set.
		for cidHex, ent := range retrying {
			seen.Observe(ent.raw)
			if _, ok := ing.ingestPointer(ent.raw, time.Now()); ok {
				delete(retrying, cidHex)
				continue
			}
			seen.Forget(ent.raw)
			ent.tries++
			if ent.tries > 3 || (ent.deadline != 0 && uint64(time.Now().Unix()) >= ent.deadline) {
				fmt.Fprintf(os.Stderr, "fabric: gave up on %s (deadline passed or unfetchable — message lost)\n", shortTx(cidHex))
				delete(retrying, cidHex)
			}
		}
	}

	if *once {
		drainOnce()
		return
	}
	// Jittered cadence (F3, AUDIT-RELAYFABRIC R-N2): a fixed drain interval
	// is a timing signature a relay operator can read per handle. Each pass
	// waits interval +/-N% (default 20, the shape internal/relay's backoff
	// uses), so drain starts decorrelate across processes and relays. A
	// timer, not a Ticker: the wait is recomputed per pass, and Ticker would
	// also panic on an explicitly-zero interval.
	if *interval <= 0 {
		check(fmt.Errorf("-fabric-interval must be positive (got %s)", *interval))
	}
	for {
		wait := fabric.JitteredInterval(*interval, *jitterPct, nil)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			drainOnce()
		}
	}
}

func fabricHandle(args []string) {
	fs := flag.NewFlagSet("fabric handle", flag.ExitOnError)
	seedHex := fs.String("seed", "", "contact seed (64-char hex)")
	sidHex := fs.String("session", "", "16-hex session id (see `spore msg sessions`); omit to derive from -all-sessions")
	stateDir := fs.String("state-dir", "", "durable E2 session state dir (with -all-sessions)")
	epoch := fs.Uint("epoch", 1, "fabric epoch n")
	_ = fs.Parse(args)
	if *seedHex == "" {
		check(fmt.Errorf("fabric handle requires -seed (64-char hex)"))
	}
	seedRaw, err := hex.DecodeString(*seedHex)
	check(err)
	if len(seedRaw) != 32 {
		check(fmt.Errorf("-seed must be 32 bytes (64 hex chars)"))
	}
	var seed [32]byte
	copy(seed[:], seedRaw)
	epochs := fabricEpochs(uint32(*epoch), false)

	if *sidHex != "" {
		raw, err := hex.DecodeString(*sidHex)
		check(err)
		if len(raw) != 8 {
			check(fmt.Errorf("-session must be 16 hex chars (8 bytes)"))
		}
		var sid [8]byte
		copy(sid[:], raw)
		out := map[string]string{}
		for _, e := range epochs {
			h, err := fabric.FabricHandle(seed, e, sid)
			check(err)
			out[fmt.Sprintf("epoch-%d", e)] = hex.EncodeToString(h[:])
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}
	if *stateDir == "" {
		check(fmt.Errorf("fabric handle requires -session or -state-dir (to enumerate live sessions)"))
	}
	states, err := ratchetwire.NewFileStateStore(*stateDir, nil)
	check(err)
	ids, err := states.IDs()
	check(err)
	out := map[string]string{}
	for _, sid := range ids {
		for _, e := range epochs {
			h, err := fabric.FabricHandle(seed, e, sid)
			check(err)
			out[fmt.Sprintf("%x@epoch-%d", sid, e)] = hex.EncodeToString(h[:])
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

// fabricSendConfig resolves the sender-side fabric configuration for
// -route-fabric EARLY (before any chain post): the contact card supplies the
// seed and relay list, -fabric-epoch supplies n (dual-publish covers n-1).
// Configuration errors here are HARD errors — a half-configured fabric route
// must fail loudly before the message is committed anywhere, the same
// discipline as the -pinned-sig check.
func fabricSendConfig(fs *flag.FlagSet, to string) (*fabricSendRoute, error) {
	if fs.Lookup("route-fabric") == nil || fs.Lookup("route-fabric").Value.String() != "true" {
		return nil, nil
	}
	maildbPath := flagValueOr(fs, "maildb", "")
	contact, ok := contactForTo(maildbPath, to)
	if !ok || contact.FabricSeed == "" || contact.FabricRelays == "" {
		return nil, fmt.Errorf("-route-fabric requires the recipient's contact card to carry a fabric seed and relay list (re-add with `spore msg mail add -invite`); got seed-present=%v relays-present=%v", contact.FabricSeed != "", contact.FabricRelays != "")
	}
	seedRaw, err := hex.DecodeString(contact.FabricSeed)
	if err != nil || len(seedRaw) != 32 {
		return nil, fmt.Errorf("contact %s has a malformed fabric seed (want 64 hex chars)", to)
	}
	var seed [32]byte
	copy(seed[:], seedRaw)
	relays, err := fabricRelayListFrom(contact.FabricRelays)
	if err != nil {
		return nil, err
	}
	if len(relays) == 0 {
		return nil, fmt.Errorf("contact %s has no fabric relays on the card", to)
	}
	epochN := uint32(1)
	if f := fs.Lookup("fabric-epoch"); f != nil {
		epochN = flagUint(f)
	}
	// Fold setup: validated eagerly so a misconfigured fold fails before
	// the message is committed anywhere (the fabricSendConfig discipline).
	fold := false
	var coverSched *fabric.CoverScheduler
	if f := fs.Lookup("fabric-cover-fold"); f != nil && f.Value.String() == "true" {
		fold = true
	}
	if fold {
		rph, rerr := resolveCoverRPH(fs, contact)
		if rerr != nil {
			return nil, rerr
		}
		cs, cerr := fabric.NewCoverScheduler(rph, nil, nil)
		if cerr != nil {
			return nil, cerr
		}
		coverSched = cs
	}
	return &fabricSendRoute{seed: seed, relays: relays, epochs: fabricEpochs(epochN, false), fold: fold, coverSched: coverSched}, nil
}

// waitFoldReal is the production fold wait: the full delay unless the
// caller's context is cancelled first (a cancelled fold publishes
// immediately — never silently drops the message).
func waitFoldReal(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "route-fabric: fold wait cancelled — publishing immediately")
	case <-timer.C:
	}
}

// resolveCoverRPH reads the sender's cover rate for fold scaling from the
// command line (-fabric-cover-rph, the same flag `fabric cover` uses). A
// zero/negative rate makes fold impossible to honor — the fold delay cap
// comes from the cover interval — so it is a hard error.
func resolveCoverRPH(fs *flag.FlagSet, contact maildb.Contact) (float64, error) {
	var rph float64
	if f := fs.Lookup("fabric-cover-rph"); f != nil {
		if v, err := strconv.ParseFloat(f.Value.String(), 64); err == nil {
			rph = v
		}
	}
	if rph <= 0 {
		return 0, fmt.Errorf("-fabric-cover-fold requires -fabric-cover-rph > 0 (the fold delay is scaled by the cover interval; the sender's cover loop should be running at the same rate)")
	}
	return rph, nil
}

// fabricSendRoute is the resolved -route-fabric configuration for one send.
type fabricSendRoute struct {
	seed       [32]byte
	relays     []string
	epochs     []uint32
	fold       bool
	coverSched *fabric.CoverScheduler
	// waitFold blocks for the fold delay; nil = the production wait
	// (cancellation-aware). Tests replace it to capture the draw.
	waitFold func(ctx context.Context, d time.Duration)
}

// flagUint reads a uint FlagSet flag across Go versions: uintValue.Get()
// has returned either uint or uint64 depending on the release.
func flagUint(f *flag.Flag) uint32 {
	g, ok := f.Value.(flag.Getter)
	if !ok {
		return 1
	}
	switch v := g.Get().(type) {
	case uint:
		return uint32(v)
	case uint64:
		return uint32(v)
	case int:
		return uint32(v)
	default:
		return 1
	}
}

func fabricRelayListFrom(csv string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	start := 0
	for i := 0; i <= len(csv); i++ {
		if i == len(csv) || csv[i] == ',' {
			item := trimSpace(csv[start:i])
			if item != "" && !seen[item] {
				seen[item] = true
				out = append(out, item)
			}
			start = i + 1
		}
	}
	return out, nil
}

// fabricPublishPointer is the sender's fput fan-out AFTER the chain post:
// publish the raw 74-byte pointer at the recipient's fabric handle(s) —
// derived from (contact seed, epoch, sid) exactly as the recipient's drain
// derives them (fabric_v1 vectors pin the byte equality). Best-effort per
// RELAY_FABRIC "Publish": at least one accepted relay means the fabric route
// worked; zero accepted means the chain pointer still delivered, so this
// only WARNS. Dedupe is the relay's (handle, CID) contract: re-sends refresh.
//
// Fold (F4b, -fabric-cover-fold): when the sender's cover loop is running
// (route.coverRPH > 0) and the flag is set, the publish waits one
// Uniform[0, one-cover-interval) draw — the mean is half a cover interval —
// so the real fput lands INSIDE the cover stream instead of spiking above
// it. One draw per call, so the dual-publish copies move together. Off by
// default: it trades up to a full cover interval of latency for send-time
// hiding, and that is the operator's conscious trade.
func fabricPublishPointer(ctx context.Context, route *fabricSendRoute, sid [8]byte, raw []byte) {
	if route == nil || len(raw) != 74 {
		return
	}
	if route.fold && route.coverSched != nil {
		if d := route.coverSched.FoldDelay(); d > 0 {
			fmt.Printf("route-fabric: folding send into cover stream (delay %s)\n", d)
			wait := route.waitFold
			if wait == nil {
				wait = waitFoldReal
			}
			wait(ctx, d)
		}
	}
	deadline := time.Unix(int64(binary.LittleEndian.Uint64(raw[66:74])), 0)
	accepted := 0
	for _, addr := range route.relays {
		for _, e := range route.epochs {
			handle, err := fabric.FabricHandle(route.seed, e, sid)
			if err != nil {
				fmt.Fprintln(os.Stderr, "route-fabric:", err)
				continue
			}
			perr := fabric.PublishAs(ctx, addr, hex.EncodeToString(handle[:]), raw, deadline)
			if perr != nil {
				fmt.Fprintf(os.Stderr, "route-fabric %s: %v\n", addr, perr)
				continue
			}
			accepted++
			fmt.Printf("route-fabric %s: queued (epoch %d)\n", addr, e)
		}
	}
	if accepted == 0 {
		fmt.Fprintln(os.Stderr, "route-fabric: NO relay accepted the pointer — chain delivery is unaffected; fabric route unavailable")
	}
}
