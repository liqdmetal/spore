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
	seen := map[string]map[string]bool{}   // per client key: drained CIDs
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
					if seen[key] == nil {
						seen[key] = map[string]bool{}
					}
				}
				ptrs, err := cl.DrainOnce(ctx, seed, lease, seen[key])
				if err != nil {
					fmt.Fprintf(os.Stderr, "fabric %s: drain: %v\n", addr, err)
					continue
				}
				for _, raw := range ptrs {
					if retry, ok := ing.ingestPointer(raw, time.Now()); !ok {
						if retry.CID != ([32]byte{}) {
							retrying[hex.EncodeToString(retry.CID[:])] = fabricRetry{raw: raw, deadline: retry.BurnDeadline, tries: 1}
						}
						continue
					}
					fmt.Printf("fabric %s: ingested pointer (session %x, epoch %d)\n", addr, tgt.sid, tgt.epoch)
				}
			}
		}
		// Retry pass: bodies whose stores only now hold the frame.
		for cidHex, ent := range retrying {
			if _, ok := ing.ingestPointer(ent.raw, time.Now()); ok {
				delete(retrying, cidHex)
				continue
			}
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
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
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
	return &fabricSendRoute{seed: seed, relays: relays, epochs: fabricEpochs(epochN, false)}, nil
}

// fabricSendRoute is the resolved -route-fabric configuration for one send.
type fabricSendRoute struct {
	seed   [32]byte
	relays []string
	epochs []uint32
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
func fabricPublishPointer(ctx context.Context, route *fabricSendRoute, sid [8]byte, raw []byte) {
	if route == nil || len(raw) != 74 {
		return
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
