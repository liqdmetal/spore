package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/credits"
	"github.com/liqdmetal/spore/internal/roster"
)

// spore sub — subscriber management for newsletters.
//
// Publisher side:
//
//	spore sub add    -roster F -channel C -addr A -pinned-sig HEX [-issues N|-unlimited] [-until 720h] [-nick N]
//	spore sub paid   -roster F -channel C -addr A -pinned-sig HEX -credit F -issuer HEX -ledger L [-issues N]
//	spore sub list   -roster F -channel C
//	spore sub remove -roster F -channel C -addr A
//	spore sub send   -roster F -channel C -notice F   (prints the exact per-subscriber send commands)
//
// Subscriber side:
//
//	spore sub follow -state F -channel C -publisher HEX
//	spore sub status -state F
//
// There is no subscription server. The publisher keeps a local roster file and
// the subscriber keeps local channel state. Nobody else holds the list, so no
// platform can deplatform a publisher or leak the subscriber list — and if the
// publisher loses the file, the list is gone. That trade is stated, not hidden.
func subcmd(args []string) {
	if len(args) == 0 {
		subUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		subAdd(args[1:])
	case "paid":
		subPaid(args[1:])
	case "list":
		subList(args[1:])
	case "remove":
		subRemove(args[1:])
	case "send":
		subSend(args[1:])
	case "follow":
		subFollow(args[1:])
	case "status":
		subStatus(args[1:])
	case "-h", "--help":
		subUsage()
	default:
		fmt.Fprintf(os.Stderr, "sub: unknown subcommand %q (want add|paid|list|remove|send|follow|status)\n", args[0])
		os.Exit(2)
	}
}

func subUsage() {
	fmt.Fprintln(os.Stderr, `usage (publisher):
  spore sub add -roster F -channel C -addr ADDR -pinned-sig HEX
        [-issues N | -unlimited] [-until 720h|RFC3339] [-nick NAME]
  spore sub paid -roster F -channel C -addr ADDR -pinned-sig HEX
        -credit F -issuer HEX -ledger L [-issues N]
        (redeem a prepaid ANONYMOUS credit for N issues -- no account, no
         payment record, no invoice: the roster stores only a counter)
  spore sub list -roster F -channel C
  spore sub remove -roster F -channel C -addr ADDR
  spore sub send -roster F -channel C -notice F [-commit]
        (print the send command for every entitled subscriber; -commit
         consumes one paid issue each and advances the sequence)

usage (subscriber):
  spore sub follow -state F -channel C -publisher HEX
  spore sub status -state F

The roster is YOUR file. No platform holds a copy, nobody can deplatform you,
and nobody can subpoena your subscriber list -- but losing the file loses the
list. Back it up.`)
}

func openRoster(path, channel string) *roster.Roster {
	if path == "" || channel == "" {
		check(errors.New("channel: -roster and -channel are required"))
	}
	r, err := roster.Open(path, channel)
	check(err)
	return r
}

func subAdd(args []string) {
	fs := flag.NewFlagSet("sub add", flag.ExitOnError)
	rosterPath := fs.String("roster", "", "roster file for this channel")
	channel := fs.String("channel", "", "channel name")
	addr := fs.String("addr", "", "subscriber carrier address")
	pinned := fs.String("pinned-sig", "", "subscriber's pinned signing key (their out-of-band trust anchor)")
	nick := fs.String("nick", "", "local label for your own use")
	issues := fs.Int("issues", 0, "number of issues to grant")
	unlimited := fs.Bool("unlimited", false, "grant unlimited issues (comped/free subscriber)")
	until := fs.String("until", "", "expiry: a duration like 720h, or an RFC3339 timestamp")
	_ = fs.Parse(args)

	r := openRoster(*rosterPath, *channel)
	grant := *issues
	if *unlimited {
		grant = -1
	}
	if grant == 0 {
		check(errors.New("sub add: pass -issues N or -unlimited"))
	}
	now := time.Now()
	exp, err := roster.ParseUntil(*until, now)
	check(err)

	s, err := r.Add(*addr, *pinned, *nick, grant, exp, now)
	check(err)

	fmt.Printf("added/updated %s\n", s.Addr)
	fmt.Println(roster.FormatSub(s, now))
	fmt.Printf("\nsubscribers: %d\n", r.Count())
	fmt.Println(r.BackupHint())
}

// channelPaid is the crypto-paid subscription path: a prepaid anonymous credit
// buys N issues with no account and no payment record.
func subPaid(args []string) {
	fs := flag.NewFlagSet("sub paid", flag.ExitOnError)
	rosterPath := fs.String("roster", "", "roster file for this channel")
	channel := fs.String("channel", "", "channel name")
	addr := fs.String("addr", "", "subscriber carrier address")
	pinned := fs.String("pinned-sig", "", "subscriber's pinned signing key")
	nick := fs.String("nick", "", "local label")
	credFile := fs.String("credit", "", "the subscriber's prepaid credit JSON")
	issuer := fs.String("issuer", "", "your issuer public key hex")
	ledger := fs.String("ledger", "", "spend ledger path (prevents reusing a credit)")
	denom := fs.String("denom", "sub", "required credit denom")
	issues := fs.Int("issues", 12, "issues this credit buys")
	until := fs.String("until", "", "optional expiry (duration or RFC3339)")
	_ = fs.Parse(args)

	if *credFile == "" || *issuer == "" || *ledger == "" {
		check(errors.New("sub paid requires -credit, -issuer and -ledger"))
	}
	if *issues <= 0 {
		check(errors.New("sub paid: -issues must be positive"))
	}
	r := openRoster(*rosterPath, *channel)

	raw, err := os.ReadFile(*credFile)
	check(err)
	var c credits.Credit
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	check(dec.Decode(&c))

	l, err := credits.OpenLedger(*ledger)
	check(err)
	now := time.Now()

	// Redeem FIRST: if the credit is bad or already spent, no subscription is
	// granted. If the roster write then fails, the credit is consumed and the
	// operator must re-grant manually -- that direction is the safe one,
	// because the alternative is a credit that buys unlimited subscriptions.
	if err := l.Redeem(&c, *issuer, *denom, now); err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(1)
	}

	exp, err := roster.ParseUntil(*until, now)
	check(err)
	s, err := r.Add(*addr, *pinned, *nick, *issues, exp, now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: credit was consumed but the roster write failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Grant manually with: spore sub add -roster %s -channel %s -addr %s -pinned-sig %s -issues %d\n",
			*rosterPath, *channel, *addr, *pinned, *issues)
		os.Exit(1)
	}

	fmt.Printf("PAID SUBSCRIPTION GRANTED  %d issues\n", *issues)
	fmt.Println(roster.FormatSub(s, now))
	fmt.Printf("\nThe ledger recorded a spend id, denom and UTC day. It holds no payment,\n")
	fmt.Printf("no amount, no invoice and no link to this subscriber's address.\n")
	fmt.Printf("subscribers: %d\n", r.Count())
}

func subList(args []string) {
	fs := flag.NewFlagSet("sub list", flag.ExitOnError)
	rosterPath := fs.String("roster", "", "roster file")
	channel := fs.String("channel", "", "channel name")
	_ = fs.Parse(args)

	r := openRoster(*rosterPath, *channel)
	now := time.Now()
	send, skipped := r.Recipients(now)

	fmt.Printf("channel      %s\n", r.Channel)
	fmt.Printf("next issue   #%d\n", r.NextSeq)
	fmt.Printf("subscribers  %d (%d entitled, %d skipped)\n\n", r.Count(), len(send), len(skipped))
	for _, s := range send {
		fmt.Println(roster.FormatSub(s, now))
	}
	for addr, why := range skipped {
		if s, ok := r.Get(addr); ok {
			fmt.Println(roster.FormatSub(s, now))
			_ = why
		}
	}
	if r.Count() == 0 {
		fmt.Println("(no subscribers yet)")
	}
}

func subRemove(args []string) {
	fs := flag.NewFlagSet("sub remove", flag.ExitOnError)
	rosterPath := fs.String("roster", "", "roster file")
	channel := fs.String("channel", "", "channel name")
	addr := fs.String("addr", "", "subscriber to remove")
	_ = fs.Parse(args)

	r := openRoster(*rosterPath, *channel)
	check(r.Remove(*addr))
	fmt.Printf("removed %s (subscribers: %d)\n", *addr, r.Count())
	fmt.Println("They keep the issues they already received: they already hold the plaintext.")
}

// channelSend prints the exact per-subscriber send commands. It deliberately
// does NOT send: sending needs a live carrier and wallet, and silently
// half-sending a paid issue is worse than printing a script the publisher can
// inspect and run.
func subSend(args []string) {
	fs := flag.NewFlagSet("sub send", flag.ExitOnError)
	rosterPath := fs.String("roster", "", "roster file")
	channel := fs.String("channel", "", "channel name")
	notice := fs.String("notice", "", "the issue notice JSON from `spore publish issue`")
	commit := fs.Bool("commit", false, "consume one paid issue per recipient and advance the sequence (do this AFTER the sends succeed)")
	_ = fs.Parse(args)

	if *notice == "" {
		check(errors.New("sub send: -notice is required"))
	}
	r := openRoster(*rosterPath, *channel)
	now := time.Now()
	send, skipped := r.Recipients(now)

	if len(send) == 0 {
		fmt.Println("no entitled subscribers")
		for addr, why := range skipped {
			fmt.Printf("  SKIP %s: %s\n", addr, why)
		}
		return
	}

	fmt.Printf("# channel %s, issue #%d -> %d subscriber(s)\n", r.Channel, r.NextSeq, len(send))
	fmt.Printf("# ONE shared body; each line below sends only the %s notice.\n", *notice)
	for _, s := range send {
		fmt.Printf("spore msg send-e2 -to %s -pinned-sig %s -msg-file %s\n", s.Addr, s.PinnedSig, *notice)
	}
	if len(skipped) > 0 {
		fmt.Printf("\n# skipped (%d):\n", len(skipped))
		for addr, why := range skipped {
			fmt.Printf("#   %s: %s\n", addr, why)
		}
	}

	if *commit {
		check(r.CommitIssue(r.NextSeq, send))
		fmt.Printf("\n# committed: %d entitlement(s) consumed, next issue is now #%d\n", len(send), r.NextSeq)
	} else {
		fmt.Printf("\n# nothing consumed. Re-run with -commit AFTER the sends succeed,\n")
		fmt.Printf("# so a failed send does not burn a subscriber's paid issue.\n")
	}
}

func subFollow(args []string) {
	fs := flag.NewFlagSet("sub follow", flag.ExitOnError)
	state := fs.String("state", "", "local channel state file")
	channel := fs.String("channel", "", "channel name")
	publisher := fs.String("publisher", "", "the publisher key you pinned out-of-band (hex)")
	_ = fs.Parse(args)

	if *state == "" || *channel == "" || *publisher == "" {
		check(errors.New("sub follow requires -state, -channel and -publisher"))
	}
	c, err := roster.OpenChannel(*state, *channel, *publisher)
	check(err)

	fmt.Printf("following   %s\n", c.Name)
	fmt.Printf("publisher   %s\n", c.PublisherPub)
	fmt.Printf("last issue  #%d\n", c.Seq())
	fmt.Println()
	fmt.Println("Open each issue with the pinned key and your recorded sequence:")
	fmt.Printf("  spore publish open -notice N -body B -publisher %s -last-seq %d\n", c.PublisherPub, c.Seq())
	fmt.Println("Then record it so a relay cannot replay an old issue:")
	fmt.Printf("  spore sub status -state %s -accept <N>\n", *state)
}

func subStatus(args []string) {
	fs := flag.NewFlagSet("sub status", flag.ExitOnError)
	state := fs.String("state", "", "local channel state file")
	seq := fs.Uint64("accept", 0, "record this issue number as accepted (advances the replay floor)")
	_ = fs.Parse(args)

	if *state == "" {
		check(errors.New("sub status: -state is required"))
	}
	c, err := roster.OpenChannel(*state, "", "")
	check(err)

	if *seq > 0 {
		if err := c.Accept(*seq); err != nil {
			fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("recorded issue #%d\n", *seq)
	}
	fmt.Printf("channel     %s\n", c.Name)
	fmt.Printf("publisher   %s\n", c.PublisherPub)
	fmt.Printf("last issue  #%d\n", c.Seq())
}
