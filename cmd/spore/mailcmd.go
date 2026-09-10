package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/invite"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchet"
)

// msgMail groups the local mail-store commands (address book + allowlist,
// conversation/thread view, and local search over indexed decrypted
// messages). Everything is endpoint-local: the maildb JSON lives on your
// machine and never leaves it.
//
// Usage:
//
//	spore msg mail -db PATH add -addr ADDR [-nick NAME] [-pinned HEX]
//	spore msg mail -db PATH list
//	spore msg mail -db PATH block -addr ADDR
//	spore msg mail -db PATH unblock -addr ADDR
//	spore msg mail -db PATH threads
//	spore msg mail -db PATH search QUERY
func msgMail(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spore msg mail -db PATH add|list|block|unblock|threads|search|purge [flags]")
		return
	}
	// Flags may appear before OR after the subcommand. Walk the args and
	// split off the first bare (non-flag, non-flag-value) token as the
	// subcommand; keep flags and their values intact in `rest`.
	sub := ""
	rest := []string{}
	expectValue := false
	for _, a := range args {
		if sub == "" && !expectValue && !strings.HasPrefix(a, "-") {
			sub = a
			continue
		}
		rest = append(rest, a)
		// A flag that takes a value consumes the next token; the next bare
		// token after that is a candidate subcommand. Track only the flags
		// defined below that take values.
		if !expectValue && strings.HasPrefix(a, "-") && !strings.Contains(a, "=") &&
			(a == "-db" || a == "-addr" || a == "-nick" || a == "-pinned" ||
				a == "-phrase" || a == "-peer" || a == "-thread" || a == "-older-than") {
			expectValue = true
			continue
		}
		expectValue = false
	}
	if sub == "" {
		fmt.Fprintln(os.Stderr, "usage: spore msg mail -db PATH add|list|block|unblock|threads|search|purge [flags]")
		return
	}
	fs := flag.NewFlagSet("msg mail "+sub, flag.ExitOnError)
	dbPath := fs.String("db", "", "path to the local mail store (maildb JSON)")
	addr := fs.String("addr", "", "chain address")
	nick := fs.String("nick", "", "contact nickname")
	pinned := fs.String("pinned", "", "out-of-band pinned signing public key hex")
	inviteToken := fs.String("invite", "", "add a contact from a spore invite token (verifies the signature and fills -addr/-nick/-pinned)")
	phrase := fs.String("phrase", "", "exact case-insensitive phrase to search for")
	searchPeer := fs.String("peer", "", "scope search to this sender/peer address (exact)")
	searchThread := fs.String("thread", "", "scope search to this session id hex (exact)")
	olderThan := fs.Duration("older-than", 0, "purge: delete indexed messages older than this duration (e.g. 30d is not supported by Go durations — use 720h)")
	_ = fs.Parse(rest)
	if *dbPath == "" {
		// Fall back to the config's maildb path (onboarding default).
		if cfg, cerr := LoadConfig(configPath("")); cerr == nil && cfg != nil && cfg.Maildb != "" {
			*dbPath = cfg.Maildb
		}
	}
	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "mail: -db PATH is required (or set maildb in ~/.spore/config.json via `spore init`)")
		os.Exit(2)
	}
	db, err := maildb.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mail:", err)
		os.Exit(2)
	}
	switch sub {
	case "add":
		// Fields supplied by an invite, if one was given. Declared outside the
		// invite branch so the contact write below can use them in both paths.
		var (
			invPrekeyURL string
			invBundle    *ratchet.SPKBundle
		)
		// An invite fills the contact fields itself, after verifying that the
		// signature is valid and the bundle is bound to the pinned key. The
		// explicit flags remain available for out-of-band pinning without an
		// invite (the original onboarding path).
		if *inviteToken != "" {
			inv, verr := invite.DecodeAndVerify(*inviteToken, time.Now())
			if verr != nil {
				fmt.Fprintf(os.Stderr, "mail add: invite rejected: %v\n", verr)
				os.Exit(2)
			}
			if *addr != "" && *addr != inv.Address {
				fmt.Fprintf(os.Stderr, "mail add: -addr %s conflicts with the invite's address %s\n", *addr, inv.Address)
				os.Exit(2)
			}
			if *pinned != "" && *pinned != inv.PinnedSig {
				fmt.Fprintln(os.Stderr, "mail add: -pinned conflicts with the invite's pinned key")
				os.Exit(2)
			}
			*addr = inv.Address
			*pinned = inv.PinnedSig
			if *nick == "" {
				*nick = inv.Name
			}
			// Record the prekey route so `send-e2 -to <nick>` needs no
			// -bundle/-bundle-url at all. PrekeyURL is preferred at send time
			// (fresh single-use prekey); the embedded bundle is the offline
			// fallback.
			invPrekeyURL = inv.PrekeyURL
			invBundle = &inv.Bundle
			fmt.Printf("invite verified (fingerprint %s)\n", inv.Fingerprint())
			if inv.PrekeyURL != "" {
				fmt.Printf("  prekey URL  %s\n", inv.PrekeyURL)
			}
			if inv.Bundle.OPKPub != nil {
				fmt.Println("  prekey      single-use (embedded) — this invite reaches ONE sender")
			}
			if inv.Name == "" {
				fmt.Println("  note        the invite carries no name — add one with -nick if you want")
			}
		}
		if *addr == "" {
			fmt.Fprintln(os.Stderr, "mail add: -addr required (or -invite TOKEN)")
			os.Exit(2)
		}
		if err := db.UpsertContact(maildb.Contact{
			Address:   *addr,
			Nickname:  *nick,
			Pinned:    *pinned,
			PrekeyURL: invPrekeyURL,
			Bundle:    invBundle,
		}); err != nil {
			fmt.Fprintln(os.Stderr, "mail add:", err)
			os.Exit(2)
		}
		fmt.Printf("contact %s added\n", *addr)
	case "list":
		for _, c := range db.Contacts() {
			flag := " "
			if c.Blocked {
				flag = "X"
			}
			fmt.Printf("%s %-40s %s %s\n", flag, c.Address, c.Nickname, c.Pinned)
		}
	case "block":
		if *addr == "" {
			fmt.Fprintln(os.Stderr, "mail block: -addr required")
			os.Exit(2)
		}
		c, ok := db.Contact(*addr)
		if !ok {
			c = maildb.Contact{Address: *addr}
		}
		c.Blocked = true
		if err := db.UpsertContact(c); err != nil {
			fmt.Fprintln(os.Stderr, "mail block:", err)
			os.Exit(2)
		}
		fmt.Printf("contact %s blocked\n", *addr)
	case "unblock":
		if *addr == "" {
			fmt.Fprintln(os.Stderr, "mail unblock: -addr required")
			os.Exit(2)
		}
		c, ok := db.Contact(*addr)
		if !ok {
			fmt.Fprintln(os.Stderr, "mail unblock: unknown contact")
			os.Exit(2)
		}
		c.Blocked = false
		if err := db.UpsertContact(c); err != nil {
			fmt.Fprintln(os.Stderr, "mail unblock:", err)
			os.Exit(2)
		}
		fmt.Printf("contact %s unblocked\n", *addr)
	case "threads":
		for _, t := range db.Threads() {
			fmt.Printf("%s peer=%s msgs=%d last=%d\n", t.SessionID, t.Peer, t.Count, t.LastAt)
		}
	case "search":
		// Remaining args (rest) are the query tokens after the subcommand
		// and any flags. Build a SearchQuery: all bare tokens are AND terms;
		// -peer/-thread/-txid scope exactly; -phrase is the exact substring.
		q := maildb.SearchQuery{}
		for _, tok := range fs.Args() {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			q.All = append(q.All, strings.ToLower(tok))
		}
		if *phrase != "" {
			q.Phrase = *phrase
		}
		if *searchPeer != "" {
			q.Peer = *searchPeer
		}
		if *searchThread != "" {
			q.Thread = *searchThread
		}
		if len(q.All) == 0 && q.Phrase == "" && q.Peer == "" && q.Thread == "" {
			fmt.Fprintln(os.Stderr, "mail search: query required")
			os.Exit(2)
		}
		terms := q.All
		if q.Phrase != "" {
			terms = append(terms, q.Phrase)
		}
		for _, m := range db.Search(q) {
			fmt.Printf("%s %s %s: %s\n", m.TxID, m.Peer, m.SessionID, db.Highlight(m.Snippet, terms))
		}
	case "purge":
		if *olderThan <= 0 {
			fmt.Fprintln(os.Stderr, "mail purge: -older-than required (e.g. -older-than 720h)")
			os.Exit(2)
		}
		n, err := db.Purge(time.Now().Add(-*olderThan))
		if err != nil {
			fmt.Fprintln(os.Stderr, "mail purge:", err)
			os.Exit(2)
		}
		fmt.Printf("purged %d message(s) older than %s\n", n, *olderThan)
	default:
		fmt.Fprintf(os.Stderr, "mail: unknown subcommand %q (want add|list|block|unblock|threads|search|purge)\n", sub)
		os.Exit(2)
	}
}
