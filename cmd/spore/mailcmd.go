package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/liqdmetal/spore/internal/maildb"
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
		fmt.Fprintln(os.Stderr, "usage: spore msg mail -db PATH add|list|block|unblock|threads|search [flags]")
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
				a == "-phrase" || a == "-peer" || a == "-thread") {
			expectValue = true
			continue
		}
		expectValue = false
	}
	if sub == "" {
		fmt.Fprintln(os.Stderr, "usage: spore msg mail -db PATH add|list|block|unblock|threads|search [flags]")
		return
	}
	fs := flag.NewFlagSet("msg mail "+sub, flag.ExitOnError)
	dbPath := fs.String("db", "", "path to the local mail store (maildb JSON)")
	addr := fs.String("addr", "", "chain address")
	nick := fs.String("nick", "", "contact nickname")
	pinned := fs.String("pinned", "", "out-of-band pinned signing public key hex")
	phrase := fs.String("phrase", "", "exact case-insensitive phrase to search for")
	searchPeer := fs.String("peer", "", "scope search to this sender/peer address (exact)")
	searchThread := fs.String("thread", "", "scope search to this session id hex (exact)")
	_ = fs.Parse(rest)
	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "mail: -db PATH is required")
		os.Exit(2)
	}
	db, err := maildb.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mail:", err)
		os.Exit(2)
	}
	switch sub {
	case "add":
		if *addr == "" {
			fmt.Fprintln(os.Stderr, "mail add: -addr required")
			os.Exit(2)
		}
		if err := db.UpsertContact(maildb.Contact{Address: *addr, Nickname: *nick, Pinned: *pinned}); err != nil {
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
	default:
		fmt.Fprintf(os.Stderr, "mail: unknown subcommand %q (want add|list|block|unblock|threads|search)\n", rest[0])
		os.Exit(2)
	}
}
