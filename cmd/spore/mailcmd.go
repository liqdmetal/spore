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
			(a == "-db" || a == "-addr" || a == "-nick" || a == "-pinned") {
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
		q := strings.Join(rest[1:], " ")
		if q == "" {
			fmt.Fprintln(os.Stderr, "mail search: query required")
			os.Exit(2)
		}
		for _, m := range db.Search(q) {
			fmt.Printf("%s %s %s: %s\n", m.TxID, m.Peer, m.SessionID, m.Snippet)
		}
	default:
		fmt.Fprintf(os.Stderr, "mail: unknown subcommand %q (want add|list|block|unblock|threads|search)\n", rest[0])
		os.Exit(2)
	}
}
