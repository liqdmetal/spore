package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/broadcast"
	"github.com/liqdmetal/spore/internal/credits"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// spore publish — sender-key newsletters: encrypt ONE body, fan out tiny notices.
//
//	spore publish issue  -identity F -channel C -seq N -file BODY [-title T] [-store URL]
//	spore publish open   -notice F -body F -publisher HEX [-last-seq N] [-out F]
//	spore publish cost   -body-bytes N -subscribers N
//
// Pairwise E2 would encrypt a 200 KB issue once PER subscriber: ~2 GB at 10k
// subscribers. Sender-key encrypts it once and gives each subscriber a ~400-byte
// notice instead — measured 476x cheaper at 10k (see `publish cost`).
//
// The trade is stated plainly: every subscriber holds the issue key, so ANY
// subscriber can encrypt a fake body under it. Authenticity therefore comes
// from the publisher's Ed25519 signature over the PLAINTEXT hash, and `open`
// refuses any issue that is not signed by the publisher key you pinned.
func publishcmd(args []string) {
	if len(args) == 0 {
		publishUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "issue":
		publishIssue(args[1:])
	case "open":
		publishOpen(args[1:])
	case "cost":
		publishCost(args[1:])
	case "-h", "--help":
		publishUsage()
	default:
		fmt.Fprintf(os.Stderr, "publish: unknown subcommand %q (want issue|open|cost)\n", args[0])
		os.Exit(2)
	}
}

func publishUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore publish issue -identity F -channel NAME -seq N -file BODY [-title T] [-out-dir D]
        (encrypt one issue under a fresh sender key; writes the shared
         ciphertext + the notice to fan out to every subscriber)
  spore publish open -notice F -body F -publisher HEX [-last-seq N] [-out F]
        (verify the publisher signature and decrypt; -publisher is REQUIRED)
  spore publish cost -body-bytes N -subscribers N
        (show sender-key vs pairwise byte cost)

Deliver the SAME notice to each subscriber over an ordinary pairwise session
(spore msg send-e2), and store the shared ciphertext ONCE. Subscribers fetch
the same body object.

Sender-key has NO forward secrecy within an issue: whoever holds an issue key
reads that issue. Keys are fresh per issue and never chained, so one leaked
key exposes exactly one issue. Publishing is intentionally NON-deniable --
a newsletter is a signed publication. Use plain E2 for deniable conversation.`)
}

func publishIssue(args []string) {
	fs := flag.NewFlagSet("publish issue", flag.ExitOnError)
	identity := fs.String("identity", "", "file containing the publisher identity private key hex")
	channel := fs.String("channel", "", "channel/publication name (stable across issues)")
	seq := fs.Uint64("seq", 0, "issue number, strictly increasing per channel (starts at 1)")
	file := fs.String("file", "", "the issue body file (any bytes)")
	title := fs.String("title", "", "optional human title (signed)")
	outDir := fs.String("out-dir", ".", "directory for the ciphertext + notice output")
	_ = fs.Parse(args)

	key, err := identitySigKey(*identity)
	check(err)
	if *channel == "" || *seq == 0 || *file == "" {
		check(errors.New("publish issue requires -channel, -seq (>=1) and -file"))
	}
	body, err := os.ReadFile(*file)
	check(err)

	ct, notice, err := broadcast.SealIssue(key, *channel, *seq, *title, body, cidOf)
	check(err)

	ctPath := fmt.Sprintf("%s/%s-%d.body", strings.TrimRight(*outDir, "/\\"), *channel, *seq)
	ntPath := fmt.Sprintf("%s/%s-%d.notice.json", strings.TrimRight(*outDir, "/\\"), *channel, *seq)
	check(os.WriteFile(ctPath, ct, 0600))
	blob, err := json.MarshalIndent(notice, "", "  ")
	check(err)
	check(os.WriteFile(ntPath, append(blob, '\n'), 0600))

	sk, pw := broadcast.FanoutCost(len(ct), len(blob), 10_000)
	fmt.Printf("channel     %s  issue #%d\n", notice.Channel, notice.Seq)
	fmt.Printf("plaintext   %d bytes (sha256 %s)\n", notice.PlainSize, notice.PlainSHA256)
	fmt.Printf("body        %s (%d bytes, encrypted ONCE)\n", ctPath, len(ct))
	fmt.Printf("notice      %s (%d bytes, sent per subscriber)\n", ntPath, len(blob))
	fmt.Printf("publisher   %s\n", notice.PublisherPub)
	fmt.Println()
	reportFanout(len(ct), len(blob), sk, pw)
	fmt.Println()
	fmt.Println("Next: store the body once, then send the notice to each subscriber:")
	fmt.Printf("  spore msg send-e2 -to <subscriber> -msg-file %s ...\n", ntPath)
	fmt.Println()
	fmt.Println("Subscribers MUST have your publisher key pinned out-of-band:")
	fmt.Printf("  spore publish open -notice N -body B -publisher %s\n", notice.PublisherPub)
}

// reportFanout tells the truth at every size. Sender-key only wins when the
// body is bigger than the notice: for a tiny issue the ~650-byte notice costs
// MORE than just sending the body pairwise, and saying otherwise would be a lie
// dressed up as a feature.
func reportFanout(bodyBytes, noticeBytes, sk, pw int) {
	if sk >= pw {
		fmt.Printf("NOTE: this issue (%d bytes) is smaller than its notice (%d bytes), so at\n", bodyBytes, noticeBytes)
		fmt.Printf("      10,000 subscribers sender-key costs MORE (%d vs %d bytes pairwise).\n", sk, pw)
		fmt.Printf("      Sender-key pays off for real newsletters; break-even is roughly a\n")
		fmt.Printf("      %d-byte body. Small notes are fine to send pairwise.\n", noticeBytes)
		return
	}
	fmt.Printf("At 10,000 subscribers: %d bytes sender-key vs %d pairwise (%.1fx cheaper)\n",
		sk, pw, float64(pw)/float64(sk))
}

func publishOpen(args []string) {
	fs := flag.NewFlagSet("publish open", flag.ExitOnError)
	noticeFile := fs.String("notice", "", "the issue notice JSON (received as a message body)")
	bodyFile := fs.String("body", "", "the shared ciphertext fetched from the store")
	publisher := fs.String("publisher", "", "REQUIRED: the publisher key you pinned out-of-band (hex)")
	lastSeq := fs.Uint64("last-seq", 0, "highest issue already accepted on this channel (rejects replays)")
	out := fs.String("out", "", "write the decrypted issue here (default: stdout)")
	_ = fs.Parse(args)

	if *noticeFile == "" || *bodyFile == "" {
		check(errors.New("publish open requires -notice and -body"))
	}
	if *publisher == "" {
		check(errors.New("publish open requires -publisher HEX: without a pinned key, ANY subscriber could have forged this issue"))
	}
	raw, err := os.ReadFile(*noticeFile)
	check(err)
	notice, ok := broadcast.ParseNotice(raw)
	if !ok {
		check(fmt.Errorf("%s is not an issue notice", *noticeFile))
	}
	ct, err := os.ReadFile(*bodyFile)
	check(err)

	plain, err := broadcast.OpenIssue(notice, ct, *publisher, *lastSeq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REJECTED: %v\n", err)
		os.Exit(1)
	}

	if *out != "" {
		check(os.WriteFile(*out, plain, 0600))
		fmt.Fprintf(os.Stderr, "channel %s issue #%d verified (%d bytes) -> %s\n", notice.Channel, notice.Seq, len(plain), *out)
		if notice.Title != "" {
			fmt.Fprintf(os.Stderr, "title   %q\n", notice.Title)
		}
		fmt.Fprintf(os.Stderr, "NOTE: record -last-seq %d so a relay cannot replay this issue.\n", notice.Seq)
		return
	}
	os.Stdout.Write(plain)
}

func publishCost(args []string) {
	fs := flag.NewFlagSet("publish cost", flag.ExitOnError)
	bodyBytes := fs.Int("body-bytes", 200_000, "issue size in bytes")
	noticeBytes := fs.Int("notice-bytes", 400, "notice size in bytes")
	subs := fs.Int("subscribers", 10_000, "subscriber count")
	_ = fs.Parse(args)

	sk, pw := broadcast.FanoutCost(*bodyBytes, *noticeBytes, *subs)
	fmt.Printf("issue        %d bytes\n", *bodyBytes)
	fmt.Printf("subscribers  %d\n", *subs)
	fmt.Printf("sender-key   %d bytes  (%.2f MB)\n", sk, float64(sk)/1e6)
	fmt.Printf("pairwise     %d bytes  (%.2f MB)\n", pw, float64(pw)/1e6)
	switch {
	case sk == 0:
	case pw > sk:
		fmt.Printf("saving       %.1fx cheaper with a sender key\n", float64(pw)/float64(sk))
	default:
		fmt.Printf("saving       NONE — the %d-byte notice outweighs a %d-byte body;\n", *noticeBytes, *bodyBytes)
		fmt.Printf("             send bodies this small pairwise instead.\n")
	}
}

// cidOf is the content address used for issue bodies. It MUST match the body
// store's addressing (ratchetwire.BodyCID) so a subscriber fetching by the
// notice's body_cid gets exactly this object.
func cidOf(b []byte) string {
	c := ratchetwire.BodyCID(b)
	return hex.EncodeToString(c[:])
}

// spore credit — prepaid ANONYMOUS credits, so paid usage needs no per-user meter.
//
//	spore credit request -denom msg [-out F]
//	spore credit issue   -identity F -request F [-out F]     (operator, after payment)
//	spore credit finalize -credit F -secret F [-out F]
//	spore credit redeem  -credit F -issuer HEX -ledger F [-denom msg]
//	spore credit revenue -ledger F
//
// Per-message billing normally means the operator COUNTS each user's messages,
// which rebuilds the activity log a private mailbox exists to destroy. A credit
// is a one-time bearer token instead: the buyer commits to a random secret, the
// operator signs the COMMITMENT at purchase, and the secret is revealed only at
// spend. The ledger records spends with no user, no IP and no exact time.
//
// HONEST LIMIT: this is a hash-commitment scheme, NOT a blind signature. The
// operator sees the commitment at purchase, so unlinkability depends on it
// discarding that commitment (policy, not mathematics). See internal/credits.
func creditcmd(args []string) {
	if len(args) == 0 {
		creditUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "request":
		creditRequest(args[1:])
	case "issue":
		creditIssue(args[1:])
	case "finalize":
		creditFinalize(args[1:])
	case "redeem":
		creditRedeem(args[1:])
	case "revenue":
		creditRevenue(args[1:])
	case "-h", "--help":
		creditUsage()
	default:
		fmt.Fprintf(os.Stderr, "credit: unknown subcommand %q (want request|issue|finalize|redeem|revenue)\n", args[0])
		os.Exit(2)
	}
}

func creditUsage() {
	fmt.Fprintln(os.Stderr, `usage (buyer):
  spore credit request -denom msg [-out req.json]      (keeps secret.hex locally)
  spore credit finalize -credit issued.json -secret secret.hex [-out credit.json]
usage (operator):
  spore credit issue -identity F -request req.json [-out issued.json]   (AFTER payment)
  spore credit redeem -credit credit.json -issuer HEX -ledger L [-denom msg]
  spore credit revenue -ledger L                       (spends per denom per day)

A credit is a BEARER token: whoever holds credit.json can spend it. Store it
like cash. The ledger records only a spend id, denom and UTC DAY -- never a
user, IP or exact timestamp, so the operator can count revenue without
building a per-user activity log.

LIMIT: the operator sees the commitment at purchase. Unlinkability relies on
it discarding that commitment; a blind signature (RSA-BSSA / Privacy Pass)
would remove that trust assumption. Buy in standard batches, ahead of use.`)
}

func creditRequest(args []string) {
	fs := flag.NewFlagSet("credit request", flag.ExitOnError)
	denom := fs.String("denom", "", `what the credit buys, e.g. "msg", "body-1mb", "permanent"`)
	out := fs.String("out", "request.json", "write the purchase request here")
	secretOut := fs.String("secret-out", "secret.hex", "write YOUR secret here (never send this to the operator)")
	_ = fs.Parse(args)

	if *denom == "" {
		check(errors.New(`credit request: -denom is required (e.g. -denom msg)`))
	}
	secret, req, err := credits.NewRequest(*denom)
	check(err)

	blob, err := json.MarshalIndent(req, "", "  ")
	check(err)
	check(os.WriteFile(*out, append(blob, '\n'), 0600))
	check(os.WriteFile(*secretOut, []byte(hex.EncodeToString(secret)+"\n"), 0600))

	fmt.Printf("denom       %s\n", *denom)
	fmt.Printf("request     %s   (send this to the operator with payment)\n", *out)
	fmt.Printf("secret      %s   (KEEP THIS — without it the credit is unspendable)\n", *secretOut)
	fmt.Println()
	fmt.Println("The request contains only a commitment. The operator cannot spend your")
	fmt.Println("credit, and cannot recognise the spend later from what it sees now.")
}

func creditIssue(args []string) {
	fs := flag.NewFlagSet("credit issue", flag.ExitOnError)
	identity := fs.String("identity", "", "operator identity private key hex file (the issuer key)")
	reqFile := fs.String("request", "", "the buyer's purchase request JSON")
	out := fs.String("out", "issued.json", "write the signed credit here")
	_ = fs.Parse(args)

	key, err := identitySigKey(*identity)
	check(err)
	if *reqFile == "" {
		check(errors.New("credit issue: -request is required"))
	}
	raw, err := os.ReadFile(*reqFile)
	check(err)
	var req credits.Request
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	check(dec.Decode(&req))

	c, err := credits.Issue(key, &req)
	check(err)
	blob, err := json.MarshalIndent(c, "", "  ")
	check(err)
	check(os.WriteFile(*out, append(blob, '\n'), 0600))

	fmt.Printf("issued      %s (denom %q)\n", *out, c.Denom)
	fmt.Printf("issuer      %s\n", c.IssuerPub)
	fmt.Println()
	fmt.Println("Return this to the buyer. To keep purchases unlinkable from spends, do")
	fmt.Println("NOT retain the commitment you just signed.")
}

func creditFinalize(args []string) {
	fs := flag.NewFlagSet("credit finalize", flag.ExitOnError)
	credFile := fs.String("credit", "", "the issued credit JSON from the operator")
	secretFile := fs.String("secret", "", "your secret hex file from `credit request`")
	out := fs.String("out", "credit.json", "write the spendable credit here")
	_ = fs.Parse(args)

	if *credFile == "" || *secretFile == "" {
		check(errors.New("credit finalize requires -credit and -secret"))
	}
	raw, err := os.ReadFile(*credFile)
	check(err)
	var c credits.Credit
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	check(dec.Decode(&c))

	sraw, err := os.ReadFile(*secretFile)
	check(err)
	secret, err := hex.DecodeString(strings.TrimSpace(string(sraw)))
	check(err)

	full, err := credits.Finalize(&c, secret)
	check(err)
	blob, err := json.MarshalIndent(full, "", "  ")
	check(err)
	check(os.WriteFile(*out, append(blob, '\n'), 0600))

	fmt.Printf("credit      %s (denom %q) — VALID and spendable\n", *out, full.Denom)
	fmt.Println("This file is a BEARER token: whoever holds it can spend it. Guard it.")
}

func creditRedeem(args []string) {
	fs := flag.NewFlagSet("credit redeem", flag.ExitOnError)
	credFile := fs.String("credit", "", "the credit being spent")
	issuer := fs.String("issuer", "", "REQUIRED: this service's issuer public key hex")
	ledger := fs.String("ledger", "", "REQUIRED: spend ledger path (prevents double spends)")
	denom := fs.String("denom", "", "require this exact denom (recommended)")
	_ = fs.Parse(args)

	if *credFile == "" || *issuer == "" || *ledger == "" {
		check(errors.New("credit redeem requires -credit, -issuer and -ledger"))
	}
	raw, err := os.ReadFile(*credFile)
	check(err)
	var c credits.Credit
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	check(dec.Decode(&c))

	l, err := credits.OpenLedger(*ledger)
	check(err)
	if err := l.Redeem(&c, *issuer, *denom, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ACCEPTED    denom %q (spends recorded: %d)\n", c.Denom, l.Count())
	fmt.Println("The ledger recorded a spend id, denom and UTC day — no user, IP or exact time.")
}

func creditRevenue(args []string) {
	fs := flag.NewFlagSet("credit revenue", flag.ExitOnError)
	ledger := fs.String("ledger", "", "spend ledger path")
	prune := fs.Duration("prune-older-than", 0, "delete spend records older than this (privacy hygiene; must exceed any credit's usable life)")
	_ = fs.Parse(args)

	if *ledger == "" {
		check(errors.New("credit revenue: -ledger is required"))
	}
	l, err := credits.OpenLedger(*ledger)
	check(err)

	if *prune > 0 {
		n := l.Prune(time.Now().Add(-*prune))
		fmt.Printf("pruned %d spend record(s) older than %s\n\n", n, *prune)
	}

	rev := l.Revenue()
	if len(rev) == 0 {
		fmt.Println("no spends recorded")
		return
	}
	fmt.Printf("total spends: %d\n\n", l.Count())
	for _, d := range l.Denoms() {
		fmt.Printf("%s:\n", d)
		days := rev[d]
		keys := make([]string, 0, len(days))
		for k := range days {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, day := range keys {
			fmt.Printf("  %s  %d\n", day, days[day])
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
