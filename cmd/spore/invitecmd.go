// spore invite — issue and verify signed contact introductions.
//
//	spore invite issue  -identity FILE -spk FILE -address ADDR [-name N] [options]
//	spore invite verify -invite "spore-invite-v1:..." [-expect FINGERPRINT]
//
// # WHY THIS EXISTS
//
// Onboarding a beta contact used to mean assembling five things by hand: your
// chain address, a prekey URL, a pinned signature, an identity card file, and a
// `mail add` command with the right flags. Each is easy to get wrong, and the
// failure mode is a silent delivery failure weeks later.
//
// An invite collapses that into one pasteable token. It is SIGNED by your
// identity key because a prekey bundle authenticates the BUNDLE only — the
// destination address is not covered by that signature, so an invite without
// its own signature could have its address swapped in transit and every pointer
// redirected to an attacker while the bundle still verified perfectly.
//
// # WHAT IT DOES NOT CONTAIN
//
// No private keys, no mailbox token, no store credential. Everything in an
// invite is safe to paste into a channel you do not control. The body-store
// token is deliberately absent and must be obtained separately.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/liqdmetal/spore/internal/invite"
	"github.com/liqdmetal/spore/internal/ratchet"
)

func invitecmd(args []string) {
	if len(args) == 0 {
		inviteUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "issue":
		inviteIssue(args[1:])
	case "verify":
		inviteVerify(args[1:])
	case "-h", "--help":
		inviteUsage()
	default:
		fmt.Fprintf(os.Stderr, "invite: unknown subcommand %q (want issue|verify)\n", args[0])
		os.Exit(2)
	}
}

func inviteUsage() {
	fmt.Fprint(os.Stderr, `spore invite — signed contact introductions

  issue   build and sign an invite to hand to a new contact
  verify  check an invite someone sent you, and show its fingerprint

issue flags:
  -identity FILE   your identity key (from spore init)
  -spk FILE        your signed-prekey private key (spore init writes spk.key)
  -address ADDR    YOUR chain address - find it with spore status
  -name NAME       how you want to be known (optional)
  -chain NAME      chain backend (default dero)
  -spk-id N        signed-prekey id that matches your published bundle (default 1)
  -mailbox URL     optional: a prekey URL a sender may fetch a FRESH bundle from
  -store URL       optional: the body store senders should use
  -note TEXT       optional free-text line carried in the invite
  -ttl DURATION    optional validity window (e.g. 720h); default no expiry
  -opk FILE        optional: embed a one-time prekey (SINGLE RECIPIENT ONLY)
  -opk-id N        one-time prekey id (default 1), only with -opk
  -allow-opk       required acknowledgement when embedding a one-time prekey

verify flags:
  -invite TOKEN    the invite string to check
  -expect FP       fail unless the fingerprint matches FP (recommended)

An invite is safe to paste anywhere: it carries public keys only. You still need
the operator's body-store token separately — it is never part of an invite.
`)
}

func inviteIssue(args []string) {
	fs := flag.NewFlagSet("invite issue", flag.ExitOnError)
	identity := fs.String("identity", "", "identity key file (hex, 32 bytes)")
	spk := fs.String("spk", "", "signed-prekey private key file (hex, 32 bytes)")
	address := fs.String("address", "", "YOUR chain address (see spore status)")
	name := fs.String("name", "", "how you want to be known")
	chain := fs.String("chain", "dero", "chain backend")
	spkID := fs.Uint("spk-id", 1, "signed-prekey id matching your published bundle")
	mailbox := fs.String("mailbox", "", "optional prekey URL senders may fetch a fresh bundle from")
	storeURL := fs.String("store", "", "optional body store URL")
	note := fs.String("note", "", "optional note carried in the invite")
	ttl := fs.Duration("ttl", 0, "optional validity window (0 = no expiry)")
	opkFile := fs.String("opk", "", "optional one-time prekey file — SINGLE RECIPIENT ONLY")
	opkID := fs.Uint("opk-id", 1, "one-time prekey id (only with -opk)")
	allowOPK := fs.Bool("allow-opk", false, "acknowledge that an embedded one-time prekey goes to exactly one person")
	_ = fs.Parse(args)

	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	if *identity == "" || *spk == "" {
		check(errors.New("invite issue requires -identity and -spk"))
	}
	if *address == "" {
		check(errors.New("invite issue requires -address — run `spore status` to see your chain address"))
	}
	if *opkFile != "" && !*allowOPK {
		check(errors.New("-opk embeds a one-time prekey that must reach exactly one person; " +
			"pass -allow-opk to confirm this invite goes to a single recipient"))
	}

	ik, err := readHexFile(*identity, 32)
	check(err)
	sk, err := readHexFile(*spk, 32)
	check(err)

	var opkPtr *[32]byte
	if *opkFile != "" {
		raw, err := readHexFile(*opkFile, 32)
		check(err)
		opkPtr = &[32]byte{}
		copy(opkPtr[:], raw)
	}

	bundle, err := ratchet.BuildBundle(ik, sk, uint32(*spkID), opkPtr, uint32(*opkID))
	check(err)

	inv, err := invite.New(ik, invite.Options{
		Name:      *name,
		Chain:     *chain,
		Address:   *address,
		Bundle:    *bundle,
		PrekeyURL: *mailbox,
		StoreURL:  *storeURL,
		Note:      *note,
		TTL:       *ttl,
		AllowOPK:  opkPtr != nil,
	})
	check(err)

	encoded, err := inv.Encode()
	check(err)

	fmt.Println(encoded)
	fmt.Println()
	fmt.Printf("fingerprint  %s\n", inv.Fingerprint())
	if inv.Name != "" {
		fmt.Printf("name         %s\n", inv.Name)
	}
	fmt.Printf("chain        %s\n", inv.Chain)
	fmt.Printf("address      %s\n", inv.Address)
	if inv.ExpiresAt != "" {
		fmt.Printf("expires      %s\n", inv.ExpiresAt)
	}
	if opkPtr != nil {
		fmt.Println()
		fmt.Println("WARNING: this invite embeds a ONE-TIME prekey. Send it to exactly one")
		fmt.Println("         person. Reusing it hands the same one-time key to several")
		fmt.Println("         senders, which defeats the extra X3DH DH it exists to provide.")
	}
	fmt.Println()
	fmt.Println("hand this to your contact OUT OF BAND, and read them the fingerprint so")
	fmt.Println("they can confirm it on a channel that is not carrying the invite. The")
	fmt.Println("signature stops silent edits; the fingerprint stops a full substitution.")
	fmt.Println()
	fmt.Println("they add you with:")
	fmt.Printf("  spore msg mail add -invite '<the spore-invite-v1:... line>'\n")
}

func inviteVerify(args []string) {
	fs := flag.NewFlagSet("invite verify", flag.ExitOnError)
	token := fs.String("invite", "", "the invite token to verify")
	expect := fs.String("expect", "", "expected fingerprint; verification fails on mismatch")
	_ = fs.Parse(args)

	if *token == "" {
		check(errors.New("invite verify requires -invite (paste the spore-invite-v1: line)"))
	}

	inv, err := invite.DecodeAndVerify(*token, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "invite verify: %v\n", err)
		os.Exit(1)
	}

	fp := inv.Fingerprint()
	fmt.Println("invite VERIFIED — the signature is valid and the bundle is bound to it")
	if inv.Name != "" {
		fmt.Printf("  name        %s\n", inv.Name)
	}
	fmt.Printf("  chain       %s\n", inv.Chain)
	fmt.Printf("  address     %s\n", inv.Address)
	fmt.Printf("  pinned-sig  %s\n", inv.PinnedSig)
	fmt.Printf("  fingerprint %s\n", fp)
	if inv.PrekeyURL != "" {
		fmt.Printf("  prekey-url  %s\n", inv.PrekeyURL)
	}
	if inv.StoreURL != "" {
		fmt.Printf("  store-url   %s\n", inv.StoreURL)
	}
	if inv.Note != "" {
		fmt.Printf("  note        %s\n", inv.Note)
	}
	fmt.Printf("  issued      %s\n", inv.IssuedAt)
	if inv.ExpiresAt != "" {
		fmt.Printf("  expires     %s\n", inv.ExpiresAt)
	}
	if inv.Bundle.OPKPub == nil {
		fmt.Println("  prekeys     degraded (no one-time prekey embedded)")
	} else {
		fmt.Println("  prekeys     one-time prekey embedded")
	}

	if *expect != "" {
		if fp != *expect {
			fmt.Fprintf(os.Stderr, "\nFINGERPRINT MISMATCH\n  expected %s\n  actual   %s\n"+
				"Someone may have substituted their own invite. Do NOT add this contact.\n", *expect, fp)
			os.Exit(1)
		}
		fmt.Println("\nfingerprint matches -expect")
		return
	}

	// No -expect supplied: say plainly that the remaining check is human.
	fmt.Println()
	fmt.Println("NEXT: confirm the fingerprint against the one your contact read you on a")
	fmt.Println("      channel the invite did not travel over. Then re-run with")
	fmt.Printf("      -expect %s\n", fp)
}
