package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/attest"
	"github.com/liqdmetal/spore/internal/secure"
)

// spore sign — detached, third-party-verifiable document signatures.
//
//	spore sign doc      -identity FILE -file DOC -statement "I agree" [-out F]
//	spore sign verify   -file DOC -sig FILE [-pinned-sig HEX]
//	spore sign sheet    -file DOC -sigs F1,F2,... [-required HEX,HEX,...]
//	spore sign anchor   -sig FILE
//
// WHY THIS IS NOT THE MESSAGE PATH: spore messages authenticate with a
// SYMMETRIC ratchet key, which is deliberately DENIABLE — the recipient cannot
// prove to a third party that you sent it, because they could have forged it
// themselves. That is right for chat and useless for a contract. `spore sign`
// is the explicit, opt-in, NON-deniable artifact: a detached Ed25519 signature
// anyone can verify with your public key.
func signcmd(args []string) {
	if len(args) == 0 {
		signUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "doc":
		signDoc(args[1:])
	case "verify":
		signVerify(args[1:])
	case "sheet":
		signSheet(args[1:])
	case "anchor":
		signAnchor(args[1:])
	case "-h", "--help":
		signUsage()
	default:
		fmt.Fprintf(os.Stderr, "sign: unknown subcommand %q (want doc|verify|sheet|anchor)\n", args[0])
		os.Exit(2)
	}
}

func signUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore sign doc -identity FILE -file DOC -statement "I agree to these terms" [-out SIG]
        (produce a detached, third-party-verifiable signature over DOC)
  spore sign verify -file DOC -sig SIG [-pinned-sig HEX]
        (verify a signature; -pinned-sig REQUIRES it to be that exact signer)
  spore sign sheet -file DOC -sigs A.sig,B.sig [-required HEX,HEX]
        (multi-party contract: verify all, report who has not signed)
  spore sign anchor -sig SIG
        (print the 32-byte digest to publish on-chain for a real timestamp)

The signing key is the SAME Ed25519 key whose public half you already share
out-of-band as -pinned-sig. Your contact pins you once; that same anchor
verifies every document you ever sign. No CA, no notary, no account.

NOTE: signed_at inside a signature is SELF-CLAIMED. For a timestamp a third
party can trust, publish 'sign anchor' on a chain and cite the block.`)
}

// identitySigKey loads the identity private key and derives the same Ed25519
// signing key used for -pinned-sig, so a user has exactly one identity.
func identitySigKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("sign: -identity is required (the file holding your identity private key hex)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h := strings.TrimSpace(string(raw))
	priv, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("sign: -identity must contain hex: %w", err)
	}
	k, err := secure.SigKeypairOf(priv)
	if err != nil {
		return nil, fmt.Errorf("sign: derive signing key: %w", err)
	}
	return k, nil
}

func hashFileOrDie(path string) ([]byte, int64) {
	if path == "" {
		check(errors.New("sign: -file is required"))
	}
	f, err := os.Open(path)
	check(err)
	defer f.Close()
	sum, n, err := attest.HashDocument(f)
	check(err)
	return sum, n
}

func signDoc(args []string) {
	fs := flag.NewFlagSet("sign doc", flag.ExitOnError)
	identity := fs.String("identity", "", "file containing your identity private key hex")
	file := fs.String("file", "", "the document to sign (any bytes: PDF, tarball, image)")
	statement := fs.String("statement", "", `what you are asserting, e.g. "I agree to these terms" (required: a signature with no stated meaning is ambiguous later)`)
	out := fs.String("out", "", "write the signature JSON here (default: DOC.sig)")
	_ = fs.Parse(args)

	if *statement == "" {
		check(errors.New(`sign doc: -statement is required (e.g. -statement "I agree to these terms")`))
	}
	key, err := identitySigKey(*identity)
	check(err)
	sum, n := hashFileOrDie(*file)

	env, err := attest.Sign(key, sum, n, *statement, time.Now())
	check(err)

	dest := *out
	if dest == "" {
		dest = *file + ".sig"
	}
	blob, err := json.MarshalIndent(env, "", "  ")
	check(err)
	check(os.WriteFile(dest, append(blob, '\n'), 0600))

	fmt.Printf("signed      %s (%d bytes)\n", *file, n)
	fmt.Printf("sha256      %s\n", env.DocSHA256)
	fmt.Printf("statement   %q\n", env.Statement)
	fmt.Printf("signer      %s\n", env.SignerPub)
	fmt.Printf("signature   %s\n", dest)
	fmt.Println()
	fmt.Println("Send the document and this .sig to the other party. They verify with:")
	fmt.Printf("  spore sign verify -file %s -sig %s -pinned-sig %s\n", *file, dest, env.SignerPub)
}

func loadEnvelope(path string) *attest.Envelope {
	raw, err := os.ReadFile(path)
	check(err)
	var env attest.Envelope
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		check(fmt.Errorf("sign: %s is not a valid signature envelope: %w", path, err))
	}
	return &env
}

func signVerify(args []string) {
	fs := flag.NewFlagSet("sign verify", flag.ExitOnError)
	file := fs.String("file", "", "the document the signature covers")
	sig := fs.String("sig", "", "the signature JSON file")
	pinned := fs.String("pinned-sig", "", "REQUIRE this exact signer key (hex). Without it, verification only proves 'somebody signed this', not WHO")
	_ = fs.Parse(args)

	if *sig == "" {
		check(errors.New("sign verify: -sig is required"))
	}
	sum, n := hashFileOrDie(*file)
	env := loadEnvelope(*sig)

	var err error
	if *pinned != "" {
		err = env.VerifyPinned(sum, *pinned)
	} else {
		err = env.Verify(sum)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("VALID\n")
	fmt.Printf("document    %s (%d bytes)\n", *file, n)
	fmt.Printf("sha256      %s\n", env.DocSHA256)
	fmt.Printf("statement   %q\n", env.Statement)
	fmt.Printf("signer      %s\n", env.SignerPub)
	fmt.Printf("claimed at  %s\n", env.SignedAt)
	if *pinned == "" {
		fmt.Println()
		fmt.Println("WARNING: no -pinned-sig given. This proves the document was signed by")
		fmt.Println("the key above, but NOT that the key belongs to your counterparty.")
		fmt.Println("Re-run with -pinned-sig <their pinned key> to bind it to an identity.")
	}
	fmt.Println()
	fmt.Println("NOTE: 'claimed at' is asserted by the signer. For a third-party-trustworthy")
	fmt.Println("timestamp, have them publish `spore sign anchor` output on-chain.")
}

func signSheet(args []string) {
	fs := flag.NewFlagSet("sign sheet", flag.ExitOnError)
	file := fs.String("file", "", "the document all signatures cover")
	sigs := fs.String("sigs", "", "comma-separated signature JSON files")
	required := fs.String("required", "", "comma-separated signer keys (hex) that MUST have signed for the sheet to be complete")
	_ = fs.Parse(args)

	if *sigs == "" {
		check(errors.New("sign sheet: -sigs is required (comma-separated .sig files)"))
	}
	sum, n := hashFileOrDie(*file)

	sheet := &attest.Sheet{}
	for _, p := range strings.Split(*sigs, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := sheet.Add(loadEnvelope(p)); err != nil {
			check(err)
		}
	}
	var req []string
	if *required != "" {
		for _, r := range strings.Split(*required, ",") {
			if r = strings.TrimSpace(r); r != "" {
				req = append(req, r)
			}
		}
	}

	missing, err := sheet.VerifyAll(sum, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SHEET INVALID: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("document    %s (%d bytes)\n", *file, n)
	fmt.Printf("sha256      %s\n", sheet.DocSHA256)
	fmt.Printf("signatures  %d valid\n", len(sheet.Sigs))
	for _, e := range sheet.Sigs {
		fmt.Printf("  OK  %s  %q  (%s)\n", e.SignerPub, e.Statement, e.SignedAt)
	}
	if len(req) > 0 {
		if len(missing) == 0 {
			fmt.Println("\nFULLY EXECUTED: every required signer has signed.")
		} else {
			fmt.Printf("\nINCOMPLETE: %d required signer(s) missing:\n", len(missing))
			for _, m := range missing {
				fmt.Printf("  MISSING  %s\n", m)
			}
			os.Exit(1)
		}
	}
}

func signAnchor(args []string) {
	fs := flag.NewFlagSet("sign anchor", flag.ExitOnError)
	sig := fs.String("sig", "", "the signature JSON file to anchor")
	_ = fs.Parse(args)

	if *sig == "" {
		check(errors.New("sign anchor: -sig is required"))
	}
	env := loadEnvelope(*sig)
	d, err := env.AnchorDigest()
	check(err)

	fmt.Printf("anchor digest  %s\n", hex.EncodeToString(d[:]))
	fmt.Println()
	fmt.Println("Publish this 32-byte digest on a chain to prove the signature existed")
	fmt.Println("no later than that block. The chain sees ONLY this digest — never the")
	fmt.Println("document, the signature, or who signed it.")
	fmt.Println()
	fmt.Println("Anyone can recompute it from the .sig file and check the block, which")
	fmt.Println("upgrades the self-claimed signed_at into a verifiable upper bound.")
}
