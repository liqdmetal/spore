// totpcmd — TOTP second-factor utilities for the hosted service.
//
//	spore totp secret [-user NAME]    generate a base32 secret (+ otpauth URI)
//	spore totp code -secret B32       print the current 6-digit code (test tool)
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/liqdmetal/spore/internal/totp"
)

func totpcmd(args []string) {
	if len(args) == 0 {
		totpUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "secret":
		totpSecret(args[1:])
	case "code":
		totpCode(args[1:])
	case "-h", "--help":
		totpUsage()
	default:
		fmt.Fprintf(os.Stderr, "totp: unknown subcommand %q (want secret|code)\n", args[0])
		os.Exit(2)
	}
}

func totpUsage() {
	fmt.Fprint(os.Stderr, `spore totp — time-based one-time passwords for the hosted mailbox

  secret [-user NAME]   generate a fresh base32 secret + otpauth:// URI to scan
                        into an authenticator app; the operator stores the
                        secret in the mailbox host's -totp file for that user
  code -secret B32      print the current 6-digit code (test/verify tool)
`)
}

func totpSecret(args []string) {
	fs := flag.NewFlagSet("totp secret", flag.ExitOnError)
	user := fs.String("user", "", "username this secret is for (only used in the otpauth URI label)")
	_ = fs.Parse(args)
	sec, err := totp.NewSecret()
	check(err)
	fmt.Printf("secret   %s\n", sec)
	label := "spore"
	if *user != "" {
		label = "spore:" + *user
	}
	fmt.Printf("otpauth  otpauth://totp/%s?secret=%s&issuer=spore&digits=6&period=30\n",
		url.PathEscape(label), sec)
	fmt.Println("store this in the mailbox host's -totp JSON: {\"<user>\": \"<secret>\"}")
}

func totpCode(args []string) {
	fs := flag.NewFlagSet("totp code", flag.ExitOnError)
	secret := fs.String("secret", "", "base32 TOTP secret")
	_ = fs.Parse(args)
	if *secret == "" {
		check(fmt.Errorf("totp code requires -secret"))
	}
	code, err := totp.Generate(*secret, time.Now())
	check(err)
	fmt.Println(code)
}
