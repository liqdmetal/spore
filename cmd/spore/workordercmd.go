// work-order — narrow RelayOS objective registration boundary.
//
// It prepares a local envelope or submits a caller-authorized registration. It
// does not discover providers, execute tasks, verify outcomes, or settle funds.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/liqdmetal/spore/internal/sporrelay/cli"
)

func workordercmd(args []string, stdout, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		workOrderUsage(stderr)
		if len(args) == 0 {
			return errors.New("work-order operation is required")
		}
		return nil
	}
	return cli.Run(context.Background(), args, stdout)
}

func workOrderUsage(w io.Writer) {
	for _, line := range []string{
		"usage:",
		"  spore work-order identity -actor-key FILE",
		"      print a Relay actor identity derived from a local Ed25519 key",
		"  spore work-order prepare -actor-key FILE -issuer FILE -grant FILE",
		"      -objective-id ID -owner-pseudonym ID -description-commitment HASH",
		"      -policy-hash HASH -out NEW_FILE",
		"      create and actor-sign an objectives.register command locally",
		"      (no network submission; only register sends the prepared command)",
		"  spore work-order register -command FILE [-relay-url URL]",
		"      submit an already-authorized RelayOS objectives.register command",
		"",
		"environment:",
		"  SPORE_RELAY_URL  RelayOS base URL when -relay-url is omitted",
		"  SPORE_RELAY_API_TOKEN  Optional reverse-proxy bearer token",
		"",
		"Preparation uses the caller's local actor key plus a RelayOS-issued grant",
		"and trusted issuer identity. Spore never creates or broadens authority.",
		"Trust in the supplied issuer identity must be established outside Spore;",
		"checking its signature locally does not establish issuer trust.",
		"The command file must contain RelayOS actor identity, scope, command, signed",
		"AuthorityGrant, and actor signature. RelayOS verifies signatures, grant time,",
		"revocation, resource scope, and replay. Registration is not execution,",
		"independent outcome verification, escrow, or on-chain settlement.",
		"A live registration smoke test is opt-in and leaves persistent state.",
		"See docs/RELAY_WORK_ORDER.md before enabling it.",
	} {
		fmt.Fprintln(w, line)
	}
}
