// work-order — narrow RelayOS objective registration boundary.
//
// This command registers a caller-authorized work-order commitment only. It
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
		"  spore work-order register -command FILE [-relay-url URL]",
		"      submit an already-authorized RelayOS objectives.register command",
		"",
		"environment:",
		"  SPORE_RELAY_URL  RelayOS base URL when -relay-url is omitted",
		"  SPORE_RELAY_API_TOKEN  Optional reverse-proxy bearer token",
		"",
		"The command file must contain RelayOS actor identity, scope, command, signed",
		"AuthorityGrant, and actor signature. RelayOS verifies signatures, grant time,",
		"revocation, resource scope, and replay. Registration is not execution,",
		"independent outcome verification, escrow, or on-chain settlement.",
	} {
		fmt.Fprintln(w, line)
	}
}
