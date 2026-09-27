// Package cli owns the user-facing file/flag boundary for RelayOS work-order
// registration. Adapter semantics and wire validation live in sporrelay.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/liqdmetal/spore/internal/sporrelay"
)

// Run dispatches the narrow work-order CLI surface. Unsupported steps return
// explicit errors and never produce an accepted/completed status.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: spore work-order register -command FILE [-relay-url URL]")
	}
	switch args[0] {
	case "register":
		return register(ctx, args[1:], stdout)
	case "execute":
		return sporrelay.ErrWorkExecutionUnsupported
	case "verify", "assurance", "complete":
		return sporrelay.ErrCompletionVerificationUnavailable
	default:
		return fmt.Errorf("work-order: unknown operation %q (supported: register; execution and verification are not available)", args[0])
	}
}

func register(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("work-order register", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	commandFile := fs.String("command", "", "JSON file containing an already-signed RelayOS objectives.register command")
	relayURL := fs.String("relay-url", os.Getenv("SPORE_RELAY_URL"), "RelayOS base URL (default SPORE_RELAY_URL)")
	apiToken := os.Getenv("SPORE_RELAY_API_TOKEN") // optional reverse-proxy gate, never RelayOS command authority
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("work-order register: unexpected positional arguments")
	}
	if *commandFile == "" {
		return errors.New("work-order register requires -command FILE containing a RelayOS-authorized signed command")
	}

	command, err := readAuthorizedCommand(*commandFile)
	if err != nil {
		return err
	}
	client := sporrelay.NewClient(&sporrelay.Config{RelayerURL: strings.TrimSpace(*relayURL), APIToken: apiToken})
	registered, err := client.RegisterWorkOrder(ctx, command)
	if err != nil {
		return err
	}
	if stdout == nil {
		stdout = io.Discard
	}
	_, err = fmt.Fprintf(stdout,
		"work order registered: %s\nexecution: unsupported by the inspected RelayOS HTTP service\nsettlement: not performed\n",
		registered.ObjectiveID)
	return err
}

const maxAuthorizedCommandBytes = 1 << 20

func readAuthorizedCommand(path string) (sporrelay.AuthorizedWorkOrderCommand, error) {
	f, err := os.Open(path)
	if err != nil {
		return sporrelay.AuthorizedWorkOrderCommand{}, fmt.Errorf("work-order register: open signed command: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAuthorizedCommandBytes+1))
	if err != nil {
		return sporrelay.AuthorizedWorkOrderCommand{}, fmt.Errorf("work-order register: read signed command: %w", err)
	}
	if len(data) > maxAuthorizedCommandBytes {
		return sporrelay.AuthorizedWorkOrderCommand{}, fmt.Errorf("work-order register: command file exceeds %d-byte limit", maxAuthorizedCommandBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var command sporrelay.AuthorizedWorkOrderCommand
	if err := dec.Decode(&command); err != nil {
		return sporrelay.AuthorizedWorkOrderCommand{}, fmt.Errorf("work-order register: decode signed command: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return sporrelay.AuthorizedWorkOrderCommand{}, errors.New("work-order register: command file contains multiple JSON values")
		}
		return sporrelay.AuthorizedWorkOrderCommand{}, fmt.Errorf("work-order register: trailing JSON: %w", err)
	}
	if err := command.Validate(); err != nil {
		return sporrelay.AuthorizedWorkOrderCommand{}, err
	}
	return command, nil
}
