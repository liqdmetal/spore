// Package cli owns the user-facing file/flag boundary for preparing and
// submitting RelayOS work-order registrations. Adapter semantics and wire
// validation live in sporrelay.
package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/sporrelay"
)

// Run dispatches the narrow work-order CLI surface. Unsupported steps return
// explicit errors and never produce an accepted/completed status.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return errors.New("usage: spore work-order identity|prepare|register; see `spore work-order --help` for details")
	}
	if len(args) == 0 {
		return errors.New("usage: spore work-order register -command FILE [-relay-url URL]")
	}
	switch args[0] {
	case "prepare":
		return prepare(args[1:], stdout)
	case "identity":
		return identifyRelayActor(args[1:], stdout)
	case "register":
		return register(ctx, args[1:], stdout)
	case "execute":
		return sporrelay.ErrWorkExecutionUnsupported
	case "verify", "assurance", "complete":
		return sporrelay.ErrCompletionVerificationUnavailable
	default:
		return fmt.Errorf("work-order: unknown operation %q (supported: identity|prepare|register; execution and verification are not available)", args[0])
	}
}

func identifyRelayActor(args []string, stdout io.Writer) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return errors.New("usage: spore work-order identity -actor-key FILE")
	}
	fs := flag.NewFlagSet("work-order identity", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	actorKeyFile := fs.String("actor-key", "", "file containing the local Relay actor's Ed25519 private key as hex")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*actorKeyFile) == "" {
		return errors.New("work-order identity requires -actor-key FILE and no positional arguments")
	}
	privateKey, err := readRelayActorPrivateKey(*actorKeyFile)
	if err != nil {
		return err
	}
	defer crypto.Zero(privateKey)
	publicKey := ed25519.PublicKey(privateKey[ed25519.SeedSize:])
	identity := sporrelay.RelayActorIdentity{
		ActorID:   sporrelay.RelayActorID(publicKey),
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	}
	if stdout == nil {
		stdout = io.Discard
	}
	return json.NewEncoder(stdout).Encode(identity)
}

func prepare(args []string, stdout io.Writer) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return errors.New("usage: spore work-order prepare -actor-key FILE -issuer FILE -grant FILE -objective-id ID -owner-pseudonym ID -description-commitment HASH -policy-hash HASH -out NEW_FILE")
	}
	fs := flag.NewFlagSet("work-order prepare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	actorKeyFile := fs.String("actor-key", "", "file containing the local Relay actor's Ed25519 private key as hex (32-byte seed or 64-byte private key)")
	issuerFile := fs.String("issuer", "", "trusted RelayOS issuer identity JSON file (actor_id and public_key)")
	grantFile := fs.String("grant", "", "RelayOS-issued signed AuthorityGrant JSON file")
	objectiveID := fs.String("objective-id", "", "objective ID named by the RelayOS grant resource")
	ownerPseudonym := fs.String("owner-pseudonym", "", "work-order owner pseudonym")
	descriptionCommitment := fs.String("description-commitment", "", "commitment to the private work description")
	policyHash := fs.String("policy-hash", "", "commitment to the acceptance policy")
	outputFile := fs.String("out", "", "new output file for the actor-signed command (must not already exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("work-order prepare: unexpected positional arguments")
	}
	for name, value := range map[string]string{
		"-actor-key": *actorKeyFile, "-issuer": *issuerFile, "-grant": *grantFile,
		"-objective-id": *objectiveID, "-owner-pseudonym": *ownerPseudonym,
		"-description-commitment": *descriptionCommitment, "-policy-hash": *policyHash,
		"-out": *outputFile,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("work-order prepare requires %s", name)
		}
	}
	if *outputFile == "-" {
		return errors.New("work-order prepare: -out must be a new file path; stdout output is disabled")
	}

	actorKey, err := readRelayActorPrivateKey(*actorKeyFile)
	if err != nil {
		return err
	}
	defer crypto.Zero(actorKey)

	var issuer sporrelay.RelayActorIdentity
	if err := readSingleJSONFile(*issuerFile, &issuer, "work-order prepare: trusted issuer"); err != nil {
		return err
	}
	var grant sporrelay.RelayAuthorityGrant
	if err := readSingleJSONFile(*grantFile, &grant, "work-order prepare: RelayOS grant"); err != nil {
		return err
	}
	work := sporrelay.WorkOrder{
		ObjectiveID:           *objectiveID,
		OwnerPseudonym:        *ownerPseudonym,
		DescriptionCommitment: *descriptionCommitment,
		PolicyHash:            *policyHash,
	}
	command, err := sporrelay.PrepareAuthorizedWorkOrder(actorKey, issuer, grant, work)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(command, "", "  ")
	if err != nil {
		return fmt.Errorf("work-order prepare: encode command: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writeNewPrivateFile(*outputFile, encoded); err != nil {
		crypto.Zero(encoded)
		return err
	}
	if stdout == nil {
		stdout = io.Discard
	}
	defer crypto.Zero(encoded)
	_, err = fmt.Fprintf(stdout,
		"prepared actor-signed RelayOS registration command: %s\ncommand file: %s\nRelayOS grant: supplied and locally signature-checked (revocation/replay still checked by RelayOS)\nregistration: not submitted\nexecution: unsupported; settlement: not performed\n",
		command.Command.ResourceID, filepath.Clean(*outputFile))
	return err
}

func readRelayActorPrivateKey(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("work-order: open local Relay actor key: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("work-order: inspect local Relay actor key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("work-order: Relay actor key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("work-order: Relay actor key file must not be accessible by group or others (chmod 600)")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, fmt.Errorf("work-order: read local Relay actor key: %w", err)
	}
	defer crypto.Zero(data)
	if len(data) > 4096 {
		return nil, errors.New("work-order: Relay actor key file is too large")
	}
	text := bytes.TrimSpace(data)
	if len(text)%2 != 0 {
		return nil, errors.New("work-order: Relay actor private key must be even-length hex")
	}
	decoded := make([]byte, hex.DecodedLen(len(text)))
	if _, err := hex.Decode(decoded, text); err != nil {
		crypto.Zero(decoded)
		return nil, fmt.Errorf("work-order: decode Relay actor private key: %w", err)
	}
	defer crypto.Zero(decoded)
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		key := append(ed25519.PrivateKey(nil), decoded...)
		derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		valid := bytes.Equal(derived, key)
		crypto.Zero(derived)
		if !valid {
			crypto.Zero(key)
			return nil, errors.New("work-order: Ed25519 private key public half does not match its seed")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("work-order: Relay actor key must decode to %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

const maxPrepareJSONBytes = 1 << 20

func readSingleJSONFile(path string, out any, label string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s: open file: %w", label, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPrepareJSONBytes+1))
	if err != nil {
		return fmt.Errorf("%s: read file: %w", label, err)
	}
	if len(data) > maxPrepareJSONBytes {
		return fmt.Errorf("%s: JSON file exceeds %d-byte limit", label, maxPrepareJSONBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%s: decode JSON: %w", label, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: file contains multiple JSON values", label)
		}
		return fmt.Errorf("%s: trailing JSON: %w", label, err)
	}
	return nil
}

func writeNewPrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("work-order prepare: create new command file: %w", err)
	}
	writeOK := false
	defer func() {
		if !writeOK {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("work-order prepare: write command file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("work-order prepare: sync command file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("work-order prepare: close command file: %w", err)
	}
	writeOK = true
	return nil
}

func register(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return errors.New("usage: spore work-order register -command FILE [-relay-url URL]")
	}
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

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

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
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return sporrelay.AuthorizedWorkOrderCommand{}, fmt.Errorf("work-order register: %w", err)
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
