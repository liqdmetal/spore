package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/sporrelay"
)

// TestLiveRelayOSRegistrationSmoke is deliberately opt-in: it submits one real
// objectives.register command and leaves that objective in the configured
// RelayOS service. Use a fresh, one-use grant scoped to a disposable test ID.
func TestLiveRelayOSRegistrationSmoke(t *testing.T) {
	mode := strings.TrimSpace(os.Getenv("SPORE_RELAY_LIVE_SMOKE"))
	if mode == "" {
		t.Skip("live RelayOS smoke test is disabled; set SPORE_RELAY_LIVE_SMOKE=register to submit one scoped registration")
	}
	if mode != "register" {
		t.Fatalf("SPORE_RELAY_LIVE_SMOKE must be exactly register to enable this persistent remote registration test, got %q", mode)
	}

	relayURL := requiredRelaySmokeEnv(t, "SPORE_RELAY_LIVE_URL")
	if relayURL != requiredRelaySmokeEnv(t, "SPORE_RELAY_LIVE_URL_CONFIRM") {
		t.Fatal("SPORE_RELAY_LIVE_URL_CONFIRM must exactly match the reviewed SPORE_RELAY_LIVE_URL")
	}
	if strings.HasPrefix(strings.ToLower(relayURL), "http://") {
		t.Fatalf("live RelayOS smoke requires HTTPS; plain HTTP is permitted only for local adapter development")
	}
	actorKeyFile := requiredRelaySmokeEnv(t, "SPORE_RELAY_LIVE_ACTOR_KEY_FILE")
	issuerFile := requiredRelaySmokeEnv(t, "SPORE_RELAY_LIVE_ISSUER_FILE")
	trustedIssuerID := requiredRelaySmokeEnv(t, "SPORE_RELAY_LIVE_TRUSTED_ISSUER_ID")
	grantFile := requiredRelaySmokeEnv(t, "SPORE_RELAY_LIVE_GRANT_FILE")
	objectiveID := requiredRelaySmokeEnv(t, "SPORE_RELAY_LIVE_OBJECTIVE_ID")
	if confirmation := strings.TrimSpace(os.Getenv("SPORE_RELAY_LIVE_SMOKE_CONFIRM")); confirmation != objectiveID {
		t.Fatalf("SPORE_RELAY_LIVE_SMOKE_CONFIRM must exactly match SPORE_RELAY_LIVE_OBJECTIVE_ID (%q) to confirm the persistent registration", objectiveID)
	}
	const disposableObjectivePrefix = "objective:spore-live-smoke:"
	if !strings.HasPrefix(objectiveID, disposableObjectivePrefix) {
		t.Fatalf("SPORE_RELAY_LIVE_OBJECTIVE_ID must use the disposable test prefix %q", disposableObjectivePrefix)
	}
	uniqueSuffix := strings.TrimPrefix(objectiveID, disposableObjectivePrefix)
	if len(uniqueSuffix) != 32 || strings.ToLower(uniqueSuffix) != uniqueSuffix {
		t.Fatal("SPORE_RELAY_LIVE_OBJECTIVE_ID must end with a fresh 32-character lowercase hex token")
	}
	if _, err := hex.DecodeString(uniqueSuffix); err != nil {
		t.Fatalf("SPORE_RELAY_LIVE_OBJECTIVE_ID suffix is not a lowercase hex token: %v", err)
	}

	var issuer sporrelay.RelayActorIdentity
	if err := readSingleJSONFile(issuerFile, &issuer, "live RelayOS smoke trusted issuer"); err != nil {
		t.Fatal(err)
	}
	if issuer.ActorID != trustedIssuerID {
		t.Fatalf("issuer identity in %s has actor_id %q, does not match the out-of-band trusted issuer ID %q", issuerFile, issuer.ActorID, trustedIssuerID)
	}
	var grant sporrelay.RelayAuthorityGrant
	if err := readSingleJSONFile(grantFile, &grant, "live RelayOS smoke grant"); err != nil {
		t.Fatal(err)
	}
	if grant.ResourceID != objectiveID {
		t.Fatalf("live smoke grant resource %q does not match configured disposable objective ID %q", grant.ResourceID, objectiveID)
	}
	notBefore, err := time.Parse(time.RFC3339Nano, grant.NotBefore)
	if err != nil {
		t.Fatalf("parse live smoke grant not_before: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil {
		t.Fatalf("parse live smoke grant expires_at: %v", err)
	}
	if expiresAt.Sub(notBefore) > time.Hour {
		t.Fatal("live smoke grant must be short-lived (at most one hour from not_before to expires_at)")
	}

	work := sporrelay.WorkOrder{
		ObjectiveID:           objectiveID,
		OwnerPseudonym:        "actor:spore-live-smoke",
		DescriptionCommitment: liveSmokeCommitment("description", objectiveID),
		PolicyHash:            liveSmokeCommitment("policy", objectiveID),
	}
	commandFile := filepath.Join(t.TempDir(), "live-relay-registration.json")
	prepareArgs := []string{
		"prepare",
		"-actor-key", actorKeyFile,
		"-issuer", issuerFile,
		"-grant", grantFile,
		"-objective-id", work.ObjectiveID,
		"-owner-pseudonym", work.OwnerPseudonym,
		"-description-commitment", work.DescriptionCommitment,
		"-policy-hash", work.PolicyHash,
		"-out", commandFile,
	}
	var prepareOutput bytes.Buffer
	if err := Run(context.Background(), prepareArgs, &prepareOutput); err != nil {
		t.Fatalf("prepare live RelayOS registration locally: %v", err)
	}
	if !strings.Contains(prepareOutput.String(), "registration: not submitted") {
		t.Fatalf("local preparation did not confirm it made no submission: %q", prepareOutput.String())
	}
	command, err := readAuthorizedCommand(commandFile)
	if err != nil {
		t.Fatalf("read locally prepared live command: %v", err)
	}
	if command.Command.Payload != work {
		t.Fatalf("prepared command does not match the smoke payload: got %+v", command.Command.Payload)
	}

	t.Logf("submitting one objectives.register command for disposable objective %q to the configured RelayOS service", objectiveID)
	var registerOutput bytes.Buffer
	if err := Run(context.Background(), []string{"register", "-command", commandFile, "-relay-url", relayURL}, &registerOutput); err != nil {
		t.Fatalf("register against configured live RelayOS service: %v", err)
	}
	if !strings.Contains(registerOutput.String(), fmt.Sprintf("work order registered: %s", objectiveID)) ||
		!strings.Contains(registerOutput.String(), "execution: unsupported") ||
		!strings.Contains(registerOutput.String(), "settlement: not performed") {
		t.Fatalf("live registration output was missing or overclaimed status: %q", registerOutput.String())
	}
	t.Logf("RelayOS accepted registration for %q; no execution or settlement was attempted", objectiveID)
}

func requiredRelaySmokeEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("SPORE_RELAY_LIVE_SMOKE=register requires %s", name)
	}
	return value
}

func liveSmokeCommitment(kind, objectiveID string) string {
	digest := sha256.Sum256([]byte("spore-relay-live-smoke:v1:" + kind + ":" + objectiveID))
	return "sha256:" + hex.EncodeToString(digest[:])
}
