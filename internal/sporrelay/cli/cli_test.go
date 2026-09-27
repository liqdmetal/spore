package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/sporrelay"
)

func signedCommandJSON(t *testing.T) []byte {
	t.Helper()
	actorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	issuerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	actorPublic := actorKey.Public().(ed25519.PublicKey)
	actorID, issuerID := testRelayActorID(actorPublic), testRelayActorID(issuerKey.Public().(ed25519.PublicKey))
	command := sporrelay.AuthorizedWorkOrderCommand{
		Actor: sporrelay.RelayActorIdentity{ActorID: actorID, PublicKey: base64.RawURLEncoding.EncodeToString(actorPublic)},
		Scope: sporrelay.RegisterObjectiveAction,
		Command: sporrelay.ObjectiveRegistrationCommand{
			Action: sporrelay.RegisterObjectiveAction, ResourceID: "objective:cli-1",
			Payload: sporrelay.WorkOrder{
				ObjectiveID: "objective:cli-1", OwnerPseudonym: "actor:buyer",
				DescriptionCommitment: "sha256:description", PolicyHash: "sha256:policy",
			},
		},
		Grant: sporrelay.RelayAuthorityGrant{
			IssuerID: issuerID, SubjectID: actorID, ResourceID: "objective:cli-1",
			Scopes: []string{sporrelay.RegisterObjectiveAction}, NotBefore: "2026-01-01T00:00:00Z",
			ExpiresAt: "2027-01-01T00:00:00Z", Nonce: "nonce",
		},
	}
	command.Grant.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerKey, relayCanonicalFields(unsignedGrantFields(command.Grant))))
	grantHash := sha256.Sum256(relayCanonicalFields(command.Grant))
	actorPayload := map[string]any{
		"actor_id": actorID, "scope": command.Scope, "command_type": "IngressCommand",
		"command": map[string]any{
			"action": command.Command.Action, "resource_id": command.Command.ResourceID,
			"payload": map[string]any{
				"objective_id":           command.Command.Payload.ObjectiveID,
				"owner_pseudonym":        command.Command.Payload.OwnerPseudonym,
				"description_commitment": command.Command.Payload.DescriptionCommitment,
				"policy_hash":            command.Command.Payload.PolicyHash,
			},
		},
		"grant_hash": fmt.Sprintf("%x", grantHash[:]),
	}
	command.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(actorKey, relayCanonicalFields(actorPayload)))
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testRelayActorID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return "did:relay:" + hex.EncodeToString(digest[:])[:40]
}

func relayCanonicalFields(value any) []byte {
	data, _ := json.Marshal(value)
	var normalized any
	_ = json.Unmarshal(data, &normalized)
	canonical, _ := json.Marshal(normalized)
	return canonical
}

func unsignedGrantFields(grant sporrelay.RelayAuthorityGrant) map[string]any {
	data, _ := json.Marshal(grant)
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	delete(fields, "signature")
	return fields
}

func writeCommand(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authorized-command.json")
	if err := os.WriteFile(path, signedCommandJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRegisterCLIUsesActualAdapterAndReportsOnlyRegistration(t *testing.T) {
	path := writeCommand(t)
	t.Setenv("SPORE_RELAY_API_TOKEN", "proxy-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/commands" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer proxy-token" {
			t.Errorf("proxy Authorization = %q", got)
		}
		var command sporrelay.AuthorizedWorkOrderCommand
		if err := json.NewDecoder(r.Body).Decode(&command); err != nil {
			t.Errorf("decode command: %v", err)
		}
		result, _ := json.Marshal(command.Command.Payload)
		_, _ = w.Write([]byte(`{"ok":true,"result":` + string(result) + `}`))
	}))
	defer server.Close()

	var stdout strings.Builder
	err := Run(context.Background(), []string{"register", "-command", path, "-relay-url", server.URL}, &stdout)
	if err != nil {
		t.Fatalf("Run(register): %v", err)
	}
	got := stdout.String()
	if !strings.Contains(got, "work order registered: objective:cli-1") {
		t.Fatalf("missing registration confirmation: %q", got)
	}
	if !strings.Contains(got, "execution: unsupported") || !strings.Contains(got, "settlement: not performed") {
		t.Fatalf("CLI implied execution or settlement: %q", got)
	}
	if strings.Contains(got, "complete") || strings.Contains(got, "assured") || strings.Contains(got, "paid") {
		t.Fatalf("registration output falsely claimed completion: %q", got)
	}
}

func TestUnsupportedOrUnverifiedOperationsCannotReportSuccess(t *testing.T) {
	tests := []struct {
		operation string
		want      error
	}{
		{"execute", sporrelay.ErrWorkExecutionUnsupported},
		{"verify", sporrelay.ErrCompletionVerificationUnavailable},
		{"assurance", sporrelay.ErrCompletionVerificationUnavailable},
		{"complete", sporrelay.ErrCompletionVerificationUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.operation, func(t *testing.T) {
			var stdout strings.Builder
			err := Run(context.Background(), []string{tc.operation, "objective:cli-1"}, &stdout)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Run(%s) error = %v, want %v", tc.operation, err, tc.want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("unsupported operation wrote success output: %q", stdout.String())
			}
		})
	}
}

func TestRegisterCLIRejectsMissingOrMalformedCommand(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	for _, args := range [][]string{
		{"register", "-relay-url", server.URL},
	} {
		if err := Run(context.Background(), args, io.Discard); err == nil {
			t.Error("register with no command file should fail")
		}
	}

	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"scope":"settlements.release"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), []string{"register", "-command", path, "-relay-url", server.URL}, io.Discard); err == nil {
		t.Error("register with malformed/unauthorized command should fail")
	}
}

func TestRegisterCLIRejectsUnverifiableSignedEnvelopeWithoutSuccessOutput(t *testing.T) {
	path := writeCommand(t)
	var command sporrelay.AuthorizedWorkOrderCommand
	if err := json.Unmarshal(signedCommandJSON(t), &command); err != nil {
		t.Fatal(err)
	}
	command.Signature = "tampered-signature"
	tampered, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout strings.Builder
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	if err := Run(context.Background(), []string{"register", "-command", path, "-relay-url", server.URL}, &stdout); err == nil {
		t.Fatal("malformed RelayOS signature was accepted")
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid signature printed registration success: %q", stdout.String())
	}
}

func TestRegisterCLIFailsOnMissingOrFalseRegistrationResponse(t *testing.T) {
	path := writeCommand(t)
	for _, body := range []string{`{"ok":true}`, `{"ok":false,"error":"expired grant"}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		var stdout strings.Builder
		err := Run(context.Background(), []string{"register", "-command", path, "-relay-url", server.URL}, &stdout)
		server.Close()
		if err == nil {
			t.Fatalf("response %s unexpectedly produced success", body)
		}
		if stdout.Len() != 0 {
			t.Fatalf("failed registration printed success: %q", stdout.String())
		}
	}
}

func prepareInputs(t *testing.T) (keyPath, issuerPath, grantPath string, actorKey, issuerKey ed25519.PrivateKey, work sporrelay.WorkOrder) {
	t.Helper()
	dir := t.TempDir()
	actorKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	issuerKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, ed25519.SeedSize))
	keyPath, issuerPath, grantPath = filepath.Join(dir, "actor.key"), filepath.Join(dir, "issuer.json"), filepath.Join(dir, "grant.json")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(actorKey[:ed25519.SeedSize])), 0o600); err != nil {
		t.Fatal(err)
	}
	issuerPublic := issuerKey.Public().(ed25519.PublicKey)
	issuer := sporrelay.RelayActorIdentity{ActorID: testRelayActorID(issuerPublic), PublicKey: base64.RawURLEncoding.EncodeToString(issuerPublic)}
	issuerJSON, err := json.Marshal(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(issuerPath, issuerJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	work = sporrelay.WorkOrder{
		ObjectiveID: "objective:prepared-1", OwnerPseudonym: "actor:prepared-buyer",
		DescriptionCommitment: "sha256:private-description", PolicyHash: "sha256:acceptance-policy",
	}
	grant := sporrelay.RelayAuthorityGrant{
		IssuerID: issuer.ActorID, SubjectID: testRelayActorID(actorKey.Public().(ed25519.PublicKey)),
		ResourceID: work.ObjectiveID, Scopes: []string{sporrelay.RegisterObjectiveAction},
		NotBefore: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), Nonce: "relay-issued-one-use-nonce",
	}
	grant.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerKey, relayCanonicalFields(unsignedGrantFields(grant))))
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grantPath, grantJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath, issuerPath, grantPath, actorKey, issuerKey, work
}

func prepareArgs(keyPath, issuerPath, grantPath, out string, work sporrelay.WorkOrder) []string {
	return []string{
		"prepare", "-actor-key", keyPath, "-issuer", issuerPath, "-grant", grantPath,
		"-objective-id", work.ObjectiveID, "-owner-pseudonym", work.OwnerPseudonym,
		"-description-commitment", work.DescriptionCommitment, "-policy-hash", work.PolicyHash,
		"-out", out,
	}
}

func assertPreparedCommandSignatures(t *testing.T, command sporrelay.AuthorizedWorkOrderCommand, actorKey, issuerKey ed25519.PrivateKey) {
	t.Helper()
	grantSignature, err := base64.RawURLEncoding.DecodeString(command.Grant.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(issuerKey.Public().(ed25519.PublicKey), relayCanonicalFields(unsignedGrantFields(command.Grant)), grantSignature) {
		t.Fatal("prepared command changed or replaced the RelayOS issuer grant")
	}
	grantHash := sha256.Sum256(relayCanonicalFields(command.Grant))
	commandJSON, err := json.Marshal(command.Command)
	if err != nil {
		t.Fatal(err)
	}
	var commandFields map[string]any
	if err := json.Unmarshal(commandJSON, &commandFields); err != nil {
		t.Fatal(err)
	}
	actorPayload := map[string]any{
		"actor_id": command.Actor.ActorID, "scope": command.Scope,
		"command_type": "IngressCommand", "command": commandFields,
		"grant_hash": hex.EncodeToString(grantHash[:]),
	}
	actorSignature, err := base64.RawURLEncoding.DecodeString(command.Signature)
	if err != nil || !ed25519.Verify(actorKey.Public().(ed25519.PublicKey), relayCanonicalFields(actorPayload), actorSignature) {
		t.Fatalf("prepared Relay actor signature failed verification: %v", err)
	}
}

func TestPrepareCLIUsesOnlyLocalActorKeyAndRelayOSIssuedGrant(t *testing.T) {
	keyPath, issuerPath, grantPath, actorKey, issuerKey, work := prepareInputs(t)
	out := filepath.Join(t.TempDir(), "authorized-registration.json")
	var stdout strings.Builder
	if err := Run(context.Background(), prepareArgs(keyPath, issuerPath, grantPath, out, work), &stdout); err != nil {
		t.Fatalf("Run(prepare): %v", err)
	}
	var command sporrelay.AuthorizedWorkOrderCommand
	if err := readSingleJSONFile(out, &command, "test prepared command"); err != nil {
		t.Fatal(err)
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("prepared command shape: %v", err)
	}
	if command.Command.Payload != work {
		t.Fatalf("prepared command changed the work-order terms: %+v", command.Command.Payload)
	}
	assertPreparedCommandSignatures(t, command, actorKey, issuerKey)
	if !strings.Contains(stdout.String(), "registration: not submitted") || strings.Contains(stdout.String(), "private-key") {
		t.Fatalf("preparation output overstates authority or leaks key material: %q", stdout.String())
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("prepared command mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestPrepareCLIRejectsBadGrantWithoutCreatingOutput(t *testing.T) {
	keyPath, issuerPath, grantPath, _, _, work := prepareInputs(t)
	var grant sporrelay.RelayAuthorityGrant
	if err := readSingleJSONFile(grantPath, &grant, "test grant"); err != nil {
		t.Fatal(err)
	}
	grant.Signature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, ed25519.SignatureSize))
	bad, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grantPath, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "must-not-exist.json")
	var stdout strings.Builder
	if err := Run(context.Background(), prepareArgs(keyPath, issuerPath, grantPath, out, work), &stdout); err == nil {
		t.Fatal("preparation accepted a grant not signed by the pinned issuer key")
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid grant preparation wrote success output: %q", stdout.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("invalid grant created output file: stat err = %v", err)
	}
}

func TestPrepareCLIRefusesOverwriteAndUnsafeActorKeyPermissions(t *testing.T) {
	keyPath, issuerPath, grantPath, _, _, work := prepareInputs(t)
	out := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(out, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), prepareArgs(keyPath, issuerPath, grantPath, out, work), io.Discard); err == nil {
		t.Fatal("prepare unexpectedly overwrote an existing file")
	}
	contents, err := os.ReadFile(out)
	if err != nil || string(contents) != "keep me" {
		t.Fatalf("existing output changed: contents=%q err=%v", contents, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := Run(context.Background(), prepareArgs(keyPath, issuerPath, grantPath, filepath.Join(t.TempDir(), "unsafe.json"), work), io.Discard); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("permissive actor-key file error = %v, want chmod guidance", err)
		}
	}
}

func TestWorkOrderIdentityPrintsOnlyDerivedPublicIdentity(t *testing.T) {
	keyPath, _, _, actorKey, _, _ := prepareInputs(t)
	var stdout strings.Builder
	if err := Run(context.Background(), []string{"identity", "-actor-key", keyPath}, &stdout); err != nil {
		t.Fatalf("Run(identity): %v", err)
	}
	var identity sporrelay.RelayActorIdentity
	if err := json.Unmarshal([]byte(stdout.String()), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.ActorID != testRelayActorID(actorKey.Public().(ed25519.PublicKey)) || identity.PublicKey != base64.RawURLEncoding.EncodeToString(actorKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("identity output does not match local actor key: %+v", identity)
	}
}

func TestPrepareCLIRejectsDuplicateJSONFields(t *testing.T) {
	keyPath, issuerPath, grantPath, _, _, work := prepareInputs(t)
	grantRaw, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	grantRaw = bytes.Replace(grantRaw, []byte(`"nonce":"relay-issued-one-use-nonce"`), []byte(`"nonce":"relay-issued-one-use-nonce","nonce":"shadowed"`), 1)
	if err := os.WriteFile(grantPath, grantRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), prepareArgs(keyPath, issuerPath, grantPath, filepath.Join(t.TempDir(), "duplicate.json"), work), io.Discard); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
		t.Fatalf("duplicate-key grant error = %v", err)
	}
}
