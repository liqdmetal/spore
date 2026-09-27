package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/sporrelay"
)

func signedCommandJSON(t *testing.T) []byte {
	t.Helper()
	actorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	command := sporrelay.AuthorizedWorkOrderCommand{
		Actor: sporrelay.RelayActorIdentity{ActorID: "did:relay:buyer", PublicKey: base64.RawURLEncoding.EncodeToString(actorKey.Public().(ed25519.PublicKey))},
		Scope: sporrelay.RegisterObjectiveAction,
		Command: sporrelay.ObjectiveRegistrationCommand{
			Action: sporrelay.RegisterObjectiveAction, ResourceID: "objective:cli-1",
			Payload: sporrelay.WorkOrder{
				ObjectiveID: "objective:cli-1", OwnerPseudonym: "actor:buyer",
				DescriptionCommitment: "sha256:description", PolicyHash: "sha256:policy",
			},
		},
		Grant: sporrelay.RelayAuthorityGrant{
			IssuerID: "did:relay:issuer", SubjectID: "did:relay:buyer", ResourceID: "objective:cli-1",
			Scopes: []string{sporrelay.RegisterObjectiveAction}, NotBefore: "2026-01-01T00:00:00Z",
			ExpiresAt: "2027-01-01T00:00:00Z", Nonce: "nonce",
			Signature: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, ed25519.SignatureSize)),
		},
		Signature: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, ed25519.SignatureSize)),
	}
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return data
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
