package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/sporrelay"
)

func workOrderCommandFile(t *testing.T) string {
	t.Helper()
	actorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	actorPublic := actorKey.Public().(ed25519.PublicKey)
	command := sporrelay.AuthorizedWorkOrderCommand{
		Actor: sporrelay.RelayActorIdentity{ActorID: "did:relay:buyer", PublicKey: base64.RawURLEncoding.EncodeToString(actorPublic)},
		Scope: sporrelay.RegisterObjectiveAction,
		Command: sporrelay.ObjectiveRegistrationCommand{
			Action: sporrelay.RegisterObjectiveAction, ResourceID: "objective:cmd-1",
			Payload: sporrelay.WorkOrder{
				ObjectiveID: "objective:cmd-1", OwnerPseudonym: "actor:buyer",
				DescriptionCommitment: "sha256:description", PolicyHash: "sha256:policy",
			},
		},
		Grant: sporrelay.RelayAuthorityGrant{
			IssuerID: "did:relay:issuer", SubjectID: "did:relay:buyer", ResourceID: "objective:cmd-1",
			Scopes: []string{sporrelay.RegisterObjectiveAction}, NotBefore: "2026-01-01T00:00:00Z",
			ExpiresAt: "2027-01-01T00:00:00Z", Nonce: "nonce",
			Signature: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, ed25519.SignatureSize)),
		},
		Signature: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, ed25519.SignatureSize)),
	}
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authorized-command.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWorkOrderCommandUsesRealAdapterAndOnlyReportsRegistration(t *testing.T) {
	path := workOrderCommandFile(t)
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

	binary := filepath.Join(t.TempDir(), "spore")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	buildSporeCLI(t, binary)
	cmd := exec.Command(binary, "work-order", "register", "-command", path, "-relay-url", server.URL)
	cmd.Env = workOrderTestEnv(os.Environ(), map[string]string{"SPORE_RELAY_API_TOKEN": "proxy-token"})
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("real spore work-order command failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("command stderr = %q", stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "work order registered: objective:cmd-1") ||
		!strings.Contains(got, "execution: unsupported") ||
		!strings.Contains(got, "settlement: not performed") {
		t.Fatalf("command output is not accurately scoped: %q", got)
	}
	for _, forbidden := range []string{"complete", "assured", "paid"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("registration claimed %q: %q", forbidden, got)
		}
	}

	t.Run("retired settle assurance fails honestly", func(t *testing.T) {
		cmd := exec.Command(binary, "settle", "assurance", "objective:missing")
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if err == nil {
			t.Fatal("removed settle assurance command unexpectedly succeeded")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Fatalf("settle assurance exit = %v, want nonzero CLI failure", err)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "settle is retired") || strings.Contains(strings.ToLower(stdout.String()+stderr.String()), "status: complete") || strings.Contains(strings.ToLower(stdout.String()+stderr.String()), "status: success") {
			t.Fatalf("removed settle assurance reported completion: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})
}

func buildSporeCLI(t *testing.T, binary string) {
	t.Helper()
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build spore CLI: %v\n%s", err, output)
	}
}

func workOrderTestEnv(current []string, overrides map[string]string) []string {
	env := make([]string, 0, len(current)+len(overrides))
	for _, entry := range current {
		key, _, _ := strings.Cut(entry, "=")
		if _, overridden := overrides[key]; !overridden {
			env = append(env, entry)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}

func TestRunWorkOrderUnsupportedOrUnverifiedHasNoSuccessOutput(t *testing.T) {
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
			var stdout, stderr strings.Builder
			err := workordercmd([]string{tc.operation, "objective:cmd-1"}, &stdout, &stderr)
			if err != tc.want {
				t.Fatalf("workordercmd error = %v, want %v", err, tc.want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("unsupported operation printed success: %q", stdout.String())
			}
		})
	}
}

func TestRunWorkOrderMissingResultCannotReportRegistration(t *testing.T) {
	path := workOrderCommandFile(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	var stdout, stderr strings.Builder
	err := workordercmd([]string{"register", "-command", path, "-relay-url", server.URL}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "without an objective registration result") {
		t.Fatalf("missing result error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("missing result printed success: %q", stdout.String())
	}
}
