package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/sporrelay"
)

func workOrderCommandFile(t *testing.T) string {
	t.Helper()
	actorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	issuerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	actorPublic := actorKey.Public().(ed25519.PublicKey)
	actorID := workOrderTestActorID(actorPublic)
	command := sporrelay.AuthorizedWorkOrderCommand{
		Actor: sporrelay.RelayActorIdentity{ActorID: actorID, PublicKey: base64.RawURLEncoding.EncodeToString(actorPublic)},
		Scope: sporrelay.RegisterObjectiveAction,
		Command: sporrelay.ObjectiveRegistrationCommand{
			Action: sporrelay.RegisterObjectiveAction, ResourceID: "objective:cmd-1",
			Payload: sporrelay.WorkOrder{
				ObjectiveID: "objective:cmd-1", OwnerPseudonym: "actor:buyer",
				DescriptionCommitment: "sha256:description", PolicyHash: "sha256:policy",
			},
		},
		Grant: sporrelay.RelayAuthorityGrant{
			IssuerID: workOrderTestActorID(issuerKey.Public().(ed25519.PublicKey)), SubjectID: actorID, ResourceID: "objective:cmd-1",
			Scopes: []string{sporrelay.RegisterObjectiveAction}, NotBefore: "2026-01-01T00:00:00Z",
			ExpiresAt: "2027-01-01T00:00:00Z", Nonce: "nonce",
		},
	}
	unsignedGrant := workOrderTestFields(command.Grant)
	delete(unsignedGrant, "signature")
	command.Grant.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerKey, workOrderTestCanonicalJSON(unsignedGrant)))
	grantHash := sha256.Sum256(workOrderTestCanonicalJSON(command.Grant))
	actorPayload := map[string]any{
		"actor_id":     actorID,
		"scope":        command.Scope,
		"command_type": "IngressCommand",
		"command":      command.Command,
		"grant_hash":   hex.EncodeToString(grantHash[:]),
	}
	command.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(actorKey, workOrderTestCanonicalJSON(actorPayload)))
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

func workOrderTestActorID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return "did:relay:" + hex.EncodeToString(digest[:])[:40]
}

func workOrderTestFields(value any) map[string]any {
	data, _ := json.Marshal(value)
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	return fields
}

func workOrderTestCanonicalJSON(value any) []byte {
	data, _ := json.Marshal(value)
	var normalized any
	_ = json.Unmarshal(data, &normalized)
	canonical, _ := json.Marshal(normalized)
	return canonical
}

func workOrderPreparationFiles(t *testing.T, work sporrelay.WorkOrder) (string, string, string, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	actorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	issuerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	actorPublic, issuerPublic := actorKey.Public().(ed25519.PublicKey), issuerKey.Public().(ed25519.PublicKey)
	actorID, issuerID := workOrderTestActorID(actorPublic), workOrderTestActorID(issuerPublic)
	keyFile := filepath.Join(dir, "actor.key")
	issuerFile := filepath.Join(dir, "issuer.json")
	grantFile := filepath.Join(dir, "grant.json")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(actorKey[:ed25519.SeedSize])), 0o600); err != nil {
		t.Fatal(err)
	}
	issuerData, err := json.Marshal(sporrelay.RelayActorIdentity{
		ActorID: issuerID, PublicKey: base64.RawURLEncoding.EncodeToString(issuerPublic),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(issuerFile, issuerData, 0o600); err != nil {
		t.Fatal(err)
	}
	grant := sporrelay.RelayAuthorityGrant{
		IssuerID: issuerID, SubjectID: actorID, ResourceID: work.ObjectiveID,
		Scopes:    []string{sporrelay.RegisterObjectiveAction},
		NotBefore: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), Nonce: "relayos-issued-nonce",
	}
	unsigned := workOrderTestFields(grant)
	delete(unsigned, "signature")
	grant.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerKey, workOrderTestCanonicalJSON(unsigned)))
	grantData, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grantFile, grantData, 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, issuerFile, grantFile, actorKey, issuerKey
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

	t.Run("local preparation uses provided authority and does not submit", func(t *testing.T) {
		work := sporrelay.WorkOrder{
			ObjectiveID: "objective:prepared-binary", OwnerPseudonym: "actor:buyer",
			DescriptionCommitment: "sha256:private-description", PolicyHash: "sha256:policy",
		}
		actorFile, issuerFile, grantFile, actorKey, issuerKey := workOrderPreparationFiles(t, work)
		outFile := filepath.Join(t.TempDir(), "prepared-command.json")
		prepare := exec.Command(binary, "work-order", "prepare",
			"-actor-key", actorFile, "-issuer", issuerFile, "-grant", grantFile,
			"-objective-id", work.ObjectiveID, "-owner-pseudonym", work.OwnerPseudonym,
			"-description-commitment", work.DescriptionCommitment, "-policy-hash", work.PolicyHash,
			"-out", outFile)
		var prepareOut, prepareErr strings.Builder
		prepare.Stdout, prepare.Stderr = &prepareOut, &prepareErr
		if err := prepare.Run(); err != nil {
			t.Fatalf("real work-order prepare failed: %v\\nstdout=%s\\nstderr=%s", err, prepareOut.String(), prepareErr.String())
		}
		if !strings.Contains(prepareOut.String(), "registration: not submitted") {
			t.Fatalf("prepare output did not state it made no network submission: %q", prepareOut.String())
		}
		var command sporrelay.AuthorizedWorkOrderCommand
		preparedBytes, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(preparedBytes, &command); err != nil {
			t.Fatalf("decode prepared envelope: %v", err)
		}
		if err := command.Validate(); err != nil {
			t.Fatalf("prepared envelope validation: %v", err)
		}
		grantSig, err := base64.RawURLEncoding.DecodeString(command.Grant.Signature)
		if err != nil || !ed25519.Verify(issuerKey.Public().(ed25519.PublicKey), workOrderTestCanonicalJSON(func() map[string]any {
			fields := workOrderTestFields(command.Grant)
			delete(fields, "signature")
			return fields
		}()), grantSig) {
			t.Fatalf("prepared command replaced or invalidated the RelayOS grant: %v", err)
		}
		grantHash := sha256.Sum256(workOrderTestCanonicalJSON(command.Grant))
		actorPayload := map[string]any{
			"actor_id": command.Actor.ActorID, "scope": command.Scope,
			"command_type": "IngressCommand", "command": command.Command,
			"grant_hash": hex.EncodeToString(grantHash[:]),
		}
		actorSig, err := base64.RawURLEncoding.DecodeString(command.Signature)
		if err != nil || !ed25519.Verify(actorKey.Public().(ed25519.PublicKey), workOrderTestCanonicalJSON(actorPayload), actorSig) {
			t.Fatalf("prepared command was not signed by the caller actor key: %v", err)
		}
		if got := command.Grant.Nonce; got != "relayos-issued-nonce" {
			t.Fatalf("prepared command changed the RelayOS-issued grant nonce: %q", got)
		}
	})

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
