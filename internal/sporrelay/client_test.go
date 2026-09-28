package sporrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validAuthorizedWorkOrder() AuthorizedWorkOrderCommand {
	actorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	issuerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	actorID := relayActorID(actorKey.Public().(ed25519.PublicKey))
	issuerID := relayActorID(issuerKey.Public().(ed25519.PublicKey))
	work := WorkOrder{
		ObjectiveID:           "objective:test-1",
		OwnerPseudonym:        "actor:buyer-pseudonym",
		DescriptionCommitment: "sha256:description",
		PolicyHash:            "sha256:policy",
	}
	now := time.Now().UTC()
	grant := RelayAuthorityGrant{
		IssuerID: issuerID, SubjectID: actorID, ResourceID: work.ObjectiveID,
		Scopes: []string{RegisterObjectiveAction}, NotBefore: now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Nonce: "unique-nonce",
	}
	grant.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerKey, relayCanonicalValue(unsignedGrantForTest(grant))))
	command := AuthorizedWorkOrderCommand{
		Actor: RelayActorIdentity{ActorID: actorID, PublicKey: base64.RawURLEncoding.EncodeToString(actorKey.Public().(ed25519.PublicKey))},
		Scope: RegisterObjectiveAction,
		Command: ObjectiveRegistrationCommand{
			Action: RegisterObjectiveAction, ResourceID: work.ObjectiveID, Payload: work,
		},
		Grant: grant,
	}
	grantHash := sha256.Sum256(relayCanonicalValue(grant))
	authorizationPayload := map[string]any{
		"actor_id": actorID, "scope": command.Scope, "command_type": "IngressCommand",
		"command": authorizedFieldsForTest(command.Command), "grant_hash": hex.EncodeToString(grantHash[:]),
	}
	command.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(actorKey, relayCanonicalValue(authorizationPayload)))
	return command
}

func relayActorID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return "did:relay:" + hex.EncodeToString(digest[:])[:40]
}

// relayCanonicalValue mirrors RelayOS canonical_bytes for these ASCII test
// fixtures: JSON map keys sort lexicographically and compactly; their one-item
// scope array is already canonical.
func relayCanonicalValue(value any) []byte {
	data, _ := json.Marshal(value)
	var normalized any
	_ = json.Unmarshal(data, &normalized)
	canonical, _ := json.Marshal(normalized)
	return canonical
}

func unsignedGrantForTest(grant RelayAuthorityGrant) map[string]any {
	fields := authorizedFieldsForTest(grant)
	delete(fields, "signature")
	return fields
}

func authorizedFieldsForTest(value any) map[string]any {
	var fields map[string]any
	data, _ := json.Marshal(value)
	_ = json.Unmarshal(data, &fields)
	return fields
}

func verifyEnvelopeSignaturesUsingRelayCanonicalRules(command AuthorizedWorkOrderCommand) (bool, bool) {
	actorPublic, actorPubErr := base64.RawURLEncoding.DecodeString(command.Actor.PublicKey)
	actorSig, actorSigErr := base64.RawURLEncoding.DecodeString(command.Signature)
	issuerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	grantSig, grantSigErr := base64.RawURLEncoding.DecodeString(command.Grant.Signature)
	if actorPubErr != nil || actorSigErr != nil || grantSigErr != nil ||
		command.Actor.ActorID != relayActorID(ed25519.PublicKey(actorPublic)) ||
		command.Grant.IssuerID != relayActorID(issuerKey.Public().(ed25519.PublicKey)) {
		return false, false
	}
	grantHash := sha256.Sum256(relayCanonicalValue(command.Grant))
	authorizationPayload := map[string]any{
		"actor_id": command.Actor.ActorID, "scope": command.Scope, "command_type": "IngressCommand",
		"command": authorizedFieldsForTest(command.Command), "grant_hash": hex.EncodeToString(grantHash[:]),
	}
	return ed25519.Verify(issuerKey.Public().(ed25519.PublicKey), relayCanonicalValue(unsignedGrantForTest(command.Grant)), grantSig),
		ed25519.Verify(ed25519.PublicKey(actorPublic), relayCanonicalValue(authorizationPayload), actorSig)
}

func TestRegisterWorkOrderUsesRelayOSCommandsContract(t *testing.T) {
	command := validAuthorizedWorkOrder()
	var got AuthorizedWorkOrderCommand
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/relay/v1/commands" {
			t.Errorf("request = %s %s; want POST /relay/v1/commands", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Errorf("Content-Type = %q", got)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode command: %v", err)
		}
		issuerOK, actorOK := verifyEnvelopeSignaturesUsingRelayCanonicalRules(got)
		if !issuerOK || !actorOK {
			t.Errorf("RelayOS-compatible signatures failed: issuer=%t actor=%t", issuerOK, actorOK)
		}
		result, _ := json.Marshal(command.Command.Payload)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":` + string(result) + `}`))
	}))
	defer server.Close()

	client := NewClient(&Config{RelayerURL: server.URL + "/relay/", APIToken: "proxy-token"})
	registered, err := client.RegisterWorkOrder(context.Background(), command)
	if err != nil {
		t.Fatalf("RegisterWorkOrder: %v", err)
	}
	if !reflect.DeepEqual(got, command) {
		t.Fatalf("wire command changed authorization material:\n got: %#v\nwant: %#v", got, command)
	}
	if gotAuth != "Bearer proxy-token" {
		t.Fatalf("proxy auth header = %q", gotAuth)
	}
	if !registered.matches(command.Command.Payload) {
		t.Fatalf("registered record = %+v, doesn't match submitted work order", registered)
	}
}

func TestRelayCanonicalJSONMatchesRelayOSUnicodeStringEncoding(t *testing.T) {
	got, err := relayCanonicalJSON(map[string]any{
		"é": "\\u2028", "face": "😀", "ascii": "<>&", "del": "\x7f",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ascii":"<>&","del":"\u007f","face":"\ud83d\ude00","\u00e9":"\\u2028"}`
	if string(got) != want {
		t.Fatalf("Relay canonical JSON = %s, want %s", got, want)
	}
}

func TestRelayCanonicalJSONRejectsNumericAuthorizationFields(t *testing.T) {
	if _, err := relayCanonicalJSON(map[string]any{"amount": 1}); err == nil {
		t.Fatal("Relay canonical JSON accepted a numeric value in a signed Relay work-order object")
	}
}

func TestPrepareAuthorizedWorkOrderBuildsRelayOSCanonicalSignature(t *testing.T) {
	command := validAuthorizedWorkOrder()
	actorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	issuerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	issuer := RelayActorIdentity{ActorID: relayActorID(issuerKey.Public().(ed25519.PublicKey)), PublicKey: base64.RawURLEncoding.EncodeToString(issuerKey.Public().(ed25519.PublicKey))}
	prepared, err := PrepareAuthorizedWorkOrder(actorKey, issuer, command.Grant, command.Command.Payload)
	if err != nil {
		t.Fatalf("PrepareAuthorizedWorkOrder: %v", err)
	}
	if err := prepared.Validate(); err != nil {
		t.Fatalf("prepared envelope validation: %v", err)
	}
	if issuerOK, actorOK := verifyEnvelopeSignaturesUsingRelayCanonicalRules(prepared); !issuerOK || !actorOK {
		t.Fatalf("prepared signatures are not RelayOS-compatible: issuer=%t actor=%t", issuerOK, actorOK)
	}
	if !reflect.DeepEqual(prepared.Grant, command.Grant) {
		t.Fatalf("preparation changed the RelayOS-issued grant: got=%+v want=%+v", prepared.Grant, command.Grant)
	}
}

func TestPrepareAuthorizedWorkOrderRejectsUntrustedOrUnusableGrant(t *testing.T) {
	command := validAuthorizedWorkOrder()
	actorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	issuerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	issuer := RelayActorIdentity{ActorID: relayActorID(issuerKey.Public().(ed25519.PublicKey)), PublicKey: base64.RawURLEncoding.EncodeToString(issuerKey.Public().(ed25519.PublicKey))}
	for _, tc := range []struct {
		name   string
		issuer RelayActorIdentity
		grant  RelayAuthorityGrant
	}{
		{"wrong trusted issuer", RelayActorIdentity{ActorID: "did:relay:other", PublicKey: issuer.PublicKey}, command.Grant},
		{"bad signature", issuer, func() RelayAuthorityGrant {
			g := command.Grant
			g.Signature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, ed25519.SignatureSize))
			return g
		}()},
		{"expired grant", issuer, func() RelayAuthorityGrant {
			g := command.Grant
			g.NotBefore = "2020-01-01T00:00:00Z"
			g.ExpiresAt = "2020-01-02T00:00:00Z"
			return g
		}()},
		{"wrong subject", issuer, func() RelayAuthorityGrant { g := command.Grant; g.SubjectID = "did:relay:other"; return g }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PrepareAuthorizedWorkOrder(actorKey, tc.issuer, tc.grant, command.Command.Payload); err == nil {
				t.Fatal("unsafe or unusable RelayOS grant was accepted")
			}
		})
	}
}

func TestSignedCommandTamperingInvalidatesRelayCompatibleSignatures(t *testing.T) {
	command := validAuthorizedWorkOrder()
	if issuerOK, actorOK := verifyEnvelopeSignaturesUsingRelayCanonicalRules(command); !issuerOK || !actorOK {
		t.Fatalf("fixture signatures should verify before tampering: issuer=%t actor=%t", issuerOK, actorOK)
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("correctly signed fixture should satisfy the adapter's envelope shape: %v", err)
	}
	mutations := []struct {
		name   string
		mutate func(*AuthorizedWorkOrderCommand)
	}{
		{"actor", func(c *AuthorizedWorkOrderCommand) { c.Actor.ActorID = "did:relay:other" }},
		{"scope", func(c *AuthorizedWorkOrderCommand) { c.Scope = "settlements.release" }},
		{"command action", func(c *AuthorizedWorkOrderCommand) { c.Command.Action = "settlements.release" }},
		{"work order", func(c *AuthorizedWorkOrderCommand) { c.Command.Payload.PolicyHash = "" }},
		{"grant subject", func(c *AuthorizedWorkOrderCommand) { c.Grant.SubjectID = "did:relay:other" }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			tampered := command
			tampered.Grant.Scopes = append([]string(nil), command.Grant.Scopes...)
			tc.mutate(&tampered)
			issuerOK, actorOK := verifyEnvelopeSignaturesUsingRelayCanonicalRules(tampered)
			if issuerOK && actorOK {
				t.Fatal("tampered envelope retained valid Relay-compatible signatures")
			}
			if err := tampered.Validate(); err == nil {
				t.Fatal("tampered command passed the adapter's required envelope-shape checks")
			}
		})
	}
}

func TestRegisterWorkOrderFailsClosedOnResponse(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantSubstr string
	}{
		{"HTTP 404 route mismatch", http.StatusNotFound, `{"error":"not found"}`, "404"},
		{"RelayOS rejected authorization", http.StatusOK, `{"ok":false,"error":"authority grant is revoked"}`, "revoked"},
		{"RelayOS accepted flag missing", http.StatusOK, `{"result":{"objective_id":"objective:test-1","owner_pseudonym":"actor:buyer-pseudonym","description_commitment":"sha256:description","policy_hash":"sha256:policy"}}`, "did not authorize or apply"},
		{"missing registration result", http.StatusOK, `{"ok":true}`, "without an objective registration result"},
		{"empty result", http.StatusOK, `{"ok":true,"result":{}}`, "does not match submitted work order"},
		{"malformed result", http.StatusOK, `{"ok":true,"result":"bad-shape"}`, "decode objective registration result"},
		{"null result", http.StatusOK, `{"ok":true,"result":null}`, "without an objective registration result"},
		{"wrong result resource", http.StatusOK, `{"ok":true,"result":{"objective_id":"other","owner_pseudonym":"actor:buyer-pseudonym","description_commitment":"sha256:description","policy_hash":"sha256:policy"}}`, "does not match submitted work order"},
		{"extra response field", http.StatusOK, `{"ok":true,"unexpected":true,"result":{}}`, "decode RelayOS command response"},
		{"trailing JSON value", http.StatusOK, `{"ok":true,"result":{}} {"ok":true}`, "decode RelayOS command response"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := NewClient(&Config{RelayerURL: server.URL})
			if result, err := client.RegisterWorkOrder(context.Background(), validAuthorizedWorkOrder()); err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("RegisterWorkOrder = (%+v, %v), want error containing %q", result, err, tc.wantSubstr)
			}
		})
	}
}

func TestRegisterWorkOrderRejectsIdentityScopeAndResourceMismatchBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := NewClient(&Config{RelayerURL: server.URL})

	tests := []struct {
		name   string
		mutate func(*AuthorizedWorkOrderCommand)
		want   string
	}{
		{"wrong actor ID for public key", func(c *AuthorizedWorkOrderCommand) { c.Actor.ActorID = "did:relay:other" }, "actor_id must be derived from its public_key"},
		{"wrong subject", func(c *AuthorizedWorkOrderCommand) { c.Grant.SubjectID = "did:relay:other" }, "subject does not match"},
		{"wrong resource", func(c *AuthorizedWorkOrderCommand) { c.Grant.ResourceID = "objective:other" }, "must be scoped to this work order"},
		{"broad grant", func(c *AuthorizedWorkOrderCommand) { c.Grant.ResourceID = "*" }, "must be scoped to this work order"},
		{"extra scope", func(c *AuthorizedWorkOrderCommand) { c.Grant.Scopes = append(c.Grant.Scopes, "settlements.release") }, "must contain only scope"},
		{"wrong action", func(c *AuthorizedWorkOrderCommand) { c.Command.Action = "settlements.release" }, "only a signed"},
		{"missing actor signature", func(c *AuthorizedWorkOrderCommand) { c.Signature = "" }, "signature are required"},
		{"malformed actor key", func(c *AuthorizedWorkOrderCommand) { c.Actor.PublicKey = "not-base64" }, "public_key must be base64url"},
		{"malformed grant signature", func(c *AuthorizedWorkOrderCommand) { c.Grant.Signature = "not-base64" }, "signatures must be base64url"},
		{"malformed grant time", func(c *AuthorizedWorkOrderCommand) { c.Grant.NotBefore = "tomorrow" }, "not_before is not RFC3339"},
		{"resource mismatch", func(c *AuthorizedWorkOrderCommand) { c.Command.ResourceID = "objective:other" }, "resource_id must equal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			command := validAuthorizedWorkOrder()
			tc.mutate(&command)
			if _, err := client.RegisterWorkOrder(context.Background(), command); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("RegisterWorkOrder error = %v; want containing %q", err, tc.want)
			}
		})
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("invalid signed-envelope shapes reached the network %d times", got)
	}
}

func TestRegisterWorkOrderDoesNotFollowRedirects(t *testing.T) {
	command := validAuthorizedWorkOrder()
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Store(true)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL+"/collect")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client := NewClient(&Config{RelayerURL: source.URL})
	if _, err := client.RegisterWorkOrder(context.Background(), command); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect response error = %v; want explicit 307 rejection", err)
	}
	if redirected.Load() {
		t.Fatal("signed command was replayed to redirect target")
	}
}

func TestCommandsEndpointRequiresAbsoluteSecureBaseURL(t *testing.T) {
	for _, raw := range []string{"", "not-a-url", "ftp://relay.example", "http:///missing-host", "http://user:pass@relay.example", "http://relay.example?x=1", "http://relay.example"} {
		client := NewClient(&Config{RelayerURL: raw})
		if _, err := client.commandsEndpoint(); err == nil {
			t.Errorf("commandsEndpoint(%q) unexpectedly succeeded", raw)
		}
	}
	for _, raw := range []string{"https://relay.example", "http://127.0.0.1:8720", "http://[::1]:8720", "http://localhost:8720"} {
		client := NewClient(&Config{RelayerURL: raw})
		if _, err := client.commandsEndpoint(); err != nil {
			t.Errorf("commandsEndpoint(%q) returned unexpected error: %v", raw, err)
		}
	}
}
