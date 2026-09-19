package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWebhookContainsMetadataOnly(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer webhook-secret" {
			t.Fatalf("missing webhook authorization")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	d, err := New(Options{WebhookURL: srv.URL, WebhookToken: "webhook-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Send(Event{TxID: "abcdef1234567890", Subject: "Spore message"}); err != nil {
		t.Fatal(err)
	}
	if got["txid"] != "abcdef1234567890" {
		t.Fatalf("unexpected txid: %#v", got["txid"])
	}
	if _, ok := got["plaintext"]; ok {
		t.Fatal("webhook payload contains plaintext field")
	}
	if _, ok := got["body"]; ok {
		t.Fatal("webhook payload contains body field")
	}
	if strings.Contains(stringValue(got), "DO NOT LEAK THIS") {
		t.Fatal("webhook payload leaked plaintext")
	}
}

func TestNewFromEnvLoadsProviderSecretsWithoutPuttingThemInEvent(t *testing.T) {
	t.Setenv("SPORE_NOTIFY_WEBHOOK_TOKEN", "env-secret")
	t.Setenv("SPORE_NOTIFY_SMTP_PASSWORD", "smtp-secret")
	t.Setenv("SPORE_NOTIFY_TWILIO_AUTH_TOKEN", "twilio-secret")

	d, err := NewFromEnv(Options{WebhookURL: "https://example.invalid", EmailTo: "user@example.com", SMTPHost: "smtp.example.com", SMTPFrom: "spore@example.com", SMSTo: "+15551234567", TwilioSID: "ACtest", TwilioFrom: "+15550000000"})
	if err != nil {
		t.Fatal(err)
	}
	if d.webhookToken != "env-secret" || d.smtpPassword != "smtp-secret" || d.twilioAuthToken != "twilio-secret" {
		t.Fatal("provider secrets were not loaded from environment")
	}
	b, _ := json.Marshal(Event{TxID: "tx", Subject: "private"})
	if strings.Contains(string(b), "secret body") {
		t.Fatal("notification event unexpectedly contains plaintext")
	}
}

func TestNewRejectsPartialEmailConfiguration(t *testing.T) {
	_, err := New(Options{EmailTo: "user@example.com", SMTPHost: "smtp.example.com"})
	if err == nil || !strings.Contains(err.Error(), "SMTP") {
		t.Fatalf("expected SMTP configuration error, got %v", err)
	}
}

func TestNewRejectsHeaderInjection(t *testing.T) {
	_, err := New(Options{WebhookURL: "http://example.test", WebhookToken: "ok\r\nX-Leak: yes"})
	if err == nil || !strings.Contains(err.Error(), "CR/LF") {
		t.Fatalf("expected CR/LF rejection, got %v", err)
	}
}

func TestNewRejectsInvalidWebhookURL(t *testing.T) {
	_, err := New(Options{WebhookURL: "not a URL"})
	if err == nil {
		t.Fatal("invalid webhook URL accepted")
	}
}

func TestNewRejectsInvalidSMSConfig(t *testing.T) {
	_, err := New(Options{SMSTo: "+15551234567", TwilioFrom: "+15557654321"})
	if err == nil || !strings.Contains(err.Error(), "SMS") {
		t.Fatalf("expected SMS configuration error, got %v", err)
	}
}

func stringValue(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func TestEventHasNoPlaintextField(t *testing.T) {
	b, err := json.Marshal(Event{TxID: "tx", Subject: "private"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "plaintext") || strings.Contains(string(b), "body") {
		t.Fatalf("event exposes body data: %s", b)
	}
}

func TestNoopDoesNotRequireProviders(t *testing.T) {
	for _, k := range []string{"SPORE_NOTIFY_WEBHOOK_TOKEN", "SPORE_NOTIFY_SMTP_PASSWORD", "SPORE_NOTIFY_TWILIO_AUTH_TOKEN"} {
		_ = os.Unsetenv(k)
	}
	d, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Send(Event{TxID: "tx"}); err != nil {
		t.Fatal(err)
	}
}
