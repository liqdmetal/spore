package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/notify"
)

func TestLoadMailboxNotifyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notify.json")
	if err := os.WriteFile(path, []byte(`{"alice":{"email":"alice@example.com","sms":"+15551234567","webhook":"https://notify.example/alice"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadMailboxNotifyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["alice"].Email != "alice@example.com" || got["alice"].SMS != "+15551234567" {
		t.Fatalf("unexpected config: %#v", got)
	}
}

func TestNotifyBodyPutEmitsMetadataOnlyAfterAcceptedPut(t *testing.T) {
	var gotBody string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer provider.Close()

	d, err := notify.New(notify.Options{WebhookURL: provider.URL})
	if err != nil {
		t.Fatal(err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ciphertext must not be forwarded"))
	})
	wrapped := notifyBodyPut(inner, d)

	req := httptest.NewRequest(http.MethodPut, "/put/abcdef0123456789", strings.NewReader("ciphertext must not be forwarded"))
	res := httptest.NewRecorder()
	wrapped.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("wrapped PUT status = %d, want 200", res.Code)
	}
	if !strings.Contains(gotBody, "abcdef0123456789") {
		t.Fatalf("notification omitted body identifier: %s", gotBody)
	}
	if strings.Contains(gotBody, "ciphertext must not be forwarded") {
		t.Fatalf("notification leaked body bytes: %s", gotBody)
	}
}
