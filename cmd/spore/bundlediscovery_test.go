package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/ratchet"
)

func sampleBundle() ratchet.SPKBundle {
	var b ratchet.SPKBundle
	b.IKPub[0] = 1
	b.SPKPub[0] = 2
	b.SPKID = 7
	b.SPKSig[0] = 3
	return b
}

func TestFetchBundleSuccess(t *testing.T) {
	want := sampleBundle()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/prekey" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Bundle ratchet.SPKBundle `json:"bundle"`
		}{Bundle: want})
	}))
	defer srv.Close()

	got, err := fetchBundle(context.Background(), srv.URL+"/prekey", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.IKPub != want.IKPub || got.SPKPub != want.SPKPub || got.SPKID != want.SPKID || got.SPKSig != want.SPKSig {
		t.Fatalf("bundle mismatch: got %+v, want %+v", got, want)
	}
}

func TestFetchBundleSendsBearerToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Bundle ratchet.SPKBundle `json:"bundle"`
		}{Bundle: sampleBundle()})
	}))
	defer srv.Close()

	if _, err := fetchBundle(context.Background(), srv.URL, "s3cr3t"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer s3cr3t" {
		t.Fatalf("Authorization header = %q, want %q", gotAuth, "Bearer s3cr3t")
	}
}

func TestFetchBundleNoTokenSendsNoAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Bundle ratchet.SPKBundle `json:"bundle"`
		}{Bundle: sampleBundle()})
	}))
	defer srv.Close()

	if _, err := fetchBundle(context.Background(), srv.URL, ""); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization header = %q, want empty when no token configured", gotAuth)
	}
}

func TestFetchBundleRejects404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, err := fetchBundle(context.Background(), srv.URL, "")
	if err == nil {
		t.Fatal("expected error on 404")
	}
	if !strings.Contains(err.Error(), "has not published") {
		t.Fatalf("unexpected error for 404: %v", err)
	}
}

func TestFetchBundleRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := fetchBundle(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestFetchBundleRejectsMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"bundle": not json`))
	}))
	defer srv.Close()

	if _, err := fetchBundle(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestFetchBundleRejectsUnknownFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"bundle":{"ik_pub":"","spk_pub":"","spk_id":0,"spk_sig":""},"extra":"field"}`))
	}))
	defer srv.Close()

	if _, err := fetchBundle(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("expected error on unknown JSON field (strict decoding)")
	}
}

func TestFetchBundleRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Pad well past the 16KiB read cap with a huge unknown field value,
		// so the decoder either truncates mid-token or hits DisallowUnknownFields.
		_, _ = w.Write([]byte(`{"bundle":{"ik_pub":"","spk_pub":"","spk_id":0,"spk_sig":""},"pad":"`))
		_, _ = w.Write([]byte(strings.Repeat("a", 32<<10)))
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	if _, err := fetchBundle(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("expected error on oversized response")
	}
}

func TestFetchBundleHonorsContextCancellation(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(block)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetchBundle(ctx, srv.URL, ""); err == nil {
		t.Fatal("expected error on cancelled context")
	}
}
