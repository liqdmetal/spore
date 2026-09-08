package store

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPStoreAuthorizationHeaderOnMethods(t *testing.T) {
	const token = "test-token"
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+":"+r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client, err := NewHTTPStoreWithToken(ts.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	cid := [32]byte{1}
	if err := client.Put(cid, []byte("body"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(cid); err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(cid); err != nil {
		t.Fatal(err)
	}
	want := []string{"PUT:Bearer " + token, "GET:Bearer " + token, "DELETE:Bearer " + token}
	if len(seen) != len(want) {
		t.Fatalf("saw %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("request %d: got %q, want %q", i, seen[i], want[i])
		}
	}
}

func TestHTTPStoreAuthorizationHeaderAbsentByDefault(t *testing.T) {
	var authorization string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client, err := NewHTTPStore(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Delete([32]byte{}); err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		t.Fatalf("got Authorization header %q, want absent", authorization)
	}
}
