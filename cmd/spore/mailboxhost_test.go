package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSplitUserRoute(t *testing.T) {
	cases := []struct {
		path     string
		wantName string
		wantRest string
		wantOK   bool
	}{
		{"/u/alice/put/abc", "alice", "/put/abc", true},
		{"/u/alice/list", "alice", "/list", true},
		{"/u/alice/prekey", "alice", "/prekey", true},
		{"/u/alice", "alice", "/", true},
		{"/u/alice/", "alice", "/", true},
		// Rejections: these must NOT route to a user.
		{"/", "", "", false},
		{"/u/", "", "", false},
		{"/u", "", "", false},
		{"u/alice/list", "", "", false},
		{"/list", "", "", false},
		// A name containing a deeper path still splits at the first slash.
		{"/u/bob/body/ff00", "bob", "/body/ff00", true},
	}
	for _, tc := range cases {
		name, rest, ok := splitUserRoute(tc.path)
		if ok != tc.wantOK || name != tc.wantName || rest != tc.wantRest {
			t.Errorf("splitUserRoute(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.path, name, rest, ok, tc.wantName, tc.wantRest, tc.wantOK)
		}
	}
}

// TestSplitUserRouteDoesNotAllowTraversal guards the path-rewrite. The host
// handler is a raw http.HandlerFunc, so the path is NOT cleaned by ServeMux:
// "/u/../bob/list" really arrives with name "..". validUserName must reject it
// rather than the request reaching any user's mailbox.
func TestSplitUserRouteDoesNotAllowTraversal(t *testing.T) {
	for _, p := range []string{
		"/u/../bob/list",
		"/u/./bob/list",
		"/u/alice/../../etc/passwd",
		"/u/%2e%2e/bob/list",
		"/u/a%2fb/list",
		"/u/..",
		"/u/.",
	} {
		name, rest, ok := splitUserRoute(p)
		if ok {
			t.Errorf("splitUserRoute(%q) accepted a traversal-shaped path (name=%q rest=%q)", p, name, rest)
		}
		if name != "" {
			t.Errorf("splitUserRoute(%q) returned name %q despite rejecting", p, name)
		}
	}
}

func TestValidUserName(t *testing.T) {
	for _, good := range []string{"alice", "bob-2", "user_name", "a.b.c", "User123"} {
		if !validUserName(good) {
			t.Errorf("validUserName(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a\\b", "a%2fb", "%2e%2e", "a%b"} {
		if validUserName(bad) {
			t.Errorf("validUserName(%q) = true, want false", bad)
		}
	}
}

func TestLoadHostTokens(t *testing.T) {
	dir := t.TempDir()

	// Missing path -> empty map, no error (loopback hosting needs no tokens).
	m, err := loadHostTokens("")
	if err != nil || len(m) != 0 {
		t.Fatalf("empty path: %v %v", m, err)
	}

	// Nonexistent file -> empty map, no error.
	m, err = loadHostTokens(filepath.Join(dir, "absent.json"))
	if err != nil || len(m) != 0 {
		t.Fatalf("absent file: %v %v", m, err)
	}

	// Valid map.
	good := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(good, []byte(`{"alice":"secret-a","bob":"secret-b"}`), 0600); err != nil {
		t.Fatal(err)
	}
	m, err = loadHostTokens(good)
	if err != nil {
		t.Fatal(err)
	}
	if m["alice"] != "secret-a" || m["bob"] != "secret-b" {
		t.Fatalf("tokens = %v", m)
	}

	// Malformed JSON must error, not silently yield no tokens (which would
	// open every mailbox).
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"alice":`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHostTokens(bad); err == nil {
		t.Fatal("malformed tokens file accepted")
	}

	// Wrong shape (array) must error too.
	arr := filepath.Join(dir, "arr.json")
	if err := os.WriteFile(arr, []byte(`["alice"]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHostTokens(arr); err == nil {
		t.Fatal("array-shaped tokens file accepted")
	}

	// Non-string values must error (DisallowUnknownFields + typed decode).
	nums := filepath.Join(dir, "nums.json")
	if err := os.WriteFile(nums, []byte(`{"alice":123}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHostTokens(nums); err == nil {
		t.Fatal("numeric token value accepted")
	}
}
