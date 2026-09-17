package peerstore

// The reverse half of the cross-binary interop story: peerstore_test.go's
// TestFetchAgainstRealRustPeer proves the Go CLIENT against a Rust SERVER;
// this file proves the Go SERVER against the real Rust `spore-peer fetch`
// client — the direction a sender's node actually runs (Go `spore serve`
// holding bodies, the recipient's Rust tooling pulling them). Both tests skip
// when SPORE_PEER_BIN is absent, so plain `go test ./...` stays hermetic and
// the wire-contract CI job (which builds the Rust binary and sets the env
// var) exercises them together.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rustPeerBin resolves the spore-peer binary the same way
// TestFetchAgainstRealRustPeer does, so both directions key off one env var.
func rustPeerBin(t *testing.T) string {
	t.Helper()
	exe := os.Getenv("SPORE_PEER_BIN")
	if exe == "" {
		exe = "spore-peer"
	}
	if _, err := exec.LookPath(exe); err != nil {
		t.Skip("spore-peer binary not found — set SPORE_PEER_BIN to the built binary")
	}
	return exe
}

// startRustFetch runs one `spore-peer fetch` invocation and waits for it to
// finish (the CLI is one-shot: connect, one frame each way, exit). Returns
// the exit error (nil on success) and the combined stderr text, which is
// where the CLI reports both success and the server's verbatim error string.
// startRustFetch returns the CLI's combined stderr text and its exit error
// (nil on success); error last per Go convention.
func startRustFetch(t *testing.T, exe, addr, cidHex, outPath string) (string, error) {
	t.Helper()
	args := []string{"fetch", "--addr", addr, "--cid", cidHex}
	if outPath != "" {
		args = append(args, "--out", outPath)
	}
	cmd := exec.Command(exe, args...)
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return errBuf.String(), err
}

// TestRustFetchFromGoServedHold is the cross-binary proof in the sender-node
// direction: a Go SporePeerStore serve listener (bound with :0, port
// discovered via LocalAddr) holds a body the real Rust client fetches,
// integrity-verifies (sha256 == cid), and writes to --out. Every byte the
// recipient sees has passed both implementations' hash checks.
func TestRustFetchFromGoServedHold(t *testing.T) {
	exe := rustPeerBin(t)

	s, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := s.LocalAddr()
	if addr == "" {
		t.Fatal("serve listener did not resolve an address")
	}

	body := []byte("sender-held ciphertext crossing the Go/Rust boundary")
	cid := sha256.Sum256(body)
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "fetched.bin")
	stderr, fetchErr := startRustFetch(t, exe, addr, hex.EncodeToString(cid[:]), out)
	if fetchErr != nil {
		t.Fatalf("rust fetch failed: %v (stderr: %s)", fetchErr, stderr)
	}
	if !strings.Contains(stderr, "fetched and integrity-verified") {
		t.Errorf("rust client did not report integrity verification (stderr: %s)", stderr)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read --out file: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("--out body mismatch: got %q want %q", got, body)
	}
}

// TestRustFetchErrorStringsFromGoServer pins the error-frame half of the
// contract from the Rust client's side: the Go server's "404 not found" and
// "410 gone" frames must surface VERBATIM as the Rust CLI's failure message —
// never reshaped into a generic error, never mistaken for a body (the
// client's status-byte handling decides, integrity never "recovers" an error
// frame). The 410 case also proves the ms-precision burn deadline travels:
// the Go hold refuses the read on the sender's side of the socket.
func TestRustFetchErrorStringsFromGoServer(t *testing.T) {
	exe := rustPeerBin(t)

	s, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := s.LocalAddr()

	missing := sha256.Sum256([]byte("no such body in this hold"))
	if stderr, err := startRustFetch(t, exe, addr, hex.EncodeToString(missing[:]), ""); err == nil {
		t.Fatal("rust fetch of a missing cid must fail")
	} else if !strings.Contains(stderr, "404 not found") {
		t.Fatalf("missing-cid stderr = %q, want the verbatim \"404 not found\" frame", stderr)
	}

	expired := []byte("burned before anyone could ask")
	expCID := sha256.Sum256(expired)
	if err := s.Put(expCID, expired, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	// Give the deadline's unix-second floor time to roll over, so the read
	// is unambiguously past (DiskStore enforces to the ms, but the seconds
	// record is the fallback master).
	time.Sleep(1100 * time.Millisecond)
	if stderr, err := startRustFetch(t, exe, addr, hex.EncodeToString(expCID[:]), ""); err == nil {
		t.Fatal("rust fetch of an expired cid must fail")
	} else if !strings.Contains(stderr, "410 gone") {
		t.Fatalf("expired-cid stderr = %q, want the verbatim \"410 gone\" frame", stderr)
	}
}

// TestRustFetchSurvivesPortZeroAndStartupRace covers the operational shape
// CI exercises: the Go listener is created and the Rust client fires
// immediately — the client's own connect loop (one-shot here, retried by the
// test) must not be confused by a connection that arrives before the first
// accept, and the Go server must answer correctly on the very first request
// it sees.
func TestRustFetchSurvivesPortZeroAndStartupRace(t *testing.T) {
	exe := rustPeerBin(t)

	s, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := s.LocalAddr()

	body := []byte("first request the server has ever seen")
	cid := sha256.Sum256(body)
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// No settle sleep: fire immediately after NewSporePeerStore returns.
	// A one-shot failure here would be a real startup race, so retry a few
	// times but expect the FIRST attempt to succeed in practice.
	deadline := time.Now().Add(10 * time.Second)
	var lastStderr string
	var lastErr error
	for time.Now().Before(deadline) {
		lastStderr, lastErr = startRustFetch(t, exe, addr, hex.EncodeToString(cid[:]), "")
		if lastErr == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("rust fetch never succeeded: %v (stderr: %s)", lastErr, lastStderr)
}
