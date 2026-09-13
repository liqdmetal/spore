package peerstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

// serveFrame answers one connection with a prebuilt frame, after consuming the
// client's request (mirrors the real protocol: request first, then response).
func serveFrame(t *testing.T, frame []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read (and discard) the framed request: 4-byte LE length + payload.
		var lenBuf [4]byte
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return
		}
		n := binary.LittleEndian.Uint32(lenBuf[:])
		if n > 0 && n < 4096 {
			_, _ = io.CopyN(io.Discard, c, int64(n))
		}
		_, _ = c.Write(frame)
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func mustFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	f := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(f, uint32(len(payload)))
	copy(f[4:], payload)
	return f
}

// The WIRE_SPEC §5 vectors, byte for byte.
func TestFetchSpecOkVector(t *testing.T) {
	// 07000000 00 34343434abcd — ok frame; body deliberately starts with
	// ASCII '4' (audit H4: status-byte dispatch must not content-sniff).
	body := []byte{0x34, 0x34, 0x34, 0x34, 0xab, 0xcd}
	cid := sha256.Sum256(body)
	addr := serveFrame(t, mustFrame(t, append([]byte{0x00}, body...)))
	got, err := Fetch(context.Background(), addr, cid)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body = %x, want %x", got, body)
	}
}

func TestFetchSpecErrorVector(t *testing.T) {
	// 0e000000 01 343034206e6f7420666f756e64 — "404 not found".
	addr := serveFrame(t, mustFrame(t, append([]byte{0x01}, []byte("404 not found")...)))
	_, err := Fetch(context.Background(), addr, sha256.Sum256([]byte("x")))
	if err != store.ErrNotFound {
		t.Fatalf("want store.ErrNotFound, got %v", err)
	}
}

func TestFetchRejectsMismatchedBody(t *testing.T) {
	body := []byte("ciphertext")
	wrong := []byte("tampered")
	cid := sha256.Sum256(body)
	addr := serveFrame(t, mustFrame(t, append([]byte{0x00}, wrong...)))
	_, err := Fetch(context.Background(), addr, cid)
	if err != ErrMismatch {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
}

func TestFetchRejectsHugeFrame(t *testing.T) {
	// A 65 MiB length prefix (over the 64 MiB cap) must be refused without
	// reading anything.
	payload := []byte{0x00}
	f := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(f, 64<<20+1)
	copy(f[4:], payload)
	addr := serveFrame(t, f)
	_, err := Fetch(context.Background(), addr, sha256.Sum256([]byte("x")))
	if err == nil {
		t.Fatal("want frame-length error")
	}
}

func TestPeerStoreWritesUnsupported(t *testing.T) {
	s := &PeerStore{Addr: "127.0.0.1:1"}
	if err := s.Put([32]byte{}, []byte("x"), time.Now()); err != ErrUnsupported {
		t.Fatalf("Put: want ErrUnsupported, got %v", err)
	}
	if err := s.Delete([32]byte{}); err != ErrUnsupported {
		t.Fatalf("Delete: want ErrUnsupported, got %v", err)
	}
}

// TestFetchAgainstRealRustPeer is the interop proof: it runs the shipped
// `spore-peer serve` binary, plants a body file, and fetches it through the
// Go client. Skipped when the Rust binary is not present (e.g. CI without a
// Rust toolchain build).
func TestFetchAgainstRealRustPeer(t *testing.T) {
	exe := os.Getenv("SPORE_PEER_BIN")
	if exe == "" {
		exe = "spore-peer"
	}
	if _, err := exec.LookPath(exe); err != nil {
		t.Skip("spore-peer binary not found — set SPORE_PEER_BIN to the built binary")
	}
	dir := t.TempDir()
	body := []byte("real-ciphertext-from-sender-node-39a1")
	cid := sha256.Sum256(body)
	if err := os.WriteFile(filepath.Join(dir, hex.EncodeToString(cid[:])+".body"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cmd := exec.Command(exe, "serve", "--listen", "127.0.0.1:"+strconv.Itoa(port), "--dir", dir)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start spore-peer: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(15 * time.Second)
	var got []byte
	var lastErr error
	for time.Now().Before(deadline) {
		got, lastErr = Fetch(context.Background(), "127.0.0.1:"+strconv.Itoa(port), cid)
		if lastErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("fetch from real peer: %v", lastErr)
	}
	if string(got) != string(body) {
		t.Fatalf("body mismatch: got %q want %q", got, body)
	}
}
