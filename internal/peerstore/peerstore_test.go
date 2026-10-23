package peerstore

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// TestFetchAgainstSporePeerServeCommand exercises the built CLI over loopback.
// It is skipped when the command binary is not available; set SPORE_PEER_BIN to
// the binary built from ./cmd/spore-peer to run it.
func TestFetchAgainstSporePeerServeCommand(t *testing.T) {
	exe := os.Getenv("SPORE_PEER_BIN")
	if exe == "" {
		exe = "spore-peer"
	}
	if _, err := exec.LookPath(exe); err != nil {
		t.Skip("spore-peer binary not found — set SPORE_PEER_BIN to the built binary")
	}
	dir := t.TempDir()
	body := []byte("synthetic E2 ciphertext for peer CLI test")
	cid := sha256.Sum256(body)
	if err := os.WriteFile(filepath.Join(dir, hex.EncodeToString(cid[:])+".body"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exe, "serve", "--listen", "127.0.0.1:0", "--dir", dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start spore-peer: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	ready := make(chan string, 1)
	readErr := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			readErr <- err
			return
		}
		ready <- strings.TrimSpace(line)
	}()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	var line string
	select {
	case line = <-ready:
	case err := <-readErr:
		t.Fatalf("spore-peer exited before announcing listener: %v", err)
	case <-timer.C:
		t.Fatal("spore-peer did not announce listener")
	}
	if !strings.HasPrefix(line, "LISTEN ") {
		t.Fatalf("unexpected readiness line %q", line)
	}
	addr := strings.TrimPrefix(line, "LISTEN ")
	got, err := Fetch(context.Background(), addr, cid)
	if err != nil {
		t.Fatalf("fetch from spore-peer: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body mismatch: got %q want byte-exact body", got)
	}
}
