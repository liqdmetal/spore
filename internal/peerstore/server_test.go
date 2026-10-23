package peerstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

type peerTestStore struct {
	body []byte
	err  error
}

func (s *peerTestStore) Put([32]byte, []byte, time.Time) error { return nil }
func (s *peerTestStore) Get([32]byte) ([]byte, error)          { return append([]byte(nil), s.body...), s.err }
func (s *peerTestStore) Delete([32]byte) error                 { return nil }
func (s *peerTestStore) Reap(time.Time) int                    { return 0 }
func (s *peerTestStore) Len() int                              { return 1 }

func startPeerServer(t *testing.T, bodyStore store.Store) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, bodyStore) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() returned during shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			_ = ln.Close()
			t.Error("Serve() did not stop after context cancellation")
		}
	})
	return ln.Addr().String()
}

func TestServeFetchesDiskStoredCiphertextByCID(t *testing.T) {
	bodyStore, err := store.NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("ratchet-encrypted peer body")
	cid := sha256.Sum256(body)
	if err := bodyStore.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	got, err := Fetch(context.Background(), startPeerServer(t, bodyStore), cid)
	if err != nil {
		t.Fatalf("Fetch(): %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body mismatch: got %q, want exact ciphertext", got)
	}
}

func TestServeMapsMissingAndExpiredBodies(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{name: "missing", err: store.ErrNotFound, want: store.ErrNotFound},
		{name: "expired", err: store.ErrExpired, want: store.ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := startPeerServer(t, &peerTestStore{err: tc.err})
			_, err := Fetch(context.Background(), addr, sha256.Sum256([]byte("opaque")))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Fetch() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestServeRejectsWrongBytesUnderCID(t *testing.T) {
	wantBody := []byte("expected ciphertext")
	cid := sha256.Sum256(wantBody)
	addr := startPeerServer(t, &peerTestStore{body: []byte("wrong ciphertext")})
	_, err := Fetch(context.Background(), addr, cid)
	if err == nil || !strings.Contains(err.Error(), "500 cid mismatch") {
		t.Fatalf("Fetch() error = %v, want peer integrity rejection", err)
	}
}

func TestServeRejectsOversizedBody(t *testing.T) {
	body := make([]byte, maxPeerBodyBytes+1)
	cid := sha256.Sum256(body)
	addr := startPeerServer(t, &peerTestStore{body: body})
	_, err := Fetch(context.Background(), addr, cid)
	if err == nil || !strings.Contains(err.Error(), "413 body too large") {
		t.Fatalf("Fetch() error = %v, want 413 body-too-large rejection", err)
	}
}

func TestDecodePeerRequestStrictCIDAndJSON(t *testing.T) {
	validCID := strings.Repeat("ab", 32)
	got, err := decodePeerRequest([]byte(`{"cid":"` + validCID + `"}`))
	if err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if hex.EncodeToString(got[:]) != validCID {
		t.Fatalf("decoded CID = %x, want %s", got, validCID)
	}

	for _, raw := range []string{
		``,
		`{`,
		`{"cid":"abcd"}`,
		`{"cid":"` + strings.Repeat("zz", 32) + `"}`,
		`{"cid":"` + validCID + `","extra":true}`,
		`{"cid":"` + validCID + `"}{}`,
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := decodePeerRequest([]byte(raw)); err == nil {
				t.Fatalf("decodePeerRequest(%q) accepted malformed input", raw)
			}
		})
	}
}

func FuzzDecodePeerRequest(f *testing.F) {
	f.Add([]byte(`{"cid":"` + strings.Repeat("00", 32) + `"}`))
	f.Add([]byte(`{"cid":"not-a-cid"}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		cid, err := decodePeerRequest(raw)
		if err == nil && len(hex.EncodeToString(cid[:])) != 64 {
			t.Fatalf("successful decode returned invalid CID length")
		}
	})
}
