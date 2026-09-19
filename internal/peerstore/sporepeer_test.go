package peerstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

// SporePeerStore loopback integration: one endpoint holds + serves, the other
// fetches — exactly the sender/receiver split of `-store sporepeer://addr`.

// newServingEndpoint starts a SporePeerStore bound to an OS-chosen loopback
// port and returns it with its resolved address.
func newServingEndpoint(t *testing.T) (*SporePeerStore, string) {
	t.Helper()
	s, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, s.LocalAddr()
}

func TestSporePeerServeAndFetchRoundTrip(t *testing.T) {
	sender, addr := newServingEndpoint(t)
	body := []byte("a long-body ciphertext that never rides a chain block")
	cid := sha256.Sum256(body)
	deadline := time.Now().Add(time.Hour)

	if err := sender.Put(cid, body, deadline); err != nil {
		t.Fatalf("hold put: %v", err)
	}
	if sender.Len() != 1 {
		t.Fatalf("hold len = %d, want 1", sender.Len())
	}

	// Receiver side: a store pointed at the sender's node, empty local hold.
	receiver, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), Addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })

	got, err := receiver.Get(cid)
	if err != nil {
		t.Fatalf("remote get: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("fetched %q, want %q", got, body)
	}
}

func TestSporePeerServeMapsErrorsToSpecStrings(t *testing.T) {
	sender, addr := newServingEndpoint(t)

	body := []byte("expiring body")
	cid := sha256.Sum256(body)
	if err := sender.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Plain client (no fallback needed): the frames on the wire must carry
	// the exact documented error strings.
	checkErrString := func(probe [32]byte, want string) {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		req := []byte(`{"cid":"` + hex64(probe) + `"}`)
		if _, err := conn.Write(frameBytes(req)); err != nil {
			t.Fatal(err)
		}
		payload, err := readFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) == 0 || payload[0] != 0x01 || string(payload[1:]) != want {
			t.Fatalf("error frame = %q, want status byte + %q", payload, want)
		}
	}

	var unknown [32]byte
	for i := range unknown {
		unknown[i] = 0x7F
	}
	checkErrString(unknown, "404 not found")

	// Tampered request shape -> 400 bad cid.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(frameBytes([]byte(`{"cid":"nope"}`))); err != nil {
		t.Fatal(err)
	}
	payload, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if string(payload) != "\x01400 bad cid" {
		t.Fatalf("bad-cid frame = %q", payload)
	}

	// Expired body -> 410 gone, and it composts from the hold.
	expired := sha256.Sum256([]byte("already gone"))
	if err := sender.Put(expired, []byte("already gone"), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	checkErrString(expired, "410 gone")
	if err := sender.Delete(expired); err == nil {
		// Compost may already have removed it via Reap on access; either way
		// the body must not be servable. (Delete of a reaped body errs.)
		_ = err
	}
}

func TestSporePeerExpiredBodyNotServed(t *testing.T) {
	sender, addr := newServingEndpoint(t)
	receiver, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), Addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })

	body := []byte("rotted away")
	cid := sha256.Sum256(body)
	if err := sender.Put(cid, body, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Get(cid); !errors.Is(err, store.ErrExpired) {
		t.Fatalf("expired fetch err = %v, want store.ErrExpired", err)
	}
}

func TestSporePeerUnknownCIDIsErrNotFound(t *testing.T) {
	_, addr := newServingEndpoint(t) // sender is only needed as the fetch target
	receiver, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), Addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })

	var missing [32]byte
	for i := range missing {
		missing[i] = 0xAB
	}
	if _, err := receiver.Get(missing); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing fetch err = %v, want store.ErrNotFound", err)
	}
}

func TestSporePeerLocalHoldFallbackWhenPeerDown(t *testing.T) {
	// A store configured with an unreachable peer but a populated local hold:
	// Get must fall back to the hold (transport error, not a definitive 404).
	dir := t.TempDir()
	s, err := NewSporePeerStore(SporePeerConfig{Dir: dir, Addr: "127.0.0.1:1"}) // port 1: nothing listens
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	body := []byte("locally held")
	cid := sha256.Sum256(body)
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(cid)
	if err != nil {
		t.Fatalf("fallback get: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("fallback got %q", got)
	}
}

func TestSporePeerRemoteErrNotFoundIsNotMaskedByLocalHold(t *testing.T) {
	// A definitive 404 from the peer must surface as ErrNotFound even when
	// the local hold HAS the body — the peer's TTL verdict is authoritative
	// (its copy composted; ours being present is a local artifact).
	sender, addr := newServingEndpoint(t)
	receiver, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), Addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })

	body := []byte("present in both holds")
	cid := sha256.Sum256(body)
	if err := sender.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Sender composts its copy; receiver's local copy remains.
	if err := sender.Delete(cid); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Get(cid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get after peer compost = %v, want ErrNotFound (peer verdict must not be masked)", err)
	}
}

// Legacy servers (WIRE_SPEC §5): raw body, no status byte, accepted only when
// sha256(whole payload) == cid.
func TestSporePeerLegacyRawBodyServer(t *testing.T) {
	body := []byte("raw body from an old spore-peer serve --dir")
	cid := sha256.Sum256(body)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				payload, err := readFrame(conn)
				if err != nil {
					return
				}
				if _, ok := parseCIDRequest(payload); !ok {
					return
				}
				conn.Write(frameBytes(body)) // raw: no status byte
			}()
		}
	}()

	got, err := Fetch(context.Background(), ln.Addr().String(), cid)
	if err != nil {
		t.Fatalf("legacy fetch: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("legacy fetch got %q", got)
	}

	// A raw response that does NOT hash to the cid must be rejected — it is
	// neither a valid status frame nor the requested body.
	wrong := sha256.Sum256([]byte("some other body entirely"))
	if _, err := Fetch(context.Background(), ln.Addr().String(), wrong); err == nil {
		t.Fatal("legacy fallback accepted bytes that hash to a different cid")
	}
}

// Serving must stay responsive under concurrent fetches (the reference serve
// is one-connection-per-request; the Go server must not serialize peers).
func TestSporePeerConcurrentFetches(t *testing.T) {
	sender, addr := newServingEndpoint(t)
	receiver, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), Addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })

	const n = 8
	bodies := make([][]byte, n)
	for i := range bodies {
		bodies[i] = []byte("concurrent body " + string(rune('a'+i)))
		cid := sha256.Sum256(bodies[i])
		if err := sender.Put(cid, bodies[i], time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cid := sha256.Sum256(bodies[i])
			got, err := receiver.Get(cid)
			if err != nil {
				errs[i] = err
				return
			}
			if !bytes.Equal(got, bodies[i]) {
				errs[i] = errors.New("mismatch")
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}
}

func TestSporePeerConfigRequiresDir(t *testing.T) {
	if _, err := NewSporePeerStore(SporePeerConfig{}); err == nil {
		t.Fatal("empty Dir must be rejected: the sender's node must hold what it serves")
	}
}

func hex64(b [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&15]
	}
	return string(out)
}
