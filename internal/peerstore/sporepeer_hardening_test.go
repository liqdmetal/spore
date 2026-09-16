package peerstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

// Hardening regressions for the unauthenticated serve surface (security
// review of the sporepeer:// listener): the attacker controls TCP and the
// length prefix, so every claim below must hold against a hostile client.

// TestServeRejectsOversizedRequest: a declared 64 MiB request must be
// refused with "400 bad frame" WITHOUT the server allocating a
// length-prefix-sized buffer. Before the fix, readFrame pre-allocated
// make([]byte, n) from the attacker-chosen prefix — N idle connections
// x 64 MiB x ioTO was a trivial remote OOM. The wire cost of the refusal
// is one small error frame.
func TestServeRejectsOversizedRequest(t *testing.T) {
	_, addr := newServingEndpoint(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var hostile uint32 = maxFrame // 64 MiB, exactly what a client may send
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], hostile)
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	// Do NOT write the payload: the server must reject on the prefix alone
	// and answer before (or without) ever seeing 64 MiB of body.

	payload, err := readFrame(conn)
	if err != nil {
		t.Fatalf("no response to oversized prefix: %v", err)
	}
	if string(payload) != "\x01400 bad frame" {
		t.Fatalf("response = %q, want \\x01400 bad frame", payload)
	}
}

// TestServeSurvivesHostileThenServesValid: hostile traffic must not wedge
// or kill the listener — a well-formed fetch immediately after an oversized
// and a malformed request must succeed.
func TestServeSurvivesHostileThenServesValid(t *testing.T) {
	sender, addr := newServingEndpoint(t)
	body := []byte("still serving after hostile probes")
	cid := sha256.Sum256(body)
	if err := sender.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	hostileConns := []struct {
		name    string
		request []byte
	}{
		{"oversized prefix", forgedFrame(maxFrame, nil)},
		{"zero length", forgedFrame(0, nil)},
		{"garbage payload", forgedFrame(8, []byte("not json"))},
	}
	for _, hc := range hostileConns {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("%s: dial: %v", hc.name, err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write(hc.request)
		// Answer (if any) is irrelevant; the connection is closed by us.
		_, _ = readFrame(conn)
		conn.Close()
	}

	// The listener must still be alive and correct.
	got, err := Fetch(context.Background(), addr, cid)
	if err != nil {
		t.Fatalf("fetch after hostile traffic: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("fetched %q, want %q", got, body)
	}
}

// TestServeExpiredBodyReports410OnWire pins the TTL story end to end: an
// expired body is never served (410), and a *burned-on-access* body must not
// reappear on the next fetch.
func TestServeExpiredBodyReports410OnWire(t *testing.T) {
	sender, addr := newServingEndpoint(t)
	body := []byte("compost me")
	cid := sha256.Sum256(body)
	if err := sender.Put(cid, body, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	if _, err := Fetch(context.Background(), addr, cid); err != store.ErrExpired {
		t.Fatalf("expired fetch err = %v, want store.ErrExpired", err)
	}
	// A second fetch must not resurrect it (Get enforces the deadline on
	// every access; nothing here rewrites the .exp file).
	if _, err := Fetch(context.Background(), addr, cid); err != store.ErrExpired {
		t.Fatalf("second expired fetch err = %v, want store.ErrExpired", err)
	}
	if sender.Reap(time.Now()) != 1 {
		t.Fatal("reap did not remove the expired body")
	}
	if _, err := sender.hold.Get(cid); err != store.ErrNotFound {
		t.Fatalf("post-reap get err = %v, want ErrNotFound", err)
	}
}

// forgedFrame builds a length-prefixed frame with an attacker-chosen prefix
// that need not match the payload (payload may be nil).
func forgedFrame(prefix uint32, payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(out, prefix)
	copy(out[4:], payload)
	return out
}
