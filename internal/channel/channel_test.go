package channel

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func testBox(t *testing.T) (*Box, *httptest.Server) {
	t.Helper()
	b := NewBox(BoxConfig{LineTTL: time.Minute, PresenceTTL: 5 * time.Second, ReapEvery: time.Hour, MaxLines: 100})
	srv := httptest.NewServer(NewServer(b))
	t.Cleanup(func() { srv.Close(); b.Stop() })
	return b, srv
}

func TestPublicRoundTrip(t *testing.T) {
	_, srv := testBox(t)
	c, _ := NewClient(srv.URL, "alice")
	ln, err := c.PublicPost(context.Background(), "#room", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if ln.Seq != 1 || ln.Private {
		t.Fatalf("line = %+v", ln)
	}
	lines, err := c.PollOpen(context.Background(), "#room", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "[alice] hello" {
		t.Fatalf("lines = %v", lines)
	}
}

func TestPrivateSealOpen(t *testing.T) {
	_, srv := testBox(t)
	key, _ := KeyFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	alice, _ := NewClient(srv.URL, "alice")
	ln, err := alice.PrivatePost(context.Background(), "#priv", key, []byte("secret room"))
	if err != nil {
		t.Fatal(err)
	}
	if !ln.Private {
		t.Fatal("should be private")
	}

	// Bob with the key can read.
	bob, _ := NewClient(srv.URL, "bob")
	lines, err := bob.PollOpen(context.Background(), "#priv", 0, key)
	if err != nil || len(lines) != 1 || lines[0] != "[alice] secret room" {
		t.Fatalf("bob read = %v, %v", lines, err)
	}

	// Eve without the key gets nothing (ciphertext she can't open).
	eve, _ := NewClient(srv.URL, "eve")
	lines, err = eve.PollOpen(context.Background(), "#priv", 0, nil)
	if err != nil || len(lines) != 0 {
		t.Fatalf("eve read = %v, %v (want empty)", lines, err)
	}

	// Wrong key fails to open (AEAD).
	wrong, _ := KeyFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	lines, err = eve.PollOpen(context.Background(), "#priv", 0, wrong)
	if err != nil || len(lines) != 0 {
		t.Fatalf("wrong-key read = %v, %v (want empty)", lines, err)
	}
}

func TestSeqDedupePoll(t *testing.T) {
	_, srv := testBox(t)
	c, _ := NewClient(srv.URL, "x")
	for i := 0; i < 3; i++ {
		c.PublicPost(context.Background(), "#r", []byte("m"))
	}
	// 3 posts -> seq 1,2,3. after=3 -> nothing.
	lines, _ := c.PollOpen(context.Background(), "#r", 3, nil)
	if len(lines) != 0 {
		t.Fatalf("after=3 should be empty, got %d", len(lines))
	}
	// after=2 -> seq 3 only.
	lines, _ = c.PollOpen(context.Background(), "#r", 2, nil)
	if len(lines) != 1 {
		t.Fatalf("after=2 should have 1, got %d", len(lines))
	}
}

func TestPresenceHeartbeatAndStale(t *testing.T) {
	b, srv := testBox(t)
	// shorten presence TTL via direct reaper test instead of sleeping 5s.
	a, _ := NewClient(srv.URL, "alice")
	cctx := context.Background()
	a.Heartbeat(cctx, "#room")
	if on := b.Online("#room"); len(on) != 1 || on[0] != "alice" {
		t.Fatalf("online = %v", on)
	}
	// Manually age the heartbeat past TTL and reap.
	b.mu.Lock()
	r := b.room("#room")
	r.presence["alice"] = time.Now().Add(-time.Minute).UnixMilli()
	b.mu.Unlock()
	b.Reap(time.Now())
	if on := b.Online("#room"); len(on) != 0 {
		t.Fatalf("stale member still online: %v", on)
	}
}

func TestLineTTLReap(t *testing.T) {
	b, srv := testBox(t)
	c, _ := NewClient(srv.URL, "alice")
	c.PublicPost(context.Background(), "#room", []byte("hi"))
	// Age past TTL and reap.
	b.mu.Lock()
	r := b.room("#room")
	for i := range r.lines {
		r.lines[i].TS = time.Now().Add(-time.Hour).UnixMilli()
	}
	b.mu.Unlock()
	b.Reap(time.Now())
	if lines := b.Poll("#room", 0); len(lines) != 0 {
		t.Fatalf("lines survived TTL: %v", lines)
	}
}

func TestBoxRingCap(t *testing.T) {
	b := NewBox(BoxConfig{LineTTL: time.Hour, MaxLines: 3})
	for i := 0; i < 6; i++ {
		b.Post("#r", "x", false, []byte("m"))
	}
	lines := b.Poll("#r", 0)
	if len(lines) != 3 {
		t.Fatalf("ring cap: got %d lines, want 3", len(lines))
	}
	// 6 posts -> seq 1..6; keep last 3 = seq 4,5,6.
	if lines[0].Seq != 4 {
		t.Fatalf("oldest kept seq = %d, want 4", lines[0].Seq)
	}
	b.Stop()
}
