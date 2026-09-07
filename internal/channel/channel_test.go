package channel

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	r, _ := b.room("#room")
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
	r, _ := b.room("#room")
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

// ---- DoS caps (audit M3 / roadmap P0) ----

func TestBoxRoomCap(t *testing.T) {
	b := NewBox(BoxConfig{MaxRooms: 2})
	if _, err := b.Post("#a", "x", false, []byte("m")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Post("#b", "x", false, []byte("m")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Post("#c", "x", false, []byte("m")); err == nil {
		t.Fatal("room cap did not refuse a new room")
	}
	// Existing rooms still accept posts after the cap is hit.
	if _, err := b.Post("#a", "x", false, []byte("m2")); err != nil {
		t.Fatalf("capped box refused post to existing room: %v", err)
	}
	// Polling an unknown channel must not create one (no budget consumption).
	b.Poll("#never", 0)
	if _, err := b.Post("#c", "x", false, []byte("m")); err == nil {
		t.Fatal("poll consumed room budget")
	}
	b.Stop()
}

func TestBoxDataAndSenderCaps(t *testing.T) {
	b := NewBox(BoxConfig{MaxDataLen: 8, MaxSenderLen: 4})
	if _, err := b.Post("#r", "x", false, make([]byte, 9)); err == nil {
		t.Fatal("oversized data accepted")
	}
	if _, err := b.Post("#r", "too-long-sender", false, []byte("m")); err == nil {
		t.Fatal("oversized sender accepted")
	}
	if _, err := b.Post("#r", "al", false, []byte("m")); err != nil {
		t.Fatalf("in-bounds post rejected: %v", err)
	}
	b.Stop()
}

func TestBoxPresenceCap(t *testing.T) {
	b := NewBox(BoxConfig{MaxPresence: 2})
	b.Heartbeat("#r", "a")
	b.Heartbeat("#r", "b")
	b.Heartbeat("#r", "c") // must be refused, not grow
	if on := b.Online("#r"); len(on) != 2 {
		t.Fatalf("presence cap: got %d online, want 2", len(on))
	}
	// Known member can refresh (cap applies to NEW addrs only).
	b.Heartbeat("#r", "a")
	if on := b.Online("#r"); len(on) != 2 {
		t.Fatalf("heartbeat refresh broke presence: %v", on)
	}
	b.Stop()
}

func TestBoxSaveAmplificationGuard(t *testing.T) {
	dir := t.TempDir()
	b, err := NewPersistentBox(BoxConfig{MaxSaveEvery: time.Hour}, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	// First post saves once; rapid subsequent posts must not re-save.
	if _, err := b.Post("#r", "x", false, []byte("m1")); err != nil {
		t.Fatal(err)
	}
	fi1, err := os.Stat(filepath.Join(dir, "channels.json"))
	if err != nil {
		t.Fatalf("first post should save: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 20; i++ {
		b.Post("#r", "x", false, []byte("spam"))
	}
	fi2, err := os.Stat(filepath.Join(dir, "channels.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("state file rewritten within MaxSaveEvery — I/O amplification guard broken")
	}
}
