package mailbox

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// M1: on a tokenless mailbox, GET /prekey pops single-use bundles, so an
// anonymous drainer can exhaust the owner's prekey batch. The per-IP token
// bucket must hold the line while genuine senders get through.

func TestPrekeyPopRateLimitedPerIP(t *testing.T) {
	oldBurst, oldRefill := prekeyBurst, prekeyRefillInterval
	prekeyBurst, prekeyRefillInterval = 3, time.Hour // tiny burst, no refill within the test
	defer func() { prekeyBurst, prekeyRefillInterval = oldBurst, oldRefill }()

	m, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	// Burst allowance (3) is consumed by the first three pops — even though
	// no batch is published, the 404s still spend budget — then 429.
	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/prekey")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound { // no batch published: pop "fails" but consumed budget
			t.Fatalf("pop %d = %d, want 404 (budget consumed even without a batch)", i+1, resp.StatusCode)
		}
	}
	resp, err := http.Get(srv.URL + "/prekey")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("pop after burst = %d, want 429", resp.StatusCode)
	}
}

func TestPrekeyPopRefillsAndSeparatesIPs(t *testing.T) {
	oldBurst, oldRefill := prekeyBurst, prekeyRefillInterval
	prekeyBurst, prekeyRefillInterval = 1, time.Millisecond
	defer func() { prekeyBurst, prekeyRefillInterval = oldBurst, oldRefill }()

	l := newPrekeyLimiter()
	now := time.Now()
	if !l.allow(now, "10.0.0.1") {
		t.Fatal("first pop for a fresh IP must pass")
	}
	if l.allow(now, "10.0.0.1") {
		t.Fatal("second immediate pop for the same IP must be refused")
	}
	if !l.allow(now, "10.0.0.2") {
		t.Fatal("a different IP must have its own budget")
	}
	if !l.allow(now.Add(50*time.Millisecond), "10.0.0.1") {
		t.Fatal("budget must refill over time")
	}
}

func TestPrekeyPublishNotLimited(t *testing.T) {
	oldBurst, oldRefill := prekeyBurst, prekeyRefillInterval
	prekeyBurst, prekeyRefillInterval = 1, time.Hour
	defer func() { prekeyBurst, prekeyRefillInterval = oldBurst, oldRefill }()

	m, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	// PUT /prekey is the owner's own publish: never throttled, even after the
	// GET budget is long gone.
	for i := 0; i < 3; i++ {
		body := bytes.NewReader([]byte(`{"bundle":{"ik_pub":"` + strconv.Itoa(i) + `"}}`))
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/prekey", body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("PUT /prekey must not be rate-limited (attempt %d)", i+1)
		}
	}
}

func TestPrekeyLimiterBoundedUnderSpoofFlood(t *testing.T) {
	l := newPrekeyLimiter()
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 20000; j++ {
				l.allow(now, "10.0."+strconv.Itoa(base)+"."+strconv.Itoa(j%250))
			}
		}(i)
	}
	wg.Wait()
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n > prekeyBucketCap {
		t.Fatalf("bucket map grew to %d, cap is %d", n, prekeyBucketCap)
	}
}
