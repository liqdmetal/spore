package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/mycelium/internal/crypto"
	"github.com/liqdmetal/mycelium/internal/store"
)

// fakeMailbox stands in for the destination mailbox's /put route in tests. It
// records every pushed body (content-addressed) and the burn deadline it was
// given, so a test can assert the forwarder actually delivered the body and
// dropped it at the relay.
type fakeMailbox struct {
	mu       sync.Mutex
	puts     map[string][]byte // cidHex -> body
	deadline map[string]string // cidHex -> X-Burn-Deadline header
	status   int
}

func newFakeMailbox(status int) *fakeMailbox {
	return &fakeMailbox{
		puts:     map[string][]byte{},
		deadline: map[string]string{},
		status:   status,
	}
}

func (f *fakeMailbox) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || len(r.URL.Path) < len("/put/") ||
			r.URL.Path[:len("/put/")] != "/put/" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.puts[r.URL.Path[len("/put/"):]] = body
		f.deadline[r.URL.Path[len("/put/"):]] = r.Header.Get("X-Burn-Deadline")
		f.mu.Unlock()
		w.WriteHeader(f.status)
	})
}

func (f *fakeMailbox) got(cidHex string) ([]byte, string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.puts[cidHex]
	return b, f.deadline[cidHex], ok
}

func (f *fakeMailbox) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.puts)
}

// newRelay spins up a relay httptest server over a fresh memory store.
func newRelay(t *testing.T, secret string) (*Relay, *httptest.Server) {
	t.Helper()
	r := New(store.NewMemStore())
	var h http.Handler = r.Handler()
	if secret != "" {
		h = r.HandlerToken(secret)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return r, srv
}

func authed(req *http.Request, secret string) *http.Request {
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	return req
}

func mustCID(body string) ([32]byte, string) {
	c := crypto.CID([]byte(body))
	return c, hex.EncodeToString(c[:])
}

// nope returns a cid for a body that is never stored (used for 404 lookups).
func nope() [32]byte {
	return crypto.CID([]byte("nope"))
}

// TestHoldThenForward is the happy path: a sender pushes a body through the
// relay bound for a destination mailbox (X-Relay-Dest). The relay acknowledges
// (202) and holds it; the background forwarder then pushes the body to the
// mailbox's /put/{cid} and drops it locally.
func TestHoldThenForward(t *testing.T) {
	dest := newFakeMailbox(http.StatusOK)
	destsrv := httptest.NewServer(dest.Handler())
	defer destsrv.Close()

	r, rsrv := newRelay(t, "")
	body := "opaque-e2e-ciphertext-hop-one"
	cid, cidHex := mustCID(body)

	// Sender pushes via the client helper (which sets X-Relay-Dest).
	err := PushViaRelay(context.Background(), rsrv.URL, destsrv.URL, cid, []byte(body), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("push via relay: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("relay holds %d, want 1 after push", r.Len())
	}

	// The body is pullable at the relay while held (destination / recipient side).
	pulled, err := PullFromRelay(context.Background(), rsrv.URL, cid)
	if err != nil {
		t.Fatalf("pull from relay: %v", err)
	}
	if !bytes.Equal(pulled, []byte(body)) {
		t.Fatalf("pulled body = %q, want %q", pulled, body)
	}

	// A forward pass delivers to the destination and drops the held copy.
	forwarded, dropped := r.ForwardOnce(context.Background())
	if forwarded != 1 || dropped != 0 {
		t.Fatalf("ForwardOnce = (%d forwarded, %d dropped), want (1, 0)", forwarded, dropped)
	}
	got, _, ok := dest.got(cidHex)
	if !ok || !bytes.Equal(got, []byte(body)) {
		t.Fatalf("destination did not receive body: ok=%v got=%q", ok, got)
	}
	if r.Len() != 0 {
		t.Fatalf("relay still holds %d after successful forward, want 0", r.Len())
	}
	// Pull after forward must now fail (body is gone).
	if _, err := PullFromRelay(context.Background(), rsrv.URL, cid); err == nil {
		t.Fatalf("pull after forward should error (body dropped)")
	}
}

// TestForwardRetriesWhenDown: when the destination mailbox is unreachable the
// relay keeps holding the body (does not drop it) and a later pass succeeds.
func TestForwardRetriesWhenDown(t *testing.T) {
	dest := newFakeMailbox(http.StatusOK)
	destsrv := httptest.NewServer(dest.Handler())

	r, rsrv := newRelay(t, "")
	body := "retry-me"
	cid, _ := mustCID(body)

	// Push while the mailbox is up, then stop it so forwarding fails.
	if err := PushViaRelay(context.Background(), rsrv.URL, destsrv.URL, cid, []byte(body), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("push: %v", err)
	}
	destsrv.Close() // destination now down

	fw, dr := r.ForwardOnce(context.Background())
	if fw != 0 || dr != 0 {
		t.Fatalf("forward to down mailbox = (%d, %d), want (0,0) — body must be retained", fw, dr)
	}
	if r.Len() != 1 {
		t.Fatalf("relay dropped a body while the mailbox was down: Len=%d, want 1", r.Len())
	}
}

// TestContentAddressing: a push whose body does not hash to the requested cid
// is rejected (400) and nothing is stored. The relay is content-addressed like
// the mailbox: a wrong body can never be planted under a referenced cid.
func TestContentAddressing(t *testing.T) {
	r, rsrv := newRelay(t, "")
	goodCID := crypto.CID([]byte("expected-body"))
	wrongBody := []byte("does-not-hash-to-goodCID")

	// POST with X-Relay-Dest set but body mismatched -> 400.
	req, _ := http.NewRequest(http.MethodPost, rsrv.URL+"/relay/"+hex.EncodeToString(goodCID[:]),
		bytes.NewReader(wrongBody))
	req.Header.Set("X-Relay-Dest", "http://127.0.0.1:1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched push status = %d, want 400", res.StatusCode)
	}
	if r.Len() != 0 {
		t.Fatalf("mismatched body must not be held: Len=%d", r.Len())
	}
	if _, err := r.st.Get(goodCID); err != store.ErrNotFound {
		t.Fatalf("mismatched body must not be stored, err=%v", err)
	}

	// Missing X-Relay-Dest -> 400 too.
	cid2, cidHex2 := mustCID("valid-body")
	req2, _ := http.NewRequest(http.MethodPost, rsrv.URL+"/relay/"+cidHex2, bytes.NewReader([]byte("valid-body")))
	res2, _ := http.DefaultClient.Do(req2)
	io.Copy(io.Discard, res2.Body)
	res2.Body.Close()
	if res2.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing-dest push status = %d, want 400", res2.StatusCode)
	}
	_ = cid2
}

// TestPullRoute: a held body is retrievable by GET /relay/{cid} (content
// addressed — only a party that knows the cid can get it) and a missing cid is
// 404. DELETE drops a held body.
func TestPullRoute(t *testing.T) {
	r, rsrv := newRelay(t, "")
	body := "pulled-body"
	cid, cidHex := mustCID(body)
	if err := PushViaRelay(context.Background(), rsrv.URL, "http://127.0.0.1:1", cid, []byte(body), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("push: %v", err)
	}

	get := func(path string) int {
		res, err := http.Get(rsrv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode
	}
	if code := get("/relay/" + cidHex); code != http.StatusOK {
		t.Fatalf("GET held body status = %d, want 200", code)
	}
	missing := nope()
	if code := get("/relay/" + hex.EncodeToString(missing[:])); code != http.StatusNotFound {
		t.Fatalf("GET missing body status = %d, want 404", code)
	}
	if code := get("/relay/zzzznothex"); code != http.StatusBadRequest {
		t.Fatalf("GET bad-cid status = %d, want 400", code)
	}

	// DELETE removes the held body.
	req, _ := http.NewRequest(http.MethodDelete, rsrv.URL+"/relay/"+cidHex, nil)
	dr, _ := http.DefaultClient.Do(req)
	io.Copy(io.Discard, dr.Body)
	dr.Body.Close()
	if dr.StatusCode != http.StatusOK {
		t.Fatalf("DELETE status = %d, want 200", dr.StatusCode)
	}
	if r.Len() != 0 {
		t.Fatalf("relay Len = %d after DELETE, want 0", r.Len())
	}
	if code := get("/relay/" + cidHex); code != http.StatusNotFound {
		t.Fatalf("GET after DELETE status = %d, want 404", code)
	}
}

// TestTokenAuth: when a token is set (HandlerToken), every route requires
// `Authorization: Bearer *** — no/wrong/bare token is refused 401; the correct
// token succeeds. The open Handler stays open.
func TestTokenAuth(t *testing.T) {
	const secret = "relay-hop-secret"
	r := New(store.NewMemStore())
	secured := httptest.NewServer(r.HandlerToken(secret))
	defer secured.Close()

	body := "authed-hop"
	_, cidHex := mustCID(body)
	doPush := func(req *http.Request) int {
		res, err := secured.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode
	}

	push := func(token string) int {
		req, _ := http.NewRequest(http.MethodPost, secured.URL+"/relay/"+cidHex, bytes.NewReader([]byte(body)))
		req.Header.Set("X-Relay-Dest", "http://127.0.0.1:1")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return doPush(req)
	}

	if code := push(""); code != http.StatusUnauthorized { // no token
		t.Fatalf("no-token push = %d, want 401", code)
	}
	if code := push("wrong-secret"); code != http.StatusUnauthorized {
		t.Fatalf("wrong-token push = %d, want 401", code)
	}
	if code := push(secret); code != http.StatusAccepted {
		t.Fatalf("correct-token push = %d, want 202", code)
	}

	// GET route is gated too.
	get := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, secured.URL+"/relay/"+cidHex, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return doPush(req)
	}
	if code := get(""); code != http.StatusUnauthorized {
		t.Fatalf("no-token GET = %d, want 401", code)
	}
	if code := get(secret); code != http.StatusOK {
		t.Fatalf("correct-token GET = %d, want 200", code)
	}

	// Open handler still serves unauthenticated.
	open := httptest.NewServer(r.Handler())
	defer open.Close()
	res, err := http.Get(open.URL + "/relay/" + cidHex)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("open handler GET = %d, want 200", res.StatusCode)
	}
}

// TestBurnExpiryNotForwarded: a body past its burn deadline is never forwarded
// to the destination; a reap pass evicts it from the relay entirely.
func TestBurnExpiryNotForwarded(t *testing.T) {
	dest := newFakeMailbox(http.StatusOK)
	destsrv := httptest.NewServer(dest.Handler())
	defer destsrv.Close()

	r, rsrv := newRelay(t, "")
	body := "burn-me"
	cid, _ := mustCID(body)
	past := time.Now().Add(-time.Minute)

	// Push with a past deadline (X-Burn-Deadline in the past).
	if err := PushViaRelay(context.Background(), rsrv.URL, destsrv.URL, cid, []byte(body), past); err != nil {
		t.Fatalf("push with past deadline: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("relay Len = %d after push, want 1", r.Len())
	}

	// A forward pass must NOT deliver it — instead it's reaped as dropped.
	fw, dr := r.ForwardOnce(context.Background())
	if fw != 0 || dr != 1 {
		t.Fatalf("ForwardOnce expired = (%d forwarded, %d dropped), want (0, 1)", fw, dr)
	}
	if dest.count() != 0 {
		t.Fatalf("expired body was forwarded to the destination; count = %d, want 0", dest.count())
	}
	if r.Len() != 0 {
		t.Fatalf("relay Len = %d after reaping expired body, want 0", r.Len())
	}
}

// TestReapEvictsExpired: Reap drops every held body past its deadline and
// leaves live bodies alone.
func TestReapEvictsExpired(t *testing.T) {
	r, rsrv := newRelay(t, "")
	liveCID, _ := mustCID("live")
	deadCID, _ := mustCID("dead")

	if err := PushViaRelay(context.Background(), rsrv.URL, "http://127.0.0.1:1",
		liveCID, []byte("live"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Push the dead one directly through the handler with a past deadline.
	req, _ := http.NewRequest(http.MethodPost, rsrv.URL+"/relay/"+hex.EncodeToString(deadCID[:]),
		bytes.NewReader([]byte("dead")))
	req.Header.Set("X-Relay-Dest", "http://127.0.0.1:1")
	req.Header.Set("X-Burn-Deadline", strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10))
	res, _ := http.DefaultClient.Do(req)
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("push expired-body status = %d, want 202", res.StatusCode)
	}
	if r.Len() != 2 {
		t.Fatalf("relay Len = %d, want 2 before reap", r.Len())
	}

	if n := r.Reap(time.Now()); n != 1 {
		t.Fatalf("Reap dropped %d, want 1", n)
	}
	if r.Len() != 1 {
		t.Fatalf("relay Len = %d after reap, want 1 (live body kept)", r.Len())
	}
}

// TestForwardLoopDelivery drives the always-on loop: with a short interval the
// held body is forwarded to the destination without an explicit ForwardOnce.
func TestForwardLoopDelivery(t *testing.T) {
	dest := newFakeMailbox(http.StatusOK)
	destsrv := httptest.NewServer(dest.Handler())
	defer destsrv.Close()

	r, rsrv := newRelay(t, "")
	body := "loop-delivery"
	cid, _ := mustCID(body)
	if err := PushViaRelay(context.Background(), rsrv.URL, destsrv.URL, cid, []byte(body), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("push: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.ForwardLoop(ctx, 5*time.Millisecond)
	}()

	// Wait for the loop to deliver + drop (poll, bounded).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if dest.count() == 1 && r.Len() == 0 {
			cancel()
			<-done
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("forward loop did not deliver: dest count=%d relay Len=%d", dest.count(), r.Len())
}
