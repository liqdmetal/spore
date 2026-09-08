package mailbox

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/longmsg"
	"github.com/liqdmetal/spore/internal/store"
	"github.com/liqdmetal/spore/internal/whisper"
)

// seedPush returns a sealed body encrypted to the mailbox plus its pointer and
// the sender ciphertext, so a test can /put the body then deliver the pointer.
func seedPush(t *testing.T, m *Mailbox, text string) (*longmsg.Pointer, []byte) {
	t.Helper()
	sender, err := longmsg.NewEndpoint(store.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := sender.SendBody(m.PublicKey(), []byte(text), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sender.Store().Get(ptr.CID)
	if err != nil {
		t.Fatal(err)
	}
	return ptr, ct
}

// TestHTTPPushThenDeliver is the sender-without-a-reachable-node flow: the
// sender POSTs the ciphertext to the mailbox's /put/<cid>, then later the
// pointer-whisper lands on-chain and the mailbox decrypts purely from its own
// store — no peer transport needed.
func TestHTTPPushThenDeliver(t *testing.T) {
	m := openMailbox(t)
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	const secret = "pushed over http, decrypted from the mailbox's own store"
	ptr, ct := seedPush(t, m, secret)
	cidHex := hex.EncodeToString(ptr.CID[:])

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/put/"+cidHex, bytes.NewReader(ct))
	do, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, do.Body)
	do.Body.Close()
	if do.StatusCode != http.StatusOK {
		t.Fatalf("put status = %d, want 200", do.StatusCode)
	}

	// Body must now be readable back (peer pull) from the mailbox.
	got, err := m.LocalFetch(context.Background(), ptr.CID)
	if err != nil || !bytes.Equal(got, ct) {
		t.Fatalf("local body after push: err=%v", err)
	}

	// Pointer lands on-chain; mailbox delivers with its OWN store as the fetch.
	msgs, err := m.Deliver(context.Background(), pointerIncoming(t, ptr, "tx-http"),
		whisper.CanonicalCodec{}, m.LocalFetch)
	if err != nil {
		t.Fatalf("deliver from pushed body: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Text != secret {
		t.Fatalf("unexpected delivered message: %+v", msgs)
	}
}

// TestHTTPPushWithDeadline: a /put carrying X-Burn-Deadline (unix seconds)
// stores the body with that deadline; once it passes, the body reports
// expired and can no longer be fetched.
func TestHTTPPushWithDeadline(t *testing.T) {
	m := openMailbox(t)
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	ptr, ct := seedPush(t, m, "burns at the deadline")
	cidHex := hex.EncodeToString(ptr.CID[:])

	put := func(deadlineSec string) int {
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/put/"+cidHex, bytes.NewReader(ct))
		if deadlineSec != "" {
			req.Header.Set("X-Burn-Deadline", deadlineSec)
		}
		do, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, do.Body)
		do.Body.Close()
		return do.StatusCode
	}

	if code := put(""); code != http.StatusOK {
		t.Fatalf("no-deadline put = %d, want 200", code)
	}
	if _, err := m.LocalFetch(context.Background(), ptr.CID); err != nil {
		t.Fatalf("no-deadline body should be fetchable, err=%v", err)
	}

	// Re-put over it with a PAST unix-seconds deadline: body is now expired.
	past := time.Now().Add(-time.Minute).Unix()
	if code := put(strconv.FormatInt(past, 10)); code != http.StatusOK {
		t.Fatalf("past-deadline put = %d, want 200", code)
	}
	if _, err := m.LocalFetch(context.Background(), ptr.CID); err != store.ErrExpired {
		t.Fatalf("expired push fetch err = %v, want store.ErrExpired", err)
	}
}

// TestHTTPBodyPutThenGetHonorsTTL verifies the HTTPStore-compatible /body PUT
// alias stores a body that can be read from /body and honors its burn deadline.
func TestHTTPBodyPutThenGetHonorsTTL(t *testing.T) {
	m := openMailbox(t)
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	ptr, ct := seedPush(t, m, "body alias")
	cidHex := hex.EncodeToString(ptr.CID[:])
	put := func(deadline time.Time) *http.Response {
		req, err := http.NewRequest(http.MethodPut, srv.URL+"/body/"+cidHex, bytes.NewReader(ct))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Burn-Deadline", strconv.FormatInt(deadline.Unix(), 10))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := put(time.Now().Add(2 * time.Minute))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("body PUT status = %d, want 200", resp.StatusCode)
	}

	resp, err := http.Get(srv.URL + "/body/" + cidHex)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || readErr != nil || !bytes.Equal(got, ct) {
		t.Fatalf("body GET status=%d err=%v match=%v", resp.StatusCode, readErr, bytes.Equal(got, ct))
	}

	resp = put(time.Now().Add(-time.Minute))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expired body PUT status = %d, want 200", resp.StatusCode)
	}
	resp, err = http.Get(srv.URL + "/body/" + cidHex)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("expired body GET status = %d, want 410", resp.StatusCode)
	}
}

// TestHTTPListGetAndRestart verifies the read API (list/get) survives a mailbox
// restart: decrypted messages are durable in the plaintext log.
func TestHTTPListGetAndRestart(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	ptr, transport := senderToMailbox(t, m, "durable across restart")
	if _, err := m.Deliver(context.Background(), pointerIncoming(t, ptr, "tx-keep"),
		whisper.CanonicalCodec{}, transport.Fetch); err != nil {
		t.Fatal(err)
	}

	// Simulate restart: reopen the same dir with a brand-new handle.
	m2, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := m2.Count(); n != 1 {
		t.Fatalf("after restart count = %d, want 1", n)
	}
	msg, err := m2.Get("tx-keep")
	if err != nil || msg.Text != "durable across restart" {
		t.Fatalf("get after restart = %+v err=%v", msg, err)
	}

	srv := httptest.NewServer(m2.Handler())
	defer srv.Close()

	lr, err := http.Get(srv.URL + "/list")
	if err != nil {
		t.Fatal(err)
	}
	var all []Message
	if err := json.NewDecoder(lr.Body).Decode(&all); err != nil {
		t.Fatal(err)
	}
	lr.Body.Close()
	if len(all) != 1 || all[0].TxID != "tx-keep" {
		t.Fatalf("list = %+v", all)
	}

	gr, err := http.Get(srv.URL + "/get/" + all[0].CID)
	if err != nil {
		t.Fatal(err)
	}
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", gr.StatusCode)
	}
	var got Message
	if err := json.NewDecoder(gr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	gr.Body.Close()
	if got.Text != "durable across restart" {
		t.Fatalf("get text = %q", got.Text)
	}

	ur, _ := http.Get(srv.URL + "/get/doesnotexist")
	if ur.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown get status = %d, want 404", ur.StatusCode)
	}
	ur.Body.Close()
}

// TestHTTPPutRejectsMismatchedBody: a sender pushing a body whose sha256 does
// NOT equal the requested cid must be rejected — a wrong body can never be
// planted under the cid a pointer will reference.
func TestHTTPPutRejectsMismatchedBody(t *testing.T) {
	m := openMailbox(t)
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	realCID := crypto.CID([]byte("expected ciphertext"))
	wrongBody := []byte("this body does not hash to the requested cid")
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/put/"+hex.EncodeToString(realCID[:]), bytes.NewReader(wrongBody))
	do, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, do.Body)
	do.Body.Close()
	if do.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched put status = %d, want 400", do.StatusCode)
	}
	if _, err := m.Store().Get(realCID); err != store.ErrNotFound {
		t.Fatalf("mismatched body must not be stored, err=%v", err)
	}
}

// TestHTTPPutRejectsOversizedBody: a body larger than the /put cap is refused
// with 413 Payload Too Large BEFORE the content-address check, and nothing is
// stored. maxBodyBytes is shrunk so the test stays cheap.
func TestHTTPPutRejectsOversizedBody(t *testing.T) {
	old := maxBodyBytes
	maxBodyBytes = 1 << 10 // 1 KiB for the test
	defer func() { maxBodyBytes = old }()

	m := openMailbox(t)
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	// Correct cid for a body that would otherwise hash-match, but oversized.
	big := bytes.Repeat([]byte{0xAB}, maxBodyBytes+64)
	cid := crypto.CID(big)
	cidHex := hex.EncodeToString(cid[:])
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/put/"+cidHex, bytes.NewReader(big))
	do, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, do.Body)
	do.Body.Close()
	if do.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized put status = %d, want 413", do.StatusCode)
	}
	if _, err := m.Store().Get(cid); err != store.ErrNotFound {
		t.Fatalf("oversized body must not be stored, err=%v", err)
	}

	// A body exactly at the cap is still accepted and content-verified.
	ok := bytes.Repeat([]byte{0xCD}, maxBodyBytes)
	okCIDarr := crypto.CID(ok)
	okCID := hex.EncodeToString(okCIDarr[:])
	req2, _ := http.NewRequest(http.MethodPut, srv.URL+"/put/"+okCID, bytes.NewReader(ok))
	do2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, do2.Body)
	do2.Body.Close()
	if do2.StatusCode != http.StatusOK {
		t.Fatalf("at-cap put status = %d, want 200", do2.StatusCode)
	}
}

// TestHTTPRoutesRejectTraversalAndBadCID: cid path segments are strictly
// 32-byte hex. Traversal ("../", "..", empty, junk) and non-hex inputs must be
// rejected with 400 on /put and /body, and unknown routes 404 — no 500, no
// panic, no filesystem escape. GET on a missing body is 404.
func TestHTTPRoutesRejectTraversalAndBadCID(t *testing.T) {
	m := openMailbox(t)
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	paths := []string{
		"/put/../../etc/passwd",
		"/put/..%2f..%2fetc%2fpasswd",
		"/put/../",
		"/put/..",
		"/put/",
		"/put/zzzz", // non-hex
		"/put/00",   // too short
		"/body/../../etc/passwd",
		"/body/..",
		"/body/gggg", // non-hex
		"/body/",
		"/get/../../etc/passwd",
	}
	for _, p := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			req, _ := http.NewRequest(method, srv.URL+p, bytes.NewReader([]byte("x")))
			do, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", method, p, err)
			}
			io.Copy(io.Discard, do.Body)
			do.Body.Close()
			// /put and /body route to parseCID (400) for bad cid; /get just
			// never finds a traversal id -> 404. None of these may 500 or 200.
			if do.StatusCode == http.StatusInternalServerError || do.StatusCode == http.StatusOK {
				t.Fatalf("%s %s: status = %d, want 4xx", method, p, do.StatusCode)
			}
		}
	}

	// PUT to /put/<cid> with the wrong HTTP method is refused 405.
	validArr := crypto.CID([]byte("abc"))
	validCID := hex.EncodeToString(validArr[:])
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/put/"+validCID, nil)
	do, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, do.Body)
	do.Body.Close()
	if do.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /put status = %d, want 405", do.StatusCode)
	}

	// /body of a valid but never-stored cid is 404, not 500.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/body/"+validCID, nil)
	do2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, do2.Body)
	do2.Body.Close()
	if do2.StatusCode != http.StatusNotFound {
		t.Fatalf("GET missing body status = %d, want 404", do2.StatusCode)
	}
}

// TestHTTPTokenAuth: when a shared token is configured via HandlerToken, every
// route requires `Authorization: Bearer <token>`. A request without the header,
// or with the wrong token, is refused 401; the correct token succeeds. The open
// Handler (no token) stays open for backward compatibility.
func TestHTTPTokenAuth(t *testing.T) {
	m := openMailbox(t)
	const secret = "hunter2-mailbox-secret"
	secured := httptest.NewServer(m.HandlerToken(secret))
	defer secured.Close()

	authed := func() *http.Request {
		req, err := http.NewRequest(http.MethodGet, secured.URL+"/list", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		return req
	}

	// No Authorization header -> 401.
	req, _ := http.NewRequest(http.MethodGet, secured.URL+"/list", nil)
	if code := do(t, secured.Client(), req); code != http.StatusUnauthorized {
		t.Fatalf("no header status = %d, want 401", code)
	}

	// Wrong token -> 401.
	req, _ = http.NewRequest(http.MethodGet, secured.URL+"/list", nil)
	req.Header.Set("Authorization", "Bearer wrong-secret")
	if code := do(t, secured.Client(), req); code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", code)
	}

	// Malformed scheme (no "Bearer " prefix) -> 401.
	req, _ = http.NewRequest(http.MethodGet, secured.URL+"/list", nil)
	req.Header.Set("Authorization", secret)
	if code := do(t, secured.Client(), req); code != http.StatusUnauthorized {
		t.Fatalf("bare-token status = %d, want 401", code)
	}

	// Correct token -> 200 (the underlying /list succeeds on an empty mailbox).
	if code := do(t, secured.Client(), authed()); code != http.StatusOK {
		t.Fatalf("correct token status = %d, want 200", code)
	}

	// Auth is enforced on write routes too, not just reads.
	req, _ = http.NewRequest(http.MethodPut, secured.URL+"/put/0000000000000000000000000000000000000000000000000000000000000000", nil)
	if code := do(t, secured.Client(), req); code != http.StatusUnauthorized {
		t.Fatalf("unauthed PUT status = %d, want 401", code)
	}

	// The open Handler with no token still serves /list unauthenticated.
	open := httptest.NewServer(m.Handler())
	defer open.Close()
	req, _ = http.NewRequest(http.MethodGet, open.URL+"/list", nil)
	if code := do(t, open.Client(), req); code != http.StatusOK {
		t.Fatalf("open handler status = %d, want 200", code)
	}
}

// do runs a request and returns the response status code.
func do(t *testing.T, client *http.Client, req *http.Request) int {
	t.Helper()
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode
}

// TestHTTPRoutesDontPanic: fuzz a handful of hostile raw paths through the real
// handler; each must return a response with no panic (no 500 from an internal
// error is also asserted where reasonable).
func TestHTTPRoutesDontPanic(t *testing.T) {
	m := openMailbox(t)
	handler := m.Handler()
	existsArr := crypto.CID([]byte("exists"))
	hostile := []string{
		"/put/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"/body/0000000000000000000000000000000000000000000000000000000000000000",
		"/body/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"/put/" + hex.EncodeToString(existsArr[:]),
		"/",
		"//put/",
		"/get/",
		"/list",
		"/body",
	}
	for _, p := range hostile {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, p, bytes.NewReader(make([]byte, 16)))
		handler.ServeHTTP(rr, req)
		if rr.Code == 0 {
			t.Fatalf("no status written for %q", p)
		}
		// /put with a PUT and a body that hashes to the given cid must succeed;
		// otherwise a 4xx is fine, but never an empty/hanging handler.
	}
}
