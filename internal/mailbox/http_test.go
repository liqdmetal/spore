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

	"github.com/liqdmetal/mycelium/internal/crypto"
	"github.com/liqdmetal/mycelium/internal/longmsg"
	"github.com/liqdmetal/mycelium/internal/store"
	"github.com/liqdmetal/mycelium/internal/whisper"
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
