package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

// RelayStore must satisfy the same interface every other body store does — the
// whole point is that it is a drop-in for -store.
var _ store.Store = (*RelayStore)(nil)

// tokenMailbox is a destination-mailbox stand-in that records the Authorization
// header it saw per cid. It exists to prove WHOSE token the mailbox sees: the
// pusher holds none, the relay presents the mailbox's own forward token.
type tokenMailbox struct {
	mu     sync.Mutex
	puts   map[string][]byte
	auth   map[string]string
	status int
}

func newTokenMailbox(status int) *tokenMailbox {
	return &tokenMailbox{puts: map[string][]byte{}, auth: map[string]string{}, status: status}
}

func (m *tokenMailbox) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/put/") {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		cidHex := strings.TrimPrefix(r.URL.Path, "/put/")
		m.mu.Lock()
		m.puts[cidHex] = body
		m.auth[cidHex] = r.Header.Get("Authorization")
		m.mu.Unlock()
		w.WriteHeader(m.status)
	})
}

func (m *tokenMailbox) got(cidHex string) ([]byte, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.puts[cidHex]
	return b, m.auth[cidHex], ok
}

// refusingStore stands in for a token-gated mailbox this caller has no token
// for: every read fails, which is exactly the sender's situation.
type refusingStore struct{ err error }

func (refusingStore) Put([32]byte, []byte, time.Time) error { return nil }
func (s refusingStore) Get([32]byte) ([]byte, error)        { return nil, s.err }
func (refusingStore) Delete([32]byte) error                 { return nil }
func (refusingStore) Reap(time.Time) int                    { return 0 }
func (refusingStore) Len() int                              { return 0 }

// TestRelayStorePushNeedsNoPusherToken is the feature's reason to exist: a
// sender with NO mailbox token can still deliver a body to a token-gated
// mailbox, because the relay authenticates the last hop with the operator-held
// forward token. It also pins the read path (relay hold while unforwarded) and
// the post-forward drop.
func TestRelayStorePushNeedsNoPusherToken(t *testing.T) {
	dest := newTokenMailbox(http.StatusOK)
	destsrv := httptest.NewServer(dest.Handler())
	defer destsrv.Close()

	r, rsrv := newRelay(t, "", destsrv.URL)
	r.SetForwardTokens(map[string]string{destsrv.URL: "mailbox-forward-secret"})

	// nil inner store: the pusher holds nothing for the mailbox, not even a client.
	rs, err := NewRelayStore(rsrv.URL, destsrv.URL, nil)
	if err != nil {
		t.Fatalf("NewRelayStore: %v", err)
	}

	body := "relay-store-push-ciphertext"
	cid, cidHex := mustCID(body)
	if err := rs.Put(cid, []byte(body), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RelayStore.Put: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("relay holds %d bodies, want 1", r.Len())
	}

	// While the relay still holds it, an untokened reader can get it back.
	got, err := rs.Get(cid)
	if err != nil {
		t.Fatalf("RelayStore.Get while held: %v", err)
	}
	if !bytes.Equal(got, []byte(body)) {
		t.Fatalf("RelayStore.Get = %q, want %q", got, body)
	}

	// Forward: the mailbox must receive the body AND the operator's token.
	if forwarded, _ := r.ForwardOnce(context.Background()); forwarded != 1 {
		t.Fatalf("forwarded %d, want 1", forwarded)
	}
	mb, auth, ok := dest.got(cidHex)
	if !ok {
		t.Fatal("mailbox never received the body")
	}
	if !bytes.Equal(mb, []byte(body)) {
		t.Fatalf("mailbox body = %q, want %q", mb, body)
	}
	if auth != "Bearer mailbox-forward-secret" {
		t.Fatalf("mailbox saw auth %q, want the relay's forward token", auth)
	}

	// After a successful forward the relay deletes its copy — a sender must not
	// expect the relay to be a durable read-back store.
	if _, err := rs.Get(cid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after forward = %v, want ErrNotFound", err)
	}
}

// TestRelayStoreRefusesUnlistedDestination: the relay's allowlist is the SSRF
// boundary and it must fail the push loudly, not silently drop the body.
func TestRelayStoreRefusesUnlistedDestination(t *testing.T) {
	_, rsrv := newRelay(t, "", "https://other.example.org")
	rs, err := NewRelayStore(rsrv.URL, "https://mail.example.org/u/alice", nil)
	if err != nil {
		t.Fatalf("NewRelayStore: %v", err)
	}
	cid, _ := mustCID("nope-body")
	err = rs.Put(cid, []byte("nope-body"), time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("Put to an unlisted destination succeeded, want a refusal")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error %v does not name the allowlist refusal", err)
	}
}

// TestRelayStoreGetPrefersInnerMailbox: the recipient (who HAS the token) reads
// from the mailbox, not the relay.
func TestRelayStoreGetPrefersInnerMailbox(t *testing.T) {
	r, rsrv := newRelay(t, "")
	inner := store.NewMemStore()
	body := "held by the mailbox"
	cid, _ := mustCID(body)
	if err := inner.Put(cid, []byte(body), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("inner put: %v", err)
	}
	rs, err := NewRelayStore(rsrv.URL, "https://mail.example.org/u/alice", inner)
	if err != nil {
		t.Fatalf("NewRelayStore: %v", err)
	}
	got, err := rs.Get(cid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte(body)) {
		t.Fatalf("Get = %q, want %q", got, body)
	}
	if r.Len() != 0 {
		t.Fatalf("relay was contacted for a mailbox-held body (holds %d)", r.Len())
	}
	if rs.Len() != 1 {
		t.Fatalf("Len = %d, want the inner store's 1", rs.Len())
	}
}

// TestRelayStoreGetFallsBackToRelay: the sender's case — the mailbox refuses the
// read (no token) and the relay's hold answers instead.
func TestRelayStoreGetFallsBackToRelay(t *testing.T) {
	dest := newTokenMailbox(http.StatusOK)
	destsrv := httptest.NewServer(dest.Handler())
	defer destsrv.Close()
	_, rsrv := newRelay(t, "", destsrv.URL)

	rs, err := NewRelayStore(rsrv.URL, destsrv.URL, refusingStore{err: errors.New("401 unauthorized")})
	if err != nil {
		t.Fatalf("NewRelayStore: %v", err)
	}
	body := "unreachable without the relay"
	cid, _ := mustCID(body)
	if err := rs.Put(cid, []byte(body), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := rs.Get(cid)
	if err != nil {
		t.Fatalf("Get with a refusing mailbox: %v", err)
	}
	if !bytes.Equal(got, []byte(body)) {
		t.Fatalf("Get = %q, want %q", got, body)
	}
}

// TestRelayStoreDeleteClearsBothLegs: after Delete neither the mailbox nor the
// relay still serves the body.
func TestRelayStoreDeleteClearsBothLegs(t *testing.T) {
	dest := newTokenMailbox(http.StatusOK)
	destsrv := httptest.NewServer(dest.Handler())
	defer destsrv.Close()
	r, rsrv := newRelay(t, "", destsrv.URL)

	inner := store.NewMemStore()
	rs, err := NewRelayStore(rsrv.URL, destsrv.URL, inner)
	if err != nil {
		t.Fatalf("NewRelayStore: %v", err)
	}
	body := "delete me on both legs"
	cid, _ := mustCID(body)
	if err := inner.Put(cid, []byte(body), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("inner put: %v", err)
	}
	if err := rs.Put(cid, []byte(body), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("relay holds %d, want 1 before delete", r.Len())
	}
	if err := rs.Delete(cid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := inner.Get(cid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("inner still holds the body after Delete: %v", err)
	}
	if r.Len() != 0 {
		t.Fatalf("relay still holds %d bodies after Delete", r.Len())
	}
	// Deleting again is not an error: the goal state is "gone".
	if err := rs.Delete(cid); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
}

// TestNewRelayStoreValidation covers the misconfigurations that would otherwise
// surface as a confusing 403 or a self-forwarding loop at push time.
func TestNewRelayStoreValidation(t *testing.T) {
	cases := []struct{ name, relay, dest, want string }{
		{"empty relay", "", "https://mail.example.org/u/a", "empty relay URL"},
		{"empty dest", "https://relay.example.org", "", "empty mailbox URL"},
		{"non-http dest", "https://relay.example.org", "ftp://mail.example.org/u/a", "must be http(s)"},
		{"same URL", "https://x.example.org", "https://x.example.org", "same URL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewRelayStore(c.relay, c.dest, nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, c.want)
			}
		})
	}
}

// TestNewRelayStoreNormalizesTrailingSlash: the relay's allowlist is keyed on
// the normalized (slash-trimmed) destination, so a trailing slash must not make
// a correctly-listed destination look unlisted.
func TestNewRelayStoreNormalizesTrailingSlash(t *testing.T) {
	rs, err := NewRelayStore("https://relay.example.org/", "https://mail.example.org/u/alice/", nil)
	if err != nil {
		t.Fatalf("NewRelayStore: %v", err)
	}
	if rs.relayBase != "https://relay.example.org" || rs.destBase != "https://mail.example.org/u/alice" {
		t.Fatalf("bases = %q / %q, want both with the trailing slash trimmed", rs.relayBase, rs.destBase)
	}
	if !strings.Contains(rs.Describe(), "https://mail.example.org/u/alice") {
		t.Fatalf("Describe() = %q, want it to name the destination", rs.Describe())
	}
}
