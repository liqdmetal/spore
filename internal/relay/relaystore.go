package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

// RelayStore is a Store whose WRITES take the anonymous relay hop instead of
// going straight to the mailbox.
//
// The problem it solves: a hosted (token-gated) mailbox authenticates EVERY
// route with one per-user bearer token. A sender that PUTs a body directly to
// the recipient's mailbox therefore needs the recipient's token — and that same
// token also opens /list, /get and /body, i.e. handing it to a sender hands
// them the recipient's whole mailbox. Routing the write through a relay fixes
// this: the sender authenticates to nothing, the relay holds the mailbox's
// forward token, and the mailbox sees the relay's IP rather than the sender's.
//
// Reads and deletes still go to the inner store (the mailbox) when the caller
// has it. Reads fall back to the relay for the window in which the relay still
// holds the body (before a successful forward — the relay deletes the body once
// the mailbox has accepted it), so an anonymous sender can verify a push
// without any token.
//
// Retention: the relay clamps a push deadline to its own maximum hold
// (DefaultMaxDeadline, 7 days, or whatever the operator configured). The
// mailbox then copies that (possibly clamped) deadline from the forwarded
// request, so a sender asking for a longer TTL gets the relay's cap — not a
// mailbox-side one.
type RelayStore struct {
	relayBase string       // e.g. https://relay.example.org
	destBase  string       // mailbox base the relay should forward to, e.g. https://mail.example.org/u/alice
	inner     store.Store  // direct mailbox handle for Get/Delete (+ Len); may be nil
	client    *http.Client // bounded: never block a phone on a wedged relay
}

// relayStoreTimeout bounds every relay call. Matches relayHTTPClient in
// client.go: http.DefaultClient has no timeout and would wedge a caller
// forever against an unreachable hop.
const relayStoreTimeout = 30 * time.Second

// NewRelayStore builds a relay-hop store. relayBase is the hop's public base
// URL, destMailboxBase is the mailbox base the relay must forward to (the same
// value the caller would have passed as the mailbox -store URL, e.g.
// https://mail.example.org/u/alice). inner may be nil: writes never touch it.
//
// The destination must ALREADY be in the relay operator's -allow-dest list;
// the relay denies forwarding to anything else (403) by design, and this
// constructor cannot discover that list, so a misconfiguration surfaces on the
// first Put as a 403 that names the destination.
func NewRelayStore(relayBase, destMailboxBase string, inner store.Store) (*RelayStore, error) {
	rb, err := normalizeBaseURL("relay", relayBase)
	if err != nil {
		return nil, err
	}
	db, err := normalizeBaseURL("mailbox", destMailboxBase)
	if err != nil {
		return nil, err
	}
	if rb == db {
		return nil, fmt.Errorf("relay store: relay and mailbox are the same URL (%s) — the relay would forward to itself", rb)
	}
	return &RelayStore{
		relayBase: rb,
		destBase:  db,
		inner:     inner,
		client:    &http.Client{Timeout: relayStoreTimeout},
	}, nil
}

// normalizeBaseURL validates an http(s) base URL and trims a trailing slash,
// so "https://mail.example.org/u/alice/" and ".../u/alice" address the same
// destination (the relay's allowlist is keyed on the normalized form).
func normalizeBaseURL(what, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("relay store: empty %s URL", what)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("relay store: bad %s URL %q: %w", what, raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("relay store: %s URL %q must be http(s)://host[/path]", what, raw)
	}
	return strings.TrimSuffix(raw, "/"), nil
}

// Describe names both legs, for a startup line an operator can read back.
func (s *RelayStore) Describe() string {
	return fmt.Sprintf("bodies: relay hop %s -> %s", s.relayBase, s.destBase)
}

// Put pushes the body through the relay hop. The relay acknowledges with 202
// once it holds the body; forwarding to the mailbox is asynchronous, so a
// momentarily-down mailbox does not drop the push. The body is content-
// addressed, so the relay verifies it hashes to cid before accepting it.
func (s *RelayStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), relayStoreTimeout)
	defer cancel()
	if err := PushViaRelay(ctx, s.relayBase, s.destBase, cid, body, deadline); err != nil {
		return fmt.Errorf("relay store: push %s -> %s: %w", s.relayBase, s.destBase, err)
	}
	return nil
}

// Get reads the body. The inner mailbox store is tried first because it is
// authoritative and authenticated for the recipient; the relay is the fallback
// for a caller with no token, during the window before the relay forwards (and
// then deletes) the body.
func (s *RelayStore) Get(cid [32]byte) ([]byte, error) {
	var innerErr error
	if s.inner != nil {
		if b, err := s.inner.Get(cid); err == nil {
			return b, nil
		} else {
			innerErr = err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), relayStoreTimeout)
	defer cancel()
	b, err := s.pull(ctx, cid)
	if err == nil {
		return b, nil
	}
	// Neither leg has it: report the mailbox's verdict when it gave one (it
	// distinguishes expired from never-seen), else the relay's.
	if innerErr != nil {
		if errors.Is(innerErr, store.ErrNotFound) || errors.Is(innerErr, store.ErrExpired) {
			return nil, innerErr
		}
	}
	return nil, err
}

// pull fetches a body directly from the relay, translating 404/410 into the
// store sentinels so Get keeps the same contract as any other Store.
func (s *RelayStore) pull(ctx context.Context, cid [32]byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.relayBase+"/relay/"+hex.EncodeToString(cid[:]), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay store: pull %s: %w", s.relayBase, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, int64(64<<10)+1))
		if err != nil {
			return nil, fmt.Errorf("relay store: pull read: %w", err)
		}
		return body, nil
	case http.StatusNotFound, http.StatusGone:
		return nil, store.ErrNotFound
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("relay store: pull %s: %s %s", s.relayBase, resp.Status, bytes.TrimSpace(msg))
	}
}

// Delete drops the body from both legs: the mailbox (when we hold a token for
// it) and the relay's held copy. A 404 on either leg is not an error — the
// point is that the body is gone.
func (s *RelayStore) Delete(cid [32]byte) error {
	var innerErr error
	if s.inner != nil {
		if err := s.inner.Delete(cid); err != nil && !errors.Is(err, store.ErrNotFound) {
			innerErr = err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), relayStoreTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.relayBase+"/relay/"+hex.EncodeToString(cid[:]), nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if innerErr != nil {
			return innerErr
		}
		return fmt.Errorf("relay store: delete %s: %w", s.relayBase, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound && innerErr == nil {
		return fmt.Errorf("relay store: delete %s: %s", s.relayBase, resp.Status)
	}
	return innerErr
}

// Reap is a no-op on the client: both the mailbox and the relay reap their own
// bodies against their own deadlines.
func (s *RelayStore) Reap(time.Time) int { return 0 }

// Len reports the inner store's body count (the relay's hold is transient and
// deliberately not counted).
func (s *RelayStore) Len() int {
	if s.inner == nil {
		return 0
	}
	return s.inner.Len()
}
