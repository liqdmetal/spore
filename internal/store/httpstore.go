package store

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// HTTPStore is a Store backed by a remote body-store server. It is the thin
// stand-in for the DHT: a shared, content-addressed, TTL-bound store that both
// endpoints can reach so the recipient can fetch a body by CID.
//
// Protocol:
//
//	PUT    /body/{cid_hex}   body=raw ciphertext, X-Burn-Deadline: unix sec
//	GET    /body/{cid_hex}   200 body | 404 not found | 410 expired
//	DELETE /body/{cid_hex}
type HTTPStore struct {
	base   string
	client *http.Client
}

// NewHTTPStore builds a client for a body-store server at baseURL (e.g.
// "http://host:8080"). Returns an error if baseURL is empty.
func NewHTTPStore(baseURL string) (*HTTPStore, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("store: empty base URL")
	}
	return &HTTPStore{
		base:   baseURL,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *HTTPStore) path(cid [32]byte) string {
	return s.base + "/body/" + hex.EncodeToString(cid[:])
}

// Put stores body under cid with the given burn deadline.
func (s *HTTPStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	req, err := http.NewRequest(http.MethodPut, s.path(cid), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Burn-Deadline", strconv.FormatInt(deadline.Unix(), 10))
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("store: put %s: %s", resp.Status, msg)
	}
	return nil
}

// Get fetches a body, translating 404/410 into ErrNotFound/ErrExpired.
func (s *HTTPStore) Get(cid [32]byte) ([]byte, error) {
	resp, err := s.client.Get(s.path(cid))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return io.ReadAll(resp.Body)
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusGone:
		return nil, ErrExpired
	default:
		return nil, fmt.Errorf("store: get %s: %s", resp.Status, resp.Status)
	}
}

// Delete removes a body.
func (s *HTTPStore) Delete(cid [32]byte) error {
	req, err := http.NewRequest(http.MethodDelete, s.path(cid), nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("store: delete %s: %s", resp.Status, resp.Status)
	}
	return nil
}

// Reap is a no-op on the client — the server reaps its own bodies.
func (s *HTTPStore) Reap(time.Time) int { return 0 }

// Len is a no-op on the client.
func (s *HTTPStore) Len() int { return 0 }
