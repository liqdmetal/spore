package store

import (
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Server exposes a Store over HTTP with automatic TTL reaping. It is the
// off-chain body store both endpoints share, standing in for the DHT.
type Server struct {
	store  Store
	reaper *time.Ticker
	done   chan struct{}
}

// NewServer wraps a Store (e.g. MemStore) as an HTTP handler and starts a
// background reaper.
func NewServer(st Store, reapInterval time.Duration) *Server {
	s := &Server{store: st, reaper: time.NewTicker(reapInterval), done: make(chan struct{})}
	go func() {
		for {
			select {
			case <-s.reaper.C:
				s.store.Reap(time.Now())
			case <-s.done:
				return
			}
		}
	}()
	return s
}

// Stop halts the reaper.
func (s *Server) Stop() {
	s.reaper.Stop()
	close(s.done)
}

// Handler returns the HTTP handler for the body-store protocol.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/body/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		hexcid := strings.TrimPrefix(r.URL.Path, prefix)
		raw, err := hex.DecodeString(hexcid)
		if err != nil || len(raw) != 32 {
			http.Error(w, "bad cid", http.StatusBadRequest)
			return
		}
		var cid [32]byte
		copy(cid[:], raw)

		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			deadline := time.Time{}
			if hdr := r.Header.Get("X-Burn-Deadline"); hdr != "" {
				if sec, err := strconv.ParseInt(hdr, 10, 64); err == nil {
					deadline = time.Unix(sec, 0)
				}
			}
			if err := s.store.Put(cid, body, deadline); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, err := s.store.Get(cid)
			switch err {
			case nil:
				_, _ = w.Write(body)
			case ErrNotFound:
				http.NotFound(w, r)
			case ErrExpired:
				http.Error(w, "expired", http.StatusGone)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		case http.MethodDelete:
			if err := s.store.Delete(cid); err != nil && err != ErrNotFound {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
