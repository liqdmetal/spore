package store

import (
	"sync"
	"time"
)

type entry struct {
	body     []byte
	deadline time.Time
}

// MemStore is an in-memory Store guarded by a mutex. It is the scaffold
// backend; a DHT implementation satisfies the same interface.
type MemStore struct {
	mu    sync.RWMutex
	items map[[32]byte]entry
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{items: make(map[[32]byte]entry)}
}

func (s *MemStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[cid] = entry{body: append([]byte(nil), body...), deadline: deadline}
	return nil
}

func (s *MemStore) Get(cid [32]byte) ([]byte, error) {
	s.mu.RLock()
	e, ok := s.items[cid]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if !e.deadline.IsZero() && time.Now().After(e.deadline) {
		return nil, ErrExpired
	}
	return append([]byte(nil), e.body...), nil
}

func (s *MemStore) Delete(cid [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[cid]; !ok {
		return ErrNotFound
	}
	delete(s.items, cid)
	return nil
}

func (s *MemStore) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for cid, e := range s.items {
		if !e.deadline.IsZero() && now.After(e.deadline) {
			delete(s.items, cid)
			n++
		}
	}
	return n
}

func (s *MemStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}
