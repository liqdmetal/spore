// Package store is the off-chain layer: a content-addressed, TTL-bound store
// for message bodies (ciphertext). This is where "compost" actually happens —
// the body never touches the chain, and it is evicted from the store once its
// deadline passes.
//
// The interface is transport-agnostic: an in-memory implementation ships
// first; a p2p gossip/DHT with the same contract is the intended production
// backend. Nodes cache bodies for N blocks then drop them.
package store

import (
	"errors"
	"time"
)

var (
	// ErrNotFound means the body is unknown at this node.
	ErrNotFound = errors.New("store: not found")
	// ErrExpired means the body was present but has passed its deadline and
	// was (or should be) evicted.
	ErrExpired = errors.New("store: expired")
)

// Store is a content-addressed body store with bounded retention.
type Store interface {
	// Put stores body under cid, retaining it until deadline.
	Put(cid [32]byte, body []byte, deadline time.Time) error
	// Get returns the body, or ErrExpired / ErrNotFound.
	Get(cid [32]byte) ([]byte, error)
	// Delete removes a body immediately.
	Delete(cid [32]byte) error
	// Reap evicts every body whose deadline has passed and returns the count.
	Reap(now time.Time) int
	// Len reports the number of stored bodies.
	Len() int
}
