// Package peerstore is the Go side of the spore-peer transport
// (docs/WIRE_SPEC.md §5): a TCP client that fetches ECDH-encrypted bodies
// directly from a peer's own node by CID — the no-mailbox, no-relay delivery
// path. Clean-room, BSD-3; the protocol is a 4-byte LE length-prefixed JSON
// request and a status-byte response frame:
//
//	frame  = uint32 LE length || payload        (length capped at 64 MiB)
//	request  = JSON {"cid": "<64 hex>"}
//	ok       = 0x00 || body        (sha256(body) MUST == cid)
//	error    = 0x01 || ASCII error ("404 not found", "400 bad cid",
//	                                "500 cid mismatch")
//
// Status-byte dispatch only — never content sniffing (audit H4): a ciphertext
// body may legitimately start with ASCII '4' or '5'.
package peerstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

const (
	maxFrame = 64 << 20 // 64 MiB, same cap as the reference serve
	dialTO   = 10 * time.Second
	ioTO     = 30 * time.Second
)

var (
	ErrMismatch    = errors.New("peerstore: body sha256 != cid")
	ErrUnsupported = errors.New("peerstore: peer transport is receive-only (the sender must run `spore-peer serve` on their own node)")
)

// Fetch requests the body for cid from the peer at addr and returns it after
// verifying sha256(body) == cid. Errors map the reference status codes to
// store sentinels where they exist (404 -> store.ErrNotFound).
func Fetch(ctx context.Context, addr string, cid [32]byte) ([]byte, error) {
	req := []byte(`{"cid":"` + hex.EncodeToString(cid[:]) + `"}`)
	frame := make([]byte, 4+len(req))
	binary.LittleEndian.PutUint32(frame, uint32(len(req)))
	copy(frame[4:], req)

	d := net.Dialer{Timeout: dialTO}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("peerstore: dial %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTO))

	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("peerstore: write request: %w", err)
	}
	payload, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	return classify(payload, cid)
}

// classify is the pure response-dispatch: status byte, then integrity.
// Extracted so fuzzing can drive it without sockets (audit H4 — a ciphertext
// body may legitimately start with ASCII '4' or '5'; only the status byte
// decides).
func classify(payload []byte, cid [32]byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("peerstore: empty response frame")
	}
	switch payload[0] {
	case 0x00:
		body := payload[1:]
		if sha256.Sum256(body) != cid {
			return nil, ErrMismatch
		}
		return body, nil
	case 0x01:
		msg := string(payload[1:])
		switch msg {
		case "404 not found":
			return nil, store.ErrNotFound
		case "410 gone":
			return nil, store.ErrExpired
		}
		return nil, fmt.Errorf("peerstore: peer: %s", msg)
	default:
		return nil, fmt.Errorf("peerstore: unknown status byte 0x%02x", payload[0])
	}
}

func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("peerstore: read length: %w", err)
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxFrame {
		return nil, fmt.Errorf("peerstore: bad frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("peerstore: read payload: %w", err)
	}
	return buf, nil
}

// PeerStore adapts Fetch to the store.Store seam so a `-store peer://host:port`
// body store can be used by E2 receivers whose sender serves from their own
// node. Writes are explicitly unsupported: the peer transport has no push in
// the JSON subset — the sender's node serves, the receiver fetches.
type PeerStore struct {
	Addr string
}

func (s *PeerStore) Put([32]byte, []byte, time.Time) error { return ErrUnsupported }
func (s *PeerStore) Get(cid [32]byte) ([]byte, error) {
	return Fetch(context.Background(), s.Addr, cid)
}
func (s *PeerStore) Delete([32]byte) error { return ErrUnsupported }
func (s *PeerStore) Reap(time.Time) int    { return 0 }
func (s *PeerStore) Len() int              { return 0 }
