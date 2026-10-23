package peerstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

const (
	maxRequestFrame          = 4 << 10
	maxPeerBodyBytes         = 20 << 20 // enough for a 16 MiB E2 frame plus framing
	maxConcurrentConnections = 8
	peerIOTimeout            = 2 * time.Minute
)

var (
	errBadPeerRequest = errors.New("peerstore: malformed request")
	errBadPeerCID     = errors.New("peerstore: malformed cid")
)

// Serve accepts one content-addressed request per TCP connection. It serves
// only bytes already in the caller's store, and verifies SHA-256 before send.
// The transport has no authentication or TLS: bind to loopback/LAN or protect
// it with a trusted VPN/tunnel. E2 ciphertext remains end-to-end encrypted.
func Serve(ctx context.Context, listener net.Listener, bodyStore store.Store) error {
	if ctx == nil {
		return errors.New("peerstore: nil context")
	}
	if listener == nil {
		return errors.New("peerstore: nil listener")
	}
	if bodyStore == nil {
		return errors.New("peerstore: nil body store")
	}
	if ctx.Err() != nil {
		return nil
	}
	bodyStore.Reap(time.Now())
	reapDone := make(chan struct{})
	stopReaper := make(chan struct{})
	go func() {
		defer close(reapDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopReaper:
				return
			case now := <-ticker.C:
				bodyStore.Reap(now)
			}
		}
	}()

	var (
		activeMu    sync.Mutex
		active      = make(map[net.Conn]struct{})
		workers     sync.WaitGroup
		shutdownOne sync.Once
	)
	shutdown := func() {
		shutdownOne.Do(func() {
			_ = listener.Close()
			activeMu.Lock()
			for conn := range active {
				_ = conn.Close()
			}
			activeMu.Unlock()
		})
	}
	stopWatcher := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			shutdown()
		case <-stopWatcher:
		}
	}()
	defer func() {
		close(stopWatcher)
		close(stopReaper)
		shutdown()
		<-watcherDone
		<-reapDone
		workers.Wait()
	}()

	semaphore := make(chan struct{}, maxConcurrentConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("peerstore: accept: %w", err)
		}
		if ctx.Err() != nil {
			_ = conn.Close()
			return nil
		}

		select {
		case semaphore <- struct{}{}:
		default:
			_ = conn.SetDeadline(time.Now().Add(peerIOTimeout))
			_ = writeResponseFrame(conn, 0x01, []byte("503 busy"))
			_ = conn.Close()
			continue
		}

		activeMu.Lock()
		active[conn] = struct{}{}
		activeMu.Unlock()
		workers.Add(1)
		go func(c net.Conn) {
			defer workers.Done()
			defer func() {
				activeMu.Lock()
				delete(active, c)
				activeMu.Unlock()
				<-semaphore
			}()
			servePeerConn(c, bodyStore)
		}(conn)
	}
}

func servePeerConn(conn net.Conn, bodyStore store.Store) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(peerIOTimeout))

	raw, err := readRequestFrame(conn)
	if err != nil {
		_ = writeResponseFrame(conn, 0x01, []byte("400 bad request"))
		return
	}
	cid, err := decodePeerRequest(raw)
	if err != nil {
		message := "400 bad request"
		if errors.Is(err, errBadPeerCID) {
			message = "400 bad cid"
		}
		_ = writeResponseFrame(conn, 0x01, []byte(message))
		return
	}

	body, err := bodyStore.Get(cid)
	if errors.Is(err, store.ErrNotFound) {
		_ = writeResponseFrame(conn, 0x01, []byte("404 not found"))
		return
	}
	if errors.Is(err, store.ErrExpired) {
		_ = writeResponseFrame(conn, 0x01, []byte("410 gone"))
		return
	}
	if err != nil {
		_ = writeResponseFrame(conn, 0x01, []byte("500 store error"))
		return
	}
	if len(body) > maxPeerBodyBytes {
		_ = writeResponseFrame(conn, 0x01, []byte("413 body too large"))
		return
	}
	if sha256.Sum256(body) != cid {
		_ = writeResponseFrame(conn, 0x01, []byte("500 cid mismatch"))
		return
	}
	_ = writeResponseFrame(conn, 0x00, body)
}

func readRequestFrame(r io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(length[:])
	if n == 0 || n > maxRequestFrame {
		return nil, fmt.Errorf("peerstore: request frame length %d is invalid", n)
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodePeerRequest(raw []byte) ([32]byte, error) {
	var cid [32]byte
	if len(raw) == 0 || len(raw) > maxRequestFrame {
		return cid, errBadPeerRequest
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return cid, errBadPeerRequest
	}
	seenCID := false
	var cidHex string
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return cid, errBadPeerRequest
		}
		key, ok := keyToken.(string)
		if !ok || key != "cid" || seenCID {
			return cid, errBadPeerRequest
		}
		seenCID = true
		if err := decoder.Decode(&cidHex); err != nil {
			return cid, errBadPeerCID
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return cid, errBadPeerRequest
	}
	if _, err := decoder.Token(); err != io.EOF {
		return cid, errBadPeerRequest
	}
	if !seenCID || len(cidHex) != hex.EncodedLen(len(cid)) {
		return cid, errBadPeerCID
	}
	decoded, err := hex.DecodeString(cidHex)
	if err != nil || len(decoded) != len(cid) {
		return cid, errBadPeerCID
	}
	copy(cid[:], decoded)
	return cid, nil
}

func writeResponseFrame(w io.Writer, status byte, body []byte) error {
	payloadLen := 1 + len(body)
	if payloadLen > maxFrame {
		return fmt.Errorf("peerstore: response frame exceeds %d bytes", maxFrame)
	}
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(payloadLen))
	if err := writeAll(w, length[:]); err != nil {
		return err
	}
	if err := writeAll(w, []byte{status}); err != nil {
		return err
	}
	return writeAll(w, body)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
