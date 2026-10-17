package main

// Bootstrap fence over the fabric drain: `spore fabric subscribe` must refuse a
// FrameInit pointer before any prekey state is touched. The relay here is a
// small fake that speaks the fabric wire verbs, so the real subscribe pipeline
// drains and ingests the pointer without the Rust relay.

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/peerstore"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
)

// fenceRelay answers the verbs subscribe uses: freg accepts any registration,
// and fpop hands out the queued pointers once each.
type fenceRelay struct {
	mu    sync.Mutex
	queue [][]byte
}

func startFenceRelay(t *testing.T, pointers [][]byte) (string, *fenceRelay) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r := &fenceRelay{queue: pointers}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(conn)
		}
	}()
	return ln.Addr().String(), r
}

func (r *fenceRelay) remaining() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.queue)
}

func (r *fenceRelay) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 || n > 1<<20 {
		return
	}
	req := make([]byte, n)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	var msg struct {
		Verb string `json:"verb"`
		Max  int    `json:"max"`
	}
	if err := json.Unmarshal(req, &msg); err != nil {
		fenceReply(conn, 1, []byte("400 bad request"))
		return
	}
	switch msg.Verb {
	case "freg":
		body, _ := json.Marshal(map[string]any{"expires": time.Now().Add(time.Hour).Unix()})
		fenceReply(conn, 0, body)
	case "fpop":
		limit := msg.Max
		if limit <= 0 {
			limit = 64
		}
		out := []string{}
		r.mu.Lock()
		for len(r.queue) > 0 && len(out) < limit {
			out = append(out, hex.EncodeToString(r.queue[0]))
			r.queue = r.queue[1:]
		}
		r.mu.Unlock()
		body, _ := json.Marshal(map[string]any{"pointers": out})
		fenceReply(conn, 0, body)
	default:
		fenceReply(conn, 1, []byte("400 unknown verb"))
	}
}

// fenceReply writes one framed reply: a status byte, then the JSON body or the
// refusal text.
func fenceReply(conn net.Conn, status byte, body []byte) {
	frame := append([]byte{status}, body...)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(frame)))
	_, _ = conn.Write(append(lenBuf[:], frame...))
}

// fenceCaptureStderr runs fn and returns everything it wrote to os.Stderr.
func fenceCaptureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stderr = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

func fenceHexFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestFabricSubscribeRefusesInitWithoutTouchingPrekeys delivers an init pointer
// over fabric. Its OPK id is not in the receiver's pool, so if the fence were
// missing the prekey path would count a lookup rejection and create the pool
// file. The fence must refuse it first, so the pool file must never appear.
func TestFabricSubscribeRefusesInitWithoutTouchingPrekeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SPORE_CONFIG", filepath.Join(dir, "absent-config.json"))

	recvID, recvSPK := make([]byte, 32), make([]byte, 32)
	var recvOPK [32]byte
	for i := range recvID {
		recvID[i], recvSPK[i] = 0x41, 0x42
		recvOPK[i] = 0x43
	}
	recvSig, err := secure.SigPubOf(recvID)
	if err != nil {
		t.Fatal(err)
	}
	stateKey := make([]byte, 32)
	holdDir := filepath.Join(dir, "hold")
	stateDir := filepath.Join(dir, "state")
	hold, err := peerstore.NewSporePeerStore(peerstore.SporePeerConfig{Dir: holdDir, Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	states, err := ratchetwire.NewFileStateStore(stateDir, stateKey)
	if err != nil {
		t.Fatal(err)
	}
	recvEP, err := ratchetwire.NewDurableEndpointWithExpiry(hold, states, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	senderIK := make([]byte, 32)
	for i := range senderIK {
		senderIK[i] = 0x51
	}
	senderEP := ratchetwire.NewEndpoint(hold)
	deadline := time.Now().Add(time.Hour)

	// A live session over the chain path, so the drain has a handle to poll.
	goodBundle, err := ratchet.BuildBundle(recvID, recvSPK, 1, &recvOPK, 1)
	if err != nil {
		t.Fatal(err)
	}
	goodPtr, _, _, err := senderEP.SendFirstSession(senderIK, goodBundle, recvSig, []byte("handshake"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	initFrame, err := ratchetwire.FetchFrame(hold, goodPtr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	initBody, err := ratchetwire.GetBody(hold, goodPtr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recvEP.ReceiveFirst(recvID, recvSPK, &recvOPK, initFrame, initBody); err != nil {
		t.Fatal(err)
	}

	// The init pointer the relay delivers over fabric. Its OPK id 77 is not in
	// the receiver's pool.
	var strangerOPK [32]byte
	for i := range strangerOPK {
		strangerOPK[i] = 0x61
	}
	strangerBundle, err := ratchet.BuildBundle(recvID, recvSPK, 1, &strangerOPK, 77)
	if err != nil {
		t.Fatal(err)
	}
	_, badPointer, err := senderEP.SendFirst(senderIK, strangerBundle, recvSig, []byte("bootstrap"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	if len(badPointer) != 74 {
		t.Fatalf("init pointer is %d bytes, want 74", len(badPointer))
	}
	// Close the test's own hold so subscribe opens the same directory fresh.
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}

	// The same init arrives twice, as it can from two relays or two ticks. Each
	// copy must be refused and stay eligible: a refused CID is never consumed.
	relayAddr, relay := startFenceRelay(t, [][]byte{badPointer, badPointer})
	var seed [32]byte
	seed[0], seed[1] = 0xF3, 0x5B
	poolPath := filepath.Join(dir, "opk-pool.json")

	out := fenceCaptureStderr(t, func() {
		fabricSubscribe([]string{
			"-identity", fenceHexFile(t, dir, "identity.key", recvID),
			"-spk", fenceHexFile(t, dir, "spk.key", recvSPK),
			"-store", "sporepeer://127.0.0.1:1", "-store-dir", holdDir,
			"-state-dir", stateDir, "-state-key", fenceHexFile(t, dir, "statekey.hex", stateKey),
			"-opk-pool", poolPath,
			"-receipts", filepath.Join(dir, "receipts.json"),
			"-fabric-seed", hex.EncodeToString(seed[:]),
			"-fabric-relay", relayAddr,
			"-fabric-epoch", "1",
			"-fabric-lease", "1h",
			"-once",
		})
	})

	// Both pointers must have been drained, so the fence is what stopped them.
	if n := relay.remaining(); n != 0 {
		t.Fatalf("relay still holds %d pointer(s): the drain never reached the init", n)
	}
	// Each copy is reported as a refusal, and neither as an ingest. Under the
	// old behavior the second copy was skipped as already consumed, so only one
	// refusal appeared.
	if n := strings.Count(out, "init pointer refused"); n != 2 {
		t.Fatalf("refusals reported=%d, want 2 (a refused CID must stay eligible)\n%s", n, out)
	}
	if strings.Contains(out, "ingested pointer") {
		t.Fatalf("refused init reported as ingested:\n%s", out)
	}
	// Both refusals are persisted in the state directory for `spore status`.
	if n, err := readFabricRefusals(stateDir); err != nil || n != 2 {
		t.Fatalf("persisted refusals=%d err=%v, want 2", n, err)
	}
	// No prekey state may be touched: the pool file must never have been written.
	if _, err := ratchetwire.ReadOnlyPrekeyRejections(poolPath); !os.IsNotExist(err) {
		t.Fatalf("fabric subscribe touched prekey state: pool read err=%v", err)
	}
}
