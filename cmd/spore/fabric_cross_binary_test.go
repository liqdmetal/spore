package main

// Cross-binary F2 interop: the REAL spore binary (`fabric subscribe -once`,
// full e2Ingestor pipeline) against the REAL Rust spore-peer relay binary.
//
//	1. Go receiver: real key material; the receiver IS the body store (a
//	   real sporepeer:// hold, like production).
//	2. Go sender: X3DH handshake + FrameMessage continuation into that hold.
//	3. The test hands the init to the receiver directly — it stands in for
//	   the chain watcher, because bootstrap rides the chain by design, never
//	   the fabric (WIRE_SPEC §8 fence).
//	4. The sender publishes the continuation pointer to the REAL Rust relay
//	   via fabric.PublishAs — exactly what -route-fabric does on send.
//	5. The REAL `spore fabric subscribe -once` binary fregs, fpos, ingests
//	   through the shared pipeline, and records the plaintext into maildb.
//
// Skips when SPORE_PEER_BIN is absent (gates.sh sets it after building the
// Rust binary; RACE_PKGS keeps this package under -race).

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/fabric"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/peerstore"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
)

// fabricWaitReadyLocal spawns cmd and parses the server's own readiness line
// (serve prints the BOUND address — a real-binary contract pinned by the
// Rust smoke) from stderr.
func fabricWaitReadyLocal(t *testing.T, cmd *exec.Cmd, marker string) (chan string, chan error) {
	t.Helper()
	ready := make(chan string, 1)
	errs := make(chan error, 1)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		errs <- err
		return ready, errs
	}
	if err := cmd.Start(); err != nil {
		errs <- err
		return ready, errs
	}
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 512)
		for {
			n, rerr := stderr.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				// Only fire on a COMPLETE line: the marker and its address
				// can arrive in separate reads, and parsing a truncated
				// line loses the port.
				if i := bytes.Index(buf, []byte(marker)); i >= 0 {
					if j := bytes.IndexByte(buf[i:], '\n'); j >= 0 {
						ready <- strings.TrimSpace(string(buf[:i+j]))
						io.Copy(io.Discard, stderr) // keep draining so the pipe never blocks
						return
					}
				}
			}
			if rerr != nil {
				errs <- fmt.Errorf("relay exited before readiness: %v (stderr: %s)", rerr, buf)
				return
			}
		}
	}()
	return ready, errs
}

// fabricRustBinLocal resolves the spore-peer binary (SPORE_PEER_BIN), skipping
// the test when absent. Relative values are interpreted from the repo root.
func fabricRustBinLocal(t *testing.T) string {
	t.Helper()
	exe := os.Getenv("SPORE_PEER_BIN")
	if exe == "" {
		t.Skip("SPORE_PEER_BIN not set — cross-binary fabric interop skipped")
	}
	if _, err := os.Stat(exe); err != nil {
		if !filepath.IsAbs(exe) {
			if abs, aerr := filepath.Abs(filepath.Join("..", "..", exe)); aerr == nil {
				if _, err2 := os.Stat(abs); err2 == nil {
					return abs
				}
			}
		}
		t.Skipf("SPORE_PEER_BIN=%s not found: %v", exe, err)
	}
	return exe
}

func TestFabricSubscribeCrossBinary(t *testing.T) {
	rustBin := fabricRustBinLocal(t)

	dir := t.TempDir()
	relayHold := filepath.Join(dir, "relay-hold")
	// The relay's hold dir must pre-exist (same contract the Rust smoke's
	// smoke_dir honors; serve reads, it does not create).
	if err := os.MkdirAll(relayHold, 0o755); err != nil {
		t.Fatal(err)
	}

	// --- 1. Real Rust relay on an ephemeral port --------------------------
	// (The Rust CLI takes --long flags; -fabric is the documented short.)
	relay := exec.Command(rustBin, "serve", "--dir", relayHold, "--listen", "127.0.0.1:0", "-fabric")
	ready, errs := fabricWaitReadyLocal(t, relay, "listening on")
	t.Cleanup(func() { _ = relay.Process.Kill() })
	var relayAddr string
	select {
	case line := <-ready:
		// serve prints: "spore-peer serve: listening on <addr>, bodies in ..."
		// Parse the addr out by the "listening on" marker, not word position.
		const marker = "listening on "
		if i := strings.Index(line, marker); i >= 0 {
			rest := line[i+len(marker):]
			if j := strings.IndexAny(rest, ", \t"); j >= 0 {
				rest = rest[:j]
			}
			relayAddr = strings.TrimSpace(rest)
		}
		if relayAddr == "" {
			t.Fatalf("unreadable readiness line: %s", line)
		}
	case err := <-errs:
		t.Fatalf("rust relay failed to start: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("rust relay readiness timeout")
	}
	t.Logf("rust relay at %s", relayAddr)
	// The port must actually answer before anything else proceeds.
	conn, err := net.DialTimeout("tcp", relayAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("relay addr %s not dialable: %v", relayAddr, err)
	}
	conn.Close()

	// --- 2. Go receiver: real kit, real sporepeer:// hold ------------------
	recvID := make([]byte, 32)
	recvSPK := make([]byte, 32)
	var recvOPK [32]byte
	for i := 0; i < 32; i++ {
		recvID[i], recvSPK[i] = byte(0x21), byte(0x22)
		recvOPK[i] = 0x23
	}
	recvSig, err := secure.SigPubOf(recvID)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ratchet.BuildBundle(recvID, recvSPK, 1, &recvOPK, 1)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := peerstore.NewSporePeerStore(peerstore.SporePeerConfig{
		Dir:    filepath.Join(dir, "hold"),
		Listen: "127.0.0.1:0",
	})
	if err != nil {
		t.Skipf("sporepeer store unavailable here: %v", err)
	}
	t.Cleanup(func() { _ = hold.Close() })
	states, err := ratchetwire.NewFileStateStore(filepath.Join(dir, "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	recvEP, err := ratchetwire.NewDurableEndpointWithExpiry(hold, states, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// --- 3. Go sender: real handshake + continuation -----------------------
	senderIK := make([]byte, 32)
	for i := range senderIK {
		senderIK[i] = 0x31
	}
	senderEP := ratchetwire.NewEndpoint(hold)
	ptr, _, sess, err := senderEP.SendFirstSession(senderIK, bundle, recvSig, []byte("handshake"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	initFrame, err := ratchetwire.FetchFrame(hold, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	initBody, err := ratchetwire.GetBody(hold, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recvEP.ReceiveFirst(recvID, recvSPK, &recvOPK, initFrame, initBody); err != nil {
		t.Fatal(err)
	}
	_, raw, err := senderEP.SendNext(sess, []byte("fabric says hi"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// --- 4. Publish to the REAL relay (-route-fabric's exact act) ----------
	// Production roles: the RECIPIENT's subscribe is the registrant; the
	// sender only fputs. So the real binary registers first (its first tick),
	// and the test publishes once the handle is live — polling past the
	// relay's correct 404 for an as-yet-unregistered handle.
	seed := [32]byte{0xF2, 0x0A}
	handle, err := fabric.FabricHandle(seed, 1, sess)
	if err != nil {
		t.Fatal(err)
	}

	// --- 5. REAL `spore fabric subscribe` drains and ingests ---------------
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	writeHex := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(hex.EncodeToString(b)), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	seedFile := writeHex("seed.hex", seed[:])
	idFile := writeHex("id.hex", recvID)
	spkFile := writeHex("spk.hex", recvSPK)
	stateKeyFile := writeHex("statekey.hex", make([]byte, 32))
	maildbPath := filepath.Join(dir, "mail.json")

	// The receiver's durable state dir must hold the session the drain
	// derives handles from: share the receiver's state directory.
	stateDir := filepath.Join(dir, "state")

	svc := exec.Command(sporeBinLocal(t), "fabric", "subscribe",
		"-identity", idFile, "-spk", spkFile,
		// The receiver IS the body store here (the hold already contains the
		// frame body the drained pointer names); a self-directed sporepeer://
		// URL satisfies the store-required validation without a remote hop.
		"-store", "sporepeer://127.0.0.1:1", "-store-dir", filepath.Join(dir, "hold"),
		"-state-dir", stateDir, "-state-key", stateKeyFile,
		"-maildb", maildbPath,
		"-fabric-seed-file", seedFile,
		"-fabric-relay", relayAddr,
		"-fabric-epoch", "1",
		"-fabric-lease", "1h",
		"-fabric-interval", "250ms",
	)
	svcEnv := append(os.Environ(),
		"SPORE_HOME="+home,
		// Hermeticity: never let the operator's real ~/.spore/config.json
		// inject flags into the subscribe run.
		"SPORE_CONFIG="+filepath.Join(dir, "absent-config.json"),
	)
	svc.Env = svcEnv
	var svcOut bytes.Buffer
	svc.Stdout = &svcOut
	svc.Stderr = &svcOut
	if err := svc.Start(); err != nil {
		t.Fatalf("start real fabric subscribe: %v", err)
	}
	t.Cleanup(func() { _ = svc.Process.Kill() })

	// Sender-side publish: retry until the recipient's registration lands
	// (the relay's 404 is the correct "handle not live yet" signal).
	pubCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		perr := fabric.PublishAs(pubCtx, relayAddr, hex.EncodeToString(handle[:]), raw, time.Now().Add(time.Hour))
		if perr == nil {
			break
		}
		if !strings.Contains(perr.Error(), "404") {
			t.Fatalf("publish to real relay: %v", perr)
		}
		if pubCtx.Err() != nil {
			t.Fatalf("recipient never registered at the relay (publish kept 404ing): %v\nsubscribe output:\n%s", perr, svcOut.String())
		}
		time.Sleep(200 * time.Millisecond)
	}

	// The real pipeline must deliver: poll the subscribe binary's maildb.
	deadline := time.Now().Add(20 * time.Second)
	for {
		db, oerr := maildb.Open(maildbPath)
		if oerr == nil {
			if hits := db.SearchSimple("fabric says hi"); len(hits) == 1 {
				t.Logf("cross-binary delivery confirmed; subscribe output:\n%s", svcOut.String())
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("fabric subscribe never delivered the message\nsubscribe output:\n%s", svcOut.String())
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// sporeBinLocal locates the Go spore binary to invoke as the real client.
// In gates the prebuilt binary is used; in ad-hoc runs the test builds it
// once into a temp dir.
func sporeBinLocal(t *testing.T) string {
	t.Helper()
	if exe := os.Getenv("SPORE_BIN"); exe != "" {
		if _, err := os.Stat(exe); err == nil {
			return exe
		}
		t.Skipf("SPORE_BIN=%s not found", exe)
	}
	exe := filepath.Join(t.TempDir(), "spore-test-bin")
	build := exec.Command("go", "build", "-o", exe, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build for cross-binary test: %v\n%s", err, out)
	}
	return exe
}
