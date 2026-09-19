package peerstore

// Cross-binary fabric interop: the pointer-forwarding half of the relay
// fabric, exercised with BOTH implementations playing BOTH client roles
// against the real Rust relay (F1 scoped the fabric relay to the
// spore-peer binary; the Go side is the F2 client face).
//
//	TestGoFabricPublishRustFabricDrain   — Go client (fabricFrame over the
//	                                      §5 JSON verbs) registers and
//	                                      publishes; the real Rust CLI drains
//	                                      with the possession token.
//	TestRustFabricPublishGoFabricDrain   — real Rust CLI publishes; the Go
//	                                      client drains and verifies
//	                                      compost-on-read and the verbatim
//	                                      403 takeover refusal.
//	TestFabricHandleDerivationMatchesVectors — the derivation equivalence
//	                                      that makes shared-seed handoff
//	                                      meaningful (Go computes the handle
//	                                      a Rust relay indexes).
//
// All of these skip when SPORE_PEER_BIN is absent, so plain `go test ./...`
// stays hermetic; gates.sh sets the env var after building the Rust binary,
// and RACE_PKGS already includes this package, so the pre-push -race gate
// runs them against a freshly built binary every time.

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/fabric"
)

// fabricRustBin wraps the package's SPORE_PEER_BIN resolution with one
// convenience: `go test` runs from the PACKAGE directory, so a RELATIVE
// SPORE_PEER_BIN (as typed in an ad-hoc shell command) is interpreted
// against the repo root two levels up, where relative paths are naturally
// written. Absolute values and PATH lookups fall through unchanged.
func fabricRustBin(t *testing.T) string {
	if exe := os.Getenv("SPORE_PEER_BIN"); exe != "" && !filepath.IsAbs(exe) {
		if abs, err := filepath.Abs(filepath.Join("..", "..", exe)); err == nil {
			if _, statErr := os.Stat(abs); statErr == nil {
				t.Setenv("SPORE_PEER_BIN", abs)
			}
		}
	}
	return rustPeerBin(t)
}

// runFabricCLI runs one `spore-peer fabric` client invocation. Returns
// stdout, stderr, and the exit error (nil on success).
func runFabricCLI(t *testing.T, exe string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(exe, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// fabricFrame is the §5 JSON frame exchange: LE32 length + JSON request,
// LE32 length + 0x00/0x01-prefixed response.
func fabricFrame(t *testing.T, conn net.Conn, req map[string]any) (byte, map[string]any) {
	t.Helper()
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(payload)))
	if _, err := conn.Write(lenBuf); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		t.Fatalf("read reply length: %v", err)
	}
	n := binary.LittleEndian.Uint32(lenBuf)
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read reply body: %v", err)
	}
	body := map[string]any{}
	_ = json.Unmarshal(buf[1:], &body)
	return buf[0], body
}

// smokePointer builds a §2-shaped 74-byte pointer payload, hex-encoded:
// `01 00 | Route 32 | CID 32 | BurnDeadline u64 LE`.
func smokePointer(t *testing.T, deadline uint64, tag byte) string {
	t.Helper()
	p := make([]byte, 0, 74)
	p = append(p, 1, 0)
	for i := 0; i < 32; i++ {
		p = append(p, tag)
	}
	for i := 0; i < 32; i++ {
		p = append(p, 0xA5+tag)
	}
	var le [8]byte
	binary.LittleEndian.PutUint64(le[:], deadline)
	p = append(p, le[:]...)
	return hex.EncodeToString(p)
}

const fabricSmokeToken = "tok-1234567890abcdef" // 20 bytes: within the 16..=128 shape

// TestGoFabricPublishRustFabricDrain: the Go client face (the F2 client
// skeleton) registers a handle and publishes a pointer to the REAL Rust
// relay; the real Rust CLI then drains it using the same possession token.
// The recipient's drain output must equal the published pointer
// byte-for-byte, and a takeover attempt against the Go-registered handle
// must fail with the verbatim 403 — the relay serves implementations
// identically.
func TestGoFabricPublishRustFabricDrain(t *testing.T) {
	exe := fabricRustBin(t)
	dir := t.TempDir()

	relay := startRustFabricRelay(t, exe, dir)
	defer relay.Stop(t)

	handle := strings.Repeat("ab", 32)
	future := uint64(time.Now().Unix()) + 600
	ptr := smokePointer(t, future, 1)

	// Go client face: reg + put.
	conn, err := net.DialTimeout("tcp", relay.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	st, body := fabricFrame(t, conn, map[string]any{
		"verb": "freg", "handle": handle, "token": fabricSmokeToken, "lease": 60,
	})
	if st != 0x00 {
		t.Fatalf("go freg status %#x body %v", st, body)
	}
	st, body = fabricFrame(t, conn, map[string]any{
		"verb": "fput", "handle": handle, "pointer_hex": ptr, "deadline": future,
	})
	if st != 0x00 {
		t.Fatalf("go fput status %#x body %v", st, body)
	}

	// Cross-implementation takeover: the real Rust CLI re-registering the
	// Go-registered handle (no prev_token) must fail with 403 verbatim.
	_, stderr, err := runFabricCLI(t, exe, "fabric", "--addr", relay.addr,
		"--sub", "reg", "--handle", handle, "--token", "attacker-token-123456", "--lease", "60")
	if err == nil {
		t.Fatal("rust CLI takeover of a go-registered handle must fail")
	} else if !strings.Contains(stderr, "403") {
		t.Fatalf("takeover stderr = %q, want the verbatim 403 refusal", stderr)
	}

	// The recipient drains with the real Rust CLI, holding the possession
	// token (in production: derived from the shared seed).
	stdout, stderr, err := runFabricCLI(t, exe, "fabric", "--addr", relay.addr,
		"--sub", "pop", "--handle", handle, "--token", fabricSmokeToken)
	if err != nil {
		t.Fatalf("rust fabric pop: %v (stderr: %s)", err, stderr)
	}
	if strings.TrimSpace(stdout) != ptr {
		t.Fatalf("drained pointer = %q, want %q", strings.TrimSpace(stdout), ptr)
	}

	// Compost-on-read is implementation-independent: the Go client's second
	// drain is empty too.
	st, body = fabricFrame(t, conn, map[string]any{
		"verb": "fpop", "handle": handle, "token": fabricSmokeToken, "max": 8,
	})
	if st != 0x00 {
		t.Fatalf("second go fpop status %#x", st)
	}
	if got, _ := body["pointers"].([]any); len(got) != 0 {
		t.Fatalf("second drain returned %v, want empty", got)
	}
}

// rustFabricRelay spawns the real `spore-peer serve -fabric` binary on a
// loopback port and waits for its "listening on" announcement (the bound
// address), reusing the readiness convention the Rust smoke test pins.
type rustFabricRelay struct {
	cmd  *exec.Cmd
	addr string
	// leak reporting when the server writes stderr lines we never parse.
	stderrPath string
}

func startRustFabricRelay(t *testing.T, exe, dir string) *rustFabricRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close() // close race is acceptable on loopback for a smoke

	stderrPath := filepath.Join(dir, "serve.stderr.log")
	errF, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exe, "serve", "--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--dir", dir, "-fabric")
	cmd.Stderr = errF
	if err := cmd.Start(); err != nil {
		errF.Close()
		t.Fatal(err)
	}
	errF.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, derr := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if derr == nil {
			conn.Close()
			return &rustFabricRelay{cmd: cmd, addr: addr, stderrPath: stderrPath}
		}
	}
	log, _ := os.ReadFile(stderrPath)
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	t.Fatalf("rust relay did not come up at %s; stderr: %s", addr, log)
	return nil
}

func (r *rustFabricRelay) Stop(t *testing.T) {
	t.Helper()
	_ = r.cmd.Process.Kill()
	_, _ = r.cmd.Process.Wait()
}

// TestRustFabricPublishGoFabricDrain: the real Rust CLI publishes through
// the real Rust relay, and the GO client drains — the recipient-relay
// direction with each side played by a different implementation. The Go
// drain must see the published pointer, refuse a wrong token with 403, and
// observe compost-on-read.
func TestRustFabricPublishGoFabricDrain(t *testing.T) {
	exe := fabricRustBin(t)
	dir := t.TempDir()

	relay := startRustFabricRelay(t, exe, dir)
	defer relay.Stop(t)

	handle := strings.Repeat("cd", 32)
	future := uint64(time.Now().Unix()) + 600
	ptr := smokePointer(t, future, 2)

	// reg + put through the real Rust CLI (the sender's side).
	if _, stderr, err := runFabricCLI(t, exe, "fabric", "--addr", relay.addr,
		"--sub", "reg", "--handle", handle, "--token", fabricSmokeToken, "--lease", "60"); err != nil {
		t.Fatalf("rust fabric reg: %v (stderr: %s)", err, stderr)
	}
	if _, stderr, err := runFabricCLI(t, exe, "fabric", "--addr", relay.addr,
		"--sub", "put", "--handle", handle, "--pointer", ptr); err != nil {
		t.Fatalf("rust fabric put: %v (stderr: %s)", err, stderr)
	}

	// Drain with the GO client: the F2 client face over the §5 JSON verbs.
	conn, err := net.DialTimeout("tcp", relay.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Cross-implementation takeover: a Go freg on the Rust-registered handle
	// without prev_token must be refused (403) — possession is enforced
	// against non-Rust clients identically.
	st, _ := fabricFrame(t, conn, map[string]any{
		"verb": "freg", "handle": handle, "token": "attacker-token-123456", "lease": 60,
	})
	if st != 0x01 {
		t.Fatalf("go takeover freg status %#x, want 0x01 (403)", st)
	}

	// Wrong-token drain from the Go client must be refused with 403 — the
	// constant-time compare serves non-Rust clients identically.
	st, _ = fabricFrame(t, conn, map[string]any{
		"verb": "fpop", "handle": handle, "token": "wrong-token-12345", "max": 8,
	})
	if st != 0x01 {
		t.Fatalf("wrong-token fpop status %#x, want 0x01 (403)", st)
	}

	st, body := fabricFrame(t, conn, map[string]any{
		"verb": "fpop", "handle": handle, "token": fabricSmokeToken, "max": 8,
	})
	if st != 0x00 {
		t.Fatalf("go fpop status %#x body %v", st, body)
	}
	got, _ := body["pointers"].([]any)
	if len(got) != 1 {
		t.Fatalf("drained %d pointers, want 1 (%v)", len(got), body)
	}
	if got[0].(string) != ptr {
		t.Fatalf("drained pointer %q, want %q", got[0].(string), ptr)
	}

	// Compost-on-read: second Go drain is empty.
	st, body = fabricFrame(t, conn, map[string]any{
		"verb": "fpop", "handle": handle, "token": fabricSmokeToken, "max": 8,
	})
	if st != 0x00 {
		t.Fatalf("second go fpop status %#x", st)
	}
	if got, _ := body["pointers"].([]any); len(got) != 0 {
		t.Fatalf("second drain returned %v, want empty", got)
	}
}

// TestFabricHandleDerivationMatchesVectors closes the derivation loop: the
// Go client face derives the same handle the Rust relay indexes by, from
// (seed, epoch, sid), matching the pinned fabric_v1 vector. This is the
// property that lets a Go sender publish to a handle a Rust recipient
// drains without ever sharing the seed with the relay.
func TestFabricHandleDerivationMatchesVectors(t *testing.T) {
	v := loadFabricVectors(t)

	seedB, err := hex.DecodeString(v.seedHex)
	if err != nil {
		t.Fatal(err)
	}
	var seed [32]byte
	copy(seed[:], seedB)

	handle, err := fabric.FabricHandle(seed, v.epoch, v.sid)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(handle[:]) != v.handleHex {
		t.Fatalf("derived handle %s, vector says %s", hex.EncodeToString(handle[:]), v.handleHex)
	}

	// The reg token derivation (HMAC over label||handle||nonce) must agree
	// byte-for-byte as well — the Rust client computes the same token.
	tok := fabric.RegToken(seed, handle, v.nonce)
	if !hmac.Equal([]byte(tok), []byte(v.regTokenHex)) {
		t.Fatalf("derived reg token %s, vector says %s", tok, v.regTokenHex)
	}
}

// fabricVectors is the fabric_v1 slice of docs/interop-vectors.json.
type fabricVectors struct {
	seedHex     string
	epoch       uint32
	sid         [8]byte
	nonce       string
	handleHex   string
	regTokenHex string
}

// loadFabricVectors locates and decodes the fabric_v1 vector section the
// same way internal/secure's conformance tests do.
func loadFabricVectors(t *testing.T) fabricVectors {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "interop-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("interop-vectors.json not found (%v) — conformance runs from the repo root checkout", err)
	}
	var doc struct {
		Fabric struct {
			SeedHex     string `json:"seed_hex"`
			Epoch       string `json:"epoch"` // JSON string in the vector file
			SidHex      string `json:"sid_hex"`
			Nonce       string `json:"reg_server_nonce"`
			HandleHex   string `json:"handle_hex"`
			RegTokenHex string `json:"reg_token_hex"`
		} `json:"fabric_v1"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	f := doc.Fabric
	epoch64, err := strconv.ParseUint(f.Epoch, 10, 32)
	if err != nil {
		t.Fatalf("bad epoch %q: %v", f.Epoch, err)
	}
	var sid [8]byte
	sidB, err := hex.DecodeString(f.SidHex)
	if err != nil || len(sidB) != 8 {
		t.Fatalf("bad sid_hex %q: %v", f.SidHex, err)
	}
	copy(sid[:], sidB)
	return fabricVectors{
		seedHex:     f.SeedHex,
		epoch:       uint32(epoch64),
		sid:         sid,
		nonce:       f.Nonce,
		handleHex:   f.HandleHex,
		regTokenHex: f.RegTokenHex,
	}
}
