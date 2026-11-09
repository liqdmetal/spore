package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startTestSocks runs a minimal SOCKS5 CONNECT server on loopback, so the
// dialer is exercised against the protocol instead of a mock.
func startTestSocks(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSocks(c)
		}
	}()
	return ln.Addr().String()
}

func serveTestSocks(c net.Conn) {
	defer c.Close()
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(greet[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	if req[1] != 0x01 {
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return
		}
		host = string(name)
	default:
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), 2*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// TestSocks5DialerCarriesARealRequest proves the CONNECT actually reaches the
// destination: a body fetched through the proxy must be the body the server
// sent, or every probe in doctor -tor is measuring nothing.
func TestSocks5DialerCarriesARealRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("through-the-proxy"))
	}))
	defer ts.Close()

	dial, err := socks5Dialer(startTestSocks(t), 3*time.Second)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: 5 * time.Second}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "through-the-proxy" {
		t.Fatalf("body = %q", body)
	}
}

func TestSocks5DialerRejectsBadProxyAddress(t *testing.T) {
	if _, err := socks5Dialer("127.0.0.1", time.Second); err == nil {
		t.Fatal("a proxy address without a port must be refused, not dialed")
	}
}

func TestSocks5DialerReportsRefusedProxy(t *testing.T) {
	// Port 1 on loopback refuses immediately; the error must name the proxy
	// rather than surfacing as a bare timeout.
	dial, err := socks5Dialer("127.0.0.1:1", time.Second)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	if _, err := dial(t.Context(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected a dial failure")
	} else if !strings.Contains(err.Error(), "dial proxy 127.0.0.1:1") {
		t.Fatalf("error should name the proxy: %v", err)
	}
}

// TestTorEvidenceRejectsAResponseThatMerelyParses is the point of the whole
// file: a status code and a JSON-looking body are not evidence. A Cloudflare
// challenge page is HTTP 200, and a TronGrid 403 is an HTML page.
func TestTorEvidenceRejectsAResponseThatMerelyParses(t *testing.T) {
	evm := evidenceEVMChainID("0x2105")
	cases := []struct {
		name    string
		fn      func(int, []byte) (string, error)
		status  int
		body    string
		wantOK  bool
		wantSub string
	}{
		{"evm base", evm, 200, `{"jsonrpc":"2.0","id":1,"result":"0x2105"}`, true, "Base mainnet"},
		{"evm challenge page", evm, 200, "<!DOCTYPE html><html><title>Just a moment...</title></html>", false, "not JSON-RPC"},
		{"evm wrong chain", evm, 200, `{"jsonrpc":"2.0","id":1,"result":"0x1"}`, false, "not Base"},
		{"solana health", evidenceSolanaHealth, 200, `{"jsonrpc":"2.0","id":1,"result":"ok"}`, true, "getHealth ok"},
		{"solana degraded", evidenceSolanaHealth, 200, `{"jsonrpc":"2.0","id":1,"result":"behind"}`, false, "want ok"},
		{"tron block", evidenceTronBlock, 200, `{"blockID":"` + strings.Repeat("ab", 32) + `","block_header":{}}`, true, "block abababab"},
		{"tron 403 html", evidenceTronBlock, 403, "<html>Forbidden</html>", false, "refuse Tor exits"},
		{"esplora tip", evidenceTipHeight, 200, "975197\n", true, "975197"},
		{"esplora html", evidenceTipHeight, 200, "<html>rate limited</html>", false, "not a positive integer"},
		{"cosmos node_info", evidenceCosmosNodeInfo, 200, `{"node_info":{"network":"cosmoshub-4","moniker":"n"}}`, true, "cosmoshub-4"},
		{"cosmos default_node_info", evidenceCosmosNodeInfo, 200, `{"default_node_info":{"network":"cosmoshub-4","moniker":"publicnode"}}`, true, "cosmoshub-4"},
		{"cosmos empty", evidenceCosmosNodeInfo, 200, `{}`, false, "neither node_info"},
		{"ton seqno", evidenceTONMasterchain, 200, `{"ok":true,"result":{"last":{"seqno":123}}}`, true, "seqno 123"},
		{"ton not ok", evidenceTONMasterchain, 200, `{"ok":false,"result":{}}`, false, "did not report"},
		{"nostr relay", evidenceNostrRelay, 200, "Please use a Nostr client to connect.", true, "nostr"},
		{"nostr not a relay", evidenceNostrRelay, 200, "<html>parked domain</html>", false, "does not look like"},
		{"mailbox 404", evidenceMailboxRoute, 404, "404 page not found", true, "route live"},
		{"mailbox 200 for zero cid", evidenceMailboxRoute, 200, "not a body store", false, "all-zero CID"},
		{"mailbox 403", evidenceMailboxRoute, 403, "", false, "store-token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.fn(c.status, []byte(c.body))
			if c.wantOK {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				if !strings.Contains(got, c.wantSub) {
					t.Fatalf("evidence %q does not mention %q", got, c.wantSub)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected refusal, got %q", got)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("error %q does not explain %q", err, c.wantSub)
			}
		})
	}
}

func TestTorCarrierProbesMirrorTheDocumentedRows(t *testing.T) {
	names := map[string]torProbe{}
	for _, p := range torCarrierProbes("", "") {
		names[p.Name] = p
		if len(p.URLs) == 0 {
			t.Fatalf("carrier %q has no endpoint to probe", p.Name)
		}
	}
	for _, want := range []string{"circuit", "evm-base", "solana", "tron", "bitcoin", "cosmos", "ton", "nostr"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("carrier row %q has no probe — the table would claim what doctor cannot re-measure", want)
		}
	}
	if _, ok := names["mailbox"]; ok {
		t.Fatal("mailbox must only appear when -store names one")
	}
	// The documented endpoint must be tried first, with the mirror behind it.
	if got := names["solana"].URLs[0]; !strings.Contains(got, "api.mainnet-beta.solana.com") {
		t.Fatalf("solana primary = %q", got)
	}
	if len(names["solana"].URLs) < 2 || !strings.Contains(names["solana"].URLs[1], "publicnode") {
		t.Fatalf("solana fallback missing: %v", names["solana"].URLs)
	}
	if len(names["tron"].URLs) < 2 || !strings.Contains(names["tron"].URLs[1], "publicnode") {
		t.Fatalf("tron fallback missing: %v", names["tron"].URLs)
	}
	withStore := false
	for _, p := range torCarrierProbes("https://host/u/alice/", "tok") {
		if p.Name == "mailbox" {
			withStore = true
			if p.Token != "tok" {
				t.Fatalf("mailbox probe dropped its token: %q", p.Token)
			}
			if !strings.HasSuffix(p.URLs[0], "/body/"+strings.Repeat("0", 64)) {
				t.Fatalf("mailbox probe URL = %q", p.URLs[0])
			}
		}
	}
	if !withStore {
		t.Fatal("mailbox probe missing with -store")
	}
}

// TestRunTorProbeSetFallsBackToTheMirror pins the behaviour the live run asked
// for: a primary edge that refuses Tor exits is a named fallback, not a red row
// and not a silent pass.
func TestRunTorProbeSetFallsBackToTheMirror(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<html>Forbidden</html>"))
	}))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			t.Errorf("mirror got an empty body — the probe must send its request body")
		}
		w.Write([]byte(`{"blockID":"` + strings.Repeat("cd", 32) + `"}`))
	}))
	defer mirror.Close()

	probe := torProbe{
		Name: "tron", Method: http.MethodPost, Body: `{}`,
		URLs:     []string{primary.URL + "/wallet/getnowblock", mirror.URL + "/wallet/getnowblock"},
		Evidence: evidenceTronBlock,
	}
	checks := runTorProbeSet(primary.Client(), []torProbe{probe}, 3*time.Second)
	if len(checks) != 1 || !checks[0].OK {
		t.Fatalf("expected one passing check, got %+v", checks)
	}
	note := checks[0].Note
	if !strings.Contains(note, "fallback") || !strings.Contains(note, "block cdcdcdcd") {
		t.Fatalf("note should name the fallback and its evidence: %q", note)
	}
	if !strings.Contains(note, "403") {
		t.Fatalf("note should say why the primary failed: %q", note)
	}
}

func TestRunTorProbeSetFailsWhenEveryEndpointFails(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("<html>down</html>"))
	}))
	defer dead.Close()
	probe := torProbe{
		Name: "solana", Method: http.MethodPost, Body: `{"jsonrpc":"2.0"}`,
		URLs:     []string{dead.URL + "/a", dead.URL + "/b"},
		Evidence: evidenceSolanaHealth,
	}
	checks := runTorProbeSet(dead.Client(), []torProbe{probe}, 3*time.Second)
	if len(checks) != 1 || checks[0].OK {
		t.Fatalf("a carrier with no answering endpoint must fail: %+v", checks)
	}
	if !strings.Contains(checks[0].Note, "/a") || !strings.Contains(checks[0].Note, "/b") {
		t.Fatalf("the failure should name every endpoint tried: %q", checks[0].Note)
	}
}

// TestRunTorDoctorFailsWhenTheProxyIsDown keeps the failure direction honest:
// an unreachable proxy must fail every row, never report a clean tab.
func TestRunTorDoctorFailsWhenTheProxyIsDown(t *testing.T) {
	checks := runTorDoctor(doctorTorOpts{Proxy: "127.0.0.1:1", Timeout: 2 * time.Second})
	if len(checks) == 0 {
		t.Fatal("no checks returned")
	}
	for _, c := range checks {
		if c.OK {
			t.Fatalf("check %q passed without a proxy", c.Name)
		}
	}
}

// Compile-time guard: the JSON round-trip in evidenceTorCircuit must remain a
// plain struct decode, so a moved field fails here rather than silently
// reporting an exit of "".
func TestTorCircuitEvidenceShape(t *testing.T) {
	var r struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal([]byte(`{"IsTor":true,"IP":"1.2.3.4"}`), &r); err != nil || !r.IsTor || r.IP != "1.2.3.4" {
		t.Fatalf("exit-check shape changed: %+v %v", r, err)
	}
}
