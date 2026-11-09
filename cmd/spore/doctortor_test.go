package main

import (
	"encoding/binary"
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
		{"tron 403 html", evidenceTronBlock, 403, "<html>Forbidden</html>", false, "rejects some user-agents"},
		{"esplora tip", evidenceTipHeight, 200, "975197\n", true, "975197"},
		{"esplora html", evidenceTipHeight, 200, "<html>rate limited</html>", false, "not a positive integer"},
		{"cosmos node_info", evidenceCosmosNodeInfo, 200, `{"node_info":{"network":"cosmoshub-4","moniker":"n"}}`, true, "cosmoshub-4"},
		{"cosmos empty", evidenceCosmosNodeInfo, 200, `{}`, false, "no node_info"},
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
	names := map[string]bool{}
	for _, p := range torCarrierProbes("") {
		names[p.Name] = true
	}
	for _, want := range []string{"circuit", "evm-base", "solana", "tron", "bitcoin", "cosmos", "ton", "nostr"} {
		if !names[want] {
			t.Fatalf("carrier row %q has no probe — the table would claim what doctor cannot re-measure", want)
		}
	}
	if names["mailbox"] {
		t.Fatal("mailbox must only appear when -store names one")
	}
	withStore := false
	for _, p := range torCarrierProbes("https://host/u/alice/") {
		if p.Name == "mailbox" {
			withStore = true
			if !strings.HasSuffix(p.URL, "/body/"+strings.Repeat("0", 64)) {
				t.Fatalf("mailbox probe URL = %q", p.URL)
			}
		}
	}
	if !withStore {
		t.Fatal("mailbox probe missing with -store")
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
