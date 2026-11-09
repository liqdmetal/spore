// doctor --tor — which carriers answer through a SOCKS5 proxy, by body.
//
// docs/ONBOARDING.md's carrier table began as mechanism reasoning (⚠️ "should
// work over Tor"), was replaced on 2026-11-09 by measurements taken on one
// circuit, and the honest complaint about that replacement is that a reader
// still has to trust it. This runs the same measurement from the binary: every
// endpoint is dialed through a SOCKS5 proxy — Tor's SocksPort by default — and
// the verdict is parsed from the response BODY.
//
// Status codes are not evidence, and the three ways they mislead are the whole
// reason this file parses bodies:
//
//	mainnet.base.org   200, but the body is a Cloudflare challenge page
//	api.trongrid.io    403 to a bare curl user-agent, a real block to the client's
//	mempool.space      fails direct as well, so it is not a Tor finding at all
//
//	spore doctor -tor
//	spore doctor -tor -tor-proxy 127.0.0.1:9150 -tor-timeout 20s
//
// No authentication is offered to the proxy: Tor's SocksPort has none, and a
// proxy that wants a password is a different tool. The carrier rows here mirror
// the rows in docs/ONBOARDING.md so the two cannot drift quietly: a carrier
// added to the table gets a probe here, or the table is claiming something the
// binary cannot re-measure.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// socks5Dialer returns a DialContext func that opens every TCP connection
// through proxyAddr (host:port) with a SOCKS5 CONNECT. Only CONNECT and the
// no-auth method are implemented: that is the whole of what Tor exposes on a
// SocksPort, and a partial client that silently fell back to a direct dial
// would report a green table for traffic that never touched the proxy.
func socks5Dialer(proxyAddr string, timeout time.Duration) (func(context.Context, string, string) (net.Conn, error), error) {
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		return nil, fmt.Errorf("proxy address %q is not host:port: %v", proxyAddr, err)
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, fmt.Errorf("socks5: unsupported network %q (Tor carries TCP only)", network)
		}
		c, err := d.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("dial proxy %s: %v", proxyAddr, err)
		}
		deadline := time.Now().Add(timeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = c.SetDeadline(deadline)
		if err := socks5Connect(c, addr); err != nil {
			c.Close()
			return nil, err
		}
		_ = c.SetDeadline(time.Time{})
		return c, nil
	}, nil
}

// socks5Connect performs the greeting and the CONNECT request on an already
// dialed connection to the proxy.
func socks5Connect(c net.Conn, addr string) error {
	// Greeting: version 5, one method offered, method 0 (no auth).
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("socks5: greeting: %v", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		return fmt.Errorf("socks5: greeting reply: %v", err)
	}
	if greet[0] != 0x05 {
		return fmt.Errorf("socks5: proxy answered version 0x%02x — that is not SOCKS5 (HTTP proxy?)", greet[0])
	}
	if greet[1] != 0x00 {
		return fmt.Errorf("socks5: proxy requires authentication (method 0x%02x); -tor-proxy takes an open SocksPort only", greet[1])
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("socks5: destination %q is not host:port: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("socks5: destination port %q is invalid", portStr)
	}

	req := []byte{0x05, 0x01, 0x00} // version, CONNECT, reserved
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("socks5: destination host %q cannot be sent as a domain name", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return fmt.Errorf("socks5: CONNECT request: %v", err)
	}

	// Reply: version, status, reserved, address type, address, port.
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return fmt.Errorf("socks5: CONNECT reply: %v", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks5: CONNECT reply has version 0x%02x", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: proxy refused CONNECT to %s: %s", addr, socks5ErrText(head[1]))
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return fmt.Errorf("socks5: CONNECT reply address: %v", err)
		}
		skip = int(n[0])
	default:
		return fmt.Errorf("socks5: CONNECT reply has unknown address type 0x%02x", head[3])
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip)+2); err != nil {
		return fmt.Errorf("socks5: CONNECT reply address/port: %v", err)
	}
	return nil
}

// socks5ErrText names the failure instead of printing a bare number: a user
// seeing "code 4" learns nothing, and code 4 under Tor usually means the
// destination refuses Tor exits rather than that the proxy is broken.
func socks5ErrText(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable (the destination may refuse Tor exits)"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("status 0x%02x", code)
	}
}

// torProbe is one carrier endpoint and the evidence that it really answered.
type torProbe struct {
	Name     string
	Method   string
	URL      string
	Body     string
	Evidence func(status int, body []byte) (string, error)
}

// torCarrierProbes mirrors docs/ONBOARDING.md §"Which carriers actually work
// over Tor", plus an exit check so the report says which circuit produced it.
func torCarrierProbes(storeURL string) []torProbe {
	probes := []torProbe{
		{Name: "circuit", Method: http.MethodGet, URL: "https://check.torproject.org/api/ip", Evidence: evidenceTorCircuit},
		{Name: "evm-base", Method: http.MethodPost, URL: "https://mainnet.base.org",
			Body:     `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`,
			Evidence: evidenceEVMChainID("0x2105")},
		{Name: "solana", Method: http.MethodPost, URL: "https://api.mainnet-beta.solana.com",
			Body:     `{"jsonrpc":"2.0","id":1,"method":"getHealth"}`,
			Evidence: evidenceSolanaHealth},
		{Name: "tron", Method: http.MethodPost, URL: "https://api.trongrid.io/wallet/getnowblock",
			Body:     `{}`,
			Evidence: evidenceTronBlock},
		{Name: "bitcoin", Method: http.MethodGet, URL: "https://blockstream.info/api/blocks/tip/height",
			Evidence: evidenceTipHeight},
		{Name: "cosmos", Method: http.MethodGet, URL: "https://cosmos-rest.publicnode.com/cosmos/base/tendermint/v1beta1/node_info",
			Evidence: evidenceCosmosNodeInfo},
		{Name: "ton", Method: http.MethodGet, URL: "https://toncenter.com/api/v2/getMasterchainInfo",
			Evidence: evidenceTONMasterchain},
		{Name: "nostr", Method: http.MethodGet, URL: "https://relay.damus.io/",
			Evidence: evidenceNostrRelay},
	}
	if storeURL != "" {
		// An all-zero CID cannot exist, so the interesting answers are 404
		// (route live, and honest about a miss) versus 200 (that is not a body
		// store) versus 401/403 (live but this client is not authorized).
		probes = append(probes, torProbe{
			Name: "mailbox", Method: http.MethodGet,
			URL:      strings.TrimRight(storeURL, "/") + "/body/" + strings.Repeat("0", 64),
			Evidence: evidenceMailboxRoute,
		})
	}
	return probes
}

func jsonRPCResult(body []byte) (json.RawMessage, error) {
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("body is not JSON-RPC (a challenge page or an HTML error is not a chain answer): %.60q", string(body))
	}
	if env.Error != nil {
		return nil, fmt.Errorf("node returned an error: %s", env.Error.Message)
	}
	if len(env.Result) == 0 {
		return nil, fmt.Errorf("no result in the JSON-RPC answer")
	}
	return env.Result, nil
}

func evidenceTorCircuit(_ int, body []byte) (string, error) {
	var r struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.IP == "" {
		return "", fmt.Errorf("cannot read the exit check: %.60q", string(body))
	}
	if !r.IsTor {
		// Reachable, and honest about what it is: results then describe this
		// proxy, not Tor, and the table makes Tor-specific claims.
		return fmt.Sprintf("exit %s — NOT a Tor exit (IsTor=false): these results describe that proxy, not Tor", r.IP), nil
	}
	return "exit " + r.IP, nil
}

func evidenceEVMChainID(want string) func(int, []byte) (string, error) {
	return func(_ int, body []byte) (string, error) {
		raw, err := jsonRPCResult(body)
		if err != nil {
			return "", err
		}
		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			return "", fmt.Errorf("chainId is not a string: %s", raw)
		}
		if got != want {
			return "", fmt.Errorf("chainId %s, want %s — not Base (check the endpoint, not Tor)", got, want)
		}
		return "eth_chainId " + got + " (Base mainnet)", nil
	}
}

func evidenceSolanaHealth(_ int, body []byte) (string, error) {
	raw, err := jsonRPCResult(body)
	if err != nil {
		return "", err
	}
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		return "", fmt.Errorf("getHealth result is not a string: %s", raw)
	}
	if got != "ok" {
		return "", fmt.Errorf("getHealth returned %q, want ok", got)
	}
	return "getHealth ok", nil
}

func evidenceTronBlock(status int, body []byte) (string, error) {
	var r struct {
		BlockID string `json:"blockID"`
		Error   string `json:"Error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		// TronGrid answers 403 to a plain curl user-agent; the client's own
		// Go user-agent is accepted. Distinguish the two in the message.
		return "", fmt.Errorf("HTTP %d, body is not a block: %.60q (TronGrid rejects some user-agents — check the UA before blaming Tor)", status, string(body))
	}
	if r.Error != "" {
		return "", fmt.Errorf("TronGrid error: %s", r.Error)
	}
	if len(r.BlockID) != 64 {
		return "", fmt.Errorf("blockID is %d chars, want 64 — that is not a block", len(r.BlockID))
	}
	return "block " + r.BlockID[:12] + "…", nil
}

func evidenceTipHeight(status int, body []byte) (string, error) {
	s := strings.TrimSpace(string(body))
	h, err := strconv.Atoi(s)
	if err != nil || h <= 0 {
		return "", fmt.Errorf("HTTP %d, tip height is not a positive integer: %.40q", status, s)
	}
	return fmt.Sprintf("esplora tip %d", h), nil
}

func evidenceCosmosNodeInfo(_ int, body []byte) (string, error) {
	var r struct {
		NodeInfo struct {
			Network string `json:"network"`
			Moniker string `json:"moniker"`
		} `json:"node_info"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.NodeInfo.Network == "" {
		return "", fmt.Errorf("body has no node_info.network: %.60q", string(body))
	}
	return "node_info " + r.NodeInfo.Network + " (" + r.NodeInfo.Moniker + ")", nil
}

func evidenceTONMasterchain(status int, body []byte) (string, error) {
	var r struct {
		OK     bool `json:"ok"`
		Result struct {
			Last struct {
				Seqno int64 `json:"seqno"`
			} `json:"last"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("HTTP %d, body is not toncenter JSON: %.60q", status, string(body))
	}
	if !r.OK || r.Result.Last.Seqno <= 0 {
		return "", fmt.Errorf("toncenter did not report a masterchain block (ok=%v)", r.OK)
	}
	return fmt.Sprintf("masterchain seqno %d", r.Result.Last.Seqno), nil
}

func evidenceNostrRelay(status int, body []byte) (string, error) {
	low := strings.ToLower(string(body))
	if status != http.StatusOK || !strings.Contains(low, "nostr") {
		return "", fmt.Errorf("HTTP %d, body does not look like a nostr relay: %.60q", status, string(body))
	}
	return "relay answered (nostr)", nil
}

func evidenceMailboxRoute(status int, body []byte) (string, error) {
	switch status {
	case http.StatusNotFound:
		return "route live (unknown CID answered 404)", nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", fmt.Errorf("route exists but refused this client (HTTP %d) — pass -store-token", status)
	case http.StatusOK:
		return "", fmt.Errorf("answered 200 for an all-zero CID — this is not behaving like a body store: %.40q", string(body))
	default:
		return "", fmt.Errorf("unexpected HTTP %d: %.40q", status, string(body))
	}
}

// doctorTorOpts configures the proxy run.
type doctorTorOpts struct {
	Proxy    string
	Timeout  time.Duration
	Store    string
	StoreTok string
}

// runTorDoctor probes every carrier through the proxy. A carrier that does not
// answer with the real payload FAILS the run: this check exists to be measured
// again, so a green report must mean the table still holds on this circuit.
func runTorDoctor(o doctorTorOpts) []doctorCheck {
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	dial, err := socks5Dialer(o.Proxy, o.Timeout)
	if err != nil {
		return []doctorCheck{{Name: "tor-proxy", OK: false, Note: err.Error()}}
	}
	tr := &http.Transport{
		DialContext:           dial,
		TLSHandshakeTimeout:   o.Timeout,
		ResponseHeaderTimeout: o.Timeout,
		DisableKeepAlives:     true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: o.Timeout}

	var out []doctorCheck
	for _, p := range torCarrierProbes(o.Store) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
		req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, strings.NewReader(p.Body))
		if err != nil {
			cancel()
			out = append(out, doctorCheck{Name: p.Name, OK: false, Note: fmt.Sprintf("request: %v", err)})
			continue
		}
		if p.Body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if p.Name == "mailbox" && o.StoreTok != "" {
			req.Header.Set("Authorization", "Bearer "+o.StoreTok)
		}
		resp, err := client.Do(req)
		elapsed := time.Since(start)
		if err != nil {
			cancel()
			out = append(out, doctorCheck{Name: p.Name, OK: false,
				Note: fmt.Sprintf("no answer through %s: %v", o.Proxy, err)})
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		cancel()
		if rerr != nil {
			out = append(out, doctorCheck{Name: p.Name, OK: false,
				Note: fmt.Sprintf("HTTP %d but the body could not be read: %v", resp.StatusCode, rerr)})
			continue
		}
		evidence, eerr := p.Evidence(resp.StatusCode, body)
		if eerr != nil {
			out = append(out, doctorCheck{Name: p.Name, OK: false, Note: eerr.Error()})
			continue
		}
		out = append(out, doctorCheck{Name: p.Name, OK: true,
			Note: fmt.Sprintf("%s  (%dms)", evidence, elapsed.Milliseconds())})
	}
	return out
}
