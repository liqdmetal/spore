// status — the spore HUD: connection health at a glance.
//
//	spore status [-chain dero|evm|xmr|solana ...] [-mailbox ADDR] [-timeout 5s]
//
// Reports per configured chain whether the RPC/wallet endpoint is reachable,
// our address, and the current chain height — plus whether a mailbox (if one
// is configured/running) is serving. It is the "am I actually connected?"
// sanity check before you try to send or receive.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
)

// statusProbe is one connection's health result.
type statusProbe struct {
	name    string
	ok      bool
	detail  string
	address string
	height  uint64
}

func statuscmd(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "per-connection probe timeout")
	mailboxHTTP := fs.String("mailbox-http", "", "optional running mailbox base URL (e.g. http://127.0.0.1:19292) to probe")
	addChainFlags(fs) // registers chain/rpc/rpc-login/from/keyfile/program/mailbox for msgBackend
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*2)
	defer cancel()

	var probes []statusProbe

	// Probe the chain backend selected via the shared chain flags.
	c := msgBackend(fs) // binds chain/rpc/from/keyfile/program/mailbox
	p := probeChain(ctx, c)
	probes = append(probes, p)

	// Optional mailbox HTTP probe.
	if *mailboxHTTP != "" {
		probes = append(probes, probeMailbox(ctx, *mailboxHTTP))
	}

	renderStatus(probes)
}

// probeChain checks one chain.Chain: reachable (Height succeeds) + address.
func probeChain(ctx context.Context, c chain.Chain) statusProbe {
	name := c.Name()
	sp := statusProbe{name: name}
	// Address first (cheap / local) — a reachable backend returns it.
	addrCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addr, aerr := c.Address(addrCtx)
	if aerr != nil {
		sp.ok = false
		sp.detail = fmt.Sprintf("address: %v", aerr)
		return sp
	}
	sp.address = addr

	// Height = the real "am I connected to a live node/chain" check.
	hctx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	h, herr := c.Height(hctx)
	if herr != nil {
		sp.ok = false
		sp.detail = fmt.Sprintf("node/chain: %v", herr)
		return sp
	}
	sp.height = h
	sp.ok = true
	sp.detail = "ok"
	return sp
}

// probeMailbox checks an always-on mailbox's HTTP surface is up.
func probeMailbox(ctx context.Context, base string) statusProbe {
	sp := statusProbe{name: "mailbox"}
	// The mailbox exposes /list (used by `mailbox list`). A 200/405 means it's
	// serving. We treat "got any HTTP response from the host" as reachable.
	url := base + "/list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		sp.ok = false
		sp.detail = err.Error()
		return sp
	}
	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		sp.ok = false
		sp.detail = fmt.Sprintf("unreachable: %v", err)
		return sp
	}
	defer resp.Body.Close()
	sp.ok = true
	sp.detail = fmt.Sprintf("serving (HTTP %d)", resp.StatusCode)
	return sp
}

// renderStatus prints the HUD.
func renderStatus(probes []statusProbe) {
	fmt.Println("spore status")
	fmt.Println("---------------")
	anyDown := false
	for _, p := range probes {
		mark := "✅"
		if !p.ok {
			mark = "❌"
			anyDown = true
		}
		line := fmt.Sprintf("  %s %-9s ", mark, p.name)
		if p.ok {
			line += fmt.Sprintf("ok  addr=%s  height=%d", truncMid(p.address, 22), p.height)
		} else {
			line += p.detail
		}
		fmt.Println(line)
	}
	fmt.Println("---------------")
	if anyDown {
		fmt.Println("some connections are DOWN — check your RPC/wallet/mailbox.")
		os.Exit(1)
	}
	fmt.Println("all connections healthy.")
}

func truncMid(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 8 {
		return s[:n]
	}
	return s[:n/2] + "…" + s[len(s)-(n/2):]
}
