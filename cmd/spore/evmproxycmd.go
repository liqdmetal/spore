// evm-proxy — thin CLI wrapper over internal/evm.Proxy (see that package for
// the design note: local EIP-155 signing for eth_sendTransaction in front of
// a read-only public RPC; everything else forwarded verbatim). Loopback-only
// listener: the key signs whatever eth_sendTransaction arrives, so the proxy
// must never be exposed.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/evm"
)

func evmProxyCmd(args []string) {
	fs := flag.NewFlagSet("evm-proxy", flag.ExitOnError)
	upstream := fs.String("rpc", "", "upstream EVM JSON-RPC endpoint (e.g. https://sepolia.base.org)")
	privKey := fs.String("private-key", "", "32-byte hex private key, funded (prefer SPORE_EVM_PRIVATE_KEY so the key stays out of shell history)")
	listen := fs.String("listen", "127.0.0.1:8555", "proxy listen address (loopback by default — do not expose)")
	_ = fs.Parse(args)

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "evm-proxy: -rpc required")
		fs.Usage()
		os.Exit(2)
	}
	keyHex := strings.TrimSpace(*privKey)
	if keyHex == "" {
		keyHex = strings.TrimSpace(os.Getenv("SPORE_EVM_PRIVATE_KEY"))
	}
	if keyHex == "" {
		fmt.Fprintln(os.Stderr, "evm-proxy: no key: pass -private-key or set SPORE_EVM_PRIVATE_KEY (32-byte hex, funded)")
		os.Exit(2)
	}
	proxy, err := evm.NewProxy(*upstream, keyHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "evm-proxy:", err)
		os.Exit(2)
	}
	listenHost, _, hostErr := net.SplitHostPort(*listen)
	if hostErr != nil || (listenHost != "127.0.0.1" && listenHost != "::1" && listenHost != "localhost") {
		fmt.Fprintln(os.Stderr, "evm-proxy: refusing to bind a non-loopback address:", *listen)
		os.Exit(2)
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           proxy.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Printf("spore evm-proxy: signing as %s\n", proxy.Signer())
	fmt.Printf("  upstream: %s\n", proxy.Upstream())
	fmt.Printf("  listen:   http://%s\n", *listen)
	fmt.Printf("use it:\n  spore msg send-e2 -chain evm -rpc http://%s -from %s ...\n", *listen, proxy.Signer())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "evm-proxy:", err)
		os.Exit(1)
	}
	fmt.Println("evm-proxy: shut down cleanly")
}
