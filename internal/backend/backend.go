// Package backend wires the concrete chain backends (dero, evm, xmr) behind a
// single lookup so the CLI can dispatch a message to any chain by name.
package backend

import (
	"context"
	"fmt"
	"strings"

	"github.com/liqdmetal/mycelium/internal/chain"
	"github.com/liqdmetal/mycelium/internal/dero"
	"github.com/liqdmetal/mycelium/internal/evm"
	"github.com/liqdmetal/mycelium/internal/xmr"
)

// ChainConfig describes how to build one chain backend.
type ChainConfig struct {
	// Type is one of "dero", "evm", "xmr".
	Type string
	// RPC is the wallet/daemon JSON-RPC endpoint.
	RPC string
	// Login is optional "user:pass" RPC auth.
	Login string
	// From is our address (EVM needs it; DERO/XMR query the wallet).
	From string
	// Name overrides the chain identifier (defaults to Type).
	Name string
}

// Build constructs the chain.Chain named by cfg.Type. Returns an error for an
// unknown or misconfigured type.
func Build(ctx context.Context, cfg ChainConfig) (chain.Chain, error) {
	switch strings.ToLower(cfg.Type) {
	case "dero":
		if cfg.RPC == "" {
			return nil, fmt.Errorf("dero backend needs -rpc (wallet RPC)")
		}
		user, pass := "", ""
		if i := strings.IndexByte(cfg.Login, ':'); i >= 0 {
			user, pass = cfg.Login[:i], cfg.Login[i+1:]
		}
		return dero.NewBackend(dero.NewClient(cfg.RPC, user, pass)), nil
	case "evm":
		if cfg.RPC == "" || cfg.From == "" {
			return nil, fmt.Errorf("evm backend needs -rpc and -from (your address)")
		}
		name := cfg.Name
		if name == "" {
			name = "evm"
		}
		return evm.NewBackend(cfg.RPC, name, cfg.From), nil
	case "xmr":
		if cfg.RPC == "" {
			return nil, fmt.Errorf("xmr backend needs -rpc (monero wallet RPC)")
		}
		return xmr.NewBackend(cfg.RPC), nil
	default:
		return nil, fmt.Errorf("unknown chain type %q (want dero|evm|xmr)", cfg.Type)
	}
}

// Supported lists the backend type names.
func Supported() []string { return []string{"dero", "evm", "xmr"} }
