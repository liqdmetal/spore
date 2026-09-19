// Package backend wires the concrete chain backends (dero, evm, xmr) behind a
// single lookup so the CLI can dispatch a message to any chain by name.
package backend

import (
	"context"
	"fmt"
	"strings"

	"github.com/gagliardetto/solana-go"

	"github.com/liqdmetal/spore/internal/bitcoin"
	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/cosmos"
	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/evm"
	"github.com/liqdmetal/spore/internal/nostr"
	solanaBackend "github.com/liqdmetal/spore/internal/solana"
	"github.com/liqdmetal/spore/internal/ton"
	"github.com/liqdmetal/spore/internal/xmr"
)

// ChainConfig describes how to build one chain backend.
type ChainConfig struct {
	// Type is one of "dero", "evm", "xmr", "solana".
	Type string
	// RPC is the wallet/daemon JSON-RPC endpoint.
	RPC string
	// Login is optional "user:pass" RPC auth.
	Login string
	// From is our address (EVM needs it; DERO/XMR query the wallet).
	From string
	// KeyFile is the path to a Solana signer keypair JSON (for solana).
	KeyFile string
	// ProgramID overrides the Solana mailbox program (defaults to mainnet).
	ProgramID string
	// Mailbox is the MyceliumMailbox contract address (EVM only). When set,
	// the EVM backend delivers via the contract's Inbox logs instead of raw
	// calldata txs.
	Mailbox string
	// Name overrides the chain identifier (defaults to Type).
	Name string
	// AllowUnverified gates backends that are built but NOT live-verified.
	AllowUnverified                bool
	Network, BaseURL               string
	PostPath, ListPath, HeightPath string
	Address                        string
	Relays                         []string
	PrivateKey                     string
	DeliveryGuaranteed             bool
	FeeRate                        uint64
	MessageField, RecipientField   string
	Signer                         bitcoin.SignerBroadcaster
	Relay                          nostr.Relay
	Sender                         ton.Sender
	ChainID                        string
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
		b := evm.NewBackend(cfg.RPC, name, cfg.From)
		if cfg.Mailbox != "" {
			b.SetMailbox(cfg.Mailbox)
		}
		return b, nil
	case "xmr":
		if !cfg.AllowUnverified {
			return nil, fmt.Errorf("xmr backend is NOT live-verified (mock-verified only; the 8-byte payment-id seam is deprecated by modern monerod) — pass -xmr-unverified to use it anyway and treat every result as experimental")
		}
		if cfg.RPC == "" {
			return nil, fmt.Errorf("xmr backend needs -rpc (monero wallet RPC)")
		}
		return xmr.NewBackend(cfg.RPC, cfg.Login), nil
	case "nostr":
		return nostr.New(nostr.Config{PrivateKey: cfg.PrivateKey, Relays: cfg.Relays, Network: cfg.Network, Relay: cfg.Relay})
	case "bitcoin":
		if cfg.BaseURL == "" || cfg.Address == "" || cfg.Signer == nil {
			return nil, fmt.Errorf("bitcoin backend needs -base-url, -address, and signer")
		}
		return &bitcoin.Backend{Client: bitcoin.Client{BaseURL: cfg.BaseURL}, Signer: cfg.Signer, AddressValue: cfg.Address, FeeRate: cfg.FeeRate, Network: bitcoin.Network(cfg.Network)}, nil
	case "cosmos":
		b := cosmos.New(cosmos.Config{ChainID: cfg.Name, BaseURL: cfg.BaseURL, PostPath: cfg.PostPath, ListPath: cfg.ListPath, HeightPath: cfg.HeightPath, MessageField: cfg.MessageField, RecipientField: cfg.RecipientField, AddressValue: cfg.Address, DeliveryGuaranteed: cfg.DeliveryGuaranteed})
		if err := b.Validate(); err != nil {
			return nil, err
		}
		return b, nil
	case "ton":
		b := ton.New(ton.Config{Address: cfg.Address, Network: cfg.Network, BaseURL: cfg.BaseURL, PostPath: cfg.PostPath, ListPath: cfg.ListPath, HeightPath: cfg.HeightPath, Sender: cfg.Sender, DeliveryGuaranteed: cfg.DeliveryGuaranteed})
		return b, nil
	case "solana":
		if cfg.KeyFile == "" {
			return nil, fmt.Errorf("solana backend needs -keyfile (solana signer keypair JSON)")
		}
		signer, err := solana.PrivateKeyFromSolanaKeygenFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("solana: parse keypair: %w", err)
		}
		prog := solanaBackend.DefaultProgramID
		if cfg.ProgramID != "" {
			pk, perr := solana.PublicKeyFromBase58(cfg.ProgramID)
			if perr != nil {
				return nil, fmt.Errorf("solana: bad program id: %w", perr)
			}
			prog = pk
		}
		return solanaBackend.NewBackend(cfg.RPC, prog, signer), nil
	default:
		return nil, fmt.Errorf("unknown chain type %q (want dero|evm|xmr|solana)", cfg.Type)
	}
}

// Supported lists the backend type names.
func Supported() []string {
	return []string{"dero", "evm", "xmr", "solana", "nostr", "bitcoin", "cosmos", "ton"}
}
