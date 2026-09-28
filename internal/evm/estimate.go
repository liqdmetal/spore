// Gas-cost estimation for the MyceliumMailbox path: one command answers
// "what does this deployment cost" instead of manual eth_gasPrice × gas
// arithmetic. This is the Phase B step-1 rule of docs/LIVE_NODES.md §3
// ("measure with eth_gasPrice at run time, never trust a doc number")
// turned into a single command.
//
// Honesty rules the output follows:
//
//   - deploy and deliver gas come from eth_estimateGas using the EXACT param
//     shapes the real operations send (a creation tx with no `to`; a
//     deliver(address,bytes) call to the mailbox). A node that refuses them
//     tells you now, for free, before any funded tx exists.
//   - burn cannot be estimated against a fresh deployment: burn(to,seq) on a
//     missing message reverts, and most nodes surface that as a failed
//     eth_estimateGas. It falls back to a conservative constant, clearly
//     labeled as an assumption — storage clearing refunds mean the true
//     cost is typically lower, so funding decisions err on the safe side.
//   - everything is priced at the live eth_gasPrice, and the caller is
//     reminded that prices move: estimate again at run time.
package evm

import (
	"context"
	"fmt"
	"math/big"
	"strings"
)

// EstimatePayloadBytes is the size of the canonical spore E2 pointer payload
// a deliver() carries on the mailbox path (WIRE_SPEC: version u8 + route
// handle 32 + 74-byte pointer + received_at u64 = 116 bytes).
const EstimatePayloadBytes = 116

// BurnGasFallback is the conservative burn(to,seq) gas assumption used when
// the node refuses to estimate a burn against an empty slot (the usual case
// on a fresh deployment). Intentionally on the high side: it is a funding
// input, and clearing a storage slot to zero typically refunds gas, making
// the real burn cheaper than this.
const BurnGasFallback = 35000

// SyntheticRecipient is the deliver() `to` used for estimation when the
// caller has no real recipient. Gas does not depend on the address value —
// only the payload length does — so a syntactically valid 20-byte address is
// enough for the node to quote.
const SyntheticRecipient = "0x000000000000000000000000000000000000dEaD"

// weiPerEth is 10^18.
var weiPerEth = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

// GasEstimate is the per-operation gas picture for one MyceliumMailbox
// deployment, priced at a single gas price (live, or overridden). Zero gas
// fields mean that operation could not be estimated — see Notes for why.
type GasEstimate struct {
	ChainID     *big.Int
	GasPriceWei *big.Int // nil until priced (see EstimateMyceliumCostsPriced)

	DeployGas  uint64
	DeliverGas uint64 // zero unless a mailbox address was given and the node answered
	BurnGas    uint64 // live estimate or BurnGasFallback — see BurnMode

	DeliverMode string // how DeliverGas was obtained
	BurnMode    string // how BurnGas was obtained

	From string // the address the estimates were quoted for ("" if unknown)

	// GasPriceOverride is true when the caller supplied the price instead of
	// trusting the node's eth_gasPrice.
	GasPriceOverride bool

	Notes []string
}

// FormatWei renders wei as ETH with trailing zeros trimmed (10^18 → "1 ETH",
// 1050000 → "0.00000000000105 ETH").
func FormatWei(wei *big.Int) string {
	if wei == nil || wei.Sign() == 0 {
		return "0 ETH"
	}
	whole := new(big.Int).Quo(wei, weiPerEth)
	rem := new(big.Int).Mod(wei, weiPerEth)
	if rem.Sign() == 0 {
		return fmt.Sprintf("%s ETH", whole.String())
	}
	frac := rem.String()
	frac = strings.Repeat("0", 18-len(frac)) + frac
	frac = strings.TrimRight(frac, "0")
	return fmt.Sprintf("%s.%s ETH", whole.String(), frac)
}

// weiForGas multiplies gas by the estimate's gas price, or nil when either
// piece is missing.
func (e *GasEstimate) weiForGas(gas uint64) *big.Int {
	if e.GasPriceWei == nil || gas == 0 {
		return nil
	}
	return new(big.Int).Mul(new(big.Int).SetUint64(gas), e.GasPriceWei)
}

// DeployWei is the deploy cost in wei, or nil when unavailable.
func (e *GasEstimate) DeployWei() *big.Int { return e.weiForGas(e.DeployGas) }

// RoundWei is one deliver+burn round in wei, or nil when unavailable.
func (e *GasEstimate) RoundWei() *big.Int {
	if e.DeliverGas == 0 || e.BurnGas == 0 {
		return nil
	}
	return e.weiForGas(e.DeliverGas + e.BurnGas)
}

// TotalWei is the wei cost of one deploy plus rounds deliver+burn rounds at
// the estimated gas price — the funding number. nil when any component is
// missing (the caller should print what IS known plus the notes instead).
func (e *GasEstimate) TotalWei(rounds int) *big.Int {
	if rounds < 1 || e.DeployGas == 0 || e.DeliverGas == 0 || e.BurnGas == 0 || e.GasPriceWei == nil {
		return nil
	}
	per := new(big.Int).SetUint64(e.DeliverGas + e.BurnGas)
	per.Mul(per, big.NewInt(int64(rounds)))
	gas := new(big.Int).SetUint64(e.DeployGas)
	gas.Add(gas, per)
	return e.weiForGas(gas.Uint64())
}

// EstimateMyceliumCostsPriced gathers the per-operation gas estimates for the
// deployment path and prices them.
//
//   - recipient: the deliver() to argument (gas does not depend on the value;
//     pass SyntheticRecipient when there is none yet).
//   - mailbox: the deployed MyceliumMailbox address. Empty means deliver/burn
//     are skipped (nothing to call yet) and only the deploy row is filled.
//   - creationCode: the solc creation bytecode (the deploy-mycelium -bin
//     content). The deploy estimate is a creation tx — no `to` — exactly the
//     shape DeployContractEIP155 estimates with.
//   - payloadBytes: the deliver payload size to price (a canonical E2 pointer
//     is EstimatePayloadBytes bytes).
//   - priceOverride: wei per gas, or nil to take the node's eth_gasPrice.
//
// The estimate is returned whenever pricing was possible; individual
// operations may be missing — read Notes. An error is returned only when no
// price could be obtained at all, since nothing can be funded without it.
func (b *Backend) EstimateMyceliumCostsPriced(ctx context.Context, recipient, mailbox, creationCode string, payloadBytes int, priceOverride *big.Int) (*GasEstimate, error) {
	est := &GasEstimate{GasPriceOverride: priceOverride != nil}
	fail := func(op string, err error) {
		est.Notes = append(est.Notes, fmt.Sprintf("%s: %v", op, err))
	}

	if cid, err := b.ChainID(ctx); err != nil {
		fail("eth_chainId", err)
	} else {
		est.ChainID = cid
	}

	if priceOverride != nil {
		est.GasPriceWei = new(big.Int).Set(priceOverride)
	} else {
		price, err := b.GasPrice(ctx)
		if err != nil {
			return nil, fmt.Errorf("evm estimate: eth_gasPrice: %w", err)
		}
		est.GasPriceWei = price
	}

	// The estimates are quoted for a sender: derive it from the key the
	// deploy would use, when one is configured. From-shape matters to some
	// nodes (they check the account exists / is funded), so quote for the
	// real sender when we can.
	if from, err := b.deriveFrom(); err != nil {
		est.Notes = append(est.Notes, fmt.Sprintf("no -from given: estimates quoted without a from address (%v)", err))
	} else {
		est.From = from
	}

	// Deploy: the exact param shape DeployContractEIP155 estimates with.
	if gas, err := b.EstimateGas(ctx, withFrom(est.From, map[string]interface{}{
		"data": "0x" + creationCode,
	})); err != nil {
		fail("deploy eth_estimateGas", err)
	} else {
		est.DeployGas = gas
	}

	if mailbox == "" {
		est.Notes = append(est.Notes,
			"no -mailbox given: deliver/burn rows skipped (deploy first, then re-run with -mailbox for the full funding number)")
		return est, nil
	}

	payload := make([]byte, payloadBytes)

	// Deliver: the exact calldata PostPayload sends on the contract path.
	deliverCalldata, err := encodeDeliver(recipient, payload)
	if err != nil {
		fail("deliver calldata", err)
		return est, nil
	}
	if gas, err := b.EstimateGas(ctx, withFrom(est.From, map[string]interface{}{
		"to":   mailbox,
		"data": deliverCalldata,
	})); err != nil {
		fail("deliver eth_estimateGas", err)
	} else {
		est.DeliverGas = gas
		est.DeliverMode = "eth_estimateGas (live)"
	}

	// Burn: try live; against a fresh deployment the node executes
	// burn(recipient, 0) on a missing message, which reverts — most nodes
	// surface that as a failed estimate. Fall back to the conservative
	// constant, labeled as the assumption it is.
	burnCalldata, err := encodeBurn(recipient, 0)
	if err != nil {
		fail("burn calldata", err)
		return est, nil
	}
	if gas, err := b.EstimateGas(ctx, withFrom(est.From, map[string]interface{}{
		"to":   mailbox,
		"data": burnCalldata,
	})); err != nil {
		est.BurnGas = BurnGasFallback
		est.BurnMode = fmt.Sprintf("conservative fallback (%d gas; empty-slot burn cannot be estimated live — clearing a slot typically refunds, so the real burn is cheaper)", BurnGasFallback)
		est.Notes = append(est.Notes, fmt.Sprintf("burn eth_estimateGas refused (expected against an empty slot): %v", err))
	} else {
		est.BurnGas = gas
		est.BurnMode = "eth_estimateGas (live)"
	}
	return est, nil
}

// deriveFrom returns the address estimates should be quoted for: the backend's
// configured sender (NewBackend's fromAddr — the CLI passes -from), "" when
// none. Kept tolerant on purpose: a read-only public RPC can still quote gas
// for a from-less estimate; the note tells the operator what happened.
func (b *Backend) deriveFrom() (string, error) {
	if b.from == "" {
		return "", fmt.Errorf("no -from address given")
	}
	return b.from, nil
}

// withFrom adds the quoted sender to an eth_estimateGas param map only when
// one is known — an absent field beats an empty-string one on real nodes.
func withFrom(from string, params map[string]interface{}) map[string]interface{} {
	if from != "" {
		params["from"] = from
	}
	return params
}
