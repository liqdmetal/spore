// Package sap provides Go bindings for relay-dex DVM contracts deployed on DERO.
// Generated from relay-dex .dvm source: RelayHTLC.dvm, RelayDEX.dvm, RelayWrappedDero.dvm
package sap

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

// Contract IDs (64-char hex) for mainnet-deployed relay-dex contracts.
// These are the deployed SC IDs from relay-dex; set via env or config at runtime.
var (
	HTLCContractID         = "" // RelayHTLC.dvm
	DEXContractID          = "" // RelayDEX.dvm
	WrappedDeroContractID  = "" // RelayWrappedDero.dvm
)

// SC argument names per DVM source
const (
	// HTLC
	HTLCArgHash        = "h"
	HTLCArgRecipient   = "recipient"
	HTLCArgExpiry      = "exp"
	HTLCArgPreimage    = "pre"

	// DEX
	DEXArgTokenA       = "ta"
	DEXArgTokenB       = "tb"
	DEXArgAmountOut    = "mo"

	// WrappedDero
	WDArgAmount        = "a" // implicit via DEROVALUE()
)

// HTLCFund funds an HTLC contract: locks DERO behind hash + expiry + recipient.
// Returns the txid of the funding transaction.
func HTLCFund(ctx context.Context, client *dero.Client, hash [32]byte, recipient string, expiry uint64, amount uint64, ringsize uint64) (string, error) {
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{
		{Name: HTLCArgHash, DataType: anchor.DataHash, Value: hex.EncodeToString(hash[:])},
		{Name: HTLCArgRecipient, DataType: anchor.DataString, Value: recipient},
		{Name: HTLCArgExpiry, DataType: anchor.DataUint64, Value: expiry},
	}
	return client.InvokeSC(ctx, HTLCContractID, args, amount, 0, ringsize, 0)
}

// HTLCClaim claims an HTLC with preimage. Returns txid.
func HTLCClaim(ctx context.Context, client *dero.Client, hash [32]byte, preimage [32]byte, recipient string, ringsize uint64) (string, error) {
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{
		{Name: HTLCArgHash, DataType: anchor.DataHash, Value: hex.EncodeToString(hash[:])},
		{Name: HTLCArgPreimage, DataType: anchor.DataHash, Value: hex.EncodeToString(preimage[:])},
		{Name: HTLCArgRecipient, DataType: anchor.DataString, Value: recipient},
	}
	return client.InvokeSC(ctx, HTLCContractID, args, 0, 0, ringsize, 0)
}

// HTLCRefund refunds an expired HTLC. Returns txid.
func HTLCRefund(ctx context.Context, client *dero.Client, hash [32]byte, ringsize uint64) (string, error) {
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{
		{Name: HTLCArgHash, DataType: anchor.DataHash, Value: hex.EncodeToString(hash[:])},
	}
	return client.InvokeSC(ctx, HTLCContractID, args, 0, 0, ringsize, 0)
}

// DEXSwap performs a constant-product swap on RelayDEX.
// Returns txid.
func DEXSwap(ctx context.Context, client *dero.Client, tokenA, tokenB string, amountOut uint64, ringsize uint64) (string, error) {
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{
		{Name: DEXArgTokenA, DataType: anchor.DataString, Value: tokenA},
		{Name: DEXArgTokenB, DataType: anchor.DataString, Value: tokenB},
		{Name: DEXArgAmountOut, DataType: anchor.DataUint64, Value: amountOut},
	}
	return client.InvokeSC(ctx, DEXContractID, args, 0, 0, ringsize, 0)
}

// WrapDERO wraps native DERO into wDERO SC token.
// Returns txid.
func WrapDERO(ctx context.Context, client *dero.Client, amount uint64, ringsize uint64) (string, error) {
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{}
	return client.InvokeSC(ctx, WrappedDeroContractID, args, amount, 0, ringsize, 0)
}

// UnwrapDERO unwraps wDERO back to native DERO.
// Returns txid.
func UnwrapDERO(ctx context.Context, client *dero.Client, amount uint64, ringsize uint64) (string, error) {
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{}
	return client.InvokeSC(ctx, WrappedDeroContractID, args, 0, amount, ringsize, 0)
}

// Error codes from DVM (returned as uint64 in RPC result, not tx error)
const (
	DVMErrOK      = 0
	DVMErrGeneric = 1
)

func DVMErrorString(code uint64) string {
	switch code {
	case DVMErrOK:
		return "ok"
	case DVMErrGeneric:
		return "generic DVM error"
	default:
		return fmt.Sprintf("unknown DVM error %d", code)
	}
}