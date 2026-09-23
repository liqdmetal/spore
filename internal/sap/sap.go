// Package sap provides Go bindings for relay-dex DVM contracts deployed on DERO.
// Generated from relay-dex .dvm source: RelayHTLC.dvm, RelayDEX.dvm, RelayWrappedDero.dvm
package sap

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

// Contract IDs (64-char hex) for mainnet-deployed relay-dex contracts.
// These are the deployed SC IDs from relay-dex; set via env or config at
// runtime: spore's CLI seeds them from the SPORE_SAP_* environment variables
// (see loadSapContractIDsFromEnv), embedders can call SetContractIDs, and a
// caller that leaves them empty gets a REFUSAL from every entry point — never
// an empty-SCID invoke that the wallet would reject opaquely (or worse,
// accept against nothing).
var (
	HTLCContractID        = "" // RelayHTLC.dvm
	DEXContractID         = "" // RelayDEX.dvm
	WrappedDeroContractID = "" // RelayWrappedDero.dvm
)

// Environment variables the spore CLI reads to seed the contract IDs. The
// operator bakes these into their deployment; they are deliberately NOT
// hardcoded because the IDs are deployment-specific (a test relay-dex
// deployment has different IDs than mainnet).
const (
	EnvHTLCSignature   = "SPORE_SAP_HTLC_SC"  // RelayHTLC.dvm SC ID
	EnvDEXSignature    = "SPORE_SAP_DEX_SC"   // RelayDEX.dvm SC ID
	EnvWrappedDeroName = "SPORE_SAP_WDERO_SC" // RelayWrappedDero.dvm SC ID
)

// SetContractIDs (re)configures the deployed relay-dex contract IDs at
// runtime. Empty strings leave the corresponding contract unconfigured.
func SetContractIDs(htlc, dex, wrappedDero string) {
	HTLCContractID = strings.TrimSpace(htlc)
	DEXContractID = strings.TrimSpace(dex)
	WrappedDeroContractID = strings.TrimSpace(wrappedDero)
}

// ContractIDs reports the currently configured contract IDs (htlc, dex,
// wrappedDero) so callers can surface their configuration in diagnostics.
func ContractIDs() (htlc, dex, wrappedDero string) {
	return HTLCContractID, DEXContractID, WrappedDeroContractID
}

// LoadContractIDsFromEnv seeds the contract IDs from the SPORE_SAP_*
// environment variables. Only set variables overwrite (unset or empty env
// leaves the current value, so an embedder that pre-configured via
// SetContractIDs is not clobbered). The spore CLI calls this once at startup
// of any sap-backed command.
func LoadContractIDsFromEnv() {
	if v := strings.TrimSpace(os.Getenv(EnvHTLCSignature)); v != "" {
		HTLCContractID = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvDEXSignature)); v != "" {
		DEXContractID = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvWrappedDeroName)); v != "" {
		WrappedDeroContractID = v
	}
}

// contractGuard returns the configured contract ID or a refusal naming the
// missing one. Every sap entry point checks BEFORE building the invoke, so
// an unconfigured deployment fails fast and locally — not as an opaque
// wallet rejection of an empty SCID (the failure mode this guard replaced).
func contractGuard(kind, envVar, id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("sap: %s contract ID not configured (set %s or call sap.SetContractIDs)", kind, envVar)
	}
	return id, nil
}

func htlcContract() (string, error) {
	return contractGuard("RelayHTLC", EnvHTLCSignature, HTLCContractID)
}
func dexContract() (string, error) { return contractGuard("RelayDEX", EnvDEXSignature, DEXContractID) }
func wrappedContract() (string, error) {
	return contractGuard("RelayWrappedDero", EnvWrappedDeroName, WrappedDeroContractID)
}

// SC argument names per DVM source
const (
	// HTLC
	HTLCArgHash      = "h"
	HTLCArgRecipient = "recipient"
	HTLCArgExpiry    = "exp"
	HTLCArgPreimage  = "pre"

	// DEX
	DEXArgTokenA    = "ta"
	DEXArgTokenB    = "tb"
	DEXArgAmountOut = "mo"

	// WrappedDero
	WDArgAmount = "a" // implicit via DEROVALUE()
)

// HTLCFund funds an HTLC contract: locks DERO behind hash + expiry + recipient.
// Returns the txid of the funding transaction. Fails before any wallet RPC if
// the RelayHTLC contract ID is not configured.
func HTLCFund(ctx context.Context, client *dero.Client, hash [32]byte, recipient string, expiry uint64, amount uint64, ringsize uint64) (string, error) {
	scid, err := htlcContract()
	if err != nil {
		return "", err
	}
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{
		{Name: HTLCArgHash, DataType: anchor.DataHash, Value: hex.EncodeToString(hash[:])},
		{Name: HTLCArgRecipient, DataType: anchor.DataString, Value: recipient},
		{Name: HTLCArgExpiry, DataType: anchor.DataUint64, Value: expiry},
	}
	return client.InvokeSC(ctx, scid, args, amount, 0, ringsize, 0)
}

// HTLCClaim claims an HTLC with preimage. Returns txid. Fails before any
// wallet RPC if the RelayHTLC contract ID is not configured.
func HTLCClaim(ctx context.Context, client *dero.Client, hash [32]byte, preimage [32]byte, recipient string, ringsize uint64) (string, error) {
	scid, err := htlcContract()
	if err != nil {
		return "", err
	}
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{
		{Name: HTLCArgHash, DataType: anchor.DataHash, Value: hex.EncodeToString(hash[:])},
		{Name: HTLCArgPreimage, DataType: anchor.DataHash, Value: hex.EncodeToString(preimage[:])},
		{Name: HTLCArgRecipient, DataType: anchor.DataString, Value: recipient},
	}
	return client.InvokeSC(ctx, scid, args, 0, 0, ringsize, 0)
}

// HTLCRefund refunds an expired HTLC. Returns txid. Fails before any wallet
// RPC if the RelayHTLC contract ID is not configured.
func HTLCRefund(ctx context.Context, client *dero.Client, hash [32]byte, ringsize uint64) (string, error) {
	scid, err := htlcContract()
	if err != nil {
		return "", err
	}
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{
		{Name: HTLCArgHash, DataType: anchor.DataHash, Value: hex.EncodeToString(hash[:])},
	}
	return client.InvokeSC(ctx, scid, args, 0, 0, ringsize, 0)
}

// DEXSwap performs a constant-product swap on RelayDEX: deposits amountIn
// of tokenA with the invoke (SC-token deposit semantics per the DVM) and
// requires at least amountOut of tokenB back. amountIn MUST be non-zero — a
// zero-deposit swap moves nothing and would be accepted by no honest pool.
// Returns txid. Fails before any wallet RPC if the RelayDEX contract ID is
// not configured.
func DEXSwap(ctx context.Context, client *dero.Client, tokenA, tokenB string, amountIn, amountOut uint64, ringsize uint64) (string, error) {
	scid, err := dexContract()
	if err != nil {
		return "", err
	}
	if amountIn == 0 {
		return "", fmt.Errorf("sap: swap requires a non-zero amountIn of %s (a zero-deposit swap moves nothing)", tokenA)
	}
	if amountOut == 0 {
		return "", fmt.Errorf("sap: swap requires a non-zero amountOut bound (0 would accept anything the pool gives)")
	}
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{
		{Name: DEXArgTokenA, DataType: anchor.DataString, Value: tokenA},
		{Name: DEXArgTokenB, DataType: anchor.DataString, Value: tokenB},
		{Name: DEXArgAmountOut, DataType: anchor.DataUint64, Value: amountOut},
	}
	return client.InvokeSC(ctx, scid, args, 0, amountIn, ringsize, 0)
}

// WrapDERO wraps native DERO into wDERO SC token (the DEROVALUE deposit
// rides the invoke). Returns txid. Fails before any wallet RPC if the
// RelayWrappedDero contract ID is not configured.
func WrapDERO(ctx context.Context, client *dero.Client, amount uint64, ringsize uint64) (string, error) {
	scid, err := wrappedContract()
	if err != nil {
		return "", err
	}
	if amount == 0 {
		return "", fmt.Errorf("sap: wrap amount must be greater than zero")
	}
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{}
	return client.InvokeSC(ctx, scid, args, amount, 0, ringsize, 0)
}

// UnwrapDERO unwraps wDERO back to native DERO (the SC-token deposit of
// `amount` rides the invoke). Returns txid. Fails before any wallet RPC if
// the RelayWrappedDero contract ID is not configured.
func UnwrapDERO(ctx context.Context, client *dero.Client, amount uint64, ringsize uint64) (string, error) {
	scid, err := wrappedContract()
	if err != nil {
		return "", err
	}
	if amount == 0 {
		return "", fmt.Errorf("sap: unwrap amount must be greater than zero")
	}
	if ringsize == 0 {
		ringsize = 16
	}
	args := anchor.Arguments{}
	return client.InvokeSC(ctx, scid, args, 0, amount, ringsize, 0)
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
