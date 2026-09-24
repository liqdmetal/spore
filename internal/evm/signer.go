package evm

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// SignAndSendTransaction is the local-signing replacement for node-side
// signing on the PostPayload send path. PostPayload builds an
// eth_sendTransaction params map and hands it to the node — but public RPCs
// refuse to sign (they are read-only). This method interprets the same params
// map, signs the legacy transaction locally with the SAME hand-rolled EIP-155
// signer the deploy command uses (btcec, RFC-6979 deterministic), and
// broadcasts it via eth_sendRawTransaction. The key exists in memory only for
// the duration of the call and is zeroed after signing.
//
// Supported params keys: from (optional; verified against the signing key),
// to (required), data (required), value/gas/gasPrice (optional; defaults:
// value 0, gasPrice from eth_gasPrice, gas from eth_estimateGas).
func (b *Backend) SignAndSendTransaction(ctx context.Context, privateKeyHex string, params map[string]interface{}) (string, error) {
	key, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("evm sign: %w", err)
	}
	defer zeroKey(key)

	from := pubkeyToAddress(key)
	if want, _ := params["from"].(string); want != "" && !strings.EqualFold(strings.TrimSpace(want), from) {
		return "", fmt.Errorf("evm sign: params.from %s does not match the signing key's address %s", want, from)
	}
	to, _ := params["to"].(string)
	if strings.TrimSpace(to) == "" {
		return "", fmt.Errorf("evm sign: eth_sendTransaction without `to` is not supported here (use `spore contract deploy-mycelium` for contract creation)")
	}
	data, _ := params["data"].(string)

	chainID, err := b.ChainID(ctx)
	if err != nil {
		return "", fmt.Errorf("evm sign: eth_chainId: %w", err)
	}
	nonce, err := b.GetNonce(ctx, from)
	if err != nil {
		return "", fmt.Errorf("evm sign: nonce: %w", err)
	}
	gasPrice, err := parseWeiParam(params["gasPrice"])
	if err != nil {
		return "", fmt.Errorf("evm sign: bad gasPrice: %w", err)
	}
	if gasPrice == nil {
		gasPrice, err = b.GasPrice(ctx)
		if err != nil {
			return "", fmt.Errorf("evm sign: gas price: %w", err)
		}
	}
	value, err := parseWeiParam(params["value"])
	if err != nil {
		return "", fmt.Errorf("evm sign: bad value: %w", err)
	}
	if value == nil {
		value = big.NewInt(0)
	}
	gas, err := parseUintParam(params["gas"])
	if err != nil {
		return "", fmt.Errorf("evm sign: bad gas: %w", err)
	}
	if gas == 0 {
		estimate := map[string]interface{}{
			"from": from,
			"to":   to,
			"data": data,
		}
		if value.Sign() > 0 {
			estimate["value"] = params["value"]
		}
		gas, err = b.EstimateGas(ctx, estimate)
		if err != nil {
			return "", fmt.Errorf("evm sign: estimate gas: %w", err)
		}
	}

	raw, err := signLegacyTx(key, nonce, gasPrice, big.NewInt(0).SetUint64(gas), &to, value, chainID, data)
	if err != nil {
		return "", fmt.Errorf("evm sign: %w", err)
	}
	var txHash string
	if err := b.call(ctx, "eth_sendRawTransaction", []interface{}{"0x" + hex.EncodeToString(raw)}, &txHash); err != nil {
		return "", fmt.Errorf("evm sign: send: %w", err)
	}
	return txHash, nil
}

// AddressForKey derives the 0x-hex EVM address of a 32-byte hex secp256k1
// key, the same derivation the deploy path uses. The proxy command prints it
// at startup so operators can confirm which address they are signing for.
func AddressForKey(privateKeyHex string) (string, error) {
	key, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return "", err
	}
	defer zeroKey(key)
	return pubkeyToAddress(key), nil
}

// parseWeiParam reads an optional wei amount from a JSON-RPC param. Accepts
// 0x-hex (what PostPayload builds) or decimal; nil when absent/empty.
func parseWeiParam(v interface{}) (*big.Int, error) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return nil, nil
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		return hexQtyToBig(s)
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("not a wei amount: %q", s)
	}
	return n, nil
}

// parseUintParam reads an optional gas value from a JSON-RPC param
// (0x-hex quantity, like PostPayload and the node would emit).
func parseUintParam(v interface{}) (uint64, error) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return 0, nil
	}
	n, err := hexQtyToBig(s)
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}
