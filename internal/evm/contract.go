// Contract deployment for the MyceliumMailbox contract on any EVM chain.
//
// Until now the EVM carrier could only CONSUME a mailbox contract — SetMailbox
// pointed the backend at an address someone else had to deploy by hand, which
// is why the roadmap row said "needs a funded EVM account on a real chain" as
// a manual step. This file closes that gap: `spore contract deploy-mycelium`
// signs and broadcasts the contract-creation transaction itself, derives the
// resulting contract address locally (the same keccak256(rlp([sender,nonce]))
// creation formula every EVM node uses), verifies code is live on chain, and
// prints the address to hand to -mailbox.
//
// No go-ethereum dependency: the legacy (pre-EIP-1559) signing scheme is
// implemented directly over btcd's secp256k1 (already a module dependency)
// and Keccak-256 from x/crypto/sha3.
//
// The creation bytecode is NOT embedded in source: embedding compiled EVM
// bytecode as a hand-typed literal invites silent drift from
// contracts/MyceliumMailbox.sol, and a wrong literal deployed to a funded
// chain is real money at stake. It is loaded from a solc-generated bin file
// (default tools/mycelium.bin, -bin to override) and the deploy command
// refuses to run without one, printing the exact generation command.
package evm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	becdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"golang.org/x/crypto/sha3"
)

// ErrNoSigner is returned when deployment is attempted without a private key.
var ErrNoSigner = errors.New("evm contract deploy: -private-key (or SPORE_EVM_PRIVATE_KEY, 32-byte hex, funded on the target chain) is required")

// ErrNoCreationCode is returned when no solc-generated creation bytecode was
// provided. GenerationCodeHint is the exact command to produce it.
var ErrNoCreationCode = errors.New("evm contract deploy: creation bytecode not found")

const GenerationCodeHint = "solc --bin contracts/MyceliumMailbox.sol | tail -1 > tools/mycelium.bin"

// LoadCreationCode reads a solc `--bin` hex blob (0x-optional, whitespace
// tolerated) from path.
func LoadCreationCode(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", ErrNoCreationCode
	}
	code := strings.TrimSpace(string(raw))
	code = strings.TrimPrefix(code, "0x")
	// One-line hex blob expected; reject anything that is not hex so a
	// mis-selected file (README, ABI JSON) fails here, not on-chain.
	if _, err := hex.DecodeString(code); err != nil {
		return "", fmt.Errorf("evm contract deploy: %s is not a hex bytecode blob: %w", path, err)
	}
	if len(code) < 20 {
		return "", fmt.Errorf("evm contract deploy: %s is too short to be creation code (%d hex chars)", path, len(code))
	}
	return code, nil
}

// ChainID fetches the chain ID (eth_chainId).
func (b *Backend) ChainID(ctx context.Context) (*big.Int, error) {
	var hexID string
	if err := b.call(ctx, "eth_chainId", []interface{}{}, &hexID); err != nil {
		return nil, err
	}
	return hexQtyToBig(hexID)
}

// GetCode returns the deployed code at addr ("0x..." — empty means no code).
func (b *Backend) GetCode(ctx context.Context, addr string) ([]byte, error) {
	var hexCode string
	if err := b.call(ctx, "eth_getCode", []interface{}{addr, "latest"}, &hexCode); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(hexCode), "0x"))
	if err != nil {
		return nil, fmt.Errorf("evm: eth_getCode returned non-hex: %w", err)
	}
	return raw, nil
}

// GetNonce returns the transaction count (eth_getTransactionCount, pending).
func (b *Backend) GetNonce(ctx context.Context, addr string) (uint64, error) {
	var hexN string
	if err := b.call(ctx, "eth_getTransactionCount", []interface{}{addr, "pending"}, &hexN); err != nil {
		return 0, err
	}
	n, err := hexQtyToBig(hexN)
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}

// EstimateGas wraps eth_estimateGas for a raw tx param map (no `to` =
// creation estimate).
func (b *Backend) EstimateGas(ctx context.Context, params map[string]interface{}) (uint64, error) {
	var hexGas string
	if err := b.call(ctx, "eth_estimateGas", []interface{}{params}, &hexGas); err != nil {
		return 0, err
	}
	g, err := hexQtyToBig(hexGas)
	if err != nil {
		return 0, err
	}
	return g.Uint64(), nil
}

// GasPrice wraps eth_gasPrice (hex wei).
func (b *Backend) GasPrice(ctx context.Context) (*big.Int, error) {
	var hexP string
	if err := b.call(ctx, "eth_gasPrice", []interface{}{}, &hexP); err != nil {
		return nil, err
	}
	return hexQtyToBig(hexP)
}

func hexQtyToBig(s string) (*big.Int, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if s == "" {
		return nil, errors.New("evm: empty hex quantity")
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("evm: bad hex quantity %q", s)
	}
	return n, nil
}

// deployResult is the outcome of a successful creation: the broadcast tx hash
// and the derived (and on-chain verified) contract address.
type deployResult struct {
	TxHash string
	Addr   string
}

// DeployContractEIP155 signs and broadcasts the contract-creation tx for
// creationCode, waits for the code to appear, and returns the tx hash +
// contract address.
//
// privateKeyHex is a 32-byte secp256k1 private key (0x-optional). It is held
// only in memory for the duration of the call and zeroed after signing.
// gasPriceOverride (wei) is optional — nil uses eth_gasPrice.
func (b *Backend) DeployContractEIP155(ctx context.Context, privateKeyHex, creationCode string, gasPriceOverride *big.Int) (deployResult, error) {
	var out deployResult
	key, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return out, err
	}
	defer zeroKey(key)
	from := pubkeyToAddress(key)

	chainID, err := b.ChainID(ctx)
	if err != nil {
		return out, fmt.Errorf("evm deploy: eth_chainId: %w", err)
	}
	nonce, err := b.GetNonce(ctx, from)
	if err != nil {
		return out, fmt.Errorf("evm deploy: nonce: %w", err)
	}
	gasPrice := gasPriceOverride
	if gasPrice == nil {
		gasPrice, err = b.GasPrice(ctx)
		if err != nil {
			return out, fmt.Errorf("evm deploy: gas price: %w", err)
		}
	}
	gas, err := b.EstimateGas(ctx, map[string]interface{}{
		"from": from,
		"data": "0x" + creationCode,
	})
	if err != nil {
		return out, fmt.Errorf("evm deploy: estimate gas: %w", err)
	}
	// Contract creation is a tx with no `to` and data = creation code.
	raw, err := signLegacyTx(key, nonce, gasPrice, big.NewInt(0).SetUint64(gas), nil, big.NewInt(0), chainID, creationCode)
	if err != nil {
		return out, err
	}
	var txHash string
	if err := b.call(ctx, "eth_sendRawTransaction", []interface{}{"0x" + hex.EncodeToString(raw)}, &txHash); err != nil {
		return out, fmt.Errorf("evm deploy: send: %w", err)
	}
	out.TxHash = txHash
	addr, err := b.waitForContract(ctx, from, nonce)
	if err != nil {
		return out, err
	}
	out.Addr = addr
	return out, nil
}

// waitForContract polls eth_getCode at the derived creation address until
// non-empty code appears (deployment succeeded) or the poll budget expires.
// The address derivation itself is the correctness anchor: if the tx mined,
// code IS at that address.
func (b *Backend) waitForContract(ctx context.Context, from string, nonce uint64) (string, error) {
	created := createAddress(from, nonce)
	if created == "" {
		return "", errors.New("evm deploy: could not derive creation address")
	}
	const attempts = 120 // ~2min at 1s blocks
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Second):
		}
		code, err := b.GetCode(ctx, created)
		if err == nil && len(code) > 0 {
			return created, nil
		}
	}
	return "", fmt.Errorf("evm deploy: no code appeared at %s after %d polls (tx may have failed or the node is slow)", created, attempts)
}

// createAddress derives the EVM contract creation address:
// keccak256(rlp([sender, nonce]))[12:]. The RLP list is two binary strings —
// the 20-byte sender and the minimal big-endian nonce — encoded directly.
func createAddress(from string, nonce uint64) string {
	fromBytes, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(from), "0x"))
	if err != nil || len(fromBytes) != 20 {
		return ""
	}
	// item1: 20-byte string -> single length byte 0x80+20 = 0x94
	item1 := append([]byte{0x94}, fromBytes...)
	item2 := encodeRLPString(minimalBigEndian(nonce))
	payload := append(append([]byte{}, item1...), item2...)
	list := append(rlpLengthPrefix(len(payload), 0xc0), payload...)
	return "0x" + hex.EncodeToString(keccak256(list)[12:])
}

// encodeRLPString encodes a binary string per RLP: bytes < 0x80 encode as
// themselves, shorter strings get the 0x80-length prefix, longer ones the
// 0xb7 long form.
func encodeRLPString(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(rlpLengthPrefix(len(b), 0x80), b...)
}

// rlpLengthPrefix returns the RLP length header for a payload of `length`
// bytes under the given offset (0xc0 for lists, 0x80 for strings).
func rlpLengthPrefix(length int, offset byte) []byte {
	if length < 56 {
		return []byte{offset + byte(length)}
	}
	lenBytes := minimalBigEndian(uint64(length))
	return append([]byte{offset + 55 + byte(len(lenBytes))}, lenBytes...)
}

func minimalBigEndian(v uint64) []byte {
	if v == 0 {
		return nil
	}
	var buf [8]byte
	n := 0
	for v > 0 {
		buf[7-n] = byte(v)
		v >>= 8
		n++
	}
	return buf[8-n:]
}

// signLegacyTx signs a legacy transaction (EIP-155 when chainID != nil) and
// returns the RLP-encoded raw tx. to == nil means contract creation.
func signLegacyTx(key *btcec.PrivateKey, nonce uint64, gasPrice, gas *big.Int, to *string, value *big.Int, chainID *big.Int, dataHex string) ([]byte, error) {
	data, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(dataHex), "0x"))
	if err != nil {
		return nil, fmt.Errorf("evm deploy: bad data hex: %w", err)
	}
	if value == nil {
		value = big.NewInt(0)
	}
	var toBytes []byte
	if to != nil {
		toBytes, err = hex.DecodeString(strings.TrimPrefix(strings.ToLower(*to), "0x"))
		if err != nil || len(toBytes) != 20 {
			return nil, errors.New("evm deploy: bad `to` address")
		}
	}

	// Unsigned EIP-155 payload: [nonce, gasPrice, gas, to, value, data,
	// chainID, 0, 0]. With chainID == nil (no replay protection) the last
	// three fields are omitted entirely.
	var unsigned []byte
	if chainID != nil {
		unsigned = legacyRLP(nonce, gasPrice, gas, toBytes, value, data, chainID, big.NewInt(0), big.NewInt(0))
	} else {
		unsigned = legacyRLP(nonce, gasPrice, gas, toBytes, value, data, nil, nil, nil)
	}
	// SignCompact emits <1-byte recovery code><32-byte R><32-byte S> (the
	// recovery code first — this is the Bitcoin compact-signature layout, not
	// Ethereum's r||s||v). With an uncompressed key the code is 27+recID.
	// RFC-6979 deterministic signing, so the same pre-image always yields the
	// same signature — re-broadcasting is idempotent.
	sig := becdsa.SignCompact(key, keccak256(unsigned), false)
	if len(sig) != 65 {
		return nil, fmt.Errorf("evm deploy: unexpected signature length %d", len(sig))
	}
	if sig[0] < 27 || sig[0] > 28 {
		// Ethereum's ecrecover only accepts recovery ids 0 and 1; ids 2/3 (R ≥
		// N, probability ~2^-128) cannot be represented in a valid v byte.
		return nil, fmt.Errorf("evm deploy: unexpected signature recovery code %d", sig[0])
	}
	r := new(big.Int).SetBytes(sig[1:33])
	s := new(big.Int).SetBytes(sig[33:65])
	recID := uint64(sig[0] - 27) // 0..3

	// EIP-155: v = chainID*2 + 35 + recID; pre-155: v = 27 + recID.
	var v *big.Int
	if chainID != nil {
		v = new(big.Int).Mul(chainID, big.NewInt(2))
		v.Add(v, big.NewInt(35+int64(recID)))
	} else {
		v = big.NewInt(27 + int64(recID))
	}

	return legacyRLP(nonce, gasPrice, gas, toBytes, value, data, v, r, s), nil
}

// legacyRLP encodes the legacy tx field list. Nil v/r/s omit the field
// entirely (the unsigned EIP-155 pre-image only carries chainID,0,0 when
// replay protection is in use).
func legacyRLP(nonce uint64, gasPrice, gas *big.Int, to []byte, value *big.Int, data []byte, v, r, s *big.Int) []byte {
	fields := [][]byte{
		encodeRLPString(minimalBigEndian(nonce)),
		encodeRLPString(bigEndianTrimmed(gasPrice)),
		encodeRLPString(bigEndianTrimmed(gas)),
	}
	if to == nil {
		fields = append(fields, []byte{0x80}) // empty string = no recipient
	} else {
		fields = append(fields, append([]byte{0x94}, to...))
	}
	fields = append(fields,
		encodeRLPString(bigEndianTrimmed(value)),
		encodeRLPString(data),
	)
	for _, bi := range []*big.Int{v, r, s} {
		if bi == nil {
			continue
		}
		fields = append(fields, encodeRLPString(bigEndianTrimmed(bi)))
	}
	var payload []byte
	for _, f := range fields {
		payload = append(payload, f...)
	}
	return append(rlpLengthPrefix(len(payload), 0xc0), payload...)
}

func bigEndianTrimmed(v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return nil
	}
	return v.Bytes()
}

func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(b)
	return h.Sum(nil)
}

func parsePrivateKey(hexKey string) (*btcec.PrivateKey, error) {
	trimmed := strings.TrimSpace(hexKey)
	if trimmed == "" {
		return nil, ErrNoSigner
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(trimmed, "0x"))
	if err != nil {
		return nil, fmt.Errorf("evm deploy: private key must be hex: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("evm deploy: private key must be 32 bytes, got %d", len(raw))
	}
	key, _ := btcec.PrivKeyFromBytes(raw)
	return key, nil
}

// pubkeyToAddress returns the 0x-hex EVM address for a secp256k1 key:
// keccak256(uncompressed pub without the 0x04 prefix)[12:].
func pubkeyToAddress(key *btcec.PrivateKey) string {
	pub := key.PubKey().SerializeUncompressed() // 0x04 || X || Y
	h := keccak256(pub[1:])
	return "0x" + hex.EncodeToString(h[12:])
}

func zeroKey(key *btcec.PrivateKey) {
	if key == nil {
		return
	}
	// btcec.PrivateKey holds a ModNScalar (a value type); Zero() scrubs the
	// scalar. The tx is already signed by the time this runs.
	key.Key.Zero()
}
