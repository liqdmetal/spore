package dero

import (
	"fmt"
	"math/big"
	"strings"
)

// ValidateAddress validates a mainnet DERO address using the R153 address
// format. It returns the trimmed canonical input. Integrated mainnet addresses
// (deroi...) are accepted because the wallet accepts them as destinations;
// proof/testnet addresses are rejected by this mainnet client.
func ValidateAddress(input string) (string, error) {
	addr := strings.TrimSpace(input)
	if addr == "" {
		return "", fmt.Errorf("dero: empty destination address")
	}
	hrp, data, err := decodeBech32(addr)
	if err != nil {
		return "", fmt.Errorf("dero: invalid destination address: %w", err)
	}
	if hrp != "dero" && hrp != "deroi" {
		return "", fmt.Errorf("dero: destination is not a mainnet address")
	}
	raw, err := convertBits(data, 5, 8, false)
	if err != nil || len(raw) < 34 || raw[0] != 1 {
		return "", fmt.Errorf("dero: invalid destination payload")
	}
	if hrp == "dero" && len(raw) != 34 {
		return "", fmt.Errorf("dero: invalid base address length")
	}
	if hrp == "deroi" {
		if len(raw) <= 34 {
			return "", fmt.Errorf("dero: invalid integrated address length")
		}
		if err := validateIntegratedArguments(raw[34:]); err != nil {
			return "", fmt.Errorf("dero: invalid integrated address: %w", err)
		}
	}
	if err := validateCompressedPoint(raw[1:34]); err != nil {
		return "", fmt.Errorf("dero: invalid destination public key: %w", err)
	}
	return addr, nil
}

// validateIntegratedArguments mirrors R153 rpc.Arguments.UnmarshalBinary for the
// argument tail that follows the 33-byte key of an integrated (deroi) address:
// the tail must decode as one CBOR map whose text keys are at least 2 bytes —
// a 1-byte name plus a 1-byte datatype, exactly as rpc.MarshalBinary writes them.
//
// Without this check the address validator was more permissive than the wallet.
// Measured against a live R153 wallet, split_integrated_address refuses a
// valid-checksum deroi address whose tail is not decodable arguments
// ("Invalid encoding for key 'D'", or "cbor: unexpected break code"), while
// this validator accepted it — so a bad destination passed every local check and
// only failed once the send reached the wallet.
func validateIntegratedArguments(tail []byte) error {
	count, i, err := cborContainerLen(tail, 0, 5) // major type 5 = CBOR map
	if err != nil {
		return fmt.Errorf("arguments are not a CBOR map: %w", err)
	}
	if count > maxRawMapPairs {
		return fmt.Errorf("too many arguments")
	}
	for n := uint64(0); n < count; n++ {
		key, next, ok := cborText(tail, i)
		if !ok || len(key) < 2 {
			return fmt.Errorf("argument key must be a name plus datatype")
		}
		i = next
		next, ok = cborSkip(tail, i, 0)
		if !ok {
			return fmt.Errorf("argument value is malformed")
		}
		i = next
	}
	return nil
}

// bn256FieldPrime is the BN256 base-field modulus p = 36u⁴+36u³+24u²+6u+1
// (derohe cryptography/bn256/constants.go, bn256.P).
//
// This is NOT the group order. The two are close but distinct:
//
//	P     = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
//	Order = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
//
// Field arithmetic must use P. Substituting Order still compiles and still
// looks correct in review, but it tests quadratic residuosity in the wrong
// field. Measured over 20k random samples per class:
//
//	49.5% of genuinely valid destinations REJECTED
//	50.2% of genuinely invalid destinations ACCEPTED
//
// i.e. very nearly a coin flip in both directions. The false-accept direction
// is the dangerous one: an unusable destination is admitted, and the failure
// only surfaces later, at send time.
//
// A wrong modulus does not fail loudly on its own, so the real-mainnet-address
// test in address_test.go (and the addr-mainnet / addr-reject self-tests in
// `spore doctor --live`) are the actual guards.
const bn256FieldPrime = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"

// bn256CurveB is the curve constant b in y² = x³ + b
// (derohe cryptography/bn256/changes.go: const B = 3).
const bn256CurveB = 3

// validateCompressedPoint mirrors derohe's bn256 xToY / G1.DecodeCompressed
// decompression check without importing the DERO implementation.
//
// The compressed form is a 32-byte big-endian x coordinate followed by a
// one-byte y selector. bn256.G1.Compress only ever emits 0x00 or 0x01, so any
// other value is rejected here as non-canonical (DERO's own decoder is more
// permissive and would fall through to a default root).
func validateCompressedPoint(encoded []byte) error {
	if len(encoded) != 33 {
		return fmt.Errorf("compressed point must be 33 bytes")
	}
	if encoded[32] != 0 && encoded[32] != 1 {
		return fmt.Errorf("invalid y selector")
	}
	x := new(big.Int).SetBytes(encoded[:32])
	modulus, ok := new(big.Int).SetString(bn256FieldPrime, 16)
	if !ok {
		return fmt.Errorf("invalid field modulus")
	}
	if x.Cmp(modulus) >= 0 {
		return fmt.Errorf("x coordinate out of range")
	}
	// xToY: t = x³ + B. The point decompresses iff t is a quadratic residue
	// mod p, i.e. ModSqrt has a solution.
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, big.NewInt(bn256CurveB))
	rhs.Mod(rhs, modulus)
	if new(big.Int).ModSqrt(rhs, modulus) == nil {
		return fmt.Errorf("point is not on curve")
	}
	return nil
}

const deroBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var deroBech32Generator = [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func decodeBech32(s string) (string, []int, error) {
	if s == "" || (strings.ToLower(s) != s && strings.ToUpper(s) != s) {
		return "", nil, fmt.Errorf("mixed case or empty address")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, fmt.Errorf("invalid separator")
	}
	hrp := s[:pos]
	values := make([]int, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		v := strings.IndexByte(deroBech32Charset, s[i])
		if v < 0 {
			return "", nil, fmt.Errorf("invalid character")
		}
		values = append(values, v)
	}
	if bech32Polymod(append(bech32HrpExpand(hrp), values...)) != 1 {
		return "", nil, fmt.Errorf("invalid checksum")
	}
	return hrp, values[:len(values)-6], nil
}

func bech32Polymod(values []int) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, gen := range deroBech32Generator {
			if (top>>uint(i))&1 != 0 {
				chk ^= gen
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i]>>5))
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i]&31))
	}
	return out
}

func convertBits(data []int, fromBits, toBits uint, pad bool) ([]byte, error) {
	if fromBits == 0 || toBits == 0 || fromBits > 8 || toBits > 8 {
		return nil, fmt.Errorf("invalid bit size")
	}
	acc := 0
	bits := uint(0)
	maxv := (1 << toBits) - 1
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits))
	for _, value := range data {
		if value < 0 || (value>>fromBits) != 0 {
			return nil, fmt.Errorf("invalid data range")
		}
		acc = (acc << fromBits) | value
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return out, nil
}
