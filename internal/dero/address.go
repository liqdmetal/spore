package dero

import (
	"fmt"
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
	if hrp == "deroi" && len(raw) <= 34 {
		return "", fmt.Errorf("dero: invalid integrated address length")
	}
	return addr, nil
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
