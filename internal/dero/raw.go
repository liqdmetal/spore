package dero

import (
	"encoding/hex"
	"fmt"

	"github.com/liqdmetal/spore/internal/anchor"
)

const maxRawPayloadBytes = 4096
const maxRawMapPairs = 64

// RawPayloadToArgs decodes the first padded DERO payload-0 map. R153 puts a
// sender-position byte before the CBOR map and random padding after it. The
// map's declared pair count, not the input length, controls parsing.
func RawPayloadToArgs(data []byte) (anchor.Arguments, error) {
	if len(data) < 2 || len(data) > maxRawPayloadBytes {
		return nil, fmt.Errorf("dero: invalid raw payload length %d", len(data))
	}
	// data[0] is DERO's reserved ring-position byte. transaction.go:
	// "1 byte has been reserved for sender position in ring representation in
	// a byte, uptp 256 ring" — and transaction_build.go writes
	// byte(witness_index[1]) into it from a randomly shuffled ring, so EVERY
	// byte value 0x00-0xff is a legitimate position.
	//
	// It is deliberately NOT range-checked. Any bound here silently drops real
	// messages (a `> 127` bound discards roughly half of large-ring traffic).
	// What actually keeps non-payload data out of this fallback is that the
	// CBOR map must parse at offset 1 and every typed argument must validate.
	count, i, err := cborContainerLen(data, 1, 5)
	if err != nil || count > maxRawMapPairs {
		return nil, fmt.Errorf("dero: invalid raw payload map")
	}
	out := make(anchor.Arguments, 0, count)
	seen := make(map[string]struct{}, count)
	for n := uint64(0); n < count; n++ {
		key, next, ok := cborText(data, i)
		if !ok || len(key) < 2 {
			return nil, fmt.Errorf("dero: invalid raw payload key")
		}
		i = next
		end, ok := cborSkip(data, i, 0)
		if !ok {
			return nil, fmt.Errorf("dero: invalid raw payload value")
		}
		value := data[i:end]
		name := string(key[:len(key)-1])
		typ := string(key[len(key)-1:])
		identity := string(key)
		if _, exists := seen[identity]; exists {
			return nil, fmt.Errorf("dero: duplicate raw payload key %q", identity)
		}
		seen[identity] = struct{}{}
		arg, err := rawArgument(name, typ, value)
		if err != nil {
			return nil, err
		}
		out = append(out, arg)
		i = end
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("dero: empty raw payload map")
	}
	return out, nil
}

func rawArgument(name, typ string, value []byte) (anchor.Argument, error) {
	arg := anchor.Argument{Name: name, DataType: typ}
	switch typ {
	case anchor.DataUint64:
		n, next, ok := cborUint(value, 0)
		if !ok || next != len(value) {
			return arg, fmt.Errorf("dero: invalid raw uint argument %q", name)
		}
		arg.Value = n
	case anchor.DataString:
		s, next, ok := cborText(value, 0)
		if !ok || next != len(value) {
			return arg, fmt.Errorf("dero: invalid raw string argument %q", name)
		}
		arg.Value = string(s)
	case anchor.DataHash:
		b, next, ok := cborBytes(value, 0)
		if !ok || next != len(value) || len(b) != 32 {
			return arg, fmt.Errorf("dero: invalid raw hash argument %q", name)
		}
		arg.Value = hex.EncodeToString(b)
	default:
		return arg, fmt.Errorf("dero: unsupported raw datatype %q", typ)
	}
	return arg, nil
}

func cborContainerLen(data []byte, i int, major byte) (uint64, int, error) {
	if i >= len(data) || data[i]>>5 != major {
		return 0, i, fmt.Errorf("wrong cbor major type")
	}
	ai := data[i] & 0x1f
	i++
	var n uint64
	switch {
	case ai < 24:
		n = uint64(ai)
	case ai == 24:
		if i+1 > len(data) {
			return 0, i, fmt.Errorf("short cbor length")
		}
		n = uint64(data[i])
		i++
	case ai == 25:
		if i+2 > len(data) {
			return 0, i, fmt.Errorf("short cbor length")
		}
		n = uint64(data[i])<<8 | uint64(data[i+1])
		i += 2
	case ai == 26:
		if i+4 > len(data) {
			return 0, i, fmt.Errorf("short cbor length")
		}
		for j := 0; j < 4; j++ {
			n = n<<8 | uint64(data[i+j])
		}
		i += 4
	case ai == 27:
		if i+8 > len(data) {
			return 0, i, fmt.Errorf("short cbor length")
		}
		for j := 0; j < 8; j++ {
			n = n<<8 | uint64(data[i+j])
		}
		i += 8
	default:
		return 0, i, fmt.Errorf("indefinite cbor length")
	}
	return n, i, nil
}

func cborText(data []byte, i int) ([]byte, int, bool) {
	b, next, ok := cborBytesLike(data, i, 3)
	return b, next, ok
}

func cborBytes(data []byte, i int) ([]byte, int, bool) {
	return cborBytesLike(data, i, 2)
}

func cborBytesLike(data []byte, i int, major byte) ([]byte, int, bool) {
	n, next, err := cborContainerLen(data, i, major)
	if err != nil || n > uint64(len(data)-next) {
		return nil, i, false
	}
	end := next + int(n)
	return data[next:end], end, true
}

func cborUint(data []byte, i int) (uint64, int, bool) {
	if i >= len(data) || data[i]>>5 != 0 {
		return 0, i, false
	}
	n, next, err := cborContainerLen(data, i, 0)
	if err != nil {
		return 0, i, false
	}
	return n, next, true
}

func cborSkip(data []byte, i, depth int) (int, bool) {
	if depth > 16 || i >= len(data) {
		return i, false
	}
	major := data[i] >> 5
	switch major {
	case 0, 1:
		_, next, err := cborContainerLen(data, i, major)
		return next, err == nil
	case 2, 3:
		_, next, ok := cborBytesLike(data, i, major)
		return next, ok
	case 4:
		count, next, err := cborContainerLen(data, i, major)
		if err != nil || count > maxRawMapPairs {
			return i, false
		}
		for j := uint64(0); j < count; j++ {
			var ok bool
			next, ok = cborSkip(data, next, depth+1)
			if !ok {
				return i, false
			}
		}
		return next, true
	case 5:
		count, next, err := cborContainerLen(data, i, major)
		if err != nil || count > maxRawMapPairs/2 {
			return i, false
		}
		for j := uint64(0); j < count*2; j++ {
			var ok bool
			next, ok = cborSkip(data, next, depth+1)
			if !ok {
				return i, false
			}
		}
		return next, true
	case 6:
		_, next, err := cborContainerLen(data, i, major)
		if err != nil {
			return i, false
		}
		return cborSkip(data, next, depth+1)
	case 7:
		ai := data[i] & 0x1f
		sz := 1
		switch ai {
		case 24:
			sz = 2
		case 25:
			sz = 3
		case 26:
			sz = 5
		case 27:
			sz = 9
		case 31:
			return i, false
		}
		if i+sz > len(data) {
			return i, false
		}
		return i + sz, true
	default:
		return i, false
	}
}
