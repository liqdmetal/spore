package dero

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/liqdmetal/spore/internal/anchor"
)

// Payload0Limit is transaction.PAYLOAD0_LIMIT in DERO R153:
// 144 bytes total minus the 33-byte transaction key.
const Payload0Limit = 111

var r153EncMode = func() cbor.EncMode {
	mode, err := (cbor.EncOptions{
		Sort:          cbor.SortCoreDeterministic,
		ShortestFloat: cbor.ShortestFloat16,
		NaNConvert:    cbor.NaNConvert7e00,
		InfConvert:    cbor.InfConvertFloat16,
		IndefLength:   cbor.IndefLengthForbidden,
		TimeTag:       cbor.EncTagRequired,
	}).EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// PackArguments serializes the supported DERO RPC arguments using the same
// deterministic CBOR settings as R153 rpc.Arguments.MarshalBinary. The result
// is unpadded; the wallet adds random padding up to Payload0Limit.
func PackArguments(args anchor.Arguments) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("dero: empty payload arguments")
	}
	values := make(map[string]interface{}, len(args))
	for _, arg := range args {
		if arg.Name == "" || !validDataType(arg.DataType) {
			return nil, fmt.Errorf("dero: invalid argument %q/%q", arg.Name, arg.DataType)
		}
		key := arg.Name + arg.DataType
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("dero: duplicate argument %q", key)
		}
		value, err := packValue(arg)
		if err != nil {
			return nil, err
		}
		values[key] = value
	}
	packed, err := r153EncMode.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("dero: CBOR encode: %w", err)
	}
	if len(packed) > Payload0Limit {
		return nil, fmt.Errorf("dero: payload is %d bytes, R153 limit is %d", len(packed), Payload0Limit)
	}
	return packed, nil
}

func validDataType(t string) bool {
	switch t {
	case anchor.DataString, anchor.DataInt64, anchor.DataUint64, anchor.DataFloat64, anchor.DataHash, anchor.DataAddress, anchor.DataTime:
		return true
	default:
		return false
	}
}

func packValue(arg anchor.Argument) (interface{}, error) {
	switch arg.DataType {
	case anchor.DataString:
		v, ok := arg.Value.(string)
		if !ok {
			return nil, fmt.Errorf("dero: %s must be string", arg.Name)
		}
		return v, nil
	case anchor.DataUint64:
		v, ok := arg.Value.(uint64)
		if !ok {
			return nil, fmt.Errorf("dero: %s must be uint64", arg.Name)
		}
		return v, nil
	case anchor.DataInt64:
		v, ok := arg.Value.(int64)
		if !ok {
			return nil, fmt.Errorf("dero: %s must be int64", arg.Name)
		}
		return v, nil
	case anchor.DataFloat64:
		v, ok := arg.Value.(float64)
		if !ok || math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("dero: %s must be finite float64", arg.Name)
		}
		return v, nil
	case anchor.DataHash:
		v, ok := arg.Value.(string)
		if !ok {
			return nil, fmt.Errorf("dero: %s must be 64-char hash hex", arg.Name)
		}
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("dero: %s must be 64-char hash hex", arg.Name)
		}
		return b, nil
	case anchor.DataAddress:
		v, ok := arg.Value.([]byte)
		if !ok || len(v) != 33 {
			return nil, fmt.Errorf("dero: %s must be a 33-byte compressed address key", arg.Name)
		}
		return v, nil
	case anchor.DataTime:
		v, ok := arg.Value.(time.Time)
		if !ok {
			return nil, fmt.Errorf("dero: %s must be time.Time", arg.Name)
		}
		return v, nil
	default:
		return nil, fmt.Errorf("dero: unsupported argument datatype %q", arg.DataType)
	}
}
