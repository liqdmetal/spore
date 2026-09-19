package dero

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/liqdmetal/spore/internal/anchor"
)

func decodeEnvelopeArgument(a argJSON) (anchor.Argument, error) {
	arg := anchor.Argument{Name: a.N, DataType: a.T}
	switch a.T {
	case anchor.DataString, anchor.DataHash:
		var value string
		if err := json.Unmarshal(a.V, &value); err != nil {
			return arg, fmt.Errorf("dero: argument %q value must be a JSON string: %w", a.N, err)
		}
		if a.T == anchor.DataHash {
			if len(value) != 64 {
				return arg, fmt.Errorf("dero: argument %q hash must be 64 hex characters", a.N)
			}
			if _, err := hex.DecodeString(value); err != nil {
				return arg, fmt.Errorf("dero: argument %q hash is not hexadecimal: %w", a.N, err)
			}
		}
		arg.Value = value
	case anchor.DataUint64:
		var value string
		if err := json.Unmarshal(a.V, &value); err != nil {
			return arg, fmt.Errorf("dero: argument %q uint must be a JSON string: %w", a.N, err)
		}
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return arg, fmt.Errorf("dero: bad uint in payload: %w", err)
		}
		arg.Value = n
	case anchor.DataInt64:
		var value string
		if err := json.Unmarshal(a.V, &value); err != nil {
			return arg, fmt.Errorf("dero: argument %q int must be a JSON string: %w", a.N, err)
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return arg, fmt.Errorf("dero: bad int in payload: %w", err)
		}
		arg.Value = n
	case anchor.DataFloat64:
		var value string
		if err := json.Unmarshal(a.V, &value); err != nil {
			return arg, fmt.Errorf("dero: argument %q float must be a JSON string: %w", a.N, err)
		}
		f, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return arg, fmt.Errorf("dero: bad float in payload")
		}
		arg.Value = f
	case anchor.DataTime:
		var value string
		if err := json.Unmarshal(a.V, &value); err != nil {
			return arg, fmt.Errorf("dero: argument %q time must be a JSON string: %w", a.N, err)
		}
		when, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return arg, fmt.Errorf("dero: bad time in payload: %w", err)
		}
		arg.Value = when
	case anchor.DataAddress:
		var encoded string
		if err := json.Unmarshal(a.V, &encoded); err != nil {
			return arg, fmt.Errorf("dero: argument %q address must be a JSON string: %w", a.N, err)
		}
		decoded, err := hex.DecodeString(encoded)
		if err != nil || len(decoded) != 33 {
			return arg, fmt.Errorf("dero: argument %q address must be 33-byte hex", a.N)
		}
		if err := validateCompressedPoint(decoded); err != nil {
			return arg, fmt.Errorf("dero: argument %q invalid compressed address: %w", a.N, err)
		}
		arg.Value = decoded
	default:
		return arg, fmt.Errorf("dero: unsupported argument datatype %q", a.T)
	}
	return arg, nil
}
