package bounds

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const defaultFileCap = 64 << 10 // 64 KiB

// ErrTooLarge is returned when a file or JSON document exceeds its size limit.
var ErrTooLarge = fmt.Errorf("bounds: exceeds read limit")

// ReadBound is like os.ReadFile but enforces a hard byte cap. Returns ErrTooLarge if exceeded.
func ReadBound(path string, limit int) ([]byte, error) {
	if limit <= 0 {
		limit = defaultFileCap
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("bounds: read %s: %w", path, err)
	}
	if len(data) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}

// UnmarshalBound reads a local JSON file and unmarshals into dst only if the content fits within maxBytes.
func UnmarshalBound(path string, v any, maxBytes int) error {
	data, err := ReadBound(path, maxBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// ReaderToJSON binds a reader through a size-limiting filter before JSON decoding.
func ReaderToJSON(r io.Reader, dst any, maxBytes int) error {
	if maxBytes <= 0 {
		maxBytes = 512 << 10 // 512 KiB default for network responses
	}
	lr := io.LimitReader(r, int64(maxBytes)+1)
	raw, err := io.ReadAll(lr)
	if err != nil {
		return err
	}
	if len(raw) > maxBytes {
		return ErrTooLarge
	}
	return json.Unmarshal(raw, dst)
}
