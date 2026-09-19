// Package bounds defines resource limits for the parser/facade layer.
// Every reader, JSON decoder, and file loadable MUST honor one of these
// caps. Zero = "not set" (fallback to default); negative = unlimited
// (explicit opt-out). A positive value is an absolute ceiling in bytes.
package bounds

import (
	"bytes"
	"fmt"
	"io"
	"math"
)

// MaxReader is the maximum number of bytes any component will read from an
// untrusted source (JSON payload, mailbox post, chain response). It guards
// against both allocation DoS and slow-read exhaustion.
// Default: 1 MiB
const DefaultMaxRead int = 1 << 20 // 1 MiB

// MaxJSON is the maximum JSON document size accepted by json.Unmarshal
// calls. Values exceeding this cause ErrDocumentTooLarge before the parser
// even starts (checked via io.LimitedReader wrapping).
// Default: 512 KiB
const DefaultMaxJSON int = 1 << 19 // 512 KiB

// MaxFileRead is the maximum bytes read from any file opened on behalf of
// untrusted input (continuity artifact, prekey blob, etc.). Local files
// trusted by design (config, key material) may exceed this — those have
// their own path and trust model.
// Default: 64 KiB
const DefaultMaxFileRead int = 1 << 16 // 64 KiB

// MaxPostSize is the maximum size of a post/entry accepted from a peer
// channel or relay node.
// Default: 16 KiB
const DefaultMaxPostSize int = 1 << 14 // 16 KiB

// Limits holds per-context caps. Components that need stricter enforcement
// than the global defaults can instantiate and use their own struct.
type Limits struct {
	MaxRead     int // unbounded read (default DefaultMaxRead)
	MaxJSON     int // JSON document (default DefaultMaxJSON)
	MaxFileRead int // file read (default DefaultMaxFileRead)
	MaxPostSize int // peer post size (default DefaultMaxPostSize)
}

// Global returns the application-wide defaults. Callers who want to share
// the same limits can just copy *Global() directly.
func Global() *Limits {
	return &Limits{
		MaxRead:     DefaultMaxRead,
		MaxJSON:     DefaultMaxJSON,
		MaxFileRead: DefaultMaxFileRead,
		MaxPostSize: DefaultMaxPostSize,
	}
}

// Limiter returns an io.LimitReader sized to the caller's configured Maximum
// read (or DefaultMaxRead if zero/negative). Returns (nil, ErrUnlimited) when
// the caller explicitly opts out.
func (l *Limits) Limiter(r io.Reader) (io.Reader, error) {
	n := l.MaxRead
	if n <= 0 {
		return nil, fmt.Errorf("bounds: reader limit must be positive (got %d)", n)
	}
	if n > math.MaxInt {
		n = math.MaxInt
	}
	return io.LimitReader(r, int64(n)), nil
}

// JSONLimiter wraps a raw byte slice in a LimitedReader that never yields more
// than l.MaxJSON bytes. Call the returned reader's Read methods to feed the
// JSON decoder.
func (l *Limits) JSONLimiter(data []byte) io.Reader {
	if l.MaxJSON <= 0 || int64(len(data)) < int64(l.MaxJSON) {
		return bytes.NewReader(data)
	}
	return io.LimitReader(bytes.NewReader(data), int64(l.MaxJSON))
}

// FileLimiter limits reads from a local file descriptor. Same semantics as
// Limiter but scoped to file-backed operations.
func (l *Limits) FileLimiter(r io.Reader) (io.Reader, error) {
	n := l.MaxFileRead
	if n <= 0 {
		return nil, fmt.Errorf("bounds: file read limit must be positive (got %d)", n)
	}
	if n > math.MaxInt {
		n = math.MaxInt
	}
	return io.LimitReader(r, int64(n)), nil
}

// PostLimiter constrains peer-post payloads.
func (l *Limits) PostLimiter(r io.Reader) (io.Reader, error) {
	n := l.MaxPostSize
	if n <= 0 {
		return nil, fmt.Errorf("bounds: post size limit must be positive (got %d)", n)
	}
	if n > math.MaxInt {
		n = math.MaxInt
	}
	return io.LimitReader(r, int64(n)), nil
}

// CheckSize validates that a byte slice does not exceed the given cap.
func CheckSize(n int, actualSize int) bool {
	return actualSize <= n
}
