package fabric

// This file is the fabric CLIENT face (slice F2): the same wire contract the
// Rust relay serves (WIRE_SPEC §8), driven from Go. The handle and possession
// token are seed-derived (derivation in fabric.go, pinned by the fabric_v1
// vectors), so a client needs only the shared seed from the contact card —
// never a per-relay secret — and every relay sees the same derivation.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// renewalWindow: re-register when a lease has this long left. The drain loop
// calls EnsureRegistered before every pass; without a window, a lease could
// expire between the check and a relay-side sweep.
const renewalWindow = 5 * time.Minute

// maxDrain is the client's per-fpop batch; the relay caps at 64.
const maxDrain = 64

// Client is one fabric relay connection set. Safe for concurrent use.
// The wire ride is pluggable (F4a's FabricTransport seam): NewClient dials
// TCP exactly as always; NewClientOn runs the identical state machine over
// any transport (in-memory for hermetic tests; the F4d sidecars later).
type Client struct {
	tr FabricTransport

	mu      sync.Mutex
	handle  string // lowercase hex
	token   string // hex possession token (seed-derived, nonce-bound)
	nonce   string // nonce the current token was bound to
	expires time.Time
}

// NewClient builds a client for the relay at addr. The handle derives from
// (seed, epoch, sid); the token is bound to a nonce at Register time.
func NewClient(addr string, seed [32]byte, epoch uint32, sid [8]byte) (*Client, error) {
	return NewClientOn(NewTCPTransport(addr), seed, epoch, sid)
}

// NewClientOn builds a client over an arbitrary transport. The state machine
// — lease renewal window, one re-register + retry on auth refusals, drain
// batching — is transport-agnostic by construction: nothing below this line
// knows how requests move.
func NewClientOn(tr FabricTransport, seed [32]byte, epoch uint32, sid [8]byte) (*Client, error) {
	handle, err := FabricHandle(seed, epoch, sid)
	if err != nil {
		return nil, err
	}
	return &Client{
		tr:     tr,
		handle: hex.EncodeToString(handle[:]),
	}, nil
}

// Close releases the underlying transport (a no-op for TCP and in-memory;
// sidecar transports own real resources).
func (c *Client) Close() error { return c.tr.Close() }

// Handle returns the lowercase-hex fabric handle this client publishes under.
func (c *Client) Handle() string { return c.handle }

// --- §5 frame primitives ----------------------------------------------------

// writeFrame/readFrame: LE32 length + payload, the framing every spore-peer
// socket speaks (§5). readFrame caps replies at 1 MiB — far above the largest
// legal fpop payload (64 × 148 hex + JSON) and far below anything hostile.
func writeFrame(w io.Writer, payload []byte) error {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("fabric: bad reply frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// verb sends one fabric verb over the transport and returns the parsed
// payload on success, or an error carrying the relay's verbatim status string.
func (c *Client) verb(ctx context.Context, verbName string, req map[string]any) (map[string]any, error) {
	out, err := c.tr.RoundTrip(ctx, Request{Verb: verbName, Payload: req})
	if err != nil {
		return nil, err
	}
	return out.Payload, nil
}

// Register performs freg against the relay. The possession token is the
// seed-derived HMAC bound to a self-chosen nonce (the F1 relay does not
// challenge, so the client supplies one and keeps it for later renewal —
// the relay never sees the seed, only the derived token).
func (c *Client) Register(ctx context.Context, seed [32]byte, lease time.Duration) error {
	c.mu.Lock()
	nonce := c.nonce
	c.mu.Unlock()
	if nonce == "" {
		nonce = fmt.Sprintf("spore-%x-%d", c.handle[:8], time.Now().UnixNano())
	}
	handleBytes, err := hex.DecodeString(c.handle)
	if err != nil {
		return err
	}
	var handleArr [32]byte
	copy(handleArr[:], handleBytes)
	token := RegToken(seed, handleArr, nonce)

	out, err := c.verb(ctx, "freg", map[string]any{
		"handle": c.handle,
		"token":  token,
		"nonce":  nonce,
		"lease":  int64(lease / time.Second),
	})
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.token = token
	c.nonce = nonce
	if exp, ok := out["expires"].(float64); ok {
		c.expires = time.Unix(int64(exp), 0)
	}
	c.mu.Unlock()
	return nil
}

// Publish performs fput: queue one 74-byte pointer envelope at this handle.
// Requires Register first.
func (c *Client) Publish(ctx context.Context, pointer []byte, deadline time.Time) error {
	if len(pointer) != 74 {
		return fmt.Errorf("fabric: publish wants a 74-byte pointer, got %d bytes", len(pointer))
	}
	_, err := c.verb(ctx, "fput", map[string]any{
		"handle":      c.handle,
		"pointer_hex": hex.EncodeToString(pointer),
		"deadline":    deadline.Unix(),
	})
	return err
}

// PublishAs performs fput at an ARBITRARY handle — the sender's verb: the
// sender derives the recipient's fabric handle from the contact seed and
// publishes to it without ever registering (registration is the recipient's
// role; fput needs no token, only a live registration at the relay).
func PublishAs(ctx context.Context, addr, handleHex string, pointer []byte, deadline time.Time) error {
	if len(pointer) != 74 {
		return fmt.Errorf("fabric: publish wants a 74-byte pointer, got %d bytes", len(pointer))
	}
	c := &Client{tr: NewTCPTransport(addr), handle: handleHex}
	_, err := c.verb(ctx, "fput", map[string]any{
		"handle":      handleHex,
		"pointer_hex": hex.EncodeToString(pointer),
		"deadline":    deadline.Unix(),
	})
	return err
}

// Drain performs fpop, returning the queued pointers oldest-first. Each
// drained pointer is exactly the 74-byte payload a sender published.
func (c *Client) Drain(ctx context.Context, max int) ([][]byte, error) {
	if max > maxDrain {
		max = maxDrain
	}
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()
	if token == "" {
		return nil, errors.New("fabric: drain before register")
	}
	out, err := c.verb(ctx, "fpop", map[string]any{
		"handle": c.handle,
		"token":  token,
		"max":    max,
	})
	if err != nil {
		return nil, err
	}
	arr, _ := out["pointers"].([]any)
	ptrs := make([][]byte, 0, len(arr))
	for _, item := range arr {
		s, _ := item.(string)
		raw, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("fabric: bad pointer hex from relay: %w", err)
		}
		ptrs = append(ptrs, raw)
	}
	return ptrs, nil
}

// EnsureRegistered registers when this process has never fregged, or when
// the lease is within renewalWindow of expiry. For the seed holder the freg
// is a chained refresh (prev_token = current token), which the relay accepts.
func (c *Client) EnsureRegistered(ctx context.Context, seed [32]byte, lease time.Duration) error {
	c.mu.Lock()
	need := c.token == "" || time.Until(c.expires) < renewalWindow
	c.mu.Unlock()
	if need {
		return c.Register(ctx, seed, lease)
	}
	return nil
}

// isAuthError reports whether a relay refusal is an auth-shape error (lease
// expired / token mismatch) that one re-register + retry can clear.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "403") || strings.Contains(msg, "404")
}

// DrainOnce is the subscribe tick: ensure the lease, drain, and return the
// raw pointer payloads for the caller to dedupe and ingest. Dedupe moved to
// the drain-union store (SeenCIDs, F3 / AUDIT-RELAYFABRIC R-N1): the old
// per-client map could only dedupe within one (relay, handle), so N-relay
// redundancy delivered the same CID once per relay, and a restart forgot
// everything. The union keys by CID (bytes 34:66) and marks CONSUMED only —
// the caller observes successes, so a pointer whose body fetch failed still
// rides a redundant copy from another relay. A 403/404 (lease expired
// server-side between renewals) triggers exactly one re-register + retry.
func (c *Client) DrainOnce(ctx context.Context, seed [32]byte, lease time.Duration) ([][]byte, error) {
	if err := c.EnsureRegistered(ctx, seed, lease); err != nil {
		return nil, err
	}
	ptrs, err := c.Drain(ctx, maxDrain)
	if err != nil && isAuthError(err) {
		if rerr := c.Register(ctx, seed, lease); rerr != nil {
			return nil, rerr
		}
		ptrs, err = c.Drain(ctx, maxDrain)
	}
	if err != nil {
		return nil, err
	}
	return ptrs, nil
}
