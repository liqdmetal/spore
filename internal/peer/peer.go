// Package peer is the seam from Go to the spore-peer Rust transport: a small
// helper that fetches a body by CID over the peer transport and returns it.
//
// The spore-peer binary (derohe-rs, BSD-3) serves/fetches ECDH-encrypted
// bodies by CID with sha256 integrity. This Go seam shells out to it so the
// long-message recv path can pull a body without reimplementing the TCP
// framing.
package peer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// MaxBody is the largest body this seam will accept from a peer (64 MB). A
// peer returning more is treated as hostile/faulty — defense against a
// compromised or buggy remote node streaming unbounded data.
const MaxBody = 64 * 1024 * 1024

// ErrTooBig is returned when a peer returns a body larger than MaxBody.
var ErrTooBig = errors.New("peer: body exceeds size limit")

// bodyResult carries the bytes (or an error) read from the transport.
type bodyResult struct {
	data []byte
	err  error
}

// errEmpty is returned for an empty body.
var errEmpty = errors.New("peer fetch: empty body")

// verifyBody applies the seam's gates to a fetched body: non-nil transport
// error, size cap, non-empty, and sha256(body) == cid. It is pure so it can be
// unit-tested without shelling to a real binary.
func verifyBody(res bodyResult, cid [32]byte) error {
	if res.err != nil {
		return res.err
	}
	if res.data == nil || len(res.data) == 0 {
		return errEmpty
	}
	if len(res.data) > MaxBody {
		return ErrTooBig
	}
	sum := sha256.Sum256(res.data)
	if sum != cid {
		return errors.New("peer fetch: body sha256 != cid (tampered or wrong body)")
	}
	return nil
}

// Fetch retrieves the body for cid from addr via the spore-peer binary.
// addr is host:port of the sender's peer transport. The body bytes are
// returned AFTER verifying sha256(body) == cid, so a tampered or wrong body
// never reaches the caller's decrypt. Caller then decrypts with the ECDH key
// from the whisper pointer.
func Fetch(ctx context.Context, binary, addr string, cid [32]byte) ([]byte, error) {
	if binary == "" {
		binary = "spore-peer"
	}
	cidHex := hex.EncodeToString(cid[:])
	tmp, err := os.CreateTemp("", "compost-body-*")
	if err != nil {
		return nil, err
	}
	out := tmp.Name()
	tmp.Close()
	defer os.Remove(out)

	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, binary, "fetch", "--addr", addr,
		"--cid", cidHex, "--out", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("peer fetch: %w: %s", err, b)
	}
	st, err := os.Stat(out)
	if err != nil {
		return nil, err
	}
	if st.Size() > MaxBody {
		return nil, ErrTooBig
	}
	body, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	if err := verifyBody(bodyResult{data: body}, cid); err != nil {
		return nil, err
	}
	return body, nil
}
