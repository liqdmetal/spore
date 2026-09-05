// Package peer is the seam from Go to the compost-peer Rust transport: a small
// helper that fetches a body by CID over the peer transport and returns it.
//
// The compost-peer binary (derohe-rs, BSD-3) serves/fetches ECDH-encrypted
// bodies by CID with sha256 integrity. This Go seam shells out to it so the
// long-message recv path can pull a body without reimplementing the TCP
// framing.
package peer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Fetch retrieves the body for cid from addr via the compost-peer binary.
// addr is host:port of the sender's peer transport. The body bytes are
// returned; caller decrypts with the ECDH key from the whisper pointer.
func Fetch(ctx context.Context, binary, addr string, cid [32]byte) ([]byte, error) {
	if binary == "" {
		binary = "compost-peer"
	}
	cidHex := hex.EncodeToString(cid[:])
	tmp, err := os.CreateTemp("", "compost-body-*")
	if err != nil {
		return nil, err
	}
	out := tmp.Name()
	tmp.Close()
	defer os.Remove(out)

	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, binary, "fetch", "--addr", addr,
		"--cid", cidHex, "--out", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("peer fetch: %w: %s", err, b)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("peer fetch: empty body")
	}
	return body, nil
}
