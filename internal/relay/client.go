package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// relayHTTPClient bounds every relay HTTP call. http.DefaultClient has NO
// timeout: an unreachable or hung relay (or mailbox, on the pull path) would
// block the caller forever — a phone on flaky mobile data could wedge mid-push
// with no way out. 30s matches the relay node's own forwarding client.
var relayHTTPClient = &http.Client{Timeout: 30 * time.Second}

// PushViaRelay pushes an opaque body through a relay hop toward a destination
// mailbox. relayBase is the anonymous middle node's base URL; destMailboxBase
// is the eventual mailbox base URL the relay should forward to, carried in the
// X-Relay-Dest header so the relay itself only ever stores/forwards the opaque
// body. The body is content-addressed: it must hash to cid. deadline bounds how
// long the relay holds the body; a zero deadline lets the relay apply its
// default retention. The call returns once the relay acknowledges (202) — the
// body is held and forwarded asynchronously.
func PushViaRelay(ctx context.Context, relayBase, destMailboxBase string, cid [32]byte, body []byte, deadline time.Time) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		relayBase+"/relay/"+hex.EncodeToString(cid[:]), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Relay-Dest", destMailboxBase)
	if !deadline.IsZero() {
		req.Header.Set("X-Burn-Deadline", strconv.FormatInt(deadline.Unix(), 10))
	}
	resp, err := relayHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("relay push: status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

// PullFromRelay pulls a held opaque body back from a relay node. Content
// addressing means only the party that already knows the cid (the destination
// mailbox or the recipient) can retrieve it; the relay itself never sees
// plaintext or keys. Returns the body, or an error if the relay no longer
// holds it.
func PullFromRelay(ctx context.Context, relayBase string, cid [32]byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		relayBase+"/relay/"+hex.EncodeToString(cid[:]), nil)
	if err != nil {
		return nil, err
	}
	resp, err := relayHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("relay pull: status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return io.ReadAll(resp.Body)
}
