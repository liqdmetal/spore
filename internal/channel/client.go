package channel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client is an HTTP client for a channel box. It is the endpoint side: it
// seals private lines (under the caller's channel key) before Post, and opens
// them after Poll. The box itself never sees a key.
type Client struct {
	base   string
	http   *http.Client
	sender string // our identity (DERO address or nick) stamped on lines
}

// NewClient points at a channel box base URL (e.g. http://host:19192).
func NewClient(base, sender string) (*Client, error) {
	if base == "" {
		return nil, fmt.Errorf("channel: empty box base URL")
	}
	return &Client{base: base, sender: sender, http: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out interface{}) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("channel: %s %s: %s %s", method, path, resp.Status, msg)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// PublicPost posts a plaintext line (public channel — readable by anyone).
func (c *Client) PublicPost(ctx context.Context, ch string, text []byte) (Line, error) {
	var out Line
	err := c.do(ctx, "POST", "/line", map[string]interface{}{
		"channel": ch, "sender": c.sender, "private": false, "data": text,
	}, &out)
	return out, err
}

// PrivatePost seals text under the channel key (random nonce), then posts the
// ciphertext. The box stores it but cannot read it.
func (c *Client) PrivatePost(ctx context.Context, ch string, k *Key, text []byte) (Line, error) {
	sealed, err := SealLine(k, ch, text)
	if err != nil {
		return Line{}, err
	}
	var out Line
	err = c.do(ctx, "POST", "/line", map[string]interface{}{
		"channel": ch, "sender": c.sender, "private": true, "data": sealed,
	}, &out)
	return out, err
}

// Poll returns raw lines in ch with seq > after (ciphertext intact).
func (c *Client) Poll(ctx context.Context, ch string, after uint64) ([]Line, error) {
	var lines []Line
	path := "/lines?channel=" + url.QueryEscape(ch) + "&after=" + strconv.FormatUint(after, 10)
	if err := c.do(ctx, "GET", path, nil, &lines); err != nil {
		return nil, err
	}
	return lines, nil
}

// PollOpen fetches lines after the given seq. If k is non-nil it decrypts
// private lines under it (wrong-key lines are dropped); otherwise private
// ciphertext is returned raw.
func (c *Client) PollOpen(ctx context.Context, ch string, after uint64, k *Key) ([]string, error) {
	var lines []Line
	path := "/lines?channel=" + url.QueryEscape(ch) + "&after=" + strconv.FormatUint(after, 10)
	if err := c.do(ctx, "GET", path, nil, &lines); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		if ln.Private {
			if k == nil {
				continue // we have no key — cannot read this room
			}
			pt, err := OpenLine(k, ch, ln.Data)
			if err != nil {
				continue // wrong key / tampered — skip
			}
			out = append(out, fmt.Sprintf("[%s] %s", ln.Sender, pt))
		} else {
			out = append(out, fmt.Sprintf("[%s] %s", ln.Sender, ln.Data))
		}
	}
	return out, nil
}

// Heartbeat announces presence on ch. Call periodically to stay "online".
func (c *Client) Heartbeat(ctx context.Context, ch string) error {
	return c.do(ctx, "POST", "/presence", map[string]interface{}{"channel": ch, "addr": c.sender}, nil)
}

// Online returns the currently-present members of ch.
func (c *Client) Online(ctx context.Context, ch string) ([]string, error) {
	var out []string
	err := c.do(ctx, "GET", "/online?channel="+url.QueryEscape(ch), nil, &out)
	return out, err
}

// HeartbeatLoop heartbeats on ch every interval until ctx is done.
func (c *Client) HeartbeatLoop(ctx context.Context, ch string, interval time.Duration) {
	if interval <= 0 {
		interval = 20 * time.Second
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = c.Heartbeat(ctx, ch)
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				return
			}
		}
	}()
}
