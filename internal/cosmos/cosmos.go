// Package cosmos provides a deliberately generic HTTP carrier for Cosmos SDK chains.
package cosmos

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
)

const (
	PointerSize     = 74
	PointerVersion  = 1
	PointerReserved = 0
)

var ErrDeliveryNotGuaranteed = errors.New("cosmos: selected endpoint cannot guarantee pointer delivery")

type Config struct {
	ChainID, BaseURL               string
	PostPath, ListPath, HeightPath string
	MessageField, RecipientField   string
	AddressValue                   string
	Timeout                        time.Duration
	HTTPClient                     *http.Client
	DeliveryGuaranteed             bool
}

type Backend struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Backend {
	if cfg.MessageField == "" {
		cfg.MessageField = "memo"
	}
	if cfg.RecipientField == "" {
		cfg.RecipientField = "to"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: cfg.Timeout}
	}
	return &Backend{cfg: cfg, client: c}
}
func (b *Backend) Validate() error {
	if s := strings.TrimSpace(b.cfg.ChainID); s == "" {
		return errors.New("cosmos: chain ID is required")
	}
	if strings.TrimSpace(b.cfg.BaseURL) == "" {
		return errors.New("cosmos: base URL is required")
	}
	u, e := url.Parse(b.cfg.BaseURL)
	if e != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("cosmos: base URL must be absolute")
	}
	if b.cfg.PostPath == "" || b.cfg.ListPath == "" || b.cfg.HeightPath == "" {
		return errors.New("cosmos: explicit profile paths are required")
	}
	return nil
}
func (b *Backend) Name() string                            { return b.cfg.ChainID }
func (b *Backend) Address(context.Context) (string, error) { return b.cfg.AddressValue, nil }
func (b *Backend) Height(ctx context.Context) (uint64, error) {
	var v struct {
		Height uint64 `json:"height"`
	}
	if err := b.get(ctx, b.cfg.HeightPath, &v); err != nil {
		return 0, err
	}
	return v.Height, nil
}
func (b *Backend) PostPayload(ctx context.Context, to string, p chain.Payload, _ uint64) (chain.PostResult, error) {
	if !b.cfg.DeliveryGuaranteed {
		return chain.PostResult{}, ErrDeliveryNotGuaranteed
	}
	if !validPointer(p) {
		return chain.PostResult{}, fmt.Errorf("cosmos: pointer must be canonical (%d bytes)", PointerSize)
	}
	v := map[string]string{b.cfg.MessageField: hex.EncodeToString(p), b.cfg.RecipientField: to}
	data, _ := json.Marshal(v)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url(b.cfg.PostPath), strings.NewReader(string(data)))
	if err != nil {
		return chain.PostResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return chain.PostResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return chain.PostResult{}, fmt.Errorf("cosmos: post status %s", resp.Status)
	}
	var out struct {
		TxHash string `json:"txhash"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return chain.PostResult{}, err
	}
	return chain.PostResult{TxID: out.TxHash}, nil
}

type message struct {
	TxID   string `json:"tx_id"`
	To     string `json:"to"`
	Memo   string `json:"memo"`
	Height int64  `json:"height"`
}

// parseMessage accepts configurable message and recipient field names.
func (b *Backend) parseMessage(raw map[string]json.RawMessage) (message, bool) {
	var m message
	get := func(name string, dst any) bool {
		v, ok := raw[name]
		return ok && json.Unmarshal(v, dst) == nil
	}
	if !get("tx_id", &m.TxID) || !get(b.cfg.RecipientField, &m.To) || !get(b.cfg.MessageField, &m.Memo) {
		return message{}, false
	}
	_ = get("height", &m.Height)
	return m, true
}

func (b *Backend) ListIncoming(ctx context.Context, min uint64) ([]chain.Incoming, error) {
	var v struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := b.get(ctx, b.cfg.ListPath, &v); err != nil {
		return nil, err
	}
	out := []chain.Incoming{}
	for _, raw := range v.Messages {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			continue
		}
		m, ok := b.parseMessage(fields)
		if !ok {
			continue
		}
		if b.cfg.AddressValue != "" && m.To != b.cfg.AddressValue || m.Height < int64(min) {
			continue
		}
		raw, err := hex.DecodeString(m.Memo)
		if err != nil || !validPointer(raw) {
			continue
		}
		out = append(out, chain.Incoming{TxID: m.TxID, TopoHeight: m.Height, Payload: chain.Payload(raw)})
	}
	return out, nil
}
func validPointer(p []byte) bool {
	if len(p) != PointerSize || p[0] != PointerVersion || p[1] != PointerReserved {
		return false
	}
	return binary.LittleEndian.Uint64(p[66:74]) != 0
}

func (b *Backend) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url(path), nil)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("cosmos: status %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}
func (b *Backend) url(path string) string {
	return strings.TrimRight(b.cfg.BaseURL, "/") + "/" + strings.TrimLeft(path, "/")
}

var _ chain.Chain = (*Backend)(nil)
