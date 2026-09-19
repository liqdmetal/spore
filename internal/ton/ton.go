// Package ton carries exact E2 pointers in TON text comments.
package ton

import (
	"context"
	"encoding/base64"
	"encoding/binary"
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

const PointerSize = 74
const PointerVersion = 1
const PointerReserved = 0

var ErrMalformedComment = errors.New("ton: malformed comment")
var ErrDeliveryNotGuaranteed = errors.New("ton: sender does not guarantee delivery")

// Sender is the wallet seam. Implementations must submit a message containing
// the exact comment supplied; no fallback transfer is permitted.
type Sender interface {
	Send(context.Context, string, string) (string, error)
}

type Config struct {
	Address                        string
	Network                        string
	BaseURL                        string
	PostPath, ListPath, HeightPath string
	HTTPClient                     *http.Client
	Timeout                        time.Duration
	Sender                         Sender
	// AllowedSources, when non-empty, is an exact allowlist for incoming sources.
	AllowedSources []string
	// DeliveryGuaranteed must be set by a sender that can prove the comment
	// reaches the recipient. TON value-only transfers are never a downgrade.
	DeliveryGuaranteed bool
}

type Backend struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Backend {

	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	return &Backend{cfg: cfg, client: cfg.HTTPClient}
}

// EncodeComment encodes the E2 pointer profile (0xe2 version, zero flags) as the TON comment payload; this is not a generic TON API message format.
func EncodeComment(pointer []byte) (string, error) {
	if !validPointer(pointer) {
		return "", fmt.Errorf("ton: pointer must be %d bytes", PointerSize)
	}
	return base64.StdEncoding.EncodeToString(pointer), nil
}

// ParseComment accepts only canonical padded base64, preventing ambiguous input.
func ParseComment(s string) ([]byte, error) {
	if len(s) != base64.StdEncoding.EncodedLen(PointerSize) {
		return nil, ErrMalformedComment
	}
	p, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(p) != PointerSize || base64.StdEncoding.EncodeToString(p) != s {
		return nil, ErrMalformedComment
	}
	if !validPointer(p) {
		return nil, ErrMalformedComment
	}
	return p, nil
}

func (b *Backend) validateConfig() error {
	if b.cfg.Network != "mainnet" && b.cfg.Network != "testnet" {
		return errors.New("ton: unsupported network profile")
	}
	if strings.TrimSpace(b.cfg.Address) == "" {
		return errors.New("ton: missing address")
	}
	u, err := url.Parse(b.cfg.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return errors.New("ton: invalid base URL")
	}
	if b.cfg.PostPath == "" || b.cfg.ListPath == "" || b.cfg.HeightPath == "" {
		return errors.New("ton: explicit profile paths are required")
	}
	return nil
}

func validPointer(p []byte) bool {
	if len(p) != PointerSize || p[0] != PointerVersion || p[1] != PointerReserved {
		return false
	}
	return binary.LittleEndian.Uint64(p[66:]) != 0
}

func (b *Backend) Name() string { return "ton" }
func (b *Backend) Address(context.Context) (string, error) {
	if b.cfg.Address == "" {
		return "", errors.New("ton: missing address")
	}
	return b.cfg.Address, nil
}
func (b *Backend) Height(ctx context.Context) (uint64, error) {
	if err := b.validateConfig(); err != nil {
		return 0, err
	}
	var v struct {
		SyncUTIME uint64 `json:"sync_utime"`
		Seqno     uint64 `json:"seqno"`
		Height    uint64 `json:"height"`
	}
	if err := b.get(ctx, b.cfg.HeightPath, &v); err != nil {
		return 0, err
	}
	if v.Height != 0 {
		return v.Height, nil
	}
	if v.Seqno != 0 {
		return v.Seqno, nil
	}
	return v.SyncUTIME, nil
}

func (b *Backend) PostPayload(ctx context.Context, to string, p chain.Payload, _ uint64) (chain.PostResult, error) {
	if err := b.validateConfig(); err != nil {
		return chain.PostResult{}, err
	}
	if strings.TrimSpace(to) == "" || to != b.cfg.Address {
		return chain.PostResult{}, errors.New("ton: recipient does not match configured address")
	}
	if !b.cfg.DeliveryGuaranteed {
		return chain.PostResult{}, ErrDeliveryNotGuaranteed
	}
	if b.cfg.Sender == nil {
		return chain.PostResult{}, errors.New("ton: sender required")
	}
	comment, err := EncodeComment(p)
	if err != nil {
		return chain.PostResult{}, err
	}
	id, err := b.cfg.Sender.Send(ctx, to, comment)
	if err != nil {
		return chain.PostResult{}, err
	}
	if id == "" {
		return chain.PostResult{}, errors.New("ton: response missing transaction id")
	}
	return chain.PostResult{TxID: id}, nil
}

type tx struct {
	Hash    string `json:"hash"`
	Account struct {
		Address string `json:"address"`
	} `json:"account"`
	Utime int64 `json:"utime"`
	InMsg struct {
		Message string `json:"message"`
		Source  string `json:"source"`
	} `json:"in_msg"`
}

func (b *Backend) ListIncoming(ctx context.Context, min uint64) ([]chain.Incoming, error) {
	if err := b.validateConfig(); err != nil {
		return nil, err
	}
	var v struct {
		Transactions []tx `json:"transactions"`
	}
	if err := b.get(ctx, b.cfg.ListPath, &v); err != nil {
		return nil, err
	}
	out := []chain.Incoming{}
	for _, t := range v.Transactions {
		if t.Account.Address != b.cfg.Address || t.Utime < int64(min) || strings.TrimSpace(t.InMsg.Source) == "" {
			continue
		}
		if len(b.cfg.AllowedSources) > 0 && !containsExact(b.cfg.AllowedSources, t.InMsg.Source) {
			continue
		}

		p, err := ParseComment(t.InMsg.Message)
		if err != nil {
			continue
		}
		out = append(out, chain.Incoming{TxID: t.Hash, TopoHeight: t.Utime, Sender: t.InMsg.Source, Payload: p})
	}
	return out, nil
}
func containsExact(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func (b *Backend) url(path string) string {
	return strings.TrimRight(b.cfg.BaseURL, "/") + "/" + strings.TrimLeft(path, "/")
}
func (b *Backend) get(ctx context.Context, path string, out any) error {
	return b.do(ctx, http.MethodGet, path, nil, out)
}
func (b *Backend) do(ctx context.Context, method, path string, body []byte, out any) error {
	var r io.Reader
	if body != nil {
		r = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, b.url(path), r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ton: http status %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

var _ chain.Chain = (*Backend)(nil)
