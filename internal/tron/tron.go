// Package tron carries exact E2 pointers in a Tron transfer memo (the tx
// data field). It is the cheap-tier memo carrier described in
// docs/CLOSE-FREE-ROUTING.md: pointer-only on chain, body off-chain with a
// TTL, strict parsing, and NO burn primitive (a Tron transfer is immutable, so
// this carrier deliberately never claims to erase a delivered message).
//
// Unlike internal/ton, which hard-codes the 74-byte V1 pointer, this carrier
// accepts both PointerV1 (74 B) and PointerV2 (106 B); their base64 memos are
// 100 and 144 chars, both under the ~200 B memo ceiling. Copying TON's V1-only
// check would make the V2 path unreachable on Tron.
package tron

import (
	"context"
	"encoding/base64"
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

// Pointer layout shared with internal/ratchetwire: byte 0 is the version, byte
// 1 is reserved (0), bytes [66:74] are the little-endian burn deadline (the
// body TTL anchor). V2 appends a 32-byte transport locator at [74:106].
const (
	PointerV1Size    = 74
	PointerV2Size    = 106
	PointerV1Version = 1
	PointerV2Version = 2
	PointerReserved  = 0
	deadlineOffset   = 66
)

var ErrMalformedComment = errors.New("tron: malformed memo")
var ErrDeliveryNotGuaranteed = errors.New("tron: sender does not guarantee delivery")

// Sender is the wallet seam. Implementations must submit a transfer whose memo
// is the exact comment supplied; no fallback (memo-less) transfer is permitted.
// The sender owns all key material — this package never touches it.
type Sender interface {
	Send(ctx context.Context, to, memo string) (string, error)
}

type Config struct {
	Address                        string
	Network                        string
	BaseURL                        string
	PostPath, ListPath, HeightPath string
	HTTPClient                     *http.Client
	Timeout                        time.Duration
	Sender                         Sender
	// AllowedSources, when non-empty, is an exact allowlist for incoming
	// senders (addresses in the same form the indexer reports).
	AllowedSources []string
	// DeliveryGuaranteed must be set by a sender that can prove the memo
	// reaches the recipient. A Tron value-only transfer is never a downgrade.
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

// validPointer enforces the exact E2 pointer shape for both versions: known
// length, matching version byte, zero reserved byte, and a nonzero burn
// deadline (a pointer with no TTL is refused, which keeps body reaping honest).
func validPointer(p []byte) bool {
	switch len(p) {
	case PointerV1Size:
		if p[0] != PointerV1Version {
			return false
		}
	case PointerV2Size:
		if p[0] != PointerV2Version {
			return false
		}
	default:
		return false
	}
	if p[1] != PointerReserved {
		return false
	}
	return binary.LittleEndian.Uint64(p[deadlineOffset:deadlineOffset+8]) != 0
}

// EncodeComment encodes an E2 pointer (V1 or V2) as the Tron memo payload:
// canonical padded base64 of the pointer bytes. It is not a generic Tron memo
// format — only a valid pointer is accepted, so plaintext can never ride here.
func EncodeComment(pointer []byte) (string, error) {
	if !validPointer(pointer) {
		return "", fmt.Errorf("tron: pointer must be a valid %d-byte v1 or %d-byte v2 pointer", PointerV1Size, PointerV2Size)
	}
	return base64.StdEncoding.EncodeToString(pointer), nil
}

// ParseComment accepts only canonical padded base64 of exactly a V1 or V2
// pointer, re-encoding to reject any non-canonical or padded-variant input.
func ParseComment(s string) ([]byte, error) {
	switch len(s) {
	case base64.StdEncoding.EncodedLen(PointerV1Size), base64.StdEncoding.EncodedLen(PointerV2Size):
	default:
		return nil, ErrMalformedComment
	}
	p, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(p) != s || !validPointer(p) {
		return nil, ErrMalformedComment
	}
	return p, nil
}

func (b *Backend) validateConfig() error {
	switch b.cfg.Network {
	case "mainnet", "nile", "shasta", "testnet":
	default:
		return errors.New("tron: unsupported network profile")
	}
	if strings.TrimSpace(b.cfg.Address) == "" {
		return errors.New("tron: missing address")
	}
	u, err := url.Parse(b.cfg.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return errors.New("tron: invalid base URL")
	}
	if b.cfg.PostPath == "" || b.cfg.ListPath == "" || b.cfg.HeightPath == "" {
		return errors.New("tron: explicit profile paths are required")
	}
	return nil
}

func (b *Backend) Name() string { return "tron" }

func (b *Backend) Address(context.Context) (string, error) {
	if strings.TrimSpace(b.cfg.Address) == "" {
		return "", errors.New("tron: missing address")
	}
	return b.cfg.Address, nil
}

func (b *Backend) Height(ctx context.Context) (uint64, error) {
	if err := b.validateConfig(); err != nil {
		return 0, err
	}
	var v struct {
		BlockHeader struct {
			RawData struct {
				Number    uint64 `json:"number"`
				Timestamp uint64 `json:"timestamp"`
			} `json:"raw_data"`
		} `json:"block_header"`
		Number uint64 `json:"number"`
	}
	if err := b.get(ctx, b.cfg.HeightPath, &v); err != nil {
		return 0, err
	}
	if v.BlockHeader.RawData.Number != 0 {
		return v.BlockHeader.RawData.Number, nil
	}
	if v.Number != 0 {
		return v.Number, nil
	}
	return v.BlockHeader.RawData.Timestamp, nil
}

func (b *Backend) PostPayload(ctx context.Context, to string, p chain.Payload, _ uint64) (chain.PostResult, error) {
	if err := b.validateConfig(); err != nil {
		return chain.PostResult{}, err
	}
	if strings.TrimSpace(to) == "" || to != b.cfg.Address {
		return chain.PostResult{}, errors.New("tron: recipient does not match configured address")
	}
	if !b.cfg.DeliveryGuaranteed {
		return chain.PostResult{}, ErrDeliveryNotGuaranteed
	}
	if b.cfg.Sender == nil {
		return chain.PostResult{}, errors.New("tron: sender required")
	}
	memo, err := EncodeComment(p)
	if err != nil {
		return chain.PostResult{}, err
	}
	id, err := b.cfg.Sender.Send(ctx, to, memo)
	if err != nil {
		return chain.PostResult{}, err
	}
	if id == "" {
		return chain.PostResult{}, errors.New("tron: response missing transaction id")
	}
	return chain.PostResult{TxID: id}, nil
}

// tx mirrors the TronGrid v1 /accounts/{address}/transactions shape for the
// fields this carrier needs. Pin the profile with visible=true so addresses
// arrive base58, matching the configured Address.
type tx struct {
	TxID           string `json:"txID"`
	BlockTimestamp int64  `json:"block_timestamp"`
	RawData        struct {
		Data     string `json:"data"` // hex-encoded memo bytes
		Contract []struct {
			Type      string `json:"type"`
			Parameter struct {
				Value struct {
					Amount       uint64 `json:"amount"`
					OwnerAddress string `json:"owner_address"`
					ToAddress    string `json:"to_address"`
				} `json:"value"`
			} `json:"parameter"`
		} `json:"contract"`
	} `json:"raw_data"`
}

func (b *Backend) ListIncoming(ctx context.Context, min uint64) ([]chain.Incoming, error) {
	if err := b.validateConfig(); err != nil {
		return nil, err
	}
	var v struct {
		Data []tx `json:"data"`
	}
	if err := b.get(ctx, b.cfg.ListPath, &v); err != nil {
		return nil, err
	}
	out := []chain.Incoming{}
	for _, t := range v.Data {
		if t.BlockTimestamp < int64(min) {
			continue
		}
		for _, c := range t.RawData.Contract {
			if c.Type != "TransferContract" && c.Type != "TransferAssetContract" {
				continue
			}
			val := c.Parameter.Value
			if val.ToAddress != b.cfg.Address {
				continue
			}
			sender := strings.TrimSpace(val.OwnerAddress)
			if sender == "" || sender == b.cfg.Address {
				continue // require sender != self
			}
			if len(b.cfg.AllowedSources) > 0 && !containsExact(b.cfg.AllowedSources, sender) {
				continue
			}
			memo, err := hex.DecodeString(t.RawData.Data)
			if err != nil {
				continue
			}
			p, err := ParseComment(string(memo))
			if err != nil {
				continue
			}
			out = append(out, chain.Incoming{
				TxID:       t.TxID,
				TopoHeight: t.BlockTimestamp,
				Sender:     sender,
				Amount:     val.Amount,
				Payload:    p,
			})
			break // one pointer per tx
		}
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
		return fmt.Errorf("tron: http status %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

// Backend implements chain.Chain but deliberately NOT chain.Burner: a Tron
// transfer memo is immutable, so there is no erase primitive to expose. Body
// compost is off-chain only (TTL store), never a claim to burn the tx.
var _ chain.Chain = (*Backend)(nil)
