// Package nostr carries opaque Spore pointer payloads as signed Nostr events.
package nostr

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	chain "github.com/liqdmetal/spore/internal/chain"
	n "github.com/nbd-wtf/go-nostr"
)

const (
	Kind         = 33301
	deletionKind = 5
	pointerTag   = "spore-pointer"
)

var ErrInvalid = errors.New("nostr: invalid configuration or payload")

const (
	pointerSize = 74
	PointerSize = pointerSize
)

func encodePointer(p []byte) (string, error) {
	if !validPointer(p) {
		return "", ErrInvalid
	}
	return hex.EncodeToString(p), nil
}
func decodePointer(s string) ([]byte, error) {
	// Pointer content is canonical lowercase hex, not merely decodable hex.
	if len(s) != pointerSize*2 || s != strings.ToLower(s) {
		return nil, ErrInvalid
	}
	p, err := hex.DecodeString(s)
	if err != nil || !validPointer(p) {
		return nil, ErrInvalid
	}
	return p, nil
}

func validPointer(p []byte) bool {
	return len(p) == pointerSize && p[0] == 1 && p[1] == 0 &&
		binary.LittleEndian.Uint64(p[pointerSize-8:]) != 0
}

type Relay interface {
	Publish(context.Context, n.Event) error
	QuerySync(context.Context, n.Filter) ([]*n.Event, error)
}

type Config struct {
	PrivateKey string
	Relays     []string
	Network    string
	Relay      Relay // injectable seam; production callers may leave nil
}

type Carrier struct {
	cfg    Config
	pubkey string
}

var _ chain.Chain = (*Carrier)(nil)
var _ chain.Burner = (*Carrier)(nil)

func New(cfg Config) (*Carrier, error) {
	if strings.TrimSpace(cfg.PrivateKey) == "" || len(cfg.Relays) == 0 || strings.TrimSpace(cfg.Network) == "" {
		return nil, ErrInvalid
	}
	for _, u := range cfg.Relays {
		if strings.TrimSpace(u) == "" {
			return nil, ErrInvalid
		}
	}
	pk, err := n.GetPublicKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("nostr key: %w", err)
	}
	return &Carrier{cfg: cfg, pubkey: pk}, nil
}
func (c *Carrier) Name() string                            { return "nostr-" + c.cfg.Network }
func (c *Carrier) Address(context.Context) (string, error) { return c.pubkey, nil }
func (c *Carrier) Height(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}
func (c *Carrier) relay(ctx context.Context) (Relay, error) {
	if c.cfg.Relay != nil {
		return c.cfg.Relay, nil
	}
	stores := make(n.MultiStore, 0, len(c.cfg.Relays))
	for _, u := range c.cfg.Relays {
		r, err := n.RelayConnect(ctx, u)
		if err != nil {
			continue
		}
		stores = append(stores, r)
	}
	if len(stores) == 0 {
		return nil, errors.New("nostr: no relay available")
	}
	return stores, nil
}
func (c *Carrier) PostPayload(ctx context.Context, recipient string, p chain.Payload, _ uint64) (chain.PostResult, error) {
	if err := ctx.Err(); err != nil {
		return chain.PostResult{}, err
	}
	if strings.TrimSpace(recipient) == "" || !validPointer(p) {
		return chain.PostResult{}, ErrInvalid
	}
	r, err := c.relay(ctx)
	if err != nil {
		return chain.PostResult{}, err
	}
	content, err := encodePointer(p)
	if err != nil {
		return chain.PostResult{}, err
	}
	ev := n.Event{Kind: Kind, Content: content, CreatedAt: n.Timestamp(time.Now().Unix()), Tags: n.Tags{n.Tag{"p", recipient}, n.Tag{"network", c.cfg.Network}, n.Tag{pointerTag, content}}}
	if err = ev.Sign(c.cfg.PrivateKey); err != nil {
		return chain.PostResult{}, err
	}
	if err = r.Publish(ctx, ev); err != nil {
		return chain.PostResult{}, err
	}
	return chain.PostResult{TxID: ev.ID}, nil
}
func (c *Carrier) ListIncoming(ctx context.Context, min uint64) ([]chain.Incoming, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := c.relay(ctx)
	if err != nil {
		return nil, err
	}
	es, err := r.QuerySync(ctx, n.Filter{Kinds: []int{Kind}, Tags: n.TagMap{"p": []string{c.pubkey}, "network": []string{c.cfg.Network}}})
	if err != nil {
		return nil, err
	}
	out := make([]chain.Incoming, 0, len(es))
	for _, ev := range es {
		if ev == nil || uint64(ev.CreatedAt) < min {
			continue
		}
		var raw string
		for _, t := range ev.Tags {
			if len(t) == 2 && t[0] == pointerTag {
				raw = t[1]
				break
			}
		}
		if raw == "" {
			raw = ev.Content
		}
		if raw == "" {
			continue
		}
		p, e := decodePointer(raw)
		if e != nil || len(p) != 74 || p[0] != 1 || p[1] != 0 {
			continue
		}
		out = append(out, chain.Incoming{TxID: ev.ID, TopoHeight: int64(ev.CreatedAt), Sender: ev.PubKey, Payload: p, BurnKey: ev.ID})
	}
	return out, nil
}
func (c *Carrier) Burn(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(id) != 64 {
		return ErrInvalid
	}
	r, e := c.relay(ctx)
	if e != nil {
		return e
	}
	ev := n.Event{Kind: deletionKind, CreatedAt: n.Timestamp(time.Now().Unix()), Tags: n.Tags{n.Tag{"e", id}}}
	if e = ev.Sign(c.cfg.PrivateKey); e != nil {
		return e
	}
	return r.Publish(ctx, ev)
}
