// Package bitcoin carries opaque E2 pointers in Bitcoin OP_RETURN outputs.
// Bitcoin is immutable: there is intentionally no Burner; compost is body-only
// (the off-chain body may be deleted after delivery, while the tx remains).
package bitcoin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/liqdmetal/spore/internal/chain"
)

const MaxOpReturnBytes = 80
const canonicalPointerLen = 74
const canonicalPointerVersion byte = 1
const minRelayOutput uint64 = 546
const maxFeeRate uint64 = 1000000

var ErrPointerTooLarge = errors.New("bitcoin: OP_RETURN payload exceeds 80-byte limit")
var ErrMalformedPointer = errors.New("bitcoin: malformed E2 pointer")

type Network string

const (
	Mainnet  Network = "mainnet"
	Signet   Network = "signet"
	Testnet4 Network = "testnet4"
)

func params(n Network) *chaincfg.Params {
	switch n {
	case Mainnet:
		return &chaincfg.MainNetParams
	case Testnet4:
		p := chaincfg.TestNet3Params
		return &p
	case Signet:
		return &chaincfg.SigNetParams
	default:
		return nil
	}
}
func PointerScript(p []byte) ([]byte, error) {
	if len(p)+2 > MaxOpReturnBytes {
		return nil, ErrPointerTooLarge
	}
	if !validPointer(p) {
		return nil, ErrMalformedPointer
	}
	return append([]byte{txscript.OP_RETURN, byte(len(p))}, p...), nil
}
func validPointer(p []byte) bool {
	if len(p) != canonicalPointerLen || p[0] != canonicalPointerVersion || p[1] != 0 {
		return false
	}
	for _, v := range p[66:] {
		if v != 0 {
			return true
		}
	}
	return false
}

func ParsePointerScript(s []byte) ([]byte, bool) {
	if len(s) != 76 || s[0] != txscript.OP_RETURN || s[1] != canonicalPointerLen || s[2] != canonicalPointerVersion || s[3] != 0 {
		return nil, false
	}
	p := append([]byte(nil), s[2:]...)
	if !validPointer(p) {
		return nil, false
	}
	return p, true
}

type UTXO struct {
	TxID  string `json:"txid"`
	Vout  uint32 `json:"vout"`
	Value uint64 `json:"value"`
}
type SignerBroadcaster interface {
	SignAndBroadcast(context.Context, *wire.MsgTx) (string, error)
}
type API interface {
	Do(context.Context, string, any) error
}
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func (c Client) get(ctx context.Context, path string, v any) error {
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: 15 * time.Second}
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+path, nil)
	if e != nil {
		return e
	}
	r, e := h.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode/100 != 2 {
		return fmt.Errorf("bitcoin esplora: http %s", r.Status)
	}
	return json.NewDecoder(r.Body).Decode(v)
}
func (c Client) Height(ctx context.Context) (uint64, error) {
	var n uint64
	e := c.get(ctx, "/blocks/tip/height", &n)
	return n, e
}
func (c Client) Address(ctx context.Context) (string, error) {
	return "", errors.New("bitcoin: address is supplied by signer")
}

type Backend struct {
	Client       Client
	Signer       SignerBroadcaster
	AddressValue string
	FeeRate      uint64
	Network      Network
}

func (b *Backend) Name() string { return "bitcoin" }
func (b *Backend) Address(context.Context) (string, error) {
	if b.AddressValue == "" {
		return "", errors.New("bitcoin: missing address")
	}
	return b.AddressValue, nil
}
func (b *Backend) Height(ctx context.Context) (uint64, error) { return b.Client.Height(ctx) }
func (b *Backend) PostPayload(ctx context.Context, to string, p chain.Payload, _ uint64) (chain.PostResult, error) {
	s, e := PointerScript(p)
	if e != nil {
		return chain.PostResult{}, e
	}
	net := params(b.Network)
	if net == nil {
		return chain.PostResult{}, errors.New("bitcoin: unsupported network")
	}
	a, e := btcAddress(to, net)
	if e != nil {
		return chain.PostResult{}, e
	}
	u := []UTXO{}
	if e = b.Client.get(ctx, "/address/"+to+"/utxo", &u); e != nil {
		return chain.PostResult{}, e
	}
	if len(u) == 0 {
		return chain.PostResult{}, errors.New("bitcoin: no spendable UTXOs")
	}
	if b.FeeRate == 0 || b.FeeRate > maxFeeRate {
		return chain.PostResult{}, errors.New("bitcoin: invalid fee rate")
	}
	tx := wire.NewMsgTx(2)
	var total uint64
	for _, x := range u {
		if x.Value == 0 {
			continue
		}
		h, e := chainHash(x.TxID)
		if e != nil {
			return chain.PostResult{}, e
		}
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&h, x.Vout), nil, nil))
		if total > ^uint64(0)-x.Value {
			return chain.PostResult{}, errors.New("bitcoin: UTXO value overflow")
		}
		total += x.Value
	}
	if len(tx.TxIn) == 0 {
		return chain.PostResult{}, errors.New("bitcoin: no spendable UTXOs")
	}
	tx.AddTxOut(wire.NewTxOut(0, s))
	vbytes := uint64(tx.SerializeSize() + 2*34 + 10)
	if b.FeeRate > ^uint64(0)/vbytes {
		return chain.PostResult{}, errors.New("bitcoin: fee overflow")
	}
	fee := b.FeeRate * vbytes
	if total <= fee || total-fee < minRelayOutput {
		return chain.PostResult{}, errors.New("bitcoin: UTXOs do not cover fee")
	}
	tx.TxOut[0].Value = 0
	dest := a
	change := total - fee
	if change > uint64(^uint64(0)>>1) {
		return chain.PostResult{}, errors.New("bitcoin: change exceeds transaction value limit")
	}
	tx.AddTxOut(wire.NewTxOut(int64(change), dest))
	if b.Signer == nil {
		return chain.PostResult{}, errors.New("bitcoin: signer required")
	}
	id, e := b.Signer.SignAndBroadcast(ctx, tx)
	return chain.PostResult{TxID: id}, e
}
func btcAddress(s string, p *chaincfg.Params) ([]byte, error) {
	addr, err := btcutil.DecodeAddress(s, p)
	if err != nil {
		return nil, fmt.Errorf("bitcoin: invalid destination address: %w", err)
	}
	if !addr.IsForNet(p) {
		return nil, errors.New("bitcoin: destination address is for the wrong network")
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("bitcoin: build destination script: %w", err)
	}
	return script, nil
}
func chainHash(s string) (chainhash.Hash, error) {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 {
		return chainhash.Hash{}, errors.New("bitcoin: invalid txid")
	}
	var h chainhash.Hash
	copy(h[:], reverse(b))
	return h, nil
}
func reverse(b []byte) []byte {
	r := append([]byte(nil), b...)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return r
}
func (b *Backend) ListIncoming(ctx context.Context, min uint64) ([]chain.Incoming, error) {
	var txs []struct {
		Txid   string `json:"txid"`
		Status struct {
			BlockHeight uint64 `json:"block_height"`
		} `json:"status"`
		Vout []struct {
			Scriptpubkey string `json:"scriptpubkey"`
			Value        uint64 `json:"value"`
		} `json:"vout"`
	}
	if e := b.Client.get(ctx, "/address/"+b.AddressValue+"/txs", &txs); e != nil {
		return nil, e
	}
	out := []chain.Incoming{}
	for _, t := range txs {
		if t.Status.BlockHeight < min {
			continue
		}
		for _, v := range t.Vout {
			raw, e := hex.DecodeString(v.Scriptpubkey)
			if e != nil {
				continue
			}
			if p, ok := ParsePointerScript(raw); ok {
				out = append(out, chain.Incoming{TxID: t.Txid, TopoHeight: int64(t.Status.BlockHeight), Payload: p})
			}
		}
	}
	return out, nil
}

var _ chain.Chain = (*Backend)(nil)
